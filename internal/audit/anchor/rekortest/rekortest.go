package rekortest

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor"
)

type witness struct {
	name string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	now  func() time.Time
}

func (w *witness) Name() string    { return w.name }
func (w *witness) KeyHash() uint32 { return anchor.CosignatureKeyHash(w.name, w.pub) }
func (w *witness) Sign(msg []byte) ([]byte, error) {
	ts := uint64(max(w.now().Unix(), 0))
	sig := ed25519.Sign(w.priv, anchor.CosignatureMessage(ts, msg))
	return append(binary.BigEndian.AppendUint64(nil, ts), sig...), nil
}

type fault struct {
	status     int
	retryAfter time.Duration
}

type Server struct {
	URL     string
	Origin  string
	LogKey  ed25519.PublicKey
	logSPKI []byte

	mu          sync.Mutex
	signer      note.Signer
	witnesses   []*witness
	leaves      [][]byte
	stored      []tlog.Hash
	faults      []fault
	delay       time.Duration
	tamperProof bool
	now         func() time.Time
}

type Option func(*Server)

func WithWitness(name string) Option {
	return func(s *Server) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		s.witnesses = append(s.witnesses, &witness{name: name, pub: pub, priv: priv, now: s.clock})
	}
}

func WithClock(now func() time.Time) Option {
	return func(s *Server) { s.now = now }
}

func New(tb testing.TB, opts ...Option) *Server {
	tb.Helper()
	s := &Server{now: time.Now}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/log/entries", s.create)
	mux.HandleFunc("GET /api/v2/checkpoint", s.checkpoint)
	srv := httptest.NewServer(mux)
	tb.Cleanup(srv.Close)
	s.URL = srv.URL
	s.Origin = srv.Listener.Addr().String()
	for _, o := range opts {
		o(s)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	s.LogKey = pub
	s.logSPKI, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		tb.Fatal(err)
	}
	skey := "PRIVATE+KEY+" + s.Origin + "+" + fmt.Sprintf("%08x", logKeyHash(s.Origin, pub)) + "+" +
		base64.StdEncoding.EncodeToString(append([]byte{1}, priv.Seed()...))
	s.signer, err = note.NewSigner(skey)
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

func logKeyHash(name string, pub ed25519.PublicKey) uint32 {
	vkey, err := note.NewEd25519VerifierKey(name, pub)
	if err != nil {
		panic(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		panic(err)
	}
	return v.KeyHash()
}

func (s *Server) clock() time.Time {
	return s.now()
}

func (s *Server) TrustedRootJSON() []byte {
	root := map[string]any{"tlogs": []any{map[string]any{
		"baseUrl": "http://" + s.Origin,
		"publicKey": map[string]any{
			"rawBytes": s.logSPKI, "keyDetails": "PKIX_ED25519",
			"validFor": map[string]any{"start": "2020-01-01T00:00:00Z"},
		},
	}}}
	b, err := json.Marshal(root)
	if err != nil {
		panic(err)
	}
	return b
}

func (s *Server) WitnessVKeys() []string {
	out := make([]string, 0, len(s.witnesses))
	for _, w := range s.witnesses {
		out = append(out, anchor.CosignatureVKey(w.name, w.pub))
	}
	return out
}

func (s *Server) FailNext(status, n int, retryAfter time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for range n {
		s.faults = append(s.faults, fault{status: status, retryAfter: retryAfter})
	}
}

func (s *Server) Delay(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = d
}

func (s *Server) TamperNextProof() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tamperProof = true
}

func (s *Server) Entries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.leaves)
}

func (s *Server) hashes() tlog.HashReaderFunc {
	return func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			if x < 0 || x >= int64(len(s.stored)) {
				return nil, fmt.Errorf("hash %d not stored", x)
			}
			out[i] = s.stored[x]
		}
		return out, nil
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{"code": 3, "message": msg}); err != nil {
		return
	}
}

func (s *Server) takeFault() (fault, time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.faults) == 0 {
		return fault{}, s.delay, false
	}
	f := s.faults[0]
	s.faults = s.faults[1:]
	return f, s.delay, true
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read request: "+err.Error())
		return
	}
	f, delay, failed := s.takeFault()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if failed {
		if f.retryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(f.retryAfter.Seconds())))
		}
		writeError(w, f.status, "injected failure")
		return
	}
	var req anchor.CreateEntryRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	hr := req.HashedRekord
	if hr.Signature.Verifier.KeyDetails != "PKIX_ED25519_PH" || hr.Signature.Verifier.PublicKey == nil ||
		len(hr.Digest) != 64 {
		writeError(w, http.StatusBadRequest, "unsupported key details or digest")
		return
	}
	key, err := x509.ParsePKIXPublicKey(hr.Signature.Verifier.PublicKey.RawBytes)
	pub, ok := key.(ed25519.PublicKey)
	if err != nil || !ok {
		writeError(w, http.StatusBadRequest, "public key is not ed25519")
		return
	}
	if err := ed25519.VerifyWithOptions(pub, hr.Digest, hr.Signature.Content,
		&ed25519.Options{Hash: crypto.SHA512}); err != nil {
		writeError(w, http.StatusBadRequest, "signature does not verify")
		return
	}
	logged, err := canonicalBody(hr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp, err := s.append(logged)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write(resp); err != nil {
		return
	}
}

func canonicalBody(hr anchor.HashedRekordRequest) ([]byte, error) {
	entry := map[string]any{
		"apiVersion": "0.0.2",
		"kind":       "hashedrekord",
		"spec": map[string]any{"hashedRekordV002": map[string]any{
			"data": map[string]any{"algorithm": "SHA2_512", "digest": hr.Digest},
			"signature": map[string]any{
				"content": hr.Signature.Content,
				"verifier": map[string]any{
					"keyDetails": hr.Signature.Verifier.KeyDetails,
					"publicKey":  map[string]any{"rawBytes": hr.Signature.Verifier.PublicKey.RawBytes},
				},
			},
		}},
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("canonical body: %w", err)
	}
	return b, nil
}

func (s *Server) append(body []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int64(len(s.leaves))
	hs, err := tlog.StoredHashes(n, body, s.hashes())
	if err != nil {
		return nil, fmt.Errorf("store leaf: %w", err)
	}
	s.leaves = append(s.leaves, body)
	s.stored = append(s.stored, hs...)
	size := n + 1
	root, err := tlog.TreeHash(size, s.hashes())
	if err != nil {
		return nil, fmt.Errorf("tree hash: %w", err)
	}
	proof, err := tlog.ProveRecord(size, n, s.hashes())
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	cp, err := s.signedCheckpoint(size, root)
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, len(proof))
	for i := range proof {
		hashes[i] = bytes.Clone(proof[i][:])
	}
	if s.tamperProof && len(hashes) > 0 {
		hashes[0][0] ^= 0xff
		s.tamperProof = false
	}
	b, err := json.Marshal(map[string]any{
		"logIndex":          strconv.FormatInt(n, 10),
		"logId":             map[string]any{"keyId": base64.StdEncoding.EncodeToString([]byte(s.Origin))},
		"kindVersion":       map[string]any{"kind": "hashedrekord", "version": "0.0.2"},
		"integratedTime":    "0",
		"inclusionPromise":  nil,
		"canonicalizedBody": body,
		"inclusionProof": map[string]any{
			"logIndex": strconv.FormatInt(n, 10), "rootHash": root[:], "treeSize": strconv.FormatInt(size, 10),
			"hashes": hashes, "checkpoint": map[string]any{"envelope": cp},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode entry: %w", err)
	}
	return b, nil
}

func (s *Server) signedCheckpoint(size int64, root tlog.Hash) (string, error) {
	text := fmt.Sprintf("%s\n%d\n%s\n", s.Origin, size, base64.StdEncoding.EncodeToString(root[:]))
	signers := make([]note.Signer, 0, 1+len(s.witnesses))
	signers = append(signers, s.signer)
	for _, w := range s.witnesses {
		signers = append(signers, w)
	}
	msg, err := note.Sign(&note.Note{Text: text}, signers...)
	if err != nil {
		return "", fmt.Errorf("sign checkpoint: %w", err)
	}
	return string(msg), nil
}

func (s *Server) checkpoint(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	size := int64(len(s.leaves))
	var root tlog.Hash
	var err error
	if size > 0 {
		root, err = tlog.TreeHash(size, s.hashes())
	}
	var cp string
	if err == nil {
		cp, err = s.signedCheckpoint(size, root)
	}
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := w.Write([]byte(cp)); err != nil {
		return
	}
}

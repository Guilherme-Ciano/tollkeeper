package rekortest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/digitorus/timestamp"
)

type tsa struct {
	mu        sync.Mutex
	root      *x509.Certificate
	leaf      *x509.Certificate
	key       *ecdsa.PrivateKey
	fail      int
	omitCerts bool
	serial    int64
}

func WithTSA() Option {
	return func(s *Server) {
		t, err := newTSA()
		if err != nil {
			panic(err)
		}
		s.tsa = t
	}
}

func newTSA() (*tsa, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("fake tsa: %w", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake-tsa-root"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("fake tsa: %w", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("fake tsa: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("fake tsa: %w", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fake-tsa"},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("fake tsa: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("fake tsa: %w", err)
	}
	return &tsa{root: root, leaf: leaf, key: leafKey}, nil
}

func (s *Server) TSAFailNext(n int) {
	s.tsa.mu.Lock()
	defer s.tsa.mu.Unlock()
	s.tsa.fail = n
}

func (s *Server) TSAOmitCertificates() {
	s.tsa.mu.Lock()
	defer s.tsa.mu.Unlock()
	s.tsa.omitCerts = true
}

func (s *Server) TSAChainPEM() []byte {
	out := make([]byte, 0, 2048)
	for _, c := range []*x509.Certificate{s.tsa.leaf, s.tsa.root} {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func (s *Server) timestamp(w http.ResponseWriter, r *http.Request) {
	if s.tsa == nil {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<14))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	req, err := timestamp.ParseRequest(body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	t := s.tsa
	t.mu.Lock()
	if t.fail > 0 {
		t.fail--
		t.mu.Unlock()
		http.Error(w, "injected failure", http.StatusServiceUnavailable)
		return
	}
	t.serial++
	ts := timestamp.Timestamp{
		HashAlgorithm: req.HashAlgorithm, HashedMessage: req.HashedMessage, Time: s.now().UTC().Truncate(time.Second),
		Nonce: req.Nonce, Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}, SerialNumber: big.NewInt(t.serial),
		AddTSACertificate: req.Certificates && !t.omitCerts,
	}
	t.mu.Unlock()
	resp, err := ts.CreateResponseWithOpts(t.leaf, t.key, crypto.SHA256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	if _, err := w.Write(resp); err != nil {
		return
	}
}

package anchor

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

const maxProofHashes = 64

type ReceiptVerifier struct {
	trust *Trust
}

func NewReceiptVerifier(t *Trust) *ReceiptVerifier {
	return &ReceiptVerifier{trust: t}
}

func Sign(key ed25519.PrivateKey, ref audit.CheckpointRef) (Submission, error) {
	digest, err := audit.AnchorDigest(ref.ChainID, ref.Seq, ref.Hash)
	if err != nil {
		return Submission{}, err
	}
	sig, err := key.Sign(nil, digest[:], &ed25519.Options{Hash: crypto.SHA512})
	if err != nil {
		return Submission{}, fmt.Errorf("sign anchor: %w", err)
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return Submission{}, audit.ErrKeyType
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Submission{}, fmt.Errorf("encode anchor key: %w", err)
	}
	return Submission{Digest: digest, Signature: sig, PublicKeyDER: der}, nil
}

func NewAnchor(ref audit.CheckpointRef, pub ed25519.PublicKey, origin string, r Receipt) *audit.Anchor {
	return &audit.Anchor{
		CoversSeq:  ref.Seq,
		CoversHash: ref.Hash,
		KeyID:      audit.KeyID(pub),
		Log:        origin,
		LogIndex:   r.LogIndex,
		Entry:      r.Entry,
		Proof:      r.Proof,
		Checkpoint: r.Checkpoint,
	}
}

type checkpointBody struct {
	origin string
	size   uint64
	root   tlog.Hash
}

func parseCheckpoint(text string) (checkpointBody, error) {
	lines := strings.SplitN(text, "\n", 4)
	if len(lines) < 4 {
		return checkpointBody{}, fmt.Errorf("%w: checkpoint has too few lines", ErrInvalidReceipt)
	}
	size, err := strconv.ParseUint(lines[1], 10, 63)
	if err != nil || size < 1 || strconv.FormatUint(size, 10) != lines[1] {
		return checkpointBody{}, fmt.Errorf("%w: checkpoint size %q", ErrInvalidReceipt, lines[1])
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != tlog.HashSize {
		return checkpointBody{}, fmt.Errorf("%w: checkpoint root hash", ErrInvalidReceipt)
	}
	cb := checkpointBody{origin: lines[0], size: size}
	copy(cb.root[:], root)
	return cb, nil
}

func (v *ReceiptVerifier) verifiers(keys []LogKey) note.Verifiers {
	list := make([]note.Verifier, 0, len(keys)+len(v.trust.witnesses))
	for i := range keys {
		list = append(list, keys[i].Verifier)
	}
	list = append(list, v.trust.witnesses...)
	return note.VerifierList(list...)
}

func (v *ReceiptVerifier) VerifyAnchor(
	chainID string,
	a *audit.Anchor,
	covered audit.CheckpointRef,
	pub ed25519.PublicKey,
) (audit.AnchorEvidence, error) {
	keys := v.trust.logs[a.Log]
	if len(keys) == 0 {
		return audit.AnchorEvidence{}, fmt.Errorf("%w: %q", ErrUntrustedLog, a.Log)
	}
	n, err := note.Open([]byte(a.Checkpoint), v.verifiers(keys))
	if err != nil {
		return audit.AnchorEvidence{}, fmt.Errorf("%w: checkpoint: %w", ErrInvalidReceipt, err)
	}
	logKey, ok := signedBy(n, keys)
	if !ok {
		return audit.AnchorEvidence{}, fmt.Errorf("%w: checkpoint not signed by %s", ErrUntrustedLog, a.Log)
	}
	cb, err := parseCheckpoint(n.Text)
	if err != nil {
		return audit.AnchorEvidence{}, err
	}
	if cb.origin != a.Log {
		return audit.AnchorEvidence{}, fmt.Errorf("%w: checkpoint origin %q", ErrInvalidReceipt, cb.origin)
	}
	if err := checkInclusion(a, cb); err != nil {
		return audit.AnchorEvidence{}, err
	}
	if err := checkEntry(a.Entry, chainID, covered, pub); err != nil {
		return audit.AnchorEvidence{}, err
	}
	ev := audit.AnchorEvidence{Log: a.Log, LogIndex: a.LogIndex, TreeSize: cb.size}
	if err := v.witness(n, &ev); err != nil {
		return ev, err
	}
	at := ev.WitnessedAt
	if at.IsZero() {
		at = time.Unix(0, covered.TS)
	}
	if !logKey.validAt(at) {
		return ev, fmt.Errorf("%w: log key not valid at %s", ErrUntrustedLog, at.UTC().Format(time.RFC3339))
	}
	return ev, nil
}

func signedBy(n *note.Note, keys []LogKey) (LogKey, bool) {
	for _, s := range n.Sigs {
		for i := range keys {
			if s.Name == keys[i].Verifier.Name() && s.Hash == keys[i].Verifier.KeyHash() {
				return keys[i], true
			}
		}
	}
	return LogKey{}, false
}

func checkInclusion(a *audit.Anchor, cb checkpointBody) error {
	if a.LogIndex >= cb.size || cb.size > math.MaxInt64 {
		return fmt.Errorf("%w: log index %d outside tree of size %d", ErrInvalidReceipt, a.LogIndex, cb.size)
	}
	if len(a.Proof) > maxProofHashes {
		return fmt.Errorf("%w: proof too long", ErrInvalidReceipt)
	}
	proof := make(tlog.RecordProof, len(a.Proof))
	for i, h := range a.Proof {
		if len(h) != tlog.HashSize {
			return fmt.Errorf("%w: proof hash %d has %d bytes", ErrInvalidReceipt, i, len(h))
		}
		copy(proof[i][:], h)
	}
	leaf := tlog.RecordHash(a.Entry)
	size, index := int64(cb.size&math.MaxInt64), int64(a.LogIndex&math.MaxInt64)
	if err := tlog.CheckRecord(proof, size, cb.root, index, leaf); err != nil {
		return fmt.Errorf("%w: inclusion proof: %w", ErrInvalidReceipt, err)
	}
	return nil
}

func checkEntry(entry []byte, chainID string, covered audit.CheckpointRef, pub ed25519.PublicKey) error {
	var e LoggedEntry
	dec := json.NewDecoder(bytes.NewReader(entry))
	if err := dec.Decode(&e); err != nil {
		return fmt.Errorf("%w: logged entry: %w", ErrInvalidReceipt, err)
	}
	hr := e.Spec.HashedRekord
	if e.Kind != entryKind || e.APIVersion != entryAPIVersion || hr == nil {
		return fmt.Errorf("%w: logged entry is %s/%s", ErrInvalidReceipt, e.Kind, e.APIVersion)
	}
	want, err := audit.AnchorDigest(chainID, covered.Seq, covered.Hash)
	if err != nil {
		return err
	}
	if hr.Data.Algorithm != hashSHA512 || !bytes.Equal(hr.Data.Digest, want[:]) {
		return ErrDigestMismatch
	}
	if hr.Signature.Verifier.KeyDetails != keyDetailsEd25519 || hr.Signature.Verifier.PublicKey == nil {
		return fmt.Errorf("%w: logged key is not Ed25519ph", ErrInvalidReceipt)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encode anchor key: %w", err)
	}
	if !bytes.Equal(hr.Signature.Verifier.PublicKey.RawBytes, der) {
		return fmt.Errorf("%w: logged entry was signed by another key", ErrInvalidReceipt)
	}
	if err := ed25519.VerifyWithOptions(pub, want[:], hr.Signature.Content,
		&ed25519.Options{Hash: crypto.SHA512}); err != nil {
		return fmt.Errorf("%w: logged signature: %w", ErrInvalidReceipt, err)
	}
	return nil
}

func (v *ReceiptVerifier) witness(n *note.Note, ev *audit.AnchorEvidence) error {
	var times []time.Time
	for _, s := range n.Sigs {
		if !v.isWitness(s) {
			continue
		}
		t, err := cosignatureTime(s)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidReceipt, err)
		}
		times = append(times, t)
	}
	ev.Witnesses = len(times)
	if ev.Witnesses < v.trust.minWitnesses {
		return fmt.Errorf("%w: %d of %d", ErrWitnessQuorum, ev.Witnesses, v.trust.minWitnesses)
	}
	if len(times) == 0 {
		return nil
	}
	slices.SortFunc(times, time.Time.Compare)
	ev.WitnessedAt = times[max(v.trust.minWitnesses, 1)-1]
	return nil
}

func (v *ReceiptVerifier) isWitness(s note.Signature) bool {
	for _, w := range v.trust.witnesses {
		if s.Name == w.Name() && s.Hash == w.KeyHash() {
			return true
		}
	}
	return false
}

func CheckLogCheckpoint(t *Trust, checkpoint string) error {
	origin, _, _ := strings.Cut(checkpoint, "\n")
	keys := t.logs[origin]
	if len(keys) == 0 {
		return fmt.Errorf("%w: %q", ErrUntrustedLog, origin)
	}
	n, err := note.Open([]byte(checkpoint), note.VerifierList(logVerifiers(keys)...))
	if err != nil {
		return fmt.Errorf("%w: checkpoint: %w", ErrUntrustedLog, err)
	}
	if _, ok := signedBy(n, keys); !ok {
		return fmt.Errorf("%w: checkpoint not signed by %s", ErrUntrustedLog, origin)
	}
	return nil
}

func logVerifiers(keys []LogKey) []note.Verifier {
	out := make([]note.Verifier, len(keys))
	for i := range keys {
		out[i] = keys[i].Verifier
	}
	return out
}

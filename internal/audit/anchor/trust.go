package anchor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
)

const (
	algEd25519     = 0x01
	algCosignature = 0x04
)

var (
	ErrBadTrust        = errors.New("invalid anchor trust material")
	ErrUntrustedLog    = errors.New("transparency log not in the trust material")
	ErrInvalidReceipt  = errors.New("invalid transparency log receipt")
	ErrDigestMismatch  = errors.New("logged digest does not match the checkpoint")
	ErrWitnessQuorum   = errors.New("not enough witness cosignatures")
	ErrRejected        = errors.New("transparency log rejected the entry")
	ErrUnavailable     = errors.New("transparency log unavailable")
	errCosignatureSize = errors.New("cosignature has the wrong size")
)

type LogKey struct {
	Origin     string
	Verifier   note.Verifier
	ValidFrom  time.Time
	ValidUntil time.Time
}

func (k LogKey) validAt(t time.Time) bool {
	if !k.ValidFrom.IsZero() && t.Before(k.ValidFrom) {
		return false
	}
	return k.ValidUntil.IsZero() || !t.After(k.ValidUntil)
}

type Trust struct {
	logs         map[string][]LogKey
	tsas         []TimestampAuthority
	witnesses    []note.Verifier
	minWitnesses int
	requireTime  bool
}

type trustedRoot struct {
	Tlogs []struct {
		BaseURL   string `json:"baseUrl"`
		PublicKey struct {
			RawBytes   []byte `json:"rawBytes"`
			KeyDetails string `json:"keyDetails"`
			ValidFor   struct {
				Start time.Time `json:"start"`
				End   time.Time `json:"end"`
			} `json:"validFor"`
		} `json:"publicKey"`
	} `json:"tlogs"`
	TimestampAuthorities []struct {
		URI       string `json:"uri"`
		CertChain struct {
			Certificates []struct {
				RawBytes []byte `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
		ValidFor struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"validFor"`
	} `json:"timestampAuthorities"`
}

func LoadTrust(paths []string, origin string) (*Trust, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: no trust files", ErrBadTrust)
	}
	t := &Trust{logs: map[string][]LogKey{}}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadTrust, err)
		}
		if err := t.add(data, origin); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if len(t.logs) == 0 {
		return nil, fmt.Errorf("%w: no usable transparency log keys", ErrBadTrust)
	}
	return t, nil
}

func ParseTrust(data []byte, origin string) (*Trust, error) {
	t := &Trust{logs: map[string][]LogKey{}}
	if err := t.add(data, origin); err != nil {
		return nil, err
	}
	if len(t.logs) == 0 {
		return nil, fmt.Errorf("%w: no usable transparency log keys", ErrBadTrust)
	}
	return t, nil
}

func (t *Trust) addPEM(data []byte, origin string) error {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN CERTIFICATE")) {
		chain, err := parseCertChain(data)
		if err != nil {
			return err
		}
		a, err := newAuthority("pem", chain, time.Time{}, time.Time{})
		if err != nil {
			return err
		}
		t.tsas = append(t.tsas, a)
		return nil
	}
	if origin == "" {
		return fmt.Errorf("%w: a PEM log key needs the log origin", ErrBadTrust)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("%w: unreadable PEM", ErrBadTrust)
	}
	v, err := logVerifier(origin, block.Bytes)
	if err != nil {
		return err
	}
	t.logs[origin] = append(t.logs[origin], LogKey{Origin: origin, Verifier: v})
	return nil
}

func (t *Trust) add(data []byte, origin string) error {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		return t.addPEM(data, origin)
	}
	var root trustedRoot
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("%w: trusted root: %w", ErrBadTrust, err)
	}
	if err := t.addAuthorities(&root); err != nil {
		return err
	}
	for i := range root.Tlogs {
		tl := &root.Tlogs[i]
		u, err := url.Parse(tl.BaseURL)
		if err != nil || u.Host == "" {
			return fmt.Errorf("%w: tlogs[%d].baseUrl %q", ErrBadTrust, i, tl.BaseURL)
		}
		origin := u.Host + strings.TrimSuffix(u.Path, "/")
		switch tl.PublicKey.KeyDetails {
		case "PKIX_ED25519", "PKIX_ECDSA_P256_SHA_256":
		default:
			continue
		}
		v, err := logVerifier(origin, tl.PublicKey.RawBytes)
		if err != nil {
			return fmt.Errorf("tlogs[%d]: %w", i, err)
		}
		t.logs[origin] = append(t.logs[origin], LogKey{
			Origin: origin, Verifier: v,
			ValidFrom: tl.PublicKey.ValidFor.Start, ValidUntil: tl.PublicKey.ValidFor.End,
		})
	}
	return nil
}

func (t *Trust) addAuthorities(root *trustedRoot) error {
	for i := range root.TimestampAuthorities {
		ta := &root.TimestampAuthorities[i]
		chain := make([]*x509.Certificate, 0, len(ta.CertChain.Certificates))
		for _, c := range ta.CertChain.Certificates {
			cert, err := x509.ParseCertificate(c.RawBytes)
			if err != nil {
				return fmt.Errorf("%w: timestampAuthorities[%d]: %w", ErrBadTrust, i, err)
			}
			chain = append(chain, cert)
		}
		a, err := newAuthority(ta.URI, chain, ta.ValidFor.Start, ta.ValidFor.End)
		if err != nil {
			return fmt.Errorf("timestampAuthorities[%d]: %w", i, err)
		}
		t.tsas = append(t.tsas, a)
	}
	return nil
}

func (t *Trust) WithWitnesses(vkeys []string, minWitnesses int) (*Trust, error) {
	if minWitnesses < 0 || minWitnesses > len(vkeys) {
		return nil, fmt.Errorf("%w: need %d witnesses but %d keys were given", ErrBadTrust, minWitnesses, len(vkeys))
	}
	out := &Trust{logs: t.logs, tsas: t.tsas, minWitnesses: minWitnesses, requireTime: t.requireTime}
	seen := map[string]bool{}
	for _, k := range vkeys {
		v, err := NewCosignatureVerifier(k)
		if err != nil {
			return nil, err
		}
		cv, ok := v.(*cosignatureVerifier)
		if !ok || seen[string(cv.key)] {
			return nil, fmt.Errorf("%w: witness key %q is listed twice", ErrBadTrust, v.Name())
		}
		seen[string(cv.key)] = true
		out.witnesses = append(out.witnesses, v)
	}
	return out, nil
}

func (t *Trust) Origins() []string {
	out := make([]string, 0, len(t.logs))
	for o := range t.logs {
		out = append(out, o)
	}
	return out
}

func logVerifier(origin string, spki []byte) (note.Verifier, error) {
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("%w: log key: %w", ErrBadTrust, err)
	}
	switch k := key.(type) {
	case ed25519.PublicKey:
		vkey, err := note.NewEd25519VerifierKey(origin, k)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadTrust, err)
		}
		v, err := note.NewVerifier(vkey)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadTrust, err)
		}
		return v, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: ECDSA log key is not P-256", ErrBadTrust)
		}
		sum := sha256.Sum256(spki)
		return &ecdsaVerifier{name: origin, hash: binary.BigEndian.Uint32(sum[:4]), key: k}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported log key type %T", ErrBadTrust, key)
	}
}

type ecdsaVerifier struct {
	name string
	hash uint32
	key  *ecdsa.PublicKey
}

func (v *ecdsaVerifier) Name() string    { return v.name }
func (v *ecdsaVerifier) KeyHash() uint32 { return v.hash }
func (v *ecdsaVerifier) Verify(msg, sig []byte) bool {
	sum := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(v.key, sum[:], sig)
}

type cosignatureVerifier struct {
	name string
	hash uint32
	key  ed25519.PublicKey
}

func CosignatureKeyHash(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', algCosignature})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
}

func NewCosignatureVerifier(vkey string) (note.Verifier, error) {
	name, rest, ok := strings.Cut(vkey, "+")
	if !ok || name == "" {
		return nil, fmt.Errorf("%w: witness key %q", ErrBadTrust, vkey)
	}
	hexHash, b64, ok := strings.Cut(rest, "+")
	if !ok {
		return nil, fmt.Errorf("%w: witness key %q", ErrBadTrust, vkey)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 1+ed25519.PublicKeySize || raw[0] != algCosignature {
		return nil, fmt.Errorf("%w: witness key %q is not an Ed25519 cosignature key", ErrBadTrust, name)
	}
	hash, err := strconv.ParseUint(hexHash, 16, 32)
	pub := ed25519.PublicKey(raw[1:])
	want := CosignatureKeyHash(name, pub)
	if err != nil || hash != uint64(want) {
		return nil, fmt.Errorf("%w: witness key %q has a wrong key hash", ErrBadTrust, name)
	}
	return &cosignatureVerifier{name: name, hash: want, key: pub}, nil
}

func CosignatureVKey(name string, pub ed25519.PublicKey) string {
	return fmt.Sprintf("%s+%08x+%s", name, CosignatureKeyHash(name, pub),
		base64.StdEncoding.EncodeToString(append([]byte{algCosignature}, pub...)))
}

func CosignatureMessage(ts uint64, body []byte) []byte {
	msg := fmt.Appendf(nil, "cosignature/v1\ntime %d\n", ts)
	return append(msg, body...)
}

func (v *cosignatureVerifier) Name() string    { return v.name }
func (v *cosignatureVerifier) KeyHash() uint32 { return v.hash }
func (v *cosignatureVerifier) Verify(msg, sig []byte) bool {
	if len(sig) != 8+ed25519.SignatureSize {
		return false
	}
	ts := binary.BigEndian.Uint64(sig[:8])
	return ed25519.Verify(v.key, CosignatureMessage(ts, msg), sig[8:])
}

func cosignatureTime(sig note.Signature) (time.Time, error) {
	raw, err := base64.StdEncoding.DecodeString(sig.Base64)
	if err != nil || len(raw) != 4+8+ed25519.SignatureSize {
		return time.Time{}, errCosignatureSize
	}
	ts := binary.BigEndian.Uint64(raw[4:12])
	if ts > 1<<62/uint64(time.Second) {
		return time.Time{}, errCosignatureSize
	}
	return time.Unix(int64(ts), 0).UTC(), nil
}

package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

const (
	HeaderType       = "tk-approval+jwt"
	AlgorithmEdDSA   = "EdDSA"
	DefaultHeader    = "X-Tollkeeper-Approval"
	DefaultMaxTTL    = 15 * time.Minute
	DefaultClockSkew = 30 * time.Second
	digestPrefix     = "sha256:"
	maxTokenBytes    = 16 << 10
)

var (
	ErrMalformed         = errors.New("malformed approval token")
	ErrUntrustedKey      = errors.New("approval token signed by untrusted key")
	ErrInvalidSignature  = errors.New("invalid approval token signature")
	ErrExpired           = errors.New("approval token expired or not yet valid")
	ErrTTLTooLong        = errors.New("approval token lifetime exceeds maximum allowed ttl")
	ErrAudienceMismatch  = errors.New("approval token audience mismatch")
	ErrIssuerMismatch    = errors.New("approval token issuer mismatch")
	ErrSubjectMismatch   = errors.New("approval token subject mismatch")
	ErrTenantMismatch    = errors.New("approval token tenant mismatch")
	ErrOperationMismatch = errors.New("approval token does not cover this tool and arguments")
	ErrReplayed          = errors.New("approval token already used")
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

type BatchItem struct {
	Tool     string `json:"tool"`
	ArgsHash string `json:"args_hash"`
}

type Claims struct {
	JTI       string      `json:"jti"`
	Issuer    string      `json:"iss,omitempty"`
	Audience  string      `json:"aud"`
	Subject   string      `json:"sub"`
	Tenant    string      `json:"tenant,omitempty"`
	Approver  string      `json:"approver"`
	Tool      string      `json:"tool,omitempty"`
	ArgsHash  string      `json:"args_hash,omitempty"`
	Batch     []BatchItem `json:"batch,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	IssuedAt  int64       `json:"iat"`
	ExpiresAt int64       `json:"exp"`
}

type KeySet struct {
	keys  []ed25519.PublicKey
	byKID map[string]ed25519.PublicKey
}

func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func NewKeySet(keys ...ed25519.PublicKey) (*KeySet, error) {
	ks := &KeySet{byKID: make(map[string]ed25519.PublicKey, len(keys))}
	for _, k := range keys {
		if err := ks.Add(k); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

func (ks *KeySet) Add(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid ed25519 public key length", ErrMalformed)
	}
	kid := KeyID(pub)
	if _, exists := ks.byKID[kid]; exists {
		return nil
	}
	ks.byKID[kid] = pub
	ks.keys = append(ks.keys, pub)
	return nil
}

func (ks *KeySet) Len() int {
	if ks == nil {
		return 0
	}
	return len(ks.keys)
}

func LoadKeySet(files []string, dir string) (*KeySet, error) {
	ks, err := NewKeySet()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		pub, lerr := audit.LoadPublicKey(f)
		if lerr != nil {
			return nil, fmt.Errorf("approval pubkey %s: %w", f, lerr)
		}
		if aerr := ks.Add(pub); aerr != nil {
			return nil, aerr
		}
	}
	if dir != "" {
		if derr := loadDirKeys(ks, dir); derr != nil {
			return nil, derr
		}
	}
	if ks.Len() == 0 {
		return nil, fmt.Errorf("no approval public keys loaded: %w", ErrUntrustedKey)
	}
	return ks, nil
}

func loadDirKeys(ks *KeySet, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read approval pubkey_dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".pub" && ext != ".pem" {
			continue
		}
		pub, lerr := audit.LoadPublicKey(filepath.Join(dir, e.Name()))
		if lerr != nil {
			return fmt.Errorf("approval pubkey %s: %w", e.Name(), lerr)
		}
		if aerr := ks.Add(pub); aerr != nil {
			return aerr
		}
	}
	return nil
}

func CanonicalArgsHash(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		trimmed = []byte("{}")
	}
	var v any
	if err := json.Unmarshal(trimmed, &v); err == nil {
		if canon, merr := json.Marshal(v); merr == nil {
			trimmed = canon
		}
	}
	sum := sha256.Sum256(trimmed)
	return digestPrefix + hex.EncodeToString(sum[:])
}

func GenerateID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "apr_" + hex.EncodeToString(b[:])
}

func Sign(priv ed25519.PrivateKey, claims Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: invalid ed25519 private key", ErrMalformed)
	}
	if claims.JTI == "" {
		claims.JTI = GenerateID()
	}
	if err := validateSignClaims(&claims); err != nil {
		return "", err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("%w: invalid ed25519 public key", ErrMalformed)
	}
	hdrBytes, err := json.Marshal(Header{Alg: AlgorithmEdDSA, Typ: HeaderType, Kid: KeyID(pub)})
	if err != nil {
		return "", fmt.Errorf("marshal approval header: %w", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal approval claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func validateSignClaims(c *Claims) error {
	if strings.TrimSpace(c.Approver) == "" {
		return fmt.Errorf("%w: approver is required", ErrMalformed)
	}
	if strings.TrimSpace(c.Audience) == "" {
		return fmt.Errorf("%w: aud is required", ErrMalformed)
	}
	if c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt {
		return fmt.Errorf("%w: iat and exp must define a positive window", ErrMalformed)
	}
	hasSingle := c.Tool != "" && c.ArgsHash != ""
	hasBatch := len(c.Batch) > 0
	if hasSingle == hasBatch {
		return fmt.Errorf("%w: specify either tool+args_hash or batch items", ErrMalformed)
	}
	for i := range c.Batch {
		if c.Batch[i].Tool == "" || !strings.HasPrefix(c.Batch[i].ArgsHash, digestPrefix) {
			return fmt.Errorf("%w: batch[%d] requires tool and sha256 args_hash", ErrMalformed, i)
		}
	}
	return nil
}

type VerifierOptions struct {
	Keys      *KeySet
	Issuer    string
	Audience  string
	MaxTTL    time.Duration
	ClockSkew time.Duration
	Now       func() time.Time
}

type Verifier struct {
	keys      *KeySet
	issuer    string
	audience  string
	maxTTL    time.Duration
	clockSkew time.Duration
	now       func() time.Time
}

func NewVerifier(opts VerifierOptions) *Verifier {
	if opts.MaxTTL <= 0 {
		opts.MaxTTL = DefaultMaxTTL
	}
	if opts.ClockSkew < 0 {
		opts.ClockSkew = DefaultClockSkew
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Verifier{
		keys:      opts.Keys,
		issuer:    opts.Issuer,
		audience:  opts.Audience,
		maxTTL:    opts.MaxTTL,
		clockSkew: opts.ClockSkew,
		now:       opts.Now,
	}
}

type VerifyRequest struct {
	Token   string
	Subject string
	Tenant  string
	Tool    string
	Args    json.RawMessage
}

type Verified struct {
	ID        string
	Approver  string
	Reason    string
	ArgsHash  string
	ExpiresAt time.Time
}

type parsedToken struct {
	hdr          Header
	claims       Claims
	signingInput string
	sig          []byte
}

func (v *Verifier) Verify(req VerifyRequest) (Verified, error) {
	if v == nil || v.keys == nil || v.keys.Len() == 0 {
		return Verified{}, ErrUntrustedKey
	}
	pt, err := parseCompact(req.Token)
	if err != nil {
		return Verified{}, err
	}
	if err := v.verifySignature(pt.hdr.Kid, pt.signingInput, pt.sig); err != nil {
		return Verified{}, err
	}
	if err := v.validateClaims(&pt.claims, req.Subject, req.Tenant); err != nil {
		return Verified{}, err
	}
	argsHash := CanonicalArgsHash(req.Args)
	if !matchOperation(&pt.claims, req.Tool, argsHash) {
		return Verified{}, ErrOperationMismatch
	}
	return Verified{
		ID:        pt.claims.JTI,
		Approver:  pt.claims.Approver,
		Reason:    pt.claims.Reason,
		ArgsHash:  argsHash,
		ExpiresAt: time.Unix(pt.claims.ExpiresAt, 0),
	}, nil
}

func parseCompact(tok string) (parsedToken, error) {
	tok = strings.TrimSpace(tok)
	if tok == "" || len(tok) > maxTokenBytes {
		return parsedToken{}, ErrMalformed
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return parsedToken{}, ErrMalformed
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return parsedToken{}, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	var hdr Header
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return parsedToken{}, fmt.Errorf("%w: header json", ErrMalformed)
	}
	if hdr.Alg != AlgorithmEdDSA || hdr.Typ != HeaderType {
		return parsedToken{}, fmt.Errorf("%w: unsupported alg or typ", ErrMalformed)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return parsedToken{}, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return parsedToken{}, fmt.Errorf("%w: payload json", ErrMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return parsedToken{}, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	return parsedToken{
		hdr:          hdr,
		claims:       claims,
		signingInput: parts[0] + "." + parts[1],
		sig:          sig,
	}, nil
}

func (v *Verifier) verifySignature(kid, signingInput string, sig []byte) error {
	if kid != "" {
		pub, ok := v.keys.byKID[kid]
		if !ok {
			return ErrUntrustedKey
		}
		if !ed25519.Verify(pub, []byte(signingInput), sig) {
			return ErrInvalidSignature
		}
		return nil
	}
	for _, pub := range v.keys.keys {
		if ed25519.Verify(pub, []byte(signingInput), sig) {
			return nil
		}
	}
	return ErrInvalidSignature
}

func (v *Verifier) validateClaims(c *Claims, subject, tenant string) error {
	if strings.TrimSpace(c.JTI) == "" || strings.TrimSpace(c.Approver) == "" {
		return fmt.Errorf("%w: missing jti or approver", ErrMalformed)
	}
	if c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt {
		return ErrExpired
	}
	if time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > v.maxTTL {
		return ErrTTLTooLong
	}
	now := v.now().Unix()
	skew := int64(v.clockSkew / time.Second)
	if now > c.ExpiresAt+skew || now < c.IssuedAt-skew {
		return ErrExpired
	}
	if v.issuer != "" && c.Issuer != v.issuer {
		return ErrIssuerMismatch
	}
	if v.audience != "" && c.Audience != v.audience {
		return ErrAudienceMismatch
	}
	if c.Subject != subject {
		return ErrSubjectMismatch
	}
	if (c.Tenant != "" || tenant != "") && c.Tenant != tenant {
		return ErrTenantMismatch
	}
	return nil
}

func matchOperation(c *Claims, tool, argsHash string) bool {
	if c.Tool != "" && c.ArgsHash != "" {
		return c.Tool == tool && subtle.ConstantTimeCompare([]byte(c.ArgsHash), []byte(argsHash)) == 1
	}
	for i := range c.Batch {
		if c.Batch[i].Tool == tool && subtle.ConstantTimeCompare([]byte(c.Batch[i].ArgsHash), []byte(argsHash)) == 1 {
			return true
		}
	}
	return false
}

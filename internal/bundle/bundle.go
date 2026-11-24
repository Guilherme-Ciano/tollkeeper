package bundle

import (
	"crypto/ed25519"
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
	Version       = 1
	payloadPrefix = "tollkeeper-bundle-v1\n"
	digestPrefix  = "sha256:"
	fileKeyConfig = "config"
	fileKeyPins   = "pins"
)

var (
	ErrMalformed        = errors.New("malformed bundle manifest")
	ErrUntrustedKey     = errors.New("bundle signed by untrusted key")
	ErrInvalidSignature = errors.New("invalid bundle signature")
	ErrExpired          = errors.New("bundle manifest expired")
	ErrDigestMismatch   = errors.New("bundle file digest mismatch")
	ErrMissingPins      = errors.New("bundle requires pins file digest")
)

type Manifest struct {
	Version   int               `json:"version"`
	BundleID  string            `json:"bundle_id"`
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Files     map[string]string `json:"files"`
	KeyID     string            `json:"key_id"`
	Signature string            `json:"signature"`
}

type signingBody struct {
	Version   int               `json:"version"`
	BundleID  string            `json:"bundle_id"`
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Files     map[string]string `json:"files"`
	KeyID     string            `json:"key_id"`
}

type SignOptions struct {
	BundleID   string
	ConfigPath string
	PinsPath   string
	TTL        time.Duration
	Now        func() time.Time
}

type VerifyOptions struct {
	ManifestPath string
	ConfigPath   string
	ConfigDigest string
	PinsPath     string
	RequirePins  bool
	Keys         []ed25519.PublicKey
	Now          func() time.Time
}

type Result struct {
	BundleID     string
	KeyID        string
	ConfigDigest string
	PinsDigest   string
	VerifiedAt   time.Time
}

func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func FileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return digestPrefix + hex.EncodeToString(sum[:]), nil
}

func canonicalPayload(m *Manifest) ([]byte, error) {
	body := signingBody{
		Version:   m.Version,
		BundleID:  m.BundleID,
		CreatedAt: m.CreatedAt.UTC(),
		Files:     m.Files,
		KeyID:     m.KeyID,
	}
	if m.ExpiresAt != nil {
		exp := m.ExpiresAt.UTC()
		body.ExpiresAt = &exp
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal bundle payload: %w", err)
	}
	out := make([]byte, 0, len(payloadPrefix)+len(b))
	out = append(out, payloadPrefix...)
	out = append(out, b...)
	return out, nil
}

func Sign(priv ed25519.PrivateKey, opts SignOptions) (*Manifest, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid ed25519 private key", ErrMalformed)
	}
	if strings.TrimSpace(opts.ConfigPath) == "" {
		return nil, fmt.Errorf("%w: config path is required", ErrMalformed)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: invalid ed25519 public key", ErrMalformed)
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC().Truncate(time.Second)
	cfgDigest, err := FileDigest(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	files := map[string]string{fileKeyConfig: cfgDigest}
	if strings.TrimSpace(opts.PinsPath) != "" {
		pinsDigest, perr := FileDigest(opts.PinsPath)
		if perr != nil {
			return nil, perr
		}
		files[fileKeyPins] = pinsDigest
	}
	id := strings.TrimSpace(opts.BundleID)
	if id == "" {
		id = "bundle-" + now.Format("20060102T150405Z")
	}
	m := &Manifest{
		Version:   Version,
		BundleID:  id,
		CreatedAt: now,
		Files:     files,
		KeyID:     KeyID(pub),
	}
	if opts.TTL > 0 {
		exp := now.Add(opts.TTL).UTC().Truncate(time.Second)
		m.ExpiresAt = &exp
	}
	payload, err := canonicalPayload(m)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, payload)
	m.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return m, nil
}

func WriteManifest(path string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bundle manifest: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write bundle manifest: %w", err)
	}
	return nil
}

func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return &m, nil
}

func LoadPublicKeys(files []string, dir string) ([]ed25519.PublicKey, error) {
	seen := map[string]bool{}
	var out []ed25519.PublicKey
	addKey := func(pub ed25519.PublicKey) {
		kid := KeyID(pub)
		if !seen[kid] {
			seen[kid] = true
			out = append(out, pub)
		}
	}
	for _, f := range files {
		pub, err := audit.LoadPublicKey(f)
		if err != nil {
			return nil, fmt.Errorf("bundle pubkey %s: %w", f, err)
		}
		addKey(pub)
	}
	if dir != "" {
		if err := loadDirPublicKeys(dir, addKey); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no bundle public keys loaded: %w", ErrUntrustedKey)
	}
	return out, nil
}

func loadDirPublicKeys(dir string, addKey func(ed25519.PublicKey)) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read bundle pubkey_dir: %w", err)
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
			return fmt.Errorf("bundle pubkey %s: %w", e.Name(), lerr)
		}
		addKey(pub)
	}
	return nil
}

func Verify(opts VerifyOptions) (Result, error) {
	if len(opts.Keys) == 0 {
		return Result{}, ErrUntrustedKey
	}
	m, err := LoadManifest(opts.ManifestPath)
	if err != nil {
		return Result{}, err
	}
	if err := verifyManifestHeaderAndSig(m, opts.Keys); err != nil {
		return Result{}, err
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC()
	if m.ExpiresAt != nil && now.After(m.ExpiresAt.UTC()) {
		return Result{}, ErrExpired
	}
	cfgDigest, err := verifyConfigDigest(m, opts.ConfigPath, opts.ConfigDigest)
	if err != nil {
		return Result{}, err
	}
	pinsDigest, err := verifyPinsDigest(m, opts.PinsPath, opts.RequirePins)
	if err != nil {
		return Result{}, err
	}
	return Result{
		BundleID:     m.BundleID,
		KeyID:        m.KeyID,
		ConfigDigest: cfgDigest,
		PinsDigest:   pinsDigest,
		VerifiedAt:   now,
	}, nil
}

func verifyManifestHeaderAndSig(m *Manifest, keys []ed25519.PublicKey) error {
	if m.Version != Version || strings.TrimSpace(m.BundleID) == "" || len(m.Files) == 0 {
		return ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid signature encoding", ErrMalformed)
	}
	payload, err := canonicalPayload(m)
	if err != nil {
		return err
	}
	matchedKID := false
	for _, pub := range keys {
		if m.KeyID != "" && KeyID(pub) != m.KeyID {
			continue
		}
		matchedKID = true
		if ed25519.Verify(pub, payload, sig) {
			return nil
		}
	}
	if m.KeyID != "" && !matchedKID {
		return ErrUntrustedKey
	}
	return ErrInvalidSignature
}

func verifyConfigDigest(m *Manifest, configPath, configDigest string) (string, error) {
	want := m.Files[fileKeyConfig]
	if !strings.HasPrefix(want, digestPrefix) {
		return "", fmt.Errorf("%w: missing config digest", ErrMalformed)
	}
	got := configDigest
	if got == "" {
		var err error
		got, err = FileDigest(configPath)
		if err != nil {
			return "", err
		}
	} else if !strings.HasPrefix(got, digestPrefix) {
		got = digestPrefix + got
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return "", fmt.Errorf("%w: config file does not match signed manifest", ErrDigestMismatch)
	}
	return got, nil
}

func verifyPinsDigest(m *Manifest, pinsPath string, requirePins bool) (string, error) {
	want := m.Files[fileKeyPins]
	if want == "" {
		if requirePins {
			return "", ErrMissingPins
		}
		return "", nil
	}
	if strings.TrimSpace(pinsPath) == "" {
		return "", fmt.Errorf("%w: manifest pins digest set but no pins path supplied", ErrMissingPins)
	}
	got, err := FileDigest(pinsPath)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return "", fmt.Errorf("%w: pins file does not match signed manifest", ErrDigestMismatch)
	}
	return got, nil
}

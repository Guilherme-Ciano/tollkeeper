package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

func TestBundleSignVerifyAndTamperDetection(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privPEM, pubPEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPubPEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := audit.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "bundle.pub")
	otherPubPath := filepath.Join(dir, "other.pub")
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPubPath, otherPubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "gateway.yaml")
	pinsPath := filepath.Join(dir, "pins.json")
	manifestPath := filepath.Join(dir, "bundle.sig.json")
	if err := os.WriteFile(cfgPath, []byte("policy:\n  default: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinsPath, []byte(`{"version":1,"tools":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	m, err := Sign(priv, SignOptions{
		BundleID:   "prod-r1",
		ConfigPath: cfgPath,
		PinsPath:   pinsPath,
		TTL:        24 * time.Hour,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(manifestPath, m); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadPublicKeys([]string{pubPath}, "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(VerifyOptions{
		ManifestPath: manifestPath,
		ConfigPath:   cfgPath,
		PinsPath:     pinsPath,
		RequirePins:  true,
		Keys:         keys,
		Now:          func() time.Time { return now.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("expected valid bundle, got %v", err)
	}
	if res.BundleID != "prod-r1" || res.ConfigDigest == "" || res.PinsDigest == "" {
		t.Fatalf("unexpected bundle result: %+v", res)
	}

	otherKeys, err := LoadPublicKeys([]string{otherPubPath}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(VerifyOptions{
		ManifestPath: manifestPath,
		ConfigPath:   cfgPath,
		PinsPath:     pinsPath,
		Keys:         otherKeys,
		Now:          func() time.Time { return now },
	}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("expected ErrUntrustedKey, got %v", err)
	}

	if _, err := Verify(VerifyOptions{
		ManifestPath: manifestPath,
		ConfigPath:   cfgPath,
		PinsPath:     pinsPath,
		Keys:         keys,
		Now:          func() time.Time { return now.Add(25 * time.Hour) },
	}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}

	if err := os.WriteFile(pinsPath, []byte(`{"version":1,"tools":{"evil":"1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(VerifyOptions{
		ManifestPath: manifestPath,
		ConfigPath:   cfgPath,
		PinsPath:     pinsPath,
		Keys:         keys,
		Now:          func() time.Time { return now },
	}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch for tampered pins, got %v", err)
	}

	if err := os.WriteFile(cfgPath, []byte("policy:\n  default: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(VerifyOptions{
		ManifestPath: manifestPath,
		ConfigPath:   cfgPath,
		PinsPath:     pinsPath,
		Keys:         keys,
		Now:          func() time.Time { return now },
	}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch for tampered config, got %v", err)
	}
}

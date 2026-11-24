package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

func TestBundleEdgeCasesDirLoadingAndDigestModes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(filepath.Join(keyDir, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	privPEM, pubPEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := audit.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "k1.pub"), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "k1_dup.pem"), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "readme.txt"), []byte("ignore"), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadPublicKeys(nil, keyDir)
	if err != nil || len(keys) != 1 {
		t.Fatalf("LoadPublicKeys dir dedupe failed: len=%d err=%v", len(keys), err)
	}

	if _, err := LoadPublicKeys(nil, filepath.Join(dir, "no-such-dir")); err == nil {
		t.Fatal("expected error for missing pubkey dir")
	}
	emptyDir := filepath.Join(dir, "empty")
	if err := os.MkdirAll(emptyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKeys(nil, emptyDir); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("expected ErrUntrustedKey for empty dir, got %v", err)
	}

	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte("policy:\n  default: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(ed25519.PrivateKey("bad"), SignOptions{ConfigPath: cfgPath}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed for short privkey, got %v", err)
	}
	if _, err := Sign(priv, SignOptions{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed for missing config path, got %v", err)
	}
	if _, err := Sign(priv, SignOptions{ConfigPath: filepath.Join(dir, "missing.yaml")}); err == nil {
		t.Fatal("expected error for missing config file")
	}

	m, err := Sign(priv, SignOptions{ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.BundleID, "bundle-") {
		t.Fatalf("expected auto-generated bundle ID, got %q", m.BundleID)
	}
	manifestPath := filepath.Join(dir, "bundle.sig.json")
	if err := WriteManifest(manifestPath, m); err != nil {
		t.Fatal(err)
	}

	rawHex := strings.TrimPrefix(m.Files[fileKeyConfig], digestPrefix)
	res, err := Verify(VerifyOptions{
		ManifestPath: manifestPath,
		ConfigDigest: rawHex,
		Keys:         keys,
	})
	if err != nil || res.BundleID != m.BundleID {
		t.Fatalf("verify with raw hex ConfigDigest failed: res=%+v err=%v", res, err)
	}

	if _, err := Verify(VerifyOptions{
		ManifestPath: manifestPath,
		ConfigDigest: rawHex,
		RequirePins:  true,
		Keys:         keys,
	}); !errors.Is(err, ErrMissingPins) {
		t.Fatalf("expected ErrMissingPins when RequirePins=true without pins in manifest, got %v", err)
	}

	if _, err := Verify(VerifyOptions{ManifestPath: manifestPath}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("expected ErrUntrustedKey with empty keys, got %v", err)
	}

	badSig := *m
	badSig.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	badSigPath := filepath.Join(dir, "badsig.json")
	if err := WriteManifest(badSigPath, &badSig); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(
		VerifyOptions{ManifestPath: badSigPath, ConfigPath: cfgPath, Keys: keys},
	); !errors.Is(
		err,
		ErrInvalidSignature,
	) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}

	badJSONPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSONPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(badJSONPath); !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed for invalid json manifest, got %v", err)
	}

	badVerPath := filepath.Join(dir, "badver.json")
	rawBadVer, err := json.Marshal(
		Manifest{Version: 99, BundleID: "x", Files: map[string]string{"config": "sha256:aa"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badVerPath, rawBadVer, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(
		VerifyOptions{ManifestPath: badVerPath, ConfigPath: cfgPath, Keys: keys},
	); !errors.Is(
		err,
		ErrMalformed,
	) {
		t.Fatalf("expected ErrMalformed for bad version, got %v", err)
	}
}

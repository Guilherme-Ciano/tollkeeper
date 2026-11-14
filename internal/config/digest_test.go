package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRecordsDigestOfRawFile(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose", "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	lookup := func(string) (string, bool) { return "placeholder", true }
	cfg, err := Load(path, lookup)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if want := hex.EncodeToString(sum[:]); cfg.Digest != want {
		t.Fatalf("Digest = %s, want %s", cfg.Digest, want)
	}
	if Digest(append(raw, '\n')) == cfg.Digest {
		t.Fatal("digest must change when the file changes")
	}
}

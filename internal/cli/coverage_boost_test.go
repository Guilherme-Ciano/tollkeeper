package cli

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func execCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cmd := Root(BuildInfo{Version: "1.7.0", Commit: "abc1234", Date: "2026-11-24"}, &outBuf, &errBuf)
	cmd.SetArgs(args)
	err = cmd.ExecuteContext(t.Context())
	return outBuf.String(), errBuf.String(), err
}

func TestVersionKeygenHealthAndKeySetHelpers(t *testing.T) {
	t.Parallel()
	out, _, err := execCLI(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(out, "1.7.0") {
		t.Fatalf("unexpected version output: %q", out)
	}

	dir := t.TempDir()
	keyDir := filepath.Join(dir, "audit-keys")
	out, _, err = execCLI(t, "audit", "keygen", "-o", keyDir)
	if err != nil {
		t.Fatalf("audit keygen: %v", err)
	}
	if !strings.Contains(out, "wrote ") {
		t.Fatalf("unexpected keygen output: %q", out)
	}

	if _, _, err := execCLI(t, "audit", "keygen", "-o", keyDir); err == nil {
		t.Fatal("expected second audit keygen without --if-missing to fail")
	}

	out, _, err = execCLI(t, "audit", "keygen", "-o", keyDir, "--if-missing")
	if err != nil || !strings.Contains(out, "keeping it") {
		t.Fatalf("audit keygen --if-missing: out=%q err=%v", out, err)
	}

	pubPath := filepath.Join(keyDir, "audit-ed25519.pub")
	pubDir := filepath.Join(dir, "audit-pubs")
	if err := os.MkdirAll(pubDir, 0o755); err != nil {
		t.Fatalf("mkdir pubDir: %v", err)
	}
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pubDir, "audit-ed25519.pub"), pubBytes, 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	if ks, err := loadCLIKeySet(pubPath, ""); err != nil || ks == nil {
		t.Fatalf("loadCLIKeySet single: err=%v", err)
	}
	if ks, err := loadCLIKeySet("", pubDir); err != nil || ks == nil {
		t.Fatalf("loadCLIKeySet dir: err=%v", err)
	}
	if ks, err := loadCLIKeySet(pubPath, pubDir); err != nil || ks == nil {
		t.Fatalf("loadCLIKeySet combined: err=%v", err)
	}
	if _, err := loadCLIKeySet("", ""); !errors.Is(err, ErrVerify) {
		t.Fatalf("expected ErrVerify for empty keyset args, got %v", err)
	}

	if _, err := openVerifySource(verifyOpts{file: filepath.Join(dir, "missing.jsonl")}); err == nil {
		t.Fatal("expected error for missing audit file")
	}
	if _, err := openVerifySource(verifyOpts{postgres: "postgres://localhost/db"}); !errors.Is(err, ErrChainRequired) {
		t.Fatalf("expected ErrChainRequired, got %v", err)
	}
	var buf bytes.Buffer
	if err := runVerifyAllChains(&buf, verifyOpts{}); !errors.Is(err, ErrVerify) {
		t.Fatalf("expected ErrVerify without --postgres, got %v", err)
	}
	if err := runVerifyAllChains(
		&buf,
		verifyOpts{postgres: "postgres://localhost/db", chainID: "c1"},
	); !errors.Is(
		err,
		ErrVerify,
	) {
		t.Fatalf("expected ErrVerify with both --all-chains and --chain-id, got %v", err)
	}
}

func TestHealthcheckCommand(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if _, _, err := execCLI(t, "healthcheck", "--url", srv.URL+"/readyz"); err != nil {
		t.Fatalf("healthcheck 200: %v", err)
	}
	if _, _, err := execCLI(t, "healthcheck", "--url", srv.URL+"/fail"); !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("expected ErrUnhealthy on 503, got %v", err)
	}
	if _, _, err := execCLI(t, "healthcheck", "--url", "://bad-url"); err == nil {
		t.Fatal("expected error on bad URL")
	}
}

func TestConfigValidateWarningsAndPolicyExplain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "tollkeeper.yaml")
	cfgYAML := `
server:
  listen: 127.0.0.1:8080
  admin_listen: 127.0.0.1:9090
  public_url: http://127.0.0.1:8080/mcp
auth:
  mode: none
upstreams:
  - id: notes
    transport: streamable_http
    url: http://127.0.0.1:18080/mcp
policy:
  default: deny
  rules:
    - name: allow-read
      tools: ["notes__read"]
      effect: allow
    - name: allow-prompt
      prompts: ["notes__sum"]
      effect: allow
    - name: allow-res
      resources: ["file:///docs/*"]
      effect: allow
pinning:
  mode: off
audit:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	out, errOut, err := execCLI(t, "config", "validate", "-c", cfgPath)
	if err != nil {
		t.Fatalf("config validate: %v (stderr=%s)", err, errOut)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected OK output, got %q", out)
	}

	out, _, err = execCLI(t, "policy", "explain", "-c", cfgPath, "--tool", "notes__read", "--sub", "alice")
	if err != nil || !strings.Contains(out, "allow") {
		t.Fatalf("policy explain tool: out=%q err=%v", out, err)
	}

	out, _, err = execCLI(t, "policy", "explain", "-c", cfgPath, "--prompt", "notes__sum", "--sub", "alice")
	if err != nil || !strings.Contains(out, "allow") {
		t.Fatalf("policy explain prompt: out=%q err=%v", out, err)
	}

	out, _, err = execCLI(t, "policy", "explain", "-c", cfgPath, "--resource", "file:///docs/a.md", "--sub", "alice")
	if err != nil || !strings.Contains(out, "allow") {
		t.Fatalf("policy explain resource: out=%q err=%v", out, err)
	}

	approvalKeys := filepath.Join(dir, "approval-keys")
	if _, _, err := execCLI(t, "approval", "keygen", "-o", approvalKeys); err != nil {
		t.Fatalf("approval keygen: %v", err)
	}
	out, _, err = execCLI(t, "approval", "keygen", "-o", approvalKeys, "--if-missing")
	if err != nil || !strings.Contains(out, "keeping") {
		t.Fatalf("approval keygen --if-missing: out=%q err=%v", out, err)
	}

	bundleKeys := filepath.Join(dir, "bundle-keys")
	if _, _, err := execCLI(t, "bundle", "keygen", "-o", bundleKeys); err != nil {
		t.Fatalf("bundle keygen: %v", err)
	}
	out, _, err = execCLI(t, "bundle", "keygen", "-o", bundleKeys, "--if-missing")
	if err != nil || !strings.Contains(out, "keeping") {
		t.Fatalf("bundle keygen --if-missing: out=%q err=%v", out, err)
	}

	manifestPath := filepath.Join(dir, "bundle.json")
	if _, _, err := execCLI(t, "bundle", "sign",
		"--key", filepath.Join(bundleKeys, "bundle-ed25519.pem"),
		"--config", cfgPath,
		"--out", manifestPath,
		"--id", "test-1",
	); err != nil {
		t.Fatalf("bundle sign: %v", err)
	}
	bundlePubDir := filepath.Join(dir, "bundle-pubs")
	if err := os.MkdirAll(bundlePubDir, 0o755); err != nil {
		t.Fatalf("mkdir bundlePubDir: %v", err)
	}
	bPubBytes, err := os.ReadFile(filepath.Join(bundleKeys, "bundle-ed25519.pub"))
	if err != nil {
		t.Fatalf("read bundle pub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundlePubDir, "bundle-ed25519.pub"), bPubBytes, 0o600); err != nil {
		t.Fatalf("write bundle pub: %v", err)
	}
	if _, _, err := execCLI(t, "bundle", "verify",
		"--manifest", manifestPath,
		"--config", cfgPath,
		"--pubkey-dir", bundlePubDir,
	); err != nil {
		t.Fatalf("bundle verify --pubkey-dir: %v", err)
	}
}

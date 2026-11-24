package cli

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/app"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root := Root(BuildInfo{Version: "test"}, &stdout, &stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(t.Context())
	return stdout.String(), err
}

func TestApprovalCLIFlow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := runCLI(t, "approval", "keygen", "-o", dir); err != nil {
		t.Fatalf("approval keygen: %v", err)
	}
	priv := filepath.Join(dir, "approval-ed25519.pem")
	pub := filepath.Join(dir, "approval-ed25519.pub")

	out, err := runCLI(
		t,
		"approval", "sign",
		"--key", priv,
		"--approver", "bob@corp.com",
		"--aud", "https://gw.example.com/mcp",
		"--sub", "alice",
		"--tool", "files__delete_file",
		"--args", `{"path":"/tmp/x"}`,
		"--ttl", "5m",
	)
	if err != nil {
		t.Fatalf("approval sign: %v", err)
	}
	tok := strings.TrimSpace(out)

	verifyOut, err := runCLI(
		t,
		"approval", "verify",
		"--token", tok,
		"--pubkey", pub,
		"--aud", "https://gw.example.com/mcp",
		"--sub", "alice",
		"--tool", "files__delete_file",
		"--args", `{"path":"/tmp/x"}`,
	)
	if err != nil {
		t.Fatalf("approval verify: %v", err)
	}
	if !strings.Contains(verifyOut, "OK ") || !strings.Contains(verifyOut, "approver=bob@corp.com") {
		t.Fatalf("unexpected verify output: %s", verifyOut)
	}

	if _, err := runCLI(
		t,
		"approval", "verify",
		"--token", tok,
		"--pubkey", pub,
		"--aud", "https://gw.example.com/mcp",
		"--sub", "alice",
		"--tool", "files__delete_file",
		"--args", `{"path":"/etc/shadow"}`,
	); err == nil {
		t.Fatal("expected verify failure for tampered arguments")
	}
}

func TestBundleCLIAndAppStartupReloadEnforcement(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := runCLI(t, "bundle", "keygen", "-o", dir); err != nil {
		t.Fatalf("bundle keygen: %v", err)
	}
	priv := filepath.Join(dir, "bundle-ed25519.pem")
	pub := filepath.Join(dir, "bundle-ed25519.pub")
	manifest := filepath.Join(dir, "bundle.sig.json")
	cfgPath := filepath.Join(dir, "gateway.yaml")

	cfgYAML := "server:\n  listen: 127.0.0.1:0\n  admin_listen: 127.0.0.1:0\n  public_url: http://127.0.0.1:8080/mcp\n" +
		"auth:\n  mode: none\n" +
		"audit:\n  enabled: false\n" +
		"upstreams:\n  - id: demo\n    transport: streamable_http\n    url: http://127.0.0.1:19999/mcp\n" +
		"policy:\n  default: deny\n" +
		"bundle:\n  enabled: true\n  manifest_file: " + filepath.ToSlash(
		manifest,
	) + "\n" +
		"  pubkey_files:\n    - " + filepath.ToSlash(
		pub,
	) + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := runCLI(
		t,
		"bundle",
		"sign",
		"--key",
		priv,
		"-c",
		cfgPath,
		"--id",
		"rel-1",
		"-o",
		manifest,
	); err != nil {
		t.Fatalf("bundle sign: %v", err)
	}
	verifyOut, err := runCLI(t, "bundle", "verify", "--manifest", manifest, "--pubkey", pub, "-c", cfgPath)
	if err != nil {
		t.Fatalf("bundle verify: %v", err)
	}
	if !strings.Contains(verifyOut, "OK bundle=rel-1") {
		t.Fatalf("unexpected bundle verify output: %s", verifyOut)
	}

	cfg, err := config.Load(cfgPath, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.Build(t.Context(), cfg, slog.New(slog.DiscardHandler), "test")
	if err != nil {
		t.Fatalf("app.Build with valid signed bundle failed: %v", err)
	}

	tamperedYAML := strings.Replace(cfgYAML, "default: deny", "default: allow", 1)
	if err := os.WriteFile(cfgPath, []byte(tamperedYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedCfg, err := config.Load(cfgPath, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(t.Context(), tamperedCfg); err == nil {
		t.Fatal("Reload must reject unsigned tampered config when bundle enforcement is active")
	}

	if _, err := app.Build(t.Context(), tamperedCfg, slog.New(slog.DiscardHandler), "test"); err == nil {
		t.Fatal("app.Build must fail closed for tampered config")
	}

	if _, err := runCLI(
		t,
		"bundle",
		"sign",
		"--key",
		priv,
		"-c",
		cfgPath,
		"--id",
		"rel-2",
		"-o",
		manifest,
	); err != nil {
		t.Fatalf("re-sign bundle: %v", err)
	}
	if err := a.Reload(t.Context(), tamperedCfg); err != nil {
		t.Fatalf("Reload with freshly signed bundle should succeed: %v", err)
	}
}

package app

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor/rekortest"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func anchoredConfig(t *testing.T, upURL string, s *rekortest.Server) (cfg config.Config, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	priv, pub, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath, rootPath := filepath.Join(dir, "k.pem"), filepath.Join(dir, "trusted_root.json")
	pubPath = filepath.Join(dir, "k.pub")
	for p, b := range map[string][]byte{keyPath: priv, pubPath: pub, rootPath: s.TrustedRootJSON()} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg = testConfig(t, upURL)
	cfg.RateLimits.Rules = nil
	cfg.Audit.Checkpoint = config.Checkpoint{Every: 2, SigningKeyFile: keyPath}
	cfg.Audit.Anchor = config.AuditAnchor{
		Enabled: true, RekorURL: s.URL, TrustFiles: []string{rootPath}, Every: 1,
		Timeout: 20 * time.Second, MaxBackoff: time.Second, Required: true,
	}
	if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "audit.") {
		t.Fatal(err)
	}
	return cfg, pubPath
}

func TestAnchoringWiredFromConfig(t *testing.T) {
	s := rekortest.New(t)
	cfg, pubPath := anchoredConfig(t, fakeUpstream(t, &headerLog{}).URL, s)
	url := startApp(t, cfg)
	cs := connect(t, url, "")
	for range 3 {
		if _, err := cs.CallTool(t.Context(),
			&mcp.CallToolParams{Name: "fake__echo", Arguments: map[string]any{"text": "x"}}); err != nil {
			t.Fatal(err)
		}
	}
	pub, err := audit.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := anchor.ParseTrust(s.TrustedRootJSON(), "")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var rep audit.Report
	for time.Now().Before(deadline) {
		f, err := os.Open(cfg.Audit.Path)
		if err != nil {
			t.Fatal(err)
		}
		rep, err = audit.VerifyWith(f, audit.VerifyOptions{PublicKey: pub, Anchors: anchor.NewReceiptVerifier(trust)})
		if cerr := f.Close(); cerr != nil {
			t.Fatal(cerr)
		}
		if err != nil {
			t.Fatal(err)
		}
		if rep.Anchors > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rep.Anchors == 0 || rep.LastAnchoredSeq == 0 || rep.LastAnchorLog != s.Origin {
		t.Fatalf("no verified anchor in the audit log: %+v", rep)
	}
}

func TestRequiredAnchoringFailsFastOnUntrustedLog(t *testing.T) {
	s := rekortest.New(t)
	other := rekortest.New(t)
	cfg, _ := anchoredConfig(t, fakeUpstream(t, &headerLog{}).URL, s)
	cfg.Audit.Anchor.RekorURL = other.URL
	a, err := Build(t.Context(), cfg, slog.New(slog.DiscardHandler), "test")
	if err != nil && !errors.Is(err, anchor.ErrUntrustedLog) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err == nil {
		if cerr := a.close(t.Context()); cerr != nil {
			t.Error(cerr)
		}
		t.Fatal("gateway started against a transparency log missing from the trust material")
	}
}

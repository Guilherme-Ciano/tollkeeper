package app

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/gateway"
)

const callSecret = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake__secret","arguments":{"text":"x"},` +
	`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`

func readyApp(t *testing.T, cfg config.Config) (a *App, url string) {
	t.Helper()
	a = runApp(t, cfg)
	deadline := time.Now().Add(5 * time.Second)
	for a.Catalog().Snapshot().Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("catalog never synced")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return a, "http://" + a.Addr("data") + "/mcp"
}

func configRecords(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var rec struct {
			Body struct {
				Event *audit.Event `json:"event"`
			} `json:"body"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.Body.Event != nil &&
			rec.Body.Event.Phase == audit.PhaseConfig {
			out = append(out, *rec.Body.Event)
		}
	}
	return out
}

func waitConfigRecords(t *testing.T, path string, n int) []audit.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		recs := configRecords(t, path)
		if len(recs) >= n || time.Now().After(deadline) {
			return recs
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReloadSwapsPolicyAndAuditsTheDigest(t *testing.T) {
	up := fakeUpstream(t, &headerLog{})
	cfg := testConfig(t, up.URL)
	cfg.Digest = "first"
	a, url := readyApp(t, cfg)
	if r := post(t, url, "", callSecret, modernHeaders("fake__secret")); !strings.Contains(r.body, "denied by policy") {
		t.Fatalf("before reload: %+v", r)
	}
	next := cfg
	next.Digest = "second"
	next.Policy.Rules = []config.Rule{{Name: "all-fake", Tools: []string{"fake__*"}, Effect: config.EffectAllow}}
	next.Server.ShutdownTimeout = time.Minute
	if err := a.Reload(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if r := post(
		t,
		url,
		"",
		callSecret,
		modernHeaders("fake__secret"),
	); r.status != 200 ||
		!strings.Contains(r.body, "secret") {
		t.Fatalf("after reload: %+v", r)
	}
	bad := next
	bad.Digest = "broken"
	bad.Policy.Rules = []config.Rule{
		{Name: "bad", Tools: []string{"*"}, When: "principal.sub +", Effect: config.EffectAllow},
	}
	if err := a.Reload(t.Context(), bad); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if r := post(t, url, "", callSecret, modernHeaders("fake__secret")); r.status != 200 {
		t.Fatalf("rejected reload changed the running policy: %+v", r)
	}
	recs := waitConfigRecords(t, cfg.Audit.Path, 2)
	if len(recs) != 2 || recs[0].Method != gateway.ConfigLoaded || recs[0].Rule != "sha256:first" ||
		recs[1].Method != gateway.ConfigReloaded || recs[1].Rule != "sha256:second" ||
		recs[1].Reason != "not applied until restart: server" {
		t.Fatalf("config records: %+v", recs)
	}
	if v := testutil.ToFloat64(a.metrics.ConfigReloads.WithLabelValues("invalid")); v != 1 {
		t.Fatalf("invalid reloads = %v", v)
	}
	if rep := verifyAuditFile(t, cfg.Audit.Path); rep.Records == 0 {
		t.Fatalf("audit chain: %+v", rep)
	}
}

func TestReloadFromFileRejectsInvalidConfig(t *testing.T) {
	up := fakeUpstream(t, &headerLog{})
	cfg := testConfig(t, up.URL)
	a, _ := readyApp(t, cfg)
	path := filepath.Join(t.TempDir(), "gw.yaml")
	if err := os.WriteFile(path, []byte("server: [not a map\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.reloadFromFile(t.Context(), path)
	if v := testutil.ToFloat64(a.metrics.ConfigReloads.WithLabelValues("invalid")); v != 1 {
		t.Fatalf("invalid reloads = %v", v)
	}
	if v := testutil.ToFloat64(a.metrics.ConfigReloads.WithLabelValues("ok")); v != 0 {
		t.Fatalf("ok reloads = %v", v)
	}
}

func TestRestartSections(t *testing.T) {
	t.Parallel()
	cur := config.Defaults()
	next := cur
	next.Policy.Default = config.EffectAllow
	next.RateLimits.Rules = []config.RateRule{{Name: "x"}}
	if got := restartSections(cur, next); len(got) != 0 {
		t.Fatalf("reloadable change flagged: %v", got)
	}
	next.Auth.Mode = config.AuthModeNone
	next.RateLimits.Store = config.RateStoreRedis
	if got := strings.Join(restartSections(cur, next), ","); got != "auth,rate_limits.store" {
		t.Fatalf("got %q", got)
	}
}

func TestReloadRotatesAuditSigningKeyLive(t *testing.T) {
	up := fakeUpstream(t, &headerLog{})
	dir := t.TempDir()
	priv1PEM, pub1PEM, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "audit-key.pem")
	if err := os.WriteFile(keyPath, priv1PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pub1, err := audit.ParsePublicKey(pub1PEM)
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t, up.URL)
	cfg.Audit.Checkpoint.SigningKeyFile = keyPath
	cfg.Audit.Checkpoint.Every = 1
	a, _ := readyApp(t, cfg)
	initialID := a.auditLog.ActiveKeyID()
	if initialID == "" {
		t.Fatal("expected active audit signing key id")
	}

	priv2PEM, _, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, priv2PEM, 0o600); err != nil {
		t.Fatal(err)
	}

	next := cfg
	next.Digest = "rotated"
	if err := a.Reload(t.Context(), next); err != nil {
		t.Fatalf("reload with rotated key: %v", err)
	}
	if a.auditLog.ActiveKeyID() == initialID {
		t.Fatalf("signing key did not rotate on reload (still %q)", initialID)
	}
	if err := a.auditLog.Close(); err != nil {
		t.Fatalf("close audit log: %v", err)
	}
	f, err := os.Open(cfg.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := audit.Verify(f, pub1)
	if err != nil {
		t.Fatalf("verify rotated chain from root pubkey: %v", err)
	}
	if rep.KeyRotations != 1 || rep.UnsignedTail != 0 {
		t.Fatalf("unexpected report after live reload rotation: %+v", rep)
	}
}

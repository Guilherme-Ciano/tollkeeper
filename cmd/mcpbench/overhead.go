package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/devissuer"
)

var errNotReady = errors.New("process did not become ready")

type overheadOpts struct {
	binDir      string
	out         string
	rates       []int
	duration    time.Duration
	warmup      time.Duration
	runs        int
	gatewayCPUs string
	upstreamCPU string
	gatewayProc int
	conns       int
}

type point struct {
	Rate          int      `json:"rate"`
	Baseline      result   `json:"baseline"`
	Gateway       result   `json:"gateway"`
	OverheadP50us int64    `json:"overhead_p50_us"`
	OverheadP90us int64    `json:"overhead_p90_us"`
	OverheadP99us int64    `json:"overhead_p99_us"`
	GatewayRSSMB  float64  `json:"gateway_rss_mb"`
	CPUPer1k      float64  `json:"gateway_cpu_ms_per_1k_calls"`
	BaselineRuns  []result `json:"baseline_runs"`
	GatewayRuns   []result `json:"gateway_runs"`
}

type summary struct {
	Date        string      `json:"date"`
	Env         environment `json:"env"`
	GatewayCPUs string      `json:"gateway_cpus"`
	GOMAXPROCS  int         `json:"gateway_gomaxprocs"`
	Features    []string    `json:"gateway_features"`
	DurationS   float64     `json:"measure_duration_s"`
	WarmupS     float64     `json:"warmup_s"`
	Runs        int         `json:"runs_per_point"`
	Points      []point     `json:"points"`
}

func freePort(ctx context.Context) (string, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("free port: %w", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return "", fmt.Errorf("free port: %w", err)
	}
	return addr, nil
}

func pinned(ctx context.Context, cpus string, procs int, bin string, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if _, err := exec.LookPath("taskset"); err == nil && cpus != "" {
		cmd = exec.CommandContext(ctx, "taskset", append([]string{"-c", cpus, bin}, args...)...)
	} else {
		cmd = exec.CommandContext(ctx, bin, args...)
	}
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(procs))
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	return cmd
}

func waitOK(ctx context.Context, url string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return fmt.Errorf("ready probe: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%w: %s", errNotReady, url)
}

func gatewayConfig(dir, listen, admin, issuerURL, upstreamURL string) (string, error) {
	priv, _, err := audit.GenerateKeyPair()
	if err != nil {
		return "", err
	}
	keyPath := filepath.Join(dir, "audit.pem")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		return "", fmt.Errorf("write key: %w", err)
	}
	cfg := fmt.Sprintf(`server:
  listen: %q
  admin_listen: %q
  public_url: "http://%s/mcp"
  allow_localhost_host: true
  pprof: true
auth:
  resource: "http://%s/mcp"
  authorization_servers: [%q]
  required_scopes: ["mcp:tools"]
  jwt:
    issuer: %q
    jwks_url: "%s/jwks.json"
    allow_insecure_jwks: true
    audiences: ["http://%s/mcp"]
    algorithms: ["EdDSA"]
upstreams:
  - id: noop
    transport: streamable_http
    url: %q
    max_concurrency: 4096
policy:
  default: deny
  rules:
    - name: readers
      subjects: { scopes_any: ["mcp:tools"] }
      tools: ["noop__noop"]
      when: 'principal.sub != "" && !tool.annotations.destructiveHint'
      effect: allow
rate_limits:
  rules:
    - { name: per-subject, tools: ["*"], per: subject, rate: 100000000/s, burst: 1000000 }
    - { name: per-tool, tools: ["noop__*"], per: subject_tool, rate: 100000000/s, burst: 1000000 }
audit:
  enabled: true
  path: %q
  chain_id: bench
  fsync: true
  batch_size: 512
  flush_interval: 50ms
  record_args: hash
  checkpoint: { every: 10000, interval: 30s, signing_key_file: %q }
telemetry:
  log_level: warn
`, listen, admin, listen, listen, issuerURL, issuerURL, issuerURL, listen, upstreamURL, filepath.Join(dir, "audit.jsonl"), keyPath)
	path := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	return path, nil
}

type harness struct {
	opts     overheadOpts
	noop     *exec.Cmd
	gateway  *exec.Cmd
	issuer   *http.Server
	token    string
	baseURL  string
	gwURL    string
	adminURL string
}

func startIssuer(ctx context.Context) (*http.Server, string, *devissuer.Issuer, error) {
	addr, err := freePort(ctx)
	if err != nil {
		return nil, "", nil, err
	}
	issURL := "http://" + addr
	cfg, err := devissuer.ParseConfig(
		strings.NewReader("issuer: " + issURL + "\nclients:\n  - id: bench\n    grants: [client_credentials]\n"),
	)
	if err != nil {
		return nil, "", nil, err
	}
	iss, err := devissuer.New(cfg, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		return nil, "", nil, err
	}
	srv := &http.Server{Addr: addr, Handler: iss.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.ErrorContext(ctx, "issuer stopped", slog.String("error", err.Error()))
		}
	}()
	return srv, issURL, iss, nil
}

func (h *harness) start(ctx context.Context, dir string) error {
	noopAddr, err := freePort(ctx)
	if err != nil {
		return err
	}
	h.noop = pinned(ctx, h.opts.upstreamCPU, 2, filepath.Join(h.opts.binDir, "noop-server"), "-listen", noopAddr)
	if err := h.noop.Start(); err != nil {
		return fmt.Errorf("start noop: %w", err)
	}
	h.baseURL = "http://" + noopAddr + "/mcp"
	srv, issURL, iss, err := startIssuer(ctx)
	if err != nil {
		return err
	}
	h.issuer = srv
	gwAddr, err := freePort(ctx)
	if err != nil {
		return err
	}
	adminAddr, err := freePort(ctx)
	if err != nil {
		return err
	}
	cfgPath, err := gatewayConfig(dir, gwAddr, adminAddr, issURL, h.baseURL)
	if err != nil {
		return err
	}
	h.gateway = pinned(
		ctx,
		h.opts.gatewayCPUs,
		h.opts.gatewayProc,
		filepath.Join(h.opts.binDir, "tollkeeper"),
		"serve",
		"-c",
		cfgPath,
	)
	if err := h.gateway.Start(); err != nil {
		return fmt.Errorf("start gateway: %w", err)
	}
	h.gwURL = "http://" + gwAddr + "/mcp"
	h.adminURL = "http://" + adminAddr
	if err := waitOK(ctx, h.adminURL+"/readyz"); err != nil {
		return err
	}
	h.token, err = iss.Mint("bench", "bench", h.gwURL, []string{"mcp:tools"}, 24*time.Hour)
	return err
}

func (h *harness) stop(ctx context.Context) {
	for _, c := range []*exec.Cmd{h.gateway, h.noop} {
		if c != nil && c.Process != nil {
			if err := c.Process.Signal(os.Interrupt); err != nil {
				slog.WarnContext(ctx, "signal failed", slog.String("error", err.Error()))
			}
			if err := c.Wait(); err != nil {
				slog.DebugContext(ctx, "process exited", slog.String("error", err.Error()))
			}
		}
	}
	if h.issuer != nil {
		if err := h.issuer.Shutdown(ctx); err != nil {
			slog.WarnContext(ctx, "issuer shutdown", slog.String("error", err.Error()))
		}
	}
}

func median(rs []result) result {
	sorted := slices.Clone(rs)
	slices.SortFunc(sorted, func(a, b result) int { return int(a.P99us - b.P99us) })
	return sorted[len(sorted)/2]
}

func (h *harness) measure(ctx context.Context, t target, rate int, client *http.Client) ([]result, error) {
	if _, err := run(ctx, t, rate, h.opts.warmup, client); err != nil {
		return nil, err
	}
	out := make([]result, 0, h.opts.runs)
	for range h.opts.runs {
		r, err := run(ctx, t, rate, h.opts.duration, client)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (h *harness) point(ctx context.Context, rate int) (point, error) {
	client := newClient(h.opts.conns)
	base, err := h.measure(ctx, target{URL: h.baseURL, Tool: "noop"}, rate, client)
	if err != nil {
		return point{}, err
	}
	before := readProc(h.gateway.Process.Pid)
	gw, err := h.measure(ctx, target{URL: h.gwURL, Tool: "noop__noop", Token: h.token}, rate, client)
	if err != nil {
		return point{}, err
	}
	after := readProc(h.gateway.Process.Pid)
	b, g := median(base), median(gw)
	var calls int64
	for _, r := range gw {
		calls += r.Sent
	}
	p := point{
		Rate: rate, Baseline: b, Gateway: g, BaselineRuns: base, GatewayRuns: gw,
		OverheadP50us: g.P50us - b.P50us, OverheadP90us: g.P90us - b.P90us, OverheadP99us: g.P99us - b.P99us,
		GatewayRSSMB: after.RSSMB,
	}
	if calls > 0 {
		p.CPUPer1k = (after.CPUSecs - before.CPUSecs) * 1000 * 1000 / float64(
			calls+int64(rate)*int64(h.opts.warmup.Seconds()),
		)
	}
	return p, nil
}

func runOverhead(ctx context.Context, o overheadOpts, stdout io.Writer) error {
	dir, err := os.MkdirTemp("", "mcpbench-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	h := &harness{opts: o}
	defer h.stop(context.WithoutCancel(ctx))
	if err := h.start(ctx, dir); err != nil {
		return err
	}
	_, tasksetErr := exec.LookPath("taskset")
	s := summary{
		Date:        time.Now().UTC().Format(time.RFC3339),
		Env:         captureEnv(ctx, runtime.Version(), tasksetErr == nil),
		GatewayCPUs: o.gatewayCPUs,
		GOMAXPROCS:  o.gatewayProc,
		DurationS:   o.duration.Seconds(),
		WarmupS:     o.warmup.Seconds(),
		Runs:        o.runs,
		Features: []string{
			"jwt EdDSA verify (cached JWKS)",
			"CEL policy rule",
			"2 GCRA rules",
			"audit intent+outcome, fsync per 512 batch, Ed25519 checkpoints",
			"OTel noop tracer",
			"Prometheus metrics",
		},
	}
	for _, rate := range o.rates {
		p, err := h.point(ctx, rate)
		if err != nil {
			return err
		}
		fmt.Fprintf(
			stdout,
			"rate=%d baseline p50=%dus p99=%dus | gateway p50=%dus p99=%dus errors=%d | overhead p50=%dus p99=%dus | rss=%.0fMB\n",
			rate,
			p.Baseline.P50us,
			p.Baseline.P99us,
			p.Gateway.P50us,
			p.Gateway.P99us,
			p.Gateway.Errors,
			p.OverheadP50us,
			p.OverheadP99us,
			p.GatewayRSSMB,
		)
		s.Points = append(s.Points, p)
	}
	return writeResults(o.out, s)
}

func writeResults(root string, s summary) error {
	host, err := os.Hostname()
	if err != nil {
		host = "host"
	}
	dir := filepath.Join(root, time.Now().UTC().Format("2006-01-02")+"-"+host+"-"+s.Env.Commit)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("results dir: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode summary: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), b, 0o600); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	envb, err := json.MarshalIndent(s.Env, "", "  ")
	if err != nil {
		return fmt.Errorf("encode env: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "env.json"), envb, 0o600); err != nil {
		return fmt.Errorf("write env: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(report(s)), 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func report(s summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# tollkeeper overhead benchmark\n\n")
	fmt.Fprintf(
		&b,
		"%s · commit `%s`%s · %s\n\n",
		s.Date,
		s.Env.Commit,
		map[bool]string{true: " (dirty)", false: ""}[s.Env.Dirty],
		s.Env.Note,
	)
	fmt.Fprintf(
		&b,
		"Hardware: %s, %d logical CPUs, %d GB RAM, Linux %s, governor=%s, boost=%s, %s. Gateway pinned to CPUs %s with GOMAXPROCS=%d.\n\n",
		s.Env.CPU,
		s.Env.LogicalCPU,
		s.Env.MemGB,
		s.Env.Kernel,
		s.Env.Governor,
		s.Env.Boost,
		s.Env.Go,
		s.GatewayCPUs,
		s.GOMAXPROCS,
	)
	fmt.Fprintf(&b, "Gateway features on: %s.\n\n", strings.Join(s.Features, "; "))
	fmt.Fprintf(
		&b,
		"Open-loop constant arrival rate, latency measured from the scheduled send time (coordinated-omission corrected). %.0fs warm-up, %d × %.0fs runs per point, median run by p99 reported.\n\n",
		s.WarmupS,
		s.Runs,
		s.DurationS,
	)
	b.WriteString(
		"| rate (calls/s) | direct p50 | direct p99 | gateway p50 | gateway p99 | added p50 | added p99 | errors | gateway RSS | CPU per 1k calls |\n",
	)
	b.WriteString("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for i := range s.Points {
		p := &s.Points[i]
		fmt.Fprintf(
			&b,
			"| %d | %d µs | %d µs | %d µs | %d µs | **%d µs** | **%d µs** | %d | %.0f MB | %.0f ms |\n",
			p.Rate,
			p.Baseline.P50us,
			p.Baseline.P99us,
			p.Gateway.P50us,
			p.Gateway.P99us,
			p.OverheadP50us,
			p.OverheadP99us,
			p.Gateway.Errors,
			p.GatewayRSSMB,
			p.CPUPer1k,
		)
	}
	return b.String()
}

package app

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/sync/errgroup"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/otlpsink"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/pgsink"
	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/gateway"
	"github.com/Guilherme-Ciano/tollkeeper/internal/pin"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
	"github.com/Guilherme-Ciano/tollkeeper/internal/upstream"
)

const (
	maxCatalogTools     = 5000
	maxDirectoryEntries = 20000
	pollInterval        = 60 * time.Second
)

type App struct {
	cfg       config.Config
	log       *slog.Logger
	metrics   *telemetry.Metrics
	tracing   *telemetry.Tracing
	keys      *authn.KeySet
	store     *ratelimit.Store
	redis     redis.UniversalClient
	auditLog  *audit.Log
	auditPG   *pgsink.Sink
	anchorer  *anchor.Anchorer
	otlp      *otlpsink.Sink
	version   string
	catalog   *catalog.Catalog
	directory *catalog.Directory
	upstreams []*upstream.Upstream
	gateway   *gateway.Gateway
	pins      *pin.Guard
	ready     atomic.Bool
	synced    map[string]*atomic.Uint64
	listeners sync.Map

	configPath string
	backend    ratelimit.Backend
	reloadMu   sync.Mutex
}

func Build(ctx context.Context, cfg config.Config, log *slog.Logger, version string) (built *App, err error) {
	a := &App{
		cfg: cfg, log: log, version: version, metrics: telemetry.NewMetrics(), catalog: catalog.New(maxCatalogTools),
		directory: catalog.NewDirectory(maxDirectoryEntries), synced: map[string]*atomic.Uint64{},
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, a.close(ctx))
		}
	}()
	tr, err := telemetry.NewTracing(
		ctx,
		cfg.Telemetry.ServiceName,
		version,
		cfg.Telemetry.OTLPEndpoint,
		cfg.Telemetry.SampleRatio,
	)
	if err != nil {
		return nil, err
	}
	a.tracing = tr
	pol, err := policy.New(cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	a.store = ratelimit.NewStore(nil)
	a.backend = a.rateBackend(ctx)
	lim, err := ratelimit.New(cfg.RateLimits, a.backend)
	if err != nil {
		return nil, err
	}
	verifier := a.verifier(ctx, cfg)
	for _, w := range cfg.Warnings() {
		log.WarnContext(ctx, "config warning", slog.String("detail", w))
	}
	var auditor gateway.Auditor
	if cfg.Audit.Enabled {
		if err := a.openAudit(ctx); err != nil {
			return nil, err
		}
		auditor = a.auditLog
	}
	if err := a.openPins(ctx); err != nil {
		return nil, err
	}
	var pins gateway.PinGuard
	if a.pins != nil {
		pins = a.pins
	}
	naming := cfg.Naming()
	callers := map[string]gateway.Caller{}
	hooks := upstream.Hooks{
		Up: func(id string, up bool) {
			v := 0.0
			if up {
				v = 1
			}
			a.metrics.UpstreamUp.WithLabelValues(id).Set(v)
		},
		BreakerState: func(id string, s int) { a.metrics.BreakerState.WithLabelValues(id).Set(float64(s)) },
	}
	for i := range cfg.Upstreams {
		uc := &cfg.Upstreams[i]
		f, err := upstream.Factory(ctx, *uc, log, upstream.LookupEnv)
		if err != nil {
			return nil, err
		}
		u := upstream.New(*uc, naming, f, log, hooks, version)
		a.synced[uc.ID] = &atomic.Uint64{}
		a.upstreams = append(a.upstreams, u)
		callers[uc.ID] = u
	}
	stateKey, err := readStateKey(cfg.Server.RequestStateKey)
	if err != nil {
		return nil, err
	}
	if stateKey == nil {
		log.InfoContext(ctx, "request state key is ephemeral",
			slog.String("hint", "set server.request_state_key_file when running several replicas"))
	}
	a.gateway = gateway.New(gateway.Deps{
		Config:     cfg,
		Verifier:   verifier,
		Policy:     pol,
		Limiter:    lim,
		Audit:      auditor,
		Catalog:    a.catalog,
		Directory:  a.directory,
		Upstreams:  callers,
		Metrics:    a.metrics,
		Tracer:     tr.Tracer(),
		Propagator: tr.Propagator,
		Log:        log,
		Version:    version,
		Pins:       pins,
		StateKey:   stateKey,
	})
	return a, nil
}

func (a *App) openPins(ctx context.Context) error {
	cfg := a.cfg.Pinning
	if cfg.Mode == config.PinModeOff {
		return nil
	}
	guard, err := pin.NewGuard(pin.Mode(cfg.Mode), cfg.File)
	if err != nil {
		return err
	}
	a.pins = guard
	if cfg.ReportToken == "" && !config.Loopback(a.cfg.Server.AdminListen) {
		a.log.WarnContext(
			ctx,
			"GET /pins is disabled: the admin listener is not loopback and pinning.report_token is empty",
		)
	}
	a.log.InfoContext(ctx, "tool pinning enabled",
		slog.String("mode", cfg.Mode),
		slog.String("file", cfg.File),
		slog.Int("approved", len(guard.Lockfile().Tools)))
	return nil
}

func (a *App) rateBackend(ctx context.Context) ratelimit.Backend {
	if a.cfg.RateLimits.Store != config.RateStoreRedis {
		return a.store
	}
	rc := a.cfg.RateLimits.Redis
	opts := &redis.UniversalOptions{
		Addrs:        rc.Addrs,
		Username:     rc.Username,
		Password:     rc.Password,
		DB:           rc.DB,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  rc.Timeout,
		WriteTimeout: rc.Timeout,
		MaxRetries:   -1,
	}
	if rc.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	a.redis = redis.NewUniversalClient(opts)
	if err := a.redis.Ping(ctx).Err(); err != nil {
		a.log.WarnContext(ctx, "redis rate limit store unreachable at startup, using the fallback until it recovers",
			slog.String("on_error", rc.OnError), slog.String("error", err.Error()))
	}
	onError := ratelimit.FallbackLocal
	if rc.OnError == config.RedisOnErrorDeny {
		onError = ratelimit.FallbackDeny
	}
	return ratelimit.NewRedis(a.redis, ratelimit.RedisOptions{
		Prefix:  rc.KeyPrefix,
		Timeout: rc.Timeout,
		OnError: onError,
		Local:   a.store,
		Failed:  func(error) { a.metrics.RateBackendErrs.Inc() },
	})
}

func (a *App) openAudit(ctx context.Context) error {
	opts := audit.Options{
		Path:               a.cfg.Audit.Path,
		ChainID:            a.cfg.Audit.ChainID,
		Buffer:             a.cfg.Audit.Buffer,
		BatchSize:          a.cfg.Audit.BatchSize,
		FlushInterval:      a.cfg.Audit.FlushInterval,
		Fsync:              a.cfg.Audit.Fsync,
		FailOpen:           a.cfg.Audit.OnBackpressure == config.BackpressureFailOpen,
		CheckpointEvery:    a.cfg.Audit.Checkpoint.Every,
		CheckpointInterval: a.cfg.Audit.Checkpoint.Interval,
		Hooks: audit.Hooks{
			Dropped:    a.metrics.AuditDropped.Inc,
			SinkError:  func(error) { a.metrics.AuditErrors.Inc() },
			QueueDepth: func(n int) { a.metrics.AuditQueue.Set(float64(n)) },
			Written:    func(n int) { a.metrics.AuditWritten.Add(float64(n)) },
		},
	}
	if a.cfg.Audit.Postgres.DSN != "" {
		if err := a.openMirror(ctx, &opts); err != nil {
			return err
		}
	}
	if o := a.cfg.Audit.OTLP; o.Endpoint != "" {
		a.otlp = otlpsink.New(otlpsink.Options{
			Endpoint: o.Endpoint, Headers: o.Headers, Service: "tollkeeper", Version: a.version,
			Batch: o.Batch, Queue: o.Queue, Interval: o.Interval,
			Client: &http.Client{Timeout: o.Timeout, CheckRedirect: upstream.NoRedirects},
			Hooks: otlpsink.Hooks{
				Exported: func(n int) { a.metrics.AuditExport.WithLabelValues("exported").Add(float64(n)) },
				Dropped:  func(n int) { a.metrics.AuditExport.WithLabelValues("dropped").Add(float64(n)) },
				Failed: func(err error) {
					a.log.WarnContext(ctx, "otlp audit export failed", slog.String("error", err.Error()))
				},
			},
		})
		opts.Committed = a.otlp.Committed
	}
	if a.cfg.Audit.Checkpoint.SigningKeyFile != "" {
		k, err := audit.LoadPrivateKey(a.cfg.Audit.Checkpoint.SigningKeyFile)
		if err != nil {
			return err
		}
		opts.Signer = k
	} else {
		a.log.WarnContext(ctx, "audit checkpoints disabled: no signing key configured")
	}
	if a.cfg.Audit.Anchor.Enabled {
		if err := a.openAnchorer(ctx, &opts); err != nil {
			return err
		}
	}
	l, err := audit.OpenContext(ctx, opts)
	if err != nil {
		return err
	}
	a.auditLog = l
	if ref, ok := l.RecoveredCheckpoint(); ok && a.anchorer != nil {
		a.anchorer.Offer(ref)
	}
	return nil
}

func (a *App) openMirror(ctx context.Context, opts *audit.Options) error {
	dsn := a.cfg.Audit.Postgres.DSN
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	connect := pgsink.Connect
	if a.cfg.Audit.Postgres.Migrate {
		connect = pgsink.Open
	}
	sink, err := connect(ctx, dsn)
	if err != nil {
		return err
	}
	a.auditPG = sink
	if err := sink.RequireSchema(ctx); err != nil {
		return err
	}
	if a.cfg.Audit.Anchor.Enabled {
		if err := sink.RequireAnchorKind(ctx); err != nil {
			return err
		}
	}
	privs, err := sink.ExcessPrivileges(ctx)
	if err != nil {
		return err
	}
	if len(privs) > 0 {
		a.log.WarnContext(ctx,
			"the audit database role can modify or disable the audit table; grant it only INSERT and SELECT",
			slog.Any("excess_privileges", privs))
	}
	opts.Mirror = sink
	opts.MirrorTimeout = a.cfg.Audit.Postgres.Timeout
	return nil
}

type anchorSink struct {
	app *App
}

func (s anchorSink) AppendAnchor(ref audit.CheckpointRef, an *audit.Anchor) error {
	if s.app.auditLog == nil {
		return audit.ErrClosed
	}
	return s.app.auditLog.AppendAnchor(ref, an)
}

func (a *App) openAnchorer(ctx context.Context, opts *audit.Options) error {
	ac := a.cfg.Audit.Anchor
	trust, err := anchor.LoadTrust(ac.TrustFiles, ac.Origin)
	if err != nil {
		return err
	}
	client, err := anchor.NewClient(ac.RekorURL, "tollkeeper", otelhttp.NewTransport(http.DefaultTransport))
	if err != nil {
		return err
	}
	if ac.Required {
		pctx, cancel := context.WithTimeout(ctx, ac.Timeout)
		defer cancel()
		cp, err := client.Checkpoint(pctx)
		if err != nil {
			return fmt.Errorf("audit anchoring required but the transparency log is unreachable: %w", err)
		}
		if err := anchor.CheckLogCheckpoint(trust, cp); err != nil {
			return fmt.Errorf("audit anchoring required: %w", err)
		}
	}
	var stamper anchor.Timestamper
	if ac.TSAURL != "" {
		if !trust.HasTimestampAuthority() {
			return fmt.Errorf("%w: audit.anchor.tsa_url is set but trust_files hold no timestamp authority",
				anchor.ErrBadTrust)
		}
		tc, err := anchor.NewTimestampClient(ac.TSAURL, otelhttp.NewTransport(http.DefaultTransport))
		if err != nil {
			return err
		}
		stamper, trust = tc, trust.RequireTime()
	}
	an, err := anchor.New(anchor.Options{
		ChainID:     a.cfg.Audit.ChainID,
		Key:         opts.Signer,
		Timestamper: stamper,
		Every:       ac.Every,
		Interval:    ac.Interval,
		Timeout:     ac.Timeout,
		MaxBackoff:  ac.MaxBackoff,
		MinSpacing:  ac.MinSpacing,
		Verifier:    anchor.NewReceiptVerifier(trust),
		Logger:      a.log,
		Hooks: anchor.Hooks{
			Attempt:  func(o string) { a.metrics.AnchorAttempts.WithLabelValues(o).Inc() },
			Duration: func(d time.Duration) { a.metrics.AnchorDuration.Observe(d.Seconds()) },
			Anchored: func(seq uint64, at time.Time) {
				a.metrics.AnchorLastSuccess.Set(float64(at.Unix()))
				a.metrics.AnchorCoveredSeq.Set(float64(seq))
			},
		},
	}, client, anchorSink{app: a})
	if err != nil {
		return err
	}
	a.anchorer = an
	opts.CheckpointCommitted = an.Offer
	opts.AnchorCommitted = an.Committed
	opts.AnchorDropped = func(error) { a.metrics.AnchorAttempts.WithLabelValues(anchor.OutcomeDropped).Inc() }
	a.log.InfoContext(ctx, "audit anchoring enabled", slog.String("rekor_url", ac.RekorURL),
		slog.String("tsa_url", ac.TSAURL),
		slog.Int("every", ac.Every), slog.Duration("interval", ac.Interval), slog.Bool("required", ac.Required))
	return nil
}

func (a *App) anchorStale() bool {
	if a.anchorer == nil || !a.cfg.Audit.Anchor.Required {
		return false
	}
	ac := a.cfg.Audit.Anchor
	return a.anchorer.Stale(time.Now(), 2*ac.Interval+ac.Timeout+ac.MaxBackoff)
}

func (a *App) Gateway() *gateway.Gateway {
	return a.gateway
}

func (a *App) Catalog() *catalog.Catalog {
	return a.catalog
}

func (a *App) Addr(name string) string {
	v, ok := a.listeners.Load(name)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func (a *App) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(a.metrics.Registry, promhttp.HandlerOpts{EnableOpenMetrics: true}))
	if a.cfg.Server.Pprof {
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	}
	mux.HandleFunc("GET /pins", a.pinReport)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !a.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		if !slices.ContainsFunc(a.upstreams, a.serving) {
			http.Error(w, "no upstream connected and synced", http.StatusServiceUnavailable)
			return
		}
		if a.anchorStale() {
			http.Error(w, "audit anchoring stale", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ready\n")); err != nil {
			a.log.DebugContext(r.Context(), "readyz write failed", slog.String("error", err.Error()))
		}
	})
	return mux
}

func (a *App) pinReportAllowed(r *http.Request) bool {
	if a.pins == nil {
		return false
	}
	token := a.cfg.Pinning.ReportToken
	if token == "" {
		return config.Loopback(a.cfg.Server.AdminListen)
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func (a *App) pinReport(w http.ResponseWriter, r *http.Request) {
	if !a.pinReportAllowed(r) {
		http.NotFound(w, r)
		return
	}
	report := pin.BuildReport(a.pins.Mode(), a.pins.Lockfile(), a.catalog.Snapshot().Tools())
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		a.log.DebugContext(r.Context(), "pin report write failed", slog.String("error", err.Error()))
	}
}

func (a *App) pinLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.Pinning.ReloadInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		changed, err := a.pins.Reload()
		if err != nil {
			a.log.WarnContext(ctx, "pin lockfile reload failed, keeping previous approvals",
				slog.String("error", err.Error()))
			continue
		}
		if !changed {
			continue
		}
		a.log.InfoContext(ctx, "pin lockfile reloaded", slog.Int("approved", len(a.pins.Lockfile().Tools)))
		a.gateway.Reevaluate()
	}
}

func newServer(ctx context.Context, h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
}

func (a *App) syncLoop(ctx context.Context, u *upstream.Upstream) {
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.Changes():
		case <-poll.C:
		}
		if a.cfg.Server.ResyncDebounce > 0 {
			t := time.NewTimer(a.cfg.Server.ResyncDebounce)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		a.resync(ctx, u)
	}
}

func (a *App) serving(u *upstream.Upstream) bool {
	gen := u.Generation()
	return u.Up() && gen > 0 && a.synced[u.ID()].Load() == gen
}

func (a *App) resync(ctx context.Context, u *upstream.Upstream) {
	signalled := u.TakeSignalled()
	var tools []catalog.Tool
	gen := u.Generation()
	up := u.Up()
	if up {
		var err error
		tools, err = u.Tools(ctx)
		if err != nil {
			a.log.WarnContext(
				ctx,
				"tool sync failed",
				slog.String("upstream", u.ID()),
				slog.String("error", err.Error()),
			)
			if u.Up() {
				u.Restore(signalled)
				return
			}
			tools, up = nil, false
		}
	}
	delta, err := a.catalog.Replace(u.ID(), tools)
	if err != nil {
		a.log.ErrorContext(
			ctx,
			"catalog update rejected",
			slog.String("upstream", u.ID()),
			slog.String("error", err.Error()),
		)
		return
	}
	if signalled&upstream.ChangedTools != 0 && delta.Empty() {
		a.gateway.NotifyListChanged(true, false, false)
	}
	if !delta.Empty() {
		a.gateway.Apply(delta)
		a.log.InfoContext(ctx, "catalog updated", slog.String("upstream", u.ID()),
			slog.Int("upserted", len(delta.Upserted)), slog.Int("removed", len(delta.Removed)),
			slog.Uint64("version", a.catalog.Snapshot().Version))
	}
	a.resyncDirectory(ctx, u, up, signalled)
	if up {
		a.synced[u.ID()].Store(gen)
	} else {
		a.synced[u.ID()].Store(0)
	}
}

func (a *App) listen(ctx context.Context, name, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s %s: %w", name, addr, err)
	}
	a.listeners.Store(name, ln.Addr().String())
	return ln, nil
}

func (a *App) Run(ctx context.Context) error {
	dataLn, err := a.listen(ctx, "data", a.cfg.Server.Listen)
	if err != nil {
		return errors.Join(err, a.close(ctx))
	}
	adminLn, err := a.listen(ctx, "admin", a.cfg.Server.AdminListen)
	if err != nil {
		return errors.Join(err, dataLn.Close(), a.close(ctx))
	}
	bgCtx, stopBg := context.WithCancel(context.WithoutCancel(ctx))
	defer stopBg()
	var bg sync.WaitGroup
	bg.Go(func() { a.store.RunJanitor(bgCtx, time.Minute) })
	if a.keys != nil {
		if err := a.keys.Refresh(ctx); err != nil {
			a.log.WarnContext(ctx, "initial jwks fetch failed, will retry on demand", slog.String("error", err.Error()))
		}
		bg.Go(func() { a.keys.Run(bgCtx, a.cfg.Auth.JWT.JWKSRefresh) })
	}
	if a.pins != nil && a.cfg.Pinning.File != "" {
		bg.Go(func() { a.pinLoop(bgCtx) })
	}
	if a.otlp != nil {
		bg.Go(func() { a.otlp.Run(bgCtx) })
	}
	if a.anchorer != nil {
		bg.Go(func() { a.anchorer.Run(bgCtx) })
	}
	for _, u := range a.upstreams {
		bg.Go(func() { u.Run(bgCtx) })
		bg.Go(func() { a.syncLoop(bgCtx, u) })
	}
	if path := a.configPath; path != "" {
		bg.Go(func() { a.reloadLoop(bgCtx, path) })
	}
	if err := a.gateway.RecordConfig(ctx, gateway.ConfigLoaded, a.cfg.Digest, ""); err != nil {
		a.log.WarnContext(ctx, "config load not audited", slog.String("error", err.Error()))
	}
	dataSrv := newServer(bgCtx, a.gateway.Handler())
	adminSrv := newServer(bgCtx, a.adminHandler())
	a.ready.Store(true)
	a.log.InfoContext(
		ctx,
		"tollkeeper listening",
		slog.String("data", dataLn.Addr().String()),
		slog.String("admin", adminLn.Addr().String()),
	)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return serve(dataSrv, dataLn) })
	g.Go(func() error { return serve(adminSrv, adminLn) })
	g.Go(func() error {
		<-gctx.Done()
		a.ready.Store(false)
		if d := a.cfg.Server.ShutdownDrainDelay; d > 0 {
			time.Sleep(d)
		}
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.Server.ShutdownTimeout)
		defer cancel()
		return errors.Join(dataSrv.Shutdown(sctx), adminSrv.Shutdown(sctx))
	})
	runErr := g.Wait()
	stopBg()
	bg.Wait()
	closeErr := a.close(ctx)
	a.log.InfoContext(ctx, "tollkeeper stopped")
	return errors.Join(runErr, closeErr)
}

func (a *App) close(ctx context.Context) error {
	var err error
	if a.auditLog != nil {
		err = a.auditLog.Close()
	}
	if a.auditPG != nil {
		a.auditPG.Close()
	}
	if a.redis != nil {
		err = errors.Join(err, a.redis.Close())
	}
	if a.tracing != nil {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		err = errors.Join(err, a.tracing.Shutdown(tctx))
	}
	return err
}

func serve(s *http.Server, ln net.Listener) error {
	if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func readStateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read request state key: %w", err)
	}
	key = bytes.TrimSpace(key)
	if len(key) < gateway.MinStateKeyLen {
		return nil, fmt.Errorf("request state key %s: need at least %d bytes", path, gateway.MinStateKeyLen)
	}
	return key, nil
}

func (a *App) resyncDirectory(ctx context.Context, u *upstream.Upstream, up bool, signalled upstream.Changed) {
	var entries []catalog.Entry
	if up {
		var err error
		entries, err = u.Directory(ctx)
		if err != nil {
			a.log.WarnContext(ctx, "prompt and resource sync failed",
				slog.String("upstream", u.ID()), slog.String("error", err.Error()))
			return
		}
	}
	changed, rejected, err := a.directory.Replace(u.ID(), entries)
	for _, rerr := range rejected {
		a.log.WarnContext(ctx, "prompt or resource rejected",
			slog.String("upstream", u.ID()), slog.String("error", rerr.Error()))
	}
	if err != nil {
		a.log.ErrorContext(ctx, "directory update rejected",
			slog.String("upstream", u.ID()), slog.String("error", err.Error()))
		return
	}
	switch {
	case changed:
		a.gateway.NotifyListChanged(false, true, true)
	case signalled&(upstream.ChangedPrompts|upstream.ChangedResources) != 0:
		a.gateway.NotifyListChanged(false, signalled&upstream.ChangedPrompts != 0,
			signalled&upstream.ChangedResources != 0)
	}
	if changed {
		a.log.InfoContext(ctx, "directory updated", slog.String("upstream", u.ID()),
			slog.Int("entries", a.directory.Snapshot().Len()))
	}
}

func (a *App) verifier(ctx context.Context, cfg config.Config) gateway.TokenVerifier {
	switch cfg.Auth.Mode {
	case config.AuthModeJWT:
		a.keys = authn.NewKeySet(
			cfg.Auth.JWT.JWKSURL,
			&http.Client{Timeout: 10 * time.Second, CheckRedirect: upstream.NoRedirects},
			cfg.Auth.JWT.JWKSMinRetry,
		)
		return authn.NewVerifier(authn.FromKeySet(a.keys), authn.VerifierOptions{
			Issuer: cfg.Auth.JWT.Issuer, Audiences: cfg.Auth.JWT.Audiences,
			Algorithms: cfg.Auth.JWT.Algorithms, Leeway: cfg.Auth.JWT.ClockSkew, Types: cfg.Auth.JWT.Types,
		})
	case config.AuthModeIntrospection:
		in := cfg.Auth.Introspection
		return authn.NewIntrospector(authn.IntrospectorOptions{
			URL: in.URL, ClientID: in.ClientID, ClientSecret: in.ClientSecret, Issuer: in.Issuer,
			Audiences: in.Audiences, CacheTTL: in.CacheTTL, Leeway: cfg.Auth.JWT.ClockSkew,
			Client: &http.Client{Timeout: in.Timeout, CheckRedirect: upstream.NoRedirects},
		})
	default:
		a.log.WarnContext(ctx, "authentication disabled: every caller is anonymous")
		return nil
	}
}

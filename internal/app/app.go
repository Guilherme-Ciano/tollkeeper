package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
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
	maxCatalogTools = 5000
	pollInterval    = 60 * time.Second
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
	catalog   *catalog.Catalog
	upstreams []*upstream.Upstream
	gateway   *gateway.Gateway
	pins      *pin.Guard
	ready     atomic.Bool
	synced    map[string]*atomic.Uint64
	listeners sync.Map
}

func Build(ctx context.Context, cfg config.Config, log *slog.Logger, version string) (built *App, err error) {
	a := &App{
		cfg: cfg, log: log, metrics: telemetry.NewMetrics(), catalog: catalog.New(maxCatalogTools),
		synced: map[string]*atomic.Uint64{},
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
	lim, err := ratelimit.New(cfg.RateLimits, a.rateBackend(ctx))
	if err != nil {
		return nil, err
	}
	var verifier gateway.TokenVerifier
	if cfg.Auth.Mode == config.AuthModeJWT {
		a.keys = authn.NewKeySet(
			cfg.Auth.JWT.JWKSURL,
			&http.Client{Timeout: 10 * time.Second, CheckRedirect: upstream.NoRedirects},
			cfg.Auth.JWT.JWKSMinRetry,
		)
		verifier = authn.NewVerifier(authn.FromKeySet(a.keys), authn.VerifierOptions{
			Issuer: cfg.Auth.JWT.Issuer, Audiences: cfg.Auth.JWT.Audiences,
			Algorithms: cfg.Auth.JWT.Algorithms, Leeway: cfg.Auth.JWT.ClockSkew, Types: cfg.Auth.JWT.Types,
		})
	} else {
		log.WarnContext(ctx, "authentication disabled: every caller is anonymous")
	}
	var auditor gateway.Auditor
	if cfg.Audit.Enabled {
		if err := a.openAudit(); err != nil {
			return nil, err
		}
		auditor = a.auditLog
	}
	var pins gateway.PinGuard
	if cfg.Pinning.Mode != config.PinModeOff {
		guard, err := pin.NewGuard(pin.Mode(cfg.Pinning.Mode), cfg.Pinning.File)
		if err != nil {
			return nil, err
		}
		a.pins, pins = guard, guard
		log.InfoContext(ctx, "tool pinning enabled",
			slog.String("mode", cfg.Pinning.Mode),
			slog.String("file", cfg.Pinning.File),
			slog.Int("approved", len(guard.Lockfile().Tools)))
	}
	naming := catalog.Naming{Separator: cfg.Server.NamespaceSeparator, Bare: !cfg.Server.NamespaceTools}
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
	a.gateway = gateway.New(gateway.Deps{
		Config:     cfg,
		Verifier:   verifier,
		Policy:     pol,
		Limiter:    lim,
		Audit:      auditor,
		Catalog:    a.catalog,
		Upstreams:  callers,
		Metrics:    a.metrics,
		Tracer:     tr.Tracer(),
		Propagator: tr.Propagator,
		Log:        log,
		Version:    version,
		Pins:       pins,
	})
	return a, nil
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

func (a *App) openAudit() error {
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
	if dsn := a.cfg.Audit.Postgres.DSN; dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
		opts.Mirror = sink
		opts.MirrorTimeout = a.cfg.Audit.Postgres.Timeout
	}
	if a.cfg.Audit.Checkpoint.SigningKeyFile != "" {
		k, err := audit.LoadPrivateKey(a.cfg.Audit.Checkpoint.SigningKeyFile)
		if err != nil {
			return err
		}
		opts.Signer = k
	} else {
		a.log.Warn("audit checkpoints disabled: no signing key configured")
	}
	l, err := audit.Open(opts)
	if err != nil {
		return err
	}
	a.auditLog = l
	return nil
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
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ready\n")); err != nil {
			a.log.DebugContext(r.Context(), "readyz write failed", slog.String("error", err.Error()))
		}
	})
	return mux
}

func (a *App) pinReport(w http.ResponseWriter, r *http.Request) {
	mode, lock := pin.ModeOff, pin.Empty()
	if a.pins != nil {
		mode, lock = a.pins.Mode(), a.pins.Lockfile()
	}
	report := pin.BuildReport(mode, lock, a.catalog.Snapshot().Tools())
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
	if !delta.Empty() {
		a.gateway.Apply(delta)
		a.log.InfoContext(ctx, "catalog updated", slog.String("upstream", u.ID()),
			slog.Int("upserted", len(delta.Upserted)), slog.Int("removed", len(delta.Removed)),
			slog.Uint64("version", a.catalog.Snapshot().Version))
	}
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
	for _, u := range a.upstreams {
		bg.Go(func() { u.Run(bgCtx) })
		bg.Go(func() { a.syncLoop(bgCtx, u) })
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

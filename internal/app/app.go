package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/gateway"
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
	auditLog  *audit.Log
	catalog   *catalog.Catalog
	upstreams []*upstream.Upstream
	gateway   *gateway.Gateway
	ready     atomic.Bool
	listeners sync.Map
}

func Build(ctx context.Context, cfg config.Config, log *slog.Logger, version string) (*App, error) {
	a := &App{cfg: cfg, log: log, metrics: telemetry.NewMetrics(), catalog: catalog.New(maxCatalogTools)}
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
	lim, err := ratelimit.New(cfg.RateLimits, a.store)
	if err != nil {
		return nil, err
	}
	var verifier gateway.TokenVerifier
	if cfg.Auth.Mode == config.AuthModeJWT {
		a.keys = authn.NewKeySet(
			cfg.Auth.JWT.JWKSURL,
			&http.Client{Timeout: 10 * time.Second},
			cfg.Auth.JWT.JWKSMinRetry,
		)
		verifier = authn.NewVerifier(authn.FromKeySet(a.keys), authn.VerifierOptions{
			Issuer: cfg.Auth.JWT.Issuer, Audiences: cfg.Auth.JWT.Audiences,
			Algorithms: cfg.Auth.JWT.Algorithms, Leeway: cfg.Auth.JWT.ClockSkew,
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
	naming := catalog.Naming{Separator: cfg.Server.NamespaceSeparator}
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
	})
	return a, nil
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
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !a.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		for _, u := range a.upstreams {
			if u.Up() {
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte("ready\n")); err != nil {
					a.log.DebugContext(r.Context(), "readyz write failed", slog.String("error", err.Error()))
				}
				return
			}
		}
		http.Error(w, "no upstream connected", http.StatusServiceUnavailable)
	})
	return mux
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

func (a *App) resync(ctx context.Context, u *upstream.Upstream) {
	var tools []catalog.Tool
	if u.Up() {
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
			tools = nil
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
		return err
	}
	adminLn, err := a.listen(ctx, "admin", a.cfg.Server.AdminListen)
	if err != nil {
		return errors.Join(err, dataLn.Close())
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
	var closeErr error
	if a.auditLog != nil {
		closeErr = a.auditLog.Close()
	}
	tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	closeErr = errors.Join(closeErr, a.tracing.Shutdown(tctx))
	a.log.InfoContext(ctx, "tollkeeper stopped")
	return errors.Join(runErr, closeErr)
}

func serve(s *http.Server, ln net.Listener) error {
	if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

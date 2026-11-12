package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sony/gobreaker/v2"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

var (
	ErrUnavailable = errors.New("upstream unavailable")
	ErrTimeout     = errors.New("upstream timeout")
	ErrBreakerOpen = errors.New("upstream circuit open")
	ErrSaturated   = errors.New("upstream concurrency limit reached")
)

type Hooks struct {
	Up           func(id string, up bool)
	BreakerState func(id string, state int)
}

type TransportFactory func(ctx context.Context) (mcp.Transport, func(), error)

type Upstream struct {
	cfg       config.Upstream
	naming    catalog.Naming
	factory   TransportFactory
	log       *slog.Logger
	hooks     Hooks
	version   string
	sem       chan struct{}
	breaker   *gobreaker.CircuitBreaker[*mcp.CallToolResult]
	changes   chan struct{}
	ready     chan struct{}
	readyOnce sync.Once
	up        atomic.Bool

	mu sync.RWMutex
	cs *mcp.ClientSession
}

func New(
	cfg config.Upstream,
	naming catalog.Naming,
	factory TransportFactory,
	log *slog.Logger,
	hooks Hooks,
	version string,
) *Upstream {
	u := &Upstream{
		cfg:     cfg,
		naming:  naming,
		factory: factory,
		log:     log.With(slog.String("upstream", cfg.ID)),
		hooks:   hooks,
		version: version,
		sem:     make(chan struct{}, cfg.MaxConcurrency),
		changes: make(chan struct{}, 1),
		ready:   make(chan struct{}),
	}
	failures := cfg.Breaker.Failures
	u.breaker = gobreaker.NewCircuitBreaker[*mcp.CallToolResult](gobreaker.Settings{
		Name:    cfg.ID,
		Timeout: cfg.Breaker.OpenFor,
		ReadyToTrip: func(c gobreaker.Counts) bool {
			return c.ConsecutiveFailures >= failures
		},
		IsExcluded: func(err error) bool {
			return errors.Is(err, context.Canceled)
		},
		OnStateChange: func(name string, _, to gobreaker.State) {
			if hooks.BreakerState != nil {
				hooks.BreakerState(name, int(to))
			}
		},
	})
	return u
}

func (u *Upstream) ID() string {
	return u.cfg.ID
}

func (u *Upstream) Up() bool {
	return u.up.Load()
}

func (u *Upstream) Changes() <-chan struct{} {
	return u.changes
}

func (u *Upstream) Ready() <-chan struct{} {
	return u.ready
}

func (u *Upstream) notify() {
	select {
	case u.changes <- struct{}{}:
	default:
	}
}

func (u *Upstream) session() *mcp.ClientSession {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.cs
}

func (u *Upstream) setUp(cs *mcp.ClientSession) {
	u.mu.Lock()
	u.cs = cs
	u.mu.Unlock()
	u.up.Store(cs != nil)
	if u.hooks.Up != nil {
		u.hooks.Up(u.cfg.ID, cs != nil)
	}
}

func (u *Upstream) connect(ctx context.Context) (*mcp.ClientSession, func(), error) {
	t, cleanup, err := u.factory(ctx)
	if err != nil {
		return nil, nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "tollkeeper", Version: u.version}, &mcp.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			u.notify()
		},
	})
	cctx, cancel := context.WithTimeoutCause(ctx, u.cfg.Timeout, ErrTimeout)
	defer cancel()
	cs, err := client.Connect(cctx, t, nil)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("connect %s: %w", u.cfg.ID, err)
	}
	return cs, cleanup, nil
}

func (u *Upstream) Run(ctx context.Context) {
	backoff := u.cfg.RestartBackoff
	for ctx.Err() == nil {
		cs, cleanup, err := u.connect(ctx)
		if err != nil {
			u.log.WarnContext(
				ctx,
				"upstream connect failed",
				slog.String("error", err.Error()),
				slog.Duration("retry_in", backoff),
			)
			if !sleep(ctx, jitter(backoff)) {
				return
			}
			backoff = min(backoff*2, u.cfg.RestartMax)
			continue
		}
		backoff = u.cfg.RestartBackoff
		u.setUp(cs)
		u.log.InfoContext(ctx, "upstream connected")
		u.notify()
		u.readyOnce.Do(func() { close(u.ready) })
		waitErr := make(chan error, 1)
		go func() { waitErr <- cs.Wait() }()
		select {
		case <-ctx.Done():
			u.setUp(nil)
			_ = cs.Close()
			if err := <-waitErr; err != nil {
				u.log.DebugContext(ctx, "upstream session closed", slog.String("error", err.Error()))
			}
			cleanup()
			return
		case err := <-waitErr:
			u.setUp(nil)
			cleanup()
			u.notify()
			attrs := []slog.Attr{}
			if err != nil {
				attrs = append(attrs, slog.String("error", err.Error()))
			}
			u.log.LogAttrs(ctx, slog.LevelWarn, "upstream disconnected", attrs...)
		}
	}
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return d/2 + rand.N(d/2+1)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (u *Upstream) Tools(ctx context.Context) ([]catalog.Tool, error) {
	cs := u.session()
	if cs == nil {
		return nil, fmt.Errorf("%s: %w", u.cfg.ID, ErrUnavailable)
	}
	ctx, cancel := context.WithTimeoutCause(ctx, u.cfg.Timeout, ErrTimeout)
	defer cancel()
	var out []catalog.Tool
	for t, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("list tools %s: %w", u.cfg.ID, err)
		}
		ct, err := u.convert(t)
		if err != nil {
			u.log.WarnContext(
				ctx,
				"upstream tool rejected",
				slog.String("tool", t.Name),
				slog.String("error", err.Error()),
			)
			continue
		}
		out = append(out, ct)
	}
	return out, nil
}

func rawJSON(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	if r, ok := v.(json.RawMessage); ok {
		return r
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func (u *Upstream) convert(t *mcp.Tool) (catalog.Tool, error) {
	name, err := u.naming.Qualify(u.cfg.ID, t.Name)
	if err != nil {
		return catalog.Tool{}, err
	}
	var a catalog.Annotations
	if t.Annotations != nil {
		a.Title = t.Annotations.Title
		a.ReadOnly = t.Annotations.ReadOnlyHint
		a.Idempotent = t.Annotations.IdempotentHint
		a.Destructive = t.Annotations.DestructiveHint == nil || *t.Annotations.DestructiveHint
		a.OpenWorld = t.Annotations.OpenWorldHint == nil || *t.Annotations.OpenWorldHint
		if a.ReadOnly {
			a.Destructive = false
		}
	} else {
		a.Destructive = true
		a.OpenWorld = true
	}
	in, out := rawJSON(t.InputSchema), rawJSON(t.OutputSchema)
	cp := *t
	cp.Name = name
	desc, err := json.Marshal(&cp)
	if err != nil {
		return catalog.Tool{}, fmt.Errorf("encode tool %s: %w", name, err)
	}
	return catalog.Tool{
		Name:        name,
		Upstream:    u.cfg.ID,
		Original:    t.Name,
		Description: t.Description,
		Annotations: a,
		Pin:         catalog.PinHash(t.Name, t.Description, in, out, a),
		Descriptor:  desc,
	}, nil
}

type Call struct {
	Tool           string
	Arguments      json.RawMessage
	Meta           map[string]any
	InputResponses mcp.InputResponseMap
	RequestState   string
}

func (u *Upstream) CallTool(ctx context.Context, c Call) (*mcp.CallToolResult, error) {
	cs := u.session()
	if cs == nil {
		return nil, fmt.Errorf("%s: %w", u.cfg.ID, ErrUnavailable)
	}
	select {
	case u.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", u.cfg.ID, context.Cause(ctx))
	}
	defer func() { <-u.sem }()
	ctx, cancel := context.WithTimeoutCause(ctx, u.cfg.Timeout, ErrTimeout)
	defer cancel()
	params := &mcp.CallToolParams{
		Meta:           c.Meta,
		Name:           c.Tool,
		InputResponses: c.InputResponses,
		RequestState:   c.RequestState,
	}
	if len(c.Arguments) > 0 {
		params.Arguments = c.Arguments
	}
	res, err := u.breaker.Execute(func() (*mcp.CallToolResult, error) {
		return cs.CallTool(ctx, params)
	})
	switch {
	case errors.Is(err, gobreaker.ErrOpenState), errors.Is(err, gobreaker.ErrTooManyRequests):
		return nil, fmt.Errorf("%s: %w", u.cfg.ID, ErrBreakerOpen)
	case err != nil && errors.Is(context.Cause(ctx), ErrTimeout):
		return nil, fmt.Errorf("%s: %w", u.cfg.ID, ErrTimeout)
	case err != nil:
		return nil, fmt.Errorf("call %s/%s: %w", u.cfg.ID, c.Tool, err)
	}
	return res, nil
}

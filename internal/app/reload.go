package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/gateway"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
)

func (a *App) WatchConfig(path string) {
	a.configPath = path
}

func restartSections(cur, next config.Config) []string {
	type section struct {
		name      string
		cur, next any
	}
	var out []string
	for _, s := range []section{
		{"server", cur.Server, next.Server},
		{"auth", cur.Auth, next.Auth},
		{"upstreams", cur.Upstreams, next.Upstreams},
		{"audit", cur.Audit, next.Audit},
		{"telemetry", cur.Telemetry, next.Telemetry},
		{"pinning", cur.Pinning, next.Pinning},
		{"rate_limits.store", cur.RateLimits.Store, next.RateLimits.Store},
		{"rate_limits.redis", cur.RateLimits.Redis, next.RateLimits.Redis},
	} {
		if !reflect.DeepEqual(s.cur, s.next) {
			out = append(out, s.name)
		}
	}
	return out
}

func (a *App) Reload(ctx context.Context, next config.Config) error {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	pol, err := policy.New(next.Policy)
	if err != nil {
		a.metrics.ConfigReloads.WithLabelValues("invalid").Inc()
		return fmt.Errorf("compile policy: %w", err)
	}
	lim, err := ratelimit.New(next.RateLimits, a.backend)
	if err != nil {
		a.metrics.ConfigReloads.WithLabelValues("invalid").Inc()
		return fmt.Errorf("rate limits: %w", err)
	}
	restart := restartSections(a.cfg, next)
	detail := ""
	if len(restart) > 0 {
		detail = "not applied until restart: " + strings.Join(restart, ", ")
	}
	if err := a.gateway.RecordConfig(ctx, gateway.ConfigReloaded, next.Digest, detail); err != nil {
		a.metrics.ConfigReloads.WithLabelValues("audit_failed").Inc()
		return err
	}
	a.gateway.Swap(pol, lim)
	a.cfg.Policy, a.cfg.RateLimits.Rules, a.cfg.Digest = next.Policy, next.RateLimits.Rules, next.Digest
	a.metrics.ConfigReloads.WithLabelValues("ok").Inc()
	attrs := []any{slog.String("sha256", next.Digest)}
	if len(restart) > 0 {
		attrs = append(attrs, slog.String("restart_required", strings.Join(restart, ",")))
	}
	a.log.InfoContext(ctx, "config reloaded: policy and rate limit rules applied", attrs...)
	return nil
}

func (a *App) reloadFromFile(ctx context.Context, path string) {
	next, err := config.Load(path, os.LookupEnv)
	if err == nil {
		err = next.Validate()
	}
	if err == nil {
		err = a.Reload(ctx, next)
	} else {
		a.metrics.ConfigReloads.WithLabelValues("invalid").Inc()
	}
	if err != nil {
		a.log.ErrorContext(ctx, "config reload rejected, keeping the running config",
			slog.String("path", path), slog.String("error", err.Error()))
	}
}

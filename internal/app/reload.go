package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"

	"github.com/Guilherme-Ciano/tollkeeper/internal/bundle"
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
		{"approvals", cur.Approvals, next.Approvals},
		{"bundle", cur.Bundle, next.Bundle},
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
	var verifiedBundle *bundle.Result
	if a.cfg.Bundle.Enabled {
		res, berr := bundle.Verify(bundle.VerifyOptions{
			ManifestPath: a.cfg.Bundle.ManifestFile,
			ConfigDigest: next.Digest,
			PinsPath:     a.cfg.Pinning.File,
			RequirePins:  a.cfg.Bundle.RequirePins,
			Keys:         a.bundleKeys,
		})
		if berr != nil {
			a.metrics.ConfigReloads.WithLabelValues("invalid").Inc()
			return fmt.Errorf("verify signed bundle: %w", berr)
		}
		verifiedBundle = &res
	}
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
	rotated, err := a.rotateAuditKey(ctx, next.Audit.Checkpoint)
	if err != nil {
		a.metrics.ConfigReloads.WithLabelValues("invalid").Inc()
		return fmt.Errorf("rotate audit key: %w", err)
	}
	if rotated {
		a.cfg.Audit.Checkpoint.SigningKeyFile = next.Audit.Checkpoint.SigningKeyFile
		a.cfg.Audit.Checkpoint.KMS = next.Audit.Checkpoint.KMS
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
	if verifiedBundle != nil {
		a.bundleStatus = verifiedBundle
	}
	a.metrics.ConfigReloads.WithLabelValues("ok").Inc()
	attrs := []any{slog.String("sha256", next.Digest)}
	if len(restart) > 0 {
		attrs = append(attrs, slog.String("restart_required", strings.Join(restart, ",")))
	}
	a.log.InfoContext(ctx, "config reloaded: policy and rate limit rules applied", attrs...)
	return nil
}

func (a *App) rotateAuditKey(ctx context.Context, next config.Checkpoint) (bool, error) {
	if a.auditLog == nil || a.auditLog.ActiveKeyID() == "" || a.anchorer != nil || !hasAuditSigner(next) {
		return false, nil
	}
	signer, _, err := buildAuditSigner(ctx, next)
	if err != nil {
		return false, err
	}
	prevID := a.auditLog.ActiveKeyID()
	if signer.KeyID() == prevID {
		return false, nil
	}
	if err := a.auditLog.RotateSigner(ctx, signer); err != nil {
		return false, err
	}
	a.log.InfoContext(ctx, "audit signing key rotated",
		slog.String("prev_key_id", prevID),
		slog.String("new_key_id", signer.KeyID()),
		slog.String("algorithm", signer.Algorithm()))
	return true, nil
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

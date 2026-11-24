package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

const (
	defaultIdempotencyHeader     = "Idempotency-Key"
	defaultIdempotencyMaxEntries = 10000
	defaultIdempotencyPrefix     = "tk:idem:"
	defaultIdempotencyTimeout    = 200 * time.Millisecond
	maxIdempotencyKeyLen         = 256
)

type IdempotencyStore interface {
	Claim(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

type MemoryIdempotencyStore struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	maxEntries int
	now        func() time.Time
}

func NewMemoryIdempotencyStore(maxEntries int, now func() time.Time) *MemoryIdempotencyStore {
	if maxEntries < 100 {
		maxEntries = defaultIdempotencyMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryIdempotencyStore{
		entries:    make(map[string]time.Time),
		maxEntries: maxEntries,
		now:        now,
	}
}

func (s *MemoryIdempotencyStore) Claim(_ context.Context, key string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if exp, ok := s.entries[key]; ok && exp.After(now) {
		return false, nil
	}
	if len(s.entries) >= s.maxEntries {
		s.evictExpiredLocked(now)
	}
	if len(s.entries) >= s.maxEntries {
		s.evictOldestLocked()
	}
	s.entries[key] = now.Add(ttl)
	return true, nil
}

func (s *MemoryIdempotencyStore) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evictExpiredLocked(s.now())
}

func (s *MemoryIdempotencyStore) RunJanitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

func (s *MemoryIdempotencyStore) evictExpiredLocked(now time.Time) int {
	removed := 0
	for k, exp := range s.entries {
		if !exp.After(now) {
			delete(s.entries, k)
			removed++
		}
	}
	return removed
}

func (s *MemoryIdempotencyStore) evictOldestLocked() {
	var oldestKey string
	var oldestExp time.Time
	first := true
	for k, exp := range s.entries {
		if first || exp.Before(oldestExp) {
			oldestKey, oldestExp, first = k, exp, false
		}
	}
	if !first {
		delete(s.entries, oldestKey)
	}
}

type RedisIdempotencyStore struct {
	client  redis.Cmdable
	prefix  string
	timeout time.Duration
}

func NewRedisIdempotencyStore(client redis.Cmdable, prefix string, timeout time.Duration) *RedisIdempotencyStore {
	if prefix == "" {
		prefix = defaultIdempotencyPrefix
	}
	if timeout <= 0 {
		timeout = defaultIdempotencyTimeout
	}
	return &RedisIdempotencyStore{
		client:  client,
		prefix:  prefix,
		timeout: timeout,
	}
}

func (s *RedisIdempotencyStore) Claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	rctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	err := s.client.SetArgs(rctx, s.prefix+key, "1", redis.SetArgs{Mode: "NX", TTL: ttl}).Err()
	if err == nil {
		return true, nil
	}
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	return false, fmt.Errorf("idempotency store claim: %w", err)
}

func (g *Gateway) checkIdempotency(ctx context.Context, w http.ResponseWriter, r *http.Request, a *Admission) bool {
	cfg := g.cfg.Idempotency
	if !cfg.Enabled || g.idempotency == nil || a.Kind != "" {
		return true
	}
	if !idempotencyToolMatch(cfg.Tools, a.Tool.Name) {
		return true
	}
	rawKey, skip, ok := g.extractIdempotencyKey(ctx, w, r, a, cfg)
	if !ok {
		return false
	}
	if skip {
		return true
	}
	scoped := scopedIdempotencyKey(a.Principal.Subject, a.Principal.Tenant, a.Tool.Name, rawKey)
	claimed, err := g.idempotency.Claim(ctx, scoped, cfg.TTL)
	if err != nil {
		g.log.ErrorContext(ctx, "idempotency store claim failed", slog.String("error", err.Error()))
		g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, "idempotency_error").Inc()
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "idempotency store unavailable")
		writeRPCError(
			w,
			http.StatusServiceUnavailable,
			a.Envelope.ID,
			CodeInternal,
			"idempotency store unavailable",
			nil,
		)
		return false
	}
	if !claimed {
		g.metrics.IdempotencyRejections.Inc()
		g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, "duplicate").Inc()
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "duplicate idempotency key")
		writeRPCError(
			w,
			http.StatusConflict,
			a.Envelope.ID,
			CodeDuplicateRequest,
			"duplicate request rejected by idempotency guard",
			map[string]any{"ttl_s": int64(cfg.TTL / time.Second)},
		)
		return false
	}
	return true
}

func (g *Gateway) extractIdempotencyKey(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	a *Admission,
	cfg config.Idempotency,
) (rawKey string, skip, ok bool) {
	if cfg.Mode == config.IdempotencyModeCanonicalHash {
		return canonicalArgsDigest(a.Envelope.Arguments), false, true
	}
	header := cfg.Header
	if header == "" {
		header = defaultIdempotencyHeader
	}
	val := strings.TrimSpace(r.Header.Get(header))
	if val == "" {
		if cfg.Mode == config.IdempotencyModeRequired {
			g.metrics.IdempotencyRejections.Inc()
			g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, "missing_idempotency_key").
				Inc()
			g.recordDecision(ctx, a, audit.DecisionRejected, "", "missing idempotency key header")
			writeRPCError(
				w,
				http.StatusBadRequest,
				a.Envelope.ID,
				CodeInvalidParams,
				"missing required idempotency header: "+header,
				nil,
			)
			return "", false, false
		}
		return "", true, true
	}
	if len(val) > maxIdempotencyKeyLen {
		g.metrics.IdempotencyRejections.Inc()
		g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, "invalid_idempotency_key").
			Inc()
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "idempotency key header too long")
		writeRPCError(w, http.StatusBadRequest, a.Envelope.ID, CodeInvalidParams, "idempotency key too long", nil)
		return "", false, false
	}
	return val, false, true
}

func idempotencyToolMatch(globs []string, name string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, pat := range globs {
		if ok, err := path.Match(pat, name); err == nil && ok {
			return true
		}
	}
	return false
}

func scopedIdempotencyKey(sub, tenant, tool, rawKey string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("tk-idem-v1\x00"))
	_, _ = h.Write([]byte(sub))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(tenant))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(tool))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(rawKey))
	return hex.EncodeToString(h.Sum(nil))
}

func canonicalArgsDigest(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		trimmed = []byte("{}")
	}
	var v any
	if err := json.Unmarshal(trimmed, &v); err == nil {
		if canon, merr := json.Marshal(v); merr == nil {
			trimmed = canon
		}
	}
	sum := sha256.Sum256(trimmed)
	return hex.EncodeToString(sum[:])
}

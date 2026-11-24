package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultReplayMaxEntries = 10000
	defaultReplayPrefix     = "tk:approval:"
	defaultReplayTimeout    = 200 * time.Millisecond
)

type ReplayStore interface {
	Consume(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

func ReplayKey(jti, tool, argsHash string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("tk-approval-jti-v1\x00"))
	_, _ = h.Write([]byte(jti))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(tool))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(argsHash))
	return hex.EncodeToString(h.Sum(nil))
}

type MemoryReplayStore struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	maxEntries int
	now        func() time.Time
}

func NewMemoryReplayStore(maxEntries int, now func() time.Time) *MemoryReplayStore {
	if maxEntries < 100 {
		maxEntries = defaultReplayMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayStore{
		entries:    make(map[string]time.Time),
		maxEntries: maxEntries,
		now:        now,
	}
}

func (s *MemoryReplayStore) Consume(_ context.Context, key string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		ttl = time.Minute
	}
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

func (s *MemoryReplayStore) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evictExpiredLocked(s.now())
}

func (s *MemoryReplayStore) RunJanitor(ctx context.Context, interval time.Duration) {
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

func (s *MemoryReplayStore) evictExpiredLocked(now time.Time) int {
	removed := 0
	for k, exp := range s.entries {
		if !exp.After(now) {
			delete(s.entries, k)
			removed++
		}
	}
	return removed
}

func (s *MemoryReplayStore) evictOldestLocked() {
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

type RedisReplayStore struct {
	client  redis.Cmdable
	prefix  string
	timeout time.Duration
}

func NewRedisReplayStore(client redis.Cmdable, prefix string, timeout time.Duration) *RedisReplayStore {
	if prefix == "" {
		prefix = defaultReplayPrefix
	}
	if timeout <= 0 {
		timeout = defaultReplayTimeout
	}
	return &RedisReplayStore{
		client:  client,
		prefix:  prefix,
		timeout: timeout,
	}
}

func (s *RedisReplayStore) Consume(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	rctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	err := s.client.SetArgs(rctx, s.prefix+key, "1", redis.SetArgs{Mode: "NX", TTL: ttl}).Err()
	if err == nil {
		return true, nil
	}
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	return false, fmt.Errorf("approval replay store consume: %w", err)
}

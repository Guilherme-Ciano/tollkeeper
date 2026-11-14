package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const gcraScript = `
local now = tonumber(ARGV[1])
if now <= 0 then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
end
local nexts = {}
local best = -1
local bestIdx = 1
for i = 1, #KEYS do
  local interval = tonumber(ARGV[2 * i])
  local tol = tonumber(ARGV[2 * i + 1])
  local tat = tonumber(redis.call('GET', KEYS[i])) or now
  local nxt = math.max(tat, now) + interval
  if nxt - now > tol then
    return {0, i, nxt - now - tol, tat - now}
  end
  nexts[i] = nxt
  local remaining = math.floor((tol - (nxt - now)) / interval)
  if best < 0 or remaining < best then
    best = remaining
    bestIdx = i
  end
end
for i = 1, #KEYS do
  redis.call('SET', KEYS[i], nexts[i], 'PX', math.ceil((nexts[i] - now) / 1000) + 1)
end
return {1, bestIdx, best, nexts[bestIdx] - now}
`

var (
	ErrBackend = errors.New("rate limit backend unavailable")
	errReply   = errors.New("unexpected rate limit script reply")
)

type OnBackendError int

const (
	FallbackLocal OnBackendError = iota
	FallbackDeny
)

type RedisOptions struct {
	Prefix  string
	Now     Clock
	Timeout time.Duration
	OnError OnBackendError
	Local   *Store
	Failed  func(error)
}

type Redis struct {
	client redis.Scripter
	script *redis.Script
	opts   RedisOptions
}

func NewRedis(client redis.Scripter, opts RedisOptions) *Redis {
	if opts.Timeout <= 0 {
		opts.Timeout = 50 * time.Millisecond
	}
	if opts.OnError == FallbackLocal && opts.Local == nil {
		opts.Local = NewStore(opts.Now)
	}
	return &Redis{client: client, script: redis.NewScript(gcraScript), opts: opts}
}

func micros(d time.Duration) int64 {
	return max(int64(d/time.Microsecond), 1)
}

func (r *Redis) Allow(ctx context.Context, reqs []Request) Result {
	if len(reqs) == 0 {
		return Result{Allowed: true}
	}
	res, err := r.eval(ctx, reqs)
	if err == nil {
		return res
	}
	if r.opts.Failed != nil {
		r.opts.Failed(err)
	}
	if r.opts.OnError == FallbackDeny {
		return Result{Allowed: false, Rule: reqs[0].Limit.Rule, Limit: reqs[0].Limit, RetryAfter: time.Second}
	}
	return r.opts.Local.Allow(ctx, reqs)
}

func (r *Redis) eval(ctx context.Context, reqs []Request) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	keys := make([]string, len(reqs))
	args := make([]any, 0, 1+2*len(reqs))
	now := int64(0)
	if r.opts.Now != nil {
		now = r.opts.Now().UnixMicro()
	}
	args = append(args, now)
	for i, q := range reqs {
		keys[i] = r.opts.Prefix + q.Key
		interval := micros(q.Limit.Interval)
		args = append(args, interval, interval*int64(q.Limit.Burst))
	}
	raw, err := r.script.Run(ctx, r.client, keys, args...).Int64Slice()
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrBackend, err)
	}
	if len(raw) != 4 || raw[1] < 1 || int(raw[1]) > len(reqs) {
		return Result{}, fmt.Errorf("%w: %w: %v", ErrBackend, errReply, raw)
	}
	lim := reqs[raw[1]-1].Limit
	if raw[0] == 0 {
		return Result{
			Allowed:    false,
			Rule:       lim.Rule,
			Limit:      lim,
			RetryAfter: time.Duration(raw[2]) * time.Microsecond,
			ResetAfter: time.Duration(raw[3]) * time.Microsecond,
		}, nil
	}
	return Result{
		Allowed:    true,
		Rule:       lim.Rule,
		Limit:      lim,
		Remaining:  int(raw[2]),
		ResetAfter: time.Duration(raw[3]) * time.Microsecond,
	}, nil
}

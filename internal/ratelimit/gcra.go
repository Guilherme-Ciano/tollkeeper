package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type Limit struct {
	Rule     string
	Interval time.Duration
	Burst    int
	Count    int
	Per      time.Duration
}

func NewLimit(rule string, count int, per time.Duration, burst int) Limit {
	return Limit{
		Rule:     rule,
		Interval: per / time.Duration(count),
		Burst:    burst,
		Count:    count,
		Per:      per,
	}
}

func (l Limit) tolerance() int64 {
	return int64(l.Interval) * int64(l.Burst)
}

type Result struct {
	Allowed    bool
	Rule       string
	Limit      Limit
	Remaining  int
	RetryAfter time.Duration
	ResetAfter time.Duration
}

type Clock func() time.Time

type cell struct {
	tat atomic.Int64
}

type Store struct {
	cells sync.Map
	now   Clock
	epoch time.Time
}

func NewStore(now Clock) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, epoch: now()}
}

func (s *Store) nanos() int64 {
	return int64(s.now().Sub(s.epoch))
}

func (s *Store) cell(key string) *cell {
	if c, ok := s.cells.Load(key); ok {
		if typed, ok := c.(*cell); ok {
			return typed
		}
	}
	fresh := &cell{}
	c, _ := s.cells.LoadOrStore(key, fresh)
	if typed, ok := c.(*cell); ok {
		return typed
	}
	return fresh
}

func (s *Store) take(key string, lim Limit, cost int, now int64) (res Result, c *cell, step int64) {
	if cost < 1 {
		cost = 1
	}
	interval := int64(lim.Interval)
	tol := lim.tolerance()
	if cost > lim.Burst {
		return Result{
			Allowed:    false,
			Rule:       lim.Rule,
			Limit:      lim,
			RetryAfter: time.Duration(interval*int64(cost) - tol),
		}, nil, 0
	}
	step = interval * int64(cost)
	c = s.cell(key)
	for {
		tat := c.tat.Load()
		base := max(tat, now)
		next := base + step
		if next-now > tol {
			retry := time.Duration(next - now - tol)
			return Result{
				Allowed:    false,
				Rule:       lim.Rule,
				Limit:      lim,
				RetryAfter: retry,
				ResetAfter: time.Duration(tat - now),
			}, nil, 0
		}
		if c.tat.CompareAndSwap(tat, next) {
			remaining := int((tol - (next - now)) / interval)
			return Result{
				Allowed:    true,
				Rule:       lim.Rule,
				Limit:      lim,
				Remaining:  remaining,
				ResetAfter: time.Duration(next - now),
			}, c, step
		}
	}
}

type Request struct {
	Key   string
	Limit Limit
	Cost  int
}

func (s *Store) Allow(_ context.Context, reqs []Request) Result {
	now := s.nanos()
	type taken struct {
		c    *cell
		step int64
	}
	committed := make([]taken, 0, len(reqs))
	var tightest Result
	for i, r := range reqs {
		res, c, step := s.take(r.Key, r.Limit, r.Cost, now)
		if !res.Allowed {
			for _, done := range committed {
				done.c.tat.Add(-done.step)
			}
			return res
		}
		committed = append(committed, taken{c: c, step: step})
		if i == 0 || res.Remaining < tightest.Remaining {
			tightest = res
		}
	}
	if len(reqs) == 0 {
		return Result{Allowed: true}
	}
	return tightest
}

func (s *Store) Sweep() int {
	now := s.nanos()
	n := 0
	s.cells.Range(func(k, v any) bool {
		c, ok := v.(*cell)
		if ok && c.tat.Load() < now {
			if s.cells.CompareAndDelete(k, v) {
				n++
			}
		}
		return true
	})
	return n
}

func (s *Store) Len() int {
	n := 0
	s.cells.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func (s *Store) RunJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
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

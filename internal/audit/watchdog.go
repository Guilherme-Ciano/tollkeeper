package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const defaultWatchInterval = 5 * time.Minute

type WatchStatus struct {
	ChainID      string
	Records      uint64
	Checkpoints  uint64
	KeyRotations uint64
	LastSeq      uint64
	LastHash     string
	UnsignedTail uint64
	Healthy      bool
	Error        string
	VerifiedAt   time.Time
}

type WatchdogOptions struct {
	Path          string
	ChainID       string
	VerifyOptions VerifyOptions
	Interval      time.Duration
	MaxUnsigned   uint64
	Now           func() time.Time
	OnResult      func(WatchStatus)
}

type Watchdog struct {
	opts     WatchdogOptions
	mu       sync.Mutex
	prevSeq  uint64
	prevHash string
	latest   atomic.Pointer[WatchStatus]
}

func NewWatchdog(opts WatchdogOptions) *Watchdog {
	if opts.Interval <= 0 {
		opts.Interval = defaultWatchInterval
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Watchdog{opts: opts}
}

func (w *Watchdog) Status() (WatchStatus, bool) {
	if p := w.latest.Load(); p != nil {
		return *p, true
	}
	return WatchStatus{}, false
}

func (w *Watchdog) Check(_ context.Context) WatchStatus {
	now := w.opts.Now().UTC()
	st := WatchStatus{VerifiedAt: now}
	f, err := os.Open(w.opts.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			st.Healthy = true
			return w.record(st)
		}
		st.Error = fmt.Sprintf("open audit log: %v", err)
		return w.record(st)
	}
	defer f.Close()

	rep, err := VerifyWith(f, w.opts.VerifyOptions)
	st.ChainID = rep.ChainID
	st.Records = rep.Records
	st.Checkpoints = rep.Checkpoints
	st.KeyRotations = rep.KeyRotations
	st.LastSeq = rep.LastSeq
	st.LastHash = rep.LastHash
	st.UnsignedTail = rep.UnsignedTail
	if err != nil {
		st.Error = err.Error()
		return w.record(st)
	}
	if w.opts.ChainID != "" && rep.Records > 0 && rep.ChainID != w.opts.ChainID {
		st.Error = fmt.Sprintf("chain id %q does not match expected %q", rep.ChainID, w.opts.ChainID)
		return w.record(st)
	}
	if err := w.checkMonotonic(rep); err != nil {
		st.Error = err.Error()
		return w.record(st)
	}
	if w.opts.MaxUnsigned > 0 && rep.UnsignedTail > w.opts.MaxUnsigned {
		st.Error = fmt.Sprintf("unsigned tail %d exceeds max_unsigned %d", rep.UnsignedTail, w.opts.MaxUnsigned)
		return w.record(st)
	}
	st.Healthy = true
	return w.record(st)
}

func (w *Watchdog) checkMonotonic(rep Report) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.prevSeq > 0 {
		if rep.LastSeq < w.prevSeq {
			return fmt.Errorf("audit log truncated: seq shrank from %d to %d: %w", w.prevSeq, rep.LastSeq, ErrTampered)
		}
		if rep.LastSeq == w.prevSeq && rep.LastHash != w.prevHash {
			return fmt.Errorf("audit log head rewritten at seq %d: %w", rep.LastSeq, ErrTampered)
		}
	}
	if rep.LastSeq > 0 {
		w.prevSeq = rep.LastSeq
		w.prevHash = rep.LastHash
	}
	return nil
}

func (w *Watchdog) record(st WatchStatus) WatchStatus {
	cp := st
	w.latest.Store(&cp)
	if w.opts.OnResult != nil {
		w.opts.OnResult(st)
	}
	return st
}

func (w *Watchdog) Run(ctx context.Context) {
	w.Check(ctx)
	t := time.NewTicker(w.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Check(ctx)
		}
	}
}

package anchor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

const (
	OutcomeOK             = "ok"
	OutcomeRetry          = "retry"
	OutcomeRejected       = "rejected"
	OutcomeInvalidReceipt = "invalid_receipt"
	OutcomeDropped        = "dropped"
)

var ErrNoSchedule = errors.New("anchoring needs every or interval")

type Submitter interface {
	Submit(ctx context.Context, s Submission) (Receipt, error)
}

type Timestamper interface {
	Timestamp(ctx context.Context, statement []byte) ([]byte, error)
}

type ReceiptSink interface {
	AppendAnchor(ref audit.CheckpointRef, a *audit.Anchor) error
}

type Hooks struct {
	Attempt  func(outcome string)
	Duration func(time.Duration)
	Anchored func(coveredSeq uint64, at time.Time)
}

type Options struct {
	ChainID     string
	Key         ed25519.PrivateKey
	Every       int
	Interval    time.Duration
	Timeout     time.Duration
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	MinSpacing  time.Duration
	Verifier    *ReceiptVerifier
	Timestamper Timestamper
	Logger      *slog.Logger
	Hooks       Hooks
	Now         func() time.Time
}

type Anchorer struct {
	opts   Options
	pub    ed25519.PublicKey
	submit Submitter
	sink   ReceiptSink

	mu           sync.Mutex
	latest       audit.CheckpointRef
	haveLatest   bool
	sinceAnchor  int
	anchoredSeq  uint64
	skipSeq      uint64
	lastAnchorAt time.Time
	started      time.Time
	lastSuccess  atomic.Int64
	wake         chan struct{}
}

func New(opts Options, s Submitter, sink ReceiptSink) (*Anchorer, error) {
	if opts.Every <= 0 && opts.Interval <= 0 {
		return nil, ErrNoSchedule
	}
	if opts.Key == nil || opts.Verifier == nil || s == nil || sink == nil {
		return nil, fmt.Errorf("%w: key, verifier, submitter and sink are required", ErrBadTrust)
	}
	pub, ok := opts.Key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, audit.ErrKeyType
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = time.Minute
	}
	if opts.BaseBackoff <= 0 {
		opts.BaseBackoff = 2 * time.Second
	}
	if opts.MaxBackoff < opts.BaseBackoff {
		opts.MaxBackoff = max(opts.BaseBackoff, 10*time.Minute)
	}
	if opts.MinSpacing <= 0 {
		opts.MinSpacing = time.Minute
	}
	return &Anchorer{
		opts: opts, pub: pub, submit: s, sink: sink, wake: make(chan struct{}, 1), started: opts.Now(),
	}, nil
}

func (a *Anchorer) Offer(ref audit.CheckpointRef) {
	a.mu.Lock()
	if !a.haveLatest || ref.Seq > a.latest.Seq {
		a.latest, a.haveLatest = ref, true
		a.sinceAnchor++
	}
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *Anchorer) LastSuccess() time.Time {
	ns := a.lastSuccess.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (a *Anchorer) Committed(ref audit.CheckpointRef) {
	now := a.opts.Now()
	a.lastSuccess.Store(now.UnixNano())
	if a.opts.Hooks.Anchored != nil {
		a.opts.Hooks.Anchored(ref.Seq, now)
	}
}

func (a *Anchorer) Stale(now time.Time, after time.Duration) bool {
	if _, due, _ := a.next(now); !due {
		return false
	}
	last := a.LastSuccess()
	if last.Before(a.started) {
		last = a.started
	}
	return now.Sub(last) > after
}

func (a *Anchorer) next(now time.Time) (audit.CheckpointRef, bool, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.haveLatest || a.latest.Seq == a.anchoredSeq || a.latest.Seq == a.skipSeq {
		return audit.CheckpointRef{}, false, 0
	}
	since := a.lastAnchorAt
	if since.IsZero() {
		since = a.started
	}
	elapsed := now.Sub(since)
	if elapsed < a.opts.MinSpacing {
		return audit.CheckpointRef{}, false, a.opts.MinSpacing - elapsed
	}
	if a.opts.Every > 0 && a.sinceAnchor >= a.opts.Every {
		return a.latest, true, 0
	}
	if a.opts.Interval <= 0 {
		return audit.CheckpointRef{}, false, 0
	}
	if a.lastAnchorAt.IsZero() || elapsed >= a.opts.Interval {
		return a.latest, true, 0
	}
	return audit.CheckpointRef{}, false, a.opts.Interval - elapsed
}

func (a *Anchorer) current() audit.CheckpointRef {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.latest
}

func (a *Anchorer) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		ref, due, wait := a.next(a.opts.Now())
		if due {
			if !a.anchorWithRetry(ctx, ref) {
				return
			}
			continue
		}
		var tick <-chan time.Time
		if wait > 0 {
			timer.Reset(wait)
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-a.wake:
		case <-tick:
		}
	}
}

func (a *Anchorer) anchorWithRetry(ctx context.Context, ref audit.CheckpointRef) bool {
	for attempt := 0; ; attempt++ {
		an, err := a.AnchorNow(ctx, ref)
		if err == nil {
			return a.deliver(ref, an)
		}
		if ctx.Err() != nil {
			return false
		}
		if !IsRetryable(err) {
			a.reject(ref, err)
			return true
		}
		d := a.backoff(attempt, err)
		a.outcome(OutcomeRetry)
		a.opts.Logger.WarnContext(ctx, "audit anchoring failed, will retry",
			slog.Uint64("covers_seq", ref.Seq), slog.Int("attempt", attempt+1),
			slog.Duration("next_retry", d), slog.String("error", err.Error()))
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
		ref = a.current()
	}
}

func (a *Anchorer) backoff(attempt int, err error) time.Duration {
	d := a.opts.MaxBackoff
	if attempt < 30 {
		d = min(a.opts.MaxBackoff, a.opts.BaseBackoff<<attempt)
	}
	d = d/2 + rand.N(d/2+1)
	var he *HTTPError
	if errors.As(err, &he) && he.RetryAfter > d {
		d = min(he.RetryAfter, a.opts.MaxBackoff)
	}
	return d
}

func (a *Anchorer) reject(ref audit.CheckpointRef, err error) {
	outcome := OutcomeRejected
	if errors.Is(err, ErrInvalidReceipt) || errors.Is(err, ErrUntrustedLog) || errors.Is(err, ErrDigestMismatch) ||
		errors.Is(err, ErrUntrustedTimestamp) || errors.Is(err, ErrNoProvenTime) ||
		errors.Is(err, ErrWitnessQuorum) {
		outcome = OutcomeInvalidReceipt
	}
	a.outcome(outcome)
	a.opts.Logger.Error("audit anchoring failed for this checkpoint",
		slog.Uint64("covers_seq", ref.Seq), slog.String("outcome", outcome), slog.String("error", err.Error()))
	a.mu.Lock()
	a.skipSeq = ref.Seq
	a.mu.Unlock()
}

func (a *Anchorer) deliver(ref audit.CheckpointRef, an *audit.Anchor) bool {
	err := a.sink.AppendAnchor(ref, an)
	if errors.Is(err, audit.ErrClosed) {
		return false
	}
	now := a.opts.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastAnchorAt = now
	if err != nil {
		a.outcome(OutcomeDropped)
		a.opts.Logger.Warn("audit anchor receipt dropped", slog.Uint64("covers_seq", ref.Seq),
			slog.String("error", err.Error()))
		return true
	}
	a.outcome(OutcomeOK)
	a.anchoredSeq = ref.Seq
	a.sinceAnchor = 0
	return true
}

func (a *Anchorer) outcome(o string) {
	if a.opts.Hooks.Attempt != nil {
		a.opts.Hooks.Attempt(o)
	}
}

func (a *Anchorer) AnchorNow(ctx context.Context, ref audit.CheckpointRef) (*audit.Anchor, error) {
	sub, err := Sign(a.opts.Key, ref)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, a.opts.Timeout)
	defer cancel()
	var token []byte
	if a.opts.Timestamper != nil {
		statement, err := audit.AnchorStatement(ref.ChainID, ref.Seq, ref.Hash)
		if err != nil {
			return nil, err
		}
		if token, err = a.opts.Timestamper.Timestamp(ctx, statement); err != nil {
			return nil, err
		}
	}
	start := time.Now()
	rec, err := a.submit.Submit(ctx, sub)
	if a.opts.Hooks.Duration != nil {
		a.opts.Hooks.Duration(time.Since(start))
	}
	if err != nil {
		return nil, err
	}
	origin, _, _ := strings.Cut(rec.Checkpoint, "\n")
	an := NewAnchor(ref, a.pub, origin, rec)
	an.Timestamp = token
	if _, err := a.opts.Verifier.VerifyAnchor(a.opts.ChainID, an, ref, a.pub); err != nil {
		return nil, err
	}
	return an, nil
}

package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type Hooks struct {
	Dropped    func()
	SinkError  func(error)
	QueueDepth func(int)
	Written    func(int)
}

type Options struct {
	Path               string
	ChainID            string
	Buffer             int
	BatchSize          int
	FlushInterval      time.Duration
	Fsync              bool
	FailOpen           bool
	Signer             ed25519.PrivateKey
	CheckpointEvery    int
	CheckpointInterval time.Duration
	Now                func() time.Time
	Hooks              Hooks
	Mirror             Mirror
	MirrorTimeout      time.Duration
}

type logFile interface {
	io.Writer
	io.ReaderAt
	io.Closer
	Stat() (os.FileInfo, error)
	Sync() error
	Truncate(size int64) error
}

type Log struct {
	opts      Options
	file      logFile
	ch        chan Event
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	sendMu    sync.RWMutex
	closed    atomic.Bool
	dropped   atomic.Uint64
	sinkErr   atomic.Pointer[error]
	fatal     atomic.Bool
	runErr    error

	seq          uint64
	prev         string
	lastCkptSeq  uint64
	lastCkptTime time.Time
	buf          bytes.Buffer
	rows         []Row
}

func Open(opts Options) (*Log, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Buffer < 1 {
		opts.Buffer = 1024
	}
	if opts.BatchSize < 1 {
		opts.BatchSize = 256
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 50 * time.Millisecond
	}
	if opts.MirrorTimeout <= 0 {
		opts.MirrorTimeout = 5 * time.Second
	}
	f, err := os.OpenFile(opts.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	l := &Log{
		opts:         opts,
		file:         f,
		ch:           make(chan Event, opts.Buffer),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		prev:         ZeroHash,
		lastCkptTime: opts.Now(),
	}
	if err := l.recover(); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if opts.Mirror != nil {
		if err := l.reconcile(); err != nil {
			return nil, errors.Join(err, f.Close())
		}
	}
	go l.run()
	return l, nil
}

func (l *Log) recover() error {
	last, err := lastLine(l.file)
	if err != nil {
		return err
	}
	if len(last) == 0 {
		return nil
	}
	var rec Record
	if err := json.Unmarshal(last, &rec); err != nil {
		return fmt.Errorf("audit log tail is not a record, refusing to continue the chain: %w", ErrMalformed)
	}
	var body Body
	if err := json.Unmarshal(rec.Body, &body); err != nil {
		return fmt.Errorf("audit log tail body: %w", ErrMalformed)
	}
	if body.ChainID != l.opts.ChainID {
		return fmt.Errorf(
			"audit log chain %q does not match configured chain %q: %w",
			body.ChainID,
			l.opts.ChainID,
			ErrMalformed,
		)
	}
	l.seq = body.Seq
	l.prev = rec.Hash
	if body.Checkpoint != nil {
		l.lastCkptSeq = body.Seq
	}
	return nil
}

func lastLine(f logFile) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat audit log: %w", err)
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}
	const chunk = 64 << 10
	var tail []byte
	for off := size; off > 0; {
		n := min(int64(chunk), off)
		off -= n
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read audit log tail: %w", err)
		}
		tail = append(slices.Clip(buf), tail...)
		trimmed := bytes.TrimRight(tail, "\n")
		if _, last, found := bytes.CutLast(trimmed, []byte("\n")); found {
			return last, nil
		}
		if off == 0 {
			return trimmed, nil
		}
	}
	return nil, nil
}

func (l *Log) Seq() uint64 {
	return atomic.LoadUint64(&l.seq)
}

func (l *Log) Dropped() uint64 {
	return l.dropped.Load()
}

func (l *Log) QueueDepth() int {
	return len(l.ch)
}

func (l *Log) SinkErr() error {
	if p := l.sinkErr.Load(); p != nil {
		return *p
	}
	return nil
}

func (l *Log) Append(ctx context.Context, e Event) error {
	l.sendMu.RLock()
	defer l.sendMu.RUnlock()
	if l.closed.Load() {
		return ErrClosed
	}
	if err := l.SinkErr(); err != nil && !l.opts.FailOpen {
		return fmt.Errorf("%w: %w", ErrSinkFailed, err)
	}
	select {
	case l.ch <- e:
		return nil
	default:
	}
	if l.opts.FailOpen {
		l.dropped.Add(1)
		if l.opts.Hooks.Dropped != nil {
			l.opts.Hooks.Dropped()
		}
		return nil
	}
	select {
	case l.ch <- e:
		return nil
	case <-l.stop:
		return ErrClosed
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrBackpressure, context.Cause(ctx))
	}
}

func (l *Log) flush(batch []Event) []Event {
	if len(batch) == 0 && !l.checkpointDue() && l.dropped.Load() == 0 {
		return batch
	}
	if err := l.write(batch); err != nil {
		l.runErr = err
		l.sinkErr.Store(&err)
		l.dropped.Add(uint64(len(batch)))
		if l.opts.Hooks.SinkError != nil {
			l.opts.Hooks.SinkError(err)
		}
		return batch[:0]
	}
	if !l.fatal.Load() {
		l.sinkErr.Store(nil)
		l.runErr = nil
	}
	return batch[:0]
}

func (l *Log) drain(batch []Event) []Event {
	for {
		select {
		case e := <-l.ch:
			batch = append(batch, e)
		default:
			return batch
		}
	}
}

func (l *Log) shutdown(batch []Event) {
	if err := l.write(l.drain(batch)); err != nil {
		l.runErr = err
	}
	if l.opts.Signer == nil || l.seq <= l.lastCkptSeq {
		return
	}
	l.resetBatch()
	if err := l.appendCheckpoint(); err != nil {
		l.runErr = errors.Join(l.runErr, err)
		return
	}
	l.runErr = errors.Join(l.runErr, l.commit())
}

func (l *Log) run() {
	defer close(l.done)
	ticker := time.NewTicker(l.opts.FlushInterval)
	defer ticker.Stop()
	batch := make([]Event, 0, l.opts.BatchSize)
	for {
		select {
		case e := <-l.ch:
			batch = append(batch, e)
			if len(batch) >= l.opts.BatchSize {
				batch = l.flush(batch)
			}
		case <-ticker.C:
			if l.opts.Hooks.QueueDepth != nil {
				l.opts.Hooks.QueueDepth(len(l.ch))
			}
			batch = l.flush(batch)
		case <-l.stop:
			l.shutdown(batch)
			return
		}
	}
}

func (l *Log) checkpointDue() bool {
	if l.opts.Signer == nil || l.seq == l.lastCkptSeq {
		return false
	}
	if l.opts.CheckpointEvery > 0 && l.seq-l.lastCkptSeq >= uint64(l.opts.CheckpointEvery) {
		return true
	}
	return l.opts.CheckpointInterval > 0 && l.opts.Now().Sub(l.lastCkptTime) >= l.opts.CheckpointInterval
}

func (l *Log) appendBody(b *Body) error {
	b.Seq = l.seq + 1
	b.TS = l.opts.Now().UnixNano()
	b.ChainID = l.opts.ChainID
	b.Prev = l.prev
	rec, err := Seal(b)
	if err != nil {
		return err
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode audit line: %w", err)
	}
	l.buf.Write(line)
	l.buf.WriteByte('\n')
	if l.opts.Mirror != nil {
		l.rows = append(l.rows, rowFor(b, rec))
	}
	atomic.StoreUint64(&l.seq, b.Seq)
	l.prev = rec.Hash
	return nil
}

func (l *Log) appendCheckpoint() error {
	ck, err := SignCheckpoint(l.opts.Signer, l.opts.ChainID, l.seq, l.prev)
	if err != nil {
		return err
	}
	if err := l.appendBody(&Body{Checkpoint: ck}); err != nil {
		return err
	}
	l.lastCkptSeq = l.seq
	l.lastCkptTime = l.opts.Now()
	return nil
}

func (l *Log) write(batch []Event) (err error) {
	if l.fatal.Load() {
		return ErrCorrupt
	}
	seq, prev, ckSeq, ckTime := l.seq, l.prev, l.lastCkptSeq, l.lastCkptTime
	d := l.dropped.Swap(0)
	defer func() {
		if err != nil {
			atomic.StoreUint64(&l.seq, seq)
			l.prev, l.lastCkptSeq, l.lastCkptTime = prev, ckSeq, ckTime
			l.dropped.Add(d)
		}
	}()
	l.resetBatch()
	if d > 0 {
		if err := l.appendBody(
			&Body{Event: &Event{Phase: PhaseDecision, Method: "audit", Decision: DecisionGap, Dropped: d}},
		); err != nil {
			return err
		}
	}
	for i := range batch {
		if err := l.appendBody(&Body{Event: &batch[i]}); err != nil {
			return err
		}
		if l.checkpointDue() {
			if err := l.appendCheckpoint(); err != nil {
				return err
			}
		}
	}
	if l.checkpointDue() {
		if err := l.appendCheckpoint(); err != nil {
			return err
		}
	}
	if err := l.commit(); err != nil {
		return err
	}
	if l.opts.Hooks.Written != nil {
		l.opts.Hooks.Written(len(batch))
	}
	return nil
}

func (l *Log) resetBatch() {
	l.buf.Reset()
	l.rows = l.rows[:0]
}

func (l *Log) commit() error {
	if l.buf.Len() == 0 {
		return nil
	}
	info, err := l.file.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	var pending Pending
	ctx, cancel := l.mirrorContext()
	defer cancel()
	if l.opts.Mirror != nil {
		if pending, err = l.opts.Mirror.Prepare(ctx, l.rows); err != nil {
			return fmt.Errorf("stage audit mirror: %w", err)
		}
	}
	if err := l.writeFile(); err != nil {
		if pending != nil {
			pending.Abort(ctx)
		}
		return l.undo(info.Size(), err)
	}
	if pending != nil {
		if err := pending.Commit(ctx); err != nil {
			return l.undo(info.Size(), fmt.Errorf("commit audit mirror: %w", err))
		}
	}
	return nil
}

func (l *Log) writeFile() error {
	if _, err := l.file.Write(l.buf.Bytes()); err != nil {
		return fmt.Errorf("write audit batch: %w", err)
	}
	if l.opts.Fsync {
		if err := l.file.Sync(); err != nil {
			return fmt.Errorf("fsync audit log: %w", err)
		}
	}
	return nil
}

func (l *Log) undo(size int64, cause error) error {
	if err := l.file.Truncate(size); err != nil {
		l.fatal.Store(true)
		fatal := fmt.Errorf("%w: %w: truncate after failed write: %w", ErrCorrupt, cause, err)
		l.sinkErr.Store(&fatal)
		return fatal
	}
	return cause
}

func (l *Log) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.sendMu.Lock()
		l.closed.Store(true)
		close(l.stop)
		l.sendMu.Unlock()
		<-l.done
		err = errors.Join(l.runErr, l.file.Close())
	})
	return err
}

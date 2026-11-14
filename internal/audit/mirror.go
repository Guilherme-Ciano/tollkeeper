package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	KindEvent      = "event"
	KindCheckpoint = "checkpoint"

	reconcileBatch = 1000
	maxLineBytes   = 16 << 20
)

var ErrMirrorAhead = errors.New("audit mirror holds records the local log does not")

type Row struct {
	ChainID string
	Seq     uint64
	TS      time.Time
	Kind    string
	Hash    string
	Prev    string
	Raw     json.RawMessage
}

type Pending interface {
	Commit(ctx context.Context) error
	Abort(ctx context.Context)
}

type Mirror interface {
	Prepare(ctx context.Context, rows []Row) (Pending, error)
	LastSeq(ctx context.Context, chainID string) (uint64, error)
}

func rowFor(b *Body, rec Record) Row {
	kind := KindEvent
	if b.Checkpoint != nil {
		kind = KindCheckpoint
	}
	return Row{
		ChainID: b.ChainID,
		Seq:     b.Seq,
		TS:      time.Unix(0, b.TS).UTC(),
		Kind:    kind,
		Hash:    rec.Hash,
		Prev:    b.Prev,
		Raw:     rec.Body,
	}
}

func (l *Log) mirrorContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), l.opts.MirrorTimeout)
}

func (l *Log) reconcile() error {
	ctx, cancel := l.mirrorContext()
	defer cancel()
	last, err := l.opts.Mirror.LastSeq(ctx, l.opts.ChainID)
	if err != nil {
		return fmt.Errorf("read audit mirror position: %w", err)
	}
	if last > l.seq {
		return fmt.Errorf("%w: mirror at seq %d, log at seq %d", ErrMirrorAhead, last, l.seq)
	}
	if last == l.seq {
		return nil
	}
	info, err := l.file.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	return l.backfill(io.NewSectionReader(l.file, 0, info.Size()), last)
}

func (l *Log) backfill(r io.Reader, after uint64) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	batch := make([]Row, 0, reconcileBatch)
	for sc.Scan() {
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("backfill audit mirror: %w", ErrMalformed)
		}
		var body Body
		if err := json.Unmarshal(rec.Body, &body); err != nil {
			return fmt.Errorf("backfill audit mirror: %w", ErrMalformed)
		}
		if body.Seq <= after {
			continue
		}
		rec.Body = append(json.RawMessage(nil), rec.Body...)
		batch = append(batch, rowFor(&body, rec))
		if len(batch) == reconcileBatch {
			if err := l.mirrorRows(batch); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read audit log for mirror backfill: %w", err)
	}
	if len(batch) == 0 {
		return nil
	}
	return l.mirrorRows(batch)
}

func (l *Log) mirrorRows(rows []Row) error {
	ctx, cancel := l.mirrorContext()
	defer cancel()
	p, err := l.opts.Mirror.Prepare(ctx, rows)
	if err != nil {
		return fmt.Errorf("backfill audit mirror: %w", err)
	}
	if err := p.Commit(ctx); err != nil {
		return fmt.Errorf("backfill audit mirror: %w", err)
	}
	return nil
}

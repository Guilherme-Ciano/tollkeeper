package pgsink

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

//go:embed schema.sql
var schema string

const migrationLock = 7_365_420_917

var columns = []string{"chain_id", "seq", "ts", "kind", "hash", "prev", "body", "raw"}

type Sink struct {
	pool *pgxpool.Pool
}

func Connect(ctx context.Context, dsn string) (*Sink, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect audit postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect audit postgres: %w", err)
	}
	return &Sink{pool: pool}, nil
}

func Open(ctx context.Context, dsn string) (*Sink, error) {
	s, err := Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := s.Migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Sink) Migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate audit postgres: %w", err)
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLock); err != nil {
		return fmt.Errorf("migrate audit postgres: %w", err)
	}
	if _, err := tx.Exec(ctx, schema); err != nil {
		return fmt.Errorf("migrate audit postgres: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migrate audit postgres: %w", err)
	}
	return nil
}

func rollback(ctx context.Context, tx pgx.Tx) {
	_ = tx.Rollback(context.WithoutCancel(ctx))
}

type pending struct {
	tx pgx.Tx
}

func (p *pending) Commit(ctx context.Context) error {
	if err := p.tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit audit rows: %w", err)
	}
	return nil
}

func (p *pending) Abort(ctx context.Context) {
	rollback(ctx, p.tx)
}

func (s *Sink) Prepare(ctx context.Context, rows []audit.Row) (audit.Pending, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin audit rows: %w", err)
	}
	src := pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
		r := &rows[i]
		return []any{r.ChainID, int64(r.Seq), r.TS, r.Kind, r.Hash, r.Prev, string(r.Raw), string(r.Raw)}, nil
	})
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tollkeeper_audit"}, columns, src); err != nil {
		rollback(ctx, tx)
		return nil, fmt.Errorf("copy audit rows: %w", err)
	}
	return &pending{tx: tx}, nil
}

func (s *Sink) LastSeq(ctx context.Context, chainID string) (uint64, error) {
	var last int64
	err := s.pool.QueryRow(ctx,
		"SELECT coalesce(max(seq), 0) FROM tollkeeper_audit WHERE chain_id = $1", chainID).Scan(&last)
	if err != nil {
		return 0, fmt.Errorf("read audit position: %w", err)
	}
	return uint64(last), nil
}

func (s *Sink) Export(ctx context.Context, chainID string, w io.Writer) error {
	rows, err := s.pool.Query(ctx,
		"SELECT raw, hash FROM tollkeeper_audit WHERE chain_id = $1 ORDER BY seq", chainID)
	if err != nil {
		return fmt.Errorf("export audit rows: %w", err)
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var raw, hash string
		if err := rows.Scan(&raw, &hash); err != nil {
			return fmt.Errorf("export audit rows: %w", err)
		}
		if err := enc.Encode(audit.Record{Body: json.RawMessage(raw), Hash: hash}); err != nil {
			return fmt.Errorf("export audit rows: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("export audit rows: %w", err)
	}
	return nil
}

func (s *Sink) Close() {
	s.pool.Close()
}

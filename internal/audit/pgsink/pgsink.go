package pgsink

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

//go:embed schema.sql
var schema string

const migrationLock = 7_365_420_917

var errSeqRange = errors.New("audit sequence out of range")

func columns() []string {
	return []string{"chain_id", "seq", "ts", "kind", "hash", "prev", "body", "raw"}
}

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

func (s *Sink) Migrate(ctx context.Context) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate audit postgres: %w", err)
	}
	defer func() {
		err = errors.Join(err, rollback(ctx, tx))
	}()
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

func rollback(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("rollback audit transaction: %w", err)
	}
	return nil
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

func (p *pending) Abort(ctx context.Context) error {
	return rollback(ctx, p.tx)
}

func (s *Sink) Prepare(ctx context.Context, rows []audit.Row) (audit.Pending, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin audit rows: %w", err)
	}
	src := pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
		r := &rows[i]
		if r.Seq > math.MaxInt64 {
			return nil, fmt.Errorf("%w: %d", errSeqRange, r.Seq)
		}
		return []any{r.ChainID, int64(r.Seq), r.TS, r.Kind, r.Hash, r.Prev, nil, string(r.Raw)}, nil
	})
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tollkeeper_audit"}, columns(), src); err != nil {
		return nil, errors.Join(fmt.Errorf("copy audit rows: %w", err), rollback(ctx, tx))
	}
	return &pending{tx: tx}, nil
}

func (s *Sink) Last(ctx context.Context, chainID string) (seq uint64, hash string, err error) {
	var last int64
	err = s.pool.QueryRow(ctx,
		"SELECT seq, hash FROM tollkeeper_audit WHERE chain_id = $1 ORDER BY seq DESC LIMIT 1", chainID,
	).Scan(&last, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("read audit position: %w", err)
	}
	if last < 0 {
		return 0, "", fmt.Errorf("%w: %d", errSeqRange, last)
	}
	return uint64(last), hash, nil
}

var ErrSchemaMissing = errors.New("audit table tollkeeper_audit does not exist")

func (s *Sink) RequireSchema(ctx context.Context) error {
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT to_regclass('tollkeeper_audit') IS NOT NULL").Scan(&exists); err != nil {
		return fmt.Errorf("check audit schema: %w", err)
	}
	if !exists {
		return fmt.Errorf("%w: apply internal/audit/pgsink/schema.sql or set audit.postgres.migrate: true", ErrSchemaMissing)
	}
	return nil
}

func (s *Sink) ExcessPrivileges(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p FROM unnest(ARRAY['UPDATE', 'DELETE', 'TRUNCATE', 'TRIGGER']) AS p
		WHERE has_table_privilege(current_user, 'tollkeeper_audit', p)
		UNION ALL
		SELECT 'OWNER' FROM pg_class
		WHERE oid = 'tollkeeper_audit'::regclass AND pg_get_userbyid(relowner) = current_user`)
	if err != nil {
		return nil, fmt.Errorf("check audit privileges: %w", err)
	}
	privs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("check audit privileges: %w", err)
	}
	return privs, nil
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

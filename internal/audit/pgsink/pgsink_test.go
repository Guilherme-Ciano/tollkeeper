package pgsink

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

func sinkForTest(t *testing.T) *Sink {
	t.Helper()
	dsn := os.Getenv("TOLLKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TOLLKEEPER_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migration is not idempotent: %v", err)
	}
	return s
}

func chainID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "test-" + hex.EncodeToString(b)
}

func writeMirrored(t *testing.T, s *Sink, chain string, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	_, priv, err := audit.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, err := audit.ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(audit.Options{
		Path: path, ChainID: chain, BatchSize: 8, FlushInterval: time.Millisecond,
		Signer: key, CheckpointEvery: 5, Mirror: s, MirrorTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		e := audit.Event{
			Phase: audit.PhaseOutcome, Method: "tools/call", Tool: "notes__search",
			Decision: audit.DecisionAllow, LatencyMicros: int64(i),
		}
		if err := l.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMirroredChainMatchesFileAndVerifies(t *testing.T) {
	t.Parallel()
	s := sinkForTest(t)
	chain := chainID(t)
	path := writeMirrored(t, s, chain, 23)
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var exported bytes.Buffer
	if err := s.Export(t.Context(), chain, &exported); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(file, exported.Bytes()) {
		t.Fatal("rows exported from postgres differ from the file")
	}
	rep, err := audit.Verify(&exported, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Events != 23 || rep.Checkpoints == 0 {
		t.Fatalf("unexpected report %+v", rep)
	}
}

func TestDatabaseRejectsTampering(t *testing.T) {
	t.Parallel()
	s := sinkForTest(t)
	chain := chainID(t)
	writeMirrored(t, s, chain, 6)
	statements := map[string]string{
		"update":   "UPDATE tollkeeper_audit SET kind = 'event' WHERE chain_id = $1 AND seq = 2",
		"delete":   "DELETE FROM tollkeeper_audit WHERE chain_id = $1 AND seq = 3",
		"truncate": "TRUNCATE tollkeeper_audit",
	}
	for name, sql := range statements {
		args := []any{chain}
		if name == "truncate" {
			args = nil
		}
		_, err := s.pool.Exec(t.Context(), sql, args...)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s was not rejected: %v", name, err)
		}
	}
	last, _, err := s.Last(t.Context(), chain)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(seq int64, prev, hash, raw string) error {
		_, err := s.pool.Exec(t.Context(),
			`INSERT INTO tollkeeper_audit (chain_id, seq, ts, kind, hash, prev, body, raw)
			 VALUES ($1, $2, now(), 'event', $3, $4, $5::jsonb, $5)`, chain, seq, hash, prev, raw)
		return err
	}
	raw := `{"seq":99}`
	good, err := audit.ChainHash(audit.ZeroHash, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := insert(int64(last)+1, audit.ZeroHash, good, raw); err == nil {
		t.Fatal("record that does not link to the chain was accepted")
	}
	if err := insert(int64(last)+1, audit.ZeroHash, strings.Repeat("a", 64), raw); err == nil {
		t.Fatal("record with a forged hash was accepted")
	}
}

func TestLastSeqForUnknownChainIsZero(t *testing.T) {
	t.Parallel()
	s := sinkForTest(t)
	last, _, err := s.Last(t.Context(), chainID(t))
	if err != nil || last != 0 {
		t.Fatalf("LastSeq = %d, %v", last, err)
	}
}

func TestNulInCallerDataDoesNotPoisonTheBatch(t *testing.T) {
	t.Parallel()
	s := sinkForTest(t)
	chain := chainID(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.Open(audit.Options{
		Path: path, ChainID: chain, BatchSize: 8, FlushInterval: time.Millisecond,
		Mirror: s, MirrorTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"before", "a\x00b", "after"} {
		e := audit.Event{Method: "tools/call", ClientName: name, Decision: audit.DecisionAllow}
		if err := l.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	last, _, err := s.Last(t.Context(), chain)
	if err != nil || last != 3 {
		t.Fatalf("mirror holds %d records (%v), want 3", last, err)
	}
	var nullBodies int
	err = s.pool.QueryRow(t.Context(),
		"SELECT count(*) FROM tollkeeper_audit WHERE chain_id = $1 AND body IS NULL", chain).Scan(&nullBodies)
	if err != nil || nullBodies != 1 {
		t.Fatalf("rows with unparseable body = %d (%v), want 1", nullBodies, err)
	}
}

func TestColumnsMustAgreeWithRaw(t *testing.T) {
	t.Parallel()
	s := sinkForTest(t)
	chain := chainID(t)
	raw := `{"seq":1,"ts":1,"chain_id":"` + chain + `","prev":"` + audit.ZeroHash + `","event":{}}`
	hash, err := audit.ChainHash(audit.ZeroHash, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	insert := func(chainCol, kind string) error {
		_, err := s.pool.Exec(t.Context(),
			`INSERT INTO tollkeeper_audit (chain_id, seq, ts, kind, hash, prev, raw)
			 VALUES ($1, 1, now(), $2, $3, $4, $5)`, chainCol, kind, hash, audit.ZeroHash, raw)
		return err
	}
	if err := insert(chain+"-copy", "event"); err == nil {
		t.Fatal("record replayed under another chain_id was accepted")
	}
	if err := insert(chain, "checkpoint"); err == nil {
		t.Fatal("record with a kind that contradicts raw was accepted")
	}
	if err := insert(chain, "event"); err != nil {
		t.Fatalf("consistent record rejected: %v", err)
	}
}

func TestTempTableCannotShadowTheChainCheck(t *testing.T) {
	t.Parallel()
	s := sinkForTest(t)
	chain := chainID(t)
	conn, err := s.pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	fakePrev := strings.Repeat("b", 64)
	if _, err := conn.Exec(
		t.Context(),
		`CREATE TEMP TABLE tollkeeper_audit (chain_id text, seq bigint, hash text)`,
	); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(t.Context()), "DROP TABLE pg_temp.tollkeeper_audit"); err != nil {
			t.Error(err)
		}
	}()
	if _, err := conn.Exec(
		t.Context(),
		`INSERT INTO pg_temp.tollkeeper_audit VALUES ($1, 41, $2)`,
		chain,
		fakePrev,
	); err != nil {
		t.Fatal(err)
	}
	raw := `{"seq":42,"ts":1,"chain_id":"` + chain + `","prev":"` + fakePrev + `","event":{}}`
	hash, err := audit.ChainHash(fakePrev, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(t.Context(),
		`INSERT INTO public.tollkeeper_audit (chain_id, seq, ts, kind, hash, prev, raw)
		 VALUES ($1, 42, now(), 'event', $2, $3, $4)`, chain, hash, fakePrev, raw)
	if err == nil {
		t.Fatal("a temporary table satisfied the chain link check")
	}
}

func TestExcessPrivilegesReportsOwner(t *testing.T) {
	t.Parallel()
	s := sinkForTest(t)
	privs, err := s.ExcessPrivileges(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(privs) == 0 {
		t.Fatal("the test role owns the table but no excess privilege was reported")
	}
}

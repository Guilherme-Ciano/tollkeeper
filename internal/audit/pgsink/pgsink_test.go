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
		e := audit.Event{Phase: audit.PhaseOutcome, Method: "tools/call", Tool: "notes__search",
			Decision: audit.DecisionAllow, LatencyMicros: int64(i)}
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
	last, err := s.LastSeq(t.Context(), chain)
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
	last, err := s.LastSeq(t.Context(), chainID(t))
	if err != nil || last != 0 {
		t.Fatalf("LastSeq = %d, %v", last, err)
	}
}

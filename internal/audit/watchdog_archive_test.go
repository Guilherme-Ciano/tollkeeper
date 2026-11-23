package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func createTestLog(t *testing.T, path, chainID string, priv ed25519.PrivateKey, n int) {
	t.Helper()
	l, err := Open(Options{
		Path:            path,
		ChainID:         chainID,
		Signer:          priv,
		CheckpointEvery: max(n, 1),
		FlushInterval:   time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	for range n {
		if err := l.Append(t.Context(), Event{
			Phase: PhaseDecision, Method: "tools/call", Decision: DecisionAllow,
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestWatchdogDetectsGrowthTruncationAndTampering(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	createTestLog(t, path, "pod-1", priv, 3)

	ks, err := NewKeySet(pub)
	if err != nil {
		t.Fatal(err)
	}
	var results []WatchStatus
	wd := NewWatchdog(WatchdogOptions{
		Path:          path,
		ChainID:       "pod-1",
		VerifyOptions: VerifyOptions{Keys: ks},
		MaxUnsigned:   10,
		OnResult: func(st WatchStatus) {
			results = append(results, st)
		},
	})

	st1 := wd.Check(t.Context())
	if !st1.Healthy || st1.Records < 4 || st1.ChainID != "pod-1" {
		t.Fatalf("initial check failed: %+v", st1)
	}

	createTestLog(t, path, "pod-1", priv, 2)
	st2 := wd.Check(t.Context())
	if !st2.Healthy || st2.LastSeq <= st1.LastSeq {
		t.Fatalf("growth check failed: st1=%+v st2=%+v", st1, st2)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	truncated := strings.Join(lines[:2], "\n") + "\n"
	if err := os.WriteFile(path, []byte(truncated), 0o600); err != nil {
		t.Fatal(err)
	}
	st3 := wd.Check(t.Context())
	if st3.Healthy || !strings.Contains(st3.Error, "truncated") {
		t.Fatalf("expected truncation failure, got %+v", st3)
	}

	latest, ok := wd.Status()
	if !ok || latest.Healthy || len(results) != 3 {
		t.Fatalf("unexpected watchdog status: ok=%v latest=%+v count=%d", ok, latest, len(results))
	}
}

func TestArchiveVerifyAndRetentionPruning(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	archiveDir := filepath.Join(dir, "archives")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	createTestLog(t, logPath, "replica-a", priv, 4)

	ks, err := NewKeySet(pub)
	if err != nil {
		t.Fatal(err)
	}

	baseTime := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	res1, err := Archive(ArchiveOptions{
		SourcePath:    logPath,
		DestDir:       archiveDir,
		VerifyOptions: VerifyOptions{Keys: ks},
		MaxAge:        48 * time.Hour,
		MaxArchives:   2,
		Now:           func() time.Time { return baseTime },
	})
	if err != nil {
		t.Fatalf("archive 1: %v", err)
	}
	if res1.Manifest.Records < 5 || res1.Manifest.ArchiveSHA256 == "" || res1.Pruned != 0 {
		t.Fatalf("unexpected archive 1 result: %+v", res1)
	}

	archPath := filepath.Join(archiveDir, res1.Manifest.ArchiveFile)
	rep, err := VerifyArchive(archPath, VerifyOptions{Keys: ks})
	if err != nil {
		t.Fatalf("verify archive 1: %v", err)
	}
	if rep.LastSeq != res1.Manifest.LastSeq || rep.LastHash != res1.Manifest.LastHash {
		t.Fatalf("archive report mismatch: %+v vs %+v", rep, res1.Manifest)
	}

	res2, err := Archive(ArchiveOptions{
		SourcePath:    logPath,
		DestDir:       archiveDir,
		VerifyOptions: VerifyOptions{Keys: ks},
		MaxAge:        48 * time.Hour,
		MaxArchives:   2,
		Now:           func() time.Time { return baseTime.Add(24 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("archive 2: %v", err)
	}
	if res2.Pruned != 0 {
		t.Fatalf("archive 2 pruned = %d, want 0", res2.Pruned)
	}

	res3, err := Archive(ArchiveOptions{
		SourcePath:    logPath,
		DestDir:       archiveDir,
		VerifyOptions: VerifyOptions{Keys: ks},
		MaxAge:        48 * time.Hour,
		MaxArchives:   2,
		Now:           func() time.Time { return baseTime.Add(72 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("archive 3: %v", err)
	}
	if res3.Pruned != 1 {
		t.Fatalf("archive 3 pruned = %d, want 1", res3.Pruned)
	}
	if _, err := os.Stat(archPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired archive 1 should have been pruned, stat err = %v", err)
	}

	tamperedPath := filepath.Join(dir, "tampered.jsonl")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := strings.Replace(string(raw), `"allow"`, `"deny!"`, 1)
	if err := os.WriteFile(tamperedPath, []byte(corrupted), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Archive(ArchiveOptions{
		SourcePath:    tamperedPath,
		DestDir:       archiveDir,
		VerifyOptions: VerifyOptions{Keys: ks},
	}); !errors.Is(err, ErrTampered) {
		t.Fatalf("archiving tampered log should fail with ErrTampered, got %v", err)
	}
}

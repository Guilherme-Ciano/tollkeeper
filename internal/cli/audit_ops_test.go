package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditArchiveAndWatchCLI(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logPath, pubPath := writeChain(t, dir, true)
	archiveDir := filepath.Join(dir, "archives")

	var watchOut bytes.Buffer
	if err := runWatch(t.Context(), &watchOut, watchCLIOpts{
		file:    logPath,
		pubkey:  pubPath,
		chainID: "c",
		once:    true,
	}); err != nil {
		t.Fatalf("runWatch --once: %v out=%s", err, watchOut.String())
	}
	if !strings.Contains(watchOut.String(), "OK chain=c") {
		t.Fatalf("unexpected watch output: %q", watchOut.String())
	}

	var archOut bytes.Buffer
	if err := runArchive(&archOut, archiveCLIOpts{
		file:        logPath,
		outDir:      archiveDir,
		pubkey:      pubPath,
		maxArchives: 3,
	}); err != nil {
		t.Fatalf("runArchive: %v out=%s", err, archOut.String())
	}
	if !strings.Contains(archOut.String(), "ARCHIVED chain=c") {
		t.Fatalf("unexpected archive output: %q", archOut.String())
	}

	err := runVerify(&bytes.Buffer{}, verifyOpts{allChains: true})
	if err == nil || !strings.Contains(err.Error(), "--all-chains requires --postgres") {
		t.Fatalf("expected --all-chains flag validation error, got %v", err)
	}
}

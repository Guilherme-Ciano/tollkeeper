package audit

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	archiveSuffix  = ".jsonl.gz"
	manifestSuffix = ".manifest.json"
)

var ErrEmptyAuditLog = errors.New("audit log has no records to archive")

type ArchiveOptions struct {
	SourcePath    string
	DestDir       string
	VerifyOptions VerifyOptions
	MaxAge        time.Duration
	MaxArchives   int
	Now           func() time.Time
}

type ArchiveManifest struct {
	ChainID       string    `json:"chain_id"`
	Records       uint64    `json:"records"`
	Events        uint64    `json:"events"`
	Checkpoints   uint64    `json:"checkpoints"`
	KeyRotations  uint64    `json:"key_rotations"`
	LastSeq       uint64    `json:"last_seq"`
	LastHash      string    `json:"last_hash"`
	UnsignedTail  uint64    `json:"unsigned_tail"`
	ArchiveFile   string    `json:"archive_file"`
	ArchiveSHA256 string    `json:"archive_sha256"`
	RawBytes      int64     `json:"raw_bytes"`
	GzipBytes     int64     `json:"gzip_bytes"`
	ArchivedAt    time.Time `json:"archived_at"`
	RetainUntil   time.Time `json:"retain_until,omitzero"`
}

type ArchiveResult struct {
	Manifest ArchiveManifest
	Pruned   int
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	if err != nil {
		return n, fmt.Errorf("write archive stream: %w", err)
	}
	return n, nil
}

func Archive(opts ArchiveOptions) (ArchiveResult, error) {
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC()
	if err := os.MkdirAll(opts.DestDir, 0o750); err != nil {
		return ArchiveResult{}, fmt.Errorf("create archive dir: %w", err)
	}
	src, err := os.Open(opts.SourcePath)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("open audit log: %w", err)
	}
	defer src.Close()

	comp, err := verifyAndCompress(src, opts.DestDir, opts.VerifyOptions)
	if err != nil {
		return ArchiveResult{}, err
	}
	if comp.report.Records == 0 {
		return ArchiveResult{}, errors.Join(ErrEmptyAuditLog, os.Remove(comp.tmpPath))
	}

	baseName := fmt.Sprintf(
		"%s-%s-seq%d",
		sanitizeChainName(comp.report.ChainID),
		now.Format("20060102T150405Z"),
		comp.report.LastSeq,
	)
	archiveName := baseName + archiveSuffix
	archivePath := filepath.Join(opts.DestDir, archiveName)
	if err := os.Rename(comp.tmpPath, archivePath); err != nil {
		return ArchiveResult{}, errors.Join(fmt.Errorf("finalize archive: %w", err), os.Remove(comp.tmpPath))
	}

	manifest := ArchiveManifest{
		ChainID:       comp.report.ChainID,
		Records:       comp.report.Records,
		Events:        comp.report.Events,
		Checkpoints:   comp.report.Checkpoints,
		KeyRotations:  comp.report.KeyRotations,
		LastSeq:       comp.report.LastSeq,
		LastHash:      comp.report.LastHash,
		UnsignedTail:  comp.report.UnsignedTail,
		ArchiveFile:   archiveName,
		ArchiveSHA256: comp.shaHex,
		RawBytes:      comp.rawBytes,
		GzipBytes:     comp.gzipBytes,
		ArchivedAt:    now,
	}
	if opts.MaxAge > 0 {
		manifest.RetainUntil = now.Add(opts.MaxAge)
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("encode archive manifest: %w", err)
	}
	manifestPath := filepath.Join(opts.DestDir, baseName+manifestSuffix)
	if err := os.WriteFile(manifestPath, append(manifestBytes, '\n'), 0o600); err != nil {
		return ArchiveResult{}, fmt.Errorf("write archive manifest: %w", err)
	}

	pruned, err := PruneArchives(opts.DestDir, opts.MaxAge, opts.MaxArchives, now)
	if err != nil {
		return ArchiveResult{Manifest: manifest}, err
	}
	return ArchiveResult{Manifest: manifest, Pruned: pruned}, nil
}

type compressedArchive struct {
	report    Report
	tmpPath   string
	shaHex    string
	rawBytes  int64
	gzipBytes int64
}

func verifyAndCompress(src io.Reader, destDir string, vo VerifyOptions) (compressedArchive, error) {
	tmp, err := os.CreateTemp(destDir, ".audit-archive-*.tmp")
	if err != nil {
		return compressedArchive{}, fmt.Errorf("create temp archive: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func(cause error) error {
		return errors.Join(cause, tmp.Close(), os.Remove(tmpPath))
	}

	hasher := sha256.New()
	gzCount := &countingWriter{w: io.MultiWriter(tmp, hasher)}
	gz := gzip.NewWriter(gzCount)
	rawCount := &countingWriter{w: gz}

	rep, err := VerifyWith(io.TeeReader(src, rawCount), vo)
	if err != nil {
		return compressedArchive{}, cleanup(errors.Join(fmt.Errorf("verify before archive: %w", err), gz.Close()))
	}
	if err := gz.Close(); err != nil {
		return compressedArchive{}, cleanup(fmt.Errorf("close gzip archive: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return compressedArchive{}, cleanup(fmt.Errorf("sync archive: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return compressedArchive{}, errors.Join(fmt.Errorf("close archive: %w", err), os.Remove(tmpPath))
	}
	return compressedArchive{
		report:    rep,
		tmpPath:   tmpPath,
		shaHex:    hex.EncodeToString(hasher.Sum(nil)),
		rawBytes:  rawCount.n,
		gzipBytes: gzCount.n,
	}, nil
}

func VerifyArchive(archivePath string, vo VerifyOptions) (Report, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return Report{}, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	gz, err := gzip.NewReader(io.TeeReader(f, hasher))
	if err != nil {
		return Report{}, fmt.Errorf("open gzip stream: %w", err)
	}
	defer gz.Close()

	rep, err := VerifyWith(gz, vo)
	if err != nil {
		return rep, err
	}
	if _, err := io.Copy(io.Discard, f); err != nil {
		return rep, fmt.Errorf("finish archive hash: %w", err)
	}
	if base, ok := strings.CutSuffix(archivePath, archiveSuffix); ok {
		manifestPath := base + manifestSuffix
		if data, rerr := os.ReadFile(manifestPath); rerr == nil {
			var m ArchiveManifest
			if err := json.Unmarshal(data, &m); err != nil {
				return rep, fmt.Errorf("parse archive manifest: %w", ErrMalformed)
			}
			gotSHA := hex.EncodeToString(hasher.Sum(nil))
			if m.ArchiveSHA256 != "" && m.ArchiveSHA256 != gotSHA {
				return rep, fmt.Errorf(
					"archive sha256 %s does not match manifest %s: %w",
					gotSHA,
					m.ArchiveSHA256,
					ErrTampered,
				)
			}
		}
	}
	return rep, nil
}

type archivedBundle struct {
	baseName   string
	archivedAt time.Time
}

func PruneArchives(dir string, maxAge time.Duration, maxArchives int, now time.Time) (int, error) {
	if maxAge <= 0 && maxArchives <= 0 {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read archive dir: %w", err)
	}
	bundles := make([]archivedBundle, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), archiveSuffix) {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), archiveSuffix)
		ts := archiveTimestamp(dir, base, entry)
		bundles = append(bundles, archivedBundle{baseName: base, archivedAt: ts})
	}
	slices.SortFunc(bundles, func(a, b archivedBundle) int {
		switch {
		case a.archivedAt.After(b.archivedAt):
			return -1
		case a.archivedAt.Before(b.archivedAt):
			return 1
		default:
			return strings.Compare(b.baseName, a.baseName)
		}
	})
	pruned := 0
	for i, b := range bundles {
		expired := maxAge > 0 && now.Sub(b.archivedAt) > maxAge
		overLimit := maxArchives > 0 && i >= maxArchives
		if !expired && !overLimit {
			continue
		}
		if err := removeBundle(dir, b.baseName); err != nil {
			return pruned, err
		}
		pruned++
	}
	return pruned, nil
}

func archiveTimestamp(dir, base string, entry os.DirEntry) time.Time {
	manifestPath := filepath.Join(dir, base+manifestSuffix)
	if data, err := os.ReadFile(manifestPath); err == nil {
		var m ArchiveManifest
		if json.Unmarshal(data, &m) == nil && !m.ArchivedAt.IsZero() {
			return m.ArchivedAt
		}
	}
	if info, err := entry.Info(); err == nil {
		return info.ModTime().UTC()
	}
	return time.Time{}
}

func removeBundle(dir, base string) error {
	if err := os.Remove(filepath.Join(dir, base+archiveSuffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove expired archive: %w", err)
	}
	if err := os.Remove(filepath.Join(dir, base+manifestSuffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove expired manifest: %w", err)
	}
	return nil
}

func sanitizeChainName(chainID string) string {
	if chainID == "" {
		return "audit"
	}
	var b strings.Builder
	b.Grow(len(chainID))
	for _, r := range chainID {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

var ErrUnrecoverable = errors.New("audit corruption is not limited to a torn tail")

type RepairReport struct {
	Report         Report
	BackupPath     string
	TruncatedBytes int64
}

func RepairTail(path string, o VerifyOptions) (RepairReport, error) {
	rep, err := verifyPath(path, o)
	if err == nil {
		return RepairReport{Report: rep}, nil
	}
	cutOffset, tailBytes, totalSize, err := splitFinalLine(path)
	if err != nil {
		return RepairReport{}, err
	}
	if !isTornTail(tailBytes) {
		return RepairReport{}, fmt.Errorf("%w: final line is syntactically complete", ErrUnrecoverable)
	}
	prefixRep, err := verifyPrefix(path, cutOffset, o)
	if err != nil {
		return RepairReport{}, fmt.Errorf("%w: %w", ErrUnrecoverable, err)
	}
	backupPath := path + ".torn"
	if err := writeBackup(backupPath, tailBytes); err != nil {
		return RepairReport{}, err
	}
	if err := truncateAndSync(path, cutOffset); err != nil {
		return RepairReport{}, err
	}
	return RepairReport{
		Report:         prefixRep,
		BackupPath:     backupPath,
		TruncatedBytes: totalSize - cutOffset,
	}, nil
}

func verifyPath(path string, o VerifyOptions) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	return VerifyWith(f, o)
}

func verifyPrefix(path string, n int64, o VerifyOptions) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	return VerifyWith(io.LimitReader(f, n), o)
}

func splitFinalLine(path string) (cutOffset int64, tail []byte, totalSize int64, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("read audit log: %w", err)
	}
	totalSize = int64(len(data))
	trimmed := bytes.TrimRight(data, "\n")
	if len(trimmed) == 0 {
		return 0, data, totalSize, nil
	}
	idx := bytes.LastIndexByte(trimmed, '\n')
	if idx < 0 {
		return 0, data, totalSize, nil
	}
	cutOffset = int64(idx + 1)
	return cutOffset, data[cutOffset:], totalSize, nil
}

func isTornTail(tail []byte) bool {
	trimmed := bytes.TrimSpace(tail)
	if len(trimmed) == 0 {
		return true
	}
	var rec Record
	return json.Unmarshal(trimmed, &rec) != nil
}

func writeBackup(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create torn tail backup %s: %w", path, err)
	}
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("write torn tail backup %s: %w", path, err)
	}
	return nil
}

func truncateAndSync(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log for truncate: %w", err)
	}
	if err := errors.Join(f.Truncate(size), f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("truncate audit log %s: %w", path, err)
	}
	return nil
}

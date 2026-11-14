package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type block struct {
	statements int
	covered    bool
}

type badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

var errMalformed = errors.New("malformed coverage line")

func parseProfile(r io.Reader) (float64, error) {
	blocks := map[string]block{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			if strings.HasPrefix(line, "mode:") {
				continue
			}
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return 0, fmt.Errorf("%w: %q", errMalformed, line)
		}
		stmts, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("%w: %q", errMalformed, line)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			return 0, fmt.Errorf("%w: %q", errMalformed, line)
		}
		prev := blocks[fields[0]]
		blocks[fields[0]] = block{statements: stmts, covered: prev.covered || count > 0}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read profile: %w", err)
	}
	var total, hit int
	for _, b := range blocks {
		total += b.statements
		if b.covered {
			hit += b.statements
		}
	}
	if total == 0 {
		return 0, nil
	}
	return float64(hit) * 100 / float64(total), nil
}

func colorFor(pct float64) string {
	switch {
	case pct >= 80:
		return "brightgreen"
	case pct >= 70:
		return "green"
	case pct >= 60:
		return "yellowgreen"
	case pct >= 50:
		return "yellow"
	default:
		return "orange"
	}
}

func render(pct float64) ([]byte, error) {
	out, err := json.Marshal(badge{
		SchemaVersion: 1,
		Label:         "coverage",
		Message:       strconv.FormatFloat(pct, 'f', 1, 64) + "%",
		Color:         colorFor(pct),
	})
	if err != nil {
		return nil, fmt.Errorf("encode badge: %w", err)
	}
	return append(out, '\n'), nil
}

func run(profile, output string) error {
	f, err := os.Open(profile)
	if err != nil {
		return fmt.Errorf("open profile: %w", err)
	}
	defer f.Close()
	pct, err := parseProfile(f)
	if err != nil {
		return err
	}
	data, err := render(pct)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		return fmt.Errorf("write badge: %w", err)
	}
	fmt.Printf("coverage %.1f%%\n", pct)
	return nil
}

func main() {
	profile := flag.String("profile", "cover.out", "coverage profile produced by go test")
	output := flag.String("out", "coverage.json", "shields.io endpoint badge file")
	flag.Parse()
	if err := run(*profile, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

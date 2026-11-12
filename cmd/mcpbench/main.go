package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var errUsage = errors.New("usage: mcpbench run|overhead [flags]")

func parseRates(s string) ([]int, error) {
	var out []int
	for f := range strings.SplitSeq(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("bad rate %q: %w", f, errUsage)
		}
		out = append(out, n)
	}
	return out, nil
}

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8080/mcp", "MCP endpoint")
	token := fs.String("token", "", "bearer token")
	tool := fs.String("tool", "noop__noop", "tool name")
	rate := fs.Int("rate", 1000, "calls per second")
	d := fs.Duration("duration", 30*time.Second, "measurement duration")
	conns := fs.Int("conns", 512, "max connections")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	r, err := run(ctx, target{URL: *url, Token: *token, Tool: *tool}, *rate, *d, newClient(*conns))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}

func cmdOverhead(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("overhead", flag.ContinueOnError)
	var o overheadOpts
	rates := fs.String("rates", "500,1000,2000,5000", "comma-separated arrival rates")
	fs.StringVar(&o.binDir, "bin-dir", "bin", "directory with tollkeeper and noop-server binaries")
	fs.StringVar(&o.out, "out", "bench/results", "results root")
	fs.DurationVar(&o.duration, "duration", 30*time.Second, "measurement duration per run")
	fs.DurationVar(&o.warmup, "warmup", 10*time.Second, "warm-up per point (discarded)")
	fs.IntVar(&o.runs, "runs", 3, "runs per point")
	fs.StringVar(&o.gatewayCPUs, "gateway-cpus", "0-3", "taskset CPU list for the gateway")
	fs.StringVar(&o.upstreamCPU, "upstream-cpus", "4-5", "taskset CPU list for the upstream")
	fs.IntVar(&o.gatewayProc, "gateway-procs", 4, "GOMAXPROCS for the gateway")
	fs.IntVar(&o.conns, "conns", 1024, "max client connections")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	var err error
	if o.rates, err = parseRates(*rates); err != nil {
		return err
	}
	return runOverhead(ctx, o, os.Stdout)
}

func dispatch(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	switch args[0] {
	case "run":
		return cmdRun(ctx, args[1:])
	case "overhead":
		return cmdOverhead(ctx, args[1:])
	default:
		return errUsage
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := dispatch(ctx, os.Args[1:])
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpbench:", err)
		os.Exit(1)
	}
}

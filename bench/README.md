# Benchmark methodology

## Micro-benchmarks

```bash
make bench
```

`go test -bench=. -benchmem -count=10` over `internal/...`. Compare runs with benchstat and only cite differences it marks as significant.

## End-to-end overhead

```bash
make build
./bin/mcpbench overhead -rates 500,1000,2000,5000 -duration 30s -warmup 10s -runs 3
```

- **What is measured.** The same `tools/call` against a no-op MCP upstream, once directly and once through tollkeeper. Overhead is the difference between the two latency distributions at the same arrival rate.
- **Load model.** Open loop at a constant arrival rate. Latency runs from the *scheduled* send time, so a slow response cannot hide the requests queued behind it (coordinated omission). Latencies go into an HdrHistogram with 3 significant digits.
- **Gateway configuration.** Every feature is on: EdDSA JWT verification with a cached JWKS, a CEL rule, two GCRA rules, audit intent and outcome records with fsync per 512-record batch and Ed25519 checkpoints, and Prometheus metrics. The OTel tracer is off (no endpoint), as in a default deployment.
- **Isolation.** The gateway is pinned to CPUs 0-3 with `GOMAXPROCS=4` and the upstream to CPUs 4-5 with `taskset`. The load generator runs on the remaining CPUs.
- **Repetitions.** A warm-up that is discarded, then N runs per rate. The run with the median p99 is reported, and every run is kept in `summary.json`.
- **Environment.** CPU, RAM, kernel, governor, boost state, Go version and git commit are written to `env.json`. Numbers are same-host loopback figures, not internet latency.

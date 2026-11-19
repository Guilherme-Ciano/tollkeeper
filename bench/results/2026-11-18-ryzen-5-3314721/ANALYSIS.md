# Analysis of the 2026-11-18 run

Two builds were measured back to back in one session, on a host that was 99% idle beforehand (desktop applications open but quiet), with identical settings: `origin/main` at v1.1.0 (`ee336bd`, in [`baseline-v1.1.0/`](baseline-v1.1.0/report.md)) and `feat/v1.3` at `3314721` (this directory). Same harness binary, same rates, gateway pinned to CPUs 0-3 with `GOMAXPROCS=4`, upstream on 4-5, load generator on 6-11, everything in a 6 GiB no-swap cgroup with `GOMEMLIMIT=1500MiB`. Each rate: 10 s warm-up, 3 × 30 s runs, median run by p99. The report header says "dirty" only because an earlier, discarded result directory was untracked in the worktree; the binaries were built from the clean commit.

The v1.3 gateway serves `tools/call` on protocol 2026-07-28 through its direct path instead of the go-sdk transport ([`internal/gateway/fastpath.go`](../../../internal/gateway/fastpath.go)); everything else in the call (JWT, CEL, GCRA, audit intent and outcome with fsync and checkpoints, metrics) is unchanged.

## Results

| offered calls/s | direct p50 / p99 | v1.1.0 gateway p50 / p99 | v1.3 gateway p50 / p99 | v1.1.0 added p50 / p99 | v1.3 added p50 / p99 | v1.1.0 CPU per 1k calls | v1.3 CPU per 1k calls |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 0.90 / 1.76 ms | 1.39 / 2.73 ms | 1.25 / 2.17 ms | 0.47 / 0.93 ms | **0.35 / 0.40 ms** | 703 ms | **484 ms** |
| 1,000 | 0.77 / 1.65 ms | 1.32 / 2.84 ms | 1.13 / 2.20 ms | 0.54 / 1.17 ms | **0.36 / 0.55 ms** | 700 ms | **426 ms** |
| 2,000 | 0.68 / 1.79 ms | 1.27 / 3.47 ms | 0.85 / 2.26 ms | 0.59 / 1.69 ms | **0.17 / 0.47 ms** | 734 ms | **428 ms** |
| 3,000 | 0.71 / 2.13 ms | 1.69 / 5.64 ms | 0.96 / 3.03 ms | 0.98 / 3.49 ms | **0.25 / 0.90 ms** | 749 ms | **447 ms** |
| 4,000 | 0.69 / 2.70 ms | 6.52 / 31.8 ms | 1.27 / 4.61 ms | 5.84 / 28.7 ms | **0.57 / 1.91 ms** | 807 ms | **467 ms** |
| 5,000 | 1.15 / 9.50 ms | 562 / 930 ms, 45,039 errors | 4.50 / 168 ms, 0 errors | 561 / 926 ms | 3.36 / 159 ms | 774 ms | 504 ms |

The direct column is the v1.3 session's baseline; the v1.1.0 session's baseline was within 5% at p50 (see its report).

- **CPU per call drops about 40%**, from 0.70-0.81 ms to 0.43-0.50 ms.
- **The ceiling moves from about 3,500 to about 5,000 calls/s on 4 cores.** v1.1.0 is already queueing at 4,000 calls/s (p99 added 28.7 ms) and collapses at 5,000 (45,039 shed or timed-out calls). v1.3 holds 4,000 calls/s with p99 added under 2 ms and completes every call at 5,000, where queueing starts to stretch the tail.
- **Added latency at moderate load is 0.2-0.4 ms at p50 and under 1 ms at p99** up to 3,000 calls/s.
- **p90 is left out on purpose.** Added latency is the gateway percentile minus the direct percentile, measured in separate runs. At 2,000 and 3,000 calls/s the direct path's own p90 varied more between runs than the gateway added, so the v1.3 differences came out negative (-0.16 and -0.11 ms). They are in `summary.json`; they mean "within noise", not "faster than direct".

## Where the remaining CPU goes

[`cpu-3000.pprof`](cpu-3000.pprof) is a 30 s CPU profile of the v1.3 gateway at 3,000 calls/s, taken with `mcpbench overhead -cpuprofile` during the first measured run. The gateway used 1.32 cores, which is 440 µs per call. Cumulative shares, which overlap:

| path | share of gateway CPU |
|---|---:|
| upstream hop: go-sdk client `CallTool`, request encoding, HTTP client, response decoding | about 33% (20% `ClientSession.CallTool` + 12.5% HTTP client loops) |
| JWT verification, almost all of it the Ed25519 signature check | 13.5% (10% `ed25519.Verify`) |
| garbage collection | 12% |
| tollkeeper's own work: envelope 4.7%, admission and CEL 4.3%, audit sequencing and sealing 5%, result encoding 2% | about 16% |
| HTTP server, otelhttp wrappers, metrics | the rest |

The go-sdk server transport no longer appears on the `tools/call` path. What is left is dominated by the client side of the second hop and by verifying the same bearer token on every call. Two concrete next steps:

1. Cache verified JWTs by token hash until `exp` (the introspection verifier already does this), which would remove most of the 13.5% for clients that reuse tokens.
2. Talk to Streamable HTTP upstreams with a direct client for `tools/call`, as the server side now does, keeping go-sdk for discovery and listing.

## Reproduce

```bash
make build
./bin/mcpbench overhead -rates 500,1000,2000,3000,4000,5000 -duration 30s -warmup 10s -runs 3
./bin/mcpbench overhead -rates 3000 -duration 30s -warmup 10s -runs 1 -cpuprofile cpu
```

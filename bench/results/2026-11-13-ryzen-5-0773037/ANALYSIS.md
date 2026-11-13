# Analysis of the 2026-11-13 run

Corrections: the harness first recorded `logical_cpus: 6` because `runtime.NumCPU` follows the load generator's own `taskset -c 6-11`. The host has 12 logical CPUs (6 cores with SMT). The JSON and report files were corrected by hand, and the harness now counts `/proc/cpuinfo`.

Conditions: gateway pinned to CPUs 0-3 (`GOMAXPROCS=4`), no-op upstream to 4-5, load generator to 6-11. Everything ran inside `systemd-run --user --scope -p MemoryMax=6G -p MemorySwapMax=0` with `GOMEMLIMIT=1500MiB` per process. Peak memory of the whole scope was 1.48 GiB for this run and 1.49 GiB for the knee run (`knee/`), with no OOM kills. The governor was `powersave` with boost on, which could not be changed without root. The method was shortened from §7.2 of the discovery doc to a 10 s warm-up and 3 × 30 s runs per rate (instead of 30 s and 5 × 120 s).

## Combined results

| offered calls/s | completed calls/s | added p50 | added p90 | added p99 | errors | gateway RSS |
|---:|---:|---:|---:|---:|---:|---:|
| 500 | 500 | 0.62 ms | 0.69 ms | 1.03 ms | 0 | 60 MB |
| 1000 | 1000 | 0.60 ms | 0.82 ms | 1.30 ms | 0 | 66 MB |
| 2000 | 2000 | 0.85 ms | 1.20 ms | 4.43 ms | 0 | 101 MB |
| 3000 | 3000 | 1.91 ms | 4.34 ms | 35.6 ms | 0 | 156 MB |
| 4000 | 3112 | saturated (~0.6 s) | | | 25,227 | 295 MB |
| 5000 | 3143 | saturated (~0.6 s) | | | 54,288 | 270 MB |

"Added" is the gateway latency minus the direct latency at the same percentile, both measured at the same offered rate. Errors at saturation are requests shed by the load generator's 2,048 in-flight cap or timed out. Sustainable throughput on 4 pinned cores is about 2,000 calls/s with p99 overhead under 5 ms. At 3,000 calls/s there are still no errors but the tail grows, and the saturation ceiling is about 3,100 completed calls/s.

## Where the time goes

The gateway uses about 0.8 ms of CPU per call (the "CPU per 1k calls" column), which is why it saturates near 4 cores × 1,250 calls/s. A 20 s CPU profile at 1,000 calls/s (auth off, otherwise the same features) shows:

- go-sdk's stateless request path decodes each request body about six times (`jsonrpc2.DecodeMessage`, `readBatch`, `extractRequestMeta`, `extractName` for header validation, `remarshal`, and the method-info decode). Together with the upstream client's response decoding, `internal/json.Unmarshal` accounts for 17% of CPU, and GC for about 23%.
- tollkeeper's own work is small: admission 3.5%, envelope parsing 3.2% and the audit sequencer about 2% of CPU. The micro-benchmarks agree: Ed25519 JWT verification 58 µs, envelope parse 17 µs, CEL 4.2 µs, audit append 4.2 µs, GCRA 0.1 µs.

The overhead is dominated by a second full MCP hop (server plus client) through go-sdk, not by policy, rate limiting or audit. The obvious next steps are to decode the body once (an upstream go-sdk PR candidate) and to reuse our parsed envelope.

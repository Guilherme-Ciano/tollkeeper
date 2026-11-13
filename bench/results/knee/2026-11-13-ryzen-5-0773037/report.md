# tollkeeper overhead benchmark

2026-11-13T23:32:57Z · commit `0773037` (dirty) · same-host loopback, no-op upstream, laptop-class desktop; not internet latency

Hardware: AMD Ryzen 5 4600G with Radeon Graphics, 12 logical CPUs, 15 GB RAM, Linux 7.3.3-1-cachyos, governor=powersave, boost=1, go1.27.4. Gateway pinned to CPUs 0-3 with GOMAXPROCS=4.

Gateway features on: jwt EdDSA verify (cached JWKS); CEL policy rule; 2 GCRA rules; audit intent+outcome, fsync per 512 batch, Ed25519 checkpoints; OTel noop tracer; Prometheus metrics.

Open-loop constant arrival rate, latency measured from the scheduled send time (coordinated-omission corrected). 10s warm-up, 3 × 30s runs per point, median run by p99 reported.

| rate (calls/s) | direct p50 | direct p99 | gateway p50 | gateway p99 | added p50 | added p99 | errors | gateway RSS | CPU per 1k calls |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3000 | 816 µs | 2771 µs | 2721 µs | 38335 µs | **1905 µs** | **35564 µs** | 0 | 156 MB | 835 ms |
| 4000 | 885 µs | 3603 µs | 614399 µs | 1046015 µs | **613514 µs** | **1042412 µs** | 25227 | 295 MB | 940 ms |

# tollkeeper overhead benchmark

2026-11-13T23:19:15Z · commit `0773037` (dirty) · same-host loopback, no-op upstream, laptop-class desktop; not internet latency

Hardware: AMD Ryzen 5 4600G with Radeon Graphics, 12 logical CPUs, 15 GB RAM, Linux 7.3.3-1-cachyos, governor=powersave, boost=1, go1.27.4. Gateway pinned to CPUs 0-3 with GOMAXPROCS=4.

Gateway features on: jwt EdDSA verify (cached JWKS); CEL policy rule; 2 GCRA rules; audit intent+outcome, fsync per 512 batch, Ed25519 checkpoints; OTel noop tracer; Prometheus metrics.

Open-loop constant arrival rate, latency measured from the scheduled send time (coordinated-omission corrected). 10s warm-up, 3 × 30s runs per point, median run by p99 reported.

| rate (calls/s) | direct p50 | direct p99 | gateway p50 | gateway p99 | added p50 | added p99 | errors | gateway RSS | CPU per 1k calls |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 853 µs | 1674 µs | 1473 µs | 2703 µs | **620 µs** | **1029 µs** | 0 | 60 MB | 786 ms |
| 1000 | 787 µs | 1739 µs | 1382 µs | 3039 µs | **595 µs** | **1300 µs** | 0 | 66 MB | 781 ms |
| 2000 | 699 µs | 1974 µs | 1547 µs | 6407 µs | **848 µs** | **4433 µs** | 0 | 101 MB | 839 ms |
| 5000 | 1209 µs | 11743 µs | 622079 µs | 1035775 µs | **620870 µs** | **1024032 µs** | 54288 | 270 MB | 752 ms |

# tollkeeper overhead benchmark

2026-11-18T23:23:42Z · commit `3314721` (dirty) · same-host loopback, no-op upstream, laptop-class desktop; not internet latency

Hardware: AMD Ryzen 5 4600G with Radeon Graphics, 12 logical CPUs, 15 GB RAM, Linux 7.3.4-1-cachyos, governor=powersave, boost=1, go1.27.4. Gateway pinned to CPUs 0-3 with GOMAXPROCS=4.

Gateway features on: jwt EdDSA verify (cached JWKS); CEL policy rule; 2 GCRA rules; audit intent+outcome, fsync per 512 batch, Ed25519 checkpoints; OTel noop tracer; Prometheus metrics.

Open-loop constant arrival rate, latency measured from the scheduled send time (coordinated-omission corrected). 10s warm-up, 3 × 30s runs per point, median run by p99 reported.

| rate (calls/s) | direct p50 | direct p99 | gateway p50 | gateway p99 | added p50 | added p99 | errors | gateway RSS | CPU per 1k calls |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 899 µs | 1764 µs | 1250 µs | 2165 µs | **351 µs** | **401 µs** | 0 | 68 MB | 484 ms |
| 1000 | 773 µs | 1652 µs | 1131 µs | 2199 µs | **358 µs** | **547 µs** | 0 | 72 MB | 426 ms |
| 2000 | 676 µs | 1793 µs | 847 µs | 2263 µs | **171 µs** | **470 µs** | 0 | 82 MB | 428 ms |
| 3000 | 710 µs | 2129 µs | 964 µs | 3031 µs | **254 µs** | **902 µs** | 0 | 95 MB | 447 ms |
| 4000 | 695 µs | 2701 µs | 1266 µs | 4611 µs | **571 µs** | **1910 µs** | 0 | 103 MB | 467 ms |
| 5000 | 1148 µs | 9495 µs | 4503 µs | 168447 µs | **3355 µs** | **158952 µs** | 0 | 208 MB | 504 ms |

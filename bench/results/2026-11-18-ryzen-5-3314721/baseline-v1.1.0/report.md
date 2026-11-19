# tollkeeper overhead benchmark

2026-11-18T23:03:39Z · commit `ee336bd` (v1.1.0, origin/main; recorded by hand because the run was started outside a git checkout) · same-host loopback, no-op upstream, laptop-class desktop; not internet latency

Hardware: AMD Ryzen 5 4600G with Radeon Graphics, 12 logical CPUs, 15 GB RAM, Linux 7.3.4-1-cachyos, governor=powersave, boost=1, go1.27.4. Gateway pinned to CPUs 0-3 with GOMAXPROCS=4.

Gateway features on: jwt EdDSA verify (cached JWKS); CEL policy rule; 2 GCRA rules; audit intent+outcome, fsync per 512 batch, Ed25519 checkpoints; OTel noop tracer; Prometheus metrics.

Open-loop constant arrival rate, latency measured from the scheduled send time (coordinated-omission corrected). 10s warm-up, 3 × 30s runs per point, median run by p99 reported.

| rate (calls/s) | direct p50 | direct p99 | gateway p50 | gateway p99 | added p50 | added p99 | errors | gateway RSS | CPU per 1k calls |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 926 µs | 1805 µs | 1394 µs | 2731 µs | **468 µs** | **926 µs** | 0 | 65 MB | 703 ms |
| 1000 | 780 µs | 1673 µs | 1323 µs | 2841 µs | **543 µs** | **1168 µs** | 0 | 69 MB | 700 ms |
| 2000 | 677 µs | 1780 µs | 1265 µs | 3465 µs | **588 µs** | **1685 µs** | 0 | 94 MB | 734 ms |
| 3000 | 711 µs | 2147 µs | 1687 µs | 5635 µs | **976 µs** | **3488 µs** | 0 | 109 MB | 749 ms |
| 4000 | 676 µs | 3157 µs | 6519 µs | 31807 µs | **5843 µs** | **28650 µs** | 0 | 127 MB | 807 ms |
| 5000 | 937 µs | 4427 µs | 561663 µs | 930303 µs | **560726 µs** | **925876 µs** | 45039 | 287 MB | 774 ms |

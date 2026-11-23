# ADR 0017: Upstream diagnostics, chaos testing, and dependency recovery

## Context

In production deployments with multiple stdio and Streamable HTTP upstreams, Prometheus counters and gauges show *that* an upstream is unhealthy, but on-call operators still need immediate per-upstream context to diagnose *why*: the exact last connection or call error, how many times the upstream reconnected, whether concurrency is saturated, what state the circuit breaker is in, and recent call latency percentiles (p50/p95).

In addition, distributed deployments rely on Redis (GCRA rate limits) and PostgreSQL (append-only audit mirror) recovering cleanly from transient outages without corrupting state or breaking tenant isolation.

## Decision

1. **Per-upstream diagnostic tracker (`upstream.Diagnostics`) and admin endpoint `GET /upstreams`:**
   - Each `Upstream` maintains a fixed-size 128-sample latency ring buffer (`diagTracker`) with O(1) recording and zero heap allocations on the call path, tracking connection timestamps, reconnect count, last health probe status, in-flight concurrency, total calls/errors, consecutive failures, last error message/timestamp, circuit breaker state and p50/p95 latency computed on read.
   - The admin listener exposes `GET /upstreams` behind the same loopback-or-`pinning.report_token` access guard as `GET /pins`, returning each upstream's diagnostics together with live sync status and registered tool count.
2. **Chaos and dependency recovery verification suites:**
   - `internal/gateway/chaos_test.go` exercises concurrent multi-tenant callers under intermittent upstream faults (`ErrUnavailable`, `ErrBreakerOpen`, `ErrTimeout`) and simultaneous `g.Swap` policy reloads, asserting zero panics, zero data races, preserved tenant isolation, unbroken audit hash chains, and clean post-fault recovery.
   - `internal/ratelimit/redis_recovery_test.go` exercises real `miniredis` shutdown (`Close`) and restart (`Restart`), verifying immediate `local` and `deny` fallback behavior during outages and automatic resumption of distributed GCRA after recovery.
   - `internal/audit/mirror_recovery_test.go` simulates transient Postgres `Commit` failures where local disk writes succeed and `mirrorBehind` latches, verifying automatic `reconcile` and `backfill` catch-up with exact hash-chain parity once the mirror recovers.
3. **Distributed benchmarks:**
   - Added `BenchmarkRedisDistributedGCRA`, `BenchmarkMultiTenantGatewayAdmission` and `BenchmarkTokenExchangeCached` to measure multi-replica GCRA, isolated tenant policy + RFC 9470 step-up admission, and cached RFC 8693 exchange throughput under parallel load.

## Alternatives considered

- **Exporting last error strings as Prometheus labels:** Causes unbounded metric cardinality when upstream error messages include dynamic IDs or timestamps. Serving structured JSON on the protected admin endpoint gives rich detail with zero metric cardinality risk.
- **External chaos frameworks only in staging:** Valuable in cluster tests, but deterministic in-process chaos and restart tests running on every CI PR under `-race` catch concurrency regressions before merge.

## Consequences

- Operators can inspect full upstream health and latency percentiles in one `GET /upstreams` call on the admin port.
- Every CI run continuously verifies Redis fallback/recovery, audit mirror backfill recovery, and multi-tenant chaos resilience under `-race`.

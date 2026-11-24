# 0021 — Provenance metadata, cost-based GCRA impact limits, and stateless idempotency

Status: Accepted

## Context

Security reviews of MCP gateways consistently raise three governance gaps that go beyond basic authentication and flat call-rate limiting:

1. **Indirect prompt injection and data-boundary visibility.** Upstreams differ sharply in trust level (public web scrapers vs. internal databases), data classification, egress capability, and blast radius. Without structured provenance metadata on tools and responses, policies must hard-code fragile tool-name globs, and agent runtimes receive no trustworthy signal separating untrusted tool output from internal sources.
2. **Impact limits vs. frequency limits.** A flat rate limit of `10/m` treats deleting 1 file identically to deleting 10,000 files or transferring \$10,000 in a single tool call. Enforcing impact budgets (records affected, batch sizes, dollar amounts) is essential for destructive and financial tools.
3. **Duplicate execution of side-effecting tool calls.** Agent retry loops, network timeouts, and prompt-induced replays can re-submit a destructive or financial `tools/call` multiple times.

At the same time, tollkeeper's data plane is deliberately stateless and sub-millisecond (ADR 0006, ADR 0020): it runs zero LLMs on the hot path, maintains no mandatory conversation/session database, and distributes as a single `CGO_ENABLED=0` binary.

## Decision

Implement all three controls as deterministic, zero-LLM, opt-in stateless primitives that compose with tollkeeper's existing CEL policy engine, GCRA rate limiter, and optional Redis backend:

### 1. Upstream provenance metadata, CEL attributes, and response stamps

- Each entry in `upstreams[]` accepts optional static `metadata`:
  - `trust`: `trusted` (default) or `untrusted`
  - `classification`: `public`, `internal` (default), `confidential`, or `restricted`
  - `egress`: `bool` (default `false`)
  - `impact`: `read`, `write`, or `destructive` (when omitted, derived deterministically from MCP tool annotations: `destructiveHint` -> `destructive`, `readOnlyHint` -> `read`, otherwise `write`).
- Metadata propagates to `catalog.Tool` during upstream resync and is exposed in CEL as `tool.trust`, `tool.classification`, `tool.egress`, and `tool.impact` at zero allocation cost.
- When `server.stamp_provenance: true` (opt-in, default `false`), the gateway attaches `_meta["tollkeeper.provenance"]` to every `tools/call` response across both the direct fast path and the go-sdk path, carrying `upstream`, `tool`, `trust`, `classification`, `egress`, `impact`, and `pin_hash`. Agent runtimes and orchestrators can use this gateway-authored metadata to isolate or down-privilege untrusted tool output deterministically.

### 2. Cost-based GCRA impact limits

- Each `rate_limits.rules[]` entry accepts optional `cost_expr` (a CEL expression evaluated with `args`, `tool`, `sub`, and `tenant` under the existing 10,000-unit cost cap and 50 ms timeout) and `max_cost` (optional per-call ceiling, capped at `burst`).
- When `cost_expr` is omitted, cost is `1` and the hot path incurs zero CEL overhead.
- When `cost_expr` is set, arguments are decoded lazily once per request only if a costed rule matches. A negative result, type error, evaluation error, or `cost > max_cost` fails closed (rejects the call with HTTP `429`). A computed cost of `0` floors to `1`.
- Both the lock-free in-memory GCRA store (`internal/ratelimit/gcra.go`) and the single-RTT Redis Lua script (`internal/ratelimit/redis.go`) advance TAT by `interval * cost`, reject immediately when `cost > burst`, and roll back all rules atomically if any rule denies the call.

### 3. Opt-in stateless idempotency / anti-replay guard

- Configured under `idempotency`: `enabled` (default `false`), `mode` (`header`, `required`, or `canonical_hash`), `header` (default `Idempotency-Key`), `ttl` (default `5m`, max `24h`), `max_entries` (default `10000`, min `100`), and `tools` globs.
- Checked in HTTP admission strictly after authentication, rate limiting, pin checks, and policy evaluation (so denied or step-up calls never poison a key) and before recording audit intent or forwarding to an upstream.
- Keys are cryptographically scoped per `(subject, tenant, tool, raw_key)` using `SHA-256` with domain separation (`tk-idem-v1`). In `canonical_hash` mode, `raw_key` is the SHA-256 of canonicalized JSON arguments (sorted object keys, stripped whitespace).
- Backed by a bounded in-memory TTL store with periodic janitor sweeping on single-instance deployments, or automatically by atomic Redis `SET NX PX` (reusing `rate_limits.redis`) in multi-replica deployments.
- Duplicate claims are rejected with HTTP `409 Conflict` and JSON-RPC error `-32009`, recorded as `decision=rejected` in the audit log, and counted in `mcpgw_idempotency_rejections_total`. Missing headers in `required` mode return HTTP `400 Bad Request` (`-32602`). Store errors fail closed with HTTP `503 Service Unavailable`.

## Alternatives considered

- **LLM-based prompt-injection classifier in the gateway.** Rejected: adds 200–2000 ms latency, external model dependencies, non-determinism, and bypassable heuristics. Provenance metadata + deterministic CEL rules + response stamping let the gateway enforce hard boundaries while giving downstream agent runtimes reliable taint signals.
- **Caching and replaying full upstream tool responses on duplicate idempotency keys.** Rejected: caching arbitrary tool payloads (which may contain PII, secrets, or megabytes of data) turns the gateway into a sensitive data store and complicates redaction and compliance. Rejecting duplicates with HTTP `409` / `-32009` keeps the guard strictly key-hash-only and stateless with respect to payload data.
- **Separate token-bucket algorithm for impact budgets.** Rejected: extending GCRA with `step = interval * cost` preserves exact all-or-nothing multi-rule rollback and single-RTT atomic Redis execution with minimal code surface.

## Consequences

- Operators can express provenance-aware policies (`tool.trust == "untrusted"`, `tool.egress`, `tool.classification == "restricted"`, `tool.impact == "destructive"`) without brittle naming conventions.
- Destructive and financial tools can enforce quantitative per-call and per-window impact budgets (records, files, currency units) across single-node and Redis-backed multi-replica clusters.
- Opt-in idempotency prevents accidental double-execution of side-effecting calls without storing response payloads.
- All three features are opt-in and add zero overhead when unconfigured.

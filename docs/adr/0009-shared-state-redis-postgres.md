# ADR 0009: Redis for shared rate limits, Postgres as an immutable audit sink

## Status

Accepted.

## Context

v0.1 kept all state per replica: GCRA cells in memory and the audit chain in a local JSONL file. Two questions follow from that in any review of a horizontally scaled deployment: "is a limit of 100 calls per minute really 100, or 100 per pod?" and "where does the compliance team query the audit trail, and who can edit it there?"

## Decision

### Rate limits

- `rate_limits.store: redis` switches the GCRA backend. One Lua script receives every matching rule for a call, evaluates all of them and writes all of them only if every rule allows, preserving the all-or-nothing semantics of [ADR 0003](0003-gcra-rate-limiting.md) across replicas in a single round trip.
- The script reads Redis `TIME`, so replicas with skewed clocks still agree. Times are microseconds, which keeps them exact in Lua's doubles.
- Keys expire one emission tolerance after their last use, so Redis memory tracks active callers.
- On a Redis error the limiter either falls back to the replica's in-memory store (`on_error: local`, default) or refuses the call (`deny`), and counts it in `mcpgw_ratelimit_backend_errors_total`. A 50 ms timeout bounds the latency Redis can add.
- One conformance suite runs against the in-memory store, miniredis in unit tests and a real Redis in CI, so the two backends cannot drift.

### Audit

- The JSONL file stays the primary log. `audit.postgres.dsn` adds a **mirror**: each batch is staged in a Postgres transaction (`COPY`), then written and fsynced to the file, then committed.
  - If staging or the file write fails, nothing is kept on either side and the existing `fail_closed` behaviour applies.
  - Once the file is fsynced it is final. A failed `COMMIT` is ambiguous (the server may have committed before the connection dropped), so the gateway never truncates the file at that point. It marks the mirror as behind and, before the next batch, reads the mirror's last sequence number and hash and backfills what is missing from the file.
- On startup the same reconciliation runs. The gateway refuses to start if Postgres holds records the file does not, or a different record at the same sequence number, since either means the file or the table was altered.
- The table defends itself against accidents and against roles that hold only `INSERT`:
  - `BEFORE UPDATE OR DELETE` and `BEFORE TRUNCATE` triggers reject every change.
  - A `BEFORE INSERT` trigger recomputes `sha256(prev || raw)` in SQL, requires the row to link to the previous record of its chain, and requires `chain_id`, `seq`, `prev` and `kind` to equal the values inside `raw`. It runs with a pinned `search_path` and looks the predecessor up in its own schema, so a temporary table cannot satisfy the check.
  - `body` is derived from `raw` by the trigger, so queries can never see content that differs from what is verified. A record `jsonb` cannot represent (for example one containing `\u0000`) is stored with a `NULL` body instead of failing the batch.
- The hash chain is not a signature. A role that can insert can still append well-formed records at the head of a chain; only the Ed25519 checkpoints and a small `--max-unsigned` detect that. The gateway therefore runs with `audit.postgres.migrate: false` by default and logs every excess privilege its role holds.
- The exact bytes are stored in `raw`. `tollkeeper audit verify --postgres` exports `raw` and runs the same verifier used for files, and fails on an empty chain.

## Alternatives considered

- **Redis `INCR` with fixed windows.** Simpler script, but bursts of twice the limit at window edges, and different semantics from the in-memory store.
- **One Redis call per rule.** Loses atomicity across rules and multiplies round trips.
- **Postgres as the only audit store.** Removes the file, but makes every tool call depend on database latency and availability, and loses the simple offline `verify` of a file.
- **Asynchronous shipping to Postgres.** Lower latency, but the database lags and the "same records in both places" invariant becomes eventual.

## Consequences

- A tool call now waits for one Postgres transaction per audit batch, not per call; batching keeps the overhead to the flush interval.
- The database owner can still drop the triggers. The model assumes the gateway connects as a role that only has `INSERT` and `SELECT` (see [docs/operations/postgres.md](../operations/postgres.md)), and external anchoring of checkpoints (v1.0) is the answer to a malicious DBA.
- A foreign writer that appends at the head of a chain makes the gateway's next batch conflict, which fails closed. That is a denial of service by someone who already holds write access to the audit database, and it is visible in `mcpgw_audit_sink_errors_total`.
- Redis Cluster requires all keys of one call in the same slot. Validation refuses several addresses unless `key_prefix` carries a hash tag such as `{tollkeeper}:`, which concentrates rate limit traffic on one shard.
- The scripts use `TIME` before writing, which needs Redis 7 or later (or Valkey).

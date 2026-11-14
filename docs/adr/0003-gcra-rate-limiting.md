# ADR 0003: GCRA rate limiting with all-or-nothing admission

## Status

Accepted, v0.1. The distributed store is tracked in [ADR 0009](0009-shared-state-redis-postgres.md).

## Context

Limits apply at several scopes at once: subject, subject plus tool, client, upstream, tool and global. A call must pass every applicable rule. The limiter runs before policy and catalog lookups to shed load early, so it must be cheap under contention.

## Decision

- Use the Generic Cell Rate Algorithm. Each key stores a single `int64`, the theoretical arrival time (TAT), updated with a compare-and-swap loop. No mutex on the hot path.
- A request lists every matching rule. The store takes all of them or none: if one rule rejects, the cells already advanced are rolled back.
- Rejections return `429` with `Retry-After` and the IETF `RateLimit` and `RateLimit-Policy` headers.
- A janitor removes idle keys so memory stays bounded by active keys, not by keys ever seen.

## Alternatives considered

- **Token bucket** (`golang.org/x/time/rate`). Equivalent semantics, but two floats per key and a mutex, and harder to express as a single atomic operation in Redis.
- **Fixed or sliding window counters.** Simple, but they allow bursts of up to twice the limit at window edges.

## Consequences

- A take costs about 97 ns serially and 43 ns in parallel, with zero allocations.
- The same algorithm maps to one Lua script per request in Redis, which keeps in-memory and distributed semantics identical.
- Tokens are spent by calls that policy later denies. This is deliberate: rate limits protect the gateway, and running policy first would let a caller probe policy for free.

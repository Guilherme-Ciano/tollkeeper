# ADR 0001: Hash-chained audit log with Ed25519 checkpoints

## Status

Accepted, v0.1.

## Context

Gateway audit logs usually live in a database or a log pipeline. Anyone with write access can change or delete entries without leaving a trace, which weakens them as evidence for SOC 2, ISO 27001, EU AI Act record-keeping or DORA-style traceability.

## Decision

- Each record is a JSONL line `{"body": <raw JSON>, "hash": "<hex>"}`. The body carries `seq`, `ts` (unix nanoseconds), `chain_id`, `prev` and either an event or a checkpoint.
- `hash = SHA-256(prev_hash || body_bytes)`. The verifier hashes the **stored bytes**, never a re-encoding, so there is no canonicalisation step to get wrong. Unknown fields are rejected.
- Checkpoints are records in the chain. Each one signs `"tollkeeper-ckpt-v1" || 0x00 || chain_id || 0x00 || seq (big endian) || hash` of the record before it with Ed25519, every N records, every T seconds and at shutdown.
- A single sequencer goroutine assigns sequence numbers. Callers enqueue without blocking. In `fail_closed` mode a tool call is refused when its *intent* record cannot be queued within 100 ms.
- Arguments are stored as a SHA-256 hash by default, for GDPR data minimisation.
- On restart the sequencer reads the last line and continues the chain. It refuses to start if the tail is corrupt or belongs to another chain.
- There is one chain per replica (`chain_id`), so no distributed sequencer is needed.

## Consequences

- Modifications, deletions, reordering and forged checkpoints are detected at the exact sequence number.
- Truncating records after the last checkpoint cannot be detected locally. External anchoring of checkpoints is planned for v1.0.
- fsync per batch bounds the window of records lost on a crash to one flush interval (50 ms by default).

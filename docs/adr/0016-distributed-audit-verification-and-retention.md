# ADR 0016: Distributed audit model, continuous chain verification, and retention

## Context

When running multiple tollkeeper replicas behind a load balancer, a single shared append-only file cannot be written safely by multiple processes without distributed locking on the critical admission path. [ADR 0009](0009-shared-state-redis-postgres.md) introduced Postgres mirroring, but operators still needed:

1. A formal multi-replica audit model explaining chain ownership, reconciliation and multi-chain verification.
2. Continuous verification to catch out-of-band file truncation, tampering or stalled checkpoint signing while the gateway is running.
3. A safe archiving and retention workflow that refuses to archive corrupted chains and tracks cryptographic integrity across archived bundles.

## Decision

1. **Formal distributed audit model (per-replica independent chains):**
   - Each gateway replica owns a distinct `audit.chain_id` (for example `${POD_NAME}`) backed by its local `fsync`ed JSONL file as the single-writer source of truth.
   - Replicas mirror committed batches transactionally into the shared append-only Postgres table `tollkeeper_audit` keyed by `(chain_id, seq)`, where database triggers enforce hash-chain continuity per `chain_id` independently — eliminating cross-replica write contention on the hot path.
   - `pgsink.Sink.ListChains` and `tollkeeper audit verify --postgres <dsn> --all-chains` verify every replica chain stored in Postgres in a single pass and fail if any chain shows tampering, missing checkpoints or sequence gaps.
2. **Continuous chain verification (`audit.Watchdog`, `audit.verify`, `tollkeeper audit watch`):**
   - `audit.Watchdog` periodically verifies the local audit log using the active key or `--pubkey-dir`, and enforces monotonic head progression (`last_seq` must never shrink and `last_hash` at the same sequence must never change) to detect truncation or silent rewrites.
   - Enabling `audit.verify.enabled: true` runs the watchdog inside the gateway and exports `mcpgw_audit_verify_runs_total{result}`, `mcpgw_audit_verify_last_seq` and `mcpgw_audit_verify_healthy`.
   - `tollkeeper audit watch` provides the same verifier as a standalone CLI daemon or one-shot check (`--once`).
3. **Verified archiving and retention (`audit.Archive`, `tollkeeper audit archive`):**
   - `audit.Archive` streams the log through `VerifyWith` while writing a gzipped bundle (`<chain>-<timestamp>-seq<last>.jsonl.gz`) and a companion `.manifest.json` containing chain metadata, `archive_sha256`, sizes and `retain_until`.
   - If verification fails for any reason, the temporary archive is deleted and archiving fails closed (`ErrTampered`).
   - `PruneArchives` enforces `max_age` (`--retain-for`) and `max_archives` (`--max-archives`), deleting expired bundle/manifest pairs cleanly.

## Alternatives considered

- **Single global hash chain across all replicas via Postgres advisory lock:** Serializes every tool call across the fleet behind a single database lock, destroying tail latency and making Postgres availability a hard SPOF for admission.
- **Blind `logrotate` compression of `audit.jsonl`:** Can archive silently truncated or tampered files without recording verifiable manifests or checking signatures before pruning.

## Consequences

- Horizontal scaling adds zero cross-replica locking to the audit hot path while preserving per-replica cryptographic tamper-evidence and fleet-wide verification via `--all-chains`.
- Operators get Prometheus alerts (`mcpgw_audit_verify_healthy == 0`) if an on-disk chain is tampered with or truncated at runtime.
- Archived chains remain independently verifiable offline via `audit.VerifyArchive` using the manifest SHA-256 and public key set.

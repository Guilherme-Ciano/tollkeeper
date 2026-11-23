# ADR 0012: Pure-Go KMS checkpoint signing and zero-downtime audit key rotation

## Context

[ADR 0001](0001-verifiable-audit-log.md) introduced Ed25519 checkpoint signing using a local private key file (`audit.checkpoint.signing_key_file`). That design is fast and self-contained, but production deployments raise two operational gaps:

1. **Key custody:** Regulated environments often prohibit storing long-lived signing private keys on host filesystems, requiring Hardware Security Modules (HSM) or Key Management Services (KMS) such as HashiCorp Vault / OpenBao Transit or AWS KMS.
2. **Key rotation:** Replacing `signing_key_file` previously required stopping the gateway or starting a new chain; verifying an existing chain spanning multiple keys was impossible with a single `--pubkey`.

## Decision

1. **Pluggable `audit.CheckpointSigner` interface:** The audit log sequencer delegates checkpoint signing to an interface (`KeyID`, `PublicKey`, `Algorithm`, `Sign(ctx, msg)`). Existing local Ed25519 keys are wrapped by `audit.LocalSigner`, preserving byte-for-byte compatibility with legacy checkpoints (omitting `alg` for Ed25519).
2. **Multi-algorithm verification (`ed25519` and `ecdsa-p256-sha256`):** Checkpoints and key rotations support both Ed25519 and ECDSA P-256 (SHA-256 + ASN.1 DER), which is universally available across cloud KMS and FIPS-validated HSMs.
3. **Pure-Go (`CGO_ENABLED=0`) KMS signers:** Add native HTTP signers in `internal/audit/kms` with zero new external module dependencies:
   - **Vault / OpenBao Transit (`provider: vault`):** supports `ed25519` and `ecdsa-p256` Transit keys, namespaces, `netguard` egress filtering, and strict redirect refusal.
   - **AWS KMS (`provider: aws`):** implements AWS SigV4 (`AWS4-HMAC-SHA256`) directly over Go's standard library for `TrentService.GetPublicKey` and `TrentService.Sign` (`ECDSA_SHA_256` over SHA-256 digests), with optional custom endpoints for VPC endpoints or LocalStack.
4. **In-band signed `KeyRotation` records and live `SIGHUP` rotation:**
   - `Log.RotateSigner` executes atomically inside the sequencer goroutine: flushes any unsigned events into a final checkpoint with the outgoing key, appends a domain-separated `key_rotation` record (`tollkeeper-keyrot-v1`) signed by the outgoing key attesting the incoming PKIX public key, switches the active signer, and emits a checkpoint signed by the incoming key. Any failure rolls back the entire batch and leaves the previous signer active.
   - `SIGHUP` reload detects when the configured signing key material changes (in-place PEM replacement or KMS key switch) and rotates live without restarting when Rekor anchoring is not bound to the startup key.
   - `audit.VerifyWith` promotes trusted rotated keys automatically when verifying from the original root public key, and `tollkeeper audit verify --pubkey-dir` loads a directory of trusted Ed25519/P-256 public keys.
   - The Postgres audit mirror schema (`internal/audit/pgsink/schema.sql`) adds `key_rotation` to `tollkeeper_audit_kind_check` and enforces `(parsed ? 'key_rotation')` in the insert trigger.

## Alternatives considered

- **CGO PKCS#11 (`miekg/pkcs11`) or AWS Go SDK v2:** PKCS#11 breaks static `CGO_ENABLED=0` cross-compiled release binaries across `linux/darwin/windows`, and pulling the full AWS SDK adds dozens of transitive dependencies solely for two JSON RPC endpoints. Pure-Go Vault Transit and AWS KMS SigV4 preserve static zero-dependency builds while keeping the `CheckpointSigner` interface open for custom signers.
- **Out-of-band key rotation (starting a new chain per key):** Simplifies verification of individual files, but fragments audit continuity and requires external metadata to prove the cutover point was not tampered with.

## Consequences

- Cross-compiled `CGO_ENABLED=0` release binaries continue to build with zero new `go.mod` dependencies.
- Auditors can verify multi-year chains spanning multiple key rotations (including local Ed25519 to AWS KMS P-256 migrations) using only the original root public key or `--pubkey-dir`.
- Rekor v2 anchoring (`audit.anchor.enabled: true`) continues to require a local Ed25519 signing key file until transparency log submission is generalized to `CheckpointSigner`.
- Postgres mirrors created before this change require applying the updated `schema.sql` migration (idempotent `DO $$` constraint update) before writing `key_rotation` records.

# ADR 0010: Anchor audit checkpoints in a Rekor v2 transparency log

## Status

Accepted.

## Context

[ADR 0001](0001-verifiable-audit-log.md) makes the audit log tamper-evident: every record is SHA-256 chained and Ed25519 checkpoints sit inside the chain. Two gaps remain, and both come from the fact that all evidence lives with the operator:

- **Whoever holds the signing key can rewrite history.** They can rebuild the chain from any point and re-sign every checkpoint. The verifier cannot tell the new chain from the original.
- **The tail can be truncated.** Deleting the last records, checkpoints included, leaves a shorter chain that still verifies.

An external, append-only witness of what the chain looked like at a given time closes both gaps. Sigstore's Rekor is the public transparency log the supply chain ecosystem already uses, including this project's own releases.

## Decision

- **Rekor v2 only.** The gateway submits a `hashedrekord` v0.0.2 entry to `POST /api/v2/log/entries` and receives the entry, an RFC 6962 inclusion proof and a C2SP signed-note checkpoint.
  - Rekor v2 needs no signed entry timestamp (SET) and can be verified offline with `golang.org/x/mod/sumdb/note` and `sumdb/tlog`. The Sigstore client stack (sigstore-go, protobuf-specs, gRPC) is not pulled in.
  - The URL is configuration because shards rotate yearly (`log2025-1.rekor.sigstore.dev`), and a private instance works the same way.
- **What is anchored.** The statement is `"tollkeeper-anchor-v1" 0x00 chain_id 0x00 be64(seq) sha256(checkpoint record)`. The covered hash is the checkpoint record's own chain hash, so one anchor commits to the entire prefix of the chain.
- **Signature.** Rekor accepts Ed25519 only as Ed25519ph over SHA-512, while checkpoints are pure Ed25519 over a different domain string. Anchoring therefore signs `SHA-512(statement)` with Ed25519ph, using the same checkpoint key.
  - Reusing the key is safe. The two domain strings differ, and RFC 8032 adds a `dom2` prefix to every Ed25519ph signature, so neither signature can be replayed as the other.
- **Where receipts live.** Each verified receipt becomes an `anchor` record inside the chain, written after the checkpoint it covers.
  - Receipts are themselves chained, so deleting or editing one is detected at its sequence number.
  - They travel with the file and reach the Postgres mirror without a new sink.
  - This matters because Rekor v2 has no search API: a lost receipt cannot be fetched again.
- **Never on the hot path.** Committed checkpoints are offered to a background job with a latest-wins slot.
  - The job anchors on `every` checkpoints or `interval` (default 15 minutes), never more often than `min_spacing` (1 minute, also after a restart), retries with full-jitter backoff and honours `Retry-After`.
  - Anchor records do not count as content: they never make a checkpoint due, so an idle gateway stops anchoring.
  - It verifies the receipt before handing it to the sequencer through a bounded, non-blocking queue.
  - A slow or unavailable Rekor lowers the anchoring rate. It never delays, blocks or drops audit writes.
- **Time.** Rekor v2 records no integration time. Two sources can prove when an anchor existed, and the verifier uses the earlier of the two:
  - **RFC 3161 timestamp** (`audit.anchor.tsa_url`, for example `https://timestamp.sigstore.dev/api/v1/timestamp`). Before submitting to Rekor, the gateway asks the timestamp authority to sign `SHA-512(statement)`, checks the nonce, and stores the token in the anchor record. Verification checks the CMS signature, a certificate chain to a timestamp authority in `trusted_root.json` with the `timeStamping` extended key usage, the authority's validity window, and that the token covers the digest recomputed from the chain. The library is `digitorus/timestamp`, the one Sigstore's own clients use.
  - **Witness cosignatures** (C2SP `tlog-cosignature`) on the checkpoint returned with the receipt. Sigstore's client guidance says checkpoints of the initial Rekor v2 launch are not witnessed, and that co-signed checkpoints in upload responses are planned, so on the public instance the timestamp authority is the time source today.
  - `audit verify --witness` checks the cosignatures that are present. The witnessed time of an anchor is the k-th earliest trusted cosignature, where k is `--min-witnesses`, so one early or dishonest witness cannot backdate it.
  - Record timestamps may not go back by more than one minute. `--max-anchor-delay` measures from the oldest record an anchor newly covers, not from the checkpoint's own timestamp, so a key holder who rebuilds a suffix today must date the forged records within that delay.
  - `--max-anchor-age` fails when the newest witnessed anchor is older than a bound. That detects a log cut back to an old anchor, which no in-file check can see.
- **Verification is offline.** It uses operator-supplied trust material: a Sigstore `trusted_root.json` or a PEM log key, plus optional witness keys.
  - `audit verify --rekor-trust` checks the log's signature on the checkpoint, the inclusion proof, that the logged digest is the one recomputed from the chain, and that the logged key is the checkpoint key.
  - `--require-anchors` and `--max-unanchored` bound the unanchored tail.

## Alternatives considered

- **Rekor v1.** It is the public default, but the SET it relies on is what Sigstore is moving away from, and v1 entries are verified with a separate API and key type. The signed-note format of v2 verifies with the Go standard library plus `x/mod`.
- **RFC 3161 timestamps alone, without Rekor.** They prove time but not an append-only history, and nobody else can audit which timestamps were issued. They complement the log instead of replacing it.
- **A sidecar file of receipts.** Simpler sequencer, but it is one more mutable file whose deletions cannot be detected, and it would not reach Postgres.
- **Synchronous anchoring.** It would bound the unanchored tail to zero, but it ties every tool call to a public service's latency and availability.

## Consequences

- The audit format gains a third record kind. Older verifiers reject logs that contain anchor records, because unknown fields are refused. Logs written without anchoring are unchanged.
- The Postgres schema accepts `kind = 'anchor'`. The migration upgrades older tables in place, and the gateway refuses to start with anchoring on if the table would reject anchor rows.
- Entries in the public log are permanent and public. They reveal no audit content, because the anchored digest commits to a 256-bit chain hash. They do reveal:
  - the checkpoint public key, which links every replica and restart to one operator;
  - the anchoring cadence, and with `every` the checkpoint rate, which follows traffic;
  - one stream of entries per replica, so the replica count;
  - to anyone who holds a chain hash, the `chain_id`, which is often a pod name.
  Interval-only scheduling is recommended on the public instance. Requests carry the generic User-Agent `tollkeeper`.
- Without a timestamp authority or witnessed checkpoints, an anchor proves inclusion, not time. The README and the threat model state this.
- With a timestamp authority configured, anchoring depends on two services. A failure of either is retried and never blocks audit writes.
- The public instance is rate limited by IP and publishes no numbers. The 1 minute minimum interval and the latest-wins policy keep a replica to about 100 entries a day at the default.

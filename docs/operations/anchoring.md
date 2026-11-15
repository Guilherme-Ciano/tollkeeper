# Anchoring the audit log in Rekor

Anchoring publishes a commitment to each signed checkpoint in a Rekor v2 transparency log and stores the receipt in the audit chain. `tollkeeper audit verify` can then prove that each anchored checkpoint is in the log. When the log returns witnessed checkpoints, it can also prove *when*, and that the chain was not rewritten afterwards. The design is in [ADR 0010](../adr/0010-rekor-checkpoint-anchoring.md).

> **Time on the public instance.** Sigstore's client guidance says checkpoints of the initial Rekor v2 launch are not witnessed; co-signed checkpoints in upload responses are planned. Set `tsa_url` so each anchor also carries an RFC 3161 timestamp from Sigstore's timestamp authority. Without it, anchors from `log2025-1` prove inclusion only, and `--max-anchor-delay` and `--max-anchor-age` fail on them.

## Prerequisites

- A checkpoint signing key (`audit.checkpoint.signing_key_file`). Anchors are signed with the same key.
- Sigstore trust material for the log. The `trusted_root.json` distributed through Sigstore's TUF repository lists every production log key with its validity window. Fetch it with a TUF client, for example `cosign initialize`, or copy it from your organisation's mirror. tollkeeper never fetches trust material itself.
- Outbound HTTPS to the log. The public Rekor v2 shard for 2025–2026 is `https://log2025-1.rekor.sigstore.dev`. Shards rotate, so check the current one in Sigstore's documentation.

## Configuration

```yaml
audit:
  chain_id: ${POD_NAME}
  checkpoint:
    signing_key_file: /var/lib/tollkeeper/keys/audit-ed25519.pem
  anchor:
    enabled: true
    rekor_url: https://log2025-1.rekor.sigstore.dev
    trust_files: [/etc/tollkeeper/trusted_root.json]
    tsa_url: https://timestamp.sigstore.dev/api/v1/timestamp
    interval: 15m
    required: false
```

| Key | Default | Notes |
| --- | --- | --- |
| `rekor_url` | | `https`; `http` only for loopback test instances |
| `trust_files` | | One or more `trusted_root.json` files or PEM log keys |
| `origin` | | Log origin for a PEM key; taken from `baseUrl` in a trusted root |
| `tsa_url` | | RFC 3161 timestamp authority; its certificate chain must be in `trust_files` (the Sigstore trusted root lists it, or add a PEM chain) |
| `every` | `0` | Anchor after this many checkpoints |
| `interval` | `15m` | Anchor at most this often; `0` or at least `1m` |
| `timeout` | `1m` | Per submission; Rekor v2 answers only once the entry is in a checkpoint |
| `max_backoff` | `10m` | Upper bound of the retry backoff |
| `min_spacing` | `1m` | Minimum time between submissions, also after a restart; lower only for a loopback test log |
| `required` | `false` | Check the log at startup and report stale anchoring on `/readyz` |

Each entry is public and permanent. It contains the checkpoint public key and a digest, not audit content. Timing still reveals the cadence, restarts and the number of replicas; prefer interval-only scheduling on the public instance.

## Verifying

```bash
tollkeeper audit verify -f audit.jsonl --pubkey audit.pub --chain-id gw-0 \
  --rekor-trust trusted_root.json \
  --witness 'witness.example+1a2b3c4d+BASE64KEY' --min-witnesses 1 \
  --require-anchors --max-unanchored 5000 --max-anchor-delay 1h --max-anchor-age 2h
```

- `--rekor-trust` verifies every anchor record: the log's signature on the checkpoint, the inclusion proof, the digest recomputed from the chain, and the checkpoint key in the entry. Without it, anchors are counted and reported as unverified.
- `--chain-id` is required with `--rekor-trust`; otherwise another chain signed by the same key would pass.
- A timestamp authority in `--rekor-trust` verifies the RFC 3161 token stored with each anchor. It is a time source on its own; no witness flags are needed.
- `--witness` checks the timestamped cosignatures that witnesses add to the log's checkpoints, and implies `--min-witnesses 1`. The witnessed time is the k-th earliest trusted cosignature. An anchor's time is the earlier of its timestamp and its witnessed time; anchors with neither prove no time, and fail when `--max-anchor-delay` or `--max-anchor-age` is set.
- `--max-anchor-delay` fails when a record was first witnessed long after it was written. Record timestamps may not go back by more than a minute, so a rebuilt suffix cannot hide behind an old date.
- `--max-unanchored` bounds the records after the last anchored checkpoint in the file.
- `--max-anchor-age` fails when the newest witnessed anchor is too old. That catches a file cut back to an older anchor, which no in-file check can detect.

A successful run ends with a line such as:

```
ANCHORED anchors=96 anchored_seq=184213 after_anchor=742 log=log2025-1.rekor.sigstore.dev#200303387 witnessed_at=2026-11-14T21:58:43Z
```

## Monitoring

| Metric | Alert when |
| --- | --- |
| `mcpgw_audit_anchor_last_success_timestamp_seconds` | `time() - value > 2 * interval + max_backoff`; the gauge is `0` until the first receipt is committed, so also alert when it stays `0` past one interval |
| `mcpgw_audit_anchor_attempts_total{outcome="rejected"}` | any increase: a configuration or key problem |
| `mcpgw_audit_anchor_attempts_total{outcome="invalid_receipt"}` | any increase: wrong trust material, or a misbehaving log |
| `mcpgw_audit_anchor_attempts_total{outcome="retry"}` | a sustained rate: the log is unavailable or rate limiting |
| `mcpgw_audit_anchor_covered_seq` | flat while `mcpgw_audit_records_written_total` grows |

## Shard rotation

When Sigstore opens a new shard, the old one is frozen shortly after and starts rejecting writes. Anchoring then fails with `rejected` or `retry`.

1. Update your `trusted_root.json` through TUF. It lists the new shard and keeps the old one.
2. Set `rekor_url` to the new shard and roll the gateway.
3. Keep the old key in the trust material. Existing anchors stay verifiable for as long as the trusted root lists it.

Anchoring never blocks audit writes, so a rotation delay only widens the unanchored tail.

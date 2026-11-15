# Anchoring the audit log in Rekor

Anchoring publishes a commitment to each signed checkpoint in a Rekor v2 transparency log and stores the receipt in the audit chain. With witness keys, `tollkeeper audit verify` can then prove that a checkpoint existed by a given time, and that the chain was not rewritten after it. The design is in [ADR 0010](../adr/0010-rekor-checkpoint-anchoring.md).

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
    interval: 15m
    required: false
```

| Key | Default | Notes |
| --- | --- | --- |
| `rekor_url` | | `https`; `http` only for loopback test instances |
| `trust_files` | | One or more `trusted_root.json` files or PEM log keys |
| `origin` | | Log origin for a PEM key; taken from `baseUrl` in a trusted root |
| `every` | `0` | Anchor after this many checkpoints |
| `interval` | `15m` | Anchor at most this often; `0` or at least `1m` |
| `timeout` | `1m` | Per submission; Rekor v2 answers only once the entry is in a checkpoint |
| `max_backoff` | `10m` | Upper bound of the retry backoff |
| `required` | `false` | Check the log at startup and report stale anchoring on `/readyz` |

Each entry is public and permanent. It contains the checkpoint public key and a digest, not audit content.

## Verifying

```bash
tollkeeper audit verify -f audit.jsonl --pubkey audit.pub \
  --rekor-trust trusted_root.json \
  --witness 'witness.example+1a2b3c4d+BASE64KEY' --min-witnesses 1 \
  --require-anchors --max-unanchored 5000 --max-anchor-delay 1h
```

- `--rekor-trust` verifies every anchor record: the log's signature on the checkpoint, the inclusion proof, the digest recomputed from the chain, and the checkpoint key in the entry. Without it, anchors are counted and reported as unverified.
- `--witness` and `--min-witnesses` check the timestamped cosignatures that witnesses add to the log's checkpoints. Only witnessed anchors prove time.
- `--max-anchor-delay` fails when a checkpoint was witnessed long after it was written. That is what a chain rebuilt by a key holder looks like.
- `--max-unanchored` bounds the records after the last anchored checkpoint. That is the part an attacker could truncate without detection.

A successful run ends with a line such as:

```
ANCHORED anchors=96 anchored_seq=184213 after_anchor=742 log=log2025-1.rekor.sigstore.dev#200303387 witnessed_at=2026-11-14T21:58:43Z
```

## Monitoring

| Metric | Alert when |
| --- | --- |
| `mcpgw_audit_anchor_last_success_timestamp_seconds` | `time() - value > 2 * interval + max_backoff` |
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

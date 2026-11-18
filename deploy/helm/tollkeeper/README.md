# tollkeeper Helm chart

Runs tollkeeper as a StatefulSet: each pod writes its own audit chain (`chain_id` is the pod name) to its own volume, so a restarted pod continues its chain and `tollkeeper audit verify` works per pod.

```bash
helm install gw deploy/helm/tollkeeper -f my-values.yaml
```

`config` is the tollkeeper configuration (see the project README); the chart fills in listeners, `public_url`, the audit path and `chain_id`, and merges your `config` over them. [`ci/full-values.yaml`](ci/full-values.yaml) is a complete example that CI renders, validates against the Kubernetes schemas and checks with `tollkeeper config validate`.

| Value | Default | Notes |
|---|---|---|
| `publicURL` | `https://mcp.example.com/mcp` | Canonical MCP URL clients use; also the RFC 9728 metadata path |
| `config` | jwt auth, deny-all policy | Your auth, upstreams, policy and rate limits. Required before the pods become ready |
| `replicaCount` | `2` | With more than one replica, use `redis.enabled` so rate limits are shared, and `requestStateKey` so a multi-round-trip retry can land on any pod |
| `auditSigningKey.secretName` | | Secret with an Ed25519 key from `tollkeeper audit keygen`; without it checkpoints are not signed |
| `requestStateKey.secretName` | | Secret with at least 32 random bytes shared by all pods, for sealing `requestState` |
| `redis.enabled`, `redis.addrs` | off | Shared GCRA rate limits; the key prefix keeps all keys in one Cluster slot |
| `postgres.enabled`, `postgres.dsnSecret` | off | Mirror audit chains to Postgres; the DSN is injected as `TOLLKEEPER_AUDIT__POSTGRES__DSN` |
| `envFromSecret` | | Secret whose keys become environment variables, for `${VAR}` references in `config` (client secrets, upstream tokens) |
| `persistence.size` | `5Gi` | Audit volume per pod; `persistence.enabled: false` uses an emptyDir and loses the chain on rescheduling |
| `serviceMonitor.enabled` | `false` | Prometheus Operator scrape of `/metrics` on the admin port |
| `prometheusRule.enabled` | `false` | The project's alert rules, pointed at this release's scrape job |
| `networkPolicy.enabled` | `false` | Restrict who may reach the MCP port (`ingressFrom`) and the admin port (`metricsFrom`) |
| `podDisruptionBudget` | `minAvailable: 1` | Only rendered with more than one replica |

Pods run as UID 65532 with a read-only root filesystem, no capabilities and no service account token. Probes use `/livez` and `/readyz` on the admin port; `/readyz` stays false until every upstream has synced. A config change rolls the pods through a checksum annotation; SIGHUP reloads are for VMs and containers outside Kubernetes.

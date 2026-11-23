# Architecture decision records

Each record states the context, the decision, the alternatives that lost and what the decision costs. They are short on purpose: the code shows *how*, these explain *why*.

| # | Decision | Status |
|---|---|---|
| [0001](0001-verifiable-audit-log.md) | Hash-chained audit log with Ed25519 checkpoints | Accepted |
| [0002](0002-cel-for-policy.md) | CEL for authorization policy, not OPA or Cedar | Accepted |
| [0003](0003-gcra-rate-limiting.md) | GCRA rate limiting with all-or-nothing admission | Accepted |
| [0004](0004-admission-at-http-layer.md) | Admission at the HTTP layer, go-sdk middleware as backstop | Accepted |
| [0005](0005-no-token-passthrough.md) | Never pass the caller's token to upstreams | Accepted |
| [0006](0006-stateless-transport-and-namespacing.md) | Stateless Streamable HTTP and `upstream__tool` namespacing | Accepted |
| [0007](0007-tool-pinning.md) | Tool definition pinning with operator approval | Accepted |
| [0008](0008-zero-code-comments.md) | Zero code comments | Accepted |
| [0009](0009-shared-state-redis-postgres.md) | Redis for shared rate limits, Postgres as an immutable audit sink | Accepted |
| [0010](0010-rekor-checkpoint-anchoring.md) | Anchor audit checkpoints in a Rekor v2 transparency log | Accepted |
| [0011](0011-stdio-sandboxing.md) | Stdio upstream sandboxing with fail-closed enforcement | Accepted |
| [0012](0012-audit-key-rotation-and-kms.md) | Pure-Go KMS checkpoint signing and zero-downtime audit key rotation | Accepted |
| [0013](0013-oauth-token-exchange-and-delegation.md) | OAuth 2.0 Token Exchange (RFC 8693) and controlled delegation | Accepted |
| [0014](0014-dpop-and-enterprise-idp.md) | Sender-constrained tokens with DPoP (RFC 9449) and enterprise IdP integration | Accepted |
| [0015](0015-tenant-policies-and-step-up.md) | Tenant-scoped policies, per-tenant rate limits, and RFC 9470 step-up authentication | Accepted |


The threat model that ties these together is in [../threat-model.md](../threat-model.md).

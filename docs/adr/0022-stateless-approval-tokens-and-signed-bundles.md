# 0022 — Stateless argument-bound human approval tokens and Ed25519-signed config bundles

Status: Accepted

## Context

Two high-priority enterprise governance requirements frequently arise in agent deployments:

1. **Operation-specific Human-in-the-Loop (HITL) approval.** OAuth step-up authentication (RFC 9470) proves that the caller re-authenticated or holds a broader scope, but it cannot answer: *"Did a human explicitly approve calling `files__delete_file` with `{"path":"/important"}` for this caller?"* Storing pending approval tickets inside the gateway would violate tollkeeper's stateless data-plane architecture (ADR 0006, ADR 0020) and force every deployment to operate an approval database.
2. **Policy and pin supply-chain integrity.** Operators deploying tollkeeper across fleets want cryptographic proof that the configuration (`gateway.yaml`) and tool pin lockfile (`pins.json`) loaded at startup and applied on `SIGHUP` hot reload were signed by a trusted CI pipeline or security team — without requiring a live control plane at boot time.

## Decision

### 1. Stateless argument-bound approval tokens (`tk-approval+jwt`)

- Approvals are represented as short-lived, compact Ed25519-signed JWTs (`alg: "EdDSA"`, `typ: "tk-approval+jwt"`) issued outside the gateway (via `tollkeeper approval sign`, a Slack/ChatOps bot, a CI workflow, or an AG-UI approval backend) and presented in `X-Tollkeeper-Approval` (configurable via `approvals.header`).
- Every token cryptographically binds:
  - `aud`: gateway `auth.resource` or `server.public_url` (prevents cross-gateway replay)
  - `sub` and `tenant`: exact caller identity
  - `approver`: human approver identity (recorded in `audit.Event.ApprovedBy` alongside `ApprovalID`)
  - `tool` + `args_hash` (`sha256:` of canonicalized JSON arguments with sorted keys and stripped whitespace) **or** a `batch` list of `(tool, args_hash)` pairs for batch approvals
  - `jti`, `iat`, and `exp`, bounded by `approvals.max_ttl` (default `15m`, max `24h`) and `approvals.clock_skew`
- Verified claims are exposed in CEL as `approval{verified, id, approver, reason}`, enabling declarative rules including separation of duties (four-eyes principle):
  ```yaml
  when: "approval.verified && approval.approver != principal.sub"
  on_deny:
    require_approval: true
    approval_ttl: 5m
    approval_reason: "Destructive call requires independent human sign-off"
  ```
- When an `allow` rule with `on_deny.require_approval: true` lacks a verified approval, tollkeeper responds with HTTP `403 Forbidden` and JSON-RPC `-32010`, returning structured challenge metadata (`approval_required`, `tool`, `args_hash`, `subject`, `tenant`, `header`, `ttl_s`, `reason`) so agent UIs (such as AG-UI / CopilotKit) can render an exact confirmation prompt.
- With `approvals.single_use: true` (default), once a policy allows an approved call, `(jti, tool, args_hash)` is consumed atomically in a bounded in-memory TTL store or Redis `SET NX PX` (reusing `rate_limits.redis`). Replays are rejected with HTTP `409 Conflict` / `-32011`. Denied calls never consume a token.
- Operators manage keys and tokens with `tollkeeper approval keygen|sign|verify`.

### 2. Ed25519-signed configuration and pin bundles

- `tollkeeper bundle sign` produces a detached `bundle.sig.json` manifest containing `version`, `bundle_id`, `created_at`, optional `expires_at`, SHA-256 digests of `config` (and optional `pins`), `key_id`, and an Ed25519 signature over the domain-separated payload `"tollkeeper-bundle-v1\n" + canonicalJSON(manifest)`.
- When `bundle.enabled: true` is configured, `app.Build` verifies the signed manifest against the exact SHA-256 of the loaded config bytes (`cfg.Digest`, eliminating TOCTOU between file load and verification) and `pinning.file` (required when `bundle.require_pins: true`), failing closed on any mismatch, expiration, or untrusted key.
- On `SIGHUP` hot reload, the gateway re-verifies the new config bytes using the **startup-pinned** `bundle` trust configuration (`pubkey_files` / `pubkey_dir` and `manifest_file`), so an attacker with write access to `config.yaml` cannot bypass bundle enforcement by flipping `bundle.enabled: false` and signalling a reload.
- Verification state is exposed via `mcpgw_bundle_verified` and `/api/overview` (`bundle.{enabled, verified, bundle_id, key_id}`).
- Operators manage bundle keys and manifests with `tollkeeper bundle keygen|sign|verify`.

## Alternatives considered

- **Built-in stateful approval queue and REST endpoints inside tollkeeper.** Rejected: adds persistence, RBAC for approvers, notification delivery, and HA state synchronization to the gateway binary. Externalizing approval issuance behind a stateless Ed25519 JWT keeps tollkeeper fast, small, and pluggable into any existing workflow tool (Slack, Jira, PagerDuty, AG-UI).
- **Signing policies via a remote control-plane API.** Rejected: introduces a runtime availability dependency on startup and reload. Detached Ed25519 manifests work in air-gapped environments, GitOps pipelines, and Kubernetes ConfigMaps/Secrets with zero network calls.

## Consequences

- Agents and UIs get cryptographic, argument-bound, single-use and batch Human-in-the-Loop approvals with full audit attribution (`approved_by`, `approval_id`) and four-eyes enforcement in CEL — with sub-millisecond verification latency (~60 µs Ed25519 verify).
- Config and tool-pin deployments gain end-to-end supply-chain integrity at both startup and live reload.
- Both capabilities are strictly opt-in and incur zero runtime cost when disabled.

# 0023 — Stateless MCP Tasks extension (SEP-2663)

Status: Accepted

## Context

Long-running MCP tool calls (batch pipelines, data exports, external builds) exceed synchronous HTTP timeouts. The MCP protocol revision `2026-07-28` introduces the official Tasks extension (`io.modelcontextprotocol/tasks`, SEP-2663), allowing servers to materialize an asynchronous `taskId` on `tools/call` (`resultType: "task"`) and letting clients poll status/results (`tasks/get`), supply mid-flight input (`tasks/update`), or cancel (`tasks/cancel`).

Proxying tasks naively in a multi-upstream gateway introduces two severe risks:
1. **Task routing state:** A gateway with multiple upstreams must know which upstream owns a `taskId` without maintaining a centralized task database.
2. **Cross-caller / cross-tenant IDOR:** If upstream `taskId` values are sequential or predictable, another authenticated caller could poll, update, or cancel someone else's running task.

## Decision

Implement opt-in (`server.tasks_enabled: true`, `server.task_ttl: 1h`) stateless task proxying using **HMAC-SHA256 sealed task handles**, following the same zero-state cryptographic design as `requestState` sealing (ADR 0006):

- When `server.tasks_enabled: true`, the gateway advertises the `io.modelcontextprotocol/tasks` extension in `ServerCapabilities`.
- When an admitted `tools/call` declares client capability `extensions["io.modelcontextprotocol/tasks"]` and targets a `streamable_http` upstream, the gateway forwards the call through the upstream's hardened HTTP client (preserving SSRF `netguard`, no-redirect transport, concurrency semaphore, timeout, and upstream OAuth/RFC 8693 token exchange).
- If the upstream responds with `resultType: "task"` and an upstream `taskId`, the gateway seals `(upstream, tool, original, pin, subject, tenant, client_id, inner_task_id, expires)` into a domain-separated HMAC-SHA256 handle (`tkt1.<payload>.<mac>`) using `server.request_state_key_file`, replacing `taskId` before responding to the client.
- On `tasks/get`, `tasks/update`, and `tasks/cancel`:
  - The gateway authenticates the caller (JWT/introspection + DPoP), verifies the `tkt1.` HMAC and expiration, and enforces exact `(subject, tenant, client_id)` equality. Foreign, tampered, or expired handles are rejected with JSON-RPC `-32602` without contacting any upstream.
  - Rate limits, audit `intent`/`outcome` records, and OTel spans are applied per task method.
  - The gateway unseals `inner_task_id`, forwards the JSON-RPC call to the owning upstream, rewrites `taskId` back to the sealed handle in the response, and stamps `_meta["tollkeeper.provenance"]` onto completed task results when `server.stamp_provenance: true`.

## Alternatives considered

- **Storing `taskId -> (upstream, owner)` in Redis or SQLite:** Adds mandatory stateful infrastructure and cleanup lifecycle. HMAC-sealed handles provide instant horizontal scaling across replicas sharing `server.request_state_key_file` with zero storage overhead.
- **Unconditionally enabling tasks:** Keeping `server.tasks_enabled` opt-in (`false` by default) preserves strict backwards compatibility for deployments that do not use long-running tasks.

## Consequences

- Multi-upstream deployments gain full SEP-2663 async task support with cryptographic owner/tenant isolation, auditability, rate limiting, and provenance stamping — with zero gateway state.
- Multi-replica deployments must share `server.request_state_key_file` so follow-up `tasks/get`, `tasks/update`, and `tasks/cancel` calls can land on any replica.

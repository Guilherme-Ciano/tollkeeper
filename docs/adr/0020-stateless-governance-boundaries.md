# ADR 0020: Deliberate Stateless Data-Plane Boundaries and Stateless Governance Primitives

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

As `tollkeeper` matures past v1.5 (OAuth 2.1, DPoP, RFC 8693 Token Exchange, RFC 9470 Step-Up, tenant-scoped CEL, stdio sandboxing, KMS checkpoint signing, SIEM export, and the embedded Admin Console), security reviews naturally raise a foundational architectural question:

Should `tollkeeper` remain a **stateless, sub-millisecond MCP security gateway**, or evolve into a **stateful Agent Security Runtime** tracking multi-turn conversation histories, cross-tool taint graphs, LLM-based payload inspection, and server-side workflow approval queues?

Turning the gateway into a stateful runtime carries steep operational costs:

- Mandatory shared session state on the hot path turns every replica into a latency- and availability-coupled component, eroding the measured `0.36 ms` p50 overhead and stateless failover guarantees ([ADR 0006](0006-stateless-transport-and-namespacing.md)).
- Running LLM classifiers inline in the data plane introduces non-determinism, prompt-injection amplification, external model dependencies, and 100–1000× latency regressions.
- Storing mutable operational state (pending approvals, live UI config edits) expands the gateway's attack surface and breaks GitOps auditability.

At the same time, many high-value governance controls—impact limits, argument-bound human approvals, data classification/provenance signals, and multi-replica configuration consistency—**can be enforced deterministically and statelessly** using cryptographic capabilities and static metadata.

## Decision

Keep the `tollkeeper` data plane **deliberately stateless, deterministic, and LLM-free**, while extending its enforcement capabilities with stateless governance primitives:

1. **In scope for `tollkeeper` (deterministic, stateless or bounded-cache primitives):**
   - **Per-call cryptographic identity & delegation:** OAuth 2.1 JWT/introspection, RFC 9449 DPoP (`cnf.jkt` + `jti` replay cache), RFC 8693 downscoped Token Exchange with `act` chains, and RFC 9470 Step-Up authentication.
   - **Per-call & impact-weighted admission:** default-deny CEL policies (global and tenant-scoped), static tool/upstream metadata (`trust`, `classification`, `egress`, `impact`), cost-based GCRA limits (`cost_expr` over `args`), and short-window idempotency / anti-replay guards.
   - **Stateless Human-in-the-Loop (HITL) approvals:** argument-bound signed capability tokens (`SHA-256(sub + tenant + tool + canonical_args)`, short TTL, approver identity, `jti` replay protection) verified in microseconds without an internal approval database.
   - **Deterministic provenance stamping:** stamping upstream/tool `trust`, `classification`, and `pin_hash` into MCP response `_meta` so downstream Agent Runtimes can enforce cross-tool information flow control on trusted metadata.
   - **Cryptographic supply-chain & replica integrity:** tool pinning lockfiles, Ed25519-signed config+pin bundles, fail-closed stdio sandboxing, SSRF `netguard`, and offline-verifiable hash-chained audit logs (local, Postgres, Rekor v2, KMS, SIEM/OTLP).
   - **Read-only embedded Admin Console:** inspection, CEL validation, diff review, and dry-run simulation without remote state mutation.

2. **Explicitly out of scope for `tollkeeper` (owned by the Agent Runtime / orchestrator):**
   - Multi-turn session memory, cross-tool taint graph tracking across separate MCP requests, and conversation-level prompt-injection defenses inside LLM context windows.
   - Semantic inspection of arbitrary natural-language tool outputs via secondary LLMs.
   - Internal database/filesystem transaction rollbacks inside upstream MCP servers whose tool contracts do not expose structured scope parameters.

## Alternatives considered

- **Stateful session taint engine inside the gateway:** Provides cross-tool flow rules directly in the proxy, but requires trusted session correlation, mandatory distributed state for every call, and complicates horizontal failover. Better implemented in the Agent Runtime consuming `tollkeeper`'s provenance metadata.
- **Inline LLM guardrail proxy:** Nondeterministic, high-latency, incompatible with air-gapped single-binary deployment.

## Consequences

- `tollkeeper` preserves its single static `CGO_ENABLED=0` binary, sub-millisecond p50 fast path, deterministic failure modes, and clean separation of duties.
- Security teams and auditors have an explicit, testable contract in [docs/threat-model.md](../threat-model.md) defining exactly what the gateway proves and what remains the Agent Runtime's responsibility.
- The `v1.6` roadmap delivers maximum enterprise governance (provenance metadata & stamps, cost-based GCRA impact limits, idempotency guard, stateless argument-bound HITL approval tokens, and signed config+pin bundles) without compromising statelessness.

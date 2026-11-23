# ADR 0018: Native SIEM Audit Sink, Reusable Policy Library, and Agent Integrations

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Enterprise security teams adopting `tollkeeper` face three recurring integration friction points:

1. **SIEM ingestion:** While `audit.otlp` ships records to OpenTelemetry collectors, many SOC pipelines expect direct HTTP ingestion in Splunk HEC, CEF (ArcSight / Microsoft Sentinel / QRadar), or newline-delimited JSON without deploying an extra collector hop.
2. **Policy cold start:** Writing CEL policies from scratch for common enterprise controls (read-only defaults, RFC 9470 step-up on destructive actions, coding-agent filesystem guardrails, multi-tenant isolation, and secret-exfiltration prevention) is slow and error-prone without tested templates.
3. **Agent platform onboarding:** Teams integrating coding agents (Claude Code, Cursor), orchestration frameworks (LangGraph, OpenAI Agents SDK, CrewAI), or user-facing agent UIs (AG-UI / CopilotKit) need idiomatic, copy-paste configurations showing Streamable HTTP auth, least-privilege tool visibility, and RFC 9470 step-up handling.

## Decision

### 1. Best-effort SIEM sink (`audit.siem`)

Add `internal/audit/siemsink`, mirroring the non-authoritative architecture of `internal/audit/otlpsink`:

- **Source of truth unchanged:** The local hash-chained `audit.jsonl` file (and optional Postgres mirror) remains authoritative. `audit.siem` attaches as a post-commit hook alongside `audit.otlp` (both can run simultaneously via fan-out).
- **Three wire formats:**
  - `json`: JSON array of enriched audit envelopes (`application/json`), carrying chain metadata, severity, and the exact committed `audit.Record`.
  - `splunk_hec`: Splunk HTTP Event Collector batches (`{"time":...,"host":service,"source":"tollkeeper","sourcetype":"tollkeeper:audit","event":<envelope>}`), with optional `index` and `sourcetype` overrides.
  - `cef`: Common Event Format (`CEF:0|Tollkeeper|MCPGateway|<version>|<class>|<method>|<sev>|ext`), escaping header pipes and extension delimiters (`=`, `\`, newlines) deterministically.
- **Hardened HTTP transport:** Uses `netguard` when `block_private_ips: true`, disables HTTP redirects (`netguard.NoRedirects`), requires `https://` unless `allow_insecure: true` or loopback, and never blocks or slows MCP admission (bounded queue with explicit drop counters in `mcpgw_audit_siem_records_total{result}`).

### 2. CI-verified reusable policy library (`policies/library/`)

Ship five production-ready policy packs, each paired with a `*_test.yaml` fixture suite verified on every CI run by `internal/cli/library_test.go` (`tollkeeper policy test`):

- `read-only-default.yaml`
- `destructive-step-up.yaml`
- `coding-agent-guardrails.yaml`
- `multi-tenant-isolation.yaml`
- `pii-and-secrets-guard.yaml`

### 3. Agent platform integrations (`examples/agents/`)

Provide self-contained examples for Claude Code, Cursor, LangGraph, OpenAI Agents SDK, CrewAI, and **AG-UI / CopilotKit**.

For AG-UI (`https://docs.ag-ui.com/introduction`), keep `tollkeeper` strictly scoped to MCP: the example demonstrates the complementary protocol stack where the frontend speaks AG-UI SSE to the agent backend, the agent speaks MCP Streamable HTTP to `tollkeeper`, and RFC 9470 `WWW-Authenticate` challenges from `tollkeeper` are translated by the agent backend into typed AG-UI `CUSTOM` (`tollkeeper.step_up_required`) human-in-the-loop events.

## Alternatives considered

- **Require OTel Collector for all SIEMs:** Adds an extra moving part and failure domain for teams already operating Splunk HEC or Sentinel/CEF HTTP collectors.
- **Embed AG-UI directly into the gateway:** Mixes Agent–User UI state and SSE run lifecycles into a stateless MCP security boundary, violating single responsibility and increasing attack surface.
- **Documentation-only policy snippets:** Snippets drift silently when CEL variables or schema fields evolve; shipping real YAML packs with `tollkeeper policy test` in CI guarantees they stay valid.

## Consequences

- Operators gain zero-collector SIEM shipping with SSRF protection, backpressure isolation, and Prometheus visibility (`mcpgw_audit_siem_records_total{result}`).
- Every policy pack in `policies/library/` is compiled and fixture-tested automatically on every PR.
- Zero new Go module dependencies are added; static `CGO_ENABLED=0` builds remain unaffected.

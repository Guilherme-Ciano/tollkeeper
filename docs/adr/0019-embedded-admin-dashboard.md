# ADR 0019: Embedded Single-Binary Admin Dashboard

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Operators and security engineers running `tollkeeper` rely on CLI commands (`policy explain`, `policy test`, `pin status`, `pin approve`, `audit verify`) and JSON/Prometheus endpoints (`/metrics`, `/pins`, `/upstreams`). While CLI workflows excel in CI/CD pipelines, day-to-day triage and policy authoring benefit enormously from an interactive browser console for:

- Monitoring live upstream readiness, circuit breakers, and rolling p50/p95 latencies.
- Authoring and compiling CEL policy rules visually with instant feedback before saving and sending `SIGHUP`.
- Inspecting side-by-side SHA-256 tool pin diffs and spotting hidden Unicode / control characters before approving tool updates.
- Simulating MCP calls (`tools/call`, `prompts/get`, `resources/read`) with arbitrary principals, tenants, DPoP states, and arguments—including RFC 9470 step-up challenges—against either the live policy or an unsaved draft.
- Searching and filtering recent hash-chained audit records alongside the continuous watchdog status.

At the same time, `tollkeeper` must remain a **single static `CGO_ENABLED=0` Go binary** with zero Node.js/npm build toolchain requirements, zero external CDN dependencies, and strict air-gapped security.

## Decision

Embed a zero-dependency vanilla HTML/CSS/JS single-page console inside `internal/adminui` via `//go:embed assets/*`, served at `/ui/` on the dedicated admin listener (`server.admin_listen`, default `127.0.0.1:9090`), backed by read-only and pure-simulation JSON APIs in `internal/app/admin_api.go` and `internal/app/admin_policy.go`:

- `GET /ui/` — embedded console with strict security headers (`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`).
- `GET /api/overview` — gateway readiness, auth/DPoP mode, policy/rate-limit summary, pinning counts, catalog totals, and audit watchdog status.
- `GET /api/policy` and `POST /api/policy/validate` — active policy DTO + YAML export, plus live structural validation (`config.ValidatePolicy`) and full CEL compilation (`policy.New`).
- `GET /api/pins` — current tool pinning report (`approved`, `new`, `changed`, canonical JSON definitions, SHA-256 hashes).
- `POST /api/simulate` — in-memory evaluation via `policy.Explain`, `policy.Visible`, and pin guard against either the live policy engine or a draft YAML payload, with zero upstream side effects.
- `GET /api/audit/events` — bounded reverse-tail reader (at most 2 MiB from EOF) over `audit.jsonl` with server-side filtering by `decision`, `phase`, `kind`, `tenant`, `sub`, `tool`, and full-text `q`.

### Security boundaries

1. **No remote mutations:** The dashboard never writes to the config file, lockfile, or disk. Policy changes are exported as validated YAML for version-controlled deployment (`SIGHUP` hot reload), and pin approvals provide copyable `tollkeeper pin approve <tool>` commands.
2. **Same access control as `/pins` and `/upstreams`:** When `server.admin_listen` is non-loopback and `pinning.report_token` is unset, both `/ui/` and `/api/*` return `404`. When `pinning.report_token` is configured, all `/api/*` endpoints require `Authorization: Bearer <token>` (returning `401` so the console prompts for the token in session memory).
3. **Zero external resources:** Strict `'self'`-only CSP guarantees no external fonts, scripts, telemetry, or inline script execution.

## Alternatives considered

- **Separate React/Vite frontend service:** Adds Node.js/npm build complexity, supply-chain surface, and a second deployment artifact.
- **Allowing live policy writes or pin approvals from HTTP:** Weakens GitOps/CLI operator review guarantees and expands the blast radius of an exposed admin token.

## Consequences

- Single-binary `CGO_ENABLED=0` builds stay self-contained with zero new Go or JS dependencies.
- Operators get immediate visual visibility into upstreams, CEL policies, tool pin diffs, call simulation, and audit chains on `http://127.0.0.1:9090/ui/`.

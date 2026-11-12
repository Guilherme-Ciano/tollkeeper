# tollkeeper

**A single Go binary between your agents and their MCP tools: OAuth 2.1 resource server, policy-as-code in CEL, GCRA rate limits, and an audit log you can cryptographically verify.**

![Go](https://img.shields.io/badge/go-1.27-333333) ![License](https://img.shields.io/badge/license-Apache--2.0-333333) ![MCP](https://img.shields.io/badge/MCP-2026--07--28-333333) ![go-sdk](https://img.shields.io/badge/go--sdk-v1.8.0-333333)

## Why

- Every MCP server you connect is a new door into your systems, and the spec now forbids the shortcut most proxies take: **forwarding the caller's token upstream** (the official Go proxy example forwards every inbound header, `Authorization` included). tollkeeper validates the token, then calls upstreams with its *own* credentials.
- "Who called which tool with what, and was it allowed?" is the question compliance teams ask. Most gateways answer it with logs anyone with database access can quietly rewrite. tollkeeper writes a **SHA-256 hash chain with Ed25519-signed checkpoints**, and `tollkeeper audit verify` names the exact record that was changed or deleted.
- Overhead is measured, not claimed: see [Benchmarks](#benchmarks).

## What it does

| Concern | How |
|---|---|
| Transport | Stateless Streamable HTTP for MCP `2026-07-28`, with fallback for `2025-11-25` clients (go-sdk v1.8.0) |
| Aggregation | N upstreams (stdio subprocesses and Streamable HTTP) under `upstream__tool` names, sorted and deterministic, re-synced on `list_changed` |
| Authentication | RFC 9728 protected-resource metadata, JWT via JWKS (`iss`, `aud` = canonical URI per RFC 8707, `exp`, algorithm allowlist), RFC 6750 challenges with `error=` and all required scopes |
| No passthrough | Upstream HTTP clients are built from config only and never see the inbound request; covered by tests |
| Authorization | First-match rules: static RBAC fast path plus optional CEL `when` over principal, tool annotations, arguments and time; default deny; `tools/list` filtered per caller; step-up challenges (`403 insufficient_scope`) |
| Rate limiting | GCRA, lock-free CAS on one `int64` per key, per subject / subject+tool / client / upstream / tool / global, all-or-nothing across rules, `429` + `Retry-After` + IETF `RateLimit` headers |
| Audit | Intent + outcome records, hashed arguments by default (GDPR data minimisation), batched fsync, Ed25519 checkpoints, chain continuity across restarts, `fail_closed` or `fail_open` with gap records |
| Request hygiene | Strict JSON-RPC envelope parsing that rejects batches, duplicate and case-variant keys (closing parser-differential policy bypasses), `Mcp-Method`/`Mcp-Name` header agreement (`-32020`), body cap |
| Observability | OTel traces with W3C context from headers or `_meta` (SEP-414), Prometheus metrics including `mcpgw_gateway_overhead_seconds` |
| Dev tooling | Built-in **DEV ONLY** OAuth issuer (client_credentials, authorization_code + PKCE S256, RFC 9207 `iss`), three demo MCP servers, a demo client and a benchmark harness, all in Go |

## Architecture

```mermaid
flowchart LR
  C[MCP client / agent] -->|Bearer JWT| IN
  subgraph gw [tollkeeper, single binary]
    IN[HTTP ingress] --> AUTH[bearer + JWKS]
    AUTH --> ADM[admission: envelope, headers, GCRA, CEL]
    ADM --> MCP[go-sdk stateless server + backstop]
    MCP --> CAT[(catalog snapshot)]
    MCP --> UM[upstream manager]
    ADM --> AUD[audit sequencer]
    MCP --> AUD
  end
  UM -->|stdio, env allowlist| N[notes]
  UM -->|streamable HTTP| W[weather]
  UM -->|streamable HTTP + own client_credentials| F[files]
  AUTH -.JWKS.-> AS[OAuth AS / dev issuer]
  AUD --> L[(audit.jsonl + Ed25519 checkpoints)]
```

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant G as tollkeeper
    participant P as Policy (CEL)
    participant L as Audit
    participant U as Upstream
    C->>G: POST /mcp tools/call notes__search (Bearer, Mcp-Method, Mcp-Name)
    G->>G: verify JWT (iss, aud, exp, alg), strict envelope, header == body
    G->>G: GCRA take (all rules or none)
    G->>P: decide(principal, tool, annotations, args, now)
    P-->>G: allow | deny | step_up(scopes)
    G->>L: intent record (deny the call if the audit buffer is full)
    G->>U: tools/call search (gateway credentials, traceparent in _meta)
    U-->>G: result
    G->>L: outcome record (result hash, latency, upstream time)
    G-->>C: result
```

The admission step runs at the HTTP layer so it can answer with real status codes (`401`, `403` step-up, `429`). The go-sdk middleware then acts as a backstop: a `tools/call` without a matching admission never reaches an upstream.

## Quickstart

Requires Docker (or rootless Podman exposing its Docker socket) and Go 1.27 for the demo client.

```bash
git clone https://github.com/Guilherme-Ciano/tollkeeper && cd tollkeeper
```

```bash
docker compose up --build -d --wait
```

```bash
go run ./cmd/democlient
```

This is the real output of that command against the compose stack:

```text
1. alice (reader) logs in with authorization_code + PKCE
  logged in as alice, granted scope "mcp:tools"
2. tools visible to alice (8):
   - files__delete_file
   - files__list_files
   - files__read_file
   - notes__create
   - notes__get
   - notes__search
   - weather__forecast
   - weather__slow_forecast
3. notes__search (stdio upstream) -> {"notes":[{"body":"Hash-chained audit log with Ed25519 checkpoints.","id":"1","title":"Gateway design"}]}
4. files__list_files (OAuth-protected upstream, gateway uses its own client_credentials) -> {"files":["/docs/readme.md","/tmp/old.log","/tmp/scratch.txt"]}
5. alice calls files__delete_file -> HTTP 403
   WWW-Authenticate: Bearer error="insufficient_scope", error_description="additional scope required", resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp", scope="mcp:tools files:write"
   {"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"insufficient scope","data":{"required_scopes":["files:write"],"rule":"destructive-needs-step-up"}}}
6. bob steps up with files:write
  logged in as bob, granted scope "mcp:tools files:write"
   bob calls files__delete_file -> HTTP 200 {"jsonrpc":"2.0","id":1,"result":{...,"structuredContent":{"deleted":"/tmp/old.log"},"resultType":"complete"}}
7. alice bursts weather__forecast
   call 1 -> HTTP 200
   ...
   call 5 -> HTTP 200
   call 6 -> HTTP 429 Retry-After=2 "weather-per-subject";r=0;t=10
```

Verify the audit chain inside the container, then tamper with a copy:

```bash
docker compose exec gateway /usr/local/bin/tollkeeper audit verify -f /var/log/tollkeeper/audit.jsonl --pubkey /var/lib/tollkeeper/keys/audit-ed25519.pub
```

```text
OK chain=compose-gateway records=21 events=20 checkpoints=1 last_seq=21 last_hash=32f7a79a…
```

After changing `"sub":"bob"` to `"sub":"eve"` on one line, or deleting one line:

```text
FAIL line 7 (seq 7): hash mismatch: record content was modified after 6 valid records
FAIL line 9 (seq 10): sequence gap: expected seq 9 after 8 valid records
```

## CLI

| Command | Purpose |
|---|---|
| `tollkeeper serve -c config.yaml` | Run the gateway |
| `tollkeeper config validate -c config.yaml` | Validate config, compile CEL rules and rate limits, report every bad field with its path |
| `tollkeeper policy test -c config.yaml -f policies_test.yaml` | Table-driven policy fixtures for CI ([example](deploy/compose/policies_test.yaml)) |
| `tollkeeper audit verify -f audit.jsonl --pubkey audit.pub` | Recompute the chain, check signatures, report the first broken record |
| `tollkeeper audit keygen -o dir` | Ed25519 checkpoint key pair |
| `tollkeeper dev-issuer -c devissuer.yaml` | DEV ONLY OAuth issuer (refuses non-loopback binds without `--i-know-this-is-insecure`) |
| `tollkeeper healthcheck --url …` | Probe for distroless container healthchecks |

## Configuration

YAML with `${ENV}` expansion (missing or multi-line values are rejected) and an env overlay (`TOLLKEEPER_SERVER__LISTEN=:8081`). Unknown keys are errors. A complete example is [deploy/compose/gateway.yaml](deploy/compose/gateway.yaml).

```yaml
policy:
  default: deny
  rules:
    - name: readers-can-read
      subjects: { scopes_any: ["mcp:tools"] }
      tools: ["notes__search", "weather__*"]
      effect: allow
    - name: notes-create-capped
      subjects: { scopes_any: ["mcp:tools"] }
      tools: ["notes__create"]
      when: "has(args.body) && size(args.body) <= 4096"
      effect: allow
    - name: destructive-needs-step-up
      tools: ["files__delete_file"]
      when: '"files:write" in principal.scopes'
      effect: allow
      on_deny: { step_up_scopes: ["files:write"] }
```

| Key | Default | Notes |
|---|---|---|
| `server.listen` / `admin_listen` | `:8080` / `:9090` | Admin serves `/metrics`, `/livez`, `/readyz` |
| `server.public_url` | required | Canonical MCP URL; also the RFC 9728 metadata path |
| `server.max_body_bytes` | 1 MiB | Enforced before parsing |
| `auth.mode` | `jwt` | `none` exists for local experiments and logs a warning |
| `auth.jwt.algorithms` | RS256, ES256, EdDSA | HS* and `none` are never accepted |
| `upstreams[].transport` | | `stdio` (explicit env allowlist, process-group kill) or `streamable_http` |
| `upstreams[].auth.type` | `none` | `bearer` or `client_credentials` with RFC 8707 `resource` |
| `rate_limits.rules[].per` | | `subject`, `subject_tool`, `client_id`, `upstream`, `tool`, `global` |
| `audit.record_args` | `hash` | `none`, `hash`, `full` (raw arguments may be personal data) |
| `audit.on_backpressure` | `fail_closed` | Calls are refused if their intent record cannot be queued |

CEL variables: `principal{sub, client_id, scopes, claims}`, `tool{name, upstream, original, pin_hash, annotations}`, `args`, `request{method, client_name}`, `now`. Programs are compiled at load time with a cost limit and a 2 ms evaluation timeout, and arguments are only decoded when a rule references `args`.

## Benchmarks

<!-- bench:start -->
Benchmarks are being re-run on a quiet machine; see `bench/results` for the committed raw numbers.
<!-- bench:end -->

Reproduce with `make bench` (micro-benchmarks, `-count=10`) and `make bench-e2e` (gateway vs. direct at constant arrival rates; methodology in [bench/README.md](bench/README.md)).

## Security model

| Threat | Mitigation |
|---|---|
| Token from another resource replayed here | `aud` must equal the canonical URI, `iss` pinned, algorithm allowlist, `exp` required |
| Token passthrough / confused deputy | Upstream clients have no access to inbound requests; per-upstream credentials; policy runs before every upstream call |
| Header/body or parser-differential bypass | Strict case-sensitive envelope parser rejects duplicate and case-variant keys (also inside `arguments`); `Mcp-Method`/`Mcp-Name` must match the body; MCP-layer backstop re-checks the admitted tool name |
| Cross-server tool shadowing | Mandatory `upstream__tool` namespacing; upstream IDs cannot contain `_`, tool names cannot contain the separator |
| Malicious upstream tool definitions | Tools with invalid schemas are quarantined instead of crashing the server (go-sdk `AddTool` panics); pin hashes recorded per call |
| Audit tampering | Hash chain + Ed25519 checkpoints that are themselves chain records; verifier rejects unknown fields |
| Secret leakage to stdio servers | Subprocesses get an explicit env allowlist, never the gateway's environment (tested) |
| DoS | Body cap, CEL cost limit and timeout, per-upstream semaphores, timeouts and circuit breakers, rate limits, rate-limited JWKS refetch on unknown `kid` |

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Known limitations (v0.1)

- **Tools only.** Resources and prompts are not aggregated yet; go-sdk has no dynamic `resources/list` handler ([go-sdk#998](https://github.com/modelcontextprotocol/go-sdk/issues/998)).
- **Progress notifications are not forwarded**, and if they were, go-sdk may deliver them after the result ([go-sdk#1337](https://github.com/modelcontextprotocol/go-sdk/issues/1337)).
- **MRTR `requestState` is passed through, not yet sealed**; tool names still route retries, so a client cannot redirect a retry to another upstream by name.
- **Tool pinning** computes and records hashes but does not enforce approval yet.
- **In-memory rate limits only**; limits are per replica. One audit chain per replica (`chain_id`).
- Upstream results pass through unchanged, including the upstream's `_meta` server info.
- Truncating the newest records after the last checkpoint is not detectable without external anchoring.

## Roadmap

- [x] v0.1: everything above, compose demo, fuzzing, published overhead numbers
- [ ] v0.2: Redis GCRA store with a shared conformance suite, Postgres audit sink with immutable triggers, OTLP log sink, RFC 7662 introspection, pin enforcement and `pin approve`, sealed MRTR state, progress forwarding, resources/prompts, hot reload
- [ ] v1.0: RFC 8693 token exchange to upstreams, DPoP, external checkpoint anchoring, Helm chart, MCP conformance suite in CI

## Development

```bash
make lint test build
```

The codebase has **zero code comments** (only `//go:` directives), enforced by `go run ./internal/tools/nocomments` in `make lint` and CI. Names and tests carry the intent; design rationale lives in [docs/adr](docs/adr). See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0

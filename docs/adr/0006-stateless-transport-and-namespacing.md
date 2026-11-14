# ADR 0006: Stateless Streamable HTTP and `upstream__tool` namespacing

## Status

Accepted, v0.1.

## Context

MCP revision `2026-07-28` removed sessions and the `initialize` handshake from Streamable HTTP. Clients released before it still speak `2025-11-25`. The gateway aggregates many upstreams whose tool names can collide, and a malicious upstream could publish a tool named like another server's tool to intercept calls.

## Decision

- Serve the go-sdk stateless handler, with a fallback for `2025-11-25` clients. No session state means any replica can serve any request.
- Expose every upstream tool as `<upstream>__<tool>`. The separator must contain a character that upstream identifiers cannot, and the catalog refuses a qualified name that another upstream already owns.
- The catalog is an immutable snapshot swapped atomically on re-sync (upstream `list_changed` or a 60 s poll), so readers never lock.
- `tools/list` is filtered per caller, and unknown tools get the same response as policy denials.

## Alternatives considered

- **Stateful sessions with session-id mapping.** Required for old clients' server-initiated requests, but it pins clients to replicas and doubles the state to secure.
- **`.` or `/` as separator.** Allowed by the spec, but several clients mishandle them.

## Consequences

- Server-initiated sampling and elicitation for legacy clients are not supported.
- Tool names are longer, and clients see which upstream owns each tool, which helps users judge trust.

# ADR 0005: Never pass the caller's token to upstreams

## Status

Accepted, v0.1.

## Context

The MCP authorization specification forbids token passthrough: a server must not forward the token it received to another service. Passing it through creates a confused deputy, lets upstreams replay a token minted for the gateway, and makes the audit trail meaningless because the upstream cannot tell the gateway's decision from the caller's own request. The go-sdk proxy example forwards every inbound header, `Authorization` included.

## Decision

- Upstream HTTP clients are built from configuration only. They have no reference to the inbound request, its headers or its context values.
- Each upstream authenticates with the gateway's own credentials: none, a static bearer bound to the upstream host, or OAuth `client_credentials`.
- Upstream, token and JWKS clients never follow redirects, so a credential cannot leak to another host.
- stdio upstreams receive an explicit environment allowlist, never the gateway's environment.
- Tests assert that no inbound `Authorization` value reaches any upstream.

## Alternatives considered

- **Passthrough.** Rejected by the spec.
- **RFC 8693 token exchange.** The right answer when upstreams need the end user's identity. Planned for v1.0, because it requires an authorization server that supports exchange and per-upstream audiences.

## Consequences

- Upstreams see the gateway as the caller. User identity reaches upstreams only through the audit log and trace context until token exchange lands.
- Compromise of an upstream does not expose callers' tokens.

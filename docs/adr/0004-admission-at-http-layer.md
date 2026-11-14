# ADR 0004: Admission at the HTTP layer, go-sdk middleware as backstop

## Status

Accepted, v0.1.

## Context

Authentication, rate limiting and authorization failures must reach the client as real HTTP semantics: `401` with a `WWW-Authenticate` challenge, `403 insufficient_scope` for step-up, `429` with `Retry-After`. The go-sdk server middleware runs after the JSON-RPC message is decoded, where it can only return JSON-RPC errors inside a `200`.

## Decision

- An HTTP handler in front of the go-sdk server parses the JSON-RPC envelope strictly, checks that `Mcp-Method` and `Mcp-Name` agree with the body, verifies the bearer token, applies rate limits and evaluates policy. It records the admission decision in the request context.
- The go-sdk middleware re-checks that every `tools/call` it sees carries an admission for the same tool name. A call without one never reaches an upstream.
- The strict parser rejects batches, duplicate keys and Unicode case-folded duplicate keys at any depth of `arguments`.

## Alternatives considered

- **Only go-sdk middleware.** Simpler, but loses status codes and lets the SDK decode bodies before any authentication.
- **Only the HTTP layer.** Fast, but a future SDK code path that dispatches a call by another route would bypass policy silently.

## Consequences

- The body is parsed twice, once by tollkeeper and once by go-sdk. The CPU profile shows tollkeeper's own envelope parse at about 3% of CPU; most of the cost is the SDK's own repeated decoding.
- Two parsers on the same bytes is a classic parser-differential risk. That is why the envelope parser rejects anything the SDK might read differently, and why fuzz targets cover it.

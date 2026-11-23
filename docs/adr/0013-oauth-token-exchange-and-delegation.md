# ADR 0013: OAuth 2.0 Token Exchange (RFC 8693) and controlled delegation

## Context

[ADR 0005](0005-no-token-passthrough.md) forbids forwarding the caller's access token to upstream MCP servers so a compromised upstream cannot replay a broad caller token against other APIs. Previously, `streamable_http` upstreams could only authenticate with a static `bearer` token or service-level `client_credentials`, which prevented upstreams from enforcing per-user row-level authorization or auditing the human user behind an agent call.

## Decision

1. **Upstream `auth.type: token_exchange` (RFC 8693):** For `streamable_http` upstreams, tollkeeper exchanges the caller's verified inbound token at the configured Authorization Server (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) for a narrowly scoped, audience/resource-bound downstream token minted exclusively for that upstream.
2. **Strict boundary against token passthrough:** The inbound raw token is carried only in an isolated request-context carrier (`identity.WithSubjectToken`) and never stored on `identity.Principal` (preventing accidental logging or CEL exposure). `tokenExchangeTransport` sends the subject token only to `auth.token_url`, enforces host pinning on the upstream (`ErrForeignHost`), and never attaches the caller's inbound token to any upstream request.
3. **Least-privilege scope intersection and delegation controls:**
   - Every `token_exchange` upstream must specify `resource` or `token_exchange.audience`.
   - Setting `intersect_caller_scopes: true` intersects `auth.scopes` with the caller's verified scopes and fails closed (`ErrDelegationDenied`) if the intersection is empty, preventing privilege escalation.
   - `max_delegation_depth` and `allowed_issuers` restrict how deeply chained `act` tokens or which issuers may be exchanged; delegation denials are classified as client faults so one unauthorized caller never trips the upstream circuit breaker.
   - Exchanges are cached in a bounded per-`(subject_token_hash, effective_scopes)` table with `singleflight` deduplication and a 30-second expiry safety skew.
   - Background MCP session initialization and catalog discovery (where no human caller is present) use `client_credentials` with optional `discovery_scopes`, while authenticated user calls fail closed if no subject token is present.
4. **First-class `act` chain and `tenant` attribution:** Both JWT verification and RFC 7662 introspection parse nested RFC 8693 `act` claims (capped at depth 8) and standard tenant claims (`tenant_id`, `tid`, `org_id`). Policy rules can match `subjects.actors` globs or inspect `principal.delegated`, `principal.actor.{sub,client_id,iss,depth,chain}` and `principal.tenant` in CEL. Every audit event records `act` and `tenant`.

## Alternatives considered

- **Forwarding the caller's bearer token directly:** Violates [ADR 0005](0005-no-token-passthrough.md) and MCP security guidance, turning every upstream server into a confused deputy.
- **Custom unsigned identity headers (`X-User-Sub`):** Easy to spoof if an upstream is reachable outside the gateway mesh and incompatible with standard OAuth 2.0 resource servers.

## Consequences

- Upstreams receive standard, short-lived, audience-pinned OAuth access tokens scoped to the exact caller and downstream resource without ever seeing the gateway's inbound token.
- Audit chains capture both the human subject (`sub`), tenant (`tenant`), and agent delegation chain (`act`) in tamper-evident records.
- Token exchange adds one Authorization Server round-trip per `(caller token, upstream, effective scopes)` until cached.

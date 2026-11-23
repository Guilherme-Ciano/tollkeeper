# ADR 0014: Sender-constrained tokens with DPoP (RFC 9449) and enterprise IdP integration

## Context

Bearer access tokens can be replayed from any machine if intercepted in transit, logs or agent tool output. RFC 9449 (OAuth 2.0 Demonstrating Proof of Possession — DPoP) binds an access token to a client-held asymmetric key pair via the `cnf.jkt` thumbprint and a per-request signed `DPoP` proof JWT.

Additionally, enterprise deployments use heterogeneous identity providers (Microsoft Entra ID, Okta, Keycloak, Auth0) that place tenant identifiers, roles, groups, client IDs and scopes in different claim paths (including nested paths such as Keycloak's `realm_access.roles`) and publish key material via OIDC Discovery (`/.well-known/openid-configuration`) rather than hardcoded JWKS URLs.

## Decision

1. **RFC 9449 DPoP verification (`auth.dpop`):**
   - Supports `mode: off | optional | required`.
   - Verifies `DPoP` proof JWTs (`typ: dpop+jwt`, strict asymmetric algorithm allowlist, embedded public JWK with private/symmetric parameters rejected, RFC 7638 thumbprint matching `cnf.jkt`, exact `htm`, canonical `htu`, bounded `iat` freshness, constant-time `ath` hash of the access token, and bounded `jti` replay cache).
   - Rejects Bearer downgrade: in `optional` mode, any token carrying `cnf.jkt` must be presented with `Authorization: DPoP` and a valid proof.
   - Optional stateless HMAC-SHA256 rotating `DPoP-Nonce` (`nonce_required: true`) issues `401` with `DPoP-Nonce` and `WWW-Authenticate: DPoP error="use_dpop_nonce"`, using `server.request_state_key_file` across replicas when configured.
   - Advertises `dpop_signing_alg_values_supported` and `dpop_bound_access_tokens_required` in RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`).
2. **Enterprise IdP presets and dot-path claim mapping (`auth.provider`, `auth.claims`):**
   - Built-in presets for `entra`, `okta`, `keycloak` and `auth0`, overridable per claim via `auth.claims.{tenant,groups,roles,client_id,scope}`.
   - Normalizes `roles`, `groups`, `acr`, `amr`, `auth_time`, `dpop` and `jkt` onto `identity.Principal` and exposes them in CEL (`principal.roles`, `principal.groups`, `principal.dpop`, `principal.jkt`, `principal.acr`, `principal.amr`) for both JWT and RFC 7662 introspection modes.
3. **OIDC / RFC 8414 metadata discovery:**
   - When `auth.mode: jwt` omits `auth.jwt.jwks_url`, tollkeeper fetches `/.well-known/openid-configuration` (falling back to `/.well-known/oauth-authorization-server`), enforces exact `issuer` equality to prevent mix-up attacks, requires HTTPS unless `allow_insecure_jwks: true`, and refuses HTTP redirects.

## Alternatives considered

- **mTLS certificate-bound tokens (RFC 8705) only:** Requires terminating client TLS directly at the gateway or propagating verified client cert headers from every L7 proxy, which complicates Kubernetes ingress setups. DPoP works end-to-end across standard HTTP proxies at the application layer.
- **Provider-specific SDKs:** Pulls heavy dependencies for simple JSON claim differences. Declarative presets with dot-path extraction keep the binary small and work identically with custom IdPs.

## Consequences

- Clients supporting RFC 9449 gain cryptographic sender-constraining and replay protection on every MCP call without infrastructure TLS changes.
- Enterprise configs for Entra ID, Okta, Keycloak and Auth0 become concise and resilient to JWKS URI rotation via OIDC discovery.
- Replay detection (`jti` cache) is process-local; when running multiple replicas, enable `nonce_required: true` with a shared `server.request_state_key_file` to bound proof validity windows consistently across replicas.

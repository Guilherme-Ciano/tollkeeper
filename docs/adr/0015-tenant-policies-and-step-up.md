# ADR 0015: Tenant-scoped policies, per-tenant rate limits, and RFC 9470 step-up authentication

## Context

In multi-tenant deployments, writing every tenant's authorization rules inside one flat `policy.rules` list makes accidental cross-tenant leakage easy: a broad global `allow` rule can inadvertently grant access to a tenant that expected stricter rules, and a single tenant bursting requests can exhaust shared subject or tool rate limits.

Similarly, basic scope step-up (`on_deny.step_up_scopes`) cannot require stronger authentication context (such as phishing-resistant MFA via `acr` or recent re-authentication via `auth_time`) or per-tool DPoP enforcement without forcing every caller on every tool to meet the highest bar.

## Decision

1. **Isolated tenant policies (`policy.tenants.<tenant_id>`):**
   - Each tenant may declare its own `default` effect and `rules` slice under `policy.tenants`.
   - When `principal.Tenant` matches an entry in `policy.tenants`, `Decide`, `Explain` and `VisibleAs` evaluate strictly against that tenant's rule set and default effect; global `policy.rules` never fall through into a tenant with an isolated policy.
   - Declarative matchers `subjects.tenants`, `subjects.roles_any` and `subjects.groups_any` simplify multi-tenant and RBAC rules without requiring CEL boilerplate.
   - Tenant policies compile at load time and swap atomically on `SIGHUP` reload.
2. **Per-tenant GCRA rate limiting (`per: tenant`, `per: tenant_tool`):**
   - Extends `ratelimit.Subject` with `Tenant` and adds `tenant` and `tenant_tool` dimensions across both in-memory and Redis GCRA backends.
3. **RFC 9470 step-up authentication (`on_deny.{acr_values, max_age, require_dpop}`):**
   - Extends `on_deny` on `allow` rules with `acr_values`, `max_age` (checked against `auth_time`, also exposed in CEL as `principal.auth_age_seconds`) and `require_dpop`.
   - When `acr_values` or `max_age` is unsatisfied, the gateway returns `401 Unauthorized` with an RFC 9470 `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="...", max_age=...` challenge plus structured JSON-RPC error `data`.
   - When `require_dpop` is unsatisfied, the gateway returns `401 Unauthorized` with a `WWW-Authenticate: DPoP` challenge.
   - Scope-only step-up (`step_up_scopes`) continues to return `403 Forbidden` with `insufficient_scope` for full backward compatibility.

## Alternatives considered

- **Evaluating global rules before or after tenant rules:** Makes it hard to reason about precedence and risks silently granting access via a global rule to a tenant that opted into strict isolation. Complete per-tenant scope isolation is simpler and safer.
- **Requiring CEL expressions for every step-up check:** Forces operators to duplicate `auth_time` arithmetic and `acr` comparisons across rules and still cannot emit RFC 9470 `acr_values` and `max_age` header parameters automatically.

## Consequences

- Multi-tenant operators can onboard tenants with strict rule and rate-limit isolation in one gateway deployment, with zero-downtime `SIGHUP` reloads and full `policy test` fixture coverage.
- High-risk tools (destructive mutations, financial approvals, secret reads) can require phishing-resistant MFA, fresh login timestamps, or DPoP binding per rule while keeping read-only tools low-friction.

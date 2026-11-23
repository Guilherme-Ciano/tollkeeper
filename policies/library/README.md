# Reusable Policy Library

Ready-to-adopt policy packs validated on every CI build with `tollkeeper policy test`.

| Pack | Purpose | Test command |
|---|---|---|
| [read-only-default.yaml](read-only-default.yaml) | Allow only tools annotated `readOnlyHint: true` and deny destructive actions by default | `tollkeeper policy test -c read-only-default.yaml -f read-only-default_test.yaml` |
| [destructive-step-up.yaml](destructive-step-up.yaml) | Require fresh phishing-resistant MFA (`acr_values: ["phr"]`, `max_age: 5m`) and approval scope on destructive tools (RFC 9470) | `tollkeeper policy test -c destructive-step-up.yaml -f destructive-step-up_test.yaml` |
| [coding-agent-guardrails.yaml](coding-agent-guardrails.yaml) | Block `.env`, `.git/`, `/etc/` and path traversal (`..`), cap delegation depth, and gate writes by scope | `tollkeeper policy test -c coding-agent-guardrails.yaml -f coding-agent-guardrails_test.yaml` |
| [multi-tenant-isolation.yaml](multi-tenant-isolation.yaml) | Isolated `policy.tenants.<id>` scopes with role matchers, DPoP requirements and per-tenant GCRA limits | `tollkeeper policy test -c multi-tenant-isolation.yaml -f multi-tenant-isolation_test.yaml` |
| [pii-and-secrets-guard.yaml](pii-and-secrets-guard.yaml) | Block secret/key leakage in tool arguments and enforce DPoP on secret access | `tollkeeper policy test -c pii-and-secrets-guard.yaml -f pii-and-secrets-guard_test.yaml` |

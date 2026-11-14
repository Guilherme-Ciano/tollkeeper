# ADR 0002: CEL for authorization policy

## Status

Accepted, v0.1.

## Context

Every `tools/call` needs an allow, deny or step-up decision based on the caller, the tool, its annotations, its arguments and the time. The decision sits on the hot path of every call, so it must be fast, bounded and safe to evaluate on attacker-controlled input. Policy authors are platform and security engineers, not Go developers.

## Decision

- Rules are evaluated first-match. Each rule has a static RBAC part (subjects, scopes, tool globs) and an optional CEL `when` expression.
- CEL (`github.com/google/cel-go`) runs in process. Expressions are compiled and type-checked once at load time against a fixed environment (`principal`, `tool`, `annotations`, `args`, `now`).
- Every program has a cost limit and an evaluation timeout. A rule that fails to compile stops startup; a rule that errors at runtime denies.
- The default is deny, and `tollkeeper policy test` evaluates fixtures in CI.

## Alternatives considered

- **OPA/Rego.** The standard for infrastructure policy, but it means either a sidecar (a network hop and a second process to secure) or embedding a large engine. Rego's partial evaluation and data documents are more power than a per-call allow/deny needs.
- **Cedar.** Excellent semantics and analyzability, but the Go implementation is younger and the entity model is heavier than tool calls require.
- **Hand-written Go predicates.** Fastest, but every policy change becomes a code change and a release.

## Consequences

- RBAC-only rules cost about 100 ns; a CEL rule costs 4.2 µs, 6.3 µs with argument access (see [Benchmarks](../../README.md#benchmarks)).
- cel-go pulls in protobuf and ANTLR, which adds roughly 8 to 10 MB to the binary and makes compilation memory-heavy.
- CEL is non-Turing-complete and side-effect free, so a policy cannot loop forever or call out to the network.

# ADR 0008: Zero code comments

## Status

Accepted, v0.1.

## Context

Comments drift from the code they describe, and in a security-sensitive codebase a stale comment is worse than none because reviewers trust it. Go's conventions encourage doc comments on every exported identifier, and linters such as `revive` and `godot` enforce them.

## Decision

- Go files contain no comments. The only exceptions are compiler directives (`//go:build`, `//go:embed`) and generated-code headers.
- Intent lives in names, small functions, types that make invalid states unrepresentable, and table-driven tests whose case names read as specifications.
- Rationale that does not fit a name lives here, in ADRs, where it is reviewed as a decision rather than buried next to a line that will change.
- `internal/tools/nocomments` enforces the rule in `make lint` and CI. Linters that demand comments are disabled.

## Alternatives considered

- **Doc comments on exported identifiers only.** The conventional middle ground. Rejected because almost everything is under `internal/`; there is no public API for godoc to serve, so doc comments would mostly restate names.
- **No rule.** Comments accumulate unevenly and nobody enforces their accuracy.

## Consequences

- pkg.go.dev shows no package documentation. If a public `pkg/` API is ever added, this ADR should be revisited for that package only.
- The rule pushes complexity into tests and ADRs, which makes both mandatory rather than optional.
- Some readers will see it as unusual. The answer is this document: the trade-off is deliberate, enforced and limited to code.

# Contributing

## Prerequisites

Go 1.27, golangci-lint v2.15.0, Docker or Podman for the compose demo.

## Workflow

```bash
make lint test build
```

- **No code comments.** Only `//go:` directives and generated-code headers are allowed, and `//nolint` is not. `go run ./internal/tools/nocomments` enforces this. Names and tests are the documentation, and design rationale goes in `docs/adr/`.
- Lint exclusions live in `.golangci.yml`, narrowly scoped by path and text.
- Every security-relevant change needs a test. Parsers need a fuzz target (`make fuzz`).
- Commits follow Conventional Commits (`feat:`, `fix:`, `perf:`, `test:`, `docs:`, `ci:`, `chore:`). Sign off with `git commit -s` (DCO).
- Performance claims need `make bench` output compared with benchstat.

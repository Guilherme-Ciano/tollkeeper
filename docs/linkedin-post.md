# LinkedIn post draft

Every MCP server you connect to an agent is a new door into your systems. Most gateways record who walked through it in a log that anyone with database access can quietly rewrite.

So I built tollkeeper, an open-source MCP gateway in Go. It is a single binary that sits between agents and their tools.

Three decisions shaped it:

1. **No token passthrough.** The MCP spec forbids forwarding the caller's token upstream, yet the official Go proxy example forwards every inbound header, Authorization included. tollkeeper validates the token as an OAuth 2.1 resource server (RFC 9728 metadata, strict audience per RFC 8707, step-up challenges), then calls each upstream with its own credentials. A test proves the client's token never reaches an upstream.

2. **An audit log you can verify.** Each record is SHA-256 chained to the previous one, and Ed25519-signed checkpoints sit inside the chain. `tollkeeper audit verify` names the exact record that was edited, deleted or reordered. Arguments are stored as hashes by default, which keeps it GDPR-minimal. When the disk fails, calls are refused rather than run unrecorded.

3. **Policy as code.** Rules are CEL expressions, compiled once and evaluated in about 4 µs. A `policy test` command lets the rules run in CI like any other code.

Two independent review passes found real bugs before release. One example: arguments like `{"path":"/tmp/x","PATH":"/etc/shadow"}` could make the policy and a case-insensitive upstream read different values. The parser now rejects case-folded duplicate keys at any depth.

The number: **0.6 ms p50 and 1.3 ms p99 of added latency at 1,000 calls/s** with JWT, CEL, rate limits and fsync'd audit all on. It sustains about 2,000 calls/s under 5 ms p99 on 4 cores of a desktop Ryzen. Profiling shows the gateway's own logic is about 9% of CPU. Most of the cost is the second MCP hop: the Go SDK decodes each request about six times, and I plan to propose an upstream fix.

These are same-host loopback numbers with a no-op upstream, so they are not internet latency. They are reproducible with `make bench-e2e`, with the hardware recorded.

Useful for EU AI Act record-keeping and DORA-style traceability, without a SaaS dependency.

Repo, architecture diagram and a `docker compose up` demo: github.com/Guilherme-Ciano/tollkeeper

#golang #mcp #oauth #security #opensource

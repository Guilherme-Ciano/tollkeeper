# Guarding Claude Code, Cursor and other coding agents in 2 minutes

Put `tollkeeper` on loopback between your coding agent and its MCP servers so every tool call is policy-checked, rate-limited, pinned against rug-pull edits and recorded in an Ed25519-signed audit log — without exposing upstream credentials to the agent.

## 1. Scaffold a local gateway

Download the latest binary from the [releases page](https://github.com/Guilherme-Ciano/tollkeeper/releases) (or build with `go install github.com/Guilherme-Ciano/tollkeeper/cmd/tollkeeper@latest`), then run:

```bash
tollkeeper init
```

This creates:

- `tollkeeper.yaml` — a loopback-only gateway fronting the MCP filesystem server, allowing reads across your workspace, writes only under `./drafts/` (blocking `..` traversal), a 300/m GCRA rate limit, tool pinning in `warn` mode and an Ed25519-signed audit log.
- `policies_test.yaml` — ready-to-run policy fixtures covering allowed reads, allowed draft writes and denied path escapes.
- `keys/audit-ed25519.pem` and `keys/audit-ed25519.pub` — the checkpoint signing key pair.

To wrap a different MCP server instead of the filesystem default:

```bash
# Wrap a Streamable HTTP MCP server (default policy: readOnlyHint tools allowed, writes denied)
tollkeeper init --upstream-id myapi --upstream-url https://mcp.example.com/mcp

# Wrap any stdio MCP server
tollkeeper init --upstream-id docs --upstream-cmd npx --upstream-cmd -y --upstream-cmd @modelcontextprotocol/server-memory
```

Verify the generated policy fixtures, then start the gateway:

```bash
tollkeeper policy test -c tollkeeper.yaml -f policies_test.yaml
tollkeeper serve -c tollkeeper.yaml
```

## 2. Connect your coding agent

### Claude Code

```bash
claude mcp add --transport http tollkeeper http://localhost:8080/mcp
```

Or add it to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "tollkeeper": {
      "type": "http",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "tollkeeper": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### VS Code / GitHub Copilot

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "tollkeeper": {
      "type": "http",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

## 3. Lock down tool definitions and verify the audit trail

Once your agent has listed tools through the gateway, inspect and approve the tool catalog, then switch `pinning.mode` from `warn` to `enforce` in `tollkeeper.yaml`:

```bash
tollkeeper pin status
tollkeeper pin approve --all
```

From that point on, if an upstream MCP server silently changes a tool description or schema (tool poisoning / rug pull), `tollkeeper` hides and refuses it until you inspect the diff and re-approve it.

At any time, cryptographically verify the local audit trail:

```bash
tollkeeper audit verify -f ./audit.jsonl --pubkey ./keys/audit-ed25519.pub --chain-id local-gateway
```

## Moving from local to a team deployment

Generate an OAuth 2.1 JWT + `pinning.mode: enforce` + hashed-argument audit skeleton with:

```bash
tollkeeper init --profile team --dir ./prod-gateway
```

See [examples/configs/github.yaml](../../examples/configs/github.yaml) and [deploy/helm/tollkeeper](../../deploy/helm/tollkeeper/README.md) for production configurations.

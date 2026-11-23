# Cursor + tollkeeper

Connect Cursor to `tollkeeper` instead of wiring raw stdio/HTTP MCP servers directly into every developer laptop. Credentials for GitHub, databases, or internal APIs stay inside the gateway, while Cursor only receives the tools the developer's token is authorized to see.

## 1. Add `.cursor/mcp.json`

Copy [mcp.json](mcp.json) into `.cursor/mcp.json` (project-scoped) or `~/.cursor/mcp.json` (user-scoped).

For a local `tollkeeper init` gateway (no auth on loopback), set `"url": "http://localhost:8080/mcp"` and omit the `headers` block.

For a team gateway with OAuth 2.1 JWTs, export `TOLLKEEPER_ACCESS_TOKEN` in your shell environment before starting Cursor (or use Cursor's built-in OAuth 2.1 discovery against `/.well-known/oauth-protected-resource/mcp`, which `tollkeeper` serves per RFC 9728).

## 2. Verify policies before rolling out to the team

```bash
tollkeeper policy explain \
  -c tollkeeper.yaml \
  --sub dev@example.com \
  --scope mcp:tools \
  --tool fs__read_file \
  --args '{"path":".env"}'
```

With [policies/library/coding-agent-guardrails.yaml](../../../policies/library/coding-agent-guardrails.yaml), secret files (`.env`, `.git/`, `/etc/`) and `..` path traversal are denied before reaching the upstream MCP server.

# Claude Code + tollkeeper

Route Claude Code's MCP tool calls through `tollkeeper` so workspace file access, GitHub calls, and destructive tools are guarded by CEL policy, pinned against rug-pull edits, and recorded in a verifiable audit log.

## 1. Start tollkeeper with coding-agent guardrails

```bash
tollkeeper init --dir ./gw
# Copy or merge rules from policies/library/coding-agent-guardrails.yaml into ./gw/tollkeeper.yaml
tollkeeper policy test -c ./gw/tollkeeper.yaml -f ./gw/policies_test.yaml
tollkeeper serve -c ./gw/tollkeeper.yaml
```

For team deployments with OAuth 2.1 (Entra ID, Okta, Auth0, Keycloak), start with `tollkeeper init --profile team` or one of the presets in [examples/configs/](../../configs/).

## 2. Register tollkeeper in Claude Code

CLI registration (local loopback):

```bash
claude mcp add --transport http tollkeeper http://localhost:8080/mcp
```

CLI registration (team gateway with OAuth Bearer token):

```bash
claude mcp add --transport http tollkeeper https://mcp.example.com/mcp \
  --header "Authorization: Bearer ${TOLLKEEPER_ACCESS_TOKEN}"
```

Or drop [mcp.json](mcp.json) as `.mcp.json` in your repository root so the entire team connects through the same policy-enforced endpoint.

## 3. Approve tool pins

```bash
tollkeeper pin status
tollkeeper pin approve --all
```

Once approved, set `pinning.mode: enforce` in `tollkeeper.yaml` so any unexpected upstream tool schema or description change is hidden and blocked until reviewed.

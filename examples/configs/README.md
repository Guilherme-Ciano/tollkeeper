# Example configurations

Ready-to-adapt configurations that put tollkeeper in front of widely used MCP servers. Validate any of them with:

```bash
tollkeeper config validate -c examples/configs/github.yaml
```

## [`github.yaml`](github.yaml): GitHub MCP server for a team of agents

[github/github-mcp-server](https://github.com/github/github-mcp-server) runs as a stdio subprocess. The personal access token lives only in the subprocess environment; agents authenticate to tollkeeper with their own OAuth tokens and never see it.

- Every agent with `mcp:tools` may call any tool the server annotates as `readOnlyHint`, so new read tools work without a policy change while new write tools stay denied.
- Creating issues and comments needs the `github:write` scope and is limited to one organisation by a CEL check on the arguments; agents without the scope get a `403 insufficient_scope` step-up challenge.
- Writes have their own rate limit (20 per hour per agent) on top of the general per-tool limit.
- `pinning.mode: enforce` means a server upgrade that changes any tool description is held back until someone reviews the diff with `tollkeeper pin approve`.

## [`filesystem.yaml`](filesystem.yaml): reference filesystem server for a local agent

The [reference filesystem server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) behind a loopback-only gateway, as a guard rail for a coding agent on a workstation.

- `namespace_tools: false` keeps the original tool names, so existing agent prompts keep working.
- Reads are allowed across the share; writes only under `/srv/shared/drafts/`, enforced on the `path` argument.
- `record_args: full` keeps complete arguments in the audit log, which is reasonable for a single-user workstation and not for shared deployments (arguments may contain personal data).

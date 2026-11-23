# OpenAI Agents SDK + tollkeeper

Use the OpenAI Agents SDK's `MCPServerStreamableHttp` client to talk to `tollkeeper` with OAuth 2.1 Bearer authentication.

## Setup

```bash
pip install openai-agents
export OPENAI_API_KEY="sk-..."
export TOLLKEEPER_URL="http://localhost:8080/mcp"
export TOLLKEEPER_ACCESS_TOKEN="<oauth2-jwt>"
python agent.py
```

When `tollkeeper` runs in `pinning.mode: enforce` with a CEL policy such as [read-only-default.yaml](../../../policies/library/read-only-default.yaml), the agent automatically sees only approved, authorized tools.

# LangGraph + tollkeeper

Connect a LangGraph ReAct agent to `tollkeeper` via `langchain-mcp-adapters` over Streamable HTTP.

## Why route LangGraph through tollkeeper?

- **Filtered tool catalog:** `client.get_tools()` only receives tools the caller's JWT is authorized to invoke (`tools/list` filtering).
- **Per-tenant & per-tool GCRA rate limits:** runaway graph loops hit HTTP `429` with `Retry-After` before exhausting downstream APIs.
- **Verifiable audit trail:** every tool call carries the end-user/agent `sub`, `tenant`, `act` delegation chain, and W3C `traceparent` into Tollkeeper's hash-chained audit log and SIEM/OTLP sinks.

## Setup

```bash
pip install langgraph langchain-openai langchain-mcp-adapters
export OPENAI_API_KEY="sk-..."
export TOLLKEEPER_URL="http://localhost:8080/mcp"
export TOLLKEEPER_ACCESS_TOKEN="<oauth2-jwt>"
python agent.py
```

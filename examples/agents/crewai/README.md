# CrewAI + tollkeeper

Connect CrewAI agents to `tollkeeper` over Streamable HTTP so different crew roles authenticate with distinct OAuth tokens and receive distinct tool subsets and rate limits.

## Pattern: least privilege per crew role

- **Researcher agent** authenticates with a read-only token (`scope: mcp:tools`) — Tollkeeper hides destructive tools and enforces read-only CEL rules.
- **Operator agent** authenticates with a scoped write token (`scope: mcp:tools notes:write`) — Tollkeeper exchanges the caller token upstream via RFC 8693 ([ADR 0013](../../../docs/adr/0013-oauth-token-exchange-and-delegation.md)) and records the full `act` delegation chain in the audit log.

## Setup

```bash
pip install crewai crewai-tools
export OPENAI_API_KEY="sk-..."
export TOLLKEEPER_URL="http://localhost:8080/mcp"
export RESEARCHER_TOKEN="<read-only-jwt>"
python crew.py
```

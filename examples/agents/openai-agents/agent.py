import asyncio
import os
from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp


async def main() -> None:
    mcp_url = os.environ.get("TOLLKEEPER_URL", "http://localhost:8080/mcp")
    token = os.environ.get("TOLLKEEPER_ACCESS_TOKEN", "")
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with MCPServerStreamableHttp(
        name="tollkeeper",
        params={
            "url": mcp_url,
            "headers": headers,
            "timeout": 15,
        },
        cache_tools_list=False,
    ) as server:
        agent = Agent(
            name="ResearchAssistant",
            instructions=(
                "Use the MCP tools exposed by tollkeeper to answer questions. "
                "If a tool call returns an authorization or step-up error, report "
                "the required scope or authentication level to the user."
            ),
            mcp_servers=[server],
        )
        result = await Runner.run(
            agent,
            "Search the gateway notes and report what audit guarantees are provided.",
        )
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())

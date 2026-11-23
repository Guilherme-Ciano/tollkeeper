import asyncio
import os
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent


async def main() -> None:
    mcp_url = os.environ.get("TOLLKEEPER_URL", "http://localhost:8080/mcp")
    token = os.environ.get("TOLLKEEPER_ACCESS_TOKEN", "")
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    client = MultiServerMCPClient(
        {
            "tollkeeper": {
                "transport": "streamable_http",
                "url": mcp_url,
                "headers": headers,
            }
        }
    )

    tools = await client.get_tools()
    model = ChatOpenAI(model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"), temperature=0)
    agent = create_react_agent(model, tools)

    result = await agent.ainvoke(
        {
            "messages": [
                (
                    "user",
                    "List the notes available through tollkeeper and summarize the gateway design note.",
                )
            ]
        }
    )
    print(result["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())

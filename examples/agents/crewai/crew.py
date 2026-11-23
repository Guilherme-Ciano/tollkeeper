import os
from crewai import Agent, Crew, Task
from crewai_tools import MCPServerAdapter


def main() -> None:
    mcp_url = os.environ.get("TOLLKEEPER_URL", "http://localhost:8080/mcp")
    researcher_token = os.environ.get("RESEARCHER_TOKEN", "")
    headers: dict[str, str] = {}
    if researcher_token:
        headers["Authorization"] = f"Bearer {researcher_token}"

    server_params = {
        "url": mcp_url,
        "transport": "streamable-http",
        "headers": headers,
    }

    with MCPServerAdapter(server_params) as mcp_tools:
        researcher = Agent(
            role="Security Researcher",
            goal="Inspect internal notes through tollkeeper without exceeding read-only permissions.",
            backstory="Audits MCP-accessible documentation under strict least privilege.",
            tools=mcp_tools,
            verbose=True,
        )

        task = Task(
            description="Search notes for 'audit' and produce a three-bullet compliance summary.",
            expected_output="A concise 3-bullet summary of the audit guarantees.",
            agent=researcher,
        )

        crew = Crew(agents=[researcher], tasks=[task], verbose=True)
        print(crew.kickoff())


if __name__ == "__main__":
    main()

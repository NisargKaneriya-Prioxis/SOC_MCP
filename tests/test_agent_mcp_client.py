import asyncio

from app.agent.mcp_client import SOCMCPClient


async def main():

    mcp_client = SOCMCPClient()

    print("\nConnecting to MCP server...")

    # --------------------------------
    # Test tool discovery
    # --------------------------------

    tools = await mcp_client.get_tools()

    print(f"\nFound {len(tools)} tools:\n")

    for tool in tools:

        print(f"Tool: {tool.name}")
        print(f"Description: {tool.description}")
        print(f"Schema: {tool.inputSchema}")
        print("-" * 50)

    # --------------------------------
    # Test tool execution
    # --------------------------------

    print("\nTesting get_alert_details...\n")

    result = await mcp_client.call_tool(
        "get_alert_details",
        {
            "incident_id": "INC-1001"
        }
    )

    print("Result:")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
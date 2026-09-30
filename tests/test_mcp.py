import asyncio

from fastmcp import Client


async def main():

    client = Client(
        "http://localhost:8000/mcp"
    )

    async with client:

        tools = await client.list_tools()

        print("Available tools:")

        for tool in tools:
            print(f"- {tool.name}")

        print("\nTesting alert tool...")

        result = await client.call_tool(
            "get_alert_details",
            {
                "incident_id": "INC-1001"
            }
        )

        print(result)


if __name__ == "__main__":
    asyncio.run(main())
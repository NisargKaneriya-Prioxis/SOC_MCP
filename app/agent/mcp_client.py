import os

from dotenv import load_dotenv
from fastmcp import Client


load_dotenv()


MCP_URL = os.getenv(
    "MCP_URL",
    "http://127.0.0.1:8000/mcp"
)


class SOCMCPClient:

    def __init__(self):
        self.mcp_url = MCP_URL

    async def get_tools(self):
        """
        Get all available tools from the SOC MCP server.
        """

        client = Client(self.mcp_url)

        async with client:
            tools = await client.list_tools()

        return tools

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict
    ):
        """
        Execute an MCP tool and return its result.
        """

        client = Client(self.mcp_url)

        async with client:

            result = await client.call_tool(
                tool_name,
                arguments
            )

            if result.is_error:
                raise RuntimeError(
                    f"MCP tool '{tool_name}' failed: "
                    f"{result.content}"
                )

            # Preferred FastMCP structured result
            if result.data is not None:
                return result.data

            # Fallback to raw structured content
            if result.structured_content is not None:
                return result.structured_content

            # Final fallback
            if result.content:
                return {
                    "content": [
                        getattr(item, "text", str(item))
                        for item in result.content
                    ]
                }

            return None
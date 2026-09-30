import json

from app.agent.llm_client import (
    client,
    DEPLOYMENT,
    convert_mcp_tools,
)
from app.agent.mcp_client import SOCMCPClient
from app.agent.prompts import SOC_SYSTEM_PROMPT


class SOCAgent:

    def __init__(self):
        self.mcp_client = SOCMCPClient()

    async def investigate(
        self,
        incident_id: str
    ) -> dict:

        print(
            f"\nStarting AI investigation: {incident_id}"
        )

        # =========================================
        # 1. Discover MCP tools
        # =========================================

        mcp_tools = await self.mcp_client.get_tools()

        llm_tools = convert_mcp_tools(
            mcp_tools
        )

        print(
            f"\nDiscovered {len(llm_tools)} MCP tools."
        )

        # =========================================
        # 2. Store all evidence collected
        # =========================================
        #
        # IMPORTANT:
        # This must be declared BEFORE the agent loop.
        #

        collected_evidence = {}

        # =========================================
        # 3. Create initial conversation
        # =========================================

        messages = [
            {
                "role": "system",
                "content": SOC_SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": (
                    f"Investigate security incident "
                    f"{incident_id}."
                ),
            },
        ]

        max_iterations = 15

        # =========================================
        # 4. Agent loop
        # =========================================

        for iteration in range(max_iterations):

            print(
                f"\nAgent iteration {iteration + 1}"
            )

            response = await (
                client.chat.completions.create(
                    model=DEPLOYMENT,
                    messages=messages,
                    tools=llm_tools,
                    tool_choice="auto",
                )
            )

            assistant_message = (
                response.choices[0].message
            )

            # =====================================
            # 5. Agent finished investigation
            # =====================================

            if not assistant_message.tool_calls:

                final_answer = (
                    assistant_message.content
                    or "No investigation report generated."
                )

                print(
                    "\nAI investigation completed."
                )

                # IMPORTANT:
                # Worker expects a dictionary,
                # not just a string.
                return {
                    "report": final_answer,
                    "evidence": collected_evidence,
                }

            # =====================================
            # 6. Store assistant tool request
            # =====================================

            messages.append(
                assistant_message
            )

            # =====================================
            # 7. Execute requested MCP tools
            # =====================================

            for tool_call in (
                assistant_message.tool_calls
            ):

                tool_name = (
                    tool_call.function.name
                )

                try:

                    arguments = json.loads(
                        tool_call.function.arguments
                    )

                except json.JSONDecodeError:

                    arguments = {}

                print(
                    f"\nAgent selected MCP tool: "
                    f"{tool_name}"
                )

                print(
                    f"Arguments: {arguments}"
                )

                try:

                    tool_result = (
                        await self.mcp_client.call_tool(
                            tool_name,
                            arguments,
                        )
                    )

                    print(
                        "MCP result received."
                    )

                except Exception as exc:

                    tool_result = {
                        "success": False,
                        "error": str(exc),
                    }

                    print(
                        f"MCP tool failed: {exc}"
                    )

                # =================================
                # 8. Save evidence
                # =================================

                collected_evidence[
                    tool_name
                ] = tool_result

                # =================================
                # 9. Send MCP result back to LLM
                # =================================

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(
                            tool_result,
                            default=str,
                        ),
                    }
                )

        # =========================================
        # 10. Safety against infinite loops
        # =========================================

        raise RuntimeError(
            "Agent exceeded maximum investigation "
            "iterations."
        )
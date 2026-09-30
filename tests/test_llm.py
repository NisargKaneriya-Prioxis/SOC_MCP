import asyncio

from app.agent.llm_client import (
    client,
    DEPLOYMENT
)


async def main():

    print("Testing Azure OpenAI connection...")
    print(f"Deployment: {DEPLOYMENT}")

    response = await client.chat.completions.create(
        model=DEPLOYMENT,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a SOC security analyst."
                )
            },
            {
                "role": "user",
                "content": (
                    "Reply only with: "
                    "SOC Agent is working"
                )
            }
        ]
    )

    result = response.choices[0].message.content

    print("\nResponse:")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
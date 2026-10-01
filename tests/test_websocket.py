import asyncio
import json

import websockets


WS_URL = "ws://127.0.0.1:8001/ws"


async def main():

    print(
        f"Connecting to WebSocket: "
        f"{WS_URL}"
    )

    async with websockets.connect(
        WS_URL
    ) as websocket:

        print(
            "WebSocket connected successfully."
        )

        print(
            "\nWaiting for SOC events...\n"
        )

        while True:

            message = await (
                websocket.recv()
            )

            try:

                data = json.loads(
                    message
                )

            except json.JSONDecodeError:

                print(
                    f"Raw message: {message}"
                )

                continue

            print("=" * 60)

            print(
                f"EVENT TYPE: "
                f"{data.get('type')}"
            )

            print(
                "DATA:"
            )

            print(
                json.dumps(
                    data.get(
                        "data",
                        {}
                    ),
                    indent=4
                )
            )


if __name__ == "__main__":
    asyncio.run(main())
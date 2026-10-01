import asyncio
import json

from app.event_sources.windows_source import (
    stream_windows_events
)


async def main():

    print(
        "\nWaiting for live Windows events..."
    )

    async for event in (
        stream_windows_events()
    ):

        print("\n" + "=" * 60)

        print(
            json.dumps(
                event,
                indent=4,
                default=str
            )
        )


if __name__ == "__main__":
    asyncio.run(main())

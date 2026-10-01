import os

from dotenv import load_dotenv

from app.event_sources.mock_source import (
    stream_mock_events
)

from app.event_sources.windows_source import (
    stream_windows_events
)


load_dotenv()


async def stream_events():
    """
    Select the configured SOC event source.

    EVENT_SOURCE=mock
        Reads events.json.

    EVENT_SOURCE=windows
        Reads live Windows Security events.
    """

    source = os.getenv(
        "EVENT_SOURCE",
        "mock"
    ).strip().lower()

    print(
        f"\nConfigured Event Source: "
        f"{source.upper()}"
    )

    if source == "mock":

        async for event in (
            stream_mock_events()
        ):
            yield event

        return

    if source == "windows":

        async for event in (
            stream_windows_events()
        ):
            yield event

        return

    raise ValueError(
        f"Unsupported EVENT_SOURCE: {source}"
    )
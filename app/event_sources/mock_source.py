import asyncio
import json
from pathlib import Path
from typing import AsyncGenerator


BASE_DIR = Path(__file__).resolve().parent.parent

EVENT_FILE = (
    BASE_DIR
    / "live_data"
    / "events.json"
)


async def stream_mock_events(
    delay_seconds: float = 3.0
) -> AsyncGenerator[dict, None]:
    """
    Stream simulated SOC events from events.json.

    Used for predictable POC demonstrations
    and automated testing.
    """

    if not EVENT_FILE.exists():
        raise FileNotFoundError(
            f"Mock event file not found: {EVENT_FILE}"
        )

    with EVENT_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:
        events = json.load(file)

    for event in events:

        await asyncio.sleep(
            delay_seconds
        )

        yield event
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


async def stream_events(
    delay_seconds: float = 3.0
) -> AsyncGenerator[dict, None]:
    """
    Simulate live security events.

    Events are read from JSON and emitted
    individually with a delay between them.
    """

    if not EVENT_FILE.exists():
        raise FileNotFoundError(
            f"Event file not found: {EVENT_FILE}"
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
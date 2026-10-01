from app.api.websocket_manager import (
    websocket_manager
)


async def publish_event(
    event_type: str,
    data: dict
) -> None:

    await websocket_manager.broadcast(
        {
            "type": event_type,
            "data": data
        }
    )
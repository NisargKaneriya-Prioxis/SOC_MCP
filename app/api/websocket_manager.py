from fastapi import WebSocket


class WebSocketManager:

    def __init__(self):

        self.active_connections: list[
            WebSocket
        ] = []

    async def connect(
        self,
        websocket: WebSocket
    ) -> None:

        await websocket.accept()

        self.active_connections.append(
            websocket
        )

    def disconnect(
        self,
        websocket: WebSocket
    ) -> None:

        if websocket in (
            self.active_connections
        ):

            self.active_connections.remove(
                websocket
            )

    async def broadcast(
        self,
        message: dict
    ) -> None:

        dead_connections = []

        for connection in (
            self.active_connections
        ):

            try:

                await connection.send_json(
                    message
                )

            except Exception:

                dead_connections.append(
                    connection
                )

        for connection in dead_connections:

            self.disconnect(
                connection
            )


websocket_manager = WebSocketManager()
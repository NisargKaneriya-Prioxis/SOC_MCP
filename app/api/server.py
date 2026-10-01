import asyncio
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
)

from app.api.routes.providers import (
    router as providers_router
)

from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.incidents import (
    router as incidents_router,
)

from app.api.routes.tickets import (
    router as tickets_router,
)

from app.api.routes.audit import (
    router as audit_router,
)

from app.api.routes.system import (
    router as system_router,
)

from app.api.websocket_manager import (
    websocket_manager,
)

from app.monitoring.monitor import SOCMonitor


# =========================================================
# SOC Monitor State
# =========================================================


soc_monitor = SOCMonitor(
    worker_count=2,
    correlation_window=10.0
)

monitor_task = None

monitor_state = {
    "running": False,
    "status": "STOPPED"
}


# =========================================================
# FastAPI Lifespan
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    global monitor_task

    print("\n" + "=" * 60)
    print("STARTING AI SOC APPLICATION")
    print("=" * 60)

    # -----------------------------------------------------
    # Start SOC Monitor
    # -----------------------------------------------------

    monitor_state["running"] = True
    monitor_state["status"] = "RUNNING"

    monitor_task = asyncio.create_task(
        soc_monitor.start()
    )

    print("SOC Monitor started successfully.")
    print("FastAPI server starting...")
    print("=" * 60)

    yield

    # -----------------------------------------------------
    # Shutdown SOC Monitor
    # -----------------------------------------------------

    print("\nStopping SOC Monitor...")

    monitor_state["running"] = False
    monitor_state["status"] = "STOPPED"

    if monitor_task:

        monitor_task.cancel()

        try:
            await monitor_task

        except asyncio.CancelledError:
            pass

    print("SOC Monitor stopped.")


# =========================================================
# FastAPI Application
# =========================================================

app = FastAPI(
    title="AI SOC API",
    description=(
        "AI-powered Security Operations Center API"
    ),
    version="1.0.0",
    lifespan=lifespan
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# API Routers
# =========================================================
app.include_router(
    providers_router
)

app.include_router(
    incidents_router
)

app.include_router(
    tickets_router
)

app.include_router(
    audit_router
)

app.include_router(
    system_router
)


# =========================================================
# Health Check
# =========================================================

@app.get("/api/health")
async def health():

    task_running = (
        monitor_task is not None
        and not monitor_task.done()
    )

    return {
        "status": "healthy",
        "service": "AI SOC API",
        "monitor": {
            "running": task_running,
            "status": (
                "RUNNING"
                if task_running
                else "STOPPED"
            )
        }
    }


# =========================================================
# WebSocket
# =========================================================

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket
):

    await websocket_manager.connect(
        websocket
    )

    try:

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:

        websocket_manager.disconnect(
            websocket
        )

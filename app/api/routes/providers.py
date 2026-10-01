import os

from fastapi import APIRouter
from dotenv import load_dotenv


load_dotenv()


router = APIRouter(
    prefix="/api/providers",
    tags=["Providers"]
)


@router.get("/status")
async def provider_status():

    return {
        "event_source": os.getenv(
            "EVENT_SOURCE",
            "mock"
        ),

        "identity_source": os.getenv(
            "IDENTITY_SOURCE",
            "mock"
        ),

        "endpoint_source": os.getenv(
            "ENDPOINT_SOURCE",
            "mock"
        ),

        "network_source": os.getenv(
            "NETWORK_SOURCE",
            "mock"
        ),

        "log_source": os.getenv(
            "LOG_SOURCE",
            "mock"
        ),

        "ticket_source": os.getenv(
            "TICKET_SOURCE",
            "mock"
        )
    }
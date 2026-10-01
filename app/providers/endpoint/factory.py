import os

from dotenv import load_dotenv

from app.providers.endpoint.mock_endpoint import (
    get_mock_endpoint_activity
)

from app.providers.endpoint.windows_endpoint import (
    get_windows_endpoint_activity
)


load_dotenv()


def get_endpoint_activity(
    device: str
) -> dict:
    """
    Retrieve endpoint evidence from the configured
    endpoint provider.
    """

    source = (
        os.getenv(
            "ENDPOINT_SOURCE",
            "mock"
        )
        .strip()
        .lower()
    )

    if source == "mock":

        return get_mock_endpoint_activity(
            device
        )

    if source == "windows":

        return get_windows_endpoint_activity(
            device
        )

    return {
        "success": False,
        "error": (
            "Unsupported ENDPOINT_SOURCE: "
            f"{source}"
        )
    }
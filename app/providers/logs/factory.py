import os

from dotenv import load_dotenv

from app.providers.logs.mock_logs import (
    search_mock_security_logs
)

from app.providers.logs.windows_logs import (
    search_windows_security_logs
)


load_dotenv()


def search_security_logs(
    incident_id: str
) -> dict:
    """
    Search security logs using the configured provider.

    Supported providers:

    LOG_SOURCE=mock
    LOG_SOURCE=windows
    """

    source = (
        os.getenv(
            "LOG_SOURCE",
            "mock"
        )
        .strip()
        .lower()
    )

    # =====================================================
    # Mock Provider
    # =====================================================

    if source == "mock":

        return search_mock_security_logs(
            incident_id
        )

    # =====================================================
    # Windows Provider
    # =====================================================

    if source == "windows":

        return search_windows_security_logs(
            incident_id
        )

    # =====================================================
    # Unsupported Provider
    # =====================================================

    return {
        "success": False,
        "source": "Unknown",
        "error": (
            "Unsupported LOG_SOURCE: "
            f"{source}"
        )
    }
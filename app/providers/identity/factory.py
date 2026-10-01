import os

from dotenv import load_dotenv

from app.providers.identity.mock_identity import (
    get_mock_login_history
)

from app.providers.identity.windows_identity import (
    get_windows_login_history
)


load_dotenv()


def get_login_history(
    user: str
) -> dict:

    source = (
        os.getenv(
            "IDENTITY_SOURCE",
            "mock"
        )
        .strip()
        .lower()
    )

    if source == "mock":

        return get_mock_login_history(
            user
        )

    if source == "windows":

        return get_windows_login_history(
            user
        )

    return {
        "success": False,
        "error": (
            "Unsupported IDENTITY_SOURCE: "
            f"{source}"
        )
    }
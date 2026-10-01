from app.mcp_server.data_loader import load_json


def get_mock_login_history(
    user: str
) -> dict:

    logins = load_json(
        "logins.json"
    )

    login = logins.get(
        user
    )

    if not login:
        return {
            "success": False,
            "source": "Mock Identity Provider",
            "error": (
                f"Login information for "
                f"{user} was not found."
            )
        }

    result = dict(
        login
    )

    result["suspicious_location"] = (
        result.get("country")
        != result.get("usual_country")
    )

    return {
        "success": True,
        "source": "Mock Identity Provider",
        "data": result
    }
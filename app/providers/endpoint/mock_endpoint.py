from app.mcp_server.data_loader import load_json


def get_mock_endpoint_activity(
    device: str
) -> dict:
    """
    Retrieve simulated endpoint telemetry.
    """

    endpoints = load_json(
        "endpoints.json"
    )

    endpoint = endpoints.get(
        device
    )

    if not endpoint:
        return {
            "success": False,
            "source": "Mock Endpoint Provider",
            "error": (
                f"Endpoint {device} "
                "was not found."
            )
        }

    return {
        "success": True,
        "source": "Mock Endpoint Provider",
        "data": endpoint
    }
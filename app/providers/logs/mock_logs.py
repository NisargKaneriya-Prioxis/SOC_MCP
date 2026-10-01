from app.mcp_server.data_loader import load_json


def search_mock_security_logs(
    incident_id: str
) -> dict:
    """
    Search simulated security logs.

    Supports predefined and dynamically
    generated POC incidents.
    """

    logs = load_json(
        "logs.json"
    )

    alerts = load_json(
        "alerts.json"
    )

    # =================================================
    # Existing predefined incident
    # =================================================

    if incident_id in logs:

        incident_logs = logs[
            incident_id
        ]

        sorted_logs = sorted(
            incident_logs,
            key=lambda item: item.get(
                "timestamp",
                ""
            )
        )

        return {
            "success": True,
            "source": "Mock Security Logs",
            "count": len(
                sorted_logs
            ),
            "data": sorted_logs
        }

    # =================================================
    # Dynamically generated incident
    # =================================================

    incident = alerts.get(
        incident_id
    )

    if not incident:

        return {
            "success": False,
            "source": "Mock Security Logs",
            "error": (
                f"Incident {incident_id} "
                "was not found."
            )
        }

    user = incident.get(
        "user"
    )

    device = incident.get(
        "device"
    )

    correlated_logs = []

    for log_entries in logs.values():

        for entry in log_entries:

            same_user = (
                user is not None
                and entry.get(
                    "user"
                ) == user
            )

            same_device = (
                device is not None
                and entry.get(
                    "device"
                ) == device
            )

            if (
                same_user
                or same_device
            ):
                correlated_logs.append(
                    entry
                )

    correlated_logs.sort(
        key=lambda item: item.get(
            "timestamp",
            ""
        )
    )

    return {
        "success": True,
        "source": "Mock Security Logs",
        "count": len(
            correlated_logs
        ),
        "data": correlated_logs
    }
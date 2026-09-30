def build_ticket_data(
    incident: dict,
    risk: dict,
    investigation_result: dict
) -> dict:

    incident_id = incident[
        "incident_id"
    ]

    user = incident.get(
        "user",
        "Unknown"
    )

    device = incident.get(
        "device",
        "Unknown"
    )

    alert = incident.get(
        "alert",
        "Security Incident"
    )

    severity = risk.get(
        "level",
        incident.get(
            "severity",
            "UNKNOWN"
        )
    )

    reasons = risk.get(
        "reasons",
        []
    )

    summary = (
        f"{alert}. "
        f"Affected user: {user}. "
        f"Affected device: {device}. "
        f"Final risk level: {severity}."
    )

    recommendations = []

    evidence = investigation_result.get(
        "evidence",
        {}
    )

    login_response = evidence.get(
        "get_login_history",
        {}
    )

    endpoint_response = evidence.get(
        "get_endpoint_activity",
        {}
    )

    network_response = evidence.get(
        "get_network_activity",
        {}
    )

    login = login_response.get(
        "data",
        login_response
    )

    endpoint = endpoint_response.get(
        "data",
        endpoint_response
    )

    network = network_response.get(
        "data",
        network_response
    )

    if login.get("mfa") is False:
        recommendations.append(
            "Enable MFA for the affected account."
        )

    if login.get("failed_logins", 0) >= 10:
        recommendations.append(
            "Review the affected account and reset "
            "credentials if compromise is confirmed."
        )

    if endpoint.get("status") == "suspicious":
        recommendations.append(
            "Investigate and consider isolating "
            "the affected endpoint."
        )

    if endpoint.get("malware_detected"):
        recommendations.append(
            "Perform malware analysis on the "
            "affected endpoint."
        )

    if (
        network.get(
            "reputation",
            ""
        ).lower()
        == "malicious"
    ):

        recommendations.append(
            "Review and block the malicious "
            "network destination as appropriate."
        )

    if not recommendations:

        recommendations.append(
            "Perform analyst review of the incident."
        )

    return {
        "incident_id": incident_id,
        "severity": severity,
        "summary": summary,
        "recommendations": recommendations,
        "risk_reasons": reasons
    }

import json
from datetime import datetime, timezone
from pathlib import Path
from app.providers.identity.factory import (
    get_login_history as provider_get_login_history
)
from app.providers.endpoint.factory import (
get_endpoint_activity as provider_get_endpoint_activity
)

from fastmcp import FastMCP

from app.mcp_server.data_loader import load_json


# =========================================================
# Configuration
# =========================================================

ROOT_DIR = Path(__file__).resolve().parents[2]

INCIDENTS_DIRECTORY = ROOT_DIR / "incidents"
TICKETS_DIRECTORY = ROOT_DIR / "tickets"


# =========================================================
# MCP Server
# =========================================================

mcp = FastMCP(
    name="Cybersecurity SOC MCP Server"
)


# =========================================================
# TOOL 1
# Alert Details
# Simulates Microsoft Sentinel
# =========================================================

@mcp.tool
def get_alert_details(
    incident_id: str
) -> dict:
    """
    Retrieve the security alert associated with an incident.

    Args:
        incident_id: Security incident ID such as INC-1001.

    Returns:
        Security alert information.
    """

    alerts = load_json(
        "alerts.json"
    )

    incident = alerts.get(
        incident_id
    )

    if not incident:
        return {
            "success": False,
            "error": (
                f"Incident {incident_id} "
                "was not found."
            )
        }

    return {
        "success": True,
        "data": incident
    }


# =========================================================
# TOOL 2
# Login History
# Simulates Okta
# =========================================================

@mcp.tool
def get_login_history(
    user: str
) -> dict:
    """
    Retrieve authentication information for a user.

    The provider is selected using IDENTITY_SOURCE.

    Supported:
    - mock
    - windows
    """

    return provider_get_login_history(
        user
    )

# =========================================================
# TOOL 3
# Endpoint Activity
# Simulates CrowdStrike
# =========================================================

@mcp.tool
def get_endpoint_activity(
    device: str
) -> dict:
    """
    Retrieve endpoint security information.

    The underlying provider is selected using
    ENDPOINT_SOURCE.

    Supported providers:

    - mock
    - windows
    """

    return provider_get_endpoint_activity(
        device
    )


# =========================================================
# TOOL 4
# Network Activity
# Simulates Palo Alto
# =========================================================

@mcp.tool
def get_network_activity(
    device: str
) -> dict:
    """
    Retrieve network activity associated with a device.

    Simulates Palo Alto firewall telemetry.

    Args:
        device: Device hostname such as LAPTOP-01.

    Returns:
        Network security evidence.
    """

    network_data = load_json(
        "network.json"
    )

    activity = network_data.get(
        device
    )

    if not activity:
        return {
            "success": False,
            "error": (
                f"Network activity for "
                f"{device} was not found."
            )
        }

    return {
        "success": True,
        "data": activity
    }


# =========================================================
# TOOL 5
# Security Logs
# Simulates Splunk
# =========================================================

@mcp.tool
def search_security_logs(
    incident_id: str
) -> dict:
    """
    Search security logs related to an incident.

    Supports both predefined incidents and dynamically
    generated incidents.

    Simulates Splunk security log correlation.

    Args:
        incident_id: Security incident ID.

    Returns:
        Correlated security logs.
    """

    logs = load_json(
        "logs.json"
    )

    alerts = load_json(
        "alerts.json"
    )

    # -----------------------------------------------------
    # Existing incident-specific logs
    # -----------------------------------------------------

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
            "count": len(
                sorted_logs
            ),
            "data": sorted_logs
        }

    # -----------------------------------------------------
    # Dynamically generated incident
    # -----------------------------------------------------

    incident = alerts.get(
        incident_id
    )

    if not incident:
        return {
            "success": False,
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
                and entry.get("user") == user
            )

            same_device = (
                device is not None
                and entry.get("device") == device
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
        "count": len(
            correlated_logs
        ),
        "data": correlated_logs
    }


# =========================================================
# TOOL 6
# Correlated Incident Evidence
# Phase 3.1
# =========================================================

@mcp.tool
def get_incident_evidence(
    incident_id: str
) -> dict:
    """
    Retrieve all correlated live evidence collected
    during the incident correlation window.

    Args:
        incident_id: Security incident ID.

    Returns:
        Incident events, detections, severity and status.
    """

    incident_path = (
        INCIDENTS_DIRECTORY
        / f"{incident_id}.json"
    )

    if not incident_path.exists():
        return {
            "success": False,
            "error": (
                "Incident evidence not found "
                f"for {incident_id}."
            )
        }

    try:
        incident = json.loads(
            incident_path.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError as exc:
        return {
            "success": False,
            "error": (
                "Incident evidence file contains "
                f"invalid JSON: {exc}"
            )
        }

    return {
        "success": True,
        "incident_id": incident_id,
        "status": incident.get(
            "status"
        ),
        "severity": incident.get(
            "severity"
        ),
        "user": incident.get(
            "user"
        ),
        "device": incident.get(
            "device"
        ),
        "detections": incident.get(
            "detections",
            []
        ),
        "events": incident.get(
            "events",
            []
        )
    }


# =========================================================
# TOOL 7
# Create SOC Ticket
# Phase 3.2
# =========================================================

@mcp.tool
def create_incident_ticket(
    incident_id: str,
    severity: str,
    summary: str,
    recommendations: list[str]
) -> dict:
    """
    Create a mock SOC incident ticket.

    This tool represents a state-changing operation.

    In the POC the ticket is stored locally as JSON.
    Later this tool can be replaced with ServiceNow,
    Jira, or another ticketing integration.

    Args:
        incident_id: Security incident ID.
        severity: Final deterministic incident severity.
        summary: Investigation summary.
        recommendations: Recommended SOC response actions.

    Returns:
        Created SOC ticket information.
    """

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    if not incident_id.strip():
        return {
            "success": False,
            "error": (
                "Incident ID is required."
            )
        }

    allowed_severities = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    severity = severity.upper().strip()

    if severity not in allowed_severities:
        return {
            "success": False,
            "error": (
                f"Invalid severity: {severity}"
            )
        }

    if not summary.strip():
        return {
            "success": False,
            "error": (
                "Ticket summary is required."
            )
        }

    # -----------------------------------------------------
    # Ensure ticket directory exists
    # -----------------------------------------------------

    TICKETS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Prevent duplicate ticket creation
    # -----------------------------------------------------

    for ticket_file in (
        TICKETS_DIRECTORY.glob(
            "SOC-*.json"
        )
    ):

        try:
            existing_ticket = json.loads(
                ticket_file.read_text(
                    encoding="utf-8"
                )
            )

        except json.JSONDecodeError:
            continue

        if (
            existing_ticket.get(
                "incident_id"
            )
            == incident_id
        ):

            return {
                "success": True,
                "duplicate": True,
                "message": (
                    "A ticket already exists "
                    "for this incident."
                ),
                "ticket": existing_ticket
            }

    # -----------------------------------------------------
    # Determine next ticket number
    # -----------------------------------------------------

    ticket_numbers = []

    existing_tickets = list(
        TICKETS_DIRECTORY.glob(
            "SOC-*.json"
        )
    )

    for ticket_file in existing_tickets:

        try:
            ticket_number = int(
                ticket_file.stem.split(
                    "-"
                )[1]
            )

            ticket_numbers.append(
                ticket_number
            )

        except (
            ValueError,
            IndexError
        ):
            continue

    if ticket_numbers:
        next_ticket_number = (
            max(ticket_numbers) + 1
        )
    else:
        next_ticket_number = 1001

    ticket_id = (
        f"SOC-{next_ticket_number}"
    )

    # -----------------------------------------------------
    # Create ticket object
    # -----------------------------------------------------

    ticket = {
        "ticket_id": ticket_id,
        "incident_id": incident_id,
        "severity": severity,
        "summary": summary,
        "recommendations": recommendations,
        "status": "OPEN",
        "created_at": datetime.now(
            timezone.utc
        ).isoformat()
    }

    # -----------------------------------------------------
    # Save ticket
    # -----------------------------------------------------

    ticket_path = (
        TICKETS_DIRECTORY
        / f"{ticket_id}.json"
    )

    ticket_path.write_text(
        json.dumps(
            ticket,
            indent=4
        ),
        encoding="utf-8"
    )

    return {
        "success": True,
        "duplicate": False,
        "ticket": ticket
    }


# =========================================================
# Run MCP Server
# =========================================================

if __name__ == "__main__":

    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=8000
    )
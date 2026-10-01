import json
from pathlib import Path

from fastapi import APIRouter


router = APIRouter(
    prefix="/api/system",
    tags=["System"]
)


ROOT_DIR = Path(__file__).resolve().parents[3]

INCIDENT_DIR = ROOT_DIR / "incidents"
TICKET_DIR = ROOT_DIR / "tickets"


def load_incidents() -> list:

    if not INCIDENT_DIR.exists():
        return []

    incidents = []

    for file in INCIDENT_DIR.glob(
        "INC-*.json"
    ):

        try:

            incidents.append(
                json.loads(
                    file.read_text(
                        encoding="utf-8"
                    )
                )
            )

        except json.JSONDecodeError:
            continue

    return incidents


@router.get("/summary")
async def get_system_summary():

    incidents = load_incidents()

    total_incidents = len(
        incidents
    )

    high_risk = sum(
        1
        for incident in incidents
        if incident.get(
            "severity"
        ) in {
            "HIGH",
            "CRITICAL"
        }
    )

    investigating = sum(
        1
        for incident in incidents
        if incident.get(
            "status"
        ) in {
            "CORRELATING",
            "QUEUED",
            "INVESTIGATING"
        }
    )

    ticket_count = (
        len(
            list(
                TICKET_DIR.glob(
                    "SOC-*.json"
                )
            )
        )
        if TICKET_DIR.exists()
        else 0
    )

    return {
        "total_incidents": total_incidents,
        "high_risk_incidents": high_risk,
        "active_investigations": investigating,
        "tickets_created": ticket_count
    }
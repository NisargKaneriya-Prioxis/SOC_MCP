import json
from pathlib import Path

from fastapi import APIRouter, HTTPException


router = APIRouter(
    prefix="/api/incidents",
    tags=["Incidents"]
)


ROOT_DIR = Path(__file__).resolve().parents[3]

INCIDENT_DIR = ROOT_DIR / "incidents"


@router.get("")
async def get_incidents():
    """
    Return all SOC incidents.
    """

    if not INCIDENT_DIR.exists():
        return []

    incidents = []

    for incident_file in INCIDENT_DIR.glob(
        "INC-*.json"
    ):

        try:

            incident = json.loads(
                incident_file.read_text(
                    encoding="utf-8"
                )
            )

            incidents.append(
                incident
            )

        except json.JSONDecodeError:
            continue

    incidents.sort(
        key=lambda item: item.get(
            "created_at",
            ""
        ),
        reverse=True
    )

    return incidents


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str
):
    """
    Return a specific SOC incident.
    """

    incident_path = (
        INCIDENT_DIR
        / f"{incident_id}.json"
    )

    if not incident_path.exists():

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return json.loads(
        incident_path.read_text(
            encoding="utf-8"
        )
    )
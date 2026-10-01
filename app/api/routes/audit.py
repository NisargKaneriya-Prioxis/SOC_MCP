import json
from pathlib import Path

from fastapi import APIRouter


router = APIRouter(
    prefix="/api/audit",
    tags=["Audit"]
)


ROOT_DIR = Path(__file__).resolve().parents[3]

AUDIT_FILE = (
    ROOT_DIR
    / "audit_logs"
    / "soc_audit.jsonl"
)


@router.get("")
async def get_audit_events():

    if not AUDIT_FILE.exists():
        return []

    events = []

    with AUDIT_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            try:

                event = json.loads(
                    line
                )

                events.append(
                    event
                )

            except json.JSONDecodeError:
                continue

    return list(
        reversed(events)
    )
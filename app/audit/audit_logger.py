import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[2]

AUDIT_DIR = ROOT_DIR / "audit_logs"

AUDIT_FILE = AUDIT_DIR / "soc_audit.jsonl"


def log_audit_event(
    event_type: str,
    incident_id: str,
    details: dict[str, Any] | None = None
) -> None:
    """
    Write one structured SOC audit event.

    Each event is written as one JSON object per line.
    """

    AUDIT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    audit_event = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_type": event_type,
        "incident_id": incident_id,
        "details": details or {}
    }

    with AUDIT_FILE.open(
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                audit_event,
                default=str
            )
            + "\n"
        )
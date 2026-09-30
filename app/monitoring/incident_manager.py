import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.monitoring.detector import DetectionResult


ROOT_DIR = Path(__file__).resolve().parents[2]

INCIDENT_DIR = ROOT_DIR / "incidents"

ALERT_DATA_FILE = (
    ROOT_DIR
    / "app"
    / "mock_data"
    / "alerts.json"
)


class IncidentManager:

    def __init__(self):
        INCIDENT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        self.active_incidents: dict[str, str] = {}

        self.next_incident_number = (
            self._get_next_incident_number()
        )

    # -------------------------------------------------
    # Incident ID generation
    # -------------------------------------------------

    def _get_next_incident_number(self) -> int:

        incident_files = list(
            INCIDENT_DIR.glob("INC-*.json")
        )

        numbers = []

        for file in incident_files:

            try:
                number = int(
                    file.stem.split("-")[1]
                )

                numbers.append(number)

            except (ValueError, IndexError):
                continue

        if not numbers:
            return 1003

        return max(numbers) + 1

    # -------------------------------------------------
    # Correlation
    # -------------------------------------------------

    def _build_correlation_key(
        self,
        event: dict
    ) -> str:

        user = event.get(
            "user",
            "unknown-user"
        )

        device = event.get(
            "device",
            "unknown-device"
        )

        return f"{user}:{device}"

    # -------------------------------------------------
    # Create/update incident
    # -------------------------------------------------

    def create_or_update_incident(
        self,
        event: dict,
        detection: DetectionResult
    ) -> tuple[dict, bool]:

        correlation_key = (
            self._build_correlation_key(event)
        )

        existing_id = self.active_incidents.get(
            correlation_key
        )

        # =============================================
        # EXISTING INCIDENT
        # =============================================

        if existing_id:

            incident = self.load_incident(
                existing_id
            )

            # Only correlate while incident is open
            # for correlation
            if incident.get("status") == "CORRELATING":

                incident["events"].append(
                    event
                )

                incident["detections"].append(
                    self._build_detection_record(
                        event,
                        detection
                    )
                )

                incident["severity"] = (
                    self._highest_severity(
                        incident.get("severity"),
                        detection.severity
                    )
                )

                incident["updated_at"] = (
                    self._current_time()
                )

                self.save_incident(
                    incident
                )

                self._sync_alert_data(
                    incident
                )

                return incident, False

        # =============================================
        # NEW INCIDENT
        # =============================================

        incident_id = (
            f"INC-{self.next_incident_number}"
        )

        self.next_incident_number += 1

        incident = {
            "incident_id": incident_id,
            "alert": detection.alert_name,
            "severity": detection.severity,
            "status": "CORRELATING",

            "user": event.get("user"),
            "device": event.get("device"),

            "events": [
                event
            ],

            "detections": [
                self._build_detection_record(
                    event,
                    detection
                )
            ],

            "created_at": self._current_time(),
            "updated_at": self._current_time()
        }

        self.active_incidents[
            correlation_key
        ] = incident_id

        self.save_incident(
            incident
        )

        self._sync_alert_data(
            incident
        )

        return incident, True

    # -------------------------------------------------
    # Detection record
    # -------------------------------------------------

    def _build_detection_record(
        self,
        event: dict,
        detection: DetectionResult
    ) -> dict:

        return {
            "rule_id": detection.rule_id,
            "alert_name": detection.alert_name,
            "severity": detection.severity,
            "reason": detection.reason,
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp")
        }

    # -------------------------------------------------
    # Incident status
    # -------------------------------------------------

    def update_status(
        self,
        incident_id: str,
        status: str
    ) -> dict:

        incident = self.load_incident(
            incident_id
        )

        incident["status"] = status
        incident["updated_at"] = (
            self._current_time()
        )

        self.save_incident(
            incident
        )

        self._sync_alert_data(
            incident
        )

        return incident

    # -------------------------------------------------
    # Load
    # -------------------------------------------------

    def load_incident(
        self,
        incident_id: str
    ) -> dict:

        file_path = (
            INCIDENT_DIR
            / f"{incident_id}.json"
        )

        if not file_path.exists():

            raise FileNotFoundError(
                f"Incident not found: {incident_id}"
            )

        return json.loads(
            file_path.read_text(
                encoding="utf-8"
            )
        )

    # -------------------------------------------------
    # Save
    # -------------------------------------------------

    def save_incident(
        self,
        incident: dict
    ) -> None:

        file_path = (
            INCIDENT_DIR
            / f"{incident['incident_id']}.json"
        )

        file_path.write_text(
            json.dumps(
                incident,
                indent=4
            ),
            encoding="utf-8"
        )

    # -------------------------------------------------
    # Sync incident with MCP alert data
    # -------------------------------------------------

    def _sync_alert_data(
        self,
        incident: dict
    ) -> None:

        if ALERT_DATA_FILE.exists():

            alerts = json.loads(
                ALERT_DATA_FILE.read_text(
                    encoding="utf-8"
                )
            )

        else:
            alerts = {}

        alerts[incident["incident_id"]] = {
            "incident_id": incident["incident_id"],
            "source": "POC Detection Engine",
            "severity": incident["severity"],
            "alert": incident["alert"],
            "user": incident["user"],
            "device": incident["device"],
            "timestamp": incident["created_at"],
            "status": incident["status"]
        }

        ALERT_DATA_FILE.write_text(
            json.dumps(
                alerts,
                indent=4
            ),
            encoding="utf-8"
        )

    # -------------------------------------------------
    # Severity comparison
    # -------------------------------------------------

    @staticmethod
    def _highest_severity(
        current: Optional[str],
        new: Optional[str]
    ) -> str:

        ranking = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        current = current or "LOW"
        new = new or "LOW"

        if ranking.get(
            new,
            0
        ) > ranking.get(
            current,
            0
        ):
            return new

        return current

    # -------------------------------------------------
    # Current UTC timestamp
    # -------------------------------------------------

    @staticmethod
    def _current_time() -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()

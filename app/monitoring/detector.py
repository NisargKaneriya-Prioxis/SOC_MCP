from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectionResult:
    detected: bool
    rule_id: Optional[str] = None
    alert_name: Optional[str] = None
    severity: Optional[str] = None
    reason: Optional[str] = None


class DetectionEngine:

    def analyze(
        self,
        event: dict
    ) -> DetectionResult:

        event_type = event.get(
            "event_type",
            ""
        )

        # ----------------------------------
        # RULE 001
        # Brute force / failed login
        # ----------------------------------

        if event_type == "login_failed":

            failed_attempts = event.get(
                "failed_attempts",
                0
            )

            if failed_attempts >= 10:

                return DetectionResult(
                    detected=True,
                    rule_id="DET-001",
                    alert_name=(
                        "Multiple Failed Login Attempts"
                    ),
                    severity="MEDIUM",
                    reason=(
                        f"{failed_attempts} failed "
                        "authentication attempts detected."
                    )
                )

        # ----------------------------------
        # RULE 002
        # Suspicious PowerShell
        # ----------------------------------

        if event_type == "process_execution":

            process = event.get(
                "process",
                ""
            ).lower()

            status = event.get(
                "status",
                ""
            ).lower()

            if (
                process == "powershell.exe"
                and status == "suspicious"
            ):

                return DetectionResult(
                    detected=True,
                    rule_id="DET-002",
                    alert_name=(
                        "Suspicious PowerShell Execution"
                    ),
                    severity="HIGH",
                    reason=(
                        "Suspicious PowerShell execution "
                        "was detected."
                    )
                )

        # ----------------------------------
        # RULE 003
        # Malicious destination
        # ----------------------------------

        if event_type == "network_connection":

            reputation = event.get(
                "reputation",
                ""
            ).lower()

            if reputation == "malicious":

                return DetectionResult(
                    detected=True,
                    rule_id="DET-003",
                    alert_name=(
                        "Malicious Network Communication"
                    ),
                    severity="HIGH",
                    reason=(
                        "Endpoint communicated with a "
                        "known malicious destination."
                    )
                )

        return DetectionResult(
            detected=False
        )
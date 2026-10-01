from dataclasses import dataclass
from typing import Optional

from app.monitoring.detection_state import DetectionState


@dataclass
class DetectionResult:
    """
    Represents the result produced by a security
    detection rule.
    """

    detected: bool
    rule_id: Optional[str] = None
    alert_name: Optional[str] = None
    severity: Optional[str] = None
    reason: Optional[str] = None


class DetectionEngine:
    """
    Security detection engine supporting both:

    1. Mock POC events
    2. Real Windows Security events

    Windows authentication detection is stateful and
    evaluates multiple related events inside a rolling
    time window.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        failure_window_minutes: int = 5
    ) -> None:

        self.state = DetectionState()

        self.failure_threshold = (
            failure_threshold
        )

        self.failure_window_minutes = (
            failure_window_minutes
        )

    # =====================================================
    # Main Detection Entry Point
    # =====================================================

    def analyze(
        self,
        event: dict
    ) -> DetectionResult:
        """
        Analyze one normalized security event.
        """

        event_type = (
            event.get(
                "event_type",
                ""
            )
            .strip()
            .lower()
        )

        source = (
            event.get(
                "source",
                ""
            )
            .strip()
        )

        # =================================================
        # Failed Authentication
        # =================================================

        if event_type == "login_failed":

            # ---------------------------------------------
            # Real Windows telemetry
            # ---------------------------------------------

            if source == "Windows Security Log":

                return (
                    self._analyze_windows_login_failure(
                        event
                    )
                )

            # ---------------------------------------------
            # Mock POC telemetry
            # ---------------------------------------------

            return (
                self._analyze_mock_login_failure(
                    event
                )
            )

        # =================================================
        # Successful Authentication
        # =================================================

        if event_type == "login_success":

            # Only the real Windows workflow currently
            # performs stateful success-after-failure
            # correlation.

            if source == "Windows Security Log":

                return (
                    self._analyze_windows_login_success(
                        event
                    )
                )

            return DetectionResult(
                detected=False
            )

        # =================================================
        # Process Execution
        # =================================================

        if event_type == "process_execution":

            return (
                self._analyze_process_execution(
                    event
                )
            )

        # =================================================
        # Network Activity
        # =================================================

        if event_type == "network_connection":

            return (
                self._analyze_network_activity(
                    event
                )
            )

        # =================================================
        # Unknown / Normal Event
        # =================================================

        return DetectionResult(
            detected=False
        )

    # =====================================================
    # MOCK MODE
    # Failed Login Detection
    # =====================================================

    def _analyze_mock_login_failure(
        self,
        event: dict
    ) -> DetectionResult:
        """
        Preserve the original mock POC rule.

        Mock events may contain an already aggregated
        failed_attempts value.
        """

        failed_attempts = event.get(
            "failed_attempts",
            0
        )

        try:
            failed_attempts = int(
                failed_attempts
            )

        except (
            TypeError,
            ValueError
        ):
            failed_attempts = 0

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

        return DetectionResult(
            detected=False
        )

    # =====================================================
    # WINDOWS MODE
    # Stateful Failed Login Detection
    # =====================================================

    def _analyze_windows_login_failure(
        self,
        event: dict
    ) -> DetectionResult:
        """
        Track individual Windows 4625 events.

        A single failed authentication does not
        automatically generate an incident.

        A detection occurs only when enough related
        failures occur within the configured rolling
        time window.
        """

        failure_count = (
            self.state.add_login_failure(
                event=event,
                window_minutes=(
                    self.failure_window_minutes
                )
            )
        )

        print(
            "\nAuthentication Detection State:"
        )

        print(
            f"User: "
            f"{event.get('user') or 'unknown'}"
        )

        print(
            f"Device: "
            f"{event.get('device') or 'unknown'}"
        )

        print(
            f"Source IP: "
            f"{event.get('source_ip') or 'unknown'}"
        )

        print(
            f"Recent failures: "
            f"{failure_count}/"
            f"{self.failure_threshold}"
        )

        # ---------------------------------------------
        # Threshold has not been reached
        # ---------------------------------------------

        if (
            failure_count
            < self.failure_threshold
        ):

            return DetectionResult(
                detected=False
            )

        # ---------------------------------------------
        # Detection already fired
        # ---------------------------------------------

        if (
            self.state
            .is_failure_detection_triggered(
                event
            )
        ):

            print(
                "Authentication detection was "
                "already triggered for this sequence."
            )

            return DetectionResult(
                detected=False
            )

        # ---------------------------------------------
        # Prevent duplicate alerts
        # ---------------------------------------------

        self.state.mark_failure_detection_triggered(
            event
        )

        # ---------------------------------------------
        # Generate detection
        # ---------------------------------------------

        return DetectionResult(
            detected=True,

            rule_id="DET-WIN-001",

            alert_name=(
                "Repeated Windows "
                "Authentication Failures"
            ),

            severity="MEDIUM",

            reason=(
                f"{failure_count} related Windows "
                "authentication failures were observed "
                f"within {self.failure_window_minutes} "
                "minutes."
            )
        )

    # =====================================================
    # WINDOWS MODE
    # Successful Login Detection
    # =====================================================

    def _analyze_windows_login_success(
        self,
        event: dict
    ) -> DetectionResult:
        """
        Check whether a successful Windows login occurred
        after repeated related authentication failures.

        Windows Event 4624 represents a successful logon
        session, while 4625 represents a failed logon.
        """

        previous_failures = (
            self.state.get_login_failure_count(
                event=event,
                window_minutes=(
                    self.failure_window_minutes
                )
            )
        )

        print(
            "\nSuccessful Authentication Observed:"
        )

        print(
            f"User: "
            f"{event.get('user') or 'unknown'}"
        )

        print(
            f"Source IP: "
            f"{event.get('source_ip') or 'unknown'}"
        )

        print(
            f"Previous related failures: "
            f"{previous_failures}"
        )

        # ---------------------------------------------
        # No previous failures
        # ---------------------------------------------

        if previous_failures == 0:

            return DetectionResult(
                detected=False
            )

        # ---------------------------------------------
        # Some failures occurred, but threshold
        # was never reached.
        # ---------------------------------------------

        if (
            previous_failures
            < self.failure_threshold
        ):

            self.state.clear_login_failures(
                event
            )

            return DetectionResult(
                detected=False
            )

        # ---------------------------------------------
        # Repeated failures followed by success
        # ---------------------------------------------

        self.state.clear_login_failures(
            event
        )

        return DetectionResult(
            detected=True,

            rule_id="DET-WIN-002",

            alert_name=(
                "Successful Login After "
                "Repeated Failures"
            ),

            severity="HIGH",

            reason=(
                "A successful Windows authentication "
                f"occurred after {previous_failures} "
                "related failed authentication attempts "
                f"within {self.failure_window_minutes} "
                "minutes."
            )
        )

    # =====================================================
    # Process Execution Detection
    # =====================================================

    def _analyze_process_execution(
        self,
        event: dict
    ) -> DetectionResult:
        """
        Analyze process execution.

        Real Windows 4688 events are observation-only
        during Phase 5.1C.

        Mock POC events retain the existing suspicious
        PowerShell rule.
        """

        process = (
            event.get(
                "process",
                ""
            )
            .strip()
            .lower()
        )

        status = (
            event.get(
                "status",
                ""
            )
            .strip()
            .lower()
        )

        source = (
            event.get(
                "source",
                ""
            )
            .strip()
        )

        # ---------------------------------------------
        # Real Windows process telemetry
        # ---------------------------------------------

        if source == "Windows Security Log":

            # Event 4688 tells us a process was created.
            # This alone is not enough evidence to call
            # the execution malicious.

            return DetectionResult(
                detected=False
            )

        # ---------------------------------------------
        # Existing mock PowerShell detection
        # ---------------------------------------------

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

        return DetectionResult(
            detected=False
        )

    # =====================================================
    # Network Detection
    # =====================================================

    def _analyze_network_activity(
        self,
        event: dict
    ) -> DetectionResult:
        """
        Preserve the original mock network rule.

        Real Windows network telemetry is not yet
        connected in Phase 5.1C.
        """

        reputation = (
            event.get(
                "reputation",
                ""
            )
            .strip()
            .lower()
        )

        if reputation == "malicious":

            return DetectionResult(
                detected=True,

                rule_id="DET-003",

                alert_name=(
                    "Malicious Network "
                    "Communication"
                ),

                severity="HIGH",

                reason=(
                    "Endpoint communicated with "
                    "a known malicious destination."
                )
            )

        return DetectionResult(
            detected=False
        )
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


class DetectionState:
    """
    Maintains short-term state required for
    stateful security detection.

    Currently tracks:
    - Recent authentication failures
    - Authentication detections that have already fired
    """

    def __init__(self) -> None:

        # Example:
        #
        # {
        #     "user|device|source_ip": deque([
        #         datetime(...),
        #         datetime(...),
        #     ])
        # }

        self.login_failures = defaultdict(
            deque
        )

        # Prevents the same failure sequence from
        # repeatedly creating security detections.
        self.triggered_failure_keys = set()

    # =====================================================
    # Authentication Correlation Key
    # =====================================================

    @staticmethod
    def build_auth_key(
        event: dict
    ) -> str:
        """
        Build a key used to correlate related
        authentication events.

        Events are grouped using:

            user + device + source IP
        """

        user = (
            event.get("user")
            or "unknown-user"
        )

        device = (
            event.get("device")
            or "unknown-device"
        )

        source_ip = (
            event.get("source_ip")
            or "unknown-ip"
        )

        # Normalize values so differences in casing
        # do not create separate authentication groups.

        user = str(user).strip().lower()

        device = str(device).strip().lower()

        source_ip = str(
            source_ip
        ).strip().lower()

        return (
            f"{user}|"
            f"{device}|"
            f"{source_ip}"
        )

    # =====================================================
    # Timestamp Parser
    # =====================================================

    @staticmethod
    def parse_timestamp(
        value: str | None
    ) -> datetime:
        """
        Convert an ISO timestamp into a timezone-aware
        datetime object.

        If the event timestamp is missing or invalid,
        current UTC time is used.
        """

        if not value:

            return datetime.now(
                timezone.utc
            )

        cleaned = str(
            value
        ).strip()

        # Windows timestamps may end with Z.
        if cleaned.endswith("Z"):

            cleaned = (
                cleaned[:-1]
                + "+00:00"
            )

        try:

            parsed = datetime.fromisoformat(
                cleaned
            )

        except (
            ValueError,
            TypeError
        ):

            return datetime.now(
                timezone.utc
            )

        # Ensure timezone information exists.
        if parsed.tzinfo is None:

            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    # =====================================================
    # Record Authentication Failure
    # =====================================================

    def add_login_failure(
        self,
        event: dict,
        window_minutes: int
    ) -> int:
        """
        Store a failed authentication event.

        Old failures outside the rolling detection
        window are automatically removed.

        Returns:
            Number of related failures currently
            inside the detection window.
        """

        key = self.build_auth_key(
            event
        )

        timestamp = self.parse_timestamp(
            event.get("timestamp")
        )

        history = self.login_failures[
            key
        ]

        # Remove old records before adding the new
        # authentication failure.
        self._remove_old_failures(
            history=history,
            current_time=timestamp,
            window_minutes=window_minutes
        )

        history.append(
            timestamp
        )

        return len(
            history
        )

    # =====================================================
    # Recent Authentication Failure Count
    # =====================================================

    def get_login_failure_count(
        self,
        event: dict,
        window_minutes: int
    ) -> int:
        """
        Return the number of related authentication
        failures currently inside the rolling window.
        """

        key = self.build_auth_key(
            event
        )

        history = self.login_failures.get(
            key
        )

        if not history:
            return 0

        timestamp = self.parse_timestamp(
            event.get("timestamp")
        )

        self._remove_old_failures(
            history=history,
            current_time=timestamp,
            window_minutes=window_minutes
        )

        # Clean empty histories.
        if not history:

            self.login_failures.pop(
                key,
                None
            )

            self.triggered_failure_keys.discard(
                key
            )

            return 0

        return len(
            history
        )

    # =====================================================
    # Detection Suppression
    # =====================================================

    def is_failure_detection_triggered(
        self,
        event: dict
    ) -> bool:
        """
        Check whether an alert has already been
        generated for this authentication sequence.
        """

        key = self.build_auth_key(
            event
        )

        return (
            key
            in self.triggered_failure_keys
        )

    def mark_failure_detection_triggered(
        self,
        event: dict
    ) -> None:
        """
        Mark an authentication sequence as already
        detected.

        This prevents failure 6, 7, 8, etc. from
        generating duplicate incidents after the
        threshold was reached at failure 5.
        """

        key = self.build_auth_key(
            event
        )

        self.triggered_failure_keys.add(
            key
        )

    # =====================================================
    # Clear Authentication State
    # =====================================================

    def clear_login_failures(
        self,
        event: dict
    ) -> None:
        """
        Clear the authentication history and alert
        suppression state associated with an event.

        This is normally called once an authentication
        sequence has been resolved or reset.
        """

        key = self.build_auth_key(
            event
        )

        self.login_failures.pop(
            key,
            None
        )

        self.triggered_failure_keys.discard(
            key
        )

    # =====================================================
    # Reset Detection State
    # =====================================================

    def reset(self) -> None:
        """
        Reset all in-memory detection state.

        Useful for:
        - Unit tests
        - Development
        - Restarting detection sessions
        """

        self.login_failures.clear()

        self.triggered_failure_keys.clear()

    # =====================================================
    # Remove Expired Failures
    # =====================================================

    @staticmethod
    def _remove_old_failures(
        history: deque,
        current_time: datetime,
        window_minutes: int
    ) -> None:
        """
        Remove authentication failures that are older
        than the configured rolling detection window.
        """

        cutoff = (
            current_time
            - timedelta(
                minutes=window_minutes
            )
        )

        while (
            history
            and history[0] < cutoff
        ):
            history.popleft()
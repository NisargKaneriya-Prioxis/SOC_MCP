import asyncio

from app.monitoring.detector import DetectionEngine
from app.monitoring.event_source import stream_events
from app.monitoring.incident_manager import IncidentManager
from app.monitoring.worker import investigation_worker


class SOCMonitor:

    def __init__(
        self,
        worker_count: int = 2,
        correlation_window: float = 10.0
    ):

        self.detector = DetectionEngine()

        self.incident_manager = (
            IncidentManager()
        )

        self.incident_queue = (
            asyncio.Queue()
        )

        self.worker_count = worker_count

        self.correlation_window = (
            correlation_window
        )

        self.correlation_tasks = {}

    async def start(self) -> None:

        print("\n" + "=" * 60)
        print("SOC CONTINUOUS SECURITY MONITOR")
        print("=" * 60)

        print(
            f"\nCorrelation Window: "
            f"{self.correlation_window} seconds"
        )

        print("\nMonitoring security events...")

        # =============================================
        # Start investigation workers
        # =============================================

        workers = []

        for number in range(
            self.worker_count
        ):

            worker = asyncio.create_task(
                investigation_worker(
                    worker_name=(
                        f"Worker-{number + 1}"
                    ),
                    incident_queue=(
                        self.incident_queue
                    )
                )
            )

            workers.append(worker)

        try:

            # =========================================
            # Event stream
            # =========================================

            async for event in stream_events():

                await self._process_event(
                    event
                )

            print(
                "\nEvent source completed."
            )

            # =========================================
            # Wait for correlation timers
            # =========================================

            if self.correlation_tasks:

                print(
                    "\nWaiting for active "
                    "correlation windows..."
                )

                await asyncio.gather(
                    *self.correlation_tasks.values(),
                    return_exceptions=True
                )

            # =========================================
            # Wait for investigations
            # =========================================

            print(
                "\nWaiting for active "
                "investigations..."
            )

            await self.incident_queue.join()

        finally:

            for worker in workers:
                worker.cancel()

            await asyncio.gather(
                *workers,
                return_exceptions=True
            )

    # =================================================
    # Event processing
    # =================================================

    async def _process_event(
        self,
        event: dict
    ) -> None:

        print("\n" + "-" * 60)

        print(
            f"Event:  "
            f"{event.get('event_id')}"
        )

        print(
            f"Type:   "
            f"{event.get('event_type')}"
        )

        print(
            f"User:   "
            f"{event.get('user', 'N/A')}"
        )

        print(
            f"Device: "
            f"{event.get('device', 'N/A')}"
        )

        detection = (
            self.detector.analyze(event)
        )

        # =============================================
        # Normal event
        # =============================================

        if not detection.detected:

            print(
                "Result: Normal / No detection"
            )

            return

        # =============================================
        # Security detection
        # =============================================

        print(
            "\n!!! SECURITY THREAT DETECTED !!!"
        )

        print(
            f"Rule:     {detection.rule_id}"
        )

        print(
            f"Alert:    {detection.alert_name}"
        )

        print(
            f"Severity: {detection.severity}"
        )

        print(
            f"Reason:   {detection.reason}"
        )

        incident, is_new = (
            self.incident_manager
            .create_or_update_incident(
                event,
                detection
            )
        )

        incident_id = incident[
            "incident_id"
        ]

        # =============================================
        # New Incident
        # =============================================

        if is_new:

            print(
                f"\nNew Incident Created: "
                f"{incident_id}"
            )

            print(
                "Status: CORRELATING"
            )

            print(
                f"Collecting related events for "
                f"{self.correlation_window} seconds..."
            )

            task = asyncio.create_task(
                self._finish_correlation(
                    incident_id
                )
            )

            self.correlation_tasks[
                incident_id
            ] = task

        # =============================================
        # Existing Incident
        # =============================================

        else:

            print(
                f"\nExisting Incident Updated: "
                f"{incident_id}"
            )

            print(
                f"Current Severity: "
                f"{incident['severity']}"
            )

            print(
                f"Total Detections: "
                f"{len(incident['detections'])}"
            )

            print(
                f"Total Events: "
                f"{len(incident['events'])}"
            )

        print("-" * 60)

    # =================================================
    # Finish correlation
    # =================================================

    async def _finish_correlation(
        self,
        incident_id: str
    ) -> None:

        await asyncio.sleep(
            self.correlation_window
        )

        incident = (
            self.incident_manager
            .load_incident(
                incident_id
            )
        )

        # Incident may already have moved on
        if (
            incident.get("status")
            != "CORRELATING"
        ):
            return

        incident = (
            self.incident_manager
            .update_status(
                incident_id,
                "QUEUED"
            )
        )

        print(
            "\n"
            + "=" * 60
        )

        print(
            "CORRELATION WINDOW COMPLETE"
        )

        print(
            f"Incident: "
            f"{incident_id}"
        )

        print(
            f"Severity: "
            f"{incident['severity']}"
        )

        print(
            f"Events Collected: "
            f"{len(incident['events'])}"
        )

        print(
            f"Detections Collected: "
            f"{len(incident['detections'])}"
        )

        print(
            "Status: QUEUED"
        )

        print(
            "=" * 60
        )

        await self.incident_queue.put(
            incident
        )
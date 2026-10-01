import asyncio

from app.api.event_publisher import publish_event
from app.monitoring.detector import DetectionEngine
# from app.monitoring.event_source import stream_events
from app.event_sources.factory import stream_events
from app.monitoring.incident_manager import IncidentManager
from app.monitoring.worker import investigation_worker


class SOCMonitor:
    """
    Continuous SOC security monitor.

    Responsibilities:
    - Receive live security events
    - Analyze events using detection rules
    - Publish live events to the dashboard
    - Create and correlate security incidents
    - Wait for the correlation window
    - Queue incidents for AI investigation
    - Keep monitoring while investigations run
    """

    def __init__(
        self,
        worker_count: int = 2,
        correlation_window: float = 10.0
    ) -> None:

        self.detector = DetectionEngine()

        self.incident_manager = IncidentManager()

        self.incident_queue = asyncio.Queue()

        self.worker_count = worker_count

        self.correlation_window = correlation_window

        # Stores correlation timer tasks using
        # incident_id as the key.
        self.correlation_tasks: dict[
            str,
            asyncio.Task
        ] = {}

    # =====================================================
    # Start SOC Monitor
    # =====================================================

    async def start(self) -> None:
        """
        Start the continuous SOC monitoring pipeline.
        """

        print("\n" + "=" * 60)
        print("SOC CONTINUOUS SECURITY MONITOR")
        print("=" * 60)

        print(
            f"\nCorrelation Window: "
            f"{self.correlation_window} seconds"
        )

        print("\nMonitoring security events...")

        # =================================================
        # Start Investigation Workers
        # =================================================

        workers = []

        for number in range(self.worker_count):

            worker = asyncio.create_task(
                investigation_worker(
                    worker_name=f"Worker-{number + 1}",
                    incident_queue=self.incident_queue
                )
            )

            workers.append(worker)

        try:

            # =============================================
            # Continuous Event Stream
            # =============================================

            async for event in stream_events():

                await self._process_event(
                    event
                )

            print("\nEvent source completed.")

            # =============================================
            # Wait for active correlation windows
            # =============================================

            if self.correlation_tasks:

                print(
                    "\nWaiting for active "
                    "correlation windows..."
                )

                await asyncio.gather(
                    *self.correlation_tasks.values(),
                    return_exceptions=True
                )

            # =============================================
            # Wait for queued investigations
            # =============================================

            print(
                "\nWaiting for active "
                "investigations..."
            )

            await self.incident_queue.join()

            print(
                "\nAll investigations completed."
            )

        finally:

            # =============================================
            # Stop investigation workers
            # =============================================

            for worker in workers:
                worker.cancel()

            await asyncio.gather(
                *workers,
                return_exceptions=True
            )

    # =====================================================
    # Process Security Event
    # =====================================================

    async def _process_event(
        self,
        event: dict
    ) -> None:
        """
        Process a single incoming security event.

        Every event is:
        1. Evaluated by the detection engine.
        2. Published to the live dashboard.
        3. Ignored if normal.
        4. Correlated into an incident if suspicious.
        """

        print("\n" + "-" * 60)

        print(f"Event:  {event.get('event_id')}")
        print(f"Source: {event.get('source', 'Unknown')}")
        print(f"Type:   {event.get('event_type')}")
        print(f"User:   {event.get('user', 'N/A')}")
        print(f"Device: {event.get('device', 'N/A')}")

        if event.get("source_ip"):
            print(
                f"Source IP: "
                f"{event.get('source_ip')}"
            )

        # =================================================
        # Analyze Event
        # =================================================

        detection = self.detector.analyze(
            event
        )

        # =================================================
        # Publish EVERY event to dashboard
        # =================================================

        await publish_event(
            "SECURITY_EVENT",
            {
                "event_id": event.get(
                    "event_id"
                ),
                "event_type": event.get(
                    "event_type"
                ),
                "user": event.get(
                    "user"
                ),
                "device": event.get(
                    "device"
                ),
                "timestamp": event.get(
                    "timestamp"
                ),
                "detection": detection.detected,
                "severity": (
                    detection.severity
                    if detection.detected
                    else None
                )
            }
        )

        # =================================================
        # Normal Event
        # =================================================

        if not detection.detected:

            print(
                "Result: Normal / No detection"
            )

            print("-" * 60)

            return

        # =================================================
        # Security Threat Detected
        # =================================================

        print(
            "\n!!! SECURITY THREAT DETECTED !!!"
        )

        print(
            f"Rule:     "
            f"{detection.rule_id}"
        )

        print(
            f"Alert:    "
            f"{detection.alert_name}"
        )

        print(
            f"Severity: "
            f"{detection.severity}"
        )

        print(
            f"Reason:   "
            f"{detection.reason}"
        )

        # =================================================
        # Create or Update Incident
        # =================================================

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

        # =================================================
        # New Incident
        # =================================================

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

            # ---------------------------------------------
            # Publish incident creation to dashboard
            # ---------------------------------------------

            await publish_event(
                "INCIDENT_CREATED",
                {
                    "incident_id": incident_id,
                    "alert": incident.get(
                        "alert"
                    ),
                    "severity": incident.get(
                        "severity"
                    ),
                    "status": incident.get(
                        "status"
                    ),
                    "user": incident.get(
                        "user"
                    ),
                    "device": incident.get(
                        "device"
                    ),
                    "created_at": incident.get(
                        "created_at"
                    )
                }
            )

            # ---------------------------------------------
            # Start correlation timer
            # ---------------------------------------------

            task = asyncio.create_task(
                self._finish_correlation(
                    incident_id
                )
            )

            self.correlation_tasks[
                incident_id
            ] = task

        # =================================================
        # Existing Incident Updated
        # =================================================

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

            # ---------------------------------------------
            # Publish update to dashboard
            # ---------------------------------------------

            await publish_event(
                "INCIDENT_UPDATED",
                {
                    "incident_id": incident_id,
                    "severity": incident.get(
                        "severity"
                    ),
                    "status": incident.get(
                        "status"
                    ),
                    "user": incident.get(
                        "user"
                    ),
                    "device": incident.get(
                        "device"
                    ),
                    "detections": len(
                        incident.get(
                            "detections",
                            []
                        )
                    ),
                    "events": len(
                        incident.get(
                            "events",
                            []
                        )
                    ),
                    "updated_at": incident.get(
                        "updated_at"
                    )
                }
            )

        print("-" * 60)

    # =====================================================
    # Finish Incident Correlation
    # =====================================================

    async def _finish_correlation(
        self,
        incident_id: str
    ) -> None:
        """
        Wait for the correlation window to finish.

        After the window:
        - Load the latest incident
        - Verify it is still correlating
        - Change state to QUEUED
        - Notify dashboard
        - Send incident to investigation worker
        """

        await asyncio.sleep(
            self.correlation_window
        )

        # =================================================
        # Load latest incident
        # =================================================

        incident = (
            self.incident_manager
            .load_incident(
                incident_id
            )
        )

        # =================================================
        # Make sure incident is still correlating
        # =================================================

        if (
            incident.get("status")
            != "CORRELATING"
        ):
            return

        # =================================================
        # Update lifecycle state
        # =================================================

        incident = (
            self.incident_manager
            .update_status(
                incident_id,
                "QUEUED"
            )
        )

        # =================================================
        # Print correlation result
        # =================================================

        print("\n" + "=" * 60)

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

        print("=" * 60)

        # =================================================
        # Publish queued incident to dashboard
        # =================================================

        await publish_event(
            "INCIDENT_QUEUED",
            {
                "incident_id": incident_id,
                "severity": incident.get(
                    "severity"
                ),
                "status": "QUEUED",
                "user": incident.get(
                    "user"
                ),
                "device": incident.get(
                    "device"
                ),
                "events_collected": len(
                    incident.get(
                        "events",
                        []
                    )
                ),
                "detections_collected": len(
                    incident.get(
                        "detections",
                        []
                    )
                )
            }
        )

        # =================================================
        # Send incident to AI investigation queue
        # =================================================

        await self.incident_queue.put(
            incident
        )

        # =================================================
        # Remove completed correlation task
        # =================================================

        self.correlation_tasks.pop(
            incident_id,
            None
        )
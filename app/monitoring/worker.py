import asyncio

from app.agent.soc_agent import SOCAgent
from app.agent.risk_engine import calculate_risk
from app.agent.ticket_builder import build_ticket_data
from app.agent.mcp_client import SOCMCPClient

from app.monitoring.incident_manager import IncidentManager
from app.audit.audit_logger import log_audit_event


async def investigation_worker(
    worker_name: str,
    incident_queue: asyncio.Queue
) -> None:
    """
    Process security incidents from the incident queue.

    Workflow:
        1. Mark incident as INVESTIGATING
        2. Run AI SOC investigation
        3. Extract collected MCP evidence
        4. Calculate deterministic risk
        5. Save investigation result
        6. Mark incident as INVESTIGATED
        7. Build ticket data
        8. Create ticket through MCP
        9. Store ticket information
        10. Mark incident as TICKET_CREATED
        11. Record audit events
    """

    agent = SOCAgent()
    incident_manager = IncidentManager()
    mcp_client = SOCMCPClient()

    while True:

        # =================================================
        # Wait for an incident
        # =================================================

        incident = await incident_queue.get()

        incident_id = incident["incident_id"]

        # Used to determine the correct failure state.
        current_stage = "INVESTIGATION"

        try:

            # =================================================
            # 1. Start investigation
            # =================================================

            incident_manager.update_status(
                incident_id,
                "INVESTIGATING"
            )

            log_audit_event(
                event_type="INVESTIGATION_STARTED",
                incident_id=incident_id,
                details={
                    "worker": worker_name
                }
            )

            print("\n" + "=" * 60)
            print(
                f"[{worker_name}] STARTING AI INVESTIGATION"
            )
            print(f"Incident: {incident_id}")
            print("Status: INVESTIGATING")
            print("=" * 60)

            # =================================================
            # 2. Run AI investigation
            # =================================================

            result = await agent.investigate(
                incident_id
            )

            if not isinstance(result, dict):
                raise TypeError(
                    "SOCAgent.investigate() must return "
                    "a dictionary containing 'report' "
                    "and 'evidence'."
                )

            # =================================================
            # 3. Get evidence collected by the AI Agent
            # =================================================

            evidence = result.get(
                "evidence",
                {}
            )

            login_response = evidence.get(
                "get_login_history",
                {}
            )

            endpoint_response = evidence.get(
                "get_endpoint_activity",
                {}
            )

            network_response = evidence.get(
                "get_network_activity",
                {}
            )

            # =================================================
            # 4. Extract structured MCP results
            # =================================================

            login = (
                login_response.get(
                    "data",
                    login_response
                )
                if isinstance(login_response, dict)
                else {}
            )

            endpoint = (
                endpoint_response.get(
                    "data",
                    endpoint_response
                )
                if isinstance(endpoint_response, dict)
                else {}
            )

            network = (
                network_response.get(
                    "data",
                    network_response
                )
                if isinstance(network_response, dict)
                else {}
            )

            # =================================================
            # 5. Calculate deterministic risk
            # =================================================

            risk = calculate_risk(
                login=login,
                endpoint=endpoint,
                network=network
            )

            print("\nRisk assessment completed.")
            print(f"Risk Score: {risk['score']}")
            print(f"Risk Level: {risk['level']}")

            # =================================================
            # 6. Store investigation and risk
            # =================================================

            incident = incident_manager.load_incident(
                incident_id
            )

            incident["risk_assessment"] = risk

            # Deterministic risk engine controls
            # authoritative final severity.
            incident["severity"] = risk["level"]

            incident["investigation_result"] = {
                "report": result.get(
                    "report",
                    "No investigation report generated."
                ),
                "evidence": evidence
            }

            incident["status"] = "INVESTIGATED"

            incident_manager.save_incident(
                incident
            )

            # Keep alerts.json synchronized with
            # the final severity/status if this method
            # is available in your IncidentManager.
            incident_manager.update_status(
                incident_id,
                "INVESTIGATED"
            )

            log_audit_event(
                event_type="INVESTIGATION_COMPLETED",
                incident_id=incident_id,
                details={
                    "worker": worker_name,
                    "risk_score": risk["score"],
                    "risk_level": risk["level"]
                }
            )

            print("\n" + "=" * 60)
            print(
                f"[{worker_name}] INVESTIGATION COMPLETE"
            )
            print(f"Incident: {incident_id}")
            print("Status: INVESTIGATED")
            print(
                f"Final Risk: "
                f"{risk['level']} ({risk['score']})"
            )
            print("=" * 60)

            print(
                result.get(
                    "report",
                    "No investigation report generated."
                )
            )

            # =================================================
            # 7. Start ticket creation stage
            # =================================================

            current_stage = "TICKET_CREATION"

            print("\n" + "=" * 60)
            print("PREPARING SOC INCIDENT TICKET")
            print(f"Incident: {incident_id}")
            print("=" * 60)

            # Reload the latest incident.
            incident = incident_manager.load_incident(
                incident_id
            )

            # =================================================
            # 8. Build structured ticket payload
            # =================================================

            ticket_data = build_ticket_data(
                incident=incident,
                risk=risk,
                investigation_result=result
            )

            log_audit_event(
                event_type="TICKET_CREATION_REQUESTED",
                incident_id=incident_id,
                details={
                    "severity": ticket_data["severity"],
                    "worker": worker_name
                }
            )

            # Optional intermediate lifecycle state.
            incident_manager.update_status(
                incident_id,
                "CREATING_TICKET"
            )

            # =================================================
            # 9. Create ticket through MCP
            # =================================================

            ticket_response = await mcp_client.call_tool(
                "create_incident_ticket",
                {
                    "incident_id":
                        ticket_data["incident_id"],

                    "severity":
                        ticket_data["severity"],

                    "summary":
                        ticket_data["summary"],

                    "recommendations":
                        ticket_data["recommendations"]
                }
            )

            # =================================================
            # 10. Validate MCP ticket result
            # =================================================

            if not isinstance(
                ticket_response,
                dict
            ):
                raise RuntimeError(
                    "Ticket MCP tool returned an "
                    "invalid response."
                )

            if not ticket_response.get(
                "success",
                False
            ):
                raise RuntimeError(
                    "Incident ticket creation failed: "
                    f"{ticket_response.get('error', 'Unknown error')}"
                )

            ticket = ticket_response.get(
                "ticket"
            )

            if not isinstance(ticket, dict):
                raise RuntimeError(
                    "Ticket creation succeeded but "
                    "no valid ticket data was returned."
                )

            ticket_id = ticket.get(
                "ticket_id"
            )

            if not ticket_id:
                raise RuntimeError(
                    "Ticket response does not contain "
                    "a ticket ID."
                )

            # =================================================
            # 11. Store ticket against incident
            # =================================================

            incident = incident_manager.load_incident(
                incident_id
            )

            incident["ticket"] = {
                "ticket_id": ticket_id,
                "status": ticket.get(
                    "status",
                    "OPEN"
                ),
                "created_at": ticket.get(
                    "created_at"
                )
            }

            incident["status"] = "TICKET_CREATED"

            incident_manager.save_incident(
                incident
            )

            # Synchronize final lifecycle state.
            incident_manager.update_status(
                incident_id,
                "TICKET_CREATED"
            )

            # =================================================
            # 12. Audit successful ticket creation
            # =================================================

            log_audit_event(
                event_type="TICKET_CREATED",
                incident_id=incident_id,
                details={
                    "ticket_id": ticket_id,
                    "severity": ticket.get(
                        "severity",
                        risk["level"]
                    ),
                    "worker": worker_name
                }
            )

            # =================================================
            # 13. Final output
            # =================================================

            print("\n" + "=" * 60)
            print(
                f"[{worker_name}] "
                "INCIDENT PROCESSING COMPLETE"
            )
            print("=" * 60)

            print(f"Incident: {incident_id}")
            print(
                f"Risk: {risk['level']} "
                f"({risk['score']})"
            )
            print(f"Ticket: {ticket_id}")
            print("Ticket Status: OPEN")
            print("Incident Status: TICKET_CREATED")

            print("=" * 60)

        except Exception as exc:

            # =================================================
            # Failure handling
            # =================================================

            try:

                incident = (
                    incident_manager.load_incident(
                        incident_id
                    )
                )

                if current_stage == "TICKET_CREATION":

                    failure_status = (
                        "TICKET_CREATION_FAILED"
                    )

                    failure_event = (
                        "TICKET_CREATION_FAILED"
                    )

                else:

                    failure_status = (
                        "INVESTIGATION_FAILED"
                    )

                    failure_event = (
                        "INVESTIGATION_FAILED"
                    )

                incident["status"] = failure_status

                incident["error"] = {
                    "stage": current_stage,
                    "message": str(exc)
                }

                incident_manager.save_incident(
                    incident
                )

                incident_manager.update_status(
                    incident_id,
                    failure_status
                )

                log_audit_event(
                    event_type=failure_event,
                    incident_id=incident_id,
                    details={
                        "stage": current_stage,
                        "error": str(exc),
                        "worker": worker_name
                    }
                )

            except Exception as save_error:

                print(
                    f"\nFailed to update incident "
                    f"{incident_id}: {save_error}"
                )

            print(
                f"\n[{worker_name}] "
                f"Processing failed for "
                f"{incident_id}"
            )

            print(
                f"Stage: {current_stage}"
            )

            print(
                f"Error: {exc}"
            )

        finally:

            # =================================================
            # Queue completion
            # =================================================

            incident_queue.task_done()
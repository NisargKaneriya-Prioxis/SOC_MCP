import json
import xml.etree.ElementTree as ET
from pathlib import Path

import win32evtlog


ROOT_DIR = Path(
    __file__
).resolve().parents[3]

INCIDENT_DIRECTORY = (
    ROOT_DIR
    / "incidents"
)

SECURITY_LOG = "Security"

EVENT_NAMESPACE = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


# =========================================================
# Helpers
# =========================================================

def _clean_value(
    value
):
    """
    Convert common empty Windows values into None.
    """

    if value is None:
        return None

    value = str(
        value
    ).strip()

    if value in {
        "",
        "-",
        "::",
        "N/A"
    }:
        return None

    return value


# =========================================================
# Parse Windows Event XML
# =========================================================

def _parse_event_xml(
    xml: str
) -> dict:
    """
    Parse Windows Event XML into a structured dictionary.
    """

    root = ET.fromstring(
        xml
    )

    system = root.find(
        "e:System",
        EVENT_NAMESPACE
    )

    if system is None:
        return {}

    event_id_element = system.find(
        "e:EventID",
        EVENT_NAMESPACE
    )

    record_element = system.find(
        "e:EventRecordID",
        EVENT_NAMESPACE
    )

    time_element = system.find(
        "e:TimeCreated",
        EVENT_NAMESPACE
    )

    computer_element = system.find(
        "e:Computer",
        EVENT_NAMESPACE
    )

    if (
        event_id_element is None
        or not event_id_element.text
    ):
        return {}

    event_id = int(
        event_id_element.text
    )

    record_number = (
        int(record_element.text)
        if (
            record_element is not None
            and record_element.text
        )
        else None
    )

    timestamp = None

    if time_element is not None:
        timestamp = (
            time_element.attrib.get(
                "SystemTime"
            )
        )

    computer = (
        computer_element.text
        if (
            computer_element is not None
            and computer_element.text
        )
        else None
    )

    # -----------------------------------------------------
    # Parse EventData fields
    # -----------------------------------------------------

    event_data = {}

    for element in root.findall(
        "e:EventData/e:Data",
        EVENT_NAMESPACE
    ):

        name = element.attrib.get(
            "Name"
        )

        if not name:
            continue

        event_data[name] = (
            element.text or ""
        )

    return {
        "event_id": event_id,
        "record_number": record_number,
        "timestamp": timestamp,
        "computer": computer,
        "data": event_data
    }


# =========================================================
# Load SOC Incident
# =========================================================

def _load_incident(
    incident_id: str
) -> dict | None:
    """
    Load the local SOC incident JSON file.
    """

    incident_path = (
        INCIDENT_DIRECTORY
        / f"{incident_id}.json"
    )

    if not incident_path.exists():
        return None

    try:

        return json.loads(
            incident_path.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError:

        return None


# =========================================================
# Normalize Windows Event
# =========================================================

def _normalize_event(
    event: dict
) -> dict:
    """
    Convert a Windows Security event into
    concise SOC investigation evidence.
    """

    event_id = event.get(
        "event_id"
    )

    data = event.get(
        "data",
        {}
    )

    result = {
        "event_id": event_id,

        "record_number": event.get(
            "record_number"
        ),

        "timestamp": event.get(
            "timestamp"
        ),

        "device": event.get(
            "computer"
        )
    }

    # =====================================================
    # Event 4624
    # Successful authentication
    # =====================================================

    if event_id == 4624:

        result.update(
            {
                "event_type":
                    "login_success",

                "user":
                    data.get(
                        "TargetUserName"
                    ),

                "source_ip":
                    _clean_value(
                        data.get(
                            "IpAddress"
                        )
                    ),

                "logon_type":
                    _clean_value(
                        data.get(
                            "LogonType"
                        )
                    ),

                "workstation":
                    _clean_value(
                        data.get(
                            "WorkstationName"
                        )
                    ),

                "authentication_package":
                    _clean_value(
                        data.get(
                            "AuthenticationPackageName"
                        )
                    )
            }
        )

    # =====================================================
    # Event 4625
    # Failed authentication
    # =====================================================

    elif event_id == 4625:

        result.update(
            {
                "event_type":
                    "login_failed",

                "user":
                    data.get(
                        "TargetUserName"
                    ),

                "source_ip":
                    _clean_value(
                        data.get(
                            "IpAddress"
                        )
                    ),

                "logon_type":
                    _clean_value(
                        data.get(
                            "LogonType"
                        )
                    ),

                "workstation":
                    _clean_value(
                        data.get(
                            "WorkstationName"
                        )
                    ),

                "failure_reason":
                    _clean_value(
                        data.get(
                            "FailureReason"
                        )
                    ),

                "status_code":
                    _clean_value(
                        data.get(
                            "Status"
                        )
                    ),

                "sub_status":
                    _clean_value(
                        data.get(
                            "SubStatus"
                        )
                    ),

                "authentication_package":
                    _clean_value(
                        data.get(
                            "AuthenticationPackageName"
                        )
                    )
            }
        )

    # =====================================================
    # Event 4688
    # Process creation
    # =====================================================

    elif event_id == 4688:

        process_path = (
            data.get(
                "NewProcessName"
            )
            or ""
        )

        process_name = (
            process_path
            .replace("/", "\\")
            .split("\\")[-1]
            .lower()
        )

        result.update(
            {
                "event_type":
                    "process_execution",

                "user": (
                    data.get(
                        "TargetUserName"
                    )
                    or
                    data.get(
                        "SubjectUserName"
                    )
                ),

                "process":
                    process_name,

                "process_path":
                    _clean_value(
                        process_path
                    ),

                "parent_process":
                    _clean_value(
                        data.get(
                            "ParentProcessName"
                        )
                        or
                        data.get(
                            "CreatorProcessName"
                        )
                    ),

                "command_line":
                    _clean_value(
                        data.get(
                            "CommandLine"
                        )
                    )
            }
        )

    else:

        result[
            "event_type"
        ] = (
            f"windows_event_{event_id}"
        )

    return result


# =========================================================
# Windows Security Log Search
# =========================================================

def search_windows_security_logs(
    incident_id: str,
    lookback_hours: int = 24,
    max_events: int = 100
) -> dict:
    """
    Search real Windows Security logs for evidence
    related to a local SOC incident.

    Currently searches:

    4624 - successful authentication
    4625 - failed authentication
    4688 - process creation
    """

    # -----------------------------------------------------
    # Load Incident
    # -----------------------------------------------------

    incident = _load_incident(
        incident_id
    )

    if not incident:

        return {
            "success": False,
            "source": "Windows Security Log",
            "error": (
                f"Incident {incident_id} "
                "was not found."
            )
        }

    incident_user = (
        incident.get(
            "user"
        )
        or ""
    )

    incident_device = (
        incident.get(
            "device"
        )
        or ""
    )

    # -----------------------------------------------------
    # Build Windows Event query
    # -----------------------------------------------------

    lookback_ms = (
        lookback_hours
        * 60
        * 60
        * 1000
    )

    query_text = (
        "*[System["
        "("
        "EventID=4624 "
        "or EventID=4625 "
        "or EventID=4688"
        ") "
        "and TimeCreated["
        f"timediff(@SystemTime) <= {lookback_ms}"
        "]"
        "]]"
    )

    query = win32evtlog.EvtQuery(
        SECURITY_LOG,
        win32evtlog.EvtQueryChannelPath,
        query_text
    )

    records = []

    # -----------------------------------------------------
    # Read Windows Events
    # -----------------------------------------------------

    while True:

        events = win32evtlog.EvtNext(
            query,
            50
        )

        if not events:
            break

        for event_handle in events:

            xml = win32evtlog.EvtRender(
                event_handle,
                win32evtlog.EvtRenderEventXml
            )

            parsed = _parse_event_xml(
                xml
            )

            if not parsed:
                continue

            normalized = _normalize_event(
                parsed
            )

            event_user = str(
                normalized.get(
                    "user"
                )
                or ""
            )

            event_device = str(
                normalized.get(
                    "device"
                )
                or ""
            )

            # =================================================
            # Correlate using incident entities
            # =================================================

            same_user = (
                bool(
                    incident_user
                )
                and
                event_user.casefold()
                ==
                str(
                    incident_user
                ).casefold()
            )

            same_device = (
                bool(
                    incident_device
                )
                and
                event_device.casefold()
                ==
                str(
                    incident_device
                ).casefold()
            )

            if not (
                same_user
                or same_device
            ):
                continue

            records.append(
                normalized
            )

            if (
                len(records)
                >= max_events
            ):
                break

        if (
            len(records)
            >= max_events
        ):
            break

    # -----------------------------------------------------
    # Chronological ordering
    # -----------------------------------------------------

    records.sort(
        key=lambda item: (
            item.get(
                "timestamp"
            )
            or ""
        )
    )

    # -----------------------------------------------------
    # Return Search Result
    # -----------------------------------------------------

    return {
        "success": True,

        "source":
            "Windows Security Log",

        "incident_id":
            incident_id,

        "count":
            len(records),

        "data":
            records
    }
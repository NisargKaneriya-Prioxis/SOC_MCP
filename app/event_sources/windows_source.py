import asyncio
import socket
import xml.etree.ElementTree as ET
from typing import AsyncGenerator

import win32evtlog


SECURITY_LOG = "Security"

MONITORED_EVENT_IDS = {
    4624,
    4625,
    4688,
}

EVENT_NAMESPACE = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def _query_latest_record_number() -> int:
    """
    Find the newest Windows Security event record number.

    Existing historical events will be ignored when
    live monitoring starts.
    """

    query = win32evtlog.EvtQuery(
        SECURITY_LOG,
        win32evtlog.EvtQueryReverseDirection,
        "*"
    )

    events = win32evtlog.EvtNext(
        query,
        1
    )

    if not events:
        return 0

    event_handle = events[0]

    xml = win32evtlog.EvtRender(
        event_handle,
        win32evtlog.EvtRenderEventXml
    )

    root = ET.fromstring(
        xml
    )

    record_element = root.find(
        "e:System/e:EventRecordID",
        EVENT_NAMESPACE
    )

    if (
        record_element is None
        or record_element.text is None
    ):
        return 0

    return int(
        record_element.text
    )


def _parse_event_xml(
    xml: str
) -> dict:
    """
    Parse Windows Event XML into a dictionary.
    """

    root = ET.fromstring(xml)

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

    computer_element = system.find(
        "e:Computer",
        EVENT_NAMESPACE
    )

    time_element = system.find(
        "e:TimeCreated",
        EVENT_NAMESPACE
    )

    event_id = (
        int(event_id_element.text)
        if (
            event_id_element is not None
            and event_id_element.text
        )
        else None
    )

    record_number = (
        int(record_element.text)
        if (
            record_element is not None
            and record_element.text
        )
        else 0
    )

    computer = (
        computer_element.text
        if (
            computer_element is not None
            and computer_element.text
        )
        else socket.gethostname()
    )

    timestamp = None

    if time_element is not None:
        timestamp = time_element.attrib.get(
            "SystemTime"
        )

    # Parse named Windows EventData fields
    event_data = {}

    data_elements = root.findall(
        "e:EventData/e:Data",
        EVENT_NAMESPACE
    )

    for element in data_elements:
        field_name = element.attrib.get(
            "Name"
        )

        if not field_name:
            continue

        event_data[field_name] = (
            element.text or ""
        )

    return {
        "event_id": event_id,
        "record_number": record_number,
        "computer": computer,
        "timestamp": timestamp,
        "data": event_data,
    }


def _query_new_security_events(
    last_record_number: int
) -> list:
    """
    Query new Windows Security events.

    Monitored Event IDs:
    4624 - Successful logon
    4625 - Failed logon
    4688 - Process creation
    """

    query_text = (
        "*[System["
        "("
        "EventID=4624 "
        "or EventID=4625 "
        "or EventID=4688"
        ")"
        f" and EventRecordID>{last_record_number}"
        "]]"
    )

    query = win32evtlog.EvtQuery(
        SECURITY_LOG,
        win32evtlog.EvtQueryChannelPath,
        query_text
    )

    parsed_events = []

    while True:

        events = win32evtlog.EvtNext(
            query,
            20
        )

        if not events:
            break

        for event_handle in events:

            xml = win32evtlog.EvtRender(
                event_handle,
                win32evtlog.EvtRenderEventXml
            )

            parsed_event = _parse_event_xml(
                xml
            )

            if parsed_event:
                parsed_events.append(
                    parsed_event
                )

    parsed_events.sort(
        key=lambda event: event["record_number"]
    )

    return parsed_events


def _normalize_4625(
    event: dict
) -> dict:
    """
    Normalize Windows Security Event ID 4625.

    Event 4625 represents a failed logon.
    """

    data = event.get(
        "data",
        {}
    )

    user = (
        data.get("TargetUserName")
        or "unknown"
    )

    device = (
        event.get("computer")
        or socket.gethostname()
    )

    source_ip = (
        data.get("IpAddress")
        or None
    )

    return {
        "event_id": (
            f"WIN-{event['record_number']}"
        ),
        "source": "Windows Security Log",
        "source_event_id": 4625,
        "event_type": "login_failed",
        "user": user,
        "device": device,
        "source_ip": source_ip,
        "logon_type": data.get(
            "LogonType"
        ),
        "failure_reason": data.get(
            "FailureReason"
        ),
        "status_code": data.get(
            "Status"
        ),
        "sub_status": data.get(
            "SubStatus"
        ),
        "timestamp": event.get(
            "timestamp"
        ),
        "record_number": event[
            "record_number"
        ],
    }


def _normalize_4688(
    event: dict
) -> dict:
    """
    Normalize Windows Security Event ID 4688.

    Event 4688 represents creation of a process.
    """

    data = event.get(
        "data",
        {}
    )

    process_path = (
        data.get("NewProcessName")
        or ""
    )

    process_name = (
        process_path
        .replace("/", "\\")
        .split("\\")[-1]
        .lower()
    )

    parent_process = (
        data.get("ParentProcessName")
        or data.get("CreatorProcessName")
        or None
    )

    user = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or "unknown"
    )

    return {
        "event_id": (
            f"WIN-{event['record_number']}"
        ),
        "source": "Windows Security Log",
        "source_event_id": 4688,
        "event_type": "process_execution",
        "user": user,
        "device": (
            event.get("computer")
            or socket.gethostname()
        ),
        "process": process_name,
        "process_path": (
            process_path or None
        ),
        "parent_process": parent_process,
        "command_line": (
            data.get("CommandLine")
            or None
        ),

        # A process starting does NOT mean it is malicious.
        "status": "observed",

        "timestamp": event.get(
            "timestamp"
        ),
        "record_number": event[
            "record_number"
        ],
    }


def _normalize_event(
    event: dict
) -> dict | None:
    """
    Convert Windows Security events into
    the common SOC event format.
    """

    event_id = event.get(
        "event_id"
    )

    if event_id == 4625:
        return _normalize_4625(
            event
        )

    if event_id == 4688:
        return _normalize_4688(
            event
        )

    return None


async def stream_windows_events(
    poll_interval: float = 2.0
) -> AsyncGenerator[dict, None]:
    """
    Continuously monitor new Windows Security events.

    Historical events are ignored.

    Only new Event IDs 4625 and 4688
    are emitted.
    """

    print(
        "\nWindows Security Event Source started."
    )

    print(
        "Monitoring Event IDs: 4625, 4688"
    )

    print(
        f"Polling every {poll_interval} seconds."
    )

    # Start from the newest existing event.
    # This prevents old historical events from
    # appearing as live SOC activity.

    last_record_number = (
        await asyncio.to_thread(
            _query_latest_record_number
        )
    )

    print(
        "Starting after Windows Event Record: "
        f"{last_record_number}"
    )

    while True:
        try:
            new_events = (
                await asyncio.to_thread(
                    _query_new_security_events,
                    last_record_number
                )
            )

            for raw_event in new_events:
                record_number = (
                    raw_event[
                        "record_number"
                    ]
                )

                if (
                    record_number
                    <= last_record_number
                ):
                    continue

                last_record_number = (
                    record_number
                )

                normalized = (
                    _normalize_event(
                        raw_event
                    )
                )

                if normalized is not None:
                    yield normalized

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            print(
                "\nWindows Event Source Error:"
            )

            print(
                str(exc)
            )

            print(
                f"Retrying in "
                f"{poll_interval} seconds..."
            )

        await asyncio.sleep(
            poll_interval
        )
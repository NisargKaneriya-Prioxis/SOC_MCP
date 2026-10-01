import xml.etree.ElementTree as ET

import win32evtlog


SECURITY_LOG = "Security"

EVENT_NAMESPACE = {
    "e": (
        "http://schemas.microsoft.com/"
        "win/2004/08/events/event"
    )
}


def _parse_event_xml(
    xml: str
) -> dict:

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

    timestamp = None

    if time_element is not None:
        timestamp = time_element.attrib.get(
            "SystemTime"
        )

    computer = (
        computer_element.text
        if (
            computer_element is not None
            and computer_element.text
        )
        else None
    )

    event_data = {}

    for element in root.findall(
        "e:EventData/e:Data",
        EVENT_NAMESPACE
    ):

        name = element.attrib.get(
            "Name"
        )

        if name:
            event_data[name] = (
                element.text or ""
            )

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": computer,
        "data": event_data
    }


def _clean_value(
    value
):

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


def get_windows_login_history(
    user: str,
    lookback_hours: int = 24,
    max_events: int = 100
) -> dict:
    """
    Retrieve real Windows authentication history.

    4624 = successful authentication
    4625 = failed authentication
    """

    if not user:
        return {
            "success": False,
            "source": "Windows Security Log",
            "error": "User is required."
        }

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
        "or EventID=4625"
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

            data = parsed.get(
                "data",
                {}
            )

            target_user = (
                data.get(
                    "TargetUserName",
                    ""
                )
            )

            # Only return evidence for the requested user.
            if (
                target_user.casefold()
                != user.casefold()
            ):
                continue

            event_id = parsed[
                "event_id"
            ]

            record = {
                "event_id": event_id,

                "result": (
                    "success"
                    if event_id == 4624
                    else "failure"
                ),

                "timestamp": parsed.get(
                    "timestamp"
                ),

                "user": target_user,

                "device": parsed.get(
                    "computer"
                ),

                "source_ip": _clean_value(
                    data.get(
                        "IpAddress"
                    )
                ),

                "logon_type": _clean_value(
                    data.get(
                        "LogonType"
                    )
                ),

                "workstation": _clean_value(
                    data.get(
                        "WorkstationName"
                    )
                ),

                "authentication_package": (
                    _clean_value(
                        data.get(
                            "AuthenticationPackageName"
                        )
                    )
                ),

                "failure_reason": None,

                "status_code": None
            }

            if event_id == 4625:

                record[
                    "failure_reason"
                ] = _clean_value(
                    data.get(
                        "FailureReason"
                    )
                )

                record[
                    "status_code"
                ] = _clean_value(
                    data.get(
                        "Status"
                    )
                )

            records.append(
                record
            )

            if len(records) >= max_events:
                break

        if len(records) >= max_events:
            break

    records.sort(
        key=lambda item: (
            item.get("timestamp")
            or ""
        )
    )

    successful_logins = sum(
        1
        for record in records
        if record["result"]
        == "success"
    )

    failed_logins = sum(
        1
        for record in records
        if record["result"]
        == "failure"
    )

    return {
        "success": True,

        "source":
            "Windows Security Log",

        "data": {
            "user": user,

            "lookback_hours":
                lookback_hours,

            "total_events":
                len(records),

            "successful_logins":
                successful_logins,

            "failed_logins":
                failed_logins,

            "events":
                records
        }
    }
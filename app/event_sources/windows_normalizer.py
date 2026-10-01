import socket


def normalize_windows_event(
    event: dict
) -> dict | None:
    """
    Convert a parsed Windows event into
    the common SOC event structure.
    """

    event_id = event.get(
        "event_id"
    )

    if event_id == 4624:
        return _normalize_4624(
            event
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


# =========================================================
# 4624
# Successful Login
# =========================================================

def _normalize_4624(
    event: dict
) -> dict:

    data = event.get(
        "data",
        {}
    )

    return {
        "event_id":
            f"WIN-{event['record_number']}",

        "source":
            "Windows Security Log",

        "source_event_id":
            4624,

        "event_type":
            "login_success",

        "timestamp":
            event.get("timestamp"),

        "user":
            data.get(
                "TargetUserName"
            ) or "unknown",

        "device":
            event.get(
                "computer"
            ) or socket.gethostname(),

        "source_ip":
            _clean_value(
                data.get(
                    "IpAddress"
                )
            ),

        "logon_type":
            data.get(
                "LogonType"
            ),

        "workstation_name":
            _clean_value(
                data.get(
                    "WorkstationName"
                )
            ),

        "authentication_package":
            data.get(
                "AuthenticationPackageName"
            ),

        "process_name":
            _clean_value(
                data.get(
                    "ProcessName"
                )
            ),

        "status":
            "observed",

        "event_classification":
            "authentication",

        "record_number":
            event["record_number"]
    }


# =========================================================
# 4625
# Failed Login
# =========================================================

def _normalize_4625(
    event: dict
) -> dict:

    data = event.get(
        "data",
        {}
    )

    return {
        "event_id":
            f"WIN-{event['record_number']}",

        "source":
            "Windows Security Log",

        "source_event_id":
            4625,

        "event_type":
            "login_failed",

        "timestamp":
            event.get("timestamp"),

        "user":
            data.get(
                "TargetUserName"
            ) or "unknown",

        "device":
            event.get(
                "computer"
            ) or socket.gethostname(),

        "source_ip":
            _clean_value(
                data.get(
                    "IpAddress"
                )
            ),

        "logon_type":
            data.get(
                "LogonType"
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

        "process_name":
            _clean_value(
                data.get(
                    "ProcessName"
                )
            ),

        "workstation_name":
            _clean_value(
                data.get(
                    "WorkstationName"
                )
            ),

        "authentication_package":
            data.get(
                "AuthenticationPackageName"
            ),

        "status":
            "observed",

        "event_classification":
            "authentication",

        "record_number":
            event["record_number"]
    }


# =========================================================
# 4688
# Process Creation
# =========================================================

def _normalize_4688(
    event: dict
) -> dict:

    data = event.get(
        "data",
        {}
    )

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

    parent_process = (
        data.get(
            "ParentProcessName"
        )
        or data.get(
            "CreatorProcessName"
        )
    )

    user = (
        data.get(
            "TargetUserName"
        )
        or data.get(
            "SubjectUserName"
        )
        or "unknown"
    )

    return {
        "event_id":
            f"WIN-{event['record_number']}",

        "source":
            "Windows Security Log",

        "source_event_id":
            4688,

        "event_type":
            "process_execution",

        "timestamp":
            event.get(
                "timestamp"
            ),

        "user":
            user,

        "device":
            event.get(
                "computer"
            ) or socket.gethostname(),

        "process":
            process_name,

        "process_path":
            _clean_value(
                process_path
            ),

        "parent_process":
            _clean_value(
                parent_process
            ),

        "command_line":
            _clean_value(
                data.get(
                    "CommandLine"
                )
            ),

        "status":
            "observed",

        "event_classification":
            "process",

        "record_number":
            event[
                "record_number"
            ]
    }


# =========================================================
# Helpers
# =========================================================

def _clean_value(
    value
):
    """
    Convert common Windows placeholder values
    into None.
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
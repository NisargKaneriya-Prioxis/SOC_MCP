import socket
import subprocess
import json


def get_windows_endpoint_activity(
    device: str
) -> dict:
    """
    Retrieve current endpoint information from
    the local Windows machine.

    This provider is observation-only.
    """

    local_device = socket.gethostname()

    # -------------------------------------------------
    # Ensure Agent is querying the local endpoint
    # -------------------------------------------------

    if (
        device
        and device.casefold()
        != local_device.casefold()
    ):
        return {
            "success": False,
            "source": "Windows Endpoint Provider",
            "error": (
                f"Device {device} is not the "
                "local Windows endpoint."
            )
        }

    # -------------------------------------------------
    # Query current Windows processes using
    # supported PowerShell CIM interface.
    # -------------------------------------------------

    powershell_command = """
    Get-CimInstance Win32_Process |
    Select-Object `
        Name,
        ProcessId,
        ParentProcessId,
        ExecutablePath,
        CommandLine,
        CreationDate |
    ConvertTo-Json -Depth 4 -Compress
    """

    try:

        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                powershell_command
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "source": "Windows Endpoint Provider",
            "error": (
                "Windows process query timed out."
            )
        }

    if completed.returncode != 0:

        return {
            "success": False,
            "source": "Windows Endpoint Provider",
            "error": (
                completed.stderr.strip()
                or
                "Windows process query failed."
            )
        }

    output = completed.stdout.strip()

    if not output:

        processes = []

    else:

        try:

            processes = json.loads(
                output
            )

        except json.JSONDecodeError:

            return {
                "success": False,
                "source": "Windows Endpoint Provider",
                "error": (
                    "Windows returned invalid "
                    "process telemetry."
                )
            }

    # PowerShell returns one object instead of
    # a list when only one record is present.
    if isinstance(
        processes,
        dict
    ):
        processes = [
            processes
        ]

    # -------------------------------------------------
    # Normalize
    # -------------------------------------------------

    normalized_processes = []

    for process in processes:

        normalized_processes.append(
            {
                "name": process.get(
                    "Name"
                ),

                "process_id": process.get(
                    "ProcessId"
                ),

                "parent_process_id": (
                    process.get(
                        "ParentProcessId"
                    )
                ),

                "executable_path": (
                    process.get(
                        "ExecutablePath"
                    )
                ),

                "command_line": (
                    process.get(
                        "CommandLine"
                    )
                ),

                "creation_date": (
                    process.get(
                        "CreationDate"
                    )
                )
            }
        )

    return {
        "success": True,

        "source":
            "Windows Endpoint Provider",

        "data": {
            "device":
                local_device,

            "process_count":
                len(
                    normalized_processes
                ),

            "processes":
                normalized_processes
        }
    }
import socket

from app.providers.endpoint.windows_endpoint import (
    get_windows_endpoint_activity
)


def main():

    device = socket.gethostname()

    result = get_windows_endpoint_activity(
        device
    )

    print(
        f"\nSource: "
        f"{result.get('source', 'Unknown')}"
    )

    if not result.get(
        "success"
    ):

        print(
            f"Error: "
            f"{result.get('error')}"
        )

        return

    data = result.get(
        "data",
        {}
    )

    print(
        f"Device: "
        f"{data.get('device', 'Unknown')}"
    )

    print(
        f"Processes: "
        f"{data.get('process_count', 0)}"
    )

    print(
        "\nSample process names:"
    )

    for process in (
        data.get(
            "processes",
            []
        )[:10]
    ):

        print(
            f"- {process.get('name')}"
        )


if __name__ == "__main__":
    main()
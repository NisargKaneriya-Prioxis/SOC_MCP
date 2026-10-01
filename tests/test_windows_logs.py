from app.providers.logs.windows_logs import (
    search_windows_security_logs
)


def main():

    incident_id = input(
        "Enter incident ID: "
    ).strip()

    result = search_windows_security_logs(
        incident_id=incident_id,
        lookback_hours=24,
        max_events=20
    )

    print(
        f"\nSource: "
        f"{result.get('source', 'Unknown')}"
    )

    if not result.get(
        "success",
        False
    ):

        print(
            f"Error: "
            f"{result.get('error', 'Unknown error')}"
        )

        return

    print(
        f"Incident: "
        f"{result.get('incident_id')}"
    )

    print(
        f"Matching Events: "
        f"{result.get('count', 0)}"
    )

    print(
        "\nEvent Summary:"
    )

    for event in result.get(
        "data",
        []
    ):

        print(
            f"- {event.get('timestamp')} "
            f"| {event.get('event_id')} "
            f"| {event.get('event_type')}"
        )


if __name__ == "__main__":
    main()
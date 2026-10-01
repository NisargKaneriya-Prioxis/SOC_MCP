from app.providers.logs.factory import (
    search_security_logs
)


def main():

    incident_id = input(
        "Enter incident ID: "
    ).strip()

    result = search_security_logs(
        incident_id
    )

    print(
        f"\nSource: {result.get('source')}"
    )

    print(
        f"Matching Events: "
        f"{result.get('count', 0)}"
    )

    for event in result.get(
        "data",
        []
    ):
        print(event)


if __name__ == "__main__":
    main()
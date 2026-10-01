from app.providers.identity.windows_identity import (
    get_windows_login_history
)


def main():

    user = input(
        "Enter Windows username: "
    ).strip()

    result = get_windows_login_history(
        user=user,
        lookback_hours=24,
        max_events=20
    )

    print(
        f"\nSource: "
        f"{result.get('source')}"
    )

    if not result.get(
        "success"
    ):

        print(
            result.get(
                "error"
            )
        )

        return

    data = result.get(
        "data",
        {}
    )

    print(
        "\nAuthentication Summary"
    )

    print(
        f"Successful: "
        f"{data.get('successful_logins', 0)}"
    )

    print(
        f"Failed: "
        f"{data.get('failed_logins', 0)}"
    )

    print(
        f"Total: "
        f"{data.get('total_events', 0)}"
    )


if __name__ == "__main__":
    main()
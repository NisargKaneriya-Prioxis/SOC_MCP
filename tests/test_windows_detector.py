from app.monitoring.detector import (
    DetectionEngine
)


def build_failure(
    number: int
) -> dict:

    return {
        "event_id":
            f"TEST-{number}",

        "source":
            "Windows Security Log",

        "source_event_id":
            4625,

        "event_type":
            "login_failed",

        "user":
            "test-user",

        "device":
            "TEST-PC",

        "source_ip":
            "192.0.2.10",

        "timestamp":
            (
                "2026-09-30T08:"
                f"{number:02d}:00+00:00"
            ),

        "status":
            "observed"
    }


def test_failure_threshold():

    detector = DetectionEngine(
        failure_threshold=5,
        failure_window_minutes=10
    )

    results = []

    for number in range(
        1,
        6
    ):

        result = detector.analyze(
            build_failure(
                number
            )
        )

        results.append(
            result
        )

    # First 4 failures should NOT alert.
    for result in results[:4]:

        assert (
            result.detected
            is False
        )

    # Fifth failure should trigger.
    assert (
        results[4].detected
        is True
    )

    assert (
        results[4].rule_id
        == "DET-WIN-001"
    )


def test_duplicate_suppression():

    detector = DetectionEngine(
        failure_threshold=5,
        failure_window_minutes=10
    )

    for number in range(
        1,
        6
    ):

        result = detector.analyze(
            build_failure(
                number
            )
        )

    assert result.detected is True

    sixth = detector.analyze(
        build_failure(
            6
        )
    )

    assert sixth.detected is False
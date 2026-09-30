from app.agent.risk_engine import calculate_risk


def test_high_risk_incident():

    login = {
        "failed_logins": 15,
        "suspicious_location": True,
        "mfa": False
    }

    endpoint = {
        "status": "suspicious",
        "malware_detected": True
    }

    network = {
        "reputation": "malicious"
    }

    result = calculate_risk(
        login,
        endpoint,
        network
    )

    assert result["level"] == "HIGH"
    assert result["score"] >= 5


def test_low_risk_incident():

    login = {
        "failed_logins": 1,
        "suspicious_location": False,
        "mfa": True
    }

    endpoint = {
        "status": "normal",
        "malware_detected": False
    }

    network = {
        "reputation": "clean"
    }

    result = calculate_risk(
        login,
        endpoint,
        network
    )

    assert result["level"] == "LOW"
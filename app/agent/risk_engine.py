from typing import Any


def calculate_risk(
    login: dict[str, Any],
    endpoint: dict[str, Any],
    network: dict[str, Any]
) -> dict:

    score = 0
    reasons = []

    # Authentication risk
    if login.get("failed_logins", 0) >= 10:
        score += 1
        reasons.append(
            "High number of failed login attempts"
        )

    if login.get("suspicious_location"):
        score += 1
        reasons.append(
            "Login detected from an unusual location"
        )

    if login.get("mfa") is False:
        score += 1
        reasons.append(
            "MFA was not used"
        )

    # Endpoint risk
    if endpoint.get("status") == "suspicious":
        score += 2
        reasons.append(
            "Suspicious endpoint process execution detected"
        )

    if endpoint.get("malware_detected"):
        score += 2
        reasons.append(
            "Endpoint security detected possible malware"
        )

    # Network risk
    if network.get("reputation", "").lower() == "malicious":
        score += 2
        reasons.append(
            "Communication with malicious destination detected"
        )

    if score >= 5:
        level = "HIGH"

    elif score >= 2:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }
    
def generate_recommendations(
    login: dict,
    endpoint: dict,
    network: dict
) -> list:
    recommendations = []

    if login.get("suspicious_location"):
        recommendations.append(
            "Review the suspicious user authentication."
        )

    if login.get("mfa") is False:
        recommendations.append(
            "Enable MFA for the affected account."
        )

    if login.get("failed_logins", 0) >= 10:
        recommendations.append(
            "Reset credentials and review failed authentication attempts."
        )

    if endpoint.get("status") == "suspicious":
        recommendations.append(
            "Isolate the affected endpoint for further investigation."
        )

    if endpoint.get("malware_detected"):
        recommendations.append(
            "Perform malware analysis on the affected endpoint."
        )

    if network.get("reputation", "").lower() == "malicious":
        recommendations.append(
            "Block the malicious destination at the network security layer."
        )

    return recommendations
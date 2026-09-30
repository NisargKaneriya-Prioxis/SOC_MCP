def generate_report(
    incident_id: str,
    alert: dict,
    login: dict,
    endpoint: dict,
    network: dict,
    logs: list,
    risk: dict,
    recommendations: list[str]
) -> str:

    report = f"""
SECURITY INCIDENT INVESTIGATION REPORT

Incident ID:
{incident_id}

==================================================
ALERT INFORMATION
==================================================

Alert:
{alert.get("alert")}

Original Severity:
{alert.get("severity")}

Affected User:
{alert.get("user")}

Affected Device:
{alert.get("device")}

==================================================
AUTHENTICATION EVIDENCE
==================================================

Failed Logins:
{login.get("failed_logins")}

Login Country:
{login.get("country")}

Usual Country:
{login.get("usual_country")}

MFA Used:
{login.get("mfa")}

Suspicious Location:
{login.get("suspicious_location")}

==================================================
ENDPOINT EVIDENCE
==================================================

Process:
{endpoint.get("process")}

Parent Process:
{endpoint.get("parent_process")}

Status:
{endpoint.get("status")}

Malware Detected:
{endpoint.get("malware_detected")}

==================================================
NETWORK EVIDENCE
==================================================

Destination IP:
{network.get("destination_ip")}

Destination Port:
{network.get("destination_port")}

Reputation:
{network.get("reputation")}

Firewall Action:
{network.get("action")}

==================================================
SECURITY TIMELINE
==================================================
"""

    for log in logs:

        report += (
            f'\n{log.get("timestamp")} - '
            f'{log.get("event")}'
        )

    report += f"""

==================================================
RISK ASSESSMENT
==================================================

Risk Score:
{risk.get("score")}

Risk Level:
{risk.get("level")}

Reasons:
"""

    for reason in risk.get("reasons", []):
        report += f"\n- {reason}"

    report += """

==================================================
RECOMMENDED ACTIONS
==================================================
"""

    for index, recommendation in enumerate(
        recommendations,
        start=1
    ):
        report += f"\n{index}. {recommendation}"

    return report.strip()
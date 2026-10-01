import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import streamlit as st


st.set_page_config(
    page_title="SOC Console",
    layout="wide",
)


@st.cache_data(ttl=5, show_spinner=False)
def get_json(base_url: str, path: str) -> Any:
    request = Request(
        f"{base_url.rstrip('/')}{path}",
        headers={"Accept": "application/json"},
    )

    try:
        with urlopen(request, timeout=5) as response:
            return json.load(response)
    except HTTPError as error:
        raise RuntimeError(
            f"API returned HTTP {error.code} for {path}."
        ) from error
    except URLError as error:
        raise RuntimeError(
            f"Cannot reach API at {base_url}."
        ) from error
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"API returned invalid JSON for {path}."
        ) from error


def load_or_stop(base_url: str, path: str) -> Any:
    try:
        return get_json(base_url, path)
    except RuntimeError as error:
        st.error(str(error))
        st.stop()


def incident_label(incident: dict[str, Any]) -> str:
    return " | ".join(
        str(value)
        for value in (
            incident.get("incident_id", "Unknown"),
            incident.get("severity", "Unknown"),
            incident.get("alert", "Untitled"),
        )
    )


base_url = st.sidebar.text_input(
    "API URL",
    value=os.getenv("SOC_API_URL", "http://127.0.0.1:8000"),
)

if st.sidebar.button("Refresh", use_container_width=True):
    st.cache_data.clear()
    st.rerun()

health = load_or_stop(base_url, "/api/health")
monitor = health.get("monitor", {})
monitor_running = monitor.get("running", False)

st.title("SOC Console")
st.caption(
    f"API {health.get('status', 'unknown')} | "
    f"Monitor {'running' if monitor_running else 'stopped'}"
)

overview_tab, incidents_tab, tickets_tab, audit_tab = st.tabs(
    ["Overview", "Incidents", "Tickets", "Audit"]
)

with overview_tab:
    summary = load_or_stop(base_url, "/api/system/summary")
    metrics = st.columns(4)
    metrics[0].metric("Incidents", summary.get("total_incidents", 0))
    metrics[1].metric("High risk", summary.get("high_risk_incidents", 0))
    metrics[2].metric("Investigating", summary.get("active_investigations", 0))
    metrics[3].metric("Tickets", summary.get("tickets_created", 0))

    st.subheader("Providers")
    providers = load_or_stop(base_url, "/api/providers/status")
    provider_rows = [
        {"Provider": name.replace("_", " ").title(), "Source": source}
        for name, source in providers.items()
    ]
    st.dataframe(provider_rows, hide_index=True, use_container_width=True)

with incidents_tab:
    incidents = load_or_stop(base_url, "/api/incidents")

    if not incidents:
        st.info("No incidents found.")
    else:
        selected_incident = st.selectbox(
            "Incident",
            incidents,
            format_func=incident_label,
        )

        incident_id = selected_incident.get("incident_id", "Unknown")
        st.subheader(str(incident_id))
        incident_metrics = st.columns(3)
        incident_metrics[0].metric(
            "Severity", selected_incident.get("severity", "Unknown")
        )
        incident_metrics[1].metric(
            "Status", selected_incident.get("status", "Unknown")
        )
        incident_metrics[2].metric(
            "Risk score",
            selected_incident.get("risk_assessment", {}).get("score", "-"),
        )

        st.write(selected_incident.get("alert", "Untitled incident"))
        st.caption(
            f"User: {selected_incident.get('user', 'Unknown')} | "
            f"Device: {selected_incident.get('device', 'Unknown')}"
        )

        report = selected_incident.get("investigation_result", {}).get("report")
        if report:
            with st.expander("Investigation report"):
                st.markdown(report)

        with st.expander("Detections"):
            st.dataframe(
                selected_incident.get("detections", []),
                hide_index=True,
                use_container_width=True,
            )

        with st.expander("Events"):
            st.json(selected_incident.get("events", []))

with tickets_tab:
    tickets = load_or_stop(base_url, "/api/tickets")

    if not tickets:
        st.info("No tickets found.")
    else:
        for ticket in tickets:
            ticket_id = ticket.get("ticket_id", "Unknown")
            incident_id = ticket.get("incident_id", "Unknown")
            with st.expander(
                f"{ticket_id} | {ticket.get('severity', 'Unknown')} | "
                f"{ticket.get('status', 'Unknown')}"
            ):
                st.caption(f"Incident: {incident_id}")
                st.write(ticket.get("summary", "No summary."))
                recommendations = ticket.get("recommendations", [])
                if recommendations:
                    st.markdown(
                        "\n".join(
                            f"- {recommendation}"
                            for recommendation in recommendations
                        )
                    )

with audit_tab:
    audit_events = load_or_stop(base_url, "/api/audit")

    if not audit_events:
        st.info("No audit events found.")
    else:
        st.dataframe(audit_events, hide_index=True, use_container_width=True)
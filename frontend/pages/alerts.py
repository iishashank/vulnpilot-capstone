"""
Alerts — real-time security alert inbox.
"""
import requests
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output
try:
    from frontend.config import API_BASE_URL, API_REQUEST_HEADERS
except ImportError:
    from config import API_BASE_URL
    API_REQUEST_HEADERS = {}

try:
    from frontend.components.ui import page_header, surface, empty_state, pill
except ImportError:
    from components.ui import page_header, surface, empty_state, pill

API = API_BASE_URL
dash.register_page(__name__, path="/alerts", name="Alerts")


SEVERITY_CONFIG = {
    "CRITICAL": {"color": "#ff1744", "bg": "rgba(255,23,68,0.12)", "border": "rgba(255,23,68,0.3)", "icon": "bi-radioactive"},
    "HIGH":     {"color": "#ff9100", "bg": "rgba(255,145,0,0.12)",  "border": "rgba(255,145,0,0.3)",  "icon": "bi-exclamation-triangle-fill"},
    "MEDIUM":   {"color": "#00e5ff", "bg": "rgba(0,229,255,0.10)",  "border": "rgba(0,229,255,0.25)", "icon": "bi-shield-exclamation"},
    "LOW":      {"color": "#00e676", "bg": "rgba(0,230,118,0.10)",  "border": "rgba(0,230,118,0.25)", "icon": "bi-info-circle-fill"},
}

TRIGGER_LABELS = {
    "new_critical": "New Critical Finding",
    "new_high":     "New High Finding",
    "new_kev":      "KEV Escalation 🔥",
    "new_asset":    "New Asset Discovered",
    "ip_change":    "IP Address Changed",
    "port_change":  "New Port Opened",
}


def layout(**kwargs):
    return dbc.Container([
        dcc.Interval(id="alerts-tick", interval=6000, n_intervals=0),
        dcc.Store(id="alerts-ack-store"),
        page_header(
            "Security alerts",
            "Review change-driven alerts emitted by the diff engine and acknowledge them after triage.",
            icon="bi-bell-fill",
            eyebrow="Alerting",
            meta=[pill("Diff-driven", "warning")],
            actions=[
                dbc.Select(
                    id="alerts-severity-filter",
                    options=[
                        {"label": "All severities", "value": ""},
                        {"label": "Critical", "value": "CRITICAL"},
                        {"label": "High", "value": "HIGH"},
                        {"label": "Medium", "value": "MEDIUM"},
                        {"label": "Low", "value": "LOW"},
                    ],
                    value="",
                    style={"maxWidth": "220px"},
                ),
            ],
        ),
        html.Div(id="alerts-ack-feedback", className="mb-3"),
        surface(html.Div(id="alerts-list"), title="Alert inbox", subtitle="Alerts remain visible after acknowledgement for auditability.", icon="bi-inboxes"),
    ], fluid=True, className="py-2")


@dash.callback(
    Output("alerts-list", "children"),
    Input("alerts-tick", "n_intervals"),
    Input("alerts-severity-filter", "value"),
    Input("alerts-ack-store", "data"),
)
def refresh_alerts(_, severity_filter, _ack):
    try:
        params = {"unacked_only": 0}
        if severity_filter:
            params["severity"] = severity_filter
        alerts = requests.get(f"{API}/alerts", params=params, timeout=3).json().get("alerts", [])
    except Exception:
        return dbc.Alert("Backend not reachable.", color="warning")

    if not alerts:
        return empty_state("All clear", "The diff engine has not emitted any alerts for the current filter set.", icon="bi-shield-check")

    items = []
    for a in alerts:
        sev = a["severity"]
        cfg = SEVERITY_CONFIG.get(sev, SEVERITY_CONFIG["MEDIUM"])
        trigger_label = TRIGGER_LABELS.get(a["trigger_type"], a["trigger_type"].replace("_", " ").title())
        acked = a["acknowledged"]

        card = dbc.Card(dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.I(className=f"bi {cfg['icon']} me-2", style={"color": cfg["color"]}),
                        dbc.Badge(sev, style={"backgroundColor": cfg["bg"], "borderColor": cfg["border"],
                                              "color": cfg["color"], "border": f"1px solid {cfg['border']}"},
                                  className="me-2 rounded-pill"),
                        dbc.Badge(trigger_label, color="dark", className="opacity-75 small"),
                        html.Span(" ✓ Acknowledged", className="text-muted small ms-2") if acked else "",
                    ], className="d-flex align-items-center mb-1"),
                    html.Div(html.Strong(a["title"], style={"color": cfg["color"]}), className="mb-1"),
                    html.Small(a.get("detail", "")[:150], className="text-muted d-block"),
                ], md=9),
                dbc.Col([
                    html.Small(a.get("created_at", "")[:19], className="text-muted d-block text-end font-monospace mb-2"),
                    dbc.Button(
                        [html.I(className="bi bi-check2-circle me-1"), "Acknowledge"],
                        id={"type": "ack-btn", "index": a["id"]},
                        color="success", size="sm", outline=True,
                        className="w-100 fw-bold",
                        disabled=acked,
                    ),
                ], md=3, className="d-flex flex-column align-items-end justify-content-between"),
            ], align="center"),
        ]), style={
            "background": cfg["bg"],
            "border": f"1px solid {cfg['border']}",
            "borderRadius": "12px",
            "marginBottom": "10px",
            "opacity": "0.6" if acked else "1",
        })
        items.append(card)

    return html.Div(items)


@dash.callback(
    Output("alerts-ack-store", "data"),
    Output("alerts-ack-feedback", "children"),
    Input({"type": "ack-btn", "index": dash.ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def acknowledge_alert(n_clicks_list):
    from dash import callback_context
    triggered = callback_context.triggered_id
    if not triggered:
        return dash.no_update, ""
    alert_id = triggered["index"]
    try:
        requests.post(f"{API}/alerts/{alert_id}/acknowledge", headers=API_REQUEST_HEADERS, timeout=3)
        return alert_id, dbc.Alert([html.I(className="bi bi-check-circle me-2"), "Alert acknowledged."],
                                   color="success", duration=3000, className="py-2")
    except Exception:
        return dash.no_update, dbc.Alert("Failed to acknowledge.", color="danger", duration=3000)

"""
Sites — manage monitored domains / target scopes.
"""

import requests
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output, State, ctx
try:
    from frontend.config import API_BASE_URL, API_REQUEST_HEADERS
except ImportError:
    from config import API_BASE_URL
    API_REQUEST_HEADERS = {}

try:
    from frontend.components.ui import page_header, surface, empty_state, pill, metric_tile
except ImportError:
    from components.ui import page_header, surface, empty_state, pill, metric_tile

API = API_BASE_URL
dash.register_page(__name__, path="/sites", name="Sites")


def layout(**kwargs):
    return dbc.Container(
        [
            dcc.Interval(id="sites-tick", interval=5000, n_intervals=0),
            page_header(
                "Managed sites",
                "Register the scopes you own, assign scan policy, and trigger recurring monitoring runs from one place.",
                icon="bi-globe2",
                eyebrow="Monitoring",
                meta=[pill("Scheduler-backed", "success"), pill("Authorized scopes only", "warning")],
                actions=[
                    dbc.Button([html.I(className="bi bi-plus-circle me-2"), "Add site"], id="add-site-btn", color="primary", className="vp-action-button"),
                ],
            ),
            html.Div(id="sites-feedback", className="mb-4"),
            surface(
                [
                    html.Div(id="sites-summary", className="vp-stat-grid mb-4"),
                    html.Div(id="sites-table"),
                ],
                title="Registered monitoring targets",
                subtitle="Each row represents a schedulable site profile with run status, alerts, and next planned execution.",
                icon="bi-diagram-3",
            ),
            dbc.Modal(
                [
                    dbc.ModalHeader(dbc.ModalTitle([html.I(className="bi bi-shield-plus me-2 text-primary"), "Register new site"]), close_button=True),
                    dbc.ModalBody(
                        [
                            dbc.Alert(
                                [
                                    html.I(className="bi bi-exclamation-triangle-fill me-2"),
                                    html.Strong("Authorized targets only. "),
                                    "Only add domains, IPs, or subnets that you own or have written permission to scan.",
                                ],
                                color="warning",
                                className="mb-3",
                            ),
                            dbc.Label("Site name", className="fw-semibold mb-2"),
                            dbc.Input(id="site-name", placeholder="e.g. Internal Demo Lab", className="mb-3"),
                            dbc.Label("Primary domain / IP range", className="fw-semibold mb-2"),
                            dbc.Input(id="site-domain", placeholder="e.g. 127.0.0.1 or example.com", className="mb-3"),
                            dbc.Label("Allowed scan scopes", className="fw-semibold mb-2"),
                            dbc.Textarea(
                                id="site-scopes",
                                placeholder="Comma-separated values. Leave equal to the primary domain/IP if you do not need multiple scopes.",
                                rows=3,
                                className="mb-3",
                            ),
                            dbc.Row(
                                [
                                    dbc.Col(
                                        [
                                            dbc.Label("Scan policy", className="fw-semibold mb-2"),
                                            dbc.Select(
                                                id="site-policy",
                                                options=[
                                                    {"label": "Safe", "value": "safe"},
                                                    {"label": "Balanced", "value": "balanced"},
                                                ],
                                                value="safe",
                                            ),
                                        ],
                                        md=6,
                                    ),
                                    dbc.Col(
                                        [
                                            dbc.Label("Schedule", className="fw-semibold mb-2"),
                                            dbc.Select(
                                                id="site-schedule",
                                                options=[
                                                    {"label": "Manual only", "value": "manual"},
                                                    {"label": "Daily", "value": "daily"},
                                                    {"label": "Weekly", "value": "weekly"},
                                                ],
                                                value="manual",
                                            ),
                                        ],
                                        md=6,
                                    ),
                                ],
                                className="mb-3",
                            ),
                            dbc.Checklist(
                                options=[{"label": "I confirm written authorization for this target.", "value": "confirmed"}],
                                id="site-auth-check",
                                value=[],
                                className="mb-0",
                            ),
                        ]
                    ),
                    dbc.ModalFooter(
                        [
                            dbc.Button("Cancel", id="close-site-modal", outline=True, color="secondary", className="vp-action-button"),
                            dbc.Button([html.I(className="bi bi-shield-check me-2"), "Register site"], id="submit-site-btn", color="success", className="vp-action-button"),
                        ]
                    ),
                ],
                id="add-site-modal",
                is_open=False,
                size="lg",
                backdrop="static",
            ),
        ],
        fluid=True,
        className="py-2",
    )


@dash.callback(
    Output("add-site-modal", "is_open"),
    Input("add-site-btn", "n_clicks"),
    Input("close-site-modal", "n_clicks"),
    State("add-site-modal", "is_open"),
    prevent_initial_call=True,
)
def toggle_modal(n_open, n_close, is_open):
    return not is_open


@dash.callback(
    Output("sites-feedback", "children"),
    Output("add-site-modal", "is_open", allow_duplicate=True),
    Input("submit-site-btn", "n_clicks"),
    State("site-name", "value"),
    State("site-domain", "value"),
    State("site-scopes", "value"),
    State("site-policy", "value"),
    State("site-schedule", "value"),
    State("site-auth-check", "value"),
    prevent_initial_call=True,
)
def create_site(_, name, domain, scopes, policy, schedule, auth_check):
    if not auth_check or "confirmed" not in auth_check:
        return dbc.Alert("You must confirm authorization before registering a site.", color="danger"), True
    if not domain:
        return dbc.Alert("Primary domain / IP range is required.", color="danger"), True

    payload = {
        "name": name or domain,
        "primary_domain": domain,
        "allowed_scopes": scopes or domain,
        "policy": policy,
        "schedule": schedule,
        "auth_confirmed": True,
    }
    try:
        response = requests.post(f"{API}/sites", json=payload, headers=API_REQUEST_HEADERS, timeout=5)
        if response.status_code == 200:
            site_id = response.json().get("site_id", "")[:8]
            return dbc.Alert([html.I(className="bi bi-check-circle-fill me-2"), f"Site registered. ID: {site_id}"], color="success"), False
        return dbc.Alert(f"Error: {response.json().get('detail', 'Unknown error')}", color="danger"), True
    except Exception as exc:
        return dbc.Alert(f"Backend not reachable: {exc}", color="danger"), True


@dash.callback(
    Output("sites-summary", "children"),
    Output("sites-table", "children"),
    Input("sites-tick", "n_intervals"),
)
def refresh_sites(_):
    try:
        sites = requests.get(f"{API}/sites", timeout=3).json().get("sites", [])
    except Exception:
        cards = [
            metric_tile("Registered sites", "—", icon="bi-globe2", tone="primary", hint="Backend offline"),
            metric_tile("Scheduled sites", "—", icon="bi-calendar-week", tone="success", hint="Waiting for API"),
            metric_tile("Unacked alerts", "—", icon="bi-bell", tone="warning", hint="No alert counts"),
            metric_tile("Critical findings", "—", icon="bi-shield-slash", tone="danger", hint="No risk summary"),
        ]
        return cards, dbc.Alert("Backend not reachable. Start the API on port 8000.", color="warning")

    scheduled = sum(1 for site in sites if site["schedule"] != "manual")
    unacked_total = sum(site["unacked_alerts"] for site in sites)
    critical_total = sum(site["critical_count"] for site in sites)
    cards = [
        metric_tile("Registered sites", len(sites), icon="bi-globe2", tone="primary", hint="Profiles available for monitoring"),
        metric_tile("Scheduled sites", scheduled, icon="bi-calendar-week", tone="success", hint="Daily or weekly cadence"),
        metric_tile("Unacked alerts", unacked_total, icon="bi-bell", tone="warning", hint="Requires operator review"),
        metric_tile("Critical findings", critical_total, icon="bi-shield-slash", tone="danger", hint="Across monitored scopes"),
    ]

    if not sites:
        return cards, empty_state("No sites registered", "Add your first managed scope to enable recurring scans and diff-aware monitoring.", icon="bi-globe2")

    rows = []
    for site in sites:
        status_color = {
            "—": "secondary",
            "done": "success",
            "running": "primary",
            "queued": "info",
            "failed": "danger",
            "stopped": "warning",
        }.get(site["last_run_status"], "secondary")
        sched_icon = {"manual": "bi-hand-index", "daily": "bi-calendar-day", "weekly": "bi-calendar-week"}.get(site["schedule"], "bi-clock")
        alert_badge = dbc.Badge(f"{site['unacked_alerts']} alerts", color="warning", className="me-2") if site["unacked_alerts"] > 0 else html.Span("—", className="text-muted")
        crit_badge = dbc.Badge(f"{site['critical_count']} critical", color="danger") if site["critical_count"] > 0 else ""

        rows.append(
            html.Tr(
                [
                    html.Td(
                        [
                            html.Div(html.Strong(site["name"])),
                            html.Small(site["primary_domain"], className="text-muted font-monospace"),
                        ]
                    ),
                    html.Td(dbc.Badge(site["policy"].upper(), color="dark", className="border")),
                    html.Td([html.I(className=f"bi {sched_icon} me-2 text-info"), html.Span(site["schedule"].capitalize())]),
                    html.Td(dbc.Badge(site["last_run_status"].upper(), color=status_color)),
                    html.Td([alert_badge, crit_badge]),
                    html.Td(html.Small(site.get("next_scan_at", "—")[:19] if site.get("next_scan_at") not in ("—", "None") else "—", className="text-muted font-monospace")),
                    html.Td(
                        html.Div(
                            [
                                dbc.Button([html.I(className="bi bi-arrow-left-right")], href="/diff", outline=True, color="secondary", size="sm", className="me-2", title="Open diff view"),
                                dbc.Button([html.I(className="bi bi-radar")], id={"type": "scan-site-btn", "index": site["site_id"]}, outline=True, color="success", size="sm", title="Scan now"),
                            ],
                            className="d-flex align-items-center",
                        )
                    ),
                ]
            )
        )

    table = dbc.Table(
        [
            html.Thead(html.Tr([html.Th("Site"), html.Th("Policy"), html.Th("Schedule"), html.Th("Last run"), html.Th("Alerts"), html.Th("Next scan"), html.Th("")])),
            html.Tbody(rows),
        ],
        hover=True,
        responsive=True,
        className="align-middle mb-0",
    )
    return cards, table


@dash.callback(
    Output("sites-feedback", "children", allow_duplicate=True),
    Input({"type": "scan-site-btn", "index": dash.ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def trigger_site_scan(_):
    triggered = ctx.triggered_id
    if not triggered:
        return dash.no_update

    site_id = triggered["index"]
    try:
        response = requests.post(f"{API}/sites/{site_id}/scan", headers=API_REQUEST_HEADERS, timeout=5)
        data = response.json()
        if response.status_code != 200:
            return dbc.Alert(f"Scan failed: {data.get('detail', 'unknown error')}", color="danger")
        run_id = data["run_id"]
        return dbc.Alert(
            [
                html.I(className="bi bi-check-circle-fill me-2"),
                "Site scan queued. ",
                html.A("Open live run", href=f"/run/{run_id}", className="fw-bold"),
            ],
            color="success",
        )
    except Exception as exc:
        return dbc.Alert(f"Could not trigger site scan: {exc}", color="danger")

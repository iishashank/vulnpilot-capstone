"""
New Scan — wizard to configure + launch a scan run.
"""

import requests
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output, State
try:
    from frontend.config import API_BASE_URL, API_REQUEST_HEADERS
except ImportError:
    from config import API_BASE_URL
    API_REQUEST_HEADERS = {}

try:
    from frontend.components.ui import page_header, surface, pill
except ImportError:
    from components.ui import page_header, surface, pill

API = API_BASE_URL

dash.register_page(__name__, path="/new-scan", name="New Scan")


def _profile_item(title, tone, icon, detail):
    return html.Div(
        [
            html.Span(html.I(className=f"bi {icon}"), className="vp-list-icon"),
            html.Div(
                [
                    html.Div([html.Strong(title, className=f"tone-{tone}")]),
                    html.Div(detail, className="vp-muted-note"),
                ]
            ),
        ],
        className="vp-list-item",
    )


layout = dbc.Container(
    [
        page_header(
            "Launch a scan",
            "Define a target scope, choose the scan profile, and start a new backend execution session.",
            icon="bi-crosshair2",
            eyebrow="Execution",
            meta=[pill("Authorization required", "warning"), pill("Profiles available", "primary")],
        ),
        html.Div(
            [
                surface(
                    [
                        dbc.Label("Target scope", className="fw-semibold mb-2"),
                        dbc.Input(
                            id="scope",
                            type="text",
                            placeholder="e.g. 127.0.0.1, 192.168.1.0/24, or example.com",
                            className="mb-4",
                        ),
                        dbc.Label("Execution profile", className="fw-semibold mb-2"),
                        dbc.Select(
                            id="profile",
                            options=[
                                {"label": "Safe", "value": "safe"},
                                {"label": "Balanced", "value": "balanced"},
                                {"label": "Aggressive", "value": "aggressive"},
                            ],
                            value="safe",
                            className="mb-4",
                        ),
                        html.Div(
                            [
                                dbc.Checkbox(id="auth", className="me-2"),
                                dbc.Label("I confirm authorized access to the target scope", className="mb-0"),
                            ],
                            className="d-flex align-items-center mb-4 p-3 rounded-4",
                            style={"background": "rgba(255,185,92,0.08)", "border": "1px solid rgba(255,185,92,0.18)"},
                        ),
                        html.Div(
                            [
                                dbc.Button(
                                    [html.I(className="bi bi-rocket-takeoff me-2"), "Start scan"],
                                    id="start",
                                    color="primary",
                                    className="vp-action-button",
                                ),
                                dbc.Button(
                                    [html.I(className="bi bi-globe2 me-2"), "Go to Sites"],
                                    href="/sites",
                                    outline=True,
                                    color="secondary",
                                    className="vp-action-button",
                                ),
                            ],
                            className="vp-inline-actions",
                        ),
                        html.Div(id="start_out", className="mt-4"),
                    ],
                    title="Scan configuration",
                    subtitle="This launches an ad hoc run immediately and opens the live execution view.",
                    icon="bi-sliders",
                    class_name="h-100",
                ),
                html.Div(
                    [
                        surface(
                            [
                                html.Div(
                                    [
                                        _profile_item("Safe", "success", "bi-shield-check", "Low-noise sweep with minimal footprint and conservative probing."),
                                        _profile_item("Balanced", "warning", "bi-binoculars", "Standard depth for most demos and controlled internal scans."),
                                        _profile_item("Aggressive", "danger", "bi-radioactive", "High-depth enumeration intended for lab environments only."),
                                    ],
                                    className="vp-list",
                                )
                            ],
                            title="Profile reference",
                            subtitle="Choose the profile that matches your environment and risk tolerance.",
                            icon="bi-layers",
                            class_name="mb-4",
                        ),
                        surface(
                            [
                                html.Div(
                                    [
                                        html.Div(
                                            [
                                                html.Span(html.I(className="bi bi-info-circle"), className="vp-list-icon"),
                                                html.Div(
                                                    [
                                                        html.Strong("What happens next"),
                                                        html.P(
                                                            "The backend expands the scope, enumerates reachable services, correlates results against the local vulnerability dataset, and stores a run for later diff analysis.",
                                                            className="vp-muted-note mb-0",
                                                        ),
                                                    ]
                                                ),
                                            ],
                                            className="vp-list-item",
                                        ),
                                        html.Div(
                                            [
                                                html.Span(html.I(className="bi bi-exclamation-triangle"), className="vp-list-icon"),
                                                html.Div(
                                                    [
                                                        html.Strong("Rules of engagement"),
                                                        html.P(
                                                            "Only scan systems you own or have written permission to assess. The UI does not make authorization optional.",
                                                            className="vp-muted-note mb-0",
                                                        ),
                                                    ]
                                                ),
                                            ],
                                            className="vp-list-item",
                                        ),
                                    ],
                                    className="vp-list",
                                )
                            ],
                            title="Operator notes",
                            subtitle="This page is for one-off executions. Use Sites for recurring monitoring.",
                            icon="bi-journal-check",
                        ),
                    ]
                ),
            ],
            className="vp-split-grid",
        ),
    ],
    fluid=True,
    className="py-2",
)


@dash.callback(
    Output("start_out", "children"),
    Input("start", "n_clicks"),
    State("scope", "value"),
    State("profile", "value"),
    State("auth", "value"),
    prevent_initial_call=True,
)
def start_scan(n, scope, profile, auth):
    if not auth:
        return dbc.Alert(
            [html.I(className="bi bi-x-circle me-2"), "You must confirm authorized scope."],
            color="danger",
        )
    if not scope or not scope.strip():
        return dbc.Alert("Please enter a target scope.", color="warning")

    try:
        response = requests.post(
            f"{API}/scan",
            json={"scope": scope.strip(), "profile": profile, "auth_confirmed": True},
            headers=API_REQUEST_HEADERS,
            timeout=5,
        )
        data = response.json()
        if response.status_code != 200:
            return dbc.Alert(data.get("detail", "Scan launch failed."), color="danger")
        run_id = data["run_id"]
    except Exception as exc:
        return dbc.Alert(f"Backend error: {exc}", color="danger")

    return dbc.Alert(
        [
            html.Div([html.I(className="bi bi-check-circle me-2"), f"Scan started: {run_id[:12]}…"], className="mb-2"),
            html.A(
                [html.I(className="bi bi-box-arrow-up-right me-2"), "Open live execution"],
                href=f"/run/{run_id}",
                className="fw-bold",
            ),
        ],
        color="success",
    )

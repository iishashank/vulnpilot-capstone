"""
navbar.py — top navigation bar for VulnPilot.

The alert-badge count is populated via a Dash callback (30-second interval)
rather than blocking at layout-build time, so the UI renders immediately
even when the backend is starting up or temporarily offline.
"""
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output
from frontend.config import API_BASE_URL


NAV_ITEMS = [
    ("/", "Dashboard", "bi-grid-1x2"),
    ("/new-scan", "New Scan", "bi-crosshair2"),
    ("/sites", "Sites", "bi-globe2"),
    ("/assets", "Assets", "bi-hdd-network"),
    ("/findings", "Findings", "bi-bug"),
    ("/alerts", "Alerts", "bi-bell-fill"),
    ("/diff", "Diff", "bi-arrow-left-right"),
    ("/evaluation", "Evaluation", "bi-clipboard-data"),
    ("/report", "Report", "bi-file-earmark-text"),
]


def navbar():
    """Return the top-bar layout. Does not make any HTTP calls at build time."""
    nav_links = []
    for href, label, icon in NAV_ITEMS:
        children = (
            html.Span(id="navbar-alert-label", children=[html.I(className=f"bi {icon} me-1"), label])
            if label == "Alerts"
            else [html.I(className=f"bi {icon} me-1"), label]
        )
        nav_links.append(dbc.NavLink(children, href=href, active="exact", className="vp-nav-link"))

    return html.Div(
        [
            dcc.Interval(id="navbar-alert-tick", interval=30_000, n_intervals=0),
            dbc.Container(
                [
                    html.Div(
                        [
                            html.A(
                                [
                                    html.Span(html.I(className="bi bi-shield-lock-fill"), className="vp-brand-mark"),
                                    html.Span(
                                        [
                                            html.Span("VulnPilot", className="vp-brand-title"),
                                            html.Span("Security Operations Console", className="vp-brand-subtitle"),
                                        ],
                                        className="vp-brand-copy",
                                    ),
                                ],
                                href="/",
                                className="vp-brand",
                            ),
                            html.Div(
                                [
                                    html.Span("CrewAI pipeline online", className="vp-top-status"),
                                    dbc.Nav(nav_links, pills=True, className="vp-nav-pills"),
                                ],
                                className="vp-nav-wrap",
                            ),
                        ],
                        className="vp-topbar",
                    ),
                ],
                fluid=True,
                className="vp-topbar-container",
            ),
        ],
        className="vp-topbar-shell",
    )


@dash.callback(
    Output("navbar-alert-label", "children"),
    Input("navbar-alert-tick", "n_intervals"),
)
def refresh_alert_badge(_):
    """Fetch unacked alert count and update the navbar badge without blocking UI render."""
    import requests

    try:
        unacked = len(
            requests.get(
                f"{API_BASE_URL}/alerts",
                params={"unacked_only": 1},
                timeout=2,
            ).json().get("alerts", [])
        )
    except Exception:
        unacked = 0

    badge = dbc.Badge(unacked, color="warning", pill=True, className="ms-1") if unacked > 0 else ""
    return [html.I(className="bi bi-bell-fill me-1"), "Alerts", badge]

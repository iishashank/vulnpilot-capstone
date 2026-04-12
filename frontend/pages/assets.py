"""
Assets — discovered hosts / assets from scan runs.
"""

import requests
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output
from config import API_BASE_URL

try:
    from frontend.components.ui import page_header, surface, empty_state, pill
except ImportError:
    from components.ui import page_header, surface, empty_state, pill

API = API_BASE_URL

dash.register_page(__name__, path="/assets", name="Assets")

layout = dbc.Container([
    dcc.Interval(id="asset-tick", interval=10000, n_intervals=0),
    page_header(
        "Discovered assets",
        "Review the asset inventory for a completed run, including IPs, open ports, and the stored risk score.",
        icon="bi-hdd-network",
        eyebrow="Inventory",
        meta=[pill("Risk-scored", "success")],
    ),
    surface([
        dbc.Row([
            dbc.Col([
                dbc.Label("Execution session", className="fw-semibold mb-2"),
                dcc.Dropdown(
                    id="asset-run-select",
                    placeholder="Select a completed run...",
                    className="font-monospace",
                ),
            ], md=6),
            dbc.Col([
                html.Div([
                    dbc.Badge("Safe 0–4", color="success", className="me-2"),
                    dbc.Badge("Elevated 5–7", color="warning", className="me-2"),
                    dbc.Badge("Critical 8–10", color="danger"),
                ], className="d-flex flex-wrap justify-content-md-end align-items-center h-100 pt-3 pt-md-0"),
            ], md=6),
        ]),
    ], title="Asset dataset", subtitle="Runs must be completed before inventory can be inspected.", icon="bi-database", class_name="mb-4"),
    surface(html.Div(id="assets-content"), title="Run inventory", subtitle="One row per discovered asset in the selected run.", icon="bi-diagram-2"),
], fluid=True, className="py-2")


@dash.callback(
    Output("asset-run-select", "options"),
    Input("asset-tick", "n_intervals"),
)
def load_runs(_):
    try:
        runs = requests.get(f"{API}/runs", timeout=3).json().get("runs", [])
    except Exception:
        return []
    return [
        {"label": f"[{r['status'].upper()}] {r['run_id'][:8]} — {r['scope']}", "value": r["run_id"]}
        for r in runs if r["status"] == "done"
    ]


@dash.callback(
    Output("assets-content", "children"),
    Input("asset-run-select", "value"),
)
def show_assets(run_id):
    if not run_id:
        return empty_state("No run selected", "Choose a completed run to inspect the discovered hosts and risk model.", icon="bi-hdd-network")

    try:
        data = requests.get(f"{API}/assets", params={"run_id": run_id}, timeout=3).json()
    except Exception:
        return dbc.Alert("Could not establish uplink to backend.", color="danger")

    assets = data.get("assets", [])
    if not assets:
        return empty_state("No assets found", "The selected run did not produce any stored asset records.", icon="bi-hdd-rack")

    rows = []
    for a in assets:
        risk = a["risk_score"]
        if risk >= 8.0:
            risk_badge = dbc.Badge(f"{risk:.1f}", color="danger", className="px-3 rounded-pill")
        elif risk >= 5.0:
            risk_badge = dbc.Badge(f"{risk:.1f}", color="warning", className="px-3 rounded-pill")
        else:
            risk_badge = dbc.Badge(f"{risk:.1f}", color="success", className="px-3 rounded-pill text-dark")

        rows.append(html.Tr([
            html.Td(html.Strong(a["host"], className="text-light")),
            html.Td(html.Code(a["ip"], className="bg-transparent p-0 text-info fw-bold")),
            html.Td(html.Span(a["open_ports"], className="font-monospace")),
            html.Td(risk_badge),
        ], className="align-middle"))

    table = dbc.Table(
        [html.Thead(html.Tr([
            html.Th("HOSTNAME", className="text-muted border-0"), html.Th("IP ADDRESS", className="text-muted border-0"), 
            html.Th("OPEN PORTS", className="text-muted border-0"), html.Th("RISK INDEX", className="text-muted border-0"),
        ]))] + [html.Tbody(rows, className="border-top-0")],
        hover=True, responsive=True, className="align-middle border-0 mb-0"
    )
    
    return table

"""
Diff View — compare two consecutive scans for a site and show deltas.
"""
import requests
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output, State
from config import API_BASE_URL

try:
    from frontend.components.ui import page_header, surface, empty_state, pill
except ImportError:
    from components.ui import page_header, surface, empty_state, pill

API = API_BASE_URL
dash.register_page(__name__, path="/diff", name="Diff View")


NEON = {"new": "#ff1744", "resolved": "#00e676", "changed": "#ff9100", "neutral": "#00e5ff"}


def _delta_badge(label, count, color):
    return dbc.Col(dbc.Card(dbc.CardBody([
        html.H3(count, className="fw-bold mb-0", style={"color": color}),
        html.Small(label, className="text-muted text-uppercase", style={"letterSpacing": "1.5px", "fontSize": "0.7rem"}),
    ]), className="text-center"), md=3, className="mb-3")


def layout(**kwargs):
    return dbc.Container([
        dcc.Store(id="diff-data-store"),
        page_header(
            "Diff view",
            "Compare the two most recent snapshots for a managed site and inspect what changed.",
            icon="bi-arrow-left-right",
            eyebrow="Drift",
            meta=[pill("Snapshot compare", "primary")],
        ),
        surface([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Select site", className="fw-semibold mb-2"),
                    dcc.Dropdown(id="diff-site-select", placeholder="Choose a monitored site...",
                                 style={"backgroundColor": "rgba(0,0,0,0.3)", "color": "#fff"}),
                ], md=8),
                dbc.Col([
                    dbc.Button([html.I(className="bi bi-arrow-left-right me-2"), "Run Diff"],
                               id="diff-run-btn", color="info", className="w-100 vp-action-button mt-4 mt-md-0"),
                ], md=4),
            ]),
        ], title="Comparison control", subtitle="Diffing is available only for registered sites with at least two stored runs.", icon="bi-funnel", class_name="mb-4"),
        html.Div(id="diff-stats"),
        dbc.Row([
            dbc.Col(html.Div(id="diff-findings-panel"), md=6),
            dbc.Col(html.Div(id="diff-assets-panel"), md=6),
        ]),
    ], fluid=True, className="py-2")


@dash.callback(Output("diff-site-select", "options"), Input("diff-site-select", "id"))
def load_sites(_):
    try:
        sites = requests.get(f"{API}/sites", timeout=3).json().get("sites", [])
        return [{"label": f"{s['name']} ({s['primary_domain']})", "value": s["site_id"]} for s in sites]
    except Exception:
        return []


@dash.callback(
    Output("diff-data-store", "data"),
    Output("diff-stats", "children"),
    Input("diff-run-btn", "n_clicks"),
    State("diff-site-select", "value"),
    prevent_initial_call=True,
)
def fetch_diff(_, site_id):
    if not site_id:
        return {}, dbc.Alert("Please select a site first.", color="warning")
    try:
        data = requests.get(f"{API}/sites/{site_id}/diff", timeout=5).json()
    except Exception:
        return {}, dbc.Alert("Backend not reachable.", color="danger")

    if "message" in data:
        return {}, dbc.Alert([html.I(className="bi bi-info-circle me-2"), data["message"]], color="info")

    new_f = len(data.get("new_findings", []))
    res_f = len(data.get("resolved_findings", []))
    new_a = len(data.get("new_assets", []))
    chg = len(data.get("ip_changes", [])) + len(data.get("port_changes", []))

    stats = dbc.Row([
        _delta_badge("New Findings",      new_f, NEON["new"]),
        _delta_badge("Resolved",          res_f, NEON["resolved"]),
        _delta_badge("New Assets",        new_a, NEON["neutral"]),
        _delta_badge("Asset Changes",     chg,   NEON["changed"]),
    ], className="mb-4 g-3")

    return data, stats


@dash.callback(
    Output("diff-findings-panel", "children"),
    Output("diff-assets-panel", "children"),
    Input("diff-data-store", "data"),
)
def render_diff_tables(data):
    if not data:
        return "", ""

    def _sev_color(sev):
        return {"CRITICAL": "#ff1744", "HIGH": "#ff9100", "MEDIUM": "#00e5ff", "LOW": "#00e676"}.get(sev, "#aaa")

    def _badge(text, color, bg):
        return dbc.Badge(text, style={"backgroundColor": bg, "color": color, "border": f"1px solid {color}",
                                      "borderRadius": "6px", "fontSize": "0.7rem"})

    # Findings panel
    finding_rows = []
    for f in data.get("new_findings", []):
        c = _sev_color(f["severity"])
        finding_rows.append(html.Tr([
            html.Td(_badge("NEW", "#0a0a0f", c), style={"background": f"rgba({','.join(str(int(c[i:i+2],16)) for i in (1,3,5))},0.1)"}),
            html.Td(html.Code(f["cve_id"], className="bg-transparent p-0 small text-warning")),
            html.Td(html.Small(f["title"][:50] + "...", className="text-muted")),
            html.Td(dbc.Badge(f"CVSS {f['cvss']:.1f}", color="dark")),
        ], className="align-middle"))
    for f in data.get("resolved_findings", []):
        finding_rows.append(html.Tr([
            html.Td(_badge("FIXED", "#0a0a0f", NEON["resolved"]), style={"background": "rgba(0,230,118,0.06)"}),
            html.Td(html.Code(f["cve_id"], className="bg-transparent p-0 small text-success")),
            html.Td(html.Small(f["title"][:50] + "...", className="text-muted")),
            html.Td(""),
        ], className="align-middle"))

    findings_panel = surface(
        dbc.Table([html.Thead(html.Tr([html.Th(""), html.Th("CVE"), html.Th("Title"), html.Th("CVSS")]))] +
                  [html.Tbody(finding_rows)] if finding_rows
                  else [html.Tbody([html.Tr([html.Td("No finding changes.", colSpan=4, className="text-muted text-center py-5")])])],
                  hover=True, responsive=True, className="align-middle border-0 mb-0 small"),
        title="Finding changes",
        subtitle="New and resolved CVE records across the last two site snapshots.",
        icon="bi-bug-fill",
        class_name="mb-4",
    )

    # Assets panel
    asset_rows = []
    for a in data.get("new_assets", []):
        asset_rows.append(html.Tr([
            html.Td(_badge("NEW", "#0a0a0f", NEON["neutral"]), style={"background": "rgba(0,229,255,0.06)"}),
            html.Td(html.Code(a["host"], className="bg-transparent p-0 small text-info")),
            html.Td(html.Small(a["ip"], className="text-muted")),
        ], className="align-middle"))
    for a in data.get("gone_assets", []):
        asset_rows.append(html.Tr([
            html.Td(_badge("GONE", "#0a0a0f", "#888"), style={"background": "rgba(150,150,150,0.06)"}),
            html.Td(html.Code(a["host"], className="bg-transparent p-0 small text-muted")),
            html.Td(html.Small(a["ip"], className="text-muted")),
        ], className="align-middle"))
    for chg in data.get("ip_changes", []):
        asset_rows.append(html.Tr([
            html.Td(_badge("IP Δ", "#0a0a0f", NEON["changed"]), style={"background": "rgba(255,145,0,0.06)"}),
            html.Td(html.Code(chg["host"], className="bg-transparent p-0 small text-warning")),
            html.Td(html.Small(f"{chg['old_ip']} → {chg['new_ip']}", className="text-muted")),
        ], className="align-middle"))
    for chg in data.get("port_changes", []):
        asset_rows.append(html.Tr([
            html.Td(_badge("Port Δ", "#0a0a0f", NEON["changed"]), style={"background": "rgba(255,145,0,0.06)"}),
            html.Td(html.Code(chg["host"], className="bg-transparent p-0 small text-warning")),
            html.Td(html.Small(f"Ports: {chg['old']} → {chg['new']}", className="text-muted")),
        ], className="align-middle"))

    assets_panel = surface(
        dbc.Table([html.Thead(html.Tr([html.Th(""), html.Th("Host"), html.Th("Detail")]))] +
                  [html.Tbody(asset_rows)] if asset_rows
                  else [html.Tbody([html.Tr([html.Td("No asset changes.", colSpan=3, className="text-muted text-center py-5")])])],
                  hover=True, responsive=True, className="align-middle border-0 mb-0 small"),
        title="Asset changes",
        subtitle="New assets, removed assets, IP drift, and port deltas.",
        icon="bi-hdd-network-fill",
    )

    return findings_panel, assets_panel

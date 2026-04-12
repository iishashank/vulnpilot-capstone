"""
Findings — vulnerability findings with severity filters.
"""

import requests
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output, State, ctx
import pandas as pd
import plotly.express as px
from config import API_BASE_URL

try:
    from frontend.components.ui import page_header, surface, empty_state, pill
except ImportError:
    from components.ui import page_header, surface, empty_state, pill

API = API_BASE_URL

dash.register_page(__name__, path="/findings", name="Findings")

layout = dbc.Container([
    dcc.Interval(id="find-tick", interval=10000, n_intervals=0),
    dcc.Store(id="findings-store"),
    page_header(
        "Vulnerability findings",
        "Inspect correlated CVEs, severity distribution, exploit markers, and affected assets for a completed run.",
        icon="bi-bug",
        eyebrow="Findings",
        meta=[pill("CVE correlated", "danger"), pill("Filterable", "primary")],
    ),
    surface([
        dbc.Row([
            dbc.Col([
                dbc.Label("Execution session", className="fw-semibold mb-2"),
                dcc.Dropdown(id="find-run-select", placeholder="Select session to analyze...", className="font-monospace"),
            ], md=4, className="mb-3 mb-md-0"),
            dbc.Col([
                dbc.Label("Severity filter", className="fw-semibold mb-2"),
                dcc.Dropdown(
                    id="find-severity",
                    options=[
                        {"label": "All severities", "value": ""},
                        {"label": "Critical", "value": "CRITICAL"},
                        {"label": "High", "value": "HIGH"},
                        {"label": "Medium", "value": "MEDIUM"},
                        {"label": "Low", "value": "LOW"},
                    ],
                    value="",
                    className="font-monospace",
                ),
            ], md=4, className="mb-3 mb-md-0"),
            dbc.Col([
                dbc.Label("KEV filter", className="fw-semibold mb-2"),
                html.Div(dbc.Switch(id="find-kev", value=False, className="mt-2", label="Known exploited only")),
            ], md=4),
        ]),
    ], title="Finding dataset", subtitle="Select a run and narrow the result set before reviewing detailed vulnerabilities.", icon="bi-funnel", class_name="mb-4"),
    surface(html.Div(id="findings-content"), title="Finding analysis", subtitle="Summary metrics, severity distribution, and the detailed table for the selected run.", icon="bi-shield-exclamation"),
    dbc.Offcanvas(
        [
            html.Div(id="finding-explain-body"),
            dbc.Button([html.I(className="bi bi-x-lg me-2"), "Close"], id="finding-explain-close", outline=True, color="secondary", className="vp-action-button mt-4"),
        ],
        id="finding-explain-panel",
        title="Finding explanation",
        is_open=False,
        placement="end",
        scrollable=True,
        backdrop=True,
        class_name="vp-explain-offcanvas",
    ),
], fluid=True, className="py-2")


@dash.callback(
    Output("find-run-select", "options"),
    Input("find-tick", "n_intervals"),
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
    Output("findings-content", "children"),
    Output("findings-store", "data"),
    Input("find-run-select", "value"),
    Input("find-severity", "value"),
    Input("find-kev", "value"),
)
def show_findings(run_id, severity, kev_only):
    if not run_id:
        return empty_state("No run selected", "Choose a completed run to load its correlated findings.", icon="bi-bug"), []

    params = {"run_id": run_id}
    if severity:
        params["severity"] = severity
    if kev_only:
        params["kev_only"] = 1

    try:
        data = requests.get(f"{API}/findings", params=params, timeout=3).json()
    except Exception:
        return dbc.Alert("Could not establish uplink to backend.", color="danger"), []

    findings = data.get("findings", [])
    if not findings:
        return empty_state("No findings match", "The selected filters returned no stored findings for this run.", icon="bi-shield-check"), []

    severity_colors = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "success"}

    rows = []
    for f in findings:
        sev_color = severity_colors.get(f["severity"], "secondary")
        glow_class = "shadow-sm bg-danger" if f["severity"] == "CRITICAL" else ""
        priority_color = severity_colors.get(f.get("priority_label"), "secondary")
        impact_tone = {
            "Data Risk": "danger",
            "Service Disruption": "warning",
            "Operational Risk": "info",
        }.get(f.get("business_impact_label"), "secondary")
        rows.append(html.Tr([
            html.Td(html.Code(f["cve_id"], className="bg-transparent p-0 text-primary fw-bold")),
            html.Td(f["title"][:80] + ("…" if len(f["title"]) > 80 else ""), className="text-light"),
            html.Td(dbc.Badge(f["severity"], color=sev_color, className=f"px-3 rounded-pill {glow_class}")),
            html.Td(html.Span(f"{f['cvss']:.1f}", className=f"font-monospace fw-bold text-{sev_color}")),
            html.Td(html.Span(f"{f['epss']:.2f}" if f["epss"] else "—", className="font-monospace fw-bold text-warning")),
            html.Td(html.I(className="bi bi-check-circle-fill text-danger") if f["exploit"] else html.Span("—", className="text-muted")),
            html.Td(html.I(className="bi bi-shield-slash-fill text-danger") if f["kev"] else html.Span("—", className="text-muted")),
            html.Td(dbc.Badge(f.get("priority_label", f["severity"]), color=priority_color, className="px-3 rounded-pill")),
            html.Td(dbc.Badge(f.get("business_impact_label", "Operational Risk"), color=impact_tone)),
            html.Td(html.Span(f["affected_assets"], className="font-monospace text-info")),
            html.Td(
                dbc.Button(
                    [html.I(className="bi bi-chat-left-text me-1"), "Explain"],
                    id={"type": "finding-explain-btn", "index": str(f["id"])},
                    size="sm",
                    outline=True,
                    color="secondary",
                    className="vp-action-button",
                )
            ),
        ], className="align-middle"))

    # Summary Cards
    def _mini_card(val, label, color):
        return dbc.Card(dbc.CardBody([
            html.H3(val, className=f"text-{color} mb-0 fw-bold font-monospace"),
            html.Small(label, className="text-muted text-uppercase fw-bold", style={"letterSpacing": "1px", "fontSize": "0.7rem"}),
        ], className="p-3 text-center"), className=f"shadow-sm border-0 border-bottom border-4 border-{color} bg-body h-100")

    max_cvss = max((f['cvss'] for f in findings), default=0)
    summary = dbc.Row([
        dbc.Col(_mini_card(len(findings), "Total Findings", "primary"), md=3, className="mb-3 mb-md-0"),
        dbc.Col(_mini_card(sum(1 for f in findings if f["severity"] == "CRITICAL"), "Critical", "danger"), md=3, className="mb-3 mb-md-0"),
        dbc.Col(_mini_card(sum(1 for f in findings if f["epss"] >= 0.5), "High EPSS", "warning"), md=3, className="mb-3 mb-md-0"),
        dbc.Col(_mini_card(f"{max_cvss:.1f}", "Max CVSS", "danger" if max_cvss >= 9.0 else "warning"), md=3),
    ], className="mb-4")

    # Bar chart
    df = pd.DataFrame(findings)
    sev_counts = df["severity"].value_counts().reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).fillna(0).reset_index()
    sev_counts.columns = ["Severity", "Count"]
    fig = px.bar(
        sev_counts, x="Severity", y="Count", color="Severity",
        color_discrete_map={"CRITICAL": "#ff2a2a", "HIGH": "#ffb800", "MEDIUM": "#00d2ff", "LOW": "#00ff88"}
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(t=10, b=10, l=10, r=10),
        height=150, showlegend=False, xaxis_title="", yaxis_title="",
        xaxis=dict(showgrid=False), yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)")
    )
    graph_card = dcc.Graph(figure=fig, config={"displayModeBar": False})

    # Table
    table = dbc.Table(
        [html.Thead(html.Tr([
            html.Th("CVE ID", className="text-muted border-0"), html.Th("DESCRIPTION", className="text-muted border-0"), 
            html.Th("SEVERITY", className="text-muted border-0"), html.Th("CVSS", className="text-muted border-0"), 
            html.Th("EPSS", className="text-muted border-0"),
            html.Th("EXPLOIT", className="text-muted border-0"), html.Th("KEV", className="text-muted border-0"), 
            html.Th("PRIORITY", className="text-muted border-0"),
            html.Th("IMPACT", className="text-muted border-0"),
            html.Th("ASSETS", className="text-muted border-0"),
            html.Th("", className="text-muted border-0"),
        ]))] + [html.Tbody(rows, className="border-top-0")],
        hover=True, responsive=True, className="align-middle border-0 mb-0"
    )
    table_note = html.P(
        "Rows are ordered by combined operational priority. EPSS adds exploit-likelihood context on top of CVSS, KEV, and public exploit indicators.",
        className="vp-table-note mt-3",
    )

    return html.Div([summary, graph_card, table, table_note]), findings


@dash.callback(
    Output("finding-explain-panel", "is_open"),
    Output("finding-explain-panel", "title"),
    Output("finding-explain-body", "children"),
    Input({"type": "finding-explain-btn", "index": dash.ALL}, "n_clicks"),
    Input("finding-explain-close", "n_clicks"),
    State("findings-store", "data"),
    prevent_initial_call=True,
)
def open_finding_explanation(_row_clicks, close_clicks, findings):
    triggered = ctx.triggered_id
    if triggered == "finding-explain-close":
        return False, "Finding explanation", ""
    if not triggered or not isinstance(triggered, dict):
        return dash.no_update, dash.no_update, dash.no_update

    finding_id = str(triggered.get("index"))
    finding = next((item for item in (findings or []) if str(item.get("id")) == finding_id), None)
    if not finding:
        return False, "Finding explanation", dbc.Alert("Could not load explanation for this finding.", color="warning")

    impact_tone = {
        "Data Risk": "danger",
        "Service Disruption": "warning",
        "Operational Risk": "info",
    }.get(finding.get("business_impact_label"), "secondary")
    priority_color = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "success"}.get(
        finding.get("priority_label"),
        "secondary",
    )

    plain_title = finding.get("plain_title") or finding["title"][:100]
    plain_summary = finding.get("plain_summary") or "This finding was stored before stakeholder-ready explanation text was generated. Re-run the scan to produce a fuller business-facing summary."
    business_impact_label = finding.get("business_impact_label") or "Operational Risk"
    business_impact_reason = finding.get("business_impact_reason") or "This issue should still be treated as an operational security concern even when the exact business path is still being reviewed."
    why_it_matters = finding.get("why_it_matters") or "The issue represents a known vulnerability on an observed service and should be reviewed by the system owner."
    priority_reason = finding.get("priority_reason") or f"Priority is currently {finding['severity'].lower()} based on the stored severity and CVSS metadata."
    next_step = finding.get("recommended_next_step") or "Confirm system ownership, validate whether the exposed service is required, and schedule remediation."

    body = html.Div(
        [
            html.Span("Stakeholder summary", className="vp-explain-eyebrow"),
            html.H4(plain_title, className="vp-explain-panel-title"),
            html.Div(
                [
                    dbc.Badge(finding["severity"], color={"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "success"}.get(finding["severity"], "secondary"), className="me-2"),
                    dbc.Badge(f"Priority: {finding.get('priority_label', finding['severity'])}", color=priority_color, className="me-2"),
                    dbc.Badge(f"EPSS {finding.get('epss', 0.0):.2f}", color="warning", className="me-2"),
                    dbc.Badge(business_impact_label, color=impact_tone, className="me-2"),
                    html.Code(finding["cve_id"], className="bg-transparent p-0 text-primary fw-bold"),
                ],
                className="mb-3",
            ),
            html.P(plain_summary, className="vp-explain-text"),
            html.Div(
                [
                    html.Div(
                        [
                            html.Span("Business impact", className="vp-explain-label"),
                            html.P(business_impact_reason, className="vp-explain-text mb-0"),
                        ],
                        className="vp-explain-block",
                    ),
                    html.Div(
                        [
                            html.Span("Why it matters", className="vp-explain-label"),
                            html.P(why_it_matters, className="vp-explain-text mb-0"),
                        ],
                        className="vp-explain-block",
                    ),
                    html.Div(
                        [
                            html.Span("Priority", className="vp-explain-label"),
                            html.P(priority_reason, className="vp-explain-text mb-0"),
                        ],
                        className="vp-explain-block",
                    ),
                    html.Div(
                        [
                            html.Span("Next step", className="vp-explain-label"),
                            html.P(next_step, className="vp-explain-text mb-0"),
                        ],
                        className="vp-explain-block",
                    ),
                ],
                className="vp-explain-grid",
            ),
        ]
    )

    return True, f"{finding['cve_id']} — Stakeholder Explanation", body

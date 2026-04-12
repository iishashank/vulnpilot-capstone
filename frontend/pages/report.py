"""
Report — generated vulnerability assessment report view.
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

dash.register_page(__name__, path="/report", name="Report")

layout = dbc.Container([
    dcc.Interval(id="report-tick", interval=10000, n_intervals=0),
    page_header(
        "Assessment report",
        "Generate a consolidated readout for a completed run, including executive summary, assets, and detailed findings.",
        icon="bi-file-earmark-text",
        eyebrow="Reporting",
        meta=[pill("Run summary", "primary"), pill("PDF export pending", "muted")],
    ),
    surface([
        dbc.Row([
            dbc.Col([
                dbc.Label("Execution session", className="fw-semibold mb-2"),
                dcc.Dropdown(id="report-run-select", placeholder="Select session to compile...", className="font-monospace"),
            ], md=6),
            dbc.Col([
                html.Div([
                    dbc.Button([html.I(className="bi bi-download me-2"), "Export PDF (coming soon)"], color="secondary", outline=True, disabled=True, className="w-100 vp-action-button")
                ], className="h-100 d-flex align-items-end justify-content-md-end pt-4 pt-md-0")
            ], md=6)
        ]),
    ], title="Report source", subtitle="Reports are generated from completed runs only.", icon="bi-funnel", class_name="mb-4"),
    surface(html.Div(id="report-content"), title="Generated report", subtitle="Structured summary based on the selected execution session.", icon="bi-journal-richtext"),
], fluid=True, className="py-2")


@dash.callback(
    Output("report-run-select", "options"),
    Input("report-tick", "n_intervals"),
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
    Output("report-content", "children"),
    Input("report-run-select", "value"),
)
def generate_report(run_id):
    if not run_id:
        return empty_state("No run selected", "Choose a completed run to generate a consolidated report view.", icon="bi-file-earmark-text")

    # Fetch data
    try:
        status = requests.get(f"{API}/scan/{run_id}/status", timeout=3).json()
        assets = requests.get(f"{API}/assets", params={"run_id": run_id}, timeout=3).json().get("assets", [])
        findings = requests.get(f"{API}/findings", params={"run_id": run_id}, timeout=3).json().get("findings", [])
    except Exception:
        return dbc.Alert("Could not establish uplink to backend.", color="danger")

    # Sort findings by derived operational priority first
    findings.sort(key=lambda f: (f.get("priority_score", 0), f.get("cvss", 0), f.get("epss", 0)), reverse=True)

    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low      = sum(1 for f in findings if f["severity"] == "LOW")
    kev_count = sum(1 for f in findings if f.get("kev"))
    exploit_count = sum(1 for f in findings if f.get("exploit"))
    high_epss_count = sum(1 for f in findings if float(f.get("epss", 0) or 0) >= 0.5)

    impact_counts = {}
    for finding in findings:
        label = finding.get("business_impact_label", "Operational Risk")
        impact_counts[label] = impact_counts.get(label, 0) + 1
    top_impact = max(impact_counts, key=impact_counts.get) if impact_counts else "Operational Risk"

    if critical or kev_count:
        ciso_posture = "Immediate management attention is recommended because the run contains critical or actively exploited issues."
    elif high:
        ciso_posture = "The environment does not show critical issues in this run, but it does contain high-severity items that should be scheduled for remediation quickly."
    elif findings:
        ciso_posture = "Current findings are lower priority, but they still indicate technical debt and exposure that should be tracked."
    else:
        ciso_posture = "No vulnerabilities were correlated in this run, so the current snapshot does not show actionable CVE-based exposure."

    # Build report sections
    report_sections = []

    # --- Header ---
    report_sections.append(
        dbc.Card(dbc.CardBody([
            html.H4("📋 Executive Summary", className="mb-3 text-uppercase fw-bold text-muted", style={"letterSpacing": "1px"}),
            html.P([
                f"Evaluation of target scope ", html.Code(status.get("scope", "N/A"), className="bg-transparent p-0 text-info fw-bold"),
                f" executed via ", html.Strong(status.get("profile", "N/A").upper(), className="text-warning"), " methodology. ",
                f"Discovered ", html.Strong(f"{len(assets)} reachable endpoints", className="text-success"),
                f" presenting ", html.Strong(f"{len(findings)} identified vulnerabilities", className="text-danger"),
                "."
            ], className="lead"),
            html.Hr(className="border-secondary opacity-25 my-4"),
            dbc.Row([
                dbc.Col(dbc.Badge(f"CRITICAL: {critical}", color="danger",  className="p-3 fs-6 w-100 rounded-3 shadow-sm" if critical else "p-3 fs-6 w-100 rounded-3 text-muted bg-transparent border"), md=3, className="mb-2 mb-md-0"),
                dbc.Col(dbc.Badge(f"HIGH: {high}",         color="warning", className="p-3 fs-6 w-100 rounded-3 shadow-sm" if high else "p-3 fs-6 w-100 rounded-3 text-muted bg-transparent border"), md=3, className="mb-2 mb-md-0"),
                dbc.Col(dbc.Badge(f"MEDIUM: {medium}",     color="info",    className="p-3 fs-6 w-100 rounded-3 shadow-sm" if medium else "p-3 fs-6 w-100 rounded-3 text-muted bg-transparent border"), md=3, className="mb-2 mb-md-0"),
                dbc.Col(dbc.Badge(f"LOW: {low}",           color="success", className="p-3 fs-6 w-100 rounded-3 shadow-sm text-dark" if low else "p-3 fs-6 w-100 rounded-3 text-muted bg-transparent border"), md=3),
            ]),
        ]), className="shadow-sm border-0 bg-body mb-5")
    )

    report_sections.append(
        dbc.Card(
            dbc.CardBody(
                [
                    html.H4("🧭 CISO Summary", className="mb-3 text-uppercase fw-bold text-muted", style={"letterSpacing": "1px"}),
                    html.P(ciso_posture, className="lead"),
                    dbc.Row([
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody([
                                    html.Small("Business impact profile", className="text-muted text-uppercase d-block mb-2", style={"letterSpacing": "1px"}),
                                    html.Strong(top_impact, className="fs-5"),
                                    html.P("This is the dominant impact category across the current findings.", className="vp-muted-note mb-0 mt-2"),
                                ]),
                                className="h-100",
                            ),
                            md=4,
                            className="mb-3",
                        ),
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody([
                                    html.Small("Immediate concerns", className="text-muted text-uppercase d-block mb-2", style={"letterSpacing": "1px"}),
                                    html.Strong(f"{critical} critical / {kev_count} KEV / {high_epss_count} high EPSS / {exploit_count} with public exploit", className="fs-5"),
                                    html.P("These are the issues most likely to require short-term coordination and executive visibility.", className="vp-muted-note mb-0 mt-2"),
                                ]),
                                className="h-100",
                            ),
                            md=4,
                            className="mb-3",
                        ),
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody([
                                    html.Small("Recommended leadership action", className="text-muted text-uppercase d-block mb-2", style={"letterSpacing": "1px"}),
                                    html.Strong("Assign owners and reduce exposure", className="fs-5"),
                                    html.P("Confirm system ownership, validate whether exposed services are necessary, and prioritize patching for the highest-risk items.", className="vp-muted-note mb-0 mt-2"),
                                ]),
                                className="h-100",
                            ),
                            md=4,
                            className="mb-3",
                        ),
                    ]),
                ]
            ),
            className="shadow-sm border-0 bg-body mb-5",
        )
    )

    # --- Assets Summary ---
    if assets:
        asset_rows = []
        for a in assets:
            risk = a["risk_score"]
            if risk >= 8.0: r_badge = dbc.Badge(f"{risk:.1f}", color="danger")
            elif risk >= 5.0: r_badge = dbc.Badge(f"{risk:.1f}", color="warning")
            else: r_badge = dbc.Badge(f"{risk:.1f}", color="success", className="text-dark")
            
            asset_rows.append(html.Tr([
                html.Td(html.Strong(a["host"])), html.Td(html.Code(a["ip"], className="bg-transparent p-0 text-info")), 
                html.Td(html.Span(a["open_ports"], className="font-monospace")), html.Td(r_badge)
            ], className="align-middle"))

        report_sections.append(
            dbc.Card(dbc.CardBody([
                html.H5("🖥️ Validated Endpoints", className="mb-3 text-uppercase fw-bold text-muted", style={"letterSpacing": "1px"}),
                dbc.Table(
                    [html.Thead(html.Tr([
                        html.Th("HOSTNAME", className="text-muted border-0"), html.Th("IP ADDRESS", className="text-muted border-0"), 
                        html.Th("PORTS", className="text-muted border-0"), html.Th("RISK", className="text-muted border-0")
                    ]))] + [html.Tbody(asset_rows, className="border-top-0")],
                    hover=True, responsive=True, size="sm", className="align-middle border-0 mb-0"
                ),
            ]), className="shadow-sm border-0 bg-body border-start border-4 border-success mb-5")
        )

    # --- Findings Detail ---
    if findings:
        report_sections.append(html.H4("🚨 Technical Findings", className="mb-4 text-uppercase fw-bold text-muted border-bottom pb-2", style={"letterSpacing": "1px"}))
    
    for f in findings:
        sev_colors = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "success"}
        sev_color = sev_colors.get(f["severity"], "secondary")

        report_sections.append(
            dbc.Card(dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.H5([
                            dbc.Badge(f["severity"], color=sev_color, className="me-2 px-3 rounded-pill shadow-sm text-uppercase"),
                            html.Code(f["cve_id"], className=f"me-2 bg-transparent p-0 fw-bold fs-5 text-{sev_color}"),
                        ], className="mb-3"),
                        html.P(f["title"], className="text-light lead fs-6"),
                    ], md=8),
                    dbc.Col([
                        html.Div([
                            html.Span("CVSS Base Score", className="text-muted small text-uppercase d-block", style={"letterSpacing": "1px"}),
                            html.Strong(f"{f['cvss']:.1f}", className=f"text-{sev_color} fs-2 font-monospace"),
                        ], className="mb-3"),
                        html.Div([
                            html.Span("EPSS / Priority", className="text-muted small text-uppercase d-block", style={"letterSpacing": "1px"}),
                            html.Strong(f"{f.get('epss', 0.0):.2f} / {f.get('priority_label', f['severity'])}", className="fs-5 font-monospace text-warning"),
                        ], className="mb-3"),
                        html.Div([
                            html.Span("Exploitability", className="text-muted small text-uppercase d-block", style={"letterSpacing": "1px"}),
                            html.Span(
                                [
                                    html.I(className="bi bi-shield-slash-fill me-2"),
                                    "KEV / public exploit context present",
                                ],
                                className="text-danger fw-bold",
                            ) if f["kev"] or f["exploit"] else html.Span([html.I(className="bi bi-shield-check me-2"), "No known exploit signal"], className="text-success"),
                        ]),
                    ], md=4, className="text-md-end border-md-start border-secondary border-opacity-25 ps-md-4"),
                ]),

                # Evidence
                html.Div([
                    html.H6("📝 Discovery Evidence", className="mt-4 text-uppercase text-info small fw-bold", style={"letterSpacing": "1px"}),
                    html.Pre(f.get("evidence", "N/A"), className="cyber-terminal p-3 mt-2 rounded text-success border-success border-opacity-25", style={"fontSize": "0.80rem", "whiteSpace": "pre-wrap"}),
                ]) if f.get("evidence") else None,

                # Remediation
                html.Div([
                    html.H6("🛡️ Remediation Directive", className="mt-4 text-uppercase text-success small fw-bold", style={"letterSpacing": "1px"}),
                    html.P(f.get("remediation", "N/A"), className="text-light bg-success bg-opacity-10 border border-success border-opacity-25 p-3 rounded"),
                ]) if f.get("remediation") else None,

                # Plain-language explanation
                html.Div([
                    html.H6("🗣️ Plain-Language Explanation", className="mt-4 text-uppercase text-warning small fw-bold", style={"letterSpacing": "1px"}),
                    html.P(f.get("plain_summary", ""), className="vp-muted-note"),
                    html.P([html.Strong("Business impact: "), f.get("business_impact_label", ""), " — ", f.get("business_impact_reason", "")], className="vp-muted-note"),
                    html.P([html.Strong("Why it matters: "), f.get("why_it_matters", "")], className="vp-muted-note"),
                    html.P([html.Strong("Priority context: "), f.get("priority_reason", "")], className="vp-muted-note"),
                    html.P([html.Strong("What a non-technical owner should do: "), f.get("recommended_next_step", "")], className="vp-muted-note mb-0"),
                ]),
            ]), className="shadow-sm bg-body mb-4 border-0 border-start border-4 h-100", style={"borderLeftColor": f"var(--bs-{sev_color}) !important"})
        )

    return html.Div(report_sections)

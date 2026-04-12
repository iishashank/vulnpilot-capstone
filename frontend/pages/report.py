"""
Report — generated vulnerability assessment report view with PDF export.
"""

from __future__ import annotations

from io import BytesIO
from textwrap import shorten

import dash
import dash_bootstrap_components as dbc
import requests
from dash import Input, Output, State, dcc, html
from dash.exceptions import PreventUpdate
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from frontend.config import API_BASE_URL

try:
    from frontend.components.ui import empty_state, page_header, pill, surface
except ImportError:
    from components.ui import empty_state, page_header, pill, surface


API = API_BASE_URL

dash.register_page(__name__, path="/report", name="Report")


def _fetch_report_payload(run_id: str) -> dict:
    status = requests.get(f"{API}/scan/{run_id}/status", timeout=5).json()
    assets = requests.get(f"{API}/assets", params={"run_id": run_id}, timeout=5).json().get("assets", [])
    findings = requests.get(f"{API}/findings", params={"run_id": run_id}, timeout=5).json().get("findings", [])
    findings.sort(key=lambda finding: (finding.get("priority_score", 0), finding.get("cvss", 0), finding.get("epss", 0)), reverse=True)

    critical = sum(1 for finding in findings if finding["severity"] == "CRITICAL")
    high = sum(1 for finding in findings if finding["severity"] == "HIGH")
    medium = sum(1 for finding in findings if finding["severity"] == "MEDIUM")
    low = sum(1 for finding in findings if finding["severity"] == "LOW")
    kev_count = sum(1 for finding in findings if finding.get("kev"))
    exploit_count = sum(1 for finding in findings if finding.get("exploit"))
    high_epss_count = sum(1 for finding in findings if float(finding.get("epss", 0) or 0) >= 0.5)

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

    return {
        "status": status,
        "assets": assets,
        "findings": findings,
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "kev_count": kev_count,
            "exploit_count": exploit_count,
            "high_epss_count": high_epss_count,
            "top_impact": top_impact,
            "ciso_posture": ciso_posture,
        },
    }


def _render_report(payload: dict):
    status = payload["status"]
    assets = payload["assets"]
    findings = payload["findings"]
    summary = payload["summary"]

    critical = summary["critical"]
    high = summary["high"]
    medium = summary["medium"]
    low = summary["low"]
    kev_count = summary["kev_count"]
    exploit_count = summary["exploit_count"]
    high_epss_count = summary["high_epss_count"]
    top_impact = summary["top_impact"]
    ciso_posture = summary["ciso_posture"]

    report_sections = []

    report_sections.append(
        dbc.Card(
            dbc.CardBody(
                [
                    html.H4("📋 Executive Summary", className="mb-3 text-uppercase fw-bold text-muted", style={"letterSpacing": "1px"}),
                    html.P(
                        [
                            "Evaluation of target scope ",
                            html.Code(status.get("scope", "N/A"), className="bg-transparent p-0 text-info fw-bold"),
                            " executed via ",
                            html.Strong(status.get("profile", "N/A").upper(), className="text-warning"),
                            " methodology. ",
                            html.Strong(f"{len(assets)} reachable endpoints", className="text-success"),
                            " and ",
                            html.Strong(f"{len(findings)} identified vulnerabilities", className="text-danger"),
                            " were recorded for this run.",
                        ],
                        className="lead",
                    ),
                    html.Hr(className="border-secondary opacity-25 my-4"),
                    dbc.Row(
                        [
                            dbc.Col(dbc.Badge(f"CRITICAL: {critical}", color="danger", className="p-3 fs-6 w-100 rounded-3 shadow-sm" if critical else "p-3 fs-6 w-100 rounded-3 text-muted bg-transparent border"), md=3, className="mb-2 mb-md-0"),
                            dbc.Col(dbc.Badge(f"HIGH: {high}", color="warning", className="p-3 fs-6 w-100 rounded-3 shadow-sm" if high else "p-3 fs-6 w-100 rounded-3 text-muted bg-transparent border"), md=3, className="mb-2 mb-md-0"),
                            dbc.Col(dbc.Badge(f"MEDIUM: {medium}", color="info", className="p-3 fs-6 w-100 rounded-3 shadow-sm" if medium else "p-3 fs-6 w-100 rounded-3 text-muted bg-transparent border"), md=3, className="mb-2 mb-md-0"),
                            dbc.Col(dbc.Badge(f"LOW: {low}", color="success", className="p-3 fs-6 w-100 rounded-3 shadow-sm text-dark" if low else "p-3 fs-6 w-100 rounded-3 text-muted bg-transparent border"), md=3),
                        ]
                    ),
                ]
            ),
            className="shadow-sm border-0 bg-body mb-5",
        )
    )

    report_sections.append(
        dbc.Card(
            dbc.CardBody(
                [
                    html.H4("🧭 CISO Summary", className="mb-3 text-uppercase fw-bold text-muted", style={"letterSpacing": "1px"}),
                    html.P(ciso_posture, className="lead"),
                    dbc.Row(
                        [
                            dbc.Col(
                                dbc.Card(
                                    dbc.CardBody(
                                        [
                                            html.Small("Business impact profile", className="text-muted text-uppercase d-block mb-2", style={"letterSpacing": "1px"}),
                                            html.Strong(top_impact, className="fs-5"),
                                            html.P("This is the dominant impact category across the current findings.", className="vp-muted-note mb-0 mt-2"),
                                        ]
                                    ),
                                    className="h-100",
                                ),
                                md=4,
                                className="mb-3",
                            ),
                            dbc.Col(
                                dbc.Card(
                                    dbc.CardBody(
                                        [
                                            html.Small("Immediate concerns", className="text-muted text-uppercase d-block mb-2", style={"letterSpacing": "1px"}),
                                            html.Strong(f"{critical} critical / {kev_count} KEV / {high_epss_count} high EPSS / {exploit_count} with public exploit", className="fs-5"),
                                            html.P("These are the issues most likely to require short-term coordination and executive visibility.", className="vp-muted-note mb-0 mt-2"),
                                        ]
                                    ),
                                    className="h-100",
                                ),
                                md=4,
                                className="mb-3",
                            ),
                            dbc.Col(
                                dbc.Card(
                                    dbc.CardBody(
                                        [
                                            html.Small("Recommended leadership action", className="text-muted text-uppercase d-block mb-2", style={"letterSpacing": "1px"}),
                                            html.Strong("Assign owners and reduce exposure", className="fs-5"),
                                            html.P("Confirm system ownership, validate whether exposed services are necessary, and prioritize patching for the highest-risk items.", className="vp-muted-note mb-0 mt-2"),
                                        ]
                                    ),
                                    className="h-100",
                                ),
                                md=4,
                                className="mb-3",
                            ),
                        ]
                    ),
                ]
            ),
            className="shadow-sm border-0 bg-body mb-5",
        )
    )

    if assets:
        asset_rows = []
        for asset in assets:
            risk = asset["risk_score"]
            if risk >= 8.0:
                risk_badge = dbc.Badge(f"{risk:.1f}", color="danger")
            elif risk >= 5.0:
                risk_badge = dbc.Badge(f"{risk:.1f}", color="warning")
            else:
                risk_badge = dbc.Badge(f"{risk:.1f}", color="success", className="text-dark")

            asset_rows.append(
                html.Tr(
                    [
                        html.Td(html.Strong(asset["host"])),
                        html.Td(html.Code(asset["ip"], className="bg-transparent p-0 text-info")),
                        html.Td(html.Span(asset["open_ports"], className="font-monospace")),
                        html.Td(risk_badge),
                    ],
                    className="align-middle",
                )
            )

        report_sections.append(
            dbc.Card(
                dbc.CardBody(
                    [
                        html.H5("🖥️ Validated Endpoints", className="mb-3 text-uppercase fw-bold text-muted", style={"letterSpacing": "1px"}),
                        dbc.Table(
                            [
                                html.Thead(
                                    html.Tr(
                                        [
                                            html.Th("HOSTNAME", className="text-muted border-0"),
                                            html.Th("IP ADDRESS", className="text-muted border-0"),
                                            html.Th("PORTS", className="text-muted border-0"),
                                            html.Th("RISK", className="text-muted border-0"),
                                        ]
                                    )
                                ),
                                html.Tbody(asset_rows, className="border-top-0"),
                            ],
                            hover=True,
                            responsive=True,
                            size="sm",
                            className="align-middle border-0 mb-0",
                        ),
                    ]
                ),
                className="shadow-sm border-0 bg-body border-start border-4 border-success mb-5",
            )
        )

    if findings:
        report_sections.append(html.H4("🚨 Technical Findings", className="mb-4 text-uppercase fw-bold text-muted border-bottom pb-2", style={"letterSpacing": "1px"}))

    for finding in findings:
        sev_color = {
            "CRITICAL": "danger",
            "HIGH": "warning",
            "MEDIUM": "info",
            "LOW": "success",
        }.get(finding["severity"], "secondary")

        report_sections.append(
            dbc.Card(
                dbc.CardBody(
                    [
                        dbc.Row(
                            [
                                dbc.Col(
                                    [
                                        html.H5(
                                            [
                                                dbc.Badge(finding["severity"], color=sev_color, className="me-2 px-3 rounded-pill shadow-sm text-uppercase"),
                                                html.Code(finding["cve_id"], className=f"me-2 bg-transparent p-0 fw-bold fs-5 text-{sev_color}"),
                                            ],
                                            className="mb-3",
                                        ),
                                        html.P(finding["title"], className="text-light lead fs-6"),
                                    ],
                                    md=8,
                                ),
                                dbc.Col(
                                    [
                                        html.Div(
                                            [
                                                html.Span("CVSS Base Score", className="text-muted small text-uppercase d-block", style={"letterSpacing": "1px"}),
                                                html.Strong(f"{finding['cvss']:.1f}", className=f"text-{sev_color} fs-2 font-monospace"),
                                            ],
                                            className="mb-3",
                                        ),
                                        html.Div(
                                            [
                                                html.Span("EPSS / Priority", className="text-muted small text-uppercase d-block", style={"letterSpacing": "1px"}),
                                                html.Strong(f"{finding.get('epss', 0.0):.2f} / {finding.get('priority_label', finding['severity'])}", className="fs-5 font-monospace text-warning"),
                                            ],
                                            className="mb-3",
                                        ),
                                        html.Div(
                                            [
                                                html.Span("Exploitability", className="text-muted small text-uppercase d-block", style={"letterSpacing": "1px"}),
                                                html.Span([html.I(className="bi bi-shield-slash-fill me-2"), "KEV / public exploit context present"], className="text-danger fw-bold")
                                                if finding["kev"] or finding["exploit"]
                                                else html.Span([html.I(className="bi bi-shield-check me-2"), "No known exploit signal"], className="text-success"),
                                            ]
                                        ),
                                    ],
                                    md=4,
                                    className="text-md-end border-md-start border-secondary border-opacity-25 ps-md-4",
                                ),
                            ]
                        ),
                        html.Div(
                            [
                                html.H6("📝 Discovery Evidence", className="mt-4 text-uppercase text-info small fw-bold", style={"letterSpacing": "1px"}),
                                html.Pre(finding.get("evidence", "N/A"), className="cyber-terminal p-3 mt-2 rounded text-success border-success border-opacity-25", style={"fontSize": "0.80rem", "whiteSpace": "pre-wrap"}),
                            ]
                        )
                        if finding.get("evidence")
                        else None,
                        html.Div(
                            [
                                html.H6("🛡️ Remediation Directive", className="mt-4 text-uppercase text-success small fw-bold", style={"letterSpacing": "1px"}),
                                html.P(finding.get("remediation", "N/A"), className="text-light bg-success bg-opacity-10 border border-success border-opacity-25 p-3 rounded"),
                            ]
                        )
                        if finding.get("remediation")
                        else None,
                        html.Div(
                            [
                                html.H6("🗣️ Plain-Language Explanation", className="mt-4 text-uppercase text-warning small fw-bold", style={"letterSpacing": "1px"}),
                                html.P(finding.get("plain_summary", ""), className="vp-muted-note"),
                                html.P([html.Strong("Business impact: "), finding.get("business_impact_label", ""), " — ", finding.get("business_impact_reason", "")], className="vp-muted-note"),
                                html.P([html.Strong("Why it matters: "), finding.get("why_it_matters", "")], className="vp-muted-note"),
                                html.P([html.Strong("Priority context: "), finding.get("priority_reason", "")], className="vp-muted-note"),
                                html.P([html.Strong("What a non-technical owner should do: "), finding.get("recommended_next_step", "")], className="vp-muted-note mb-0"),
                            ]
                        ),
                    ]
                ),
                className="shadow-sm bg-body mb-4 border-0 border-start border-4 h-100",
                style={"borderLeftColor": f"var(--bs-{sev_color}) !important"},
            )
        )

    return html.Div(report_sections)


def _pdf_table(rows, col_widths=None, header_background=colors.HexColor("#1d4ed8")):
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), header_background),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#eef2ff")]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _build_pdf(buffer, payload: dict):
    status = payload["status"]
    assets = payload["assets"]
    findings = payload["findings"]
    summary = payload["summary"]

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading2"], fontSize=15, textColor=colors.HexColor("#0f172a"), spaceAfter=8))
    styles.add(ParagraphStyle(name="SmallBody", parent=styles["BodyText"], fontSize=9.5, leading=13, textColor=colors.HexColor("#334155")))
    styles.add(ParagraphStyle(name="MetricText", parent=styles["BodyText"], fontSize=10, leading=12, textColor=colors.HexColor("#0f172a")))

    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.55 * inch, bottomMargin=0.55 * inch, leftMargin=0.65 * inch, rightMargin=0.65 * inch, title=f"VulnPilot Assessment Report {status.get('run_id', '')}")
    elements = []

    elements.append(Paragraph("VulnPilot Assessment Report", styles["Title"]))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Run ID: <b>{status.get('run_id', 'N/A')}</b>", styles["SmallBody"]))
    elements.append(Paragraph(f"Scope: <b>{status.get('scope', 'N/A')}</b> | Profile: <b>{str(status.get('profile', 'N/A')).upper()}</b> | Status: <b>{status.get('status', 'N/A').upper()}</b>", styles["SmallBody"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Executive Summary", styles["SectionTitle"]))
    elements.append(Paragraph(summary["ciso_posture"], styles["BodyText"]))
    elements.append(Spacer(1, 8))
    elements.append(
        _pdf_table(
            [
                ["Critical", "High", "Medium", "Low", "KEV", "High EPSS", "Assets", "Findings"],
                [
                    str(summary["critical"]),
                    str(summary["high"]),
                    str(summary["medium"]),
                    str(summary["low"]),
                    str(summary["kev_count"]),
                    str(summary["high_epss_count"]),
                    str(len(assets)),
                    str(len(findings)),
                ],
            ],
            col_widths=[0.8 * inch] * 8,
        )
    )
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("Leadership View", styles["SectionTitle"]))
    elements.append(Paragraph(f"<b>Business impact profile:</b> {summary['top_impact']}", styles["SmallBody"]))
    elements.append(Paragraph(f"<b>Public exploit context:</b> {summary['exploit_count']} finding(s) include a public exploit signal.", styles["SmallBody"]))
    elements.append(Paragraph("<b>Recommended action:</b> Assign owners, confirm whether exposed services are necessary, and prioritize patching or exposure reduction for the highest-risk items.", styles["SmallBody"]))
    elements.append(Spacer(1, 12))

    if assets:
        elements.append(Paragraph("Validated Endpoints", styles["SectionTitle"]))
        asset_rows = [["Host", "IP Address", "Open Ports", "Risk Score"]]
        for asset in assets:
            asset_rows.append([asset["host"], asset["ip"], str(asset["open_ports"]), f"{float(asset['risk_score']):.1f}"])
        elements.append(_pdf_table(asset_rows, col_widths=[2.2 * inch, 1.6 * inch, 1.1 * inch, 1.0 * inch]))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("Technical Findings", styles["SectionTitle"]))
    if not findings:
        elements.append(Paragraph("No correlated findings were recorded for this run.", styles["BodyText"]))
    else:
        for idx, finding in enumerate(findings, start=1):
            severity = finding.get("severity", "UNKNOWN")
            elements.append(
                Paragraph(
                    f"{idx}. <b>{finding.get('cve_id', 'N/A')}</b> — {finding.get('title', 'Untitled finding')} <font color='#64748b'>[{severity}]</font>",
                    styles["BodyText"],
                )
            )
            elements.append(Spacer(1, 4))
            elements.append(
                _pdf_table(
                    [
                        ["CVSS", "EPSS", "Priority", "Impact"],
                        [
                            f"{float(finding.get('cvss', 0.0)):.1f}",
                            f"{float(finding.get('epss', 0.0) or 0.0):.2f}",
                            finding.get("priority_label", severity),
                            finding.get("business_impact_label", "Operational Risk"),
                        ],
                    ],
                    col_widths=[0.9 * inch, 0.9 * inch, 1.5 * inch, 2.8 * inch],
                    header_background=colors.HexColor("#334155"),
                )
            )
            elements.append(Spacer(1, 4))
            if finding.get("plain_summary"):
                elements.append(Paragraph(f"<b>Plain-language summary:</b> {finding['plain_summary']}", styles["SmallBody"]))
            if finding.get("why_it_matters"):
                elements.append(Paragraph(f"<b>Why it matters:</b> {finding['why_it_matters']}", styles["SmallBody"]))
            if finding.get("priority_reason"):
                elements.append(Paragraph(f"<b>Priority context:</b> {finding['priority_reason']}", styles["SmallBody"]))
            if finding.get("recommended_next_step"):
                elements.append(Paragraph(f"<b>Recommended next step:</b> {finding['recommended_next_step']}", styles["SmallBody"]))
            if finding.get("evidence"):
                elements.append(Paragraph(f"<b>Evidence:</b> {shorten(str(finding['evidence']), width=420, placeholder=' ...')}", styles["SmallBody"]))
            if finding.get("remediation"):
                elements.append(Paragraph(f"<b>Remediation:</b> {finding['remediation']}", styles["SmallBody"]))
            elements.append(Spacer(1, 10))

    doc.build(elements)


layout = dbc.Container(
    [
        dcc.Interval(id="report-tick", interval=10000, n_intervals=0),
        dcc.Download(id="report-download"),
        page_header(
            "Assessment report",
            "Generate a consolidated readout for a completed run, including executive summary, assets, detailed findings, and a downloadable PDF report.",
            icon="bi-file-earmark-text",
            eyebrow="Reporting",
            meta=[pill("Run summary", "primary"), pill("PDF export available", "success")],
        ),
        surface(
            [
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                dbc.Label("Execution session", className="fw-semibold mb-2"),
                                dcc.Dropdown(id="report-run-select", placeholder="Select session to compile...", className="font-monospace"),
                            ],
                            md=6,
                        ),
                        dbc.Col(
                            [
                                html.Div(
                                    [
                                        dbc.Button(
                                            [html.I(className="bi bi-download me-2"), "Export PDF"],
                                            id="report-export-btn",
                                            color="secondary",
                                            outline=True,
                                            className="w-100 vp-action-button",
                                        )
                                    ],
                                    className="h-100 d-flex align-items-end justify-content-md-end pt-4 pt-md-0",
                                )
                            ],
                            md=6,
                        ),
                    ]
                ),
            ],
            title="Report source",
            subtitle="Reports are generated from completed runs only.",
            icon="bi-funnel",
            class_name="mb-4",
        ),
        surface(html.Div(id="report-content"), title="Generated report", subtitle="Structured summary based on the selected execution session.", icon="bi-journal-richtext"),
    ],
    fluid=True,
    className="py-2",
)


@dash.callback(Output("report-run-select", "options"), Input("report-tick", "n_intervals"))
def load_runs(_):
    try:
        runs = requests.get(f"{API}/runs", timeout=3).json().get("runs", [])
    except Exception:
        return []
    return [{"label": f"[{run['status'].upper()}] {run['run_id'][:8]} — {run['scope']}", "value": run["run_id"]} for run in runs if run["status"] == "done"]


@dash.callback(Output("report-content", "children"), Input("report-run-select", "value"))
def generate_report(run_id):
    if not run_id:
        return empty_state("No run selected", "Choose a completed run to generate a consolidated report view.", icon="bi-file-earmark-text")

    try:
        payload = _fetch_report_payload(run_id)
    except Exception:
        return dbc.Alert("Could not establish uplink to backend.", color="danger")
    return _render_report(payload)


@dash.callback(
    Output("report-download", "data"),
    Input("report-export-btn", "n_clicks"),
    State("report-run-select", "value"),
    prevent_initial_call=True,
)
def export_report_pdf(_clicks, run_id):
    if not run_id:
        raise PreventUpdate

    payload = _fetch_report_payload(run_id)

    def _writer(buffer: BytesIO):
        _build_pdf(buffer, payload)

    scope = str(payload["status"].get("scope", "scope")).replace("/", "_").replace(" ", "_")
    filename = f"vulnpilot-report-{scope}-{run_id[:8]}.pdf"
    return dcc.send_bytes(_writer, filename)

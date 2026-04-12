"""
Dashboard — overview of recent scan runs + summary stats + graphs.
"""

import requests
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output
import plotly.express as px
import pandas as pd
from config import API_BASE_URL

try:
    from frontend.components.ui import page_header, surface, metric_tile, pill, empty_state
except ImportError:
    from components.ui import page_header, surface, metric_tile, pill, empty_state

API = API_BASE_URL

dash.register_page(__name__, path="/", name="Dashboard")


layout = dbc.Container(
    [
        dcc.Interval(id="dash-tick", interval=5000, n_intervals=0),
        page_header(
            "Security Command Center",
            "Track scan execution, observed exposure, and drift across monitored scopes from one operational workspace.",
            icon="bi-grid-1x2-fill",
            eyebrow="Overview",
            meta=[
                pill("CrewAI orchestrated", "primary"),
                pill("Historical diffing active", "success"),
                pill("Web operator console", "muted"),
            ],
            actions=[
                dbc.Button([html.I(className="bi bi-crosshair2 me-2"), "Start Scan"], href="/new-scan", color="primary", className="vp-action-button"),
                dbc.Button([html.I(className="bi bi-globe2 me-2"), "Managed Sites"], href="/sites", outline=True, color="secondary", className="vp-action-button"),
            ],
        ),
        surface(
            [
                html.Div(id="summary-cards", className="vp-stat-grid"),
            ],
            title="Current posture",
            subtitle="Live counts based on completed runs and the latest stored findings.",
            icon="bi-speedometer2",
            class_name="compact mb-4",
        ),
        dbc.Row(
            [
                dbc.Col(
                    surface(
                        dcc.Loading(
                            dcc.Graph(id="severity-donut", config={"displayModeBar": False}, style={"height": "320px"}),
                            type="dot",
                        ),
                        title="Finding severity mix",
                        subtitle="Distribution of correlated findings across all completed runs.",
                        icon="bi-pie-chart-fill",
                        class_name="h-100",
                    ),
                    md=5,
                    className="mb-4",
                ),
                dbc.Col(
                    surface(
                        dcc.Loading(
                            dcc.Graph(id="vuln-assets-bar", config={"displayModeBar": False}, style={"height": "320px"}),
                            type="dot",
                        ),
                        title="Highest-risk assets",
                        subtitle="Top assets ranked by stored risk score across completed scans.",
                        icon="bi-bar-chart-fill",
                        class_name="h-100",
                    ),
                    md=7,
                    className="mb-4",
                ),
            ]
        ),
        surface(
            html.Div(id="runs-table"),
            title="Recent runs",
            subtitle="Latest execution sessions, progress state, scope, and scan profile.",
            icon="bi-broadcast-pin",
        ),
    ],
    fluid=True,
    className="py-2",
)


@dash.callback(
    Output("summary-cards", "children"),
    Output("runs-table", "children"),
    Output("severity-donut", "figure"),
    Output("vuln-assets-bar", "figure"),
    Input("dash-tick", "n_intervals"),
)
def refresh_dashboard(_):
    empty_layout = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=0, b=0, l=0, r=0),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        font=dict(color="rgba(189,203,227,0.45)", family="Sora"),
        annotations=[
            dict(
                text="No data yet",
                showarrow=False,
                font=dict(size=13, color="rgba(189,203,227,0.4)"),
                x=0.5,
                y=0.5,
                xref="paper",
                yref="paper",
            )
        ],
    )
    fig_donut = {"data": [], "layout": empty_layout}
    fig_bar = {"data": [], "layout": empty_layout}

    try:
        runs_data = requests.get(f"{API}/runs", timeout=3).json().get("runs", [])
    except Exception:
        cards = [
            metric_tile("Scan runs", "—", icon="bi-broadcast", tone="primary", hint="Backend offline"),
            metric_tile("Live sessions", "—", icon="bi-activity", tone="warning", hint="Waiting for API"),
            metric_tile("Assets tracked", "—", icon="bi-hdd-network", tone="success", hint="No inventory"),
            metric_tile("Critical findings", "—", icon="bi-shield-slash", tone="danger", hint="No correlation data"),
        ]
        return cards, dbc.Alert("Backend not reachable. Start the API on port 8000.", color="danger"), fig_donut, fig_bar

    running = sum(1 for r in runs_data if r["status"] == "running")
    all_findings = []
    all_assets = []

    for run in runs_data:
        if run["status"] != "done":
            continue
        try:
            findings_data = requests.get(f"{API}/findings", params={"run_id": run["run_id"]}, timeout=3).json()
            assets_data = requests.get(f"{API}/assets", params={"run_id": run["run_id"]}, timeout=3).json()
        except Exception:
            continue
        all_findings.extend(findings_data.get("findings", []))
        all_assets.extend(assets_data.get("assets", []))

    critical_count = sum(1 for finding in all_findings if finding["severity"] == "CRITICAL")
    total_assets = len(set(asset["ip"] for asset in all_assets))

    cards = [
        metric_tile("Scan runs", len(runs_data), icon="bi-broadcast", tone="primary", hint="Stored execution sessions"),
        metric_tile("Live sessions", running, icon="bi-activity", tone="warning", hint="Queued or actively running scans"),
        metric_tile("Assets tracked", total_assets, icon="bi-hdd-network", tone="success", hint="Unique IPs seen in completed runs"),
        metric_tile("Critical findings", critical_count, icon="bi-shield-slash", tone="danger", hint="Critical CVEs currently present"),
    ]

    common_layout = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=8, b=8, l=8, r=8),
        font=dict(family="JetBrains Mono", color="rgba(216,228,246,0.82)"),
    )
    palette = {"CRITICAL": "#ff6d81", "HIGH": "#ffb95c", "MEDIUM": "#6be3ff", "LOW": "#67d5a5"}

    if all_findings:
        df_findings = pd.DataFrame(all_findings)
        sev_counts = df_findings["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        total_findings = len(all_findings)
        fig_donut = px.pie(
            sev_counts,
            values="Count",
            names="Severity",
            hole=0.72,
            color="Severity",
            color_discrete_map=palette,
        )
        fig_donut.update_traces(
            textinfo="label+percent",
            textfont=dict(size=11, color="white", family="Sora"),
            marker=dict(line=dict(color="rgba(7,17,31,0.95)", width=3)),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<extra></extra>",
        )
        fig_donut.update_layout(
            **common_layout,
            showlegend=True,
            legend=dict(
                orientation="v",
                x=1.0,
                y=0.5,
                font=dict(size=11, color="rgba(216,228,246,0.72)"),
                bgcolor="rgba(0,0,0,0)",
            ),
            annotations=[
                dict(
                    text=f"<b>{total_findings}</b><br><span style='font-size:10px'>findings</span>",
                    x=0.5,
                    y=0.5,
                    showarrow=False,
                    font=dict(size=16, color="#7fb3ff", family="Sora"),
                )
            ],
        )

    if all_assets:
        df_assets = pd.DataFrame(all_assets)
        grouped = df_assets.groupby("host").agg({"risk_score": "max"}).reset_index()
        top_assets = grouped.sort_values("risk_score", ascending=True).tail(6)

        def risk_color(score):
            if score >= 8:
                return palette["CRITICAL"]
            if score >= 5:
                return palette["HIGH"]
            return palette["LOW"]

        fig_bar = px.bar(
            top_assets,
            x="risk_score",
            y="host",
            orientation="h",
            text="risk_score",
        )
        fig_bar.update_traces(
            marker_color=[risk_color(score) for score in top_assets["risk_score"]],
            marker_line_width=0,
            texttemplate="<b>%{text:.1f}</b>",
            textposition="outside",
            textfont=dict(color="rgba(216,228,246,0.9)", size=11),
            hovertemplate="<b>%{y}</b><br>Risk score: %{x:.1f}<extra></extra>",
        )
        fig_bar.update_layout(
            **common_layout,
            xaxis=dict(
                showgrid=True,
                gridcolor="rgba(255,255,255,0.06)",
                zeroline=False,
                title="",
                tickfont=dict(color="rgba(216,228,246,0.58)", size=10),
                range=[0, 11],
            ),
            yaxis=dict(showgrid=False, title="", tickfont=dict(color="rgba(216,228,246,0.85)", size=11)),
            bargap=0.34,
        )

    if not runs_data:
        table = empty_state("No runs yet", "Launch a scan to populate this workspace with execution history and correlated findings.", icon="bi-broadcast")
    else:
        rows = []
        for run in runs_data:
            status = run["status"]
            status_color = {
                "done": "success",
                "running": "primary",
                "queued": "secondary",
                "failed": "danger",
                "stopped": "warning",
            }.get(status, "secondary")
            progress = dbc.Progress(
                value=run["progress"],
                color=status_color,
                striped=True,
                animated=(status == "running"),
                style={"height": "10px"},
            )
            rows.append(
                html.Tr(
                    [
                        html.Td(html.A(run["run_id"][:8], href=f"/run/{run['run_id']}", className="fw-bold text-primary font-monospace")),
                        html.Td(html.Code(run["scope"] or "—", className="bg-transparent p-0 text-light")),
                        html.Td(dbc.Badge(status.upper(), color=status_color)),
                        html.Td(progress, style={"minWidth": "180px"}),
                        html.Td(dbc.Badge(run["profile"], color="dark", className="border")),
                        html.Td(run.get("created_at", "")[:19], className="text-muted font-monospace small"),
                    ]
                )
            )
        table = dbc.Table(
            [
                html.Thead(
                    html.Tr(
                        [
                            html.Th("Run ID"),
                            html.Th("Scope"),
                            html.Th("Status"),
                            html.Th("Progress"),
                            html.Th("Profile"),
                            html.Th("Started"),
                        ]
                    )
                ),
                html.Tbody(rows),
            ],
            hover=True,
            responsive=True,
            className="align-middle mb-0",
        )

    return cards, table, fig_donut, fig_bar

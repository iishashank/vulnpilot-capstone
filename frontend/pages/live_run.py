"""
Live Run — real-time progress bar + log streaming for a running scan.
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

dash.register_page(__name__, path_template="/run/<run_id>", name="Live Run")


def layout(run_id=None, **kwargs):
    return dbc.Container(
        [
            dcc.Store(id="run_id_store", data=run_id),
            dcc.Store(id="last_log_id", data=0),
            dcc.Interval(id="tick", interval=1500, n_intervals=0),
            page_header(
                "Live execution",
                "Follow the active scan in real time, including progress, backend status, and orchestration logs.",
                icon="bi-broadcast",
                eyebrow="Runtime",
                meta=[pill(f"Run {run_id[:8]}" if run_id else "No run selected", "primary")],
                actions=[
                    dbc.Button([html.I(className="bi bi-arrow-left me-2"), "Dashboard"], href="/", outline=True, color="secondary", className="vp-action-button"),
                ],
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            surface(
                                [
                                    html.Div(id="status_text", className="mb-4"),
                                    dbc.Progress(id="progress", value=0, color="primary", striped=True, animated=True, style={"height": "12px"}, className="mb-4"),
                                    html.Div(
                                        [
                                            dbc.Button([html.I(className="bi bi-stop-circle me-2"), "Abort run"], id="stop_btn", color="danger", outline=True, className="vp-action-button"),
                                        ],
                                        className="vp-inline-actions",
                                    ),
                                    html.Div(id="stop_feedback", className="mt-4"),
                                ],
                                title="Execution state",
                                subtitle="Progress and run metadata are refreshed every 1.5 seconds.",
                                icon="bi-activity",
                                class_name="mb-4",
                            ),
                            html.Div(id="done-links"),
                        ],
                        md=4,
                        className="mb-4",
                    ),
                    dbc.Col(
                        surface(
                            [
                                html.Div(
                                    [
                                        html.Span("Awaiting telemetry...", id="log-status", className="text-muted small font-monospace"),
                                    ],
                                    className="d-flex justify-content-end mb-3",
                                ),
                                html.Pre(id="logs_box", className="cyber-terminal mb-0"),
                            ],
                            title="Runtime log stream",
                            subtitle="Agent-stage events, warnings, and errors from the backend execution pipeline.",
                            icon="bi-terminal",
                            class_name="h-100",
                        ),
                        md=8,
                    ),
                ]
            ),
        ],
        fluid=True,
        className="py-2",
    )


@dash.callback(
    Output("progress", "value"),
    Output("progress", "color"),
    Output("progress", "style"),
    Output("status_text", "children"),
    Output("done-links", "children"),
    Input("tick", "n_intervals"),
    State("run_id_store", "data"),
)
def poll_status(_, run_id):
    if not run_id:
        return 0, "primary", {"height": "12px"}, "", ""

    try:
        status = requests.get(f"{API}/scan/{run_id}/status", timeout=3).json()
    except Exception:
        return 0, "primary", {"height": "12px"}, dbc.Alert("Cannot reach backend", color="warning"), ""

    if "error" in status:
        return 0, "danger", {"height": "12px"}, dbc.Alert("Run not found", color="danger"), ""

    state = status["status"]
    progress = status["progress"]
    color_map = {"running": "primary", "done": "success", "failed": "danger", "stopped": "warning", "queued": "info"}
    bar_color = color_map.get(state, "primary")

    info = html.Div(
        [
            html.Div(dbc.Badge(state.upper(), color=bar_color, className="mb-3"), className="mb-2"),
            html.Div([html.Span("Profile", className="text-muted d-block small"), html.Strong(status["profile"].upper(), className="tone-primary")], className="mb-3"),
            html.Div([html.Span("Scope", className="text-muted d-block small"), html.Code(status["scope"], className="bg-transparent p-0 text-light")], className="mb-3"),
            html.Div([html.Span("Progress", className="text-muted d-block small"), html.Strong(f"{progress}%", className="font-monospace")]),
        ]
    )

    links = ""
    if state == "done":
        links = surface(
            [
                html.Div(
                    [
                        dbc.Button([html.I(className="bi bi-hdd-network me-2"), "Assets"], href="/assets", outline=True, color="secondary", className="vp-action-button"),
                        dbc.Button([html.I(className="bi bi-bug me-2"), "Findings"], href="/findings", outline=True, color="secondary", className="vp-action-button"),
                        dbc.Button([html.I(className="bi bi-file-earmark-text me-2"), "Report"], href="/report", color="success", className="vp-action-button"),
                    ],
                    className="vp-inline-actions",
                )
            ],
            title="Run complete",
            subtitle="Jump into the post-run analysis pages.",
            icon="bi-check-circle",
        )

    return progress, bar_color, {"height": "12px"}, info, links


@dash.callback(
    Output("logs_box", "children"),
    Output("last_log_id", "data"),
    Output("log-status", "children"),
    Input("tick", "n_intervals"),
    State("run_id_store", "data"),
    State("last_log_id", "data"),
    State("logs_box", "children"),
)
def poll_logs(_, run_id, last_id, existing):
    if not run_id:
        return "", 0, "Idle"

    try:
        data = requests.get(f"{API}/scan/{run_id}/logs", params={"since_id": last_id}, timeout=3).json()
    except Exception:
        return existing or "", last_id, "Connection lost"

    logs = data.get("logs", [])
    if not logs:
        return existing or "", last_id, "Streaming..."

    def colorize(entry):
        level = entry["level"]
        ts = entry["ts"][11:19]
        if level == "ERROR":
            line = html.Span(f"[ERR] {entry['message']}", style={"color": "#ff7f90"})
        elif level == "WARN":
            line = html.Span(f"[WRN] {entry['message']}", style={"color": "#ffc46d"})
        else:
            line = html.Span(f"[INF] {entry['message']}")
        return html.Div([html.Span(f"[{ts}] ", className="text-muted"), line])

    new_lines = [colorize(log) for log in logs]
    if existing:
        merged = existing + new_lines if isinstance(existing, list) else [existing] + new_lines
        return merged, logs[-1]["id"], f"Receiving ({len(logs)} new lines)"
    return new_lines, logs[-1]["id"], f"Receiving ({len(logs)} new lines)"


@dash.callback(
    Output("stop_btn", "disabled"),
    Output("stop_feedback", "children"),
    Input("stop_btn", "n_clicks"),
    State("run_id_store", "data"),
    prevent_initial_call=True,
)
def stop_run(_, run_id):
    try:
        requests.post(f"{API}/scan/{run_id}/stop", headers=API_REQUEST_HEADERS, timeout=3)
    except Exception:
        return False, dbc.Alert([html.I(className="bi bi-exclamation-triangle me-2"), "Failed to send abort signal."], color="danger")
    return True, dbc.Alert([html.I(className="bi bi-info-circle me-2"), "Abort signal sent. Awaiting termination."], color="warning")

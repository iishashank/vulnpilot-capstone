"""
Evaluation — controlled validation metrics and explainability coverage.
"""

import requests
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output, ctx

from frontend.config import API_BASE_URL, API_REQUEST_HEADERS

try:
    from frontend.components.ui import page_header, surface, metric_tile, empty_state, pill
except ImportError:
    from components.ui import page_header, surface, metric_tile, empty_state, pill


API = API_BASE_URL

dash.register_page(__name__, path="/evaluation", name="Evaluation")


def _fmt_pct(value):
    if value is None:
        return "—"
    return f"{float(value):.2f}%"


def _metric_cards(metrics: dict, explainability_label: str) -> list:
    tone_map = {
        "scan_success_rate": "primary",
        "vulnerability_correlation_precision": "danger",
        "drift_detection_precision": "warning",
        "drift_detection_recall": "info",
        "drift_detection_f1": "success",
        "alert_deduplication_rate": "primary",
        "prioritization_quality": "warning",
        "explainability_score": "success",
    }
    icon_map = {
        "scan_success_rate": "bi-check2-circle",
        "vulnerability_correlation_precision": "bi-bug",
        "drift_detection_precision": "bi-crosshair2",
        "drift_detection_recall": "bi-arrow-repeat",
        "drift_detection_f1": "bi-broadcast-pin",
        "alert_deduplication_rate": "bi-bell-slash",
        "prioritization_quality": "bi-sort-down",
        "explainability_score": "bi-chat-square-text",
    }
    label_map = {
        "scan_success_rate": "Scan Success Rate",
        "vulnerability_correlation_precision": "Correlation Precision",
        "drift_detection_precision": "Drift Precision",
        "drift_detection_recall": "Drift Recall",
        "drift_detection_f1": "Drift F1",
        "alert_deduplication_rate": "Alert Dedup Rate",
        "prioritization_quality": "Prioritization Quality",
        "explainability_score": explainability_label,
    }
    ordered_keys = [
        "scan_success_rate",
        "vulnerability_correlation_precision",
        "drift_detection_precision",
        "drift_detection_recall",
        "drift_detection_f1",
        "alert_deduplication_rate",
        "prioritization_quality",
        "explainability_score",
    ]
    return [
        metric_tile(
            label_map[key],
            _fmt_pct(metrics.get(key)),
            icon=icon_map[key],
            tone=tone_map[key],
            hint="Validation metric" if "drift" in key or "correlation" in key else "Evaluation signal",
        )
        for key in ordered_keys
    ]


layout = dbc.Container(
    [
        dcc.Interval(id="eval-tick", interval=10000, n_intervals=0),
        page_header(
            "Evaluation and trust metrics",
            "Inspect controlled validation scores, live operational metrics, and the plain-language explainability layer used for non-technical reviewers.",
            icon="bi-clipboard-data",
            eyebrow="Evaluation",
            meta=[
                pill("Controlled validation", "primary"),
                pill("Live operational metrics", "warning"),
                pill("Explainability visible", "success"),
            ],
            actions=[
                dbc.Button(
                    [html.I(className="bi bi-play-circle me-2"), "Run controlled evaluation"],
                    id="eval-run-btn",
                    color="primary",
                    className="vp-action-button",
                ),
            ],
        ),
        html.Div(id="eval-status", className="mb-4"),
        surface(
            html.Div(id="eval-validation-cards", className="vp-stat-grid"),
            title="Controlled validation harness",
            subtitle="These top metrics are from a seeded three-run scenario with known banners and known drift, and should be presented as correctness checks under known conditions rather than as universal benchmarks.",
            icon="bi-bezier2",
            class_name="compact mb-4",
        ),
        dbc.Row(
            [
                dbc.Col(
                    surface(
                        html.Div(id="eval-operational-cards", className="vp-stat-grid"),
                        title="Live prototype metrics",
                        subtitle="These bottom metrics reflect ongoing prototype behavior over accumulated runs in the current database state rather than seeded ground-truth validation.",
                        icon="bi-speedometer2",
                        class_name="compact h-100",
                    ),
                    md=6,
                    className="mb-4",
                ),
                dbc.Col(
                    surface(
                        html.Div(id="eval-methodology"),
                        title="Measurement notes",
                        subtitle="Definitions and caveats for the metrics shown in this panel.",
                        icon="bi-info-circle",
                        class_name="h-100",
                    ),
                    md=6,
                    className="mb-4",
                ),
            ]
        ),
        surface(
            html.Div(id="eval-explainability"),
            title="Explainability sample",
            subtitle="A real plain-language summary generated from the controlled evaluation findings.",
            icon="bi-chat-square-text",
        ),
    ],
    fluid=True,
    className="py-2",
)


@dash.callback(
    Output("eval-status", "children"),
    Output("eval-validation-cards", "children"),
    Output("eval-operational-cards", "children"),
    Output("eval-methodology", "children"),
    Output("eval-explainability", "children"),
    Input("eval-tick", "n_intervals"),
    Input("eval-run-btn", "n_clicks"),
    prevent_initial_call=False,
)
def refresh_evaluation(_tick, run_clicks):
    action_notice = None
    if ctx.triggered_id == "eval-run-btn":
        try:
            response = requests.post(
                f"{API}/evaluation/run",
                headers=API_REQUEST_HEADERS,
                timeout=5,
            )
            payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            if response.ok:
                action_notice = dbc.Alert(payload.get("message", "Controlled evaluation started."), color="info")
            else:
                detail = payload.get("detail", "Could not start controlled evaluation.")
                action_notice = dbc.Alert(str(detail), color="warning")
        except Exception as exc:
            action_notice = dbc.Alert(f"Could not start controlled evaluation: {exc}", color="danger")

    try:
        snapshot = requests.get(f"{API}/evaluation/metrics", timeout=5).json()
    except Exception:
        empty = empty_state(
            "Evaluation service unavailable",
            "The backend could not be reached, so no metrics or explainability sample could be loaded.",
            icon="bi-clipboard-x",
        )
        status = action_notice or dbc.Alert("Backend not reachable. Start the API to load evaluation metrics.", color="danger")
        return status, empty, empty, empty, empty

    status_data = snapshot.get("status", {})
    validation = snapshot.get("validation") or {}
    operational = snapshot.get("operational") or {}

    status_parts = []
    if action_notice:
        status_parts.append(action_notice)

    if status_data.get("running"):
        status_parts.append(
            dbc.Alert(
                f"Controlled evaluation running since {status_data.get('started_at', '—')}. {status_data.get('message', '')}",
                color="primary",
            )
        )
    else:
        status_parts.append(
            dbc.Alert(
                status_data.get("message", "No controlled evaluation has been run yet."),
                color="secondary" if not validation else "success",
            )
        )

    validation_metrics = validation.get("metrics") or {}
    if validation_metrics:
        validation_cards = _metric_cards(validation_metrics, "Explainability Score")
    else:
        validation_cards = [
            empty_state(
                "No controlled metrics yet",
                "Run the controlled evaluation to populate the paper-facing metrics such as Scan Success Rate, Correlation Precision, Drift F1, and Explainability Score.",
                icon="bi-play-circle",
            )
        ]

    operational_cards = [
        metric_tile("Runtime SSR", _fmt_pct(operational.get("scan_success_rate")), icon="bi-check2-circle", tone="primary", hint=f"{operational.get('completed_runs', 0)}/{operational.get('total_runs', 0)} completed"),
        metric_tile("Dedup Rate", _fmt_pct(operational.get("alert_deduplication_rate")), icon="bi-bell-slash", tone="warning", hint=f"{operational.get('alert_count', 0)} alert rows"),
        metric_tile("Priority Quality", _fmt_pct(operational.get("prioritization_quality")), icon="bi-sort-down", tone="info", hint=f"{operational.get('finding_count', 0)} findings ranked"),
        metric_tile("Explainability Coverage", _fmt_pct(operational.get("explainability_score")), icon="bi-chat-square-text", tone="success", hint="Coverage proxy over generated explanations"),
    ]

    notes = validation.get("notes") or [
        "Controlled metrics are computed only from the seeded validation scenario, not inferred from arbitrary production data without ground truth.",
        "Explainability Score in the app is currently a coverage proxy based on generated explanation completeness.",
    ]
    methodology = html.Div(
        [
            html.Ul([html.Li(note, className="vp-muted-note mb-2") for note in notes], className="mb-0"),
            html.Hr(className="border-secondary opacity-25"),
            html.Div(
                [
                    html.H5("How to present these metrics", className="vp-explain-panel-title mb-2"),
                    html.Ul(
                        [
                            html.Li(
                                "These top metrics are from a controlled validation harness used to verify correctness.",
                                className="vp-muted-note mb-2",
                            ),
                            html.Li(
                                "These bottom metrics reflect live system behavior over accumulated runs.",
                                className="vp-muted-note mb-2",
                            ),
                            html.Li(
                                "So the first set proves correctness under known conditions, and the second set reflects ongoing prototype operation.",
                                className="vp-muted-note mb-0",
                            ),
                        ],
                        className="mb-3",
                    ),
                    html.H5("What not to claim", className="vp-explain-panel-title mb-2"),
                    html.Ul(
                        [
                            html.Li(
                                "Do not present the top block as a universal benchmark across arbitrary environments.",
                                className="vp-muted-note mb-2",
                            ),
                            html.Li(
                                "Do not claim the system always achieves 100% precision or recall in real-world deployments.",
                                className="vp-muted-note mb-2",
                            ),
                            html.Li(
                                "Do not imply this is internet-scale or production-scale benchmarking; it is controlled prototype validation plus live operational telemetry.",
                                className="vp-muted-note mb-0",
                            ),
                        ],
                        className="mb-3",
                    ),
                    html.Hr(className="border-secondary opacity-25"),
                ]
            ),
            html.Div(
                [
                    html.Span("Mode", className="vp-explain-label"),
                    html.P(validation.get("mode", "—"), className="vp-explain-text mb-2"),
                    html.Span("Scenario", className="vp-explain-label"),
                    html.P(
                        f"{validation.get('scenario', {}).get('host', '—')} | baseline {validation.get('scenario', {}).get('baseline_banner', '—')} | changed {validation.get('scenario', {}).get('changed_banner', '—')}",
                        className="vp-explain-text mb-0",
                    ),
                ]
            ),
        ]
    )

    sample = (validation.get("evidence") or {}).get("sample_explanation") or {}
    if sample:
        explainability = html.Div(
            [
                dbc.Badge("Stakeholder-facing output", color="success", className="mb-3"),
                html.H4(sample.get("plain_title", "Plain-language explanation"), className="vp-explain-panel-title"),
                html.P(sample.get("plain_summary", ""), className="vp-explain-text"),
                dbc.Row(
                    [
                        dbc.Col(
                            surface(
                                html.P(sample.get("business_impact_reason", ""), className="vp-explain-text mb-0"),
                                title=sample.get("business_impact_label", "Business impact"),
                                icon="bi-briefcase",
                                class_name="compact h-100",
                            ),
                            md=6,
                            className="mb-3",
                        ),
                        dbc.Col(
                            surface(
                                html.P(sample.get("why_it_matters", ""), className="vp-explain-text mb-0"),
                                title="Why it matters",
                                icon="bi-exclamation-diamond",
                                class_name="compact h-100",
                            ),
                            md=6,
                            className="mb-3",
                        ),
                    ]
                ),
                dbc.Row(
                    [
                        dbc.Col(
                            surface(
                                html.P(sample.get("priority_reason", ""), className="vp-explain-text mb-0"),
                                title="Priority context",
                                icon="bi-sort-down",
                                class_name="compact h-100",
                            ),
                            md=6,
                            className="mb-3",
                        ),
                        dbc.Col(
                            surface(
                                html.P(sample.get("recommended_next_step", ""), className="vp-explain-text mb-0"),
                                title="Recommended next step",
                                icon="bi-arrow-right-circle",
                                class_name="compact h-100",
                            ),
                            md=6,
                            className="mb-3",
                        ),
                    ]
                ),
            ]
        )
    else:
        explainability = empty_state(
            "No explainability sample yet",
            "Run the controlled evaluation to generate a real plain-language explanation sample from a seeded finding.",
            icon="bi-chat-square-text",
        )

    return status_parts, validation_cards, operational_cards, methodology, explainability

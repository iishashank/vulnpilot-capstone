"""
Shared Dash UI primitives for the VulnPilot frontend.
"""

from dash import html
import dash_bootstrap_components as dbc


def page_header(title, subtitle, icon="bi-grid-1x2", eyebrow=None, actions=None, meta=None):
    return html.Div(
        [
            html.Div(
                [
                    html.Div(
                        [html.Span(eyebrow, className="vp-kicker")] if eyebrow else [],
                        className="mb-2",
                    ),
                    html.Div(
                        [
                            html.Span(html.I(className=f"bi {icon}"), className="vp-page-icon"),
                            html.H2(title, className="vp-page-title"),
                        ],
                        className="vp-page-title-row",
                    ),
                    html.P(subtitle, className="vp-page-subtitle"),
                    html.Div(meta or [], className="vp-page-meta"),
                ],
                className="vp-page-copy",
            ),
            html.Div(actions or [], className="vp-page-actions"),
        ],
        className="vp-page-header",
    )


def surface(children, title=None, subtitle=None, icon=None, actions=None, class_name=""):
    header = None
    if title or subtitle or icon or actions:
        header = html.Div(
            [
                html.Div(
                    [
                        html.Div(
                            [
                                html.Span(html.I(className=f"bi {icon}"), className="vp-panel-icon")
                                if icon
                                else None,
                                html.Div(
                                    [
                                        html.H3(title, className="vp-panel-title") if title else None,
                                        html.P(subtitle, className="vp-panel-subtitle") if subtitle else None,
                                    ]
                                ),
                            ],
                            className="vp-panel-heading",
                        ),
                    ]
                ),
                html.Div(actions or [], className="vp-panel-actions"),
            ],
            className="vp-panel-header",
        )
    return html.Section(
        [header, html.Div(children, className="vp-panel-body")],
        className=f"vp-surface {class_name}".strip(),
    )


def metric_tile(label, value, icon="bi-activity", tone="primary", hint=None):
    return html.Div(
        [
            html.Div(
                [
                    html.Span(html.I(className=f"bi {icon}"), className=f"vp-metric-icon tone-{tone}"),
                    html.Span(label, className="vp-metric-label"),
                ],
                className="vp-metric-top",
            ),
            html.Div(str(value), className=f"vp-metric-value tone-{tone}"),
            html.Div(hint or "", className="vp-metric-hint"),
        ],
        className="vp-metric-tile",
    )


def empty_state(title, detail, icon="bi-inbox"):
    return html.Div(
        [
            html.Div(html.I(className=f"bi {icon}"), className="vp-empty-icon"),
            html.H4(title, className="vp-empty-title"),
            html.P(detail, className="vp-empty-detail"),
        ],
        className="vp-empty-state",
    )


def pill(text, tone="muted"):
    return html.Span(text, className=f"vp-pill tone-{tone}")


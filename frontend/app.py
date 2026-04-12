import os
import dash
import dash_bootstrap_components as dbc
from dash import html
try:
    from frontend.components.navbar import navbar
except ImportError:
    from components.navbar import navbar

app = dash.Dash(
    __name__,
    use_pages=True,
    external_stylesheets=[
        dbc.themes.DARKLY,      # Base dark theme
        dbc.icons.BOOTSTRAP,    # Icons
    ],
    suppress_callback_exceptions=True,
    title="VulnPilot — Vulnerability Assessment",
    meta_tags=[
        {"name": "description", "content": "Autonomous multi-agent cybersecurity vulnerability assessment dashboard"},
    ],
)
server = app.server

app.layout = html.Div(
    [
        navbar(),
        html.Main(dash.page_container, className="vp-page-shell"),
    ],
    className="vp-app-shell",
)

if __name__ == "__main__":
    app.run(
        debug=os.getenv("DEBUG", "true").lower() in ("1", "true", "yes"),
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8050")),
    )

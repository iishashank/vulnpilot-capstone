"""
config.py — VulnPilot runtime configuration.

All tunables live here. Override any value via environment variable.

  USE_CREWAI=true ./start_backend.sh   → CrewAI/LangChain orchestration path
  USE_CREWAI=false ./start_backend.sh  → direct pipeline path
"""
import os


def _env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).lower() in ("1", "true", "yes")


def _csv_env(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]

# ── Orchestration mode ────────────────────────────────────────────────────────
# When True, scan runs are executed through the CrewAI/LangChain layer
# (backend/orchestrator.py). When False, run_pipeline() in scanner.py is
# called directly.
USE_CREWAI: bool = _env_flag("USE_CREWAI", "true")

# ── API base URL (used by frontend pages) ────────────────────────────────────
API_BASE_URL: str = os.environ.get("VULNPILOT_API_URL", "http://127.0.0.1:8000")

# ── Control-plane security ───────────────────────────────────────────────────
CONTROL_PLANE_API_KEY: str = os.environ.get("VULNPILOT_API_KEY", "").strip()
ALLOW_LOCAL_CONTROL_PLANE: bool = _env_flag("VULNPILOT_ALLOW_LOCAL_CONTROL", "true")
CORS_ORIGINS: list[str] = _csv_env(
    "VULNPILOT_CORS_ORIGINS",
    "http://127.0.0.1:8050,http://127.0.0.1:8060,http://localhost:8050,http://localhost:8060",
)

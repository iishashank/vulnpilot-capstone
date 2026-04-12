#!/usr/bin/env bash
# start_backend.sh — Boot the VulnPilot FastAPI backend.
#
# Usage:
#   ./start_backend.sh
#   PORT=8010 USE_CREWAI=true ./start_backend.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV="$SCRIPT_DIR/.venv"
if [ ! -x "$VENV/bin/python" ]; then
    echo "Missing canonical environment at $VENV"
    echo "Run:"
    echo "  python3 -m venv .venv"
    echo "  .venv/bin/pip install -r backend/requirements.txt"
    echo "  .venv/bin/pip install -r frontend/requirements.txt"
    exit 1
fi

PORT="${PORT:-8000}"
HOST="${HOST:-127.0.0.1}"
USE_CREWAI="${USE_CREWAI:-true}"

if [ ! -f "$SCRIPT_DIR/datasets/vuln_lookup.db" ]; then
    echo "Missing datasets/vuln_lookup.db"
    echo "Run: .venv/bin/python setup_datasets.py"
    exit 1
fi

echo "Starting VulnPilot backend"
echo "  Host:      $HOST"
echo "  Port:      $PORT"
echo "  Ops DB:    $SCRIPT_DIR/datasets/ops.db"
echo "  Vuln DB:   $SCRIPT_DIR/datasets/vuln_lookup.db"
echo "  KEV cache: $SCRIPT_DIR/datasets/kev.json"
echo "  CrewAI:    $USE_CREWAI"
echo

exec env USE_CREWAI="$USE_CREWAI" "$VENV/bin/python" -m uvicorn backend.app:app \
    --host "$HOST" \
    --port "$PORT" \
    --reload \
    --log-level info

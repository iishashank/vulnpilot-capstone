#!/usr/bin/env bash
# start_frontend.sh — Boot the VulnPilot Dash frontend.
#
# Usage:
#   ./start_frontend.sh
#   PORT=8060 API_PORT=8010 ./start_frontend.sh

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

PORT="${PORT:-8050}"
HOST="${HOST:-127.0.0.1}"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8000}"
DEBUG="${DEBUG:-true}"
API_URL="${VULNPILOT_API_URL:-http://${API_HOST}:${API_PORT}}"
PYTHONPATH_VALUE="${PYTHONPATH:-$SCRIPT_DIR}"

echo "Starting VulnPilot frontend"
echo "  Host:    $HOST"
echo "  Port:    $PORT"
echo "  API URL: $API_URL"
echo "  PYTHONPATH: $PYTHONPATH_VALUE"
echo

exec env HOST="$HOST" PORT="$PORT" DEBUG="$DEBUG" PYTHONPATH="$PYTHONPATH_VALUE" \
    VULNPILOT_API_URL="$API_URL" "$VENV/bin/python" -m frontend.app

#!/usr/bin/env bash
# start_demo.sh — one-command demo boot for VulnPilot.
#
# Starts backend and frontend on fresh demo ports, writes logs/PIDs to
# .runtime/, and optionally opens the browser.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV="$SCRIPT_DIR/.venv"
if [ ! -x "$VENV/bin/python" ]; then
    echo "Missing canonical environment at $VENV"
    exit 1
fi

RUNTIME_DIR="$SCRIPT_DIR/.runtime"
mkdir -p "$RUNTIME_DIR"

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8010}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-8060}"
USE_CREWAI="${USE_CREWAI:-true}"
OPEN_BROWSER="${OPEN_BROWSER:-1}"
SEED_DEMO_SITE="${SEED_DEMO_SITE:-1}"
TRIGGER_SAMPLE_SCAN="${TRIGGER_SAMPLE_SCAN:-0}"

if [ -f "$RUNTIME_DIR/backend.pid" ]; then
    OLD_PID="$(cat "$RUNTIME_DIR/backend.pid" 2>/dev/null || true)"
    if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
    fi
fi

if [ -f "$RUNTIME_DIR/frontend.pid" ]; then
    OLD_PID="$(cat "$RUNTIME_DIR/frontend.pid" 2>/dev/null || true)"
    if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
    fi
fi

echo "Booting VulnPilot demo mode"
echo "  Backend:  http://${BACKEND_HOST}:${BACKEND_PORT}"
echo "  Frontend: http://${FRONTEND_HOST}:${FRONTEND_PORT}"
echo

env USE_CREWAI="$USE_CREWAI" "$VENV/bin/python" -m uvicorn backend.app:app \
    --host "$BACKEND_HOST" \
    --port "$BACKEND_PORT" \
    > "$RUNTIME_DIR/backend.log" 2>&1 &
echo $! > "$RUNTIME_DIR/backend.pid"

sleep 2

env HOST="$FRONTEND_HOST" PORT="$FRONTEND_PORT" DEBUG="true" \
    PYTHONPATH="$SCRIPT_DIR" \
    VULNPILOT_API_URL="http://${BACKEND_HOST}:${BACKEND_PORT}" \
    "$VENV/bin/python" -m frontend.app \
    > "$RUNTIME_DIR/frontend.log" 2>&1 &
echo $! > "$RUNTIME_DIR/frontend.pid"

sleep 2

if [ "$SEED_DEMO_SITE" = "1" ]; then
    env BACKEND_HOST="$BACKEND_HOST" BACKEND_PORT="$BACKEND_PORT" TRIGGER_SCAN="$TRIGGER_SAMPLE_SCAN" \
        bash "$SCRIPT_DIR/demo_seed.sh" > "$RUNTIME_DIR/demo_seed.log" 2>&1 || true
fi

echo "Backend PID:  $(cat "$RUNTIME_DIR/backend.pid")"
echo "Frontend PID: $(cat "$RUNTIME_DIR/frontend.pid")"
echo
echo "Open these in your browser:"
echo "  Frontend: http://${FRONTEND_HOST}:${FRONTEND_PORT}"
echo "  API docs: http://${BACKEND_HOST}:${BACKEND_PORT}/docs"
echo
echo "Logs:"
echo "  $RUNTIME_DIR/backend.log"
echo "  $RUNTIME_DIR/frontend.log"
if [ "$SEED_DEMO_SITE" = "1" ]; then
    echo "  $RUNTIME_DIR/demo_seed.log"
fi
echo
echo "Stop both with: ./stop_demo.sh"

if [ "$OPEN_BROWSER" = "1" ] && command -v open >/dev/null 2>&1; then
    open "http://${FRONTEND_HOST}:${FRONTEND_PORT}" >/dev/null 2>&1 || true
fi

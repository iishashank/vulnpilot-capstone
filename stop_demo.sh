#!/usr/bin/env bash
# stop_demo.sh — stop backend/frontend processes started by start_demo.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$SCRIPT_DIR/.runtime"

stop_pid_file() {
    local name="$1"
    local path="$RUNTIME_DIR/$2"
    if [ -f "$path" ]; then
        local pid
        pid="$(cat "$path" 2>/dev/null || true)"
        if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            echo "Stopped $name ($pid)"
        else
            echo "$name already stopped"
        fi
        rm -f "$path"
    else
        echo "No $name pid file"
    fi
}

stop_pid_file "backend" "backend.pid"
stop_pid_file "frontend" "frontend.pid"

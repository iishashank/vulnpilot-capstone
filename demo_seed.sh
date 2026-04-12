#!/usr/bin/env bash
# demo_seed.sh — create/reuse the localhost demo site and optionally trigger a scan.
#
# Usage:
#   ./demo_seed.sh
#   TRIGGER_SCAN=1 ./demo_seed.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV="$SCRIPT_DIR/.venv"
if [ ! -x "$VENV/bin/python" ]; then
    echo "Missing canonical environment at $VENV"
    exit 1
fi

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8010}"
TRIGGER_SCAN="${TRIGGER_SCAN:-0}"
API_URL="http://${BACKEND_HOST}:${BACKEND_PORT}"

SITE_NAME="${SITE_NAME:-Localhost Lab}"
PRIMARY_DOMAIN="${PRIMARY_DOMAIN:-127.0.0.1}"
ALLOWED_SCOPES="${ALLOWED_SCOPES:-127.0.0.1}"
POLICY="${POLICY:-balanced}"
SCHEDULE="${SCHEDULE:-manual}"

export API_URL TRIGGER_SCAN SITE_NAME PRIMARY_DOMAIN ALLOWED_SCOPES POLICY SCHEDULE

"$VENV/bin/python" - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

api_url = os.environ["API_URL"].rstrip("/")
site_name = os.environ["SITE_NAME"]
primary_domain = os.environ["PRIMARY_DOMAIN"]
allowed_scopes = os.environ["ALLOWED_SCOPES"]
policy = os.environ["POLICY"]
schedule = os.environ["SCHEDULE"]
trigger_scan = os.environ.get("TRIGGER_SCAN", "0") == "1"


def get_json(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def post_json(url: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


try:
    sites = get_json(f"{api_url}/sites").get("sites", [])
except urllib.error.URLError as exc:
    print(f"Could not reach backend at {api_url}: {exc}", file=sys.stderr)
    sys.exit(1)

match = next(
    (
        site
        for site in sites
        if site.get("name") == site_name and site.get("primary_domain") == primary_domain
    ),
    None,
)

if match:
    site_id = match["site_id"]
    print(f"Using existing demo site: {site_name} ({site_id})")
else:
    created = post_json(
        f"{api_url}/sites",
        {
            "name": site_name,
            "primary_domain": primary_domain,
            "allowed_scopes": allowed_scopes,
            "policy": policy,
            "schedule": schedule,
            "auth_confirmed": True,
            "auth_note": "Local demo scope seeded by demo_seed.sh",
        },
    )
    site_id = created["site_id"]
    print(f"Created demo site: {site_name} ({site_id})")

if trigger_scan:
    triggered = post_json(f"{api_url}/sites/{site_id}/scan", {})
    run_id = triggered.get("run_id", "unknown")
    print(f"Triggered managed scan: {run_id}")
    print(f"Open Live Run or Sites in the frontend to watch progress.")
else:
    print("Scan not triggered. Use TRIGGER_SCAN=1 ./demo_seed.sh to start a managed demo run.")
PY

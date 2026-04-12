# VulnPilot

Capstone prototype for continuous, site-aware vulnerability monitoring with:

- FastAPI backend orchestration
- Dash analyst console
- CVE/CPE/Exploit/KEV/EPSS enrichment
- drift detection across consecutive runs
- stakeholder-friendly explainability for findings

## Runtime layout

```text
Backend   : FastAPI + SQLAlchemy + CrewAI flow path
Frontend  : Dash + Bootstrap
Ops DB    : datasets/ops.db
Vuln DB   : datasets/vuln_lookup.db
KEV cache : datasets/kev.json
EPSS cache: datasets/epss_scores.json
```

The active runtime database is `datasets/ops.db`. Old SQLite files from earlier
experiments are archived under `legacy/obsolete-state/` and are not used by the
application.

Large generated datasets and local runtime databases are intentionally not
committed to source control. After cloning the repo, rebuild local intelligence
artifacts with:

```bash
.venv/bin/python setup_datasets.py
```

and let the application recreate `datasets/ops.db` on first run.

## Canonical Python environment

There is one supported environment for the project:

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
.venv/bin/pip install -r frontend/requirements.txt
```

Do not use `venv/`. The current scripts, validation steps, and demo startup all
assume `.venv/`.

## Ports

Normal development defaults:

- Backend: `127.0.0.1:8000`
- Frontend: `127.0.0.1:8050`

Demo-mode defaults:

- Backend: `127.0.0.1:8010`
- Frontend: `127.0.0.1:8060`

## Start commands

### Backend

```bash
./start_backend.sh
```

Useful overrides:

```bash
PORT=8010 USE_CREWAI=true ./start_backend.sh
```

### Frontend

```bash
./start_frontend.sh
```

Useful overrides:

```bash
PORT=8060 API_PORT=8010 ./start_frontend.sh
```

### One-command demo boot

```bash
./start_demo.sh
```

This starts:

- backend on `127.0.0.1:8010`
- frontend on `127.0.0.1:8060`
- CrewAI orchestration enabled
- logs and pid files under `.runtime/`

Stop both with:

```bash
./stop_demo.sh
```

### Seed the demo site

After demo mode is up:

```bash
./demo_seed.sh
```

This creates or reuses a managed site named `Localhost Lab` pointing at
`127.0.0.1`.

To trigger a sample managed scan immediately:

```bash
TRIGGER_SCAN=1 ./demo_seed.sh
```

## Demo flow

Recommended demo path:

1. Run `./start_demo.sh`
2. Run `./demo_seed.sh`
3. Open the frontend at `http://127.0.0.1:8060`
4. Go to `Sites`
5. Trigger `Scan now` for `Localhost Lab`
6. Use `Live Run` to show the orchestration logs
7. Use `Findings`, `Report`, `Diff`, and `Alerts` after completion

For a stronger drift demo:

1. Run a first localhost scan
2. Start or stop a local service on a monitored port
3. Run a second managed scan
4. Show `Diff` and `Alerts`

## What the scripts do

### `start_backend.sh`

- validates `.venv`
- validates `datasets/vuln_lookup.db`
- prints active host/port/runtime paths
- launches `uvicorn backend.app:app`

### `start_frontend.sh`

- validates `.venv`
- reads the backend URL from `VULNPILOT_API_URL` or `API_HOST` + `API_PORT`
- launches the Dash app on the requested host/port

### `start_demo.sh`

- starts backend and frontend on clean demo ports
- writes `.runtime/backend.log` and `.runtime/frontend.log`
- stores pids under `.runtime/`
- optionally seeds `Localhost Lab`
- optionally opens the browser

### `demo_seed.sh`

- creates or reuses the managed demo site
- can optionally trigger a managed scan

## Data and datasets

VulnPilot uses a hybrid intelligence model:

- scan-time lookups use the local `datasets/vuln_lookup.db`, `datasets/kev.json`, and `datasets/epss_scores.json`
- external feeds/APIs are used only to refresh those local stores

This keeps scans fast and reproducible while still allowing regular intelligence
updates.

### Operational state

`datasets/ops.db` stores:

- sites
- scan runs
- scan logs
- assets
- findings
- alerts
- scheduler jobs

### Vulnerability intelligence

`datasets/vuln_lookup.db` contains indexed data built from:

- NVD CVE feeds
- CPE dictionary mappings
- ExploitDB references

### KEV cache

`datasets/kev.json` stores the CISA KEV catalog used to mark
Known Exploited Vulnerabilities.

### EPSS cache

`datasets/epss_scores.json` stores EPSS exploit-likelihood scores sourced from
FIRST so findings can be ranked with more operational context than CVSS alone.

## Threat-intelligence refresh API

The backend exposes a control-plane API for refreshing local intelligence from
external feeds.

### Start a full refresh

```bash
curl -X POST http://127.0.0.1:8010/intel/refresh \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VULNPILOT_API_KEY" \
  -d '{"refresh_vuln_db": true, "refresh_kev": true, "refresh_epss": true}'
```

### Refresh only KEV

```bash
curl -X POST http://127.0.0.1:8010/intel/refresh \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VULNPILOT_API_KEY" \
  -d '{"refresh_vuln_db": false, "refresh_kev": true, "refresh_epss": true}'
```

### Check refresh status

```bash
curl -H "X-API-Key: $VULNPILOT_API_KEY" \
  http://127.0.0.1:8010/intel/status
```

The status response includes:

- the currently active refresh job, if any
- the latest completed/failed refresh job
- the current file timestamps for `vuln_lookup.db`, `kev.json`, and `epss_scores.json`

## Discovery enhancements

For domain scopes, VulnPilot still performs direct DNS resolution by default.
If `subfinder` or `amass` are installed on the host, the recon stage will also
use them for passive subdomain enumeration before service scanning.

Install them on macOS with:

```bash
brew install subfinder amass
```

VulnPilot passes a workspace-local `subfinder` config from
`tooling/subfinder/config.yaml` and `tooling/subfinder/provider-config.yaml`,
so passive recon does not depend on per-user config files under
`~/Library/Application Support/subfinder`.

## Validation

The current prototype validation is documented in:

`evaluation/prototype_validation_2026-04-03.md`

That validation covers:

- CrewAI-orchestrated run execution
- localhost asset discovery
- CVE correlation
- drift detection across repeated runs
- alert generation

## Repo hygiene

- Active DB: `datasets/ops.db`
- Archived legacy DBs: `legacy/obsolete-state/`
- Runtime logs/pids: `.runtime/`
- Canonical Python env: `.venv/`

## Rules of engagement

Only scan systems you own or have explicit written permission to test. The
product is built for authorized monitoring and demo/lab use.

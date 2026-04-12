# Prototype Validation — 2026-04-03

## Scope

This validation was run against the current capstone implementation after the
scanner, diff pipeline, site persistence, and scheduler state were rewired.
The goal was not full benchmarking. The goal was to confirm that the project
now behaves like a real end-to-end prototype rather than a stubbed demo.

## Environment

- Workspace: `/Users/shashankrallabandi/CAPSTONE`
- Python environment: local `.venv`
- Validation style: controlled localhost lab run
- Backend exercised through FastAPI `TestClient`
- Temporary local services:
  - custom HTTP service on `127.0.0.1:8080` returning `Server: Apache/2.4.49`
  - temporary Redis-like listener on `127.0.0.1:6379` for second-run drift validation

## What Was Validated

1. Site registration with authorization enforcement
2. Site-triggered scan execution
3. Site-linked persistence of runs, assets, and findings
4. Live asset/service enumeration from a real reachable target
5. CVE correlation from `datasets/vuln_lookup.db`
6. Diff execution across consecutive runs
7. Alert creation from drift output
8. Persistent scheduler state for scheduled sites

## Results

### 1. Scheduler persistence

- Creating a site with `schedule="manual"` created a `scheduler_jobs` record in
  inactive state with no `next_run_at`, as expected.
- Creating a site with `schedule="daily"` created an active `scheduler_jobs`
  record with a persisted `next_run_at` value matching the `sites.next_scan_at`
  value.

### 2. First controlled scan

A managed site was created for scope `127.0.0.1` with `policy="safe"` and then
scanned through the `/sites/{site_id}/scan` flow.

Observed result:

- run status reached `done`
- scan artifacts were stored with the correct `site_id`
- `1` asset snapshot was persisted for `127.0.0.1`
- open ports observed on the validation host were:
  - `3306`
  - `5432`
  - `8080`

The temporary HTTP service on `8080` was fingerprinted as:

- service: `apache`
- version: `2.4.49`
- vendor/product mapping: `apache:http_server`

### 3. Vulnerability intelligence correlation

The first run produced real findings from the local vulnerability database.
The following findings were observed in the validation output:

- `CVE-2021-41773` — `CRITICAL`
- `CVE-2021-42013` — `CRITICAL`
- `CVE-2021-41524` — `HIGH`
- one additional environment-dependent `MEDIUM` finding derived from another
  locally reachable service

This confirms that the scanner is no longer inserting a hardcoded demo CVE list.
It is now deriving findings from observed service fingerprints and local
vulnerability intelligence.

### 4. Initial alert generation

Because the first run had no prior comparison baseline, the diff engine treated
it as the initial snapshot and created initial high/critical alerts for the new
high-risk findings. The observed alert titles included:

- `Initial scan: [CRITICAL] CVE-2021-41773`
- `Initial scan: [CRITICAL] CVE-2021-42013`
- `Initial scan: [HIGH] CVE-2021-41524`

### 5. Drift validation on second run

Before the second run, a temporary Redis-like listener was started on
`127.0.0.1:6379`. The same site was then scanned again.

Observed diff result:

- no new assets
- one port change on the existing host
- old port set: `[3306, 5432, 8080]`
- new port set: `[3306, 5432, 6379, 8080]`

Observed alert result:

- `port_change` alert generated with title:
  - `New ports opened on 127.0.0.1`

This confirms that the diff engine is now wired into the completed run path and
is generating persisted alert records from real state changes.

## What This Validation Supports

The current implementation can now credibly support the following statements:

- the project performs real host/service enumeration on reachable targets
- the project persists site-linked scan state
- the project performs CVE correlation against a local vulnerability database
- the project compares consecutive run snapshots for a managed site
- the project generates alerts from drift results
- the project stores scheduler state in the database for scheduled monitoring

## Additional Validation: CrewAI and LangChain Orchestration

After the base prototype validation above, the scan pipeline was upgraded so
that `run_pipeline()` defaults to a real CrewAI execution path. This second
validation pass focused on whether the new orchestration layer is genuinely in
the runtime path, rather than only present as an unused dependency.

### 1. Runtime integration confirmed

The backend imported cleanly with the CrewAI orchestration enabled, and the
scan flow completed successfully through the normal `/sites/{site_id}/scan`
endpoint. The following log markers were recorded during the first controlled
run:

- `CrewAI Orchestrator: flow initialized for scope 127.0.0.1 using profile balanced.`
- `CrewAI Recon Agent: LangChain tool discover_targets returned 1 candidate target(s).`
- `CrewAI Scanner Agent: 127.0.0.1 (127.0.0.1) has 3 open port(s): [3306, 5432, 8888]`
- `CrewAI Vulnerability Agent: 1557 KEV entries loaded.`
- `CrewAI Persistence Agent: persisted 1 asset snapshot(s) and 0 finding snapshot(s).`
- `CrewAI Diff Agent: 0 new finding(s), 1 new asset(s), 0 port change set(s).`
- `CrewAI Report Agent: Observed 1 active asset(s), correlated 0 finding(s), detected 1 new asset(s), 0 new finding(s), and 0 port change set(s).`

These log lines confirm that the execution path now runs through a CrewAI Flow
and that the scan stages are exposed as LangChain tools rather than being
invoked only through the earlier direct pipeline.

### 2. Diff and alert behavior through the CrewAI path

A second controlled run was performed for the same managed site after opening a
temporary additional port on `127.0.0.1:9000`.

Observed result:

- first run port set: `[3306, 5432, 8888]`
- second run port set: `[3306, 5432, 8888, 9000]`
- diff output reported one `port_change` set for the existing asset
- an unacknowledged alert was created with title:
  - `New ports opened on 127.0.0.1`

This confirms that the CrewAI path is not bypassing the diff engine or alerting
logic. The historical comparison and alert creation remain active after the
orchestration upgrade.

### 3. Service fingerprinting through the CrewAI path

A focused Apache-banner validation was also run on `127.0.0.1:8080` with the
CrewAI path enabled. The persisted service record for that run showed:

- port `8080`
- service `apache`
- banner `Apache/2.4.49`
- vendor/product mapping `apache:http_server`

In that specific CrewAI validation run, the correlation stage loaded KEV data
and executed normally but did not emit matched CVEs for the observed services.
That outcome is still useful: it shows that the CrewAI flow reached the
fingerprinting and correlation stages without falling back to the direct
pipeline. The earlier direct validation above remains the stronger evidence for
local CVE correlation correctness.

## What This Validation Does Not Yet Prove

- large-scale performance
- internet-wide or enterprise-scale reconnaissance
- accuracy across diverse real-world banners and service obfuscation cases
- distributed scheduling or worker orchestration
- native iOS or Android client readiness
- formal analyst usability improvements

## Practical Conclusion

The project has moved beyond a dashboard-backed stub. It now qualifies as a
real working prototype for:

- controlled continuous monitoring,
- local vulnerability intelligence correlation,
- drift-aware alert generation,
- and real CrewAI/LangChain-backed orchestration of the scan workflow.

It still requires broader real-world testing and hardening before stronger
production-style claims would be justified.

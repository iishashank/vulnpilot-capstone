"""
app.py — FastAPI backend for VulnPilot Domain Security Platform.
"""

import json
import secrets
import uuid
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Depends, Query, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session

from .db import Base, engine, SessionLocal
from .evaluation_metrics import get_metrics_snapshot, launch_controlled_evaluation
from .explainability import explain_finding
from .intel_refresh import VULN_DB_PATH, launch_intel_refresh_job
from .models import ScanRun, ScanLog, Asset, Finding, Site, Alert, IntelRefreshJob
from .prioritization import classify_priority_band, finding_priority_score, severity_sort_key
from .scanner import orchestration_label, run_pipeline
from .scheduler import start_scheduler, stop_scheduler, refresh_site_schedule
from .threat_intel import EPSS_CACHE_PATH
from shared.schemas import (
    FindingWorkflowUpdateRequest,
    IntelRefreshRequest,
    ScanRequest,
    SiteCreateRequest,
)

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import ALLOW_LOCAL_CONTROL_PLANE, CONTROL_PLANE_API_KEY, CORS_ORIGINS

DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets"
KEV_CACHE_PATH = DATASET_DIR / "kev.json"


def _ensure_schema():
    """Create missing tables and add lightweight SQLite column migrations."""
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        assets_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(assets)").fetchall()}
        if "ports_json" not in assets_cols:
            conn.exec_driver_sql("ALTER TABLE assets ADD COLUMN ports_json TEXT DEFAULT '[]'")
        if "services_json" not in assets_cols:
            conn.exec_driver_sql("ALTER TABLE assets ADD COLUMN services_json TEXT DEFAULT '[]'")
        intel_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(intel_refresh_jobs)").fetchall()}
        if intel_cols:
            if "refresh_epss" not in intel_cols:
                conn.exec_driver_sql("ALTER TABLE intel_refresh_jobs ADD COLUMN refresh_epss BOOLEAN DEFAULT 1")
            if "refreshed_epss" not in intel_cols:
                conn.exec_driver_sql("ALTER TABLE intel_refresh_jobs ADD COLUMN refreshed_epss BOOLEAN DEFAULT 0")


_ensure_schema()


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(title="VulnPilot — Domain Security Platform", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "X-API-Key"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_control_plane_access(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    client_host = request.client.host if request.client else ""
    if ALLOW_LOCAL_CONTROL_PLANE and client_host in {"127.0.0.1", "::1", "localhost", "testclient"}:
        return
    if CONTROL_PLANE_API_KEY and x_api_key and secrets.compare_digest(x_api_key, CONTROL_PLANE_API_KEY):
        return
    raise HTTPException(
        status_code=401,
        detail="Control-plane access requires localhost origin or a valid X-API-Key.",
    )


def _ports_for_asset(asset: Asset):
    raw = getattr(asset, "ports_json", "") or ""
    if raw:
        try:
            return sorted(int(port) for port in json.loads(raw))
        except Exception:
            pass
    return list(range(int(asset.open_ports or 0)))


def _serialize_refresh_job(job: IntelRefreshJob | None):
    if not job:
        return None
    return {
        "job_id": job.job_id,
        "status": job.status,
        "refresh_vuln_db": job.refresh_vuln_db,
        "refresh_kev": job.refresh_kev,
        "refresh_epss": getattr(job, "refresh_epss", False),
        "refreshed_vuln_db": job.refreshed_vuln_db,
        "refreshed_kev": job.refreshed_kev,
        "refreshed_epss": getattr(job, "refreshed_epss", False),
        "message": job.message or "",
        "started_at": str(job.started_at) if job.started_at else "",
        "finished_at": str(job.finished_at) if job.finished_at else "",
        "created_at": str(job.created_at) if job.created_at else "",
    }


def _file_metadata(path: Path):
    if not path.exists():
        return {
            "path": str(path),
            "exists": False,
            "updated_at": "",
            "size_bytes": 0,
        }
    stat = path.stat()
    return {
        "path": str(path),
        "exists": True,
        "updated_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        "size_bytes": stat.st_size,
    }


# ─── Sites ───────────────────────────────────────────────────────────────────

@app.post("/sites")
def create_site(
    payload: SiteCreateRequest,
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    if not payload.auth_confirmed:
        raise HTTPException(status_code=400, detail="Authorization confirmation required. You must confirm written permission to scan this target.")
    site_id = str(uuid.uuid4())
    schedule = payload.schedule
    site = Site(
        site_id=site_id,
        name=payload.name or payload.primary_domain or "Unnamed",
        primary_domain=payload.primary_domain,
        allowed_scopes=payload.allowed_scopes or payload.primary_domain,
        policy=payload.policy,
        schedule=schedule,
        auth_confirmed=True,
        auth_note=payload.auth_note,
    )
    if schedule == "daily":
        site.next_scan_at = datetime.utcnow() + timedelta(hours=24)
    elif schedule == "weekly":
        site.next_scan_at = datetime.utcnow() + timedelta(days=7)
    db.add(site)
    db.commit()
    refresh_site_schedule(site_id, schedule, True)
    return {"site_id": site_id}


@app.get("/sites")
def list_sites(db: Session = Depends(get_db)):
    sites = db.query(Site).order_by(Site.created_at.desc()).all()
    site_ids = [site.site_id for site in sites]
    latest_runs: dict[str, ScanRun] = {}
    unacked_alert_counts: dict[str, int] = {}
    critical_counts_by_run: dict[str, int] = {}

    if site_ids:
        runs = (
            db.query(ScanRun)
            .filter(ScanRun.site_id.in_(site_ids))
            .order_by(ScanRun.site_id.asc(), ScanRun.created_at.desc())
            .all()
        )
        for run in runs:
            if run.site_id and run.site_id not in latest_runs:
                latest_runs[run.site_id] = run

        latest_run_ids = [run.run_id for run in latest_runs.values()]
        if latest_run_ids:
            critical_counts_by_run = {
                run_id: count
                for run_id, count in (
                    db.query(Finding.run_id, func.count(Finding.id))
                    .filter(Finding.run_id.in_(latest_run_ids), Finding.severity == "CRITICAL")
                    .group_by(Finding.run_id)
                    .all()
                )
            }

        unacked_alert_counts = {
            site_id: count
            for site_id, count in (
                db.query(Alert.site_id, func.count(Alert.id))
                .filter(Alert.site_id.in_(site_ids), Alert.acknowledged == False)
                .group_by(Alert.site_id)
                .all()
            )
        }

    result = []
    for s in sites:
        last_run = latest_runs.get(s.site_id)
        alert_count = unacked_alert_counts.get(s.site_id, 0)
        critical_count = critical_counts_by_run.get(last_run.run_id, 0) if last_run else 0
        result.append({
            "site_id": s.site_id,
            "name": s.name,
            "primary_domain": s.primary_domain,
            "allowed_scopes": s.allowed_scopes,
            "policy": s.policy,
            "schedule": s.schedule,
            "auth_confirmed": s.auth_confirmed,
            "created_at": str(s.created_at) if s.created_at else "",
            "last_scan_at": str(s.last_scan_at) if s.last_scan_at else "Never",
            "next_scan_at": str(s.next_scan_at) if s.next_scan_at else "—",
            "last_run_status": last_run.status if last_run else "—",
            "unacked_alerts": alert_count,
            "critical_count": critical_count,
        })
    return {"sites": result}


@app.post("/sites/{site_id}/scan")
def trigger_site_scan(
    site_id: str,
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    site = db.query(Site).filter(Site.site_id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    if not site.auth_confirmed:
        raise HTTPException(status_code=403, detail="Authorization not confirmed for this site")
    run_id = str(uuid.uuid4())
    db.add(ScanRun(run_id=run_id, site_id=site_id, scope=site.allowed_scopes, profile=site.policy, status="queued", progress=0))
    site.last_scan_at = datetime.utcnow()
    db.commit()
    t = threading.Thread(
        target=run_pipeline,
        args=(run_id,),
        kwargs={"site_id": site_id},
        daemon=True,
    )
    t.start()
    return {"run_id": run_id, "orchestration": orchestration_label()}


@app.get("/sites/{site_id}/diff")
def get_site_diff(site_id: str, db: Session = Depends(get_db)):
    """Return diff between the last two completed runs for the site."""
    runs = (
        db.query(ScanRun)
        .filter(ScanRun.site_id == site_id, ScanRun.status == "done")
        .order_by(ScanRun.created_at.desc())
        .limit(2)
        .all()
    )
    if len(runs) < 2:
        return {"message": "Need at least 2 completed runs to diff", "runs": [r.run_id for r in runs]}

    curr_run, prev_run = runs[0], runs[1]

    curr_findings = {f.cve_id: f for f in db.query(Finding).filter(Finding.run_id == curr_run.run_id).all()}
    prev_findings = {f.cve_id: f for f in db.query(Finding).filter(Finding.run_id == prev_run.run_id).all()}
    curr_assets = {a.host: a for a in db.query(Asset).filter(Asset.run_id == curr_run.run_id).all()}
    prev_assets = {a.host: a for a in db.query(Asset).filter(Asset.run_id == prev_run.run_id).all()}

    def _finding_dict(f):
        return {"cve_id": f.cve_id, "title": f.title, "severity": f.severity, "cvss": f.cvss, "kev": f.kev}

    return {
        "run_a": prev_run.run_id,
        "run_b": curr_run.run_id,
        "new_findings":      [_finding_dict(f) for cve_id, f in curr_findings.items() if cve_id not in prev_findings],
        "resolved_findings": [_finding_dict(f) for cve_id, f in prev_findings.items() if cve_id not in curr_findings],
        "new_assets":        [{"host": h, "ip": a.ip} for h, a in curr_assets.items() if h not in prev_assets],
        "gone_assets":       [{"host": h, "ip": a.ip} for h, a in prev_assets.items() if h not in curr_assets],
        "ip_changes":        [{"host": h, "old_ip": prev_assets[h].ip, "new_ip": curr_assets[h].ip}
                              for h in curr_assets if h in prev_assets and curr_assets[h].ip != prev_assets[h].ip],
        "port_changes":      [{"host": h, "old": _ports_for_asset(prev_assets[h]), "new": _ports_for_asset(curr_assets[h])}
                              for h in curr_assets if h in prev_assets and _ports_for_asset(curr_assets[h]) != _ports_for_asset(prev_assets[h])],
    }


# ─── Alerts ───────────────────────────────────────────────────────────────────

@app.get("/alerts")
def list_alerts(site_id: str = "", severity: str = "", unacked_only: int = 0, db: Session = Depends(get_db)):
    q = db.query(Alert)
    if site_id:
        q = q.filter(Alert.site_id == site_id)
    if severity:
        q = q.filter(Alert.severity == severity.upper())
    if unacked_only == 1:
        q = q.filter(Alert.acknowledged == False)
    rows = q.limit(150).all()
    rows.sort(key=lambda alert: (not alert.acknowledged, severity_sort_key(alert.severity), str(alert.created_at or "")), reverse=True)
    return {"alerts": [
        {
            "id": a.id,
            "site_id": a.site_id,
            "run_id": a.run_id,
            "finding_id": a.finding_id,
            "trigger_type": a.trigger_type,
            "severity": a.severity,
            "title": a.title,
            "detail": a.detail,
            "acknowledged": a.acknowledged,
            "created_at": str(a.created_at) if a.created_at else "",
        }
        for a in rows
    ]}


@app.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    db.commit()
    return {"ok": True}


# ─── Threat Intelligence Refresh ─────────────────────────────────────────────

@app.post("/intel/refresh")
def start_intel_refresh(
    payload: IntelRefreshRequest,
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    if not payload.refresh_vuln_db and not payload.refresh_kev and not payload.refresh_epss:
        raise HTTPException(status_code=400, detail="At least one refresh target must be enabled.")

    active_job = (
        db.query(IntelRefreshJob)
        .filter(IntelRefreshJob.status.in_(["queued", "running"]))
        .order_by(IntelRefreshJob.created_at.desc())
        .first()
    )
    if active_job:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "A threat-intelligence refresh job is already running.",
                "job": _serialize_refresh_job(active_job),
            },
        )

    job = IntelRefreshJob(
        job_id=str(uuid.uuid4()),
        status="queued",
        refresh_vuln_db=payload.refresh_vuln_db,
        refresh_kev=payload.refresh_kev,
        refresh_epss=payload.refresh_epss,
        message="Refresh queued.",
    )
    db.add(job)
    db.commit()
    launch_intel_refresh_job(job.job_id, payload.refresh_vuln_db, payload.refresh_kev, payload.refresh_epss)
    db.refresh(job)
    return {"job": _serialize_refresh_job(job)}


@app.get("/intel/status")
def intel_status(
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    latest_job = db.query(IntelRefreshJob).order_by(IntelRefreshJob.created_at.desc()).first()
    active_job = (
        db.query(IntelRefreshJob)
        .filter(IntelRefreshJob.status.in_(["queued", "running"]))
        .order_by(IntelRefreshJob.created_at.desc())
        .first()
    )
    return {
        "active_job": _serialize_refresh_job(active_job),
        "latest_job": _serialize_refresh_job(latest_job),
        "vuln_db": _file_metadata(VULN_DB_PATH),
        "kev_cache": _file_metadata(KEV_CACHE_PATH),
        "epss_cache": _file_metadata(EPSS_CACHE_PATH),
    }


@app.get("/intel/jobs/{job_id}")
def intel_job_status(
    job_id: str,
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    job = db.query(IntelRefreshJob).filter(IntelRefreshJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Refresh job not found")
    return {"job": _serialize_refresh_job(job)}


# ─── Evaluation Metrics ──────────────────────────────────────────────────────

@app.get("/evaluation/metrics")
def evaluation_metrics(db: Session = Depends(get_db)):
    # `db` is accepted for consistency with the API layer and to avoid creating
    # a second dependency path later if per-request context is needed.
    del db
    return get_metrics_snapshot()


@app.post("/evaluation/run")
def run_controlled_evaluation(
    _: None = Depends(require_control_plane_access),
):
    worker = launch_controlled_evaluation()
    if worker is None:
        raise HTTPException(status_code=409, detail="A controlled evaluation is already running.")
    return {"ok": True, "message": "Controlled evaluation started."}


# ─── Findings Workflow ────────────────────────────────────────────────────────

@app.patch("/findings/{finding_id}/workflow")
def update_finding_workflow(
    finding_id: int,
    payload: FindingWorkflowUpdateRequest,
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if payload.status is not None:
        finding.workflow_status = payload.status
    if payload.notes is not None:
        finding.workflow_notes = payload.notes
    if payload.owner is not None:
        finding.workflow_owner = payload.owner
    db.commit()
    return {"ok": True, "workflow_status": finding.workflow_status}


# ─── Scan lifecycle ──────────────────────────────────────────────────────────

@app.post("/scan")
def start_scan(
    payload: ScanRequest,
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    if not payload.auth_confirmed:
        raise HTTPException(status_code=400, detail="Authorization confirmation required before launching a scan.")

    site_id = payload.site_id
    scope = payload.scope.strip()
    profile = payload.profile or "safe"

    if site_id:
        site = db.query(Site).filter(Site.site_id == site_id).first()
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        if not site.auth_confirmed:
            raise HTTPException(status_code=403, detail="Authorization not confirmed for this site")
        scope = scope or site.allowed_scopes
        profile = payload.profile or site.policy

    run_id = str(uuid.uuid4())
    db.add(ScanRun(run_id=run_id, scope=scope, profile=profile, status="queued", progress=0, site_id=site_id))
    db.commit()
    t = threading.Thread(
        target=run_pipeline,
        args=(run_id,),
        kwargs={"site_id": site_id},
        daemon=True,
    )
    t.start()
    return {"run_id": run_id, "orchestration": orchestration_label()}


@app.get("/scan/{run_id}/status")
def scan_status(run_id: str, db: Session = Depends(get_db)):
    run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()
    if not run:
        return {"error": "not_found"}
    return {
        "run_id": run.run_id,
        "site_id": run.site_id,
        "status": run.status,
        "progress": run.progress,
        "scope": run.scope,
        "profile": run.profile,
        "created_at": str(run.created_at) if run.created_at else "",
    }


@app.get("/scan/{run_id}/logs")
def scan_logs(run_id: str, since_id: int = 0, db: Session = Depends(get_db)):
    rows = (
        db.query(ScanLog)
        .filter(ScanLog.run_id == run_id, ScanLog.id > since_id)
        .order_by(ScanLog.id.asc())
        .all()
    )
    return {"logs": [{"id": x.id, "ts": str(x.ts), "level": x.level, "message": x.message} for x in rows]}


@app.post("/scan/{run_id}/stop")
def stop_scan(
    run_id: str,
    _: None = Depends(require_control_plane_access),
    db: Session = Depends(get_db),
):
    run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()
    if not run:
        return {"error": "not_found"}
    run.status = "stopped"
    db.commit()
    return {"ok": True}


# ─── Runs / Assets / Findings (backwards-compatible) ─────────────────────────

@app.get("/runs")
def list_runs(db: Session = Depends(get_db)):
    rows = db.query(ScanRun).order_by(ScanRun.created_at.desc()).limit(50).all()
    return {"runs": [{
        "run_id": r.run_id, "site_id": r.site_id, "scope": r.scope, "profile": r.profile,
        "status": r.status, "progress": r.progress,
        "created_at": str(r.created_at) if r.created_at else "",
    } for r in rows]}


@app.get("/assets")
def list_assets(run_id: str = "", site_id: str = "", db: Session = Depends(get_db)):
    q = db.query(Asset)
    if run_id:
        q = q.filter(Asset.run_id == run_id)
    if site_id:
        q = q.filter(Asset.site_id == site_id)
    rows = q.all()
    return {"assets": [{
        "id": r.id, "run_id": r.run_id, "site_id": r.site_id,
        "host": r.host, "ip": r.ip, "open_ports": r.open_ports, "risk_score": r.risk_score,
        "ports": json.loads(r.ports_json or "[]"), "services": json.loads(r.services_json or "[]"),
        "first_seen": str(r.first_seen) if r.first_seen else "",
        "last_seen": str(r.last_seen) if r.last_seen else "",
        "status": r.status,
    } for r in rows]}


@app.get("/findings")
def list_findings(run_id: str = "", site_id: str = "", severity: str = "", kev_only: int = 0, db: Session = Depends(get_db)):
    q = db.query(Finding)
    if run_id:
        q = q.filter(Finding.run_id == run_id)
    if site_id:
        q = q.filter(Finding.site_id == site_id)
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    if kev_only == 1:
        q = q.filter(Finding.kev == 1)
    rows = q.order_by(Finding.cvss.desc()).all()
    findings = []
    for r in rows:
        priority_score = finding_priority_score(r.cvss, kev=bool(r.kev), exploit=bool(r.exploit), epss=r.epss)
        finding = {
            "id": r.id, "run_id": r.run_id, "site_id": r.site_id,
            "cve_id": r.cve_id, "title": r.title, "severity": r.severity,
            "cvss": r.cvss, "epss": r.epss, "kev": r.kev, "exploit": r.exploit,
            "affected_assets": r.affected_assets, "evidence": r.evidence, "remediation": r.remediation,
            "workflow_status": r.workflow_status, "workflow_notes": r.workflow_notes, "workflow_owner": r.workflow_owner,
            "priority_score": priority_score,
            "priority_label": classify_priority_band(r.cvss, kev=bool(r.kev), exploit=bool(r.exploit), epss=r.epss, fallback=r.severity),
        }
        finding.update(explain_finding(finding))
        findings.append(finding)
    findings.sort(
        key=lambda item: (
            item["priority_score"],
            severity_sort_key(item["priority_label"]),
            item["cvss"],
            item["epss"],
        ),
        reverse=True,
    )
    return {"findings": findings}

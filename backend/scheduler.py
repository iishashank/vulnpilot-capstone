"""
scheduler.py — lightweight DB-backed scheduler for continuous site scanning.

The scheduler persists timing state in the application database instead of
keeping jobs only in process memory. That makes restart behavior predictable
and keeps the monitoring loop aligned with the paper's continuous-scan claims.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta

from .db import SessionLocal
from .models import SchedulerJob, ScanRun, Site
from .scanner import run_pipeline


_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()
_scheduler_lock = threading.Lock()


def _next_run_at(schedule: str, base: datetime | None = None) -> datetime | None:
    base = base or datetime.utcnow()
    if schedule == "daily":
        return base + timedelta(days=1)
    if schedule == "weekly":
        return base + timedelta(weeks=1)
    return None


def _job_id(site_id: str) -> str:
    return f"site_{site_id}"


def _upsert_job(db, site: Site) -> SchedulerJob:
    job = db.query(SchedulerJob).filter(SchedulerJob.site_id == site.site_id).first()
    if not job:
        job = SchedulerJob(job_id=_job_id(site.site_id), site_id=site.site_id)
        db.add(job)

    job.schedule = site.schedule
    job.active = bool(site.auth_confirmed and site.schedule != "manual")

    if job.active:
        if site.next_scan_at is None:
            site.next_scan_at = _next_run_at(site.schedule)
        job.next_run_at = site.next_scan_at
    else:
        site.next_scan_at = None
        job.next_run_at = None

    return job


def _sync_jobs_from_sites() -> None:
    db = SessionLocal()
    try:
        sites = db.query(Site).all()
        seen_site_ids = set()
        for site in sites:
            _upsert_job(db, site)
            seen_site_ids.add(site.site_id)

        for job in db.query(SchedulerJob).all():
            if job.site_id not in seen_site_ids:
                db.delete(job)

        db.commit()
    finally:
        db.close()


def _dispatch_site_scan(site_id: str) -> None:
    """Create a ScanRun and start the pipeline in its own worker thread."""
    db = SessionLocal()
    try:
        site = db.query(Site).filter(Site.site_id == site_id).first()
        if not site or not site.auth_confirmed:
            return

        existing = (
            db.query(ScanRun)
            .filter(
                ScanRun.site_id == site_id,
                ScanRun.status.in_(["queued", "running"]),
            )
            .first()
        )
        if existing:
            return

        run_id = str(uuid.uuid4())
        db.add(
            ScanRun(
                run_id=run_id,
                site_id=site_id,
                scope=site.allowed_scopes,
                profile=site.policy,
                status="queued",
                progress=0,
            )
        )
        site.last_scan_at = datetime.utcnow()
        site.next_scan_at = _next_run_at(site.schedule, site.last_scan_at)

        job = db.query(SchedulerJob).filter(SchedulerJob.site_id == site_id).first()
        if job:
            job.last_run_at = site.last_scan_at
            job.next_run_at = site.next_scan_at

        db.commit()

        worker = threading.Thread(
            target=run_pipeline,
            args=(run_id,),
            kwargs={"site_id": site_id},
            daemon=True,
        )
        worker.start()
    finally:
        db.close()


def _scheduler_loop() -> None:
    while not _scheduler_stop.wait(5):
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            due_jobs = (
                db.query(SchedulerJob)
                .filter(
                    SchedulerJob.active == True,
                    SchedulerJob.next_run_at.isnot(None),
                    SchedulerJob.next_run_at <= now,
                )
                .all()
            )

            due_site_ids = [job.site_id for job in due_jobs]
        finally:
            db.close()

        for site_id in due_site_ids:
            _dispatch_site_scan(site_id)


def start_scheduler() -> None:
    global _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread and _scheduler_thread.is_alive():
            return

        _scheduler_stop.clear()
        _sync_jobs_from_sites()
        _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True, name="vulnpilot-scheduler")
        _scheduler_thread.start()


def stop_scheduler() -> None:
    global _scheduler_thread
    with _scheduler_lock:
        _scheduler_stop.set()
        if _scheduler_thread and _scheduler_thread.is_alive():
            _scheduler_thread.join(timeout=2)
        _scheduler_thread = None


def refresh_site_schedule(site_id: str, schedule: str, auth_confirmed: bool) -> None:
    """
    Persist schedule state for a site. This is called after site create/update.
    """
    db = SessionLocal()
    try:
        site = db.query(Site).filter(Site.site_id == site_id).first()
        if not site:
            return

        site.schedule = schedule
        site.auth_confirmed = auth_confirmed
        _upsert_job(db, site)
        db.commit()
    finally:
        db.close()

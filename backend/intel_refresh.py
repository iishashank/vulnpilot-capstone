"""
intel_refresh.py — refreshes external threat-intelligence feeds into the local
runtime datasets used by VulnPilot.

The scan path continues to read from the local SQLite and KEV cache for fast,
reproducible lookups. This module adds an explicit control-plane refresh job so
operators can update those local datasets without turning every scan into a
live network dependency.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime
from pathlib import Path

from .db import SessionLocal
from .models import IntelRefreshJob
from .scanner import refresh_kev_cache
from .threat_intel import refresh_epss_cache

from setup_datasets import (
    build_database,
    download_cpe_dictionary,
    download_exploitdb_csv,
    download_nvd_feeds,
)


DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets"
VULN_DB_PATH = DATASET_DIR / "vuln_lookup.db"

_refresh_lock = threading.Lock()


def refresh_in_progress() -> bool:
    return _refresh_lock.locked()


def _update_job(job_id: str, **fields) -> None:
    db = SessionLocal()
    try:
        job = db.query(IntelRefreshJob).filter(IntelRefreshJob.job_id == job_id).first()
        if not job:
            return
        for key, value in fields.items():
            setattr(job, key, value)
        db.commit()
    finally:
        db.close()


def launch_intel_refresh_job(
    job_id: str,
    refresh_vuln_db: bool,
    refresh_kev: bool,
    refresh_epss: bool,
) -> threading.Thread:
    thread = threading.Thread(
        target=run_intel_refresh_job,
        args=(job_id, refresh_vuln_db, refresh_kev, refresh_epss),
        daemon=True,
    )
    thread.start()
    return thread


def run_intel_refresh_job(job_id: str, refresh_vuln_db: bool, refresh_kev: bool, refresh_epss: bool) -> None:
    started_at = datetime.utcnow()
    temp_db_path = DATASET_DIR / f".vuln_lookup.{job_id}.tmp.db"

    if not _refresh_lock.acquire(blocking=False):
        _update_job(
            job_id,
            status="failed",
            started_at=started_at,
            finished_at=datetime.utcnow(),
            message="Another intelligence refresh job is already running.",
        )
        return

    try:
        _update_job(
            job_id,
            status="running",
            started_at=started_at,
            message="Threat-intelligence refresh started.",
        )

        messages: list[str] = []
        refreshed_vuln_db = False
        refreshed_kev = False
        refreshed_epss = False

        if refresh_kev:
            kev_result = refresh_kev_cache(force=True)
            kev_cves = kev_result.get("cves", frozenset())
            kev_source = str(kev_result.get("source", "none"))
            refreshed_kev = kev_source == "live"
            messages.append(
                f"KEV sync source: {kev_source} ({len(kev_cves)} entries available locally)."
            )

        if refresh_epss:
            epss_result = refresh_epss_cache(force=True)
            epss_scores = epss_result.get("scores", {})
            epss_source = str(epss_result.get("source", "none"))
            refreshed_epss = epss_source == "live"
            messages.append(
                f"EPSS sync source: {epss_source} ({len(epss_scores)} entries available locally)."
            )

        if refresh_vuln_db:
            if temp_db_path.exists():
                temp_db_path.unlink()
            json_files = download_nvd_feeds()
            cpe_xml = download_cpe_dictionary()
            exploitdb_csv = download_exploitdb_csv()
            built_path = build_database(
                json_files,
                cpe_xml,
                exploitdb_csv,
                output_path=temp_db_path,
            )
            os.replace(built_path, VULN_DB_PATH)
            refreshed_vuln_db = True
            messages.append(
                f"Local vulnerability database rebuilt from {len(json_files)} NVD feed(s)."
            )

        if not messages:
            messages.append("No refresh work requested.")

        _update_job(
            job_id,
            status="done",
            refreshed_vuln_db=refreshed_vuln_db,
            refreshed_kev=refreshed_kev,
            refreshed_epss=refreshed_epss,
            finished_at=datetime.utcnow(),
            message=" ".join(messages),
        )
    except Exception as exc:
        if temp_db_path.exists():
            temp_db_path.unlink()
        _update_job(
            job_id,
            status="failed",
            finished_at=datetime.utcnow(),
            message=f"Threat-intelligence refresh failed: {exc}",
        )
    finally:
        _refresh_lock.release()

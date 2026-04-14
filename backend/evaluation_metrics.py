"""
evaluation_metrics.py — controlled evaluation harness and app-facing metrics.

This module intentionally separates:

1. Controlled validation metrics
   Metrics that require seeded ground truth, such as correlation precision and
   drift precision / recall / F1. These are computed from a reproducible local
   scenario and persisted as a JSON artifact for the UI and paper.

2. Operational runtime metrics
   Metrics that can be computed continuously from the current database state,
   such as scan success rate, alert deduplication, prioritization quality, and
   explainability coverage.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

from .db import SessionLocal
from .explainability import explain_finding
from .models import Alert, Asset, Finding, ScanLog, ScanRun, SchedulerJob, Site
from .prioritization import finding_priority_score
from .scanner import PROFILE_HOST_LIMITS, PROFILE_PORTS, PROFILE_TIMEOUTS, orchestration_label, run_pipeline


ARTIFACT_PATH = Path(__file__).resolve().parent.parent / "evaluation" / "latest_metrics.json"
_evaluation_lock = threading.Lock()
_evaluation_state = {
    "running": False,
    "started_at": "",
    "finished_at": "",
    "message": "",
}

_EXPLAINABILITY_FIELDS = (
    "plain_title",
    "plain_summary",
    "why_it_matters",
    "priority_reason",
    "business_impact_label",
    "business_impact_reason",
    "recommended_next_step",
)

_EVAL_PROFILE = "__evaluation__"
_EVAL_HOST = "127.0.0.1"
_EVAL_PORT_CANDIDATES = [8000, 8080, 8443, 8888, 9000, 9200, 27017, 6379, 3389]


@dataclass
class _EvalServer:
    server: ThreadingHTTPServer
    thread: threading.Thread

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


class _BannerHandler(BaseHTTPRequestHandler):
    banner = "nginx/1.25.0"

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

    def do_GET(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _fmt: str, *_args: Any) -> None:
        return

    def version_string(self) -> str:
        return self.banner


class _ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def refresh_operational_metrics() -> dict[str, Any]:
    db = SessionLocal()
    try:
        return _compute_operational_metrics(db)
    finally:
        db.close()


def get_metrics_snapshot() -> dict[str, Any]:
    payload = {
        "status": dict(_evaluation_state),
        "operational": refresh_operational_metrics(),
        "validation": None,
    }
    if ARTIFACT_PATH.exists():
        try:
            payload["validation"] = json.loads(ARTIFACT_PATH.read_text())
        except Exception as exc:
            payload["status"]["message"] = f"Could not read evaluation artifact: {exc}"
    return payload


def launch_controlled_evaluation() -> threading.Thread | None:
    if not _evaluation_lock.acquire(blocking=False):
        _evaluation_state.update(
            {
                "running": False,
                "message": "A controlled evaluation is already running.",
            }
        )
        return None

    _evaluation_state.update(
        {
            "running": True,
            "started_at": datetime.utcnow().isoformat(timespec="seconds"),
            "finished_at": "",
            "message": "Controlled evaluation started.",
        }
    )
    worker = threading.Thread(target=_run_controlled_evaluation, daemon=True)
    worker.start()
    return worker


def _pick_two_free_ports() -> tuple[int, int]:
    free: list[int] = []
    for port in _EVAL_PORT_CANDIDATES:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((_EVAL_HOST, port))
        except OSError:
            continue
        finally:
            sock.close()
        free.append(port)
        if len(free) == 2:
            return free[0], free[1]
    raise RuntimeError("Could not reserve two free monitored ports for controlled evaluation.")


def _start_server(port: int, banner: str) -> _EvalServer:
    handler = type(f"EvalBannerHandler_{port}", (_BannerHandler,), {"banner": banner})
    server = _ReusableHTTPServer((_EVAL_HOST, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return _EvalServer(server=server, thread=thread)


def _expected_apache_cves() -> set[str]:
    db_path = Path(__file__).resolve().parent.parent / "datasets" / "vuln_lookup.db"
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT DISTINCT c.cve_id
            FROM cves c
            JOIN cve_cpes cc ON c.cve_id = cc.cve_id
            JOIN cpes p ON p.cpe_uri = cc.cpe_uri
            WHERE p.vendor = 'apache'
              AND p.product = 'http_server'
              AND p.version = '2.4.49'
            ORDER BY c.cve_id ASC
            """
        )
        return {row[0] for row in cur.fetchall()}
    finally:
        conn.close()


def _safe_pct(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return round((numerator / denominator) * 100.0, 2)


def _f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return round(2 * precision * recall / (precision + recall), 2)


def _explainability_coverage(findings: list[dict[str, Any]]) -> float:
    if not findings:
        return 0.0
    covered = 0
    for finding in findings:
        explanation = explain_finding(finding)
        if all(str(explanation.get(field, "")).strip() for field in _EXPLAINABILITY_FIELDS):
            covered += 1
    return _safe_pct(covered, len(findings))


def _explainability_by_severity(findings: list[dict[str, Any]]) -> dict[str, dict[str, float | int]]:
    breakdown: dict[str, dict[str, float | int]] = {}
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        bucket = [finding for finding in findings if str(finding.get("severity", "")).upper() == severity]
        if not bucket:
            continue
        complete = 0
        for finding in bucket:
            explanation = explain_finding(finding)
            if all(str(explanation.get(field, "")).strip() for field in _EXPLAINABILITY_FIELDS):
                complete += 1
        breakdown[severity] = {
            "total_findings": len(bucket),
            "complete_explanations": complete,
            "coverage": _safe_pct(complete, len(bucket)),
        }
    return breakdown


def _reported_match_false_positive_rate(reported: set[str], expected: set[str]) -> float:
    if not reported:
        return 0.0
    false_positives = reported - expected
    return _safe_pct(len(false_positives), len(reported))


def _prioritization_quality(findings: list[dict[str, Any]]) -> float:
    if not findings:
        return 0.0
    important = [
        finding
        for finding in findings
        if bool(finding.get("kev")) or bool(finding.get("exploit")) or float(finding.get("epss") or 0.0) >= 0.5
    ]
    if not important:
        return 100.0

    ranked = sorted(
        findings,
        key=lambda finding: (
            finding_priority_score(
                finding.get("cvss", 0.0),
                kev=bool(finding.get("kev")),
                exploit=bool(finding.get("exploit")),
                epss=finding.get("epss", 0.0),
            ),
            float(finding.get("cvss") or 0.0),
            float(finding.get("epss") or 0.0),
        ),
        reverse=True,
    )
    top_n = ranked[: len(important)]
    captured = sum(1 for finding in top_n if finding in important)
    return _safe_pct(captured, len(important))


def _alert_dedup_rate(alerts: list[Alert]) -> float:
    if not alerts:
        return 100.0
    unresolved = [alert for alert in alerts if not alert.acknowledged]
    if not unresolved:
        return 100.0
    keys = [(alert.site_id, alert.trigger_type, alert.title, alert.detail) for alert in unresolved]
    duplicates = len(keys) - len(set(keys))
    return round((1 - (duplicates / len(unresolved))) * 100.0, 2)


def _compute_operational_metrics(db) -> dict[str, Any]:
    runs = db.query(ScanRun).all()
    findings_rows = db.query(Finding).all()
    alerts = db.query(Alert).all()

    total_runs = len(runs)
    done_runs = sum(1 for run in runs if run.status == "done")
    findings = [
        {
            "cve_id": row.cve_id,
            "severity": row.severity,
            "cvss": row.cvss,
            "epss": row.epss,
            "kev": row.kev,
            "exploit": row.exploit,
            "affected_assets": row.affected_assets,
            "evidence": row.evidence,
        }
        for row in findings_rows
    ]

    return {
        "scan_success_rate": _safe_pct(done_runs, total_runs) if total_runs else None,
        "total_runs": total_runs,
        "completed_runs": done_runs,
        "alert_deduplication_rate": _alert_dedup_rate(alerts),
        "prioritization_quality": _prioritization_quality(findings),
        "explainability_score": _explainability_coverage(findings),
        "explainability_by_severity": _explainability_by_severity(findings),
        "finding_count": len(findings),
        "alert_count": len(alerts),
    }


def _diff_between_runs(prev_run_id: str, curr_run_id: str, db) -> dict[str, Any]:
    prev_run = db.query(ScanRun).filter(ScanRun.run_id == prev_run_id, ScanRun.status == "done").first()
    curr_run = db.query(ScanRun).filter(ScanRun.run_id == curr_run_id, ScanRun.status == "done").first()
    if not prev_run or not curr_run:
        return {}

    curr_findings = {finding.cve_id: finding for finding in db.query(Finding).filter(Finding.run_id == curr_run_id).all()}
    prev_findings = {finding.cve_id: finding for finding in db.query(Finding).filter(Finding.run_id == prev_run_id).all()}
    curr_assets = {asset.host: asset for asset in db.query(Asset).filter(Asset.run_id == curr_run_id).all()}
    prev_assets = {asset.host: asset for asset in db.query(Asset).filter(Asset.run_id == prev_run_id).all()}

    def _ports(asset: Asset) -> list[int]:
        try:
            return sorted(int(port) for port in json.loads(asset.ports_json or "[]"))
        except Exception:
            return []

    return {
        "run_a": prev_run_id,
        "run_b": curr_run_id,
        "new_findings": sorted([cve_id for cve_id in curr_findings if cve_id not in prev_findings]),
        "resolved_findings": sorted([cve_id for cve_id in prev_findings if cve_id not in curr_findings]),
        "port_changes": [
            {
                "host": host,
                "old": _ports(prev_assets[host]),
                "new": _ports(curr_assets[host]),
            }
            for host in curr_assets
            if host in prev_assets and _ports(curr_assets[host]) != _ports(prev_assets[host])
        ],
    }


def _cleanup_evaluation_site(site_id: str) -> None:
    db = SessionLocal()
    try:
        db.query(Alert).filter(Alert.site_id == site_id).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.site_id == site_id).delete(synchronize_session=False)
        db.query(Asset).filter(Asset.site_id == site_id).delete(synchronize_session=False)
        run_ids = [row.run_id for row in db.query(ScanRun.run_id).filter(ScanRun.site_id == site_id).all()]
        if run_ids:
            db.query(ScanLog).filter(ScanLog.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(ScanRun).filter(ScanRun.site_id == site_id).delete(synchronize_session=False)
        db.query(SchedulerJob).filter(SchedulerJob.site_id == site_id).delete(synchronize_session=False)
        db.query(Site).filter(Site.site_id == site_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _first_timestamp(rows: list[ScanLog], patterns: tuple[str, ...]) -> datetime | None:
    for row in rows:
        message = row.message or ""
        if any(pattern in message for pattern in patterns):
            return row.ts
    return None


def _stage_latencies_for_run(run_id: str, db) -> dict[str, float]:
    rows = (
        db.query(ScanLog)
        .filter(ScanLog.run_id == run_id)
        .order_by(ScanLog.ts.asc(), ScanLog.id.asc())
        .all()
    )
    if not rows:
        return {}

    recon_start = _first_timestamp(rows, ("Recon Agent [CrewAI]: starting scope expansion.", "Orchestrator started"))
    scan_start = _first_timestamp(rows, ("Scanner Agent [CrewAI]: starting service enumeration.", "Scan Agent:"))
    vuln_start = _first_timestamp(rows, ("Vulnerability Agent [CrewAI]: starting CVE correlation.", "Vulnerability Agent:"))
    diff_start = _first_timestamp(rows, ("Diff Agent [CrewAI]: starting drift comparison.", "Diff Agent:"))
    report_end = _first_timestamp(rows, ("Report Agent [CrewAI]: run complete", "Report Agent: run completed successfully."))

    def _delta_seconds(start: datetime | None, end: datetime | None) -> float | None:
        if not start or not end:
            return None
        return round(max((end - start).total_seconds(), 0.0), 3)

    values = {
        "recon_seconds": _delta_seconds(recon_start, scan_start),
        "scan_seconds": _delta_seconds(scan_start, vuln_start),
        "vulnerability_seconds": _delta_seconds(vuln_start, diff_start),
        "diff_seconds": _delta_seconds(diff_start, report_end),
        "total_pipeline_seconds": _delta_seconds(recon_start, report_end),
    }
    return {key: value for key, value in values.items() if value is not None}


def _stage_latency_breakdown(run_ids: list[str], db) -> dict[str, Any]:
    per_run: dict[str, dict[str, float]] = {}
    stage_samples: dict[str, list[float]] = {}

    for run_id in run_ids:
        latencies = _stage_latencies_for_run(run_id, db)
        if not latencies:
            continue
        per_run[run_id] = latencies
        for stage, seconds in latencies.items():
            stage_samples.setdefault(stage, []).append(seconds)

    summary = {}
    for stage, samples in stage_samples.items():
        summary[stage] = {
            "mean_seconds": round(mean(samples), 3),
            "std_seconds": round(pstdev(samples), 3) if len(samples) > 1 else 0.0,
            "samples": len(samples),
        }

    return {"summary": summary, "per_run": per_run}


def _run_controlled_evaluation() -> None:
    original_ports = PROFILE_PORTS.get(_EVAL_PROFILE)
    original_timeout = PROFILE_TIMEOUTS.get(_EVAL_PROFILE)
    original_host_limit = PROFILE_HOST_LIMITS.get(_EVAL_PROFILE)
    site_id = str(uuid.uuid4())
    servers: list[_EvalServer] = []

    try:
        primary_port, extra_port = _pick_two_free_ports()
        PROFILE_PORTS[_EVAL_PROFILE] = [primary_port, extra_port]
        PROFILE_TIMEOUTS[_EVAL_PROFILE] = 0.35
        PROFILE_HOST_LIMITS[_EVAL_PROFILE] = 4

        run_ids = [str(uuid.uuid4()) for _ in range(3)]

        db = SessionLocal()
        try:
            db.add(
                Site(
                    site_id=site_id,
                    name="Controlled Evaluation Site",
                    primary_domain=_EVAL_HOST,
                    allowed_scopes=_EVAL_HOST,
                    policy=_EVAL_PROFILE,
                    schedule="manual",
                    auth_confirmed=True,
                )
            )
            db.commit()
            db.add(
                ScanRun(
                    run_id=run_ids[0],
                    site_id=site_id,
                    scope=_EVAL_HOST,
                    profile=_EVAL_PROFILE,
                    status="queued",
                    progress=0,
                )
            )
            db.commit()
        finally:
            db.close()

        servers.append(_start_server(primary_port, "nginx/1.25.0"))
        time.sleep(0.35)
        run_pipeline(run_ids[0], site_id=site_id)
        servers.pop().close()
        time.sleep(0.5)

        change_introduced_at = datetime.utcnow()
        servers.append(_start_server(primary_port, "Apache/2.4.49"))
        servers.append(_start_server(extra_port, "Apache/2.4.49"))
        time.sleep(0.35)
        db = SessionLocal()
        try:
            db.add(
                ScanRun(
                    run_id=run_ids[1],
                    site_id=site_id,
                    scope=_EVAL_HOST,
                    profile=_EVAL_PROFILE,
                    status="queued",
                    progress=0,
                )
            )
            db.commit()
        finally:
            db.close()
        run_pipeline(run_ids[1], site_id=site_id)
        time.sleep(0.4)

        db = SessionLocal()
        try:
            diff_after_second = _diff_between_runs(run_ids[0], run_ids[1], db)
            alerts_after_second = db.query(Alert).filter(Alert.site_id == site_id).all()
            run1_findings = db.query(Finding).filter(Finding.run_id == run_ids[0]).all()
            run2_findings_rows = db.query(Finding).filter(Finding.run_id == run_ids[1]).all()
            stage_breakdown = _stage_latency_breakdown(run_ids[:2], db)
        finally:
            db.close()

        db = SessionLocal()
        try:
            db.add(
                ScanRun(
                    run_id=run_ids[2],
                    site_id=site_id,
                    scope=_EVAL_HOST,
                    profile=_EVAL_PROFILE,
                    status="queued",
                    progress=0,
                )
            )
            db.commit()
        finally:
            db.close()
        run_pipeline(run_ids[2], site_id=site_id)
        servers.pop().close()
        servers.pop().close()
        time.sleep(0.4)

        db = SessionLocal()
        try:
            runs = [db.query(ScanRun).filter(ScanRun.run_id == run_id).first() for run_id in run_ids]
            all_alerts = db.query(Alert).filter(Alert.site_id == site_id).all()
            stage_breakdown = _stage_latency_breakdown(run_ids, db)
        finally:
            db.close()

        expected_cves = _expected_apache_cves()
        run2_findings = {
            "rows": [
                {
                    "cve_id": row.cve_id,
                    "severity": row.severity,
                    "cvss": row.cvss,
                    "epss": row.epss,
                    "kev": row.kev,
                    "exploit": row.exploit,
                    "affected_assets": row.affected_assets,
                    "evidence": row.evidence,
                }
                for row in run2_findings_rows
            ]
        }
        run2_cves = {row["cve_id"] for row in run2_findings["rows"]}
        true_positive_cves = run2_cves & expected_cves
        false_positive_cves = run2_cves - expected_cves

        actual_changes = {f"finding:{cve_id}" for cve_id in expected_cves}
        actual_changes.add("port_change")
        reported_changes = {f"finding:{cve_id}" for cve_id in diff_after_second.get("new_findings", [])}
        if diff_after_second.get("port_changes"):
            reported_changes.add("port_change")

        drift_tp = len(actual_changes & reported_changes)
        drift_precision = _safe_pct(drift_tp, len(reported_changes)) if reported_changes else 0.0
        drift_recall = _safe_pct(drift_tp, len(actual_changes))
        drift_f1 = _f1(drift_precision, drift_recall)

        actual_port_changes = {
            (
                _EVAL_HOST,
                tuple(sorted([primary_port])),
                tuple(sorted([primary_port, extra_port])),
            )
        }
        reported_port_changes = {
            (
                str(change.get("host")),
                tuple(sorted(int(port) for port in change.get("old", []))),
                tuple(sorted(int(port) for port in change.get("new", []))),
            )
            for change in diff_after_second.get("port_changes", [])
        }
        port_change_tp = len(actual_port_changes & reported_port_changes)
        port_change_precision = _safe_pct(port_change_tp, len(reported_port_changes)) if reported_port_changes else 0.0
        port_change_recall = _safe_pct(port_change_tp, len(actual_port_changes))

        first_alert_time = min((alert.created_at for alert in alerts_after_second if alert.created_at), default=None)
        mttd_seconds = round(max((first_alert_time - change_introduced_at).total_seconds(), 0.0), 3) if first_alert_time else None

        validation_findings = run2_findings["rows"]
        explainability_score = _explainability_coverage(validation_findings)
        explainability_by_severity = _explainability_by_severity(validation_findings)
        sample_explanation = explain_finding(validation_findings[0]) if validation_findings else {}

        validation = {
            "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
            "mode": orchestration_label(),
            "scenario": {
                "host": _EVAL_HOST,
                "profile": _EVAL_PROFILE,
                "ports": {"baseline": [primary_port], "changed": [primary_port, extra_port]},
                "baseline_banner": "nginx/1.25.0",
                "changed_banner": "Apache/2.4.49",
            },
            "metrics": {
                "scan_success_rate": _safe_pct(sum(1 for run in runs if run and run.status == "done"), len(runs)),
                "vulnerability_correlation_precision": _safe_pct(len(true_positive_cves), len(run2_cves)),
                "vulnerability_correlation_false_positive_rate": _reported_match_false_positive_rate(run2_cves, expected_cves),
                "drift_detection_precision": drift_precision,
                "drift_detection_recall": drift_recall,
                "drift_detection_f1": drift_f1,
                "port_change_detection_precision": port_change_precision,
                "port_change_detection_recall": port_change_recall,
                "mean_time_to_detect_seconds": mttd_seconds,
                "alert_deduplication_rate": _alert_dedup_rate(all_alerts),
                "prioritization_quality": _prioritization_quality(validation_findings),
                "explainability_score": explainability_score,
            },
            "evidence": {
                "expected_cves": sorted(expected_cves),
                "false_positive_cves": sorted(false_positive_cves),
                "baseline_findings": sorted({row.cve_id for row in run1_findings}),
                "changed_findings": sorted(run2_cves),
                "drift_after_second_run": diff_after_second,
                "change_introduced_at": change_introduced_at.isoformat(timespec="milliseconds"),
                "first_alert_created_at": first_alert_time.isoformat(timespec="milliseconds") if first_alert_time else "",
                "alert_types": sorted({alert.trigger_type for alert in alerts_after_second}),
                "stage_latency_breakdown": stage_breakdown,
                "explainability_by_severity": explainability_by_severity,
                "sample_explanation": sample_explanation,
            },
            "notes": [
                "Vulnerability Correlation Precision is measured against a controlled Apache 2.4.49 banner mapped to the local vulnerability database.",
                "Drift metrics are computed over seeded changes only: newly introduced Apache CVEs and one newly opened monitored port.",
                "Vulnerability Correlation False Positive Rate is reported over emitted matches in the seeded scenario because the harness does not define a full real-world negative universe.",
                "Mean Time to Detect measures the elapsed time between introducing the changed service state and persisting the first alert for that changed run.",
                "Stage latency values are derived from timestamped ScanLog events and averaged across the controlled runs.",
                "Explainability Score is currently a deterministic coverage proxy based on whether all plain-language explanation fields are generated.",
            ],
        }

        ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT_PATH.write_text(json.dumps(validation, indent=2))
        _evaluation_state.update(
            {
                "running": False,
                "finished_at": datetime.utcnow().isoformat(timespec="seconds"),
                "message": "Controlled evaluation completed successfully.",
            }
        )
    except Exception as exc:
        _evaluation_state.update(
            {
                "running": False,
                "finished_at": datetime.utcnow().isoformat(timespec="seconds"),
                "message": f"Controlled evaluation failed: {exc}",
            }
        )
        if not ARTIFACT_PATH.exists():
            ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT_PATH.write_text(
            json.dumps(
                {
                    "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
                    "mode": orchestration_label(),
                    "error": str(exc),
                },
                indent=2,
            )
        )
    finally:
        while servers:
            servers.pop().close()
        _cleanup_evaluation_site(site_id)
        if original_ports is None:
            PROFILE_PORTS.pop(_EVAL_PROFILE, None)
        else:
            PROFILE_PORTS[_EVAL_PROFILE] = original_ports
        if original_timeout is None:
            PROFILE_TIMEOUTS.pop(_EVAL_PROFILE, None)
        else:
            PROFILE_TIMEOUTS[_EVAL_PROFILE] = original_timeout
        if original_host_limit is None:
            PROFILE_HOST_LIMITS.pop(_EVAL_PROFILE, None)
        else:
            PROFILE_HOST_LIMITS[_EVAL_PROFILE] = original_host_limit
        _evaluation_lock.release()

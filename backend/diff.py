"""
diff.py — compare consecutive scan runs for a site.
Detects new/resolved findings, asset changes, and fires Alerts.
"""
import json
from datetime import datetime
from sqlalchemy.orm import Session
from .models import ScanRun, Asset, Finding, Alert
from .prioritization import classify_priority_band


def _port_set(asset: Asset) -> set[int]:
    raw = getattr(asset, "ports_json", "") or ""
    if raw:
        try:
            return {int(port) for port in json.loads(raw)}
        except Exception:
            pass
    return set(range(int(asset.open_ports or 0)))


def _finding_alert_severity(finding: Finding) -> str:
    return classify_priority_band(
        finding.cvss,
        kev=bool(finding.kev),
        exploit=bool(finding.exploit),
        epss=finding.epss,
        fallback=finding.severity,
    )


def _queue_alert(
    db: Session,
    alerts_to_add: list[Alert],
    *,
    site_id: str,
    run_id: str,
    trigger_type: str,
    severity: str,
    title: str,
    detail: str,
    finding_id: int | None = None,
) -> None:
    duplicate = (
        db.query(Alert.id)
        .filter(
            Alert.site_id == site_id,
            Alert.trigger_type == trigger_type,
            Alert.title == title,
            Alert.detail == detail,
            Alert.acknowledged == False,
        )
        .first()
    )
    if duplicate:
        return
    for pending in alerts_to_add:
        if (
            pending.site_id == site_id
            and pending.trigger_type == trigger_type
            and pending.title == title
            and pending.detail == detail
            and not pending.acknowledged
        ):
            return
    alerts_to_add.append(
        Alert(
            site_id=site_id,
            run_id=run_id,
            finding_id=finding_id,
            trigger_type=trigger_type,
            severity=severity,
            title=title,
            detail=detail,
            created_at=datetime.utcnow(),
        )
    )


def run_diff(site_id: str, current_run_id: str, db: Session) -> dict:
    """
    Compare the current run against the most recent previous run for the site.
    Returns a dict describing deltas and stores Alert rows.
    """
    # Find the previous completed run for this site (not the current one)
    prev_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.site_id == site_id,
            ScanRun.status == "done",
            ScanRun.run_id != current_run_id,
        )
        .order_by(ScanRun.created_at.desc())
        .first()
    )

    curr_findings = db.query(Finding).filter(Finding.run_id == current_run_id).all()
    curr_assets   = db.query(Asset).filter(Asset.run_id == current_run_id).all()

    # Build lookups
    curr_cves   = {f.cve_id: f for f in curr_findings}
    curr_hosts  = {a.host: a for a in curr_assets}

    delta = {
        "new_findings":      [],
        "resolved_findings": [],
        "new_assets":        [],
        "gone_assets":       [],
        "ip_changes":        [],
        "port_changes":      [],
    }

    alerts_to_add = []

    if prev_run is None:
        # First run for this site — everything is "new", just alert on criticals
        for f in curr_findings:
            alert_severity = _finding_alert_severity(f)
            if alert_severity in ("CRITICAL", "HIGH") or f.kev:
                delta["new_findings"].append(f.cve_id)
                _queue_alert(
                    db,
                    alerts_to_add,
                    site_id=site_id,
                    run_id=current_run_id,
                    finding_id=f.id,
                    trigger_type="new_critical" if alert_severity == "CRITICAL" else ("new_kev" if f.kev else "new_high"),
                    severity=alert_severity,
                    title=f"Initial scan: [{alert_severity}] {f.cve_id}",
                    detail=f"First detection of {f.cve_id} — {f.title[:120]}",
                )
        for a in curr_assets:
            delta["new_assets"].append(a.host)
    else:
        prev_findings = db.query(Finding).filter(Finding.run_id == prev_run.run_id).all()
        prev_assets   = db.query(Asset).filter(Asset.run_id == prev_run.run_id).all()

        prev_cves  = {f.cve_id: f for f in prev_findings}
        prev_hosts = {a.host: a for a in prev_assets}

        # ── Finding diffs ──────────────────────────────────────────────────
        for cve_id, f in curr_cves.items():
            if cve_id not in prev_cves:
                delta["new_findings"].append(cve_id)
                alert_severity = _finding_alert_severity(f)
                if alert_severity in ("CRITICAL", "HIGH") or f.kev:
                    _queue_alert(
                        db,
                        alerts_to_add,
                        site_id=site_id,
                        run_id=current_run_id,
                        finding_id=f.id,
                        trigger_type="new_critical" if alert_severity == "CRITICAL" else ("new_kev" if f.kev else "new_high"),
                        severity=alert_severity,
                        title=f"New [{alert_severity}] found: {cve_id}",
                        detail=f.title[:200],
                    )
            else:
                # Check if KEV status changed
                prev_f = prev_cves[cve_id]
                if not prev_f.kev and f.kev:
                    _queue_alert(
                        db,
                        alerts_to_add,
                        site_id=site_id,
                        run_id=current_run_id,
                        finding_id=f.id,
                        trigger_type="new_kev",
                        severity="CRITICAL",
                        title=f"KEV Escalation: {cve_id} is now actively exploited",
                        detail=f.title[:200],
                    )

        for cve_id in prev_cves:
            if cve_id not in curr_cves:
                delta["resolved_findings"].append(cve_id)

        # ── Asset diffs ────────────────────────────────────────────────────
        for host, a in curr_hosts.items():
            if host not in prev_hosts:
                delta["new_assets"].append(host)
                _queue_alert(
                    db,
                    alerts_to_add,
                    site_id=site_id,
                    run_id=current_run_id,
                    trigger_type="new_asset",
                    severity="HIGH",
                    title=f"New asset discovered: {host} ({a.ip})",
                    detail=f"Host {host} ({a.ip}) was not present in the previous scan.",
                )
            else:
                prev_a = prev_hosts[host]
                if prev_a.ip != a.ip:
                    delta["ip_changes"].append({"host": host, "old": prev_a.ip, "new": a.ip})
                    _queue_alert(
                        db,
                        alerts_to_add,
                        site_id=site_id,
                        run_id=current_run_id,
                        trigger_type="ip_change",
                        severity="MEDIUM",
                        title=f"IP change: {host} ({prev_a.ip} → {a.ip})",
                        detail=f"The IP address for {host} changed unexpectedly.",
                    )
                prev_ports = _port_set(prev_a)
                curr_ports = _port_set(a)
                if prev_ports != curr_ports:
                    added = sorted(curr_ports - prev_ports)
                    removed = sorted(prev_ports - curr_ports)
                    delta["port_changes"].append({"host": host, "old": sorted(prev_ports), "new": sorted(curr_ports)})
                    if added:
                        _queue_alert(
                            db,
                            alerts_to_add,
                            site_id=site_id,
                            run_id=current_run_id,
                            trigger_type="port_change",
                            severity="HIGH",
                            title=f"New ports opened on {host}",
                            detail=f"Added ports: {added}. Removed ports: {removed or 'none'}.",
                        )

        for host in prev_hosts:
            if host not in curr_hosts:
                delta["gone_assets"].append(host)

    # Persist all alerts
    for alert in alerts_to_add:
        db.add(alert)
    db.commit()

    return delta

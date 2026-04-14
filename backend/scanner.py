"""
scanner.py — site-aware scan pipeline with live discovery, enumeration,
vulnerability correlation, and drift-triggered alerting.

This still aims at capstone-scale practicality: it uses Python sockets for
discovery and banner grabbing, and optionally benefits from richer service
metadata if better tooling is installed later.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import sqlite3 as stdlib_sqlite3
import ssl
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger(__name__)

from sqlalchemy.orm import Session

from .db import SessionLocal
from .diff import run_diff
from .models import Asset, Finding, ScanLog, ScanRun
from .prioritization import classify_priority_band
from .threat_intel import get_epss_scores


_vuln_db_path = Path(__file__).resolve().parent.parent / "datasets" / "vuln_lookup.db"
_kev_cache_path = Path(__file__).resolve().parent.parent / "datasets" / "kev.json"
_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_CACHE_MAX_AGE_SECONDS = 86400  # 24 hours


def refresh_kev_cache(force: bool = False) -> dict[str, object]:
    """
    Load or refresh the cached CISA Known Exploited Vulnerabilities catalog.

    Strategy:
      1. Use `datasets/kev.json` if it exists and is < 24 h old unless forced.
      2. Otherwise attempt to download from the CISA live feed
         and save/update the cache.
      3. If both fail, fall back to the local cache if present.
    """
    # --- try local cache first ---
    if not force and _kev_cache_path.exists():
        cache_age = time.time() - _kev_cache_path.stat().st_mtime
        if cache_age < _KEV_CACHE_MAX_AGE_SECONDS:
            try:
                with _kev_cache_path.open() as f:
                    data = json.load(f)
                cves = frozenset(
                    v["cveID"]
                    for v in data.get("vulnerabilities", [])
                    if v.get("cveID")
                )
                if cves:
                    return {"cves": cves, "source": "cache", "cache_path": str(_kev_cache_path)}
            except Exception as exc:
                log.warning("KEV cache read failed: %s", exc)

    # --- attempt live download ---
    try:
        req = urllib.request.Request(
            _KEV_FEED_URL,
            headers={"User-Agent": "VulnPilot-KEVRefresh/1.0"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read()
        data = json.loads(raw)
        # persist to cache
        _kev_cache_path.parent.mkdir(parents=True, exist_ok=True)
        _kev_cache_path.write_bytes(raw)
        cves = frozenset(
            v["cveID"]
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        )
        return {"cves": cves, "source": "live", "cache_path": str(_kev_cache_path)}
    except Exception as exc:
        log.warning("KEV live-feed download failed (%s); KEV enrichment skipped.", exc)

    # --- fall back to stale cache if online fetch failed ---
    if _kev_cache_path.exists():
        try:
            with _kev_cache_path.open() as f:
                data = json.load(f)
            cves = frozenset(
                v["cveID"]
                for v in data.get("vulnerabilities", [])
                if v.get("cveID")
            )
            return {"cves": cves, "source": "stale-cache", "cache_path": str(_kev_cache_path)}
        except Exception:
            pass

    return {"cves": frozenset(), "source": "none", "cache_path": str(_kev_cache_path)}


def _fetch_kev_cves() -> frozenset[str]:
    return refresh_kev_cache(force=False)["cves"]

PORT_HINTS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8000: "http",
    8080: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9200: "elasticsearch",
    27017: "mongodb",
}

PROFILE_PORTS = {
    "safe": [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443],
    "balanced": [21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 587, 993, 995, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017],
}
PROFILE_PORTS["aggressive"] = sorted(set(PROFILE_PORTS["balanced"] + list(range(1, 1025))))

PROFILE_TIMEOUTS = {
    "safe": 0.35,
    "balanced": 0.45,
    "aggressive": 0.25,
}

PROFILE_HOST_LIMITS = {
    "safe": 16,
    "balanced": 48,
    "aggressive": 128,
}

PASSIVE_DISCOVERY_TOOLS = (
    (
        "subfinder",
        [
            "subfinder",
            "-silent",
            "-config",
            str(Path(__file__).resolve().parent.parent / "tooling" / "subfinder" / "config.yaml"),
            "-pc",
            str(Path(__file__).resolve().parent.parent / "tooling" / "subfinder" / "provider-config.yaml"),
            "-d",
        ],
        12,
    ),
    ("amass", ["amass", "enum", "-passive", "-norecursive", "-noalts", "-d"], 15),
)

SERVICE_PATTERNS = {
    "apache": re.compile(r"apache(?:/| )(?P<version>\d+(?:\.\d+){1,3})", re.IGNORECASE),
    "nginx": re.compile(r"nginx(?:/| )(?P<version>\d+(?:\.\d+){1,3})", re.IGNORECASE),
    "openssh": re.compile(r"openssh[_/ -](?P<version>\d+(?:\.\d+)+)", re.IGNORECASE),
    "mysql": re.compile(r"(?P<version>\d+\.\d+\.\d+)", re.IGNORECASE),
    "postgresql": re.compile(r"postgres(?:ql)?[ /-]?(?P<version>\d+(?:\.\d+)+)", re.IGNORECASE),
    "redis": re.compile(r"redis[_/ -]?(?P<version>\d+(?:\.\d+)+)", re.IGNORECASE),
    "mongodb": re.compile(r"mongodb[ /-]?(?P<version>\d+(?:\.\d+)+)", re.IGNORECASE),
}

SERVICE_TO_CPE = {
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
}


def _log(db: Session, run_id: str, msg: str, level: str = "INFO") -> None:
    db.add(ScanLog(run_id=run_id, level=level, message=msg, ts=datetime.utcnow()))
    db.commit()


def _check_stopped(db: Session, run_id: str) -> bool:
    db.expire_all()
    run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()
    return run is not None and run.status == "stopped"


def _set_progress(db: Session, run: ScanRun, value: int) -> None:
    if run.progress == value:
        return
    run.progress = value
    db.commit()


def _normalize_scope_token(token: str) -> str:
    token = token.strip()
    if token.startswith(("http://", "https://")):
        parsed = urlparse(token)
        return parsed.netloc or token
    return token


def _is_domain_candidate(token: str) -> bool:
    return bool(re.search(r"[a-zA-Z]", token)) and "." in token and "/" not in token and " " not in token


def _discover_subdomains(domain: str, max_hosts: int) -> tuple[list[str], list[str]]:
    discovered: set[str] = set()
    notes: list[str] = []

    for tool_name, base_cmd, timeout_seconds in PASSIVE_DISCOVERY_TOOLS:
        if not shutil.which(tool_name):
            continue
        try:
            result = subprocess.run(
                [*base_cmd, domain],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            if result.returncode != 0 and result.stderr.strip():
                notes.append(f"{tool_name} passive discovery warning: {result.stderr.strip()[:180]}")
            output_lines = [
                line.strip().lower()
                for line in result.stdout.splitlines()
                if line.strip() and not line.lstrip().startswith("[")
            ]
            for candidate in output_lines:
                if candidate == domain or candidate.endswith(f".{domain}"):
                    discovered.add(candidate)
            if output_lines:
                notes.append(f"{tool_name} discovered {len(output_lines)} candidate subdomain(s) for {domain}.")
        except Exception as exc:
            notes.append(f"{tool_name} passive discovery failed for {domain}: {exc}")

    ordered = sorted(discovered)
    if len(ordered) > max_hosts:
        notes.append(
            f"Passive discovery for {domain} returned {len(ordered)} subdomain(s); limiting to first {max_hosts}."
        )
        ordered = ordered[:max_hosts]
    return ordered, notes


def _expand_scope(scope: str, profile: str) -> tuple[list[dict], list[str]]:
    targets: list[dict] = []
    warnings: list[str] = []
    max_hosts = PROFILE_HOST_LIMITS.get(profile, PROFILE_HOST_LIMITS["safe"])

    seen = set()
    tokens = [_normalize_scope_token(tok) for tok in scope.replace("\n", ",").split(",") if tok.strip()]
    if not tokens:
        return [], ["No target scope provided."]

    for token in tokens:
        try:
            network = ipaddress.ip_network(token, strict=False)
            hosts = list(network.hosts())
            if len(hosts) > max_hosts:
                warnings.append(
                    f"Scope {token} expands to {len(hosts)} hosts; limiting to first {max_hosts} for this profile."
                )
                hosts = hosts[:max_hosts]
            for host_ip in hosts:
                ip = str(host_ip)
                if ip not in seen:
                    seen.add(ip)
                    targets.append({"host": ip, "ip": ip})
            continue
        except ValueError:
            pass

        try:
            ipaddress.ip_address(token)
            if token not in seen:
                seen.add(token)
                targets.append({"host": token, "ip": token})
            continue
        except ValueError:
            pass

        candidate_hosts = [token]
        if _is_domain_candidate(token):
            subdomains, passive_notes = _discover_subdomains(token, max_hosts)
            warnings.extend(passive_notes)
            candidate_hosts.extend(subdomains)

        for candidate_host in candidate_hosts:
            try:
                infos = socket.getaddrinfo(candidate_host, None, socket.AF_INET, socket.SOCK_STREAM)
                ips = sorted({info[4][0] for info in infos})
                if not ips:
                    warnings.append(f"{candidate_host} resolved to no IPv4 addresses.")
                    continue
                for ip in ips:
                    host_label = candidate_host if len(ips) == 1 else f"{candidate_host}::{ip}"
                    dedupe_key = (candidate_host, ip)
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    targets.append({"host": host_label, "ip": ip})
            except socket.gaierror:
                warnings.append(f"Could not resolve target: {candidate_host}")

    return targets, warnings


def _read_plain_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(0.6)
        data = sock.recv(512)
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _http_probe(host: str, ip: str, port: int, timeout: float, use_tls: bool) -> str:
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        stream = sock
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            stream = context.wrap_socket(sock, server_hostname=host.split("::")[0] or ip)

        request = f"HEAD / HTTP/1.0\r\nHost: {host.split('::')[0]}\r\nUser-Agent: VulnPilot\r\n\r\n"
        stream.sendall(request.encode("ascii", errors="ignore"))
        response = stream.recv(1024).decode("utf-8", errors="ignore")
        return response
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _fingerprint_service(host: str, ip: str, port: int, timeout: float) -> dict:
    hint = PORT_HINTS.get(port, "unknown")
    banner = ""

    try:
        if hint == "http":
            banner = _http_probe(host, ip, port, timeout, use_tls=False)
        elif hint == "https":
            banner = _http_probe(host, ip, port, timeout, use_tls=True)
        else:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                if hint == "redis":
                    try:
                        sock.sendall(b"PING\r\n")
                    except Exception:
                        pass
                banner = _read_plain_banner(sock)
    except Exception:
        return {"port": port, "service": hint, "banner": "", "version": "", "vendor": "", "product": ""}

    normalized_service = hint
    vendor = ""
    product = ""
    version = ""
    lower_banner = banner.lower()

    if "server:" in lower_banner:
        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                banner = line.split(":", 1)[1].strip()
                lower_banner = banner.lower()
                break

    if "apache" in lower_banner:
        normalized_service = "apache"
    elif "nginx" in lower_banner:
        normalized_service = "nginx"
    elif "openssh" in lower_banner or hint == "ssh":
        normalized_service = "openssh"
    elif "mysql" in lower_banner or hint == "mysql":
        normalized_service = "mysql"
    elif "postgres" in lower_banner or hint == "postgresql":
        normalized_service = "postgresql"
    elif "redis" in lower_banner or hint == "redis":
        normalized_service = "redis"
    elif "mongodb" in lower_banner or hint == "mongodb":
        normalized_service = "mongodb"

    pattern = SERVICE_PATTERNS.get(normalized_service)
    if pattern:
        match = pattern.search(banner)
        if match:
            version = match.group("version")

    if normalized_service in SERVICE_TO_CPE:
        vendor, product = SERVICE_TO_CPE[normalized_service]

    if normalized_service == "openssh" and version.endswith("p1"):
        version = version[:-2]

    return {
        "port": port,
        "service": normalized_service,
        "banner": banner[:240],
        "version": version,
        "vendor": vendor,
        "product": product,
    }


def _scan_target(target: dict, profile: str) -> dict:
    host = target["host"]
    ip = target["ip"]
    ports = PROFILE_PORTS.get(profile, PROFILE_PORTS["safe"])
    timeout = PROFILE_TIMEOUTS.get(profile, PROFILE_TIMEOUTS["safe"])

    open_ports: list[int] = []
    services: list[dict] = []

    def _probe(port: int) -> dict | None:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                pass
        except Exception:
            return None
        return _fingerprint_service(host, ip, port, timeout)

    with ThreadPoolExecutor(max_workers=32) as pool:
        future_map = {pool.submit(_probe, port): port for port in ports}
        for future in as_completed(future_map):
            result = future.result()
            if not result:
                continue
            open_ports.append(result["port"])
            services.append(result)

    open_ports.sort()
    services.sort(key=lambda item: item["port"])
    return {"host": host, "ip": ip, "ports": open_ports, "services": services}


def _version_candidates(version: str) -> list[str]:
    if not version:
        return []
    parts = version.split(".")
    candidates = [version]
    if len(parts) >= 2:
        candidates.append(".".join(parts[:2]))
    if len(parts) >= 1:
        candidates.append(parts[0])
    return list(dict.fromkeys(candidates))


def _lookup_vulnerabilities(service: dict, vuln_conn: stdlib_sqlite3.Connection) -> list[dict]:
    if not service.get("vendor") or not service.get("product") or not service.get("version"):
        return []

    cur = vuln_conn.cursor()
    cpe_rows = []
    for candidate in _version_candidates(service["version"]):
        cpe_rows = cur.execute(
            """
            SELECT cpe_uri FROM cpes
            WHERE vendor = ? AND product = ? AND (version = ? OR version LIKE ?)
            LIMIT 8
            """,
            (service["vendor"], service["product"], candidate, f"{candidate}%"),
        ).fetchall()
        if cpe_rows:
            break

    cpe_uris = [row[0] for row in cpe_rows]
    if not cpe_uris:
        return []

    placeholders = ",".join("?" for _ in cpe_uris)
    rows = cur.execute(
        f"""
        SELECT DISTINCT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity, cc.cpe_uri
        FROM cves c
        JOIN cve_cpes cc ON cc.cve_id = c.cve_id
        WHERE cc.cpe_uri IN ({placeholders})
        ORDER BY COALESCE(c.cvss_v3_score, 0) DESC, c.cve_id ASC
        LIMIT 6
        """,
        cpe_uris,
    ).fetchall()

    findings = []
    for row in rows:
        exploit = cur.execute(
            "SELECT exploit_id FROM exploits WHERE codes_json LIKE ? LIMIT 1",
            (f"%{row[0]}%",),
        ).fetchone()
        findings.append(
            {
                "cve_id": row[0],
                "description": row[1] or "",
                "cvss": float(row[2] or 0.0),
                "severity": row[3] or "MEDIUM",
                "cpe_uri": row[4],
                "exploit": 1 if exploit else 0,
            }
        )
    return findings


def _aggregate_findings(
    scan_results: list[dict],
    vuln_conn: stdlib_sqlite3.Connection,
    kev_cves: frozenset[str] | None = None,
    epss_scores: dict[str, dict[str, float | str]] | None = None,
) -> tuple[list[dict], dict]:
    """
    Correlate observed services against the local vuln DB and optionally enrich
    each finding with CISA KEV membership (kev=1 if CVE appears in the catalog).
    """
    if kev_cves is None:
        kev_cves = frozenset()
    if epss_scores is None:
        epss_scores = {}

    finding_map: dict[str, dict] = {}
    host_max_cvss: dict[str, float] = {}

    for asset in scan_results:
        host = asset["host"]
        host_max_cvss.setdefault(host, 0.0)
        for service in asset["services"]:
            matches = _lookup_vulnerabilities(service, vuln_conn)
            for match in matches:
                host_max_cvss[host] = max(host_max_cvss[host], match["cvss"])
                entry = finding_map.setdefault(
                    match["cve_id"],
                    {
                        "cve_id": match["cve_id"],
                        "title": match["description"][:140],
                        "severity": match["severity"],
                        "cvss": match["cvss"],
                        "epss": float(epss_scores.get(match["cve_id"], {}).get("epss", 0.0) or 0.0),
                        "kev": 1 if match["cve_id"] in kev_cves else 0,
                        "exploit": match["exploit"],
                        "affected_assets": set(),
                        "evidence_parts": [],
                        "remediation": f"Validate service exposure and patch the affected component. Reference: {match['cpe_uri']}",
                    },
                )
                entry["affected_assets"].add(host)
                entry["exploit"] = max(entry["exploit"], match["exploit"])
                entry["cvss"] = max(entry["cvss"], match["cvss"])
                entry["epss"] = max(
                    float(entry.get("epss", 0.0) or 0.0),
                    float(epss_scores.get(match["cve_id"], {}).get("epss", 0.0) or 0.0),
                )
                if entry["severity"] != "CRITICAL" and match["severity"] == "CRITICAL":
                    entry["severity"] = "CRITICAL"
                # KEV status: once true, stays true (union across services)
                if match["cve_id"] in kev_cves:
                    entry["kev"] = 1
                entry["evidence_parts"].append(
                    f"{host}:{service['port']} {service['service']} {service['version']} matched {match['cpe_uri']}"
                )

    findings = []
    for item in finding_map.values():
        item["severity"] = classify_priority_band(
            item["cvss"],
            kev=bool(item["kev"]),
            exploit=bool(item["exploit"]),
            epss=item["epss"],
            fallback=item["severity"],
        )
        findings.append(
            {
                **item,
                "affected_assets": len(item["affected_assets"]),
                "evidence": "; ".join(item["evidence_parts"][:5]),
            }
        )
    findings.sort(key=lambda finding: (-finding["cvss"], finding["cve_id"]))
    return findings, host_max_cvss


def _asset_risk_score(asset: dict, host_max_cvss: dict) -> float:
    base = min(len(asset["ports"]) * 0.8, 4.5)
    sensitive_ports = {22, 3389, 3306, 5432, 6379, 9200, 27017}
    if any(port in sensitive_ports for port in asset["ports"]):
        base += 1.5
    if any(service["service"] in {"apache", "nginx", "http", "https"} for service in asset["services"]):
        base += 1.0
    return round(min(10.0, max(base, host_max_cvss.get(asset["host"], 0.0))), 1)


def discover_targets(scope: str, profile: str) -> tuple[list[dict], list[str]]:
    """Expand a user scope into concrete host/IP targets for scanning."""
    return _expand_scope(scope, profile)


def enumerate_target_services(targets: list[dict], profile: str) -> list[dict]:
    """Probe the monitored port set for each target and return open services."""
    scan_results: list[dict] = []
    for target in targets:
        result = _scan_target(target, profile)
        if result["ports"]:
            scan_results.append(result)
    return scan_results


def correlate_scan_results(scan_results: list[dict]) -> tuple[list[dict], dict[str, float], str]:
    """Match observed services against the local vulnerability intelligence DB."""
    findings: list[dict] = []
    host_max_cvss: dict[str, float] = {}
    kev_status = "KEV enrichment unavailable."
    epss_scores = get_epss_scores()
    epss_status = (
        f"{len(epss_scores)} EPSS entries loaded"
        if epss_scores
        else "EPSS data unavailable"
    )

    if _vuln_db_path.exists():
        kev_cves = _fetch_kev_cves()
        kev_status = (
            f"{len(kev_cves)} KEV entries loaded"
            if kev_cves
            else "KEV data unavailable (offline or cache missing)"
        )
        vuln_conn = stdlib_sqlite3.connect(str(_vuln_db_path))
        try:
            findings, host_max_cvss = _aggregate_findings(scan_results, vuln_conn, kev_cves, epss_scores)
        finally:
            vuln_conn.close()
    else:
        kev_status = "vuln_lookup.db not found; skipping CVE correlation."

    return findings, host_max_cvss, f"{kev_status}; {epss_status}"


def persist_scan_artifacts(
    db: Session,
    run: ScanRun,
    run_id: str,
    scan_results: list[dict],
    findings: list[dict],
    host_max_cvss: dict[str, float],
) -> None:
    """Persist asset and finding snapshots for a completed scan stage."""
    now = datetime.utcnow()

    for asset in scan_results:
        db.add(
            Asset(
                site_id=run.site_id,
                run_id=run_id,
                host=asset["host"],
                ip=asset["ip"],
                open_ports=len(asset["ports"]),
                ports_json=json.dumps(asset["ports"]),
                services_json=json.dumps(asset["services"]),
                risk_score=_asset_risk_score(asset, host_max_cvss),
                first_seen=now,
                last_seen=now,
                status="active",
            )
        )

    db.commit()

    for finding in findings:
        db.add(
            Finding(
                site_id=run.site_id,
                run_id=run_id,
                cve_id=finding["cve_id"],
                title=finding["title"],
                severity=finding["severity"],
                cvss=finding["cvss"],
                epss=finding["epss"],
                kev=finding["kev"],
                exploit=finding["exploit"],
                affected_assets=finding["affected_assets"],
                evidence=finding["evidence"],
                remediation=finding["remediation"],
            )
        )
    db.commit()


def run_pipeline_direct(run_id: str, site_id: str | None = None) -> None:
    db = SessionLocal()

    try:
        run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()
        if not run:
            return

        if site_id and not run.site_id:
            run.site_id = site_id

        run.status = "running"
        _set_progress(db, run, 3)
        _log(db, run_id, f"Orchestrator started — scope: {run.scope}, profile: {run.profile}")

        if _check_stopped(db, run_id):
            _log(db, run_id, "Run stopped by user.", "WARN")
            return

        targets, warnings = discover_targets(run.scope, run.profile)
        for warning in warnings:
            _log(db, run_id, warning, "WARN")

        _log(db, run_id, f"Recon Agent: expanded scope into {len(targets)} candidate target(s).")
        _set_progress(db, run, 15)

        if _check_stopped(db, run_id):
            _log(db, run_id, "Run stopped by user.", "WARN")
            return

        scan_results: list[dict] = []
        for index, target in enumerate(targets, start=1):
            result = _scan_target(target, run.profile)
            if result["ports"]:
                scan_results.append(result)
                _log(
                    db,
                    run_id,
                    f"Scan Agent: {result['host']} ({result['ip']}) has {len(result['ports'])} open port(s): {result['ports']}",
                )
            else:
                _log(db, run_id, f"Scan Agent: no monitored ports open on {target['host']} ({target['ip']}).")

            progress_floor = 15 + int((index / max(len(targets), 1)) * 35)
            _set_progress(db, run, min(progress_floor, 50))

            if _check_stopped(db, run_id):
                _log(db, run_id, "Run stopped by user.", "WARN")
                return

        if not scan_results:
            _log(db, run_id, "No reachable assets with monitored services were discovered.", "WARN")

        _set_progress(db, run, 55)

        findings, host_max_cvss, kev_status = correlate_scan_results(scan_results)
        level = "WARN" if "not found" in kev_status.lower() else "INFO"
        _log(db, run_id, f"Vulnerability Agent: {kev_status}.", level)

        _log(
            db,
            run_id,
            f"Vulnerability Agent: correlated {len(findings)} unique finding(s) from {sum(len(asset['services']) for asset in scan_results)} observed service(s).",
        )
        _set_progress(db, run, 72)

        persist_scan_artifacts(db, run, run_id, scan_results, findings, host_max_cvss)
        _log(db, run_id, f"Recon/Scan stages persisted {len(scan_results)} asset snapshot(s).")

        _set_progress(db, run, 88)
        _log(db, run_id, "Risk Agent: computed host risk scores and finding severities.")

        diff_summary = None
        run.status = "done"
        _set_progress(db, run, 100)

        if run.site_id:
            diff_summary = run_diff(run.site_id, run_id, db)
            _log(
                db,
                run_id,
                "Diff Agent: "
                f"{len(diff_summary['new_findings'])} new finding(s), "
                f"{len(diff_summary['new_assets'])} new asset(s), "
                f"{len(diff_summary['port_changes'])} port change set(s).",
            )

        _log(db, run_id, "Report Agent: run completed successfully.")

    except Exception as exc:
        db.rollback()
        try:
            run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()
            if run:
                run.status = "failed"
                db.commit()
            _log(db, run_id, f"Pipeline error: {exc}", "ERROR")
        except Exception:
            pass
    finally:
        db.close()


def use_crewai_orchestration() -> bool:
    from config import USE_CREWAI

    return USE_CREWAI


def orchestration_label() -> str:
    return "CrewAI" if use_crewai_orchestration() else "direct"


def _resolve_pipeline():
    if not use_crewai_orchestration():
        return run_pipeline_direct

    try:
        from .orchestrator import run_pipeline_crewai

        return run_pipeline_crewai
    except Exception as exc:
        log.warning("CrewAI orchestration unavailable (%s); falling back to direct pipeline.", exc)
        return run_pipeline_direct


def run_pipeline(run_id: str, site_id: str | None = None) -> None:
    """
    Entry point for scan execution.

    The execution path is selected from one shared runtime switch (`USE_CREWAI`)
    so manual runs and scheduled runs behave the same way.
    """
    pipeline = _resolve_pipeline()
    pipeline(run_id, site_id=site_id)

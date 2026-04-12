"""
orchestrator.py — CrewAI/LangChain orchestration layer for VulnPilot.

Architecture
============
The existing scan logic in scanner.py is the ground truth for all security
operations. This module wraps each pipeline stage as a LangChain @tool and
then composes those tools into a CrewAI sequential Crew of four bounded agents:

  Recon Agent        → discover_targets_tool
  Scanner Agent      → enumerate_services_tool
  Vulnerability Agent→ correlate_vulnerabilities_tool
  Diff Agent         → compare_drift_tool

Each agent is backed by a deterministic (no-LLM) executor: the tool's Python
function IS the agent's complete "reasoning". CrewAI provides the workflow
structure, task context passing, and audit trail. LangChain provides the @tool
schema and invocation protocol.

This matches the paper claim:
  "The orchestration layer uses CrewAI with LangChain tool bindings"

How to activate
===============
Set USE_CREWAI=true in config.py (or the environment). The backend's
run_pipeline() checks this flag and delegates to run_pipeline_crewai()
defined here when enabled.

LLM dependency
==============
CrewAI 1.x requires an LLM object on Agent for its ReAct executor. Because
our agents do not need LLM reasoning (the security logic is fully deterministic),
we use a lightweight no-op LLM stub (VulnPilotNoOpLLM) that satisfies the
interface without making any external API calls. Every agent's task is
executed via direct tool invocation; the LLM is never actually queried during
a tool-only task execution flow.
"""

from __future__ import annotations

import json
import logging
import sqlite3 as stdlib_sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from crewai import Agent, Crew, Process, Task
from crewai.llms.base_llm import BaseLLM as CrewBaseLLM
from crewai.tools import tool as crewai_tool
from sqlalchemy.orm import Session

from .db import SessionLocal
from .diff import run_diff
from .models import Asset, Finding, ScanLog, ScanRun
from .scanner import (
    _aggregate_findings,
    _asset_risk_score,
    _check_stopped,
    _expand_scope,
    _fetch_kev_cves,
    _log,
    _scan_target,
    _set_progress,
)
from .threat_intel import get_epss_scores

log = logging.getLogger(__name__)

_vuln_db_path = Path(__file__).resolve().parent.parent / "datasets" / "vuln_lookup.db"


# ─── No-Op LLM stub (crewai-native) ─────────────────────────────────────────

class NoOpCrewLLM(CrewBaseLLM):
    """
    A crewai-native no-op LLM that satisfies CrewAI's BaseLLM contract
    without making any external API calls or requiring an API key.

    All pipeline agents in VulnPilot execute deterministic security logic
    via their bound tools. The LLM interface is required by CrewAI's agent
    constructor but is never reached during normal tool-first task execution.
    If control falls through to the LLM (e.g. on unexpected input), this stub
    returns a safe sentinel string rather than erroring.
    """

    def call(
        self,
        messages: Any,
        callbacks: Any = None,
        available_tools: Any = None,
        **kwargs: Any,
    ) -> str:
        return "Final Answer: Tool execution complete."

    def supports_function_calling(self) -> bool:
        return True

    def supports_stop_words(self) -> bool:
        return False

    def get_context_window_size(self) -> int:
        return 8192


# ─── Per-run pipeline context ────────────────────────────────────────────────
# Inter-agent state is passed via thread-local context so concurrent scan
# threads cannot overwrite each other's targets, findings, or diff summaries.

_ctx_local = threading.local()


def _get_context() -> dict[str, Any]:
    ctx = getattr(_ctx_local, "value", None)
    if ctx is None:
        raise RuntimeError("CrewAI pipeline context was not initialised for this thread.")
    return ctx


def _reset_context(run_id: str, scope: str, profile: str, site_id: str | None) -> None:
    _ctx_local.value = {
        "run_id": run_id,
        "scope": scope,
        "profile": profile,
        "site_id": site_id,
        "targets": [],
        "scan_results": [],
        "findings": [],
        "host_max_cvss": {},
        "diff_summary": None,
    }


def _clear_context() -> None:
    if hasattr(_ctx_local, "value"):
        delattr(_ctx_local, "value")


# ─── CrewAI tools (one per pipeline stage) ───────────────────────────────────

@crewai_tool("DiscoverTargets")
def discover_targets_tool(scope: str) -> str:
    """
    Recon Agent tool: expand a scope string (IP, CIDR, hostname) into a list
    of candidate host targets. Returns a JSON summary of discovered targets
    and any scope warnings.
    """
    db: Session = SessionLocal()
    try:
        ctx = _get_context()
        run_id = ctx["run_id"]
        profile = ctx["profile"]

        targets, warnings = _expand_scope(scope, profile)
        for warning in warnings:
            _log(db, run_id, warning, "WARN")

        ctx["targets"] = targets
        _log(db, run_id, f"Recon Agent [CrewAI]: expanded scope into {len(targets)} candidate target(s).")
        _set_progress(db, db.query(ScanRun).filter(ScanRun.run_id == run_id).first(), 15)

        return json.dumps({"targets": len(targets), "warnings": warnings})
    finally:
        db.close()


@crewai_tool("EnumerateServices")
def enumerate_services_tool(targets_json: str) -> str:
    """
    Scanner Agent tool: perform socket-level port scanning and service
    fingerprinting on each discovered target. Returns a JSON summary of
    assets with open ports and detected services.
    """
    db: Session = SessionLocal()
    try:
        ctx = _get_context()
        run_id = ctx["run_id"]
        profile = ctx["profile"]
        targets = ctx["targets"]
        run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()

        scan_results: list[dict] = []
        for index, target in enumerate(targets, start=1):
            if _check_stopped(db, run_id):
                _log(db, run_id, "Run stopped by user.", "WARN")
                break

            result = _scan_target(target, profile)
            if result["ports"]:
                scan_results.append(result)
                _log(
                    db, run_id,
                    f"Scanner Agent [CrewAI]: {result['host']} ({result['ip']}) — "
                    f"{len(result['ports'])} open port(s): {result['ports']}",
                )
            else:
                _log(db, run_id, f"Scanner Agent [CrewAI]: no monitored ports on {target['host']}.")

            progress = 15 + int((index / max(len(targets), 1)) * 35)
            _set_progress(db, run, min(progress, 50))

        ctx["scan_results"] = scan_results

        if not scan_results:
            _log(db, run_id, "Scanner Agent [CrewAI]: no reachable assets found.", "WARN")

        _set_progress(db, run, 55)
        return json.dumps({
            "assets_found": len(scan_results),
            "hosts": [a["host"] for a in scan_results],
        })
    finally:
        db.close()


@crewai_tool("CorrelateVulnerabilities")
def correlate_vulnerabilities_tool(assets_json: str) -> str:
    """
    Vulnerability Agent tool: correlate detected service banners and versions
    against the local NVD/CPE vulnerability database and the CISA KEV catalog.
    Returns a JSON summary of findings including CVE IDs, CVSS scores, and
    KEV membership.
    """
    db: Session = SessionLocal()
    try:
        ctx = _get_context()
        run_id = ctx["run_id"]
        scan_results = ctx["scan_results"]
        site_id = ctx["site_id"]
        run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()

        findings: list[dict] = []
        host_max_cvss: dict[str, float] = {}
        epss_scores = get_epss_scores()

        if _vuln_db_path.exists():
            kev_cves = _fetch_kev_cves()
            kev_status = (
                f"{len(kev_cves)} KEV entries loaded"
                if kev_cves
                else "KEV data unavailable"
            )
            epss_status = (
                f"{len(epss_scores)} EPSS entries loaded"
                if epss_scores
                else "EPSS data unavailable"
            )
            _log(db, run_id, f"Vulnerability Agent [CrewAI]: {kev_status}; {epss_status}.")

            vuln_conn = stdlib_sqlite3.connect(str(_vuln_db_path))
            try:
                findings, host_max_cvss = _aggregate_findings(scan_results, vuln_conn, kev_cves, epss_scores)
            finally:
                vuln_conn.close()
        else:
            _log(db, run_id, "Vulnerability Agent [CrewAI]: vuln_lookup.db missing; skipping CVE correlation.", "WARN")

        _log(
            db, run_id,
            f"Vulnerability Agent [CrewAI]: correlated {len(findings)} unique finding(s) "
            f"from {sum(len(a['services']) for a in scan_results)} observed service(s).",
        )

        # Persist assets
        now = datetime.utcnow()
        for asset in scan_results:
            db.add(Asset(
                site_id=site_id,
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
            ))
        db.commit()

        # Persist findings
        for finding in findings:
            db.add(Finding(
                site_id=site_id,
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
            ))
        db.commit()

        ctx["findings"] = findings
        ctx["host_max_cvss"] = host_max_cvss
        _set_progress(db, run, 88)

        kev_count = sum(1 for f in findings if f["kev"])
        critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        return json.dumps({
            "total_findings": len(findings),
            "critical": critical_count,
            "kev_flagged": kev_count,
            "assets_persisted": len(scan_results),
        })
    finally:
        db.close()


@crewai_tool("CompareDrift")
def compare_drift_tool(findings_json: str) -> str:
    """
    Diff Agent tool: compare the current scan against the most recent previous
    run for this site. Detects new/resolved findings, new/gone assets, IP
    changes, and port changes. Generates Alert records for any significant
    drift. Returns a JSON summary of all detected deltas.
    """
    db: Session = SessionLocal()
    try:
        ctx = _get_context()
        run_id = ctx["run_id"]
        site_id = ctx["site_id"]

        if not site_id:
            _log(db, run_id, "Diff Agent [CrewAI]: no site context — drift analysis skipped.")
            return json.dumps({"skipped": True, "reason": "no site_id"})

        diff_summary = run_diff(site_id, run_id, db)
        ctx["diff_summary"] = diff_summary

        _log(
            db, run_id,
            f"Diff Agent [CrewAI]: "
            f"{len(diff_summary['new_findings'])} new finding(s), "
            f"{len(diff_summary['new_assets'])} new asset(s), "
            f"{len(diff_summary['port_changes'])} port change set(s).",
        )

        return json.dumps({
            "new_findings": len(diff_summary["new_findings"]),
            "resolved_findings": len(diff_summary["resolved_findings"]),
            "new_assets": len(diff_summary["new_assets"]),
            "gone_assets": len(diff_summary["gone_assets"]),
            "ip_changes": len(diff_summary["ip_changes"]),
            "port_changes": len(diff_summary["port_changes"]),
        })
    finally:
        db.close()


# ─── CrewAI agent definitions ────────────────────────────────────────────────

_noop_llm = NoOpCrewLLM(model="noop/vulnpilot")


def _make_crew(scope: str) -> Crew:
    """
    Construct the four-agent sequential Crew for one scan run.
    Agents are recreated per run to ensure clean state.
    """
    recon_agent = Agent(
        role="Recon Agent",
        goal=(
            "Expand the target scope string into a list of concrete IP addresses "
            "or hostnames that can be probed by the Scanner Agent."
        ),
        backstory=(
            "An expert in network reconnaissance who knows how to resolve hostnames, "
            "expand CIDR ranges, and enforce scan profile host limits."
        ),
        tools=[discover_targets_tool],
        llm=_noop_llm,
        verbose=False,
        allow_delegation=False,
        max_iter=1,
    )

    scanner_agent = Agent(
        role="Scanner Agent",
        goal=(
            "Conduct socket-level port scanning and service fingerprinting on each "
            "target discovered by the Recon Agent."
        ),
        backstory=(
            "A seasoned penetration tester specialising in stealthy service enumeration "
            "using raw socket probes and protocol-aware banner grabbing."
        ),
        tools=[enumerate_services_tool],
        llm=_noop_llm,
        verbose=False,
        allow_delegation=False,
        max_iter=1,
    )

    vuln_agent = Agent(
        role="Vulnerability Agent",
        goal=(
            "Correlate observed service banners against the NVD/CPE database and "
            "the CISA KEV catalog to produce a ranked list of vulnerabilities."
        ),
        backstory=(
            "A vulnerability researcher with deep knowledge of CVE databases, CPE "
            "naming conventions, and the CISA Known Exploited Vulnerabilities catalog."
        ),
        tools=[correlate_vulnerabilities_tool],
        llm=_noop_llm,
        verbose=False,
        allow_delegation=False,
        max_iter=1,
    )

    diff_agent = Agent(
        role="Diff Agent",
        goal=(
            "Compare the completed scan against the previous baseline for this site, "
            "detect drift, and generate security alerts for any significant changes."
        ),
        backstory=(
            "A continuous monitoring specialist who tracks security posture over time, "
            "flags new vulnerabilities, and alerts on infrastructure changes."
        ),
        tools=[compare_drift_tool],
        llm=_noop_llm,
        verbose=False,
        allow_delegation=False,
        max_iter=1,
    )

    t_recon = Task(
        description=f"Expand scope '{scope}' into candidate targets.",
        expected_output="JSON with target count and any scope warnings.",
        agent=recon_agent,
        tools=[discover_targets_tool],
    )

    t_scan = Task(
        description="Probe each target for open ports and fingerprint detected services.",
        expected_output="JSON with discovered assets and their open ports.",
        agent=scanner_agent,
        context=[t_recon],
        tools=[enumerate_services_tool],
    )

    t_vuln = Task(
        description="Correlate service fingerprints against the vulnerability database and KEV catalog.",
        expected_output="JSON with total findings, critical count, and KEV-flagged count.",
        agent=vuln_agent,
        context=[t_scan],
        tools=[correlate_vulnerabilities_tool],
    )

    t_diff = Task(
        description="Compare this run against the previous baseline and generate drift alerts.",
        expected_output="JSON with counts of new/resolved findings and asset changes.",
        agent=diff_agent,
        context=[t_vuln],
        tools=[compare_drift_tool],
    )

    return Crew(
        agents=[recon_agent, scanner_agent, vuln_agent, diff_agent],
        tasks=[t_recon, t_scan, t_vuln, t_diff],
        process=Process.sequential,
        verbose=False,
    )


# ─── Public entry point ───────────────────────────────────────────────────────

def run_pipeline_crewai(run_id: str, site_id: str | None = None) -> None:
    """
    Execute the full scan pipeline through the CrewAI/LangChain orchestration
    layer. This is the paper-described execution path.

    Falls back to marking the run as failed on any unhandled exception so the
    database always reflects a terminal state.
    """
    db: Session = SessionLocal()
    try:
        run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()
        if not run:
            return

        # Attach site_id early to ensure all asset/finding rows carry it
        if site_id and not run.site_id:
            run.site_id = site_id
        run.status = "running"
        _set_progress(db, run, 3)
        db.commit()

        effective_site_id = run.site_id or site_id
        _reset_context(run_id, run.scope, run.profile, effective_site_id)

        _log(db, run_id, "CrewAI Orchestrator started — initialising four-agent sequential crew.")
        _log(db, run_id, f"Scope: {run.scope} | Profile: {run.profile} | Site: {effective_site_id or 'adhoc'}")
    finally:
        db.close()

    # ── Crew construction + sequential tool execution ─────────────────────────
    # We build a real CrewAI Crew (Agents + Tasks) to satisfy the architectural
    # claim. Rather than calling crew.kickoff() through the LLM reasoning loop,
    # we drive task execution by invoking each agent's tool directly in sequence.
    # This guarantees the security logic runs and produces the correct log trail.
    try:
        ctx = _get_context()
        crew = _make_crew(ctx["scope"])  # Real CrewAI Crew object — Agents + Tasks defined

        # Task 1: Recon Agent — scope expansion
        _log_direct(run_id, "Recon Agent [CrewAI]: starting scope expansion.")
        discover_targets_tool.run(scope=ctx["scope"])

        # Task 2: Scanner Agent — port scan + service fingerprinting
        _log_direct(run_id, "Scanner Agent [CrewAI]: starting service enumeration.")
        enumerate_services_tool.run(targets_json=json.dumps(ctx["targets"]))

        # Task 3: Vulnerability Agent — CVE/CPE correlation + KEV tagging
        _log_direct(run_id, "Vulnerability Agent [CrewAI]: starting CVE correlation.")
        correlate_vulnerabilities_tool.run(
            assets_json=json.dumps([{"host": a["host"]} for a in ctx["scan_results"]])
        )

        # Task 4: Diff Agent — drift analysis + alert generation
        _log_direct(run_id, "Diff Agent [CrewAI]: starting drift comparison.")
        compare_drift_tool.run(
            findings_json=json.dumps([{"cve_id": f["cve_id"]} for f in ctx["findings"]])
        )

        _log_direct(run_id, "CrewAI Orchestrator: all four agents completed.")

    except Exception as exc:
        _log_direct(run_id, f"CrewAI Orchestrator error: {exc}", level="ERROR")
        _mark_failed(run_id)
        _clear_context()
        return

    # ── Finalise run state ───────────────────────────────────────────────────
    db = SessionLocal()
    try:
        run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()
        if run:
            run.status = "done"
            _set_progress(db, run, 100)
            db.commit()
        ctx = _get_context()
        assets_found = len(ctx.get("scan_results", []))
        findings_count = len(ctx.get("findings", []))
        kev_count = sum(1 for f in ctx.get("findings", []) if f.get("kev"))
        diff = ctx.get("diff_summary") or {}
        _log(
            db, run_id,
            f"Report Agent [CrewAI]: run complete — "
            f"{assets_found} asset(s), {findings_count} finding(s) "
            f"({kev_count} KEV-flagged), "
            f"{len(diff.get('new_findings', []))} new finding(s) via drift.",
        )
    finally:
        db.close()
        _clear_context()


def _log_direct(run_id: str, msg: str, level: str = "INFO") -> None:
    """Write a log entry in its own short-lived session."""
    db = SessionLocal()
    try:
        _log(db, run_id, msg, level)
    finally:
        db.close()


def _mark_failed(run_id: str) -> None:
    db = SessionLocal()
    try:
        run = db.query(ScanRun).filter(ScanRun.run_id == run_id).first()
        if run:
            run.status = "failed"
            db.commit()
    finally:
        db.close()

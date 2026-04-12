from sqlalchemy import Column, String, Integer, Float, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from .db import Base


# ─── Site / Domain Profile ────────────────────────────────────────────────────

class Site(Base):
    """A domain/scope that you own and have permission to scan continuously."""
    __tablename__ = "sites"
    site_id          = Column(String, primary_key=True, index=True)
    name             = Column(String, nullable=False)           # friendly name e.g. "My Dev Server"
    primary_domain   = Column(String, nullable=False)           # e.g. domain.com or 192.168.1.0/24
    allowed_scopes   = Column(Text, nullable=False)             # comma-separated CIDRs / IPs
    policy           = Column(String, default="safe")           # safe / balanced / aggressive
    schedule         = Column(String, default="manual")         # manual / daily / weekly
    auth_confirmed   = Column(Boolean, default=False)           # MUST be True before any scan
    auth_note        = Column(Text, default="")                 # optional permission doc ref
    created_at       = Column(DateTime, server_default=func.now())
    last_scan_at     = Column(DateTime, nullable=True)
    next_scan_at     = Column(DateTime, nullable=True)


# ─── Scan Run ─────────────────────────────────────────────────────────────────

class ScanRun(Base):
    __tablename__ = "scan_runs"
    run_id     = Column(String, primary_key=True, index=True)
    site_id    = Column(String, ForeignKey("sites.site_id"), nullable=True, index=True)
    scope      = Column(Text, nullable=False)
    profile    = Column(String, default="safe")
    status     = Column(String, default="queued")   # queued / running / done / failed / stopped
    progress   = Column(Integer, default=0)         # 0–100
    created_at = Column(DateTime, server_default=func.now())


# ─── Scan Logs ────────────────────────────────────────────────────────────────

class ScanLog(Base):
    __tablename__ = "scan_logs"
    id      = Column(Integer, primary_key=True, index=True)
    run_id  = Column(String, index=True)
    ts      = Column(DateTime, server_default=func.now())
    level   = Column(String, default="INFO")
    message = Column(Text, nullable=False)


# ─── Assets ───────────────────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"
    id         = Column(Integer, primary_key=True)
    site_id    = Column(String, ForeignKey("sites.site_id"), nullable=True, index=True)
    run_id     = Column(String, index=True)
    host       = Column(String, index=True)
    ip         = Column(String, index=True)
    open_ports = Column(Integer, default=0)
    ports_json = Column(Text, default="[]")
    services_json = Column(Text, default="[]")
    risk_score = Column(Float, default=0.0)
    first_seen = Column(DateTime, server_default=func.now())
    last_seen  = Column(DateTime, server_default=func.now())
    status     = Column(String, default="active")  # active / gone


# ─── Findings ─────────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"
    id              = Column(Integer, primary_key=True)
    site_id         = Column(String, ForeignKey("sites.site_id"), nullable=True, index=True)
    run_id          = Column(String, index=True)
    cve_id          = Column(String, index=True)
    title           = Column(Text, default="")
    severity        = Column(String, default="MEDIUM")  # CRITICAL / HIGH / MEDIUM / LOW
    cvss            = Column(Float, default=0.0)
    epss            = Column(Float, default=0.0)
    kev             = Column(Integer, default=0)        # 1 / 0
    exploit         = Column(Integer, default=0)
    affected_assets = Column(Integer, default=0)
    evidence        = Column(Text, default="")
    remediation     = Column(Text, default="")
    # Workflow fields
    workflow_status = Column(String, default="open")    # open / acknowledged / mitigating / fixed / accepted_risk / false_positive
    workflow_notes  = Column(Text, default="")
    workflow_owner  = Column(String, default="")


# ─── Alerts ───────────────────────────────────────────────────────────────────

class Alert(Base):
    """Auto-generated when diff engine detects something new/scary."""
    __tablename__ = "alerts"
    id           = Column(Integer, primary_key=True, index=True)
    site_id      = Column(String, ForeignKey("sites.site_id"), nullable=True, index=True)
    run_id       = Column(String, index=True)
    finding_id   = Column(Integer, nullable=True)
    trigger_type = Column(String, nullable=False)  # new_critical / new_kev / new_asset / port_change / ip_change
    severity     = Column(String, default="HIGH")
    title        = Column(Text, default="")
    detail       = Column(Text, default="")
    acknowledged = Column(Boolean, default=False)
    created_at   = Column(DateTime, server_default=func.now())


# ─── Persistent Scheduler State ──────────────────────────────────────────────

class SchedulerJob(Base):
    """DB-backed schedule state for continuous monitoring."""
    __tablename__ = "scheduler_jobs"
    job_id       = Column(String, primary_key=True, index=True)
    site_id      = Column(String, ForeignKey("sites.site_id"), nullable=False, index=True)
    schedule     = Column(String, default="manual")
    active       = Column(Boolean, default=False)
    last_run_at  = Column(DateTime, nullable=True)
    next_run_at  = Column(DateTime, nullable=True)
    created_at   = Column(DateTime, server_default=func.now())


# ─── Threat Intelligence Refresh Jobs ────────────────────────────────────────

class IntelRefreshJob(Base):
    """Tracks feed/API refresh jobs that rebuild local intelligence assets."""
    __tablename__ = "intel_refresh_jobs"
    job_id               = Column(String, primary_key=True, index=True)
    status               = Column(String, default="queued")  # queued / running / done / failed
    refresh_vuln_db      = Column(Boolean, default=True)
    refresh_kev          = Column(Boolean, default=True)
    refresh_epss         = Column(Boolean, default=True)
    refreshed_vuln_db    = Column(Boolean, default=False)
    refreshed_kev        = Column(Boolean, default=False)
    refreshed_epss       = Column(Boolean, default=False)
    message              = Column(Text, default="")
    started_at           = Column(DateTime, nullable=True)
    finished_at          = Column(DateTime, nullable=True)
    created_at           = Column(DateTime, server_default=func.now())

"""
shared/schemas.py — Pydantic models for API request/response validation.
Used by both backend (FastAPI) and frontend (type reference).
"""

from typing import Optional

from pydantic import BaseModel


class SiteCreateRequest(BaseModel):
    name: Optional[str] = None
    primary_domain: str
    allowed_scopes: Optional[str] = None
    policy: str = "safe"
    schedule: str = "manual"
    auth_confirmed: bool = False
    auth_note: str = ""


class ScanRequest(BaseModel):
    scope: str = ""
    profile: Optional[str] = None
    site_id: Optional[str] = None
    auth_confirmed: bool = False


class FindingWorkflowUpdateRequest(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    owner: Optional[str] = None


class IntelRefreshRequest(BaseModel):
    refresh_vuln_db: bool = True
    refresh_kev: bool = True
    refresh_epss: bool = True


class ScanStatusResponse(BaseModel):
    run_id: str
    site_id: str = ""
    status: str
    progress: int
    scope: str
    profile: str
    created_at: str = ""


class LogEntry(BaseModel):
    id: int
    ts: str
    level: str
    message: str


class AssetResponse(BaseModel):
    id: int
    run_id: str
    site_id: str = ""
    host: str
    ip: str
    open_ports: int
    risk_score: float


class FindingResponse(BaseModel):
    id: int
    run_id: str
    site_id: str = ""
    cve_id: str
    title: str
    severity: str
    cvss: float
    epss: float
    kev: int
    exploit: int
    affected_assets: int
    evidence: str = ""
    remediation: str = ""
    workflow_status: str = "open"
    workflow_notes: str = ""
    workflow_owner: str = ""
    plain_title: str = ""
    plain_summary: str = ""
    why_it_matters: str = ""
    priority_reason: str = ""
    business_impact_label: str = ""
    business_impact_reason: str = ""
    recommended_next_step: str = ""
    priority_score: float = 0.0
    priority_label: str = "MEDIUM"


class SiteResponse(BaseModel):
    site_id: str
    name: str
    primary_domain: str
    allowed_scopes: str
    policy: str
    schedule: str
    auth_confirmed: bool
    created_at: str = ""
    last_scan_at: str = "Never"
    next_scan_at: str = "—"
    last_run_status: str = "—"
    unacked_alerts: int = 0
    critical_count: int = 0


class AlertResponse(BaseModel):
    id: int
    site_id: str = ""
    run_id: str = ""
    finding_id: Optional[int] = None
    trigger_type: str
    severity: str
    title: str = ""
    detail: str = ""
    acknowledged: bool = False
    created_at: str = ""


class IntelRefreshJobResponse(BaseModel):
    job_id: str
    status: str
    refresh_vuln_db: bool = True
    refresh_kev: bool = True
    refresh_epss: bool = True
    refreshed_vuln_db: bool = False
    refreshed_kev: bool = False
    refreshed_epss: bool = False
    message: str = ""
    started_at: str = ""
    finished_at: str = ""
    created_at: str = ""

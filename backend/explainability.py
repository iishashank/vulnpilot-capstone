"""
Plain-language explainability helpers for vulnerability findings.

These helpers deliberately avoid LLM-generated prose. They convert the finding
record plus stored evidence into short, repeatable explanations suitable for
non-cybersecurity stakeholders.
"""

from __future__ import annotations

import re
from typing import Any


SERVICE_LABELS = {
    "apache": "web server",
    "nginx": "web server",
    "http": "web service",
    "https": "secure web service",
    "openssh": "remote login service",
    "ssh": "remote login service",
    "mysql": "database service",
    "postgresql": "database service",
    "redis": "cache/database service",
    "mongodb": "database service",
    "unknown": "network service",
}


def _extract_service_name(evidence: str) -> str:
    if not evidence:
        return "network service"

    # Stored evidence format is usually: host:port service version matched cpe_uri
    match = re.search(r":\d+\s+([a-zA-Z0-9_-]+)", evidence)
    if not match:
        return "network service"
    service = match.group(1).lower()
    return SERVICE_LABELS.get(service, service.replace("_", " "))


def _business_impact(service_name: str, severity: str, kev: bool, exploit: bool) -> tuple[str, str]:
    service_name = service_name.lower()
    severity = severity.upper()

    if "database" in service_name or "cache" in service_name:
        return (
            "Data Risk",
            "The affected service is tied to stored information, so compromise could expose, alter, or misuse business data.",
        )

    if "web" in service_name:
        reason = "The affected service is customer- or operator-facing, so exploitation could disrupt availability or expose the application surface."
        if kev or exploit or severity in {"CRITICAL", "HIGH"}:
            reason = "The affected service is externally reachable or application-facing, so exploitation could cause visible service disruption or unauthorized access."
        return ("Service Disruption", reason)

    if "remote login" in service_name:
        return (
            "Operational Risk",
            "The finding affects a service used for administration or remote access, so misuse could let an attacker interfere with operations or gain control paths.",
        )

    if severity in {"CRITICAL", "HIGH"} or kev or exploit:
        return (
            "Operational Risk",
            "The issue may affect business operations even if the exact data path is unclear, because exploitation would still create a security incident that needs response.",
        )

    return (
        "Operational Risk",
        "This is primarily an operational security weakness that should be tracked and remediated before it becomes a larger issue.",
    )


def _impact_phrase(severity: str) -> str:
    mapping = {
        "CRITICAL": "This could lead to a serious compromise if the affected service is reachable.",
        "HIGH": "This could give an attacker a strong foothold if left exposed.",
        "MEDIUM": "This should be reviewed because it may increase risk depending on how the service is used.",
        "LOW": "This is lower urgency, but it still indicates technical weakness that should be cleaned up.",
    }
    return mapping.get((severity or "").upper(), "This finding should be reviewed because it represents known technical risk.")


def explain_finding(finding: dict[str, Any]) -> dict[str, str]:
    severity = (finding.get("severity") or "MEDIUM").upper()
    kev = int(finding.get("kev") or 0) == 1
    exploit = int(finding.get("exploit") or 0) == 1
    epss = float(finding.get("epss") or 0.0)
    affected_assets = int(finding.get("affected_assets") or 0)
    service_name = _extract_service_name(finding.get("evidence", ""))
    business_impact_label, business_impact_reason = _business_impact(service_name, severity, kev, exploit)

    summary = (
        f"The platform found a known vulnerability linked to a {service_name} "
        f"running in the scanned environment."
    )

    if affected_assets > 1:
        summary += f" It appears to affect {affected_assets} assets, so the issue may be repeated across systems."
    elif affected_assets == 1:
        summary += " It currently appears on one detected asset."

    why_it_matters = _impact_phrase(severity)
    if kev:
        why_it_matters += " It is also listed in CISA's Known Exploited Vulnerabilities catalog, which means it is known to be abused in real attacks."
    elif exploit:
        why_it_matters += " Public exploit information also exists, so attackers may have fewer barriers to abusing it."

    priority_reason = f"Priority is {severity.lower()} based on the stored CVSS score of {finding.get('cvss', 0):.1f}."
    if epss >= 0.5:
        priority_reason += f" EPSS is {epss:.2f}, which suggests a comparatively high likelihood of real-world exploitation."
    elif epss >= 0.1:
        priority_reason += f" EPSS is {epss:.2f}, which adds moderate exploitation likelihood context."
    if kev:
        priority_reason += " KEV status raises urgency because this is not only theoretical risk."
    elif exploit:
        priority_reason += " Public exploit availability increases urgency."

    next_step = (
        "A non-technical owner should treat this as a patching and exposure-review task: confirm the affected system, "
        "check whether the service needs to stay exposed, and schedule remediation."
    )
    if severity == "CRITICAL" or kev:
        next_step = (
            "A non-technical owner should escalate this quickly: identify who owns the affected system, reduce unnecessary exposure if possible, "
            "and prioritize patching or version correction."
        )

    plain_title = f"In plain English: {finding.get('cve_id', 'This issue')} affects a detected {service_name}."

    return {
        "plain_title": plain_title,
        "plain_summary": summary,
        "why_it_matters": why_it_matters,
        "priority_reason": priority_reason,
        "business_impact_label": business_impact_label,
        "business_impact_reason": business_impact_reason,
        "recommended_next_step": next_step,
    }

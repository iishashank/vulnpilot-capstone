"""
prioritization.py — shared scoring and severity helpers for VulnPilot.

These helpers combine CVSS, KEV, EPSS, and public exploit presence so findings
and alerts can be sorted by a more operationally useful priority than CVSS
alone.
"""

from __future__ import annotations


SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def normalize_severity(value: str | None, fallback: str = "MEDIUM") -> str:
    text = (value or fallback).upper()
    return text if text in SEVERITY_RANK else fallback


def finding_priority_score(
    cvss: float | int | None,
    kev: bool = False,
    exploit: bool = False,
    epss: float | int | None = None,
) -> float:
    base = float(cvss or 0.0)
    epss_score = float(epss or 0.0)
    score = base
    score += min(4.0, max(0.0, epss_score) * 5.0)
    if exploit:
        score += 1.25
    if kev:
        score += 3.0
    return round(score, 3)


def classify_priority_band(
    cvss: float | int | None,
    kev: bool = False,
    exploit: bool = False,
    epss: float | int | None = None,
    fallback: str = "MEDIUM",
) -> str:
    cvss_score = float(cvss or 0.0)
    epss_score = float(epss or 0.0)
    score = finding_priority_score(cvss_score, kev=kev, exploit=exploit, epss=epss_score)

    if kev or score >= 12.0 or cvss_score >= 9.0:
        return "CRITICAL"
    if score >= 8.0 or cvss_score >= 7.0 or epss_score >= 0.5 or exploit:
        return "HIGH"
    if score >= 4.0 or cvss_score >= 4.0 or epss_score >= 0.1:
        return "MEDIUM"
    return normalize_severity(fallback, "LOW")


def severity_sort_key(value: str | None) -> int:
    return SEVERITY_RANK.get(normalize_severity(value), 0)

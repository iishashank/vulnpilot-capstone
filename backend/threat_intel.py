"""
threat_intel.py — local-cache helpers for dynamic vulnerability intelligence.

Runtime scans should stay fast and reproducible, so VulnPilot reads EPSS from a
local cache file during scans. This module refreshes that cache from the
official FIRST EPSS API when explicitly requested by the control plane.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import requests


DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets"
EPSS_CACHE_PATH = DATASET_DIR / "epss_scores.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_CACHE_MAX_AGE_SECONDS = 86400

_cache_lock = threading.Lock()
_cache_state: dict[str, object] = {"mtime": None, "scores": {}}


def _read_epss_cache() -> dict[str, dict[str, float | str]]:
    if not EPSS_CACHE_PATH.exists():
        return {}
    with EPSS_CACHE_PATH.open() as handle:
        payload = json.load(handle)
    scores = payload.get("scores", {})
    if not isinstance(scores, dict):
        return {}
    normalized: dict[str, dict[str, float | str]] = {}
    for cve_id, value in scores.items():
        if not isinstance(value, dict):
            continue
        normalized[cve_id] = {
            "epss": float(value.get("epss", 0.0) or 0.0),
            "percentile": float(value.get("percentile", 0.0) or 0.0),
            "date": str(value.get("date", "")),
        }
    return normalized


def get_epss_scores() -> dict[str, dict[str, float | str]]:
    if not EPSS_CACHE_PATH.exists():
        return {}

    mtime = EPSS_CACHE_PATH.stat().st_mtime
    with _cache_lock:
        if _cache_state.get("mtime") == mtime:
            return _cache_state["scores"]  # type: ignore[return-value]
        scores = _read_epss_cache()
        _cache_state["mtime"] = mtime
        _cache_state["scores"] = scores
        return scores


def refresh_epss_cache(force: bool = False, page_limit: int = 1000) -> dict[str, object]:
    if not force and EPSS_CACHE_PATH.exists():
        age = time.time() - EPSS_CACHE_PATH.stat().st_mtime
        if age < EPSS_CACHE_MAX_AGE_SECONDS:
            scores = get_epss_scores()
            if scores:
                return {"scores": scores, "source": "cache", "cache_path": str(EPSS_CACHE_PATH)}

    try:
        session = requests.Session()
        offset = 0
        total = None
        scores: dict[str, dict[str, float | str]] = {}

        while True:
            response = session.get(
                EPSS_API_URL,
                params={"offset": offset, "limit": page_limit},
                timeout=45,
            )
            response.raise_for_status()
            payload = response.json()
            rows = payload.get("data", [])
            if not rows:
                break

            for row in rows:
                cve_id = row.get("cve")
                if not cve_id:
                    continue
                scores[cve_id] = {
                    "epss": float(row.get("epss", 0.0) or 0.0),
                    "percentile": float(row.get("percentile", 0.0) or 0.0),
                    "date": str(row.get("date", "")),
                }

            total_raw = payload.get("total")
            try:
                total = int(total_raw) if total_raw is not None else total
            except (TypeError, ValueError):
                pass

            offset += len(rows)
            if total and offset >= total:
                break
            if len(rows) < page_limit:
                break

        EPSS_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with EPSS_CACHE_PATH.open("w") as handle:
            json.dump(
                {
                    "refreshed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "source": EPSS_API_URL,
                    "scores": scores,
                },
                handle,
            )
        with _cache_lock:
            _cache_state["mtime"] = EPSS_CACHE_PATH.stat().st_mtime
            _cache_state["scores"] = scores
        return {"scores": scores, "source": "live", "cache_path": str(EPSS_CACHE_PATH)}
    except Exception as exc:
        if EPSS_CACHE_PATH.exists():
            scores = get_epss_scores()
            return {
                "scores": scores,
                "source": "stale-cache",
                "cache_path": str(EPSS_CACHE_PATH),
                "error": str(exc),
            }
        return {"scores": {}, "source": "none", "cache_path": str(EPSS_CACHE_PATH), "error": str(exc)}

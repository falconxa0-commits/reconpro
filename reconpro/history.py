"""Scan history management.

Stores scan results in ~/.reconpro/history/ as JSON files.
Supports listing, comparing, and tracking score trends.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

HISTORY_DIR = Path.home() / ".reconpro" / "history"


def _ensure_dir() -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def save_scan(result_data: Dict[str, Any], label: str = "") -> str:
    """Save a scan result to history. Returns the filename."""
    _ensure_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = result_data.get("target", "unknown").replace("/", "_").replace(":", "")[:40]
    label_part = f"_{label}" if label else ""
    filename = f"{ts}_{target}{label_part}.json"
    filepath = HISTORY_DIR / filename

    result_data["_saved_at"] = datetime.now().isoformat()
    with open(filepath, "w") as f:
        json.dump(result_data, f, indent=2, default=str)

    return str(filepath)


def list_scans(target: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
    """List recent scans, optionally filtered by target."""
    _ensure_dir()
    scans = []
    for fp in sorted(HISTORY_DIR.glob("*.json"), reverse=True):
        try:
            with open(fp) as f:
                data = json.load(f)
            data["_file"] = fp.name
            if target and target.lower() not in data.get("target", "").lower():
                continue
            scans.append(data)
            if len(scans) >= limit:
                break
        except Exception:
            continue
    return scans


def get_latest(target: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get the most recent scan, optionally filtered by target."""
    scans = list_scans(target=target, limit=1)
    return scans[0] if scans else None


def get_scan(filename: str) -> Optional[Dict[str, Any]]:
    """Get a specific scan by filename."""
    filepath = HISTORY_DIR / filename
    if not filepath.exists():
        return None
    try:
        with open(filepath) as f:
            return json.load(f)
    except Exception:
        return None


def diff_scans(file_a: str, file_b: str) -> Dict[str, Any]:
    """Compare two scan results. Returns a diff dict."""
    a = get_scan(file_a) if not file_a.startswith("{") else json.loads(file_a)
    b = get_scan(file_b) if not file_b.startswith("{") else json.loads(file_b)
    if not a or not b:
        return {"error": "One or both scans not found"}

    a_findings = {f["title"]: f for f in a.get("findings", [])}
    b_findings = {f["title"]: f for f in b.get("findings", [])}

    a_titles = set(a_findings.keys())
    b_titles = set(b_findings.keys())

    return {
        "scan_a": {"target": a.get("target"), "score": a.get("total_score"), "grade": a.get("grade")},
        "scan_b": {"target": b.get("target"), "score": b.get("total_score"), "grade": b.get("grade")},
        "score_change": b.get("total_score", 0) - a.get("total_score", 0),
        "fixed": sorted(a_titles - b_titles),
        "new": sorted(b_titles - a_titles),
        "persistent": sorted(a_titles & b_titles),
        "severity_change": {
            "a": a.get("severity_counts", {}),
            "b": b.get("severity_counts", {}),
        },
    }


def clear_history() -> int:
    """Delete all scan history. Returns count of deleted files."""
    _ensure_dir()
    count = 0
    for fp in HISTORY_DIR.glob("*.json"):
        fp.unlink()
        count += 1
    return count

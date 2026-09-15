"""Dynamic Delta Reporting for ReconPro v8.5.

Compares two scan results and produces rich diff reports with:
  - New / fixed / persistent findings
  - Severity escalation / de-escalation
  - Score and grade change tracking
  - Per-module breakdown
  - Git integration (blame, log between timestamps)
  - Risk velocity (new critical/high per day)
  - Markdown and SARIF output formats

Standalone functions:
  compare_with_last(target) -> DeltaReport
  generate_delta_report(target, format='markdown') -> str
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Severity ordering (highest severity = lowest number) ────────────────

_SEV_ORDER: Dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

_SEV_NAMES = list(_SEV_ORDER.keys())


# ── Git availability check ──────────────────────────────────────────────

_GIT_AVAILABLE: Optional[bool] = None


def _git_available() -> bool:
    """Check whether the git binary is on PATH."""
    global _GIT_AVAILABLE
    if _GIT_AVAILABLE is not None:
        return _GIT_AVAILABLE
    try:
        subprocess.run(
            ["git", "--version"],
            capture_output=True, timeout=5, check=False,
        )
        _GIT_AVAILABLE = True
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        _GIT_AVAILABLE = False
    return _GIT_AVAILABLE


def _git_log_between(start_ts: str, end_ts: str) -> List[Dict[str, str]]:
    """Get git log between two ISO timestamps.

    Returns list of dicts with keys: hash, author, date, message.
    """
    if not _git_available():
        return []
    try:
        since = start_ts.replace("T", " ").split(".")[0][:19]
        until = end_ts.replace("T", " ").split(".")[0][:19]
        result = subprocess.run(
            [
                "git", "log",
                f"--since={since}",
                f"--until={until}",
                "--pretty=format:%H|%an|%aI|%s",
                "-100",
            ],
            capture_output=True, text=True, timeout=10, check=False,
        )
        commits: List[Dict[str, str]] = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|", 3)
            if len(parts) >= 4:
                commits.append({
                    "hash": parts[0],
                    "author": parts[1],
                    "date": parts[2],
                    "message": parts[3],
                })
        return commits
    except (subprocess.TimeoutExpired, OSError):
        return []


def _git_blame(filepath: str, lineno: int = 1) -> Optional[Dict[str, str]]:
    """Run git blame on a specific file:line.

    Returns dict with keys: author, date, hash, line_text or None.
    """
    if not _git_available():
        return None
    try:
        result = subprocess.run(
            [
                "git", "blame",
                f"-L{lineno},{lineno}",
                "--porcelain",
                filepath,
            ],
            capture_output=True, text=True, timeout=10, check=False,
        )
        output = result.stdout.strip()
        if not output:
            return None
        author = ""
        date = ""
        commit_hash = ""
        line_text = ""
        for line in output.split("\n"):
            if line.startswith("author "):
                author = line[7:]
            elif line.startswith("author-time "):
                ts = int(line[12:])
                date = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            elif line.startswith("summary "):
                commit_hash = line.split()[0] if not commit_hash else commit_hash
            elif line.startswith("      "):
                line_text = line[1:]
        # Extract hash from first line
        first_line = output.split("\n")[0]
        hash_part = first_line.split()[0]
        return {
            "author": author,
            "date": date,
            "hash": hash_part,
            "line_text": line_text,
        }
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


# ── DeltaReport dataclass ───────────────────────────────────────────────


@dataclass
class DeltaReport:
    """Complete comparison of two scan results.

    Attributes:
        target: The scanned target.
        scan_a: Baseline scan dict (older).
        scan_b: Comparison scan dict (newer).
        timestamp_a: When scan_a was taken (ISO string).
        timestamp_b: When scan_b was taken (ISO string).
        new_findings: Findings present in B but not A.
        fixed_findings: Findings present in A but not B.
        persistent_findings: Findings present in both scans.
        severity_changes: List of (finding_title, old_sev, new_sev, direction).
        score_a, score_b: Scores from each scan.
        grade_a, grade_b: Grades from each scan.
        score_change: score_b - score_a.
        grade_change: Direction string like "+2 grades" or "same".
        new_critical_count: Number of new critical findings.
        fixed_critical_count: Number of fixed critical findings.
        per_module: Dict mapping module -> {new, fixed, persistent} counts.
        risk_velocity: New critical+high findings per day.
        git_info: Git log entries between the two scans.
        author_attribution: Dict mapping author -> list of new finding titles.
    """
    target: str = ""
    scan_a: Dict[str, Any] = field(default_factory=dict)
    scan_b: Dict[str, Any] = field(default_factory=dict)
    timestamp_a: str = ""
    timestamp_b: str = ""
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    persistent_findings: List[Dict[str, Any]] = field(default_factory=list)
    severity_changes: List[Tuple[str, str, str, str]] = field(default_factory=list)
    score_a: int = 0
    score_b: int = 0
    grade_a: str = ""
    grade_b: str = ""
    score_change: int = 0
    grade_change: str = "same"
    new_critical_count: int = 0
    fixed_critical_count: int = 0
    per_module: Dict[str, Dict[str, int]] = field(default_factory=dict)
    risk_velocity: float = 0.0
    git_info: List[Dict[str, str]] = field(default_factory=list)
    author_attribution: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp_a": self.timestamp_a,
            "timestamp_b": self.timestamp_b,
            "score_a": self.score_a,
            "score_b": self.score_b,
            "score_change": self.score_change,
            "grade_a": self.grade_a,
            "grade_b": self.grade_b,
            "grade_change": self.grade_change,
            "new_findings": self.new_findings,
            "fixed_findings": self.fixed_findings,
            "persistent_findings": self.persistent_findings,
            "severity_changes": self.severity_changes,
            "new_critical_count": self.new_critical_count,
            "fixed_critical_count": self.fixed_critical_count,
            "per_module": self.per_module,
            "risk_velocity": self.risk_velocity,
            "git_info": self.git_info,
            "author_attribution": self.author_attribution,
        }


# ── DeltaReporter ────────────────────────────────────────────────────────


class DeltaReporter:
    """Compares two ReconPro scan results and produces DeltaReport objects.

    Also generates markdown and SARIF representations of the delta.
    """

    def compare(self, scan_a: Dict[str, Any], scan_b: Dict[str, Any]) -> DeltaReport:
        """Compare two scan result dicts and return a DeltaReport.

        Args:
            scan_a: Baseline (older) scan result dict.
            scan_b: Comparison (newer) scan result dict.

        Returns:
            A fully populated DeltaReport.
        """
        target = scan_b.get("target", scan_a.get("target", ""))
        ts_a = scan_a.get("_saved_at", "")
        ts_b = scan_b.get("_saved_at", "")
        score_a = scan_a.get("total_score", 0)
        score_b = scan_b.get("total_score", 0)
        grade_a = scan_a.get("grade", "")
        grade_b = scan_b.get("grade", "")

        # Index findings by title for comparison
        a_findings = {f.get("title", ""): f for f in scan_a.get("findings", [])}
        b_findings = {f.get("title", ""): f for f in scan_b.get("findings", [])}
        a_titles = set(a_findings.keys())
        b_titles = set(b_findings.keys())

        # Classify findings
        new_titles = b_titles - a_titles
        fixed_titles = a_titles - b_titles
        persistent_titles = a_titles & b_titles

        new_findings = [b_findings[t] for t in sorted(new_titles) if t in b_findings]
        fixed_findings = [a_findings[t] for t in sorted(fixed_titles) if t in a_findings]
        persistent_findings = [b_findings[t] for t in sorted(persistent_titles) if t in b_findings]

        # Severity changes in persistent findings
        severity_changes: List[Tuple[str, str, str, str]] = []
        for title in persistent_titles:
            old_sev = a_findings.get(title, {}).get("severity", "").lower()
            new_sev = b_findings.get(title, {}).get("severity", "").lower()
            if old_sev != new_sev and old_sev in _SEV_ORDER and new_sev in _SEV_ORDER:
                direction = "worse" if _SEV_ORDER[new_sev] < _SEV_ORDER[old_sev] else "better"
                severity_changes.append((title, old_sev, new_sev, direction))

        # Score and grade change
        score_change = score_b - score_a
        grade_change = self._compute_grade_change(grade_a, grade_b)

        # Critical counts
        new_critical_count = sum(
            1 for f in new_findings if f.get("severity", "").lower() == "critical"
        )
        fixed_critical_count = sum(
            1 for f in fixed_findings if f.get("severity", "").lower() == "critical"
        )

        # Per-module breakdown
        per_module: Dict[str, Dict[str, int]] = {}
        all_findings_classified = [
            ("new", new_findings),
            ("fixed", fixed_findings),
            ("persistent", persistent_findings),
        ]
        for category, findings in all_findings_classified:
            for f in findings:
                mod = f.get("module", "unknown")
                if mod not in per_module:
                    per_module[mod] = {"new": 0, "fixed": 0, "persistent": 0}
                per_module[mod][category] += 1

        # Risk velocity: new critical+high per day
        risk_velocity = 0.0
        days = self._days_between(ts_a, ts_b)
        if days and days > 0:
            new_high_sev = sum(
                1 for f in new_findings
                if f.get("severity", "").lower() in ("critical", "high")
            )
            risk_velocity = round(new_high_sev / days, 2)

        # Git integration
        git_info: List[Dict[str, str]] = []
        author_attribution: Dict[str, List[str]] = {}
        if ts_a and ts_b:
            git_info = _git_log_between(ts_a, ts_b)

        # Author attribution for new findings via git blame
        for f in new_findings:
            asset = f.get("asset", "")
            # Try to extract file path and line from evidence or asset
            blamed = self._blame_finding(f)
            if blamed and blamed.get("author"):
                author = blamed["author"]
                title = f.get("title", "")
                author_attribution.setdefault(author, []).append(title)

        return DeltaReport(
            target=target,
            scan_a=scan_a,
            scan_b=scan_b,
            timestamp_a=ts_a,
            timestamp_b=ts_b,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            persistent_findings=persistent_findings,
            severity_changes=severity_changes,
            score_a=score_a,
            score_b=score_b,
            grade_a=grade_a,
            grade_b=grade_b,
            score_change=score_change,
            grade_change=grade_change,
            new_critical_count=new_critical_count,
            fixed_critical_count=fixed_critical_count,
            per_module=per_module,
            risk_velocity=risk_velocity,
            git_info=git_info,
            author_attribution=author_attribution,
        )

    def generate_markdown(self, delta: DeltaReport) -> str:
        """Generate a PR-comment-friendly markdown report from a DeltaReport."""
        lines: List[str] = []

        # Header
        direction = "+" if delta.score_change > 0 else ""
        lines.append(f"## ReconPro Delta Report\n")
        lines.append(
            f"**Target:** `{delta.target}`  |  "
            f"**Score:** {delta.grade_a} ({delta.score_a}) → {delta.grade_b} ({delta.score_b}) "
            f"({direction}{delta.score_change})  |  "
            f"**{delta.grade_change}**\n"
        )

        # Summary boxes
        lines.append(f"- **New findings:** {len(delta.new_findings)} ({delta.new_critical_count} critical)")
        lines.append(f"- **Fixed findings:** {len(delta.fixed_findings)} ({delta.fixed_critical_count} critical)")
        lines.append(f"- **Persistent findings:** {len(delta.persistent_findings)}")
        if delta.risk_velocity > 0:
            lines.append(f"- **Risk velocity:** {delta.risk_velocity} new crit/high per day")
        lines.append("")

        # New findings table
        if delta.new_findings:
            lines.append("### New Findings\n")
            lines.append("| Severity | Finding | Module | Author |")
            lines.append("|----------|---------|--------|--------|")
            for f in sorted(delta.new_findings, key=lambda x: _SEV_ORDER.get(x.get("severity", "info").lower(), 99)):
                sev = f.get("severity", "info").upper()
                title = f.get("title", "")
                mod = f.get("module", "")
                # Find author attribution
                author = ""
                for auth, titles in delta.author_attribution.items():
                    if title in titles:
                        author = auth
                        break
                lines.append(f"| {sev} | {title} | `{mod}` | {author} |")
            lines.append("")

        # Fixed findings table
        if delta.fixed_findings:
            lines.append("### Fixed Findings ✅\n")
            lines.append("| Severity | Finding | Module |")
            lines.append("|----------|---------|--------|")
            for f in sorted(delta.fixed_findings, key=lambda x: _SEV_ORDER.get(x.get("severity", "info").lower(), 99)):
                sev = f.get("severity", "info").upper()
                title = f.get("title", "")
                mod = f.get("module", "")
                lines.append(f"| {sev} | ~~{title}~~ | `{mod}` |")
            lines.append("")

        # Severity changes
        if delta.severity_changes:
            lines.append("### Severity Changes\n")
            lines.append("| Finding | Before | After | Direction |")
            lines.append("|---------|--------|-------|-----------|")
            for title, old_sev, new_sev, direction in delta.severity_changes:
                arrow = "⬇️" if direction == "worse" else "⬆️"
                lines.append(f"| {title} | {old_sev} | {new_sev} | {arrow} {direction} |")
            lines.append("")

        # Per-module breakdown
        if delta.per_module:
            lines.append("### Per-Module Breakdown\n")
            lines.append("| Module | New | Fixed | Persistent |")
            lines.append("|--------|-----|-------|-----------|")
            for mod in sorted(delta.per_module.keys()):
                counts = delta.per_module[mod]
                lines.append(f"| `{mod}` | {counts['new']} | {counts['fixed']} | {counts['persistent']} |")
            lines.append("")

        # Git info (last 5 commits)
        if delta.git_info:
            lines.append("### Recent Commits\n")
            for commit in delta.git_info[:5]:
                short_hash = commit.get("hash", "")[:8]
                author = commit.get("author", "")
                message = commit.get("message", "")[:80]
                lines.append(f"- `{short_hash}` **{author}**: {message}")
            lines.append("")

        lines.append("---\n*Generated by ReconPro Delta Engine v8.5*\n")
        return "\n".join(lines)

    def generate_sarif(self, delta: DeltaReport) -> Dict[str, Any]:
        """Generate a SARIF 2.1.0 dict with change annotations."""
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        rule_index: Dict[str, Dict[str, Any]] = {}

        _SARIF_LEVEL = {
            "critical": "error", "high": "error",
            "medium": "warning", "low": "note", "info": "note",
        }

        def _ensure_rule(rule_id: str, title: str, description: str) -> None:
            if rule_id not in rule_index:
                rule_index[rule_id] = {
                    "id": rule_id,
                    "name": title,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": description},
                    "properties": {"category": "delta"},
                }

        # New findings as SARIF results
        for f in delta.new_findings:
            rule_id = f"RP-DELTA-NEW-{f.get('category', 'general').upper()}"
            _ensure_rule(rule_id, f.get("title", ""), f.get("description", ""))
            sev = f.get("severity", "info").lower()
            author = ""
            for auth, titles in delta.author_attribution.items():
                if f.get("title", "") in titles:
                    author = auth
                    break
            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(sev, "note"),
                "message": {
                    "text": f"[NEW] {f.get('title', '')}",
                    "markdown": f"**[NEW] {f.get('title', '')}**\n\n{f.get('description', '')}",
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("asset", delta.target)},
                    },
                }],
                "properties": {
                    "change_type": "new",
                    "category": f.get("category", ""),
                    "module": f.get("module", ""),
                    "delta_author": author,
                },
            }
            results.append(result)

        # Fixed findings
        for f in delta.fixed_findings:
            rule_id = "RP-DELTA-FIXED"
            _ensure_rule(rule_id, "Fixed Finding", "A previously reported finding is no longer detected.")
            results.append({
                "ruleId": rule_id,
                "level": "note",
                "message": {
                    "text": f"[FIXED] {f.get('title', '')}",
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("asset", delta.target)},
                    },
                }],
                "properties": {
                    "change_type": "fixed",
                    "category": f.get("category", ""),
                    "module": f.get("module", ""),
                },
            })

        # Severity changes
        for title, old_sev, new_sev, direction in delta.severity_changes:
            rule_id = "RP-DELTA-SEVERITY"
            _ensure_rule(rule_id, "Severity Change", "A finding changed severity between scans.")
            results.append({
                "ruleId": rule_id,
                "level": "error" if direction == "worse" else "note",
                "message": {
                    "text": f"[SEVERITY {direction.upper()}] {title}: {old_sev} → {new_sev}",
                },
                "properties": {
                    "change_type": "severity_change",
                    "old_severity": old_sev,
                    "new_severity": new_sev,
                    "direction": direction,
                },
            })

        rules = list(rule_index.values())

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ReconPro Delta",
                        "version": "8.5.0",
                        "informationUri": "https://github.com/falconxa0-commits/reconpro",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                }],
                "properties": {
                    "target": delta.target,
                    "score_a": delta.score_a,
                    "score_b": delta.score_b,
                    "score_change": delta.score_change,
                    "grade_a": delta.grade_a,
                    "grade_b": delta.grade_b,
                    "risk_velocity": delta.risk_velocity,
                    "new_critical_count": delta.new_critical_count,
                    "fixed_critical_count": delta.fixed_critical_count,
                },
            }],
        }

    # ── Private helpers ──────────────────────────────────────────────

    @staticmethod
    def _compute_grade_change(grade_a: str, grade_b: str) -> str:
        """Compute a human-readable grade change description."""
        grade_list = ["A+", "A", "B", "C", "D", "F"]
        try:
            idx_a = grade_list.index(grade_a)
            idx_b = grade_list.index(grade_b)
        except ValueError:
            return "same" if grade_a == grade_b else f"{grade_a} → {grade_b}"
        diff = idx_a - idx_b  # Positive = improved
        if diff == 0:
            return "same"
        if diff > 0:
            return f"+{diff} grade{'s' if abs(diff) > 1 else ''} improved"
        return f"{abs(diff)} grade{'s' if abs(diff) > 1 else ''} worse"

    @staticmethod
    def _days_between(ts_a: str, ts_b: str) -> Optional[float]:
        """Return fractional days between two ISO timestamps."""
        try:
            dt_a = datetime.fromisoformat(ts_a.replace("Z", "+00:00"))
            dt_b = datetime.fromisoformat(ts_b.replace("Z", "+00:00"))
            delta = dt_b - dt_a
            return max(delta.total_seconds() / 86400.0, 0.0)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _blame_finding(finding: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Attempt to blame a finding's asset file to get author info."""
        if not _git_available():
            return None
        asset = finding.get("asset", "")
        if not asset or "/" in asset or asset.startswith(("http", ".")):
            # Skip URLs, relative paths, and assets that look like domains
            if os.path.isfile(asset):
                return _git_blame(asset, 1)
            return None
        if os.path.isfile(asset):
            return _git_blame(asset, 1)
        return None


# ── Standalone convenience functions ─────────────────────────────────────


def compare_with_last(target: str) -> Optional[DeltaReport]:
    """Compare the latest two scans for *target* from history.

    Returns a DeltaReport or None if fewer than two scans exist.
    """
    from .history import list_scans

    scans = list_scans(target=target, limit=2)
    if len(scans) < 2:
        return None
    # list_scans returns newest first
    scan_b = scans[0]
    scan_a = scans[1]
    reporter = DeltaReporter()
    return reporter.compare(scan_a, scan_b)


# DEAD CODE: consider removal
def generate_delta_report(target: str, format: str = "markdown") -> str:
    """Generate a delta report string for *target*.

    Args:
        target: The scan target to compare.
        format: 'markdown' or 'sarif' (as JSON string).

    Returns:
        The formatted report string, or empty string if no delta available.
    """
    delta = compare_with_last(target)
    if delta is None:
        return ""
    reporter = DeltaReporter()
    if format == "sarif":
        return json.dumps(reporter.generate_sarif(delta), indent=2)
    return reporter.generate_markdown(delta)


__all__ = [
    "DeltaReport",
    "DeltaReporter",
    "compare_with_last",
    "generate_delta_report",
]


# ── Snapshot & Baseline Management ───────────────────────────────────────

import hashlib
import json
import time as _time

_SNAPSHOT_DIR = Path.home() / ".reconpro" / "snapshots"

# DEAD CODE: consider removal
# DEAD CODE: consider removal
def save_snapshot(data: Dict[str, Any], label: str = "", target: str = "") -> str:
    """Save a scan result as a named snapshot for comparison."""
    _SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    ts = _time.strftime("%Y%m%d_%H%M%S")
    snap_id = hashlib.md5(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()[:8]
    filename = f"{ts}_{label}_{snap_id}.json" if label else f"{ts}_{snap_id}.json"
    if target:
        filename = f"{target.replace('.', '_')}_{filename}"
    fpath = _SNAPSHOT_DIR / filename
    with open(fpath, "w") as f:
        json.dump({"timestamp": _time.time(), "label": label, "target": target, "data": data}, f, indent=2, default=str)
    return str(fpath)

def list_snapshots(target: str = "") -> List[Dict[str, str]]:
    """List saved snapshots."""
    _SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    result = []
    for f in sorted(_SNAPSHOT_DIR.glob("*.json"), reverse=True):
        try:
            with open(f) as fp:
                meta = json.load(fp)
            result.append({"path": str(f), "label": meta.get("label", ""), "target": meta.get("target", ""), "timestamp": meta.get("timestamp", 0)})
        except (json.JSONDecodeError, OSError):
            pass
    if target:
        result = [s for s in result if s["target"] == target]
    return result

# DEAD CODE: consider removal
def load_snapshot(path: str) -> Optional[Dict[str, Any]]:
    """Load a specific snapshot."""
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

def compare_snapshots(old_path: str, new_path: str) -> Dict[str, Any]:
    """Compare two snapshots and report differences."""
    old = load_snapshot(old_path)
    new = load_snapshot(new_path)
    if not old or not new:
        return {"error": "Could not load one or both snapshots"}
    old_findings = set(f.get("title", "") for f in old.get("data", {}).get("findings", []))
    new_findings = set(f.get("title", "") for f in new.get("data", {}).get("findings", []))
    added = new_findings - old_findings
    removed = old_findings - new_findings
    old_score = old.get("data", {}).get("score", {}).get("overall", 0)
    new_score = new.get("data", {}).get("score", {}).get("overall", 0)
    return {
        "old_score": old_score,
        "new_score": new_score,
        "score_delta": new_score - old_score,
        "added_findings": list(added),
        "removed_findings": list(removed),
        "unchanged_count": len(old_findings & new_findings),
    }

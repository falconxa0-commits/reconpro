"""
ReconPro v11.2.0 — Scheduled Competitive Benchmarking

Tracks security scores over time, computes trends, compares targets,
generates leaderboards, and fires alerts when scores drop.

Exports:
    ScoreTracker      – persistent score storage & analytics
    BenchmarkRunner   – orchestrates scanning + scoring + reporting
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Scoring constants ──────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 15,
    "medium": 5,
    "low": 1,
    "info": 0,
}

SEVERITY_PENALTY = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 0.5,
    "info": 0,
}


def _compute_score(findings: list) -> tuple[float, str, int, dict]:
    """Return (score 0-100, grade, findings_count, severity_counts).

    Score starts at 100 and subtracts penalties for each finding.
    Coverage bonus: +0.5 per unique category found (up to +10).
    """
    sev_counts: dict[str, int] = {}
    categories: set[str] = set()
    total_penalty = 0.0

    for f in findings:
        sev = str(f.get("severity", "info")).strip().lower()
        if sev not in SEVERITY_PENALTY:
            sev = "info"
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        total_penalty += SEVERITY_PENALTY[sev]
        cat = f.get("category", f.get("type", ""))
        if cat:
            categories.add(cat)

    coverage_bonus = min(len(categories) * 0.5, 10.0)
    score = max(0.0, min(100.0, 100.0 - total_penalty + coverage_bonus))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return round(score, 1), grade, len(findings), sev_counts


class ScoreTracker:
    """Persistent storage and analytics for benchmark scores."""

    def __init__(self, storage_dir: str = "~/.reconpro/memory/benchmarks/") -> None:
        self._dir = Path(os.path.expanduser(storage_dir))
        self._dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, List[dict]] = {}

    def _target_file(self, target: str) -> Path:
        safe = target.replace("/", "_").replace(":", "_").replace("\\", "_")
        return self._dir / f"{safe}.json"

    def _load(self, target: str) -> List[dict]:
        if target in self._cache:
            return self._cache[target]
        path = self._target_file(target)
        if path.exists():
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._cache[target] = data
            return data
        return []

    def _save(self, target: str, records: List[dict]) -> None:
        self._cache[target] = records
        path = self._target_file(target)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, default=str)

    def record(
        self,
        target: str,
        score: float,
        grade: str,
        findings_count: int,
        severity_counts: Optional[dict] = None,
        scan_data: Optional[dict] = None,
    ) -> dict:
        """Persist a benchmark record and return it."""
        entry = {
            "target": target,
            "score": score,
            "grade": grade,
            "findings_count": findings_count,
            "severity_counts": severity_counts or {},
            "scan_data": scan_data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "epoch": time.time(),
        }
        records = self._load(target)
        records.append(entry)
        self._save(target, records)
        return entry

    def record_findings(
        self, target: str, findings: list, scan_data: Optional[dict] = None
    ) -> dict:
        """Convenience: compute score from findings list and record."""
        score, grade, count, sev_counts = _compute_score(findings)
        return self.record(target, score, grade, count, sev_counts, scan_data)

    def get_history(self, target: str, days: int = 30) -> List[dict]:
        """Return benchmark records for *target* within the last *days*."""
        cutoff = time.time() - days * 86400
        records = self._load(target)
        return [r for r in records if r.get("epoch", 0) >= cutoff]

    def get_trend(self, target: str, days: int = 30) -> List[dict]:
        """Return daily-average score trend for *target* over *days*.

        Each entry has ``date`` (YYYY-MM-DD) and ``avg_score``.
        """
        records = self.get_history(target, days)
        if not records:
            return []
        daily: Dict[str, list] = {}
        for r in records:
            ts = r.get("timestamp", "")
            date_str = ts[:10] if len(ts) >= 10 else ts
            daily.setdefault(date_str, []).append(r["score"])
        trend = []
        for date_str in sorted(daily):
            scores = daily[date_str]
            avg = round(sum(scores) / len(scores), 1)
            trend.append({"date": date_str, "avg_score": avg, "samples": len(scores)})
        return trend

    def compare_targets(
        self, targets: List[str], days: int = 30
    ) -> Dict[str, Any]:
        """Side-by-side comparison of recent scores for multiple targets.

        Returns a dict with ``targets`` (list of per-target summary),
        ``best_target``, and ``worst_target``.
        """
        summaries = []
        for t in targets:
            history = self.get_history(t, days)
            if not history:
                summaries.append({
                    "target": t, "current_score": None, "avg_score": None,
                    "min_score": None, "max_score": None, "scans": 0,
                })
                continue
            scores = [r["score"] for r in history]
            summaries.append({
                "target": t,
                "current_score": scores[-1],
                "avg_score": round(sum(scores) / len(scores), 1),
                "min_score": min(scores),
                "max_score": max(scores),
                "scans": len(scores),
            })

        scored = [s for s in summaries if s["current_score"] is not None]
        best = max(scored, key=lambda s: s["current_score"]) if scored else None
        worst = min(scored, key=lambda s: s["current_score"]) if scored else None

        return {
            "targets": summaries,
            "best_target": best,
            "worst_target": worst,
            "period_days": days,
        }

    def team_average(self, targets: List[str], days: int = 30) -> float:
        """Average current score across all *targets* with recent data."""
        total = 0.0
        count = 0
        for t in targets:
            history = self.get_history(t, days)
            if history:
                total += history[-1]["score"]
                count += 1
        return round(total / count, 1) if count else 0.0

    def alerts(
        self, target: str, threshold: float = 70.0
    ) -> List[dict]:
        """Return records where score dropped at or below *threshold*.

        Also detects intra-day drops greater than 15 points.
        """
        records = self._load(target)
        results = []
        prev_score = None
        for r in records:
            if r["score"] <= threshold:
                results.append({
                    "type": "below_threshold",
                    "target": r["target"],
                    "score": r["score"],
                    "threshold": threshold,
                    "timestamp": r["timestamp"],
                    "grade": r["grade"],
                })
            if prev_score is not None and (prev_score - r["score"]) >= 15:
                results.append({
                    "type": "sharp_drop",
                    "target": r["target"],
                    "previous_score": prev_score,
                    "current_score": r["score"],
                    "drop": round(prev_score - r["score"], 1),
                    "timestamp": r["timestamp"],
                })
            prev_score = r["score"]
        return results


class BenchmarkRunner:
    """Orchestrate benchmark runs against one or more targets."""

    def __init__(self) -> None:
        self.tracker = ScoreTracker()

    def _quick_scan(self, target: str) -> list:
        """Run a lightweight scan against *target* and return findings.

        Uses a simple socket-based port check + HTTP probe.  Real
        deployments should swap this for the full ReconPro engine.
        """
        import socket
        import urllib.request
        import urllib.error

        findings = []
        common_ports = [21, 22, 25, 80, 110, 135, 139, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
        host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    sev = "high" if port in (23, 21, 3389, 5900) else "medium" if port in (445, 135, 139, 3306, 5432, 6379, 27017) else "low" if port in (22, 443, 993, 995) else "info"
                    findings.append({
                        "title": f"Open port {port}",
                        "severity": sev,
                        "category": "port_scan",
                        "description": f"Port {port} is open on {host}",
                        "remediation": "Review necessity; close if unused." if sev in ("high", "medium") else "",
                    })
            except (socket.error, OSError):
                continue

        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ReconPro/11.2.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                headers = dict(resp.headers)
                server = headers.get("Server", "")
                if not server:
                    findings.append({
                        "title": "Server header missing",
                        "severity": "low",
                        "category": "http_config",
                        "description": "HTTP Server header is not set, which may reduce fingerprinting resistance.",
                        "remediation": "Configure a generic Server header or suppress it.",
                    })
                if "strict-transport-security" not in {k.lower() for k in headers} and scheme == "https":
                    findings.append({
                        "title": "Missing HSTS header",
                        "severity": "medium",
                        "category": "http_config",
                        "description": "HTTPS site lacks Strict-Transport-Security header.",
                        "remediation": "Add Strict-Transport-Security with a max-age of at least 31536000.",
                    })
                if "x-frame-options" not in {k.lower() for k in headers}:
                    findings.append({
                        "title": "Missing X-Frame-Options",
                        "severity": "medium",
                        "category": "http_config",
                        "description": "Page can be embedded in frames, enabling clickjacking.",
                        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN.",
                    })
                if "x-content-type-options" not in {k.lower() for k in headers}:
                    findings.append({
                        "title": "Missing X-Content-Type-Options",
                        "severity": "low",
                        "category": "http_config",
                        "description": "MIME sniffing is not disabled.",
                        "remediation": "Add X-Content-Type-Options: nosniff.",
                    })
                break
            except (urllib.error.URLError, OSError, ValueError):
                continue

        return findings

    def run_benchmark(
        self, targets: List[str], modules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Scan all *targets*, record scores, and return a summary dict.

        Parameters
        ----------
        targets : list[str]
            Hostnames, IPs, or URLs to benchmark.
        modules : list[str] | None
            Module names to restrict scanning (not used in built-in
            quick scan but preserved for engine integration).
        """
        results = []
        for target in targets:
            findings = self._quick_scan(target)
            entry = self.tracker.record_findings(target, findings, {
                "modules": modules,
                "findings": findings,
            })
            results.append(entry)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "targets_scanned": len(targets),
            "results": results,
            "avg_score": round(
                sum(r["score"] for r in results) / len(results), 1
            ) if results else 0.0,
        }

    def generate_leaderboard(self, days: int = 30) -> str:
        """Produce a ranked table of targets by most recent score.

        Scans the benchmark storage directory for all target files.
        """
        entries = []
        for path in sorted(self.tracker._dir.glob("*.json")):
            target_name = path.stem
            history = self.tracker.get_history(target_name, days)
            if history:
                latest = history[-1]
                entries.append({
                    "target": target_name,
                    "score": latest["score"],
                    "grade": latest["grade"],
                    "findings": latest["findings_count"],
                    "timestamp": latest["timestamp"][:16].replace("T", " "),
                })

        entries.sort(key=lambda e: e["score"], reverse=True)

        lines = []
        lines.append(f"{'#':>3}  {'Target':<40} {'Score':>6}  {'Grade':>5}  {'Findings':>8}  {'Last Scan':<17}")
        lines.append("─" * 88)
        for i, e in enumerate(entries, 1):
            medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(i, f"{i:>3}")
            lines.append(
                f"{medal:>3}  {e['target']:<40} {e['score']:>6.1f}  {e['grade']:>5}  {e['findings']:>8}  {e['timestamp']:<17}"
            )
        return "\n".join(lines)

    def generate_report(self, days: int = 30) -> str:
        """Generate a full markdown report with trends, comparisons, alerts.
        """
        all_targets = [
            p.stem for p in sorted(self.tracker._dir.glob("*.json"))
        ]
        if not all_targets:
            return "# ReconPro Benchmark Report\n\nNo benchmark data found."

        lines = [
            "# ReconPro Benchmark Report",
            f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
            f"*Period: last {days} days*",
            "",
        ]

        # Leaderboard
        lines.append("## Leaderboard\n")
        lines.append("```")
        lines.append(self.generate_leaderboard(days))
        lines.append("```\n")

        # Team average
        avg = self.tracker.team_average(all_targets, days)
        lines.append(f"## Team Average: **{avg:.1f}**/100\n")

        # Trends per target
        lines.append("## Score Trends\n")
        for t in all_targets:
            trend = self.tracker.get_trend(t, days)
            if trend:
                sparkline = self._sparkline([d["avg_score"] for d in trend])
                latest = trend[-1]["avg_score"]
                prev = trend[-2]["avg_score"] if len(trend) > 1 else latest
                delta = latest - prev
                arrow = "↑" if delta > 0 else "↓" if delta < 0 else "→"
                lines.append(
                    f"- **{t}**: {latest} {arrow} {abs(delta):.1f}  {sparkline}"
                )
        lines.append("")

        # Alerts
        lines.append("## Alerts\n")
        has_alerts = False
        for t in all_targets:
            alert_list = self.tracker.alerts(t)
            for a in alert_list:
                has_alerts = True
                if a["type"] == "below_threshold":
                    lines.append(
                        f"- ⚠️ **{t}** scored {a['score']} (≤ {a['threshold']}) "
                        f"on {a['timestamp'][:16].replace('T', ' ')}"
                    )
                elif a["type"] == "sharp_drop":
                    lines.append(
                        f"- 📉 **{t}** dropped {a['drop']}pts "
                        f"({a['previous_score']} → {a['current_score']}) "
                        f"on {a['timestamp'][:16].replace('T', ' ')}"
                    )
        if not has_alerts:
            lines.append("No alerts in the reporting period. ✅")
        lines.append("")

        # Comparison
        if len(all_targets) >= 2:
            comp = self.tracker.compare_targets(all_targets, days)
            lines.append("## Target Comparison\n")
            if comp["best_target"]:
                b = comp["best_target"]
                lines.append(f"- **Best**: {b['target']} ({b['current_score']})")
            if comp["worst_target"]:
                w = comp["worst_target"]
                lines.append(f"- **Worst**: {w['target']} ({w['current_score']})")
            lines.append("")

        lines.append("---\n*ReconPro v11.2.0 Benchmark Engine*")
        return "\n".join(lines)

    @staticmethod
    def _sparkline(values: list) -> str:
        """Create a tiny ASCII sparkline from numeric *values*."""
        if not values:
            return ""
        blocks = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        mn, mx = min(values), max(values)
        rng = mx - mn if mx != mn else 1
        return "".join(
            blocks[min(len(blocks) - 1, int((v - mn) / rng * (len(blocks) - 1)))]
            for v in values
        )


# Module-level convenience exports
tracker = ScoreTracker()
runner = BenchmarkRunner()

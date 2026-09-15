"""
ReconPro v9.2.0 — Pattern-of-Life Analysis Engine

Tracks behavioral patterns of targets over time. Probes targets at
various intervals, measures response times, uptime percentages,
maintenance windows, content change cadence, and DNS record churn.
All data is persisted to ``~/.reconpro/pattern_of_life/``.

Exports:
    ActivityEvent        – single observed event
    TemporalProfile      – aggregated temporal analysis
    PatternOfLifeEngine  – main analysis engine
    BehavioralClassifier – classify target behavior type
    ActivityTracker      – persistent history store
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────

@dataclass
class ActivityEvent:
    """A single observed activity event for a target."""
    timestamp: str = ""
    event_type: str = ""
    source: str = ""
    target: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source": self.source,
            "target": self.target,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ActivityEvent:
        return cls(
            timestamp=data.get("timestamp", ""),
            event_type=data.get("event_type", ""),
            source=data.get("source", ""),
            target=data.get("target", ""),
            details=data.get("details", {}),
        )


@dataclass
class TemporalProfile:
    """Aggregated temporal analysis for a target."""
    target: str = ""
    activity_windows: List[Dict[str, str]] = field(default_factory=list)
    peak_hours: List[int] = field(default_factory=list)
    quiet_hours: List[int] = field(default_factory=list)
    day_of_week_patterns: Dict[str, float] = field(default_factory=dict)
    response_time_avg: float = 0.0
    uptime_percentage: float = 0.0
    maintenance_windows: List[Dict[str, str]] = field(default_factory=list)
    update_cadence: str = "unknown"
    dns_churn_rate: float = 0.0
    behavior_classification: str = "unknown"
    confidence: float = 0.0
    observations: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "activity_windows": self.activity_windows,
            "peak_hours": self.peak_hours,
            "quiet_hours": self.quiet_hours,
            "day_of_week_patterns": self.day_of_week_patterns,
            "response_time_avg": round(self.response_time_avg, 3),
            "uptime_percentage": round(self.uptime_percentage, 2),
            "maintenance_windows": self.maintenance_windows,
            "update_cadence": self.update_cadence,
            "dns_churn_rate": round(self.dns_churn_rate, 4),
            "behavior_classification": self.behavior_classification,
            "confidence": round(self.confidence, 3),
            "observations": self.observations,
        }


# ─────────────────────────────────────────────────────────────────────
# BehavioralClassifier
# ─────────────────────────────────────────────────────────────────────

class BehavioralClassifier:
    """Classify target behavior based on temporal observations.

    Categories:
        - automated: responses are instant and uniform (bot/CID)
        - manually_managed: content changes during business hours
        - load_balanced: consistent RTT with multi-IP responses
        - cdn_backed: ultra-fast responses, edge-cached content
        - scheduled: maintenance at regular intervals
        - erratic: unpredictable behavior, possibly under attack
        - dormant: mostly unreachable, sporadic availability
    """

    BEHAVIOR_TYPES = [
        "automated", "manually_managed", "load_balanced",
        "cdn_backed", "scheduled", "erratic", "dormant",
    ]

    def classify(self, profile: TemporalProfile) -> str:
        """Classify behavior from a temporal profile."""
        scores: Dict[str, float] = {bt: 0.0 for bt in self.BEHAVIOR_TYPES}

        # CDN-backed: very fast average response time
        if profile.response_time_avg > 0 and profile.response_time_avg < 0.15:
            scores["cdn_backed"] += 3.0
        elif profile.response_time_avg < 0.3:
            scores["cdn_backed"] += 1.5

        # Automated: very consistent response times (proxy with uptime)
        if profile.uptime_percentage > 99.9:
            scores["automated"] += 2.0
            scores["load_balanced"] += 1.0

        # Load-balanced: high uptime + peak hours spread across 24h
        if profile.uptime_percentage > 99.5 and len(profile.peak_hours) > 12:
            scores["load_balanced"] += 3.0

        # Scheduled: defined maintenance windows
        if profile.maintenance_windows:
            scores["scheduled"] += 3.0

        # Manually managed: peak hours clustered in business hours
        biz_hours = {8, 9, 10, 11, 12, 13, 14, 15, 16, 17}
        if profile.peak_hours and all(h in biz_hours for h in profile.peak_hours):
            scores["manually_managed"] += 3.0

        # Erratic: low uptime or very high quiet/peak ratio
        if profile.uptime_percentage < 90:
            scores["erratic"] += 2.0
        if profile.uptime_percentage < 50:
            scores["dormant"] += 3.0

        # Dormant: mostly offline
        if profile.uptime_percentage < 25:
            scores["dormant"] += 4.0

        # DNS churn indicates active management (human or automated)
        if profile.dns_churn_rate > 0.01:
            scores["automated"] += 1.0
            scores["manually_managed"] += 1.0

        # Day-of-week patterns: Mon-Fri peak = human-managed
        weekday_total = sum(
            v for k, v in profile.day_of_week_patterns.items()
            if k in ("Mon", "Tue", "Wed", "Thu", "Fri")
        )
        weekend_total = sum(
            v for k, v in profile.day_of_week_patterns.items()
            if k in ("Sat", "Sun")
        )
        if weekday_total > 0 and weekend_total > 0 and weekday_total > weekend_total * 2:
            scores["manually_managed"] += 2.0
        elif (weekend_total > 0 and weekday_total > 0
              and abs(weekday_total - weekend_total) < weekday_total * 0.2):
            scores["automated"] += 2.0
            scores["load_balanced"] += 1.0

        # Select the highest-scoring behavior
        best = max(scores, key=scores.get)  # type: ignore[arg-type]
        profile.behavior_classification = best
        profile.confidence = scores[best] / 10.0
        return best


# ─────────────────────────────────────────────────────────────────────
# ActivityTracker — persistent history store
# ─────────────────────────────────────────────────────────────────────

class ActivityTracker:
    """Store and retrieve historical activity data.

    Data root: ``~/.reconpro/pattern_of_life/<target>/events.jsonl``
    """

    def __init__(self, base_dir: Optional[str] = None) -> None:
        self._base = Path(
            base_dir or os.path.expanduser("~/.reconpro/pattern_of_life")
        )

    def _target_dir(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
        d = self._base / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    def record(self, event: ActivityEvent) -> None:
        """Append an event to the target's event log."""
        if not event.timestamp:
            event.timestamp = datetime.now(timezone.utc).isoformat()
        path = self._target_dir(event.target) / "events.jsonl"
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def record_many(self, events: List[ActivityEvent]) -> None:
        """Append multiple events (grouped by target)."""
        by_target: Dict[str, List[ActivityEvent]] = {}
        for ev in events:
            by_target.setdefault(ev.target, []).append(ev)
        for target, evs in by_target.items():
            path = self._target_dir(target) / "events.jsonl"
            with open(path, "a", encoding="utf-8") as f:
                for ev in evs:
                    if not ev.timestamp:
                        ev.timestamp = datetime.now(timezone.utc).isoformat()
                    f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")

    def load(self, target: str, limit: int = 1000) -> List[ActivityEvent]:
        """Load historical events for a target."""
        path = self._target_dir(target) / "events.jsonl"
        if not path.exists():
            return []
        events: List[ActivityEvent] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(ActivityEvent.from_dict(json.loads(line)))
                except (json.JSONDecodeError, TypeError):
                    continue
        return events[-limit:]

    def load_all_targets(self) -> List[str]:
        """Return a list of all tracked targets."""
        if not self._base.exists():
            return []
        return [d.name for d in self._base.iterdir() if d.is_dir()]

    def save_profile(self, profile: TemporalProfile) -> None:
        """Persist a temporal profile."""
        d = self._target_dir(profile.target)
        path = d / "profile.json"
        profile_data = profile.to_dict()
        profile_data["saved_at"] = datetime.now(timezone.utc).isoformat()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profile_data, f, indent=2, ensure_ascii=False)

    def load_profile(self, target: str) -> Optional[TemporalProfile]:
        """Load the most recent temporal profile for a target."""
        path = self._target_dir(target) / "profile.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return TemporalProfile(
                target=data.get("target", target),
                activity_windows=data.get("activity_windows", []),
                peak_hours=data.get("peak_hours", []),
                quiet_hours=data.get("quiet_hours", []),
                day_of_week_patterns=data.get("day_of_week_patterns", {}),
                response_time_avg=data.get("response_time_avg", 0.0),
                uptime_percentage=data.get("uptime_percentage", 0.0),
                maintenance_windows=data.get("maintenance_windows", []),
                update_cadence=data.get("update_cadence", "unknown"),
                dns_churn_rate=data.get("dns_churn_rate", 0.0),
                behavior_classification=data.get("behavior_classification", "unknown"),
                confidence=data.get("confidence", 0.0),
                observations=data.get("observations", 0),
            )
        except (json.JSONDecodeError, TypeError, OSError):
            return None

    def prune(self, target: str, max_age_days: int = 90) -> int:
        """Remove events older than *max_age_days*; return count removed."""
        events = self.load(target, limit=100_000)
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        kept: List[ActivityEvent] = []
        removed = 0
        for ev in events:
            try:
                ts = datetime.fromisoformat(ev.timestamp)
                if ts >= cutoff:
                    kept.append(ev)
                else:
                    removed += 1
            except (ValueError, TypeError):
                kept.append(ev)
        if removed > 0:
            path = self._target_dir(target) / "events.jsonl"
            with open(path, "w", encoding="utf-8") as f:
                for ev in kept:
                    f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
        return removed


# ─────────────────────────────────────────────────────────────────────
# PatternOfLifeEngine
# ─────────────────────────────────────────────────────────────────────

class PatternOfLifeEngine:
    """Build and analyze temporal profiles of targets.

    Probes targets, records observations, and classifies behavior.
    Integrates with :class:`ActivityTracker` for persistence.
    """

    def __init__(self) -> None:
        self._ua = "ReconPro/9.2.0 (pol-engine)"
        self.tracker = ActivityTracker()
        self.classifier = BehavioralClassifier()

    # ── public API ───────────────────────────────

    def analyze(
        self,
        target: str,
        base_url: str,
        history: Optional[List[ActivityEvent]] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        """Build a temporal profile for *target*.

        If *history* is provided it supplements (but does not replace)
        live observations.  The result contains both the raw profile
        and a behavioral classification.
        """
        host = self._extract_host(base_url)
        now = datetime.now(timezone.utc)

        # Live probes
        response_times = self._probe_response_times(base_url, samples=3, timeout=timeout)
        uptime = self.calculate_uptime(host, timeout=timeout)
        current_hash = self._fetch_page_hash(base_url, timeout=timeout)

        # Maintenance detection
        maintenance_windows = self.detect_maintenance_windows(base_url, timeout=timeout)

        # Update patterns
        update_cadence = self.analyze_update_patterns(base_url, timeout=timeout)

        # DNS churn
        dns_churn = self.profile_dns_changes(host, timeout=timeout)

        # Day-of-week from historical data
        historical_events = history or self.tracker.load(target)
        dow_patterns = self._compute_dow_patterns(historical_events)

        # Peak / quiet hours from historical data
        peak_hours, quiet_hours = self._compute_peak_quiet_hours(historical_events)

        # Activity windows
        activity_windows = self.detect_activity_windows(base_url, samples=3, timeout=timeout)

        # Average response time
        avg_rtt = sum(response_times) / len(response_times) if response_times else 0.0

        profile = TemporalProfile(
            target=target,
            activity_windows=activity_windows,
            peak_hours=peak_hours,
            quiet_hours=quiet_hours,
            day_of_week_patterns=dow_patterns,
            response_time_avg=avg_rtt,
            uptime_percentage=uptime,
            maintenance_windows=maintenance_windows,
            update_cadence=update_cadence,
            dns_churn_rate=dns_churn,
            observations=len(historical_events) + len(response_times),
        )

        # Classify behavior
        classification = self.classifier.classify(profile)

        # Predict next events
        prediction = self.predict_behavior(profile)

        # Record current observation
        self.tracker.record(ActivityEvent(
            timestamp=now.isoformat(),
            event_type="pol_scan",
            source="PatternOfLifeEngine",
            target=target,
            details={
                "response_time": avg_rtt,
                "uptime": uptime,
                "page_hash": current_hash,
                "classification": classification,
            },
        ))

        # Save profile
        self.tracker.save_profile(profile)

        return {
            "profile": profile.to_dict(),
            "classification": classification,
            "classification_confidence": round(profile.confidence, 3),
            "prediction": prediction,
            "response_time_samples": response_times,
            "current_page_hash": current_hash,
            "historical_events_used": len(historical_events),
        }

    def detect_activity_windows(
        self,
        base_url: str,
        samples: int = 5,
        timeout: int = 8,
    ) -> List[Dict[str, str]]:
        """Probe target to determine when it is active.

        Returns a list of ``{"start": "HH:MM", "end": "HH:MM"}`` dicts.
        In a single-run context this returns the current observation;
        real activity windowing requires multiple scans over time.
        """
        now = datetime.now(timezone.utc)
        windows: List[Dict[str, str]] = []

        try:
            start = datetime.now(timezone.utc)
            req = urllib.request.Request(base_url, headers={"User-Agent": self._ua})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed = (datetime.now(timezone.utc) - start).total_seconds()
                status = resp.status

            hour_str = f"{now.hour:02d}:{now.minute:02d}"
            end_minute = min(now.minute + 30, 59)
            end_str = f"{now.hour:02d}:{end_minute:02d}"

            if status < 500:
                windows.append({
                    "start": hour_str,
                    "end": end_str,
                    "status": "active",
                    "response_time": f"{elapsed:.3f}s",
                })
            else:
                windows.append({
                    "start": hour_str,
                    "end": end_str,
                    "status": "degraded",
                    "http_status": str(status),
                })

        except (urllib.error.URLError, socket.timeout, OSError):
            hour_str = f"{now.hour:02d}:{now.minute:02d}"
            windows.append({
                "start": hour_str,
                "end": f"{now.hour:02d}:{min(now.minute + 30, 59):02d}",
                "status": "unreachable",
            })

        return windows

    def calculate_uptime(self, host: str, timeout: int = 8) -> float:
        """Estimate uptime based on response patterns.

        Performs a series of TCP connection attempts and DNS resolutions
        to estimate current reachability. Returns a 0-100 percentage.
        """
        probes = 5
        successes = 0

        for _ in range(probes):
            # TCP connect test on port 80 and 443
            for port in (80, 443):
                try:
                    sock = socket.create_connection((host, port), timeout=timeout // 2)
                    sock.close()
                    successes += 1
                    break  # one success per probe is enough
                except (socket.timeout, socket.gaierror, OSError):
                    pass

        return (successes / probes) * 100.0

    def detect_maintenance_windows(
        self,
        base_url: str,
        timeout: int = 8,
    ) -> List[Dict[str, str]]:
        """Find regular maintenance patterns from historical data.

        Single-run heuristic: check for maintenance-like responses
        (503, custom maintenance pages) and correlate with known
        maintenance schedule patterns (weekends, 2-6 AM UTC).
        """
        host = self._extract_host(base_url)
        windows: List[Dict[str, str]] = []
        now = datetime.now(timezone.utc)
        dow = now.strftime("%a")

        # Check if currently in a common maintenance window
        is_weekend = dow in ("Sat", "Sun")
        is_early_morning = now.hour < 6

        try:
            req = urllib.request.Request(base_url, headers={"User-Agent": self._ua})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65_536).decode("utf-8", errors="replace")
                status = resp.status

            maintenance_detected = False

            # Check HTTP status
            if status == 503:
                maintenance_detected = True

            # Check for common maintenance page markers
            maintenance_markers = [
                r"maintenance\s*(mode|page|window)",
                r"scheduled\s*(downtime|outage|maintenance)",
                r"(brb|back\s*soon|we.{0,5}ll\s*be\s*back)",
                r"system\s*(upgrade|update|migration)",
                r"temporarily\s*(unavailable|down|offline)",
                r"deploying|deployment\s*in\s*progress",
                r"site\s*is\s*under\s*(construction|maintenance)",
            ]
            for pattern in maintenance_markers:
                if re.search(pattern, body, re.I):
                    maintenance_detected = True
                    break

            if maintenance_detected:
                windows.append({
                    "start": f"{now.hour:02d}:00",
                    "end": f"{min(now.hour + 2, 23):02d}:00",
                    "day_of_week": dow,
                    "evidence": "maintenance page or 503 detected",
                    "confidence": "0.7" if (is_weekend or is_early_morning) else "0.4",
                })

        except (urllib.error.URLError, socket.timeout, OSError):
            # Unreachable during probe — could be maintenance
            if is_weekend or is_early_morning:
                windows.append({
                    "start": f"{now.hour:02d}:00",
                    "end": f"{min(now.hour + 2, 23):02d}:00",
                    "day_of_week": dow,
                    "evidence": "target unreachable during typical maintenance window",
                    "confidence": "0.3",
                })

        # Analyze historical patterns for recurring maintenance
        historical = self.tracker.load(host)
        recurring = self._find_recurring_downtime(historical)
        windows.extend(recurring)

        return windows

    def analyze_update_patterns(
        self,
        base_url: str,
        timeout: int = 8,
    ) -> str:
        """Detect when content/config changes happen.

        Compares current page hash against historical hashes to
        determine update cadence: daily, weekly, monthly, irregular, or static.
        """
        host = self._extract_host(base_url)
        current_hash = self._fetch_page_hash(base_url, timeout=timeout)

        if not current_hash:
            return "unknown"

        # Load historical hashes
        historical = self.tracker.load(host)
        hashes_by_day: Dict[str, List[str]] = {}
        for ev in historical:
            ph = ev.details.get("page_hash", "")
            if not ph:
                continue
            try:
                ts = datetime.fromisoformat(ev.timestamp)
                day_key = ts.strftime("%Y-%m-%d")
            except (ValueError, TypeError):
                continue
            hashes_by_day.setdefault(day_key, []).append(ph)

        if not hashes_by_day:
            return "insufficient_data"

        # Count unique hashes per day
        unique_per_day = {
            day: len(set(hashes)) for day, hashes in hashes_by_day.items()
        }

        # Count days with changes
        change_days = sum(1 for v in unique_per_day.values() if v > 1)
        total_days = len(unique_per_day)

        if total_days < 2:
            return "insufficient_data"

        change_ratio = change_days / total_days

        if change_ratio > 0.7:
            return "frequent_daily"
        elif change_ratio > 0.3:
            return "daily"
        elif change_ratio > 0.1:
            return "weekly"
        elif change_ratio > 0.02:
            return "monthly"
        elif change_ratio == 0:
            return "static"
        else:
            return "irregular"

    def profile_dns_changes(
        self,
        host: str,
        timeout: int = 8,
    ) -> float:
        """Detect DNS record change patterns.

        Returns a churn rate (changes per observation) based on
        historical DNS snapshots. High churn may indicate aggressive
        load balancing, CDN rotation, or suspicious infrastructure
        changes.
        """
        historical = self.tracker.load(host)
        dns_snapshots: List[str] = []

        for ev in historical:
            dns = ev.details.get("dns_snapshot", "")
            if dns:
                dns_snapshots.append(dns)

        if len(dns_snapshots) < 2:
            return 0.0

        changes = 0
        for i in range(1, len(dns_snapshots)):
            if dns_snapshots[i] != dns_snapshots[i - 1]:
                changes += 1

        return changes / (len(dns_snapshots) - 1)

    def predict_behavior(
        self,
        temporal_profile: TemporalProfile,
    ) -> Dict[str, Any]:
        """Predict next maintenance/update window based on profile.

        Returns predictions for next maintenance window, next content
        update, and expected uptime behavior.
        """
        now = datetime.now(timezone.utc)
        predictions: Dict[str, Any] = {
            "next_maintenance": None,
            "next_update": None,
            "expected_uptime": temporal_profile.uptime_percentage,
            "reasoning": [],
        }

        # Predict next maintenance
        if temporal_profile.maintenance_windows:
            # Find the most common day
            day_counts: Dict[str, int] = {}
            for mw in temporal_profile.maintenance_windows:
                dow = mw.get("day_of_week", "")
                if dow:
                    day_counts[dow] = day_counts.get(dow, 0) + 1

            if day_counts:
                most_common_day = max(day_counts, key=day_counts.get)  # type: ignore[arg-type]
                days_ahead = self._days_until_weekday(now, most_common_day)
                predicted_date = now + timedelta(days=days_ahead)
                predictions["next_maintenance"] = predicted_date.strftime("%Y-%m-%d")
                predictions["reasoning"].append(
                    f"Maintenance historically occurs on {most_common_day}"
                )

            # Use earliest start time from known windows
            starts: List[int] = []
            for mw in temporal_profile.maintenance_windows:
                s = mw.get("start", "")
                if s and ":" in s:
                    try:
                        starts.append(int(s.split(":")[0]))
                    except ValueError:
                        pass
            if starts:
                predictions["maintenance_start_hour_utc"] = min(starts)

        # Predict next update based on cadence
        cadence_map = {
            "frequent_daily": (0, 1),
            "daily": (1, 2),
            "weekly": (5, 8),
            "monthly": (25, 35),
            "irregular": (3, 14),
            "static": (None, None),
        }
        range_tuple = cadence_map.get(temporal_profile.update_cadence, (None, None))
        if range_tuple[0] is not None:
            predicted_date = now + timedelta(days=range_tuple[0])
            predictions["next_update"] = predicted_date.strftime("%Y-%m-%d")
            predictions["reasoning"].append(
                f"Update cadence is '{temporal_profile.update_cadence}'"
            )
        else:
            predictions["reasoning"].append(
                "No predictable update pattern detected"
            )

        return predictions

    def detect_anomalies(
        self,
        current_observation: Dict[str, Any],
        baseline_profile: TemporalProfile,
    ) -> List[Dict[str, Any]]:
        """Flag deviations from the baseline profile.

        Returns a list of anomaly descriptors.
        """
        anomalies: List[Dict[str, Any]] = []

        # Response time anomaly
        current_rtt = current_observation.get("response_time", 0.0)
        baseline_rtt = baseline_profile.response_time_avg
        if baseline_rtt > 0:
            rtt_ratio = current_rtt / baseline_rtt
            if rtt_ratio > 5.0:
                anomalies.append({
                    "type": "response_time_spike",
                    "severity": "high",
                    "detail": f"Response time {rtt_ratio:.1f}x baseline ({current_rtt:.3f}s vs {baseline_rtt:.3f}s)",
                })
            elif rtt_ratio > 2.0:
                anomalies.append({
                    "type": "response_time_increase",
                    "severity": "medium",
                    "detail": f"Response time {rtt_ratio:.1f}x baseline ({current_rtt:.3f}s vs {baseline_rtt:.3f}s)",
                })

        # Uptime anomaly
        current_up = current_observation.get("uptime", 100.0)
        baseline_up = baseline_profile.uptime_percentage
        if current_up < baseline_up - 10:
            anomalies.append({
                "type": "uptime_drop",
                "severity": "high" if current_up < 50 else "medium",
                "detail": f"Uptime dropped from {baseline_up:.1f}% to {current_up:.1f}%",
            })

        # Content change anomaly
        current_hash = current_observation.get("page_hash", "")
        if current_hash and baseline_profile.update_cadence == "static":
            historical = self.tracker.load(baseline_profile.target)
            old_hashes = {
                ev.details.get("page_hash", "")
                for ev in historical[-10:]
            }
            old_hashes.discard("")
            if old_hashes and current_hash not in old_hashes:
                anomalies.append({
                    "type": "unexpected_content_change",
                    "severity": "medium",
                    "detail": "Content changed despite 'static' classification",
                })

        # DNS anomaly
        current_dns = current_observation.get("dns_snapshot", "")
        if current_dns and baseline_profile.dns_churn_rate < 0.01:
            historical = self.tracker.load(baseline_profile.target)
            old_dns = [
                ev.details.get("dns_snapshot", "")
                for ev in historical[-5:]
            ]
            old_dns = [d for d in old_dns if d]
            if old_dns and current_dns not in old_dns:
                anomalies.append({
                    "type": "dns_change_on_stable_target",
                    "severity": "high",
                    "detail": "DNS records changed on a historically stable target",
                })

        return anomalies

    # ── private helpers ───────────────────────────────

    @staticmethod
    def _extract_host(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname or parsed.path.split("/")[0]

    def _probe_response_times(
        self, base_url: str, samples: int = 5, timeout: int = 8
    ) -> List[float]:
        """Time HTTP requests and return a list of response times in seconds."""
        times: List[float] = []
        for _ in range(samples):
            try:
                start = datetime.now(timezone.utc)
                req = urllib.request.Request(base_url, headers={"User-Agent": self._ua})
                with urllib.request.urlopen(req, timeout=timeout) as _resp:
                    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
                    times.append(elapsed)
            except (urllib.error.URLError, socket.timeout, OSError):
                times.append(timeout)  # max penalty
        return times

    def _fetch_page_hash(
        self, base_url: str, timeout: int = 8
    ) -> str:
        """Fetch page content and return its SHA-256 hash."""
        try:
            req = urllib.request.Request(base_url, headers={"User-Agent": self._ua})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(131_072)  # first 128 KB
            return hashlib.sha256(body).hexdigest()[:32]
        except (urllib.error.URLError, socket.timeout, OSError):
            return ""

    @staticmethod
    def _compute_dow_patterns(events: List[ActivityEvent]) -> Dict[str, float]:
        """Compute relative activity per day of week."""
        dow_counts: Dict[str, int] = {
            "Mon": 0, "Tue": 0, "Wed": 0, "Thu": 0,
            "Fri": 0, "Sat": 0, "Sun": 0,
        }
        for ev in events:
            try:
                ts = datetime.fromisoformat(ev.timestamp)
                dow = ts.strftime("%a")
                dow_counts[dow] += 1
            except (ValueError, TypeError):
                continue
        total = sum(dow_counts.values())
        if total == 0:
            return {}
        return {k: round(v / total, 4) for k, v in dow_counts.items()}

    @staticmethod
    def _compute_peak_quiet_hours(
        events: List[ActivityEvent],
    ) -> Tuple[List[int], List[int]]:
        """Determine peak and quiet hours from event timestamps."""
        hour_counts = [0] * 24
        for ev in events:
            try:
                ts = datetime.fromisoformat(ev.timestamp)
                hour_counts[ts.hour] += 1
            except (ValueError, TypeError):
                continue
        if not any(hour_counts):
            return [], []
        max_count = max(hour_counts)
        min_count = min(hour_counts)
        if max_count == min_count:
            return list(range(24)), []
        threshold_high = max_count * 0.75
        threshold_low = max_count * 0.25
        peak = [i for i, c in enumerate(hour_counts) if c >= threshold_high]
        quiet = [i for i, c in enumerate(hour_counts) if c <= threshold_low]
        return peak, quiet

    @staticmethod
    def _find_recurring_downtime(
        events: List[ActivityEvent],
    ) -> List[Dict[str, str]]:
        """Find recurring downtime patterns in historical events."""
        downtime_by_dow: Dict[str, List[int]] = {}
        for ev in events:
            if ev.event_type != "pol_scan":
                continue
            status = ev.details.get("status", "")
            if status not in ("unreachable", "degraded"):
                continue
            try:
                ts = datetime.fromisoformat(ev.timestamp)
                dow = ts.strftime("%a")
                downtime_by_dow.setdefault(dow, []).append(ts.hour)
            except (ValueError, TypeError):
                continue

        windows: List[Dict[str, str]] = []
        for dow, hours in downtime_by_dow.items():
            if len(hours) < 2:
                continue
            # Check if downtime clusters around a specific hour
            hour_freq = Counter(hours)
            most_common_hour, count = hour_freq.most_common(1)[0]
            if count >= 2:
                windows.append({
                    "start": f"{most_common_hour:02d}:00",
                    "end": f"{min(most_common_hour + 2, 23):02d}:00",
                    "day_of_week": dow,
                    "evidence": f"recurring downtime at hour {most_common_hour} UTC ({count} occurrences)",
                    "confidence": str(min(count / 5.0, 0.9))[:4],
                })
        return windows

    @staticmethod
    def _days_until_weekday(now: datetime, target_dow: str) -> int:
        """Days until next occurrence of *target_dow* (e.g. 'Sun')."""
        dow_map = {
            "Mon": 0, "Tue": 1, "Wed": 2, "Thu": 3,
            "Fri": 4, "Sat": 5, "Sun": 6,
        }
        target = dow_map.get(target_dow, 0)
        current = now.weekday()
        diff = (target - current) % 7
        return diff if diff > 0 else 7

    def _resolve_dns_snapshot(self, host: str, timeout: int = 8) -> str:
        """Return a canonical string of resolved IPs for comparison."""
        try:
            answers = socket.getaddrinfo(host, None)
            ips = sorted({addr[4][0] for addr in answers if addr[4]})
            return ",".join(ips)
        except (socket.gaierror, OSError):
            return ""

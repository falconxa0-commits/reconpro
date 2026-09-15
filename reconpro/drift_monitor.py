"""ReconPro v9.2.0 — Infrastructure Drift Detection

Tracks how a target’s infrastructure changes over time by capturing
snapshots of DNS, TLS, HTTP headers, tech stack, and security posture.
Compares consecutive snapshots to detect meaningful drift.

Exports:
    DriftSnapshot              – point-in-time infrastructure state
    DriftEvent                 – single detected change
    InfrastructureDriftMonitor – main drift detection engine
    DriftRiskScorer            – risk scoring for drift events
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# Drift categories used throughout the module.
DRIFT_CATEGORIES = (
    "DNS_CHANGE",
    "CERT_CHANGE",
    "HEADER_CHANGE",
    "TECH_CHANGE",
    "PORT_CHANGE",
    "SECURITY_CHANGE",
    "CONTENT_CHANGE",
    "STATUS_CHANGE",
)


# Security headers we track.
_TRACKED_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
)


# Technology fingerprints extracted from headers / page content.
_TECH_SIGNATURES: Dict[str, List[str]] = {
    "nginx": ["server: nginx"],
    "apache": ["server: apache"],
    "cloudflare": ["server: cloudflare", "cf-ray"],
    "aws_elb": ["server: awselb", "x-amzn-trace-id"],
    "aws_s3": ["server: amazons3", "x-amz-request-id"],
    "azure": ["server: microsoft-iis", "x-azure-ref", "x-ms-request-id"],
    "gcp": ["server: gws", "x-goog-request-id"],
    "express": ["x-powered-by: express"],
    "nextjs": ["x-powered-by: next.js", "__next/"],
    "react": ["react", "__next/", "_next/static"],
    "wordpress": ["wp-content", "wp-includes", "wordpress"],
    "drupal": ["drupal", "sites/default/files"],
    "django": ["csrfmiddlewaretoken", "django"],
    "flask": ["flask", "werkzeug"],
    "laravel": ["laravel_session"],
    "php": ["x-powered-by: php", ".php"],
    "aspnet": ["x-aspnet-version", "asp.net"],
    "cloudfront": ["x-amz-cf-id", "x-cache: hit from cloudfront"],
    "fastly": ["x-served-by: cache-", "fastly"],
    "varnish": ["x-varnish", "x-hit"],
    "kubernetes": ["x-kubernetes", "server: openresty"],
    "docker": ["x-docker"],
}


# Common ports to check for open status.
_COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                9200, 27017)


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------

@dataclass
class DriftSnapshot:
    """Point-in-time capture of a target’s infrastructure."""
    target: str = ""
    timestamp: str = ""
    dns_records: Dict[str, Any] = field(default_factory=dict)
    tls_cert: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tech_stack: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    security_headers: Set[str] = field(default_factory=set)
    page_hash: str = ""
    status_code: int = 0
    body_length: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "dns_records": self.dns_records,
            "tls_cert": self.tls_cert,
            "headers": {k: v for k, v in sorted(self.headers.items())},
            "tech_stack": sorted(self.tech_stack),
            "open_ports": sorted(self.open_ports),
            "security_headers": sorted(self.security_headers),
            "page_hash": self.page_hash,
            "status_code": self.status_code,
            "body_length": self.body_length,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DriftSnapshot:
        return cls(
            target=data.get("target", ""),
            timestamp=data.get("timestamp", ""),
            dns_records=data.get("dns_records", {}),
            tls_cert=data.get("tls_cert", {}),
            headers=data.get("headers", {}),
            tech_stack=data.get("tech_stack", []),
            open_ports=data.get("open_ports", []),
            security_headers=set(data.get("security_headers", [])),
            page_hash=data.get("page_hash", ""),
            status_code=data.get("status_code", 0),
            body_length=data.get("body_length", 0),
        )


@dataclass
class DriftEvent:
    """A single detected infrastructure change."""
    timestamp: str = ""
    field_changed: str = ""
    old_value: str = ""
    new_value: str = ""
    severity: str = "low"
    risk_impact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "field_changed": self.field_changed,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "severity": self.severity,
            "risk_impact": self.risk_impact,
        }


# ------------------------------------------------------------------
# DriftRiskScorer
# ------------------------------------------------------------------

class DriftRiskScorer:
    """Score drift events by risk.

    Different drift types carry different risk weights:

    - Security header **removal** → critical
    - DNS record change → high
    - TLS certificate change → medium-high
    - Technology stack change → medium
    - HTTP header change → low-medium
    - Content change → low
    - Port change → high
    """

    # Base severity scores 0–100
    _SEVERITY_WEIGHTS: Dict[str, float] = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0,
        "info": 10.0,
    }

    # Category → default severity
    _CATEGORY_DEFAULTS: Dict[str, str] = {
        "DNS_CHANGE": "high",
        "CERT_CHANGE": "medium",
        "HEADER_CHANGE": "low",
        "TECH_CHANGE": "medium",
        "PORT_CHANGE": "high",
        "SECURITY_CHANGE": "critical",
        "CONTENT_CHANGE": "low",
        "STATUS_CHANGE": "medium",
    }

    # Security header removal is always critical.
    _CRITICAL_SECURITY_HEADERS = (
        "strict-transport-security",
        "content-security-policy",
    )

    def score_event(self, event: DriftEvent) -> float:
        """Return a 0–100 risk score for a single drift event."""
        base = self._SEVERITY_WEIGHTS.get(event.severity, 25.0)

        # Boost for security header removal
        field_lower = event.field_changed.lower()
        if event.field_changed.startswith("security_header_removed:"):
            hdr = field_lower.replace("security_header_removed:", "")
            if hdr in self._CRITICAL_SECURITY_HEADERS:
                return 100.0
            return 85.0

        # Boost for DNS changes
        if "dns" in field_lower:
            base = max(base, 70.0)

        # Boost for TLS cert changes
        if "cert" in field_lower or "tls" in field_lower:
            base = max(base, 60.0)

        # Boost for new open ports
        if "port" in field_lower and "added" in event.risk_impact.lower():
            base = max(base, 80.0)

        return min(base, 100.0)

    def score_drift(self, events: List[DriftEvent]) -> float:
        """Aggregate 0–100 risk score for a list of drift events."""
        if not events:
            return 0.0
        individual = [self.score_event(e) for e in events]
        # Weighted: worst event counts more, but all contribute.
        worst = max(individual)
        average = sum(individual) / len(individual)
        score = worst * 0.6 + average * 0.4
        # Slight bump for volume
        volume_factor = min(len(events) / 10.0, 1.0) * 10.0
        return min(score + volume_factor, 100.0)

    def classify_event(self, event: DriftEvent) -> str:
        """Return the severity string for a drift event."""
        return self._CATEGORY_DEFAULTS.get(event.field_changed, "low")


# ------------------------------------------------------------------
# InfrastructureDriftMonitor
# ------------------------------------------------------------------

class InfrastructureDriftMonitor:
    """Capture, compare, and report infrastructure drift for targets.

    Snapshots are persisted to ``~/.reconpro/drift/<target>/``.
    """

    def __init__(self) -> None:
        self._ua = "ReconPro/9.2.0 (drift-monitor)"
        self._scorer = DriftRiskScorer()
        self._store = Path(os.path.expanduser("~/.reconpro/drift"))

    # -- public API ---------------------------------------------------

    def take_snapshot(
        self, target: str, base_url: str, timeout: int = 8
    ) -> DriftSnapshot:
        """Capture the current infrastructure state of *target*."""
        host = self._extract_host(base_url)
        now = datetime.now(timezone.utc).isoformat()

        dns_records = self._capture_dns(host, timeout=timeout)
        tls_cert = self._capture_tls_cert(host, timeout=timeout)
        headers: Dict[str, str] = {}
        body = ""
        status_code = 0
        body_length = 0

        try:
            req = urllib.request.Request(
                base_url, headers={"User-Agent": self._ua}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read(262_144).decode("utf-8", errors="replace")
                status_code = resp.status
                body_length = len(body)
        except (urllib.error.URLError, socket.timeout, OSError):
            pass

        page_hash = (
            hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:32]
            if body else ""
        )
        tech_stack = self._detect_tech_stack(headers, body)
        security_headers = self._extract_security_headers(headers)
        open_ports = self._scan_common_ports(host, timeout=timeout)

        return DriftSnapshot(
            target=target,
            timestamp=now,
            dns_records=dns_records,
            tls_cert=tls_cert,
            headers=headers,
            tech_stack=tech_stack,
            open_ports=open_ports,
            security_headers=security_headers,
            page_hash=page_hash,
            status_code=status_code,
            body_length=body_length,
        )

    def compare_snapshots(
        self, snapshot_a: DriftSnapshot, snapshot_b: DriftSnapshot
    ) -> List[DriftEvent]:
        """Compare two snapshots and return a list of DriftEvents.

        *snapshot_a* is the older baseline, *snapshot_b* the newer.
        """
        events: List[DriftEvent] = []
        ts = snapshot_b.timestamp or datetime.now(timezone.utc).isoformat()

        # DNS changes
        events.extend(self._diff_dict(
            ts, "DNS_CHANGE", snapshot_a.dns_records, snapshot_b.dns_records
        ))

        # TLS cert changes
        events.extend(self._diff_dict(
            ts, "CERT_CHANGE", snapshot_a.tls_cert, snapshot_b.tls_cert
        ))

        # Header changes (excluding noisy headers)
        noisy = {"date", "set-cookie", "x-cache", "x-timer", "age",
                 "x-request-id", "x-ratelimit-remaining", "etag"}
        filtered_a = {k: v for k, v in snapshot_a.headers.items()
                      if k.lower() not in noisy}
        filtered_b = {k: v for k, v in snapshot_b.headers.items()
                      if k.lower() not in noisy}
        events.extend(self._diff_dict(
            ts, "HEADER_CHANGE", filtered_a, filtered_b
        ))

        # Tech stack changes
        events.extend(self._diff_list(
            ts, "TECH_CHANGE", snapshot_a.tech_stack, snapshot_b.tech_stack
        ))

        # Port changes
        events.extend(self._diff_list(
            ts, "PORT_CHANGE",
            [str(p) for p in snapshot_a.open_ports],
            [str(p) for p in snapshot_b.open_ports],
        ))

        # Security header changes
        events.extend(self._diff_security_headers(
            ts, snapshot_a.security_headers, snapshot_b.security_headers
        ))

        # Content hash change
        if (snapshot_a.page_hash and snapshot_b.page_hash
                and snapshot_a.page_hash != snapshot_b.page_hash):
            events.append(DriftEvent(
                timestamp=ts,
                field_changed="CONTENT_CHANGE",
                old_value=snapshot_a.page_hash,
                new_value=snapshot_b.page_hash,
                severity="low",
                risk_impact="Page content changed",
            ))

        # Status code change
        if snapshot_a.status_code != snapshot_b.status_code:
            sev = "high" if snapshot_b.status_code >= 500 else "medium"
            events.append(DriftEvent(
                timestamp=ts,
                field_changed="STATUS_CHANGE",
                old_value=str(snapshot_a.status_code),
                new_value=str(snapshot_b.status_code),
                severity=sev,
                risk_impact=(
                    f"HTTP status changed from {snapshot_a.status_code} "
                    f"to {snapshot_b.status_code}"
                ),
            ))

        # Body length change (significant)
        if snapshot_a.body_length > 0 and snapshot_b.body_length > 0:
            ratio = snapshot_b.body_length / max(snapshot_a.body_length, 1)
            if ratio > 1.5 or ratio < 0.5:
                events.append(DriftEvent(
                    timestamp=ts,
                    field_changed="CONTENT_CHANGE",
                    old_value=str(snapshot_a.body_length),
                    new_value=str(snapshot_b.body_length),
                    severity="medium",
                    risk_impact=(
                        f"Body length changed by {abs(ratio - 1) * 100:.0f}%"
                    ),
                ))

        return events

    def detect_drift(
        self, target: str, base_url: str, timeout: int = 8
    ) -> Dict[str, Any]:
        """Take a snapshot and compare against the last saved one."""
        current = self.take_snapshot(target, base_url, timeout=timeout)
        self.save_snapshot(current)

        previous = self._load_latest_snapshot(target, exclude_current=True)
        if previous is None:
            return {
                "target": target,
                "drift_detected": False,
                "message": "No previous snapshot to compare against",
                "current_snapshot": current.to_dict(),
                "drift_events": [],
                "risk_score": 0.0,
            }

        events = self.compare_snapshots(previous, current)
        risk_score = self._scorer.score_drift(events)

        return {
            "target": target,
            "drift_detected": len(events) > 0,
            "drift_event_count": len(events),
            "previous_timestamp": previous.timestamp,
            "current_timestamp": current.timestamp,
            "drift_events": [e.to_dict() for e in events],
            "risk_score": round(risk_score, 1),
            "current_snapshot": current.to_dict(),
        }

    def save_snapshot(self, snapshot: DriftSnapshot) -> Path:
        """Persist a snapshot to ``~/.reconpro/drift/<target>/``."""
        target_dir = self._target_dir(snapshot.target)
        ts_safe = re.sub(r"[^\w\-]", "_", snapshot.timestamp)
        path = target_dir / f"snapshot_{ts_safe}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snapshot.to_dict(), f, indent=2, ensure_ascii=False)
        return path

    def load_snapshots(self, target: str) -> List[DriftSnapshot]:
        """Load all saved snapshots for a target, newest first."""
        target_dir = self._target_dir(target)
        if not target_dir.exists():
            return []
        snapshots: List[DriftSnapshot] = []
        for p in sorted(target_dir.glob("snapshot_*.json"), reverse=True):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                snapshots.append(DriftSnapshot.from_dict(data))
            except (json.JSONDecodeError, TypeError, OSError):
                continue
        return snapshots

    def analyze_drift_trend(self, target: str) -> Dict[str, Any]:
        """Analyze drift patterns over time.

        Returns trend analysis: increasing, decreasing, cyclical,
        or stable, along with category breakdowns.
        """
        snapshots = self.load_snapshots(target)
        if len(snapshots) < 2:
            return {
                "target": target,
                "trend": "insufficient_data",
                "snapshot_count": len(snapshots),
                "category_breakdown": {},
                "details": [],
            }

        all_events: List[DriftEvent] = []
        for i in range(len(snapshots) - 1):
            events = self.compare_snapshots(snapshots[i + 1], snapshots[i])
            all_events.extend(events)

        # Category breakdown
        category_counts: Dict[str, int] = {}
        for ev in all_events:
            cat = ev.field_changed
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Group events by snapshot pair to detect trends
        pairs: List[int] = []
        for i in range(len(snapshots) - 1):
            pair_events = self.compare_snapshots(
                snapshots[i + 1], snapshots[i]
            )
            pairs.append(len(pair_events))

        # Determine trend
        trend = self._determine_trend(pairs)

        # Time between changes
        change_intervals: List[str] = []
        for i in range(len(snapshots) - 1):
            events = self.compare_snapshots(snapshots[i + 1], snapshots[i])
            if events:
                try:
                    ts_a = datetime.fromisoformat(snapshots[i + 1].timestamp)
                    ts_b = datetime.fromisoformat(snapshots[i].timestamp)
                    delta = abs((ts_b - ts_a).total_seconds())
                    if delta < 3600:
                        interval = f"{int(delta // 60)} minutes"
                    elif delta < 86400:
                        interval = f"{delta / 3600:.1f} hours"
                    else:
                        interval = f"{delta / 86400:.1f} days"
                    change_intervals.append(interval)
                except (ValueError, TypeError):
                    pass

        return {
            "target": target,
            "trend": trend,
            "snapshot_count": len(snapshots),
            "total_drift_events": len(all_events),
            "category_breakdown": category_counts,
            "events_per_snapshot_pair": pairs,
            "change_intervals": change_intervals,
            "risk_trend": self._risk_trend(snapshots),
            "details": [e.to_dict() for e in all_events],
        }

    def score_drift_risk(self, drift_events: List[DriftEvent]) -> float:
        """Convenience wrapper around DriftRiskScorer.score_drift."""
        return self._scorer.score_drift(drift_events)

    def generate_drift_report(self, target: str) -> Dict[str, Any]:
        """Generate a full drift analysis report for a target.

        Includes current snapshot, trend analysis, risk scoring,
        and actionable recommendations.
        """
        snapshots = self.load_snapshots(target)
        trend = self.analyze_drift_trend(target)

        # Severity summary
        critical = sum(1 for e in trend.get("details", []) if e.get("severity") == "critical")
        high = sum(1 for e in trend.get("details", []) if e.get("severity") == "high")
        medium = sum(1 for e in trend.get("details", []) if e.get("severity") == "medium")
        low = sum(1 for e in trend.get("details", []) if e.get("severity") == "low")

        # Current snapshot
        current = snapshots[0] if snapshots else None

        # Recommendations
        recommendations = self._generate_recommendations(
            trend, current
        )

        return {
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_snapshots": len(snapshots),
                "total_drift_events": trend.get("total_drift_events", 0),
                "trend": trend.get("trend", "unknown"),
                "current_risk_score": self._scorer.score_drift(
                    [DriftEvent(**e) for e in trend.get("details", [])]
                ),
            },
            "severity_breakdown": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "category_breakdown": trend.get("category_breakdown", {}),
            "trend_analysis": trend,
            "current_snapshot": current.to_dict() if current else None,
            "recommendations": recommendations,
        }

    # -- private helpers ---------------------------------------------

    def _target_dir(self, target: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
        d = self._store / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _load_latest_snapshot(
        self, target: str, exclude_current: bool = False
    ) -> Optional[DriftSnapshot]:
        """Load the most recent snapshot (optionally skipping the latest)."""
        snapshots = self.load_snapshots(target)
        if not snapshots:
            return None
        if exclude_current and len(snapshots) > 1:
            return snapshots[1]
        return snapshots[0]

    @staticmethod
    def _extract_host(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname or parsed.path.split("/")[0]

    def _capture_dns(
        self, host: str, timeout: int = 8
    ) -> Dict[str, Any]:
        """Resolve DNS and return structured records."""
        records: Dict[str, Any] = {}
        try:
            answers = socket.getaddrinfo(host, None)
            a_records = sorted({addr[4][0] for addr in answers if addr[4]})
            records["A"] = a_records
            records["AAAA"] = [
                addr[4][0] for addr in answers
                if addr[0] == socket.AF_INET6 and addr[4]
            ]
        except (socket.gaierror, OSError) as exc:
            records["error"] = str(exc)

        # Check for CNAME-like patterns
        records["hostname"] = host
        return records

    def _capture_tls_cert(
        self, host: str, timeout: int = 8
    ) -> Dict[str, Any]:
        """Fetch the TLS certificate details."""
        cert_info: Dict[str, Any] = {}
        try:
            from .http_layer import inspection_context
            # certificate inspection (audited helper — not data transport)
            ctx = inspection_context()
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    if cert:
                        cert_info["subject"] = {
                            k: v for item in cert.get("subject", [])
                            for k, v in item
                        }
                        cert_info["issuer"] = {
                            k: v for item in cert.get("issuer", [])
                            for k, v in item
                        }
                        cert_info["not_before"] = cert.get("notBefore", "")
                        cert_info["not_after"] = cert.get("notAfter", "")
                        cert_info["serial"] = cert.get("serialNumber", "")
                        cert_info["version"] = cert.get("version", "")
                        cert_info["san"] = [
                            v for item in cert.get("subjectAltName", [])
                            for v in item[1:]  # skip the type tag
                        ]
        except (socket.timeout, socket.gaierror, ssl.SSLError, OSError) as exc:
            cert_info["error"] = str(exc)
        return cert_info

    @staticmethod
    def _detect_tech_stack(
        headers: Dict[str, str], body: str
    ) -> List[str]:
        """Detect technologies from headers and page content."""
        detected: List[str] = []
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined = header_str + "\n" + body
        combined_lower = combined.lower()

        for tech, signatures in _TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined_lower:
                    if tech not in detected:
                        detected.append(tech)
                    break

        return sorted(detected)

    @staticmethod
    def _extract_security_headers(
        headers: Dict[str, str],
    ) -> Set[str]:
        """Return the set of tracked security headers present."""
        found: Set[str] = set()
        for hdr in _TRACKED_SECURITY_HEADERS:
            if hdr in headers:
                found.add(hdr)
        return found

    def _scan_common_ports(
        self, host: str, timeout: int = 8
    ) -> List[int]:
        """Scan a set of common ports and return open ones."""
        open_ports: List[int] = []
        per_port_timeout = max(1, timeout // 8)
        for port in _COMMON_PORTS:
            try:
                sock = socket.create_connection(
                    (host, port), timeout=per_port_timeout
                )
                sock.close()
                open_ports.append(port)
            except (socket.timeout, socket.gaierror, OSError):
                pass
        return open_ports

    # -- diff helpers ------------------------------------------------

    def _diff_dict(
        self,
        ts: str,
        category: str,
        a: Dict[str, Any],
        b: Dict[str, Any],
    ) -> List[DriftEvent]:
        """Compare two dicts and emit DriftEvents for differences."""
        events: List[DriftEvent] = []
        all_keys = set(a.keys()) | set(b.keys())
        severity = self._scorer._CATEGORY_DEFAULTS.get(category, "low")

        for key in all_keys:
            old_val = json.dumps(a.get(key), sort_keys=True, default=str)
            new_val = json.dumps(b.get(key), sort_keys=True, default=str)
            if old_val != new_val:
                impact = f"{key}: {'added' if key not in a else 'removed' if key not in b else 'changed'}"
                events.append(DriftEvent(
                    timestamp=ts,
                    field_changed=category,
                    old_value=old_val[:500],
                    new_value=new_val[:500],
                    severity=severity,
                    risk_impact=impact,
                ))
        return events

    def _diff_list(
        self,
        ts: str,
        category: str,
        a: List[str],
        b: List[str],
    ) -> List[DriftEvent]:
        """Compare two lists and emit events for additions/removals."""
        events: List[DriftEvent] = []
        severity = self._scorer._CATEGORY_DEFAULTS.get(category, "low")
        set_a = set(a)
        set_b = set(b)

        added = set_b - set_a
        removed = set_a - set_b

        for item in sorted(added):
            events.append(DriftEvent(
                timestamp=ts,
                field_changed=category,
                old_value="",
                new_value=str(item),
                severity=severity,
                risk_impact=f"{item} added",
            ))
        for item in sorted(removed):
            events.append(DriftEvent(
                timestamp=ts,
                field_changed=category,
                old_value=str(item),
                new_value="",
                severity=severity,
                risk_impact=f"{item} removed",
            ))
        return events

    def _diff_security_headers(
        self,
        ts: str,
        a: Set[str],
        b: Set[str],
    ) -> List[DriftEvent]:
        """Diff security headers — removal is always critical."""
        events: List[DriftEvent] = []

        added = b - a
        removed = a - b

        for hdr in sorted(added):
            events.append(DriftEvent(
                timestamp=ts,
                field_changed=f"SECURITY_CHANGE",
                old_value="",
                new_value=hdr,
                severity="low",  # addition is good
                risk_impact=f"Security header added: {hdr}",
            ))

        for hdr in sorted(removed):
            is_critical = hdr in self._scorer._CRITICAL_SECURITY_HEADERS
            events.append(DriftEvent(
                timestamp=ts,
                field_changed=f"SECURITY_CHANGE",
                old_value=hdr,
                new_value="",
                severity="critical" if is_critical else "high",
                risk_impact=f"Security header removed: {hdr}",
            ))

        return events

    # -- trend analysis helpers --------------------------------------

    @staticmethod
    def _determine_trend(pairs: List[int]) -> str:
        """Classify the drift trend from a list of event counts."""
        if len(pairs) < 2:
            return "stable"

        first_half = pairs[: len(pairs) // 2]
        second_half = pairs[len(pairs) // 2 :]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)

        if avg_first == 0 and avg_second == 0:
            return "stable"
        if avg_first == 0:
            return "increasing"

        ratio = avg_second / avg_first
        if ratio > 1.5:
            return "increasing"
        elif ratio < 0.5:
            return "decreasing"
        else:
            # Check for cyclical pattern (alternating high/low)
            if len(pairs) >= 4:
                alternating = 0
                for i in range(1, len(pairs)):
                    if pairs[i] == pairs[i - 1]:
                        continue
                    if i == 1:
                        alternating += 1
                        continue
                    curr_up = pairs[i] > pairs[i - 1]
                    prev_up = pairs[i - 1] > pairs[i - 2]
                    if prev_up != curr_up:
                        alternating += 1
                if alternating > len(pairs) * 0.6:
                    return "cyclical"
            return "stable"

    def _risk_trend(self, snapshots: List[DriftSnapshot]) -> str:
        """Determine if overall risk is trending up or down."""
        if len(snapshots) < 3:
            return "insufficient_data"

        scores: List[float] = []
        for i in range(len(snapshots) - 1):
            events = self.compare_snapshots(snapshots[i + 1], snapshots[i])
            scores.append(self._scorer.score_drift(events))

        recent = scores[: max(1, len(scores) // 2)]
        older = scores[max(1, len(scores) // 2) :]
        avg_recent = sum(recent) / len(recent)
        avg_older = sum(older) / len(older) if older else 0.0

        if avg_recent > avg_older * 1.3:
            return "increasing_risk"
        elif avg_recent < avg_older * 0.7:
            return "decreasing_risk"
        return "stable_risk"

    @staticmethod
    def _generate_recommendations(
        trend: Dict[str, Any],
        current: Optional[DriftSnapshot],
    ) -> List[str]:
        """Produce actionable recommendations based on drift data."""
        recs: List[str] = []
        breakdown = trend.get("category_breakdown", {})

        if "SECURITY_CHANGE" in breakdown:
            recs.append(
                "CRITICAL: Security headers were modified. Review and restore "
                "HSTS and CSP headers immediately."
            )

        if "DNS_CHANGE" in breakdown:
            recs.append(
                "HIGH: DNS records changed. Verify this was authorized and check "
                "for DNS hijacking or unauthorized zone transfers."
            )

        if "PORT_CHANGE" in breakdown:
            recs.append(
                "HIGH: Open port configuration changed. Audit new exposed "
                "services and ensure firewall rules are up to date."
            )

        if "CERT_CHANGE" in breakdown:
            recs.append(
                "MEDIUM: TLS certificate changed. Verify the new certificate "
                "is legitimate and not issued by a compromised CA."
            )

        if "TECH_CHANGE" in breakdown:
            recs.append(
                "MEDIUM: Technology stack changed. This may indicate a "
                "deployment, migration, or potential compromise."
            )

        if trend.get("trend") == "increasing":
            recs.append(
                "WARNING: Infrastructure drift is increasing over time. "
                "Consider implementing infrastructure-as-code with drift detection."
            )

        if current:
            if not current.security_headers:
                recs.append(
                    "INFO: No security headers detected. Implement at minimum "
                    "HSTS, CSP, and X-Content-Type-Options."
                )
            if 9200 in current.open_ports:
                recs.append(
                    "INFO: Elasticsearch port 9200 is open. Ensure it is not "
                    "exposed to the public internet."
                )
            if 6379 in current.open_ports:
                recs.append(
                    "INFO: Redis port 6379 is open. Ensure authentication is "
                    "enabled and access is restricted."
                )
            if 27017 in current.open_ports:
                recs.append(
                    "INFO: MongoDB port 27017 is open. Ensure authentication is "
                    "enabled and the port is firewalled."
                )

        if not recs:
            recs.append(
                "No significant issues detected. Continue monitoring for changes."
            )

        return recs

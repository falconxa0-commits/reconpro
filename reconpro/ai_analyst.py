"""ReconPro v11 — AI Security Analyst Engine.

Pure-Python rule-based reasoning system for intelligent security analysis.
Zero external dependencies. No LLM required.

Provides:
- Finding classification into attack categories
- Cross-module finding correlation and deduplication
- Exploitability estimation
- Business impact analysis
- Attack path detection and chaining
- Remediation prioritization
- MITRE ATT&CK / CWE / CAPEC mapping
- Confidence scoring with explicit uncertainty
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ExtendedFinding:
    """A Finding enriched with AI analyst annotations."""

    # Original finding fields
    title: str
    severity: str
    category: str
    module: str
    description: str
    evidence: str
    asset: str
    points_deducted: int = 0
    remediation: str = ""
    dread_score: float = 0.0

    # AI analyst fields
    executive_summary: str = ""
    technical_explanation: str = ""
    attack_narrative: str = ""
    risk_justification: str = ""
    business_impact: str = ""
    mitre_attack_mapping: Dict[str, str] = field(default_factory=dict)
    cwe_mapping: List[str] = field(default_factory=list)
    capec_mapping: List[str] = field(default_factory=list)
    cvss_interpretation: Dict[str, Any] = field(default_factory=dict)
    remediation_plan: List[str] = field(default_factory=list)
    validation_steps: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    supporting_evidence: List[str] = field(default_factory=list)
    exploitability: float = 0.0
    business_impact_score: float = 0.0
    attacker_effort: str = "medium"
    likelihood: float = 0.0
    root_cause: str = ""
    chained_vulnerabilities: List[str] = field(default_factory=list)
    uncertainty_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "asset": self.asset,
            "points_deducted": self.points_deducted,
            "remediation": self.remediation,
            "dread_score": self.dread_score,
            "executive_summary": self.executive_summary,
            "technical_explanation": self.technical_explanation,
            "attack_narrative": self.attack_narrative,
            "risk_justification": self.risk_justification,
            "business_impact": self.business_impact,
            "mitre_attack_mapping": self.mitre_attack_mapping,
            "cwe_mapping": self.cwe_mapping,
            "capec_mapping": self.capec_mapping,
            "cvss_interpretation": self.cvss_interpretation,
            "remediation_plan": self.remediation_plan,
            "validation_steps": self.validation_steps,
            "confidence_score": self.confidence_score,
            "supporting_evidence": self.supporting_evidence,
            "exploitability": self.exploitability,
            "business_impact_score": self.business_impact_score,
            "attacker_effort": self.attacker_effort,
            "likelihood": self.likelihood,
            "root_cause": self.root_cause,
            "chained_vulnerabilities": self.chained_vulnerabilities,
            "uncertainty_note": self.uncertainty_note,
        }


@dataclass
class ClassificationResult:
    """Result of finding classification."""
    attack_category: str
    confidence: float
    indicators: List[str] = field(default_factory=list)
    sub_category: str = ""


@dataclass
class CorrelationGroup:
    """A group of correlated findings."""
    findings: List[Dict[str, Any]]
    correlation_type: str  # "shared_asset", "attack_chain", "duplicate", "complementary"
    attack_chain: List[str] = field(default_factory=list)
    combined_risk: str = "medium"
    combined_confidence: float = 0.0


@dataclass
class AttackPath:
    """A detected attack path through multiple findings."""
    steps: List[Dict[str, Any]]
    entry_point: str = ""
    objective: str = ""
    complexity: str = "medium"  # low, medium, high, very_high
    likelihood: float = 0.5
    impact: float = 0.5
    confidence: float = 0.0
    narrative: str = ""


@dataclass
class AnalysisReport:
    """Complete analysis output from AIAnalystEngine."""
    target: str = ""
    total_findings: int = 0
    classified: List[Dict[str, Any]] = field(default_factory=list)
    correlated: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    prioritized: List[Dict[str, Any]] = field(default_factory=list)
    extended_findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    timestamp: float = field(default_factory=time.time)
    dedup_count: int = 0
    analysis_duration_ms: float = 0.0
    false_positive_reduction: Dict[str, int] = field(default_factory=lambda: {"before": 0, "after": 0, "removed": 0})
    asset_criticality: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_findings": self.total_findings,
            "classified_count": len(self.classified),
            "correlated_count": len(self.correlated),
            "attack_paths_count": len(self.attack_paths),
            "prioritized_count": len(self.prioritized),
            "extended_findings": self.extended_findings,
            "summary": self.summary,
            "timestamp": self.timestamp,
            "dedup_count": self.dedup_count,
            "analysis_duration_ms": self.analysis_duration_ms,
            "false_positive_reduction": self.false_positive_reduction,
            "asset_criticality": self.asset_criticality,
            "correlated": self.correlated,
            "attack_paths": self.attack_paths,
            "prioritized": self.prioritized,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Mapping Tables — MITRE ATT&CK / CWE / CAPEC
# ═══════════════════════════════════════════════════════════════════════════

# Category → MITRE ATT&CK mappings (tactic_id, technique_id, technique_name)
MITRE_ATTACK_MAP: Dict[str, List[Dict[str, str]]] = {
    "sqli": [
        {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
        {"tactic": "TA0002", "technique": "T1059", "name": "Command and Scripting Interpreter"},
    ],
    "xss": [
        {"tactic": "TA0002", "technique": "T1059.007", "name": "JavaScript Execution"},
        {"tactic": "TA0001", "technique": "T1189", "name": "Drive-by Compromise"},
    ],
    "ssrf": [
        {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
        {"tactic": "TA0007", "technique": "T1046", "name": "Network Service Discovery"},
    ],
    "rce": [
        {"tactic": "TA0002", "technique": "T1059", "name": "Command and Scripting Interpreter"},
        {"tactic": "TA0004", "technique": "T1548", "name": "Abuse Elevation Control Mechanism"},
    ],
    "auth_bypass": [
        {"tactic": "TA0001", "technique": "T1078", "name": "Valid Accounts"},
        {"tactic": "TA0006", "technique": "T1110", "name": "Brute Force"},
    ],
    "privilege_escalation": [
        {"tactic": "TA0004", "technique": "T1548", "name": "Abuse Elevation Control Mechanism"},
        {"tactic": "TA0004", "technique": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "credential_theft": [
        {"tactic": "TA0006", "technique": "T1110.001", "name": "Password Spraying"},
        {"tactic": "TA0006", "technique": "T1552", "name": "Unsecured Credentials"},
        {"tactic": "TA0003", "technique": "T1553", "name": "Subvert Trust Controls"},
    ],
    "info_disclosure": [
        {"tactic": "TA0009", "technique": "T1566", "name": "Phishing"},
        {"tactic": "TA0007", "technique": "T1083", "name": "File and Directory Discovery"},
    ],
    "data_exposure": [
        {"tactic": "TA0009", "technique": "T1560", "name": "Archive Collected Data"},
        {"tactic": "TA0010", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    ],
    "misconfiguration": [
        {"tactic": "TA0007", "technique": "T1082", "name": "System Information Discovery"},
        {"tactic": "TA0005", "technique": "T1562", "name": "Impair Defenses"},
    ],
    "crypto_failure": [
        {"tactic": "TA0005", "technique": "T1573", "name": "Encrypted Channel"},
        {"tactic": "TA0011", "technique": "T1571", "name": "Non-Standard Port"},
    ],
    "dos": [
        {"tactic": "TA0040", "technique": "T1498", "name": "Network Denial of Service"},
        {"tactic": "TA0040", "technique": "T1486", "name": "Data Encrypted for Impact"},
    ],
    "injection": [
        {"tactic": "TA0002", "technique": "T1059", "name": "Command and Scripting Interpreter"},
        {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
    ],
    "beaconing": [
        {"tactic": "TA0011", "technique": "T1071", "name": "Application Layer Protocol"},
        {"tactic": "TA0011", "technique": "T1573.001", "name": "Symmetric Encryption"},
    ],
    "infrastructure": [
        {"tactic": "TA0042", "technique": "T1583", "name": "Acquire Infrastructure"},
        {"tactic": "TA0043", "technique": "T1595", "name": "Active Scanning"},
    ],
    "steganography": [
        {"tactic": "TA0005", "technique": "T1001", "name": "Data Obfuscation"},
        {"tactic": "TA0010", "technique": "T1041", "name": "Exfiltration Over C2 Channel"},
    ],
    "supply_chain": [
        {"tactic": "TA0042", "technique": "T1585", "name": "Establish Accounts"},
        {"tactic": "TA0001", "technique": "T1195.002", "name": "Compromise Software Supply Chain"},
    ],
    "xxe": [
        {"tactic": "TA0002", "technique": "T1059.009", "name": "Command and Scripting Interpreter"},
        {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application"},
    ],
    "default_credentials": [
        {"tactic": "TA0006", "technique": "T1110.001", "name": "Password Spraying"},
        {"tactic": "TA0001", "technique": "T1078.001", "name": "Default Accounts"},
    ],
    "open_redirect": [
        {"tactic": "TA0001", "technique": "T1566.002", "name": "Spearphishing Link"},
        {"tactic": "TA0005", "technique": "T1070.005", "name": "Network Traffic Capture"},
    ],
    "jwt_exposure": [
        {"tactic": "TA0006", "technique": "T1552.001", "name": "Credentials in Files"},
        {"tactic": "TA0003", "technique": "T1553.002", "name": "Code Signing"},
    ],
    "sensitive_api": [
        {"tactic": "TA0007", "technique": "T1046", "name": "Network Service Discovery"},
        {"tactic": "TA0009", "technique": "T1213", "name": "Data from Information Repositories"},
    ],
    "dns_recon": [
        {"tactic": "TA0043", "technique": "T1590.002", "name": "DNS"},
        {"tactic": "TA0043", "technique": "T1595.002", "name": "Software Vulnerability Scanning"},
    ],
    "tech_fingerprint": [
        {"tactic": "TA0043", "technique": "T1592.004", "name": "Software"},
        {"tactic": "TA0043", "technique": "T1592.002", "name": "Firmware"},
    ],
    "waf_detected": [
        {"tactic": "TA0043", "technique": "T1595.002", "name": "Software Vulnerability Scanning"},
    ],
    "header_analysis": [
        {"tactic": "TA0043", "technique": "T1592", "name": "Gather Victim Host Information"},
    ],
    "certificate": [
        {"tactic": "TA0043", "technique": "T1590.005", "name": "Trusted Third-Party Domains"},
    ],
    "wayback": [
        {"tactic": "TA0043", "technique": "T1593", "name": "Search Open Websites/Domains"},
    ],
    "honeypot": [
        {"tactic": "TA0007", "technique": "T1590", "name": "Gather Victim Org Information"},
    ],
    "dark_web": [
        {"tactic": "TA0043", "technique": "T1589", "name": "Gather Victim Identity Information"},
    ],
    "dead_drop": [
        {"tactic": "TA0011", "technique": "T1573", "name": "Encrypted Channel"},
    ],
    "covert_channel": [
        {"tactic": "TA0010", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    ],
    "cve": [
        {"tactic": "TA0042", "technique": "T1588.004", "name": "Exploits"},
    ],
    "api_discovery": [
        {"tactic": "TA0007", "technique": "T1046", "name": "Network Service Discovery"},
    ],
    "cloud_infrastructure": [
        {"tactic": "TA0043", "technique": "T1580", "name": "Cloud Infrastructure Discovery"},
    ],
    "container": [
        {"tactic": "TA0002", "technique": "T1610", "name": "Deploy Container"},
    ],
}

# Category → CWE mappings
CWE_MAP: Dict[str, List[str]] = {
    "sqli": ["CWE-89", "CWE-564"],
    "xss": ["CWE-79", "CWE-87"],
    "ssrf": ["CWE-918", "CWE-927"],
    "rce": ["CWE-78", "CWE-94"],
    "auth_bypass": ["CWE-287", "CWE-306", "CWE-862"],
    "privilege_escalation": ["CWE-269", "CWE-427"],
    "credential_theft": ["CWE-522", "CWE-798", "CWE-259"],
    "info_disclosure": ["CWE-200", "CWE-215"],
    "data_exposure": ["CWE-200", "CWE-359"],
    "misconfiguration": ["CWE-16", "CWE-2", "CWE-614"],
    "crypto_failure": ["CWE-327", "CWE-328", "CWE-326"],
    "dos": ["CWE-400", "CWE-770"],
    "injection": ["CWE-74", "CWE-78", "CWE-917"],
    "xxe": ["CWE-611", "CWE-827"],
    "default_credentials": ["CWE-798", "CWE-258"],
    "open_redirect": ["CWE-601"],
    "jwt_exposure": ["CWE-522", "CWE-613"],
    "beaconing": ["CWE-918", "CWE-862"],
    "steganography": ["CWE-218", "CWE-1004"],
    "supply_chain": ["CWE-1357", "CWE-829", "CWE-494"],
    "dns_recon": ["CWE-404", "CWE-350"],
    "tech_fingerprint": ["CWE-200"],
    "honeypot": ["CWE-200"],
    "dark_web": ["CWE-200", "CWE-522"],
    "dead_drop": ["CWE-918", "CWE-311"],
    "covert_channel": ["CWE-226", "CWE-311"],
    "container": ["CWE-94", "CWE-77"],
}

# Category → CAPEC mappings
CAPEC_MAP: Dict[str, List[str]] = {
    "sqli": ["CAPEC-66", "CAPEC-108"],
    "xss": ["CAPEC-86", "CAPEC-63"],
    "ssrf": ["CAPEC-664"],
    "rce": ["CAPEC-131", "CAPEC-165"],
    "auth_bypass": ["CAPEC-114", "CAPEC-600"],
    "privilege_escalation": ["CAPEC-122", "CAPEC-233"],
    "credential_theft": ["CAPEC-16", "CAPEC-547"],
    "info_disclosure": ["CAPEC-201", "CAPEC-352"],
    "data_exposure": ["CAPEC-201", "CAPEC-601"],
    "misconfiguration": ["CAPEC-213", "CAPEC-16"],
    "crypto_failure": ["CAPEC-97", "CAPEC-18"],
    "dos": ["CAPEC-125", "CAPEC-463"],
    "injection": ["CAPEC-100", "CAPEC-242"],
    "xxe": ["CAPEC-201", "CAPEC-219"],
    "default_credentials": ["CAPEC-16", "CAPEC-547"],
    "open_redirect": ["CAPEC-601"],
    "jwt_exposure": ["CAPEC-16"],
    "beaconing": ["CAPEC-664", "CAPEC-652"],
    "steganography": ["CAPEC-600", "CAPEC-166"],
    "supply_chain": ["CAPEC-441", "CAPEC-660"],
    "covert_channel": ["CAPEC-604", "CAPEC-157"],
}

# CVSS base score mapping by severity
CVSS_BASE_SCORES: Dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 3.5,
    "info": 1.0,
}


# ═══════════════════════════════════════════════════════════════════════════
# Severity helpers (canonical from constants.py)
# ═══════════════════════════════════════════════════════════════════════════

_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 10.0, "high": 8.0, "medium": 6.0, "low": 3.0, "info": 1.0,
}


def _sev_val(severity: str) -> float:
    return _SEVERITY_WEIGHTS.get(severity.lower(), 1.0)


# ═══════════════════════════════════════════════════════════════════════════
# FindingClassifier
# ═══════════════════════════════════════════════════════════════════════════

class FindingClassifier:
    """Classifies findings into attack categories using rule-based patterns.

    Uses title, description, evidence, and module name to determine the
    most likely attack category with a confidence score.
    """

    # (pattern, category, weight)
    _TITLE_RULES: List[Tuple[str, str, float]] = [
        (r"\bsql\b|\bsqli\b|injection.*sql", "sqli", 0.95),
        (r"\bxss\b|cross.?site.?script", "xss", 0.95),
        (r"\bssrf\b|server.?side.?request", "ssrf", 0.95),
        (r"\brce\b|remote.?code.?exec|code.?injection", "rce", 0.95),
        (r"auth.*bypass|bypass.*auth|unauthorized.*access", "auth_bypass", 0.90),
        (r"privilege.*escal|escalat.*priv", "privilege_escalation", 0.90),
        (r"default.*cred|credential.*exposure|password.*leak|credential.*theft", "credential_theft", 0.90),
        (r"sensitive.*data.*expos|data.*leak|information.*disclos", "data_exposure", 0.85),
        (r"misconfigur|security.*header|csp.*missing|hsts.*missing", "misconfiguration", 0.85),
        (r"weak.*encrypt|crypto.*fail|tls.*weak|ssl.*weak|no.*encrypt", "crypto_failure", 0.85),
        (r"denial.*service|dos\b|resource.*exhaust", "dos", 0.85),
        (r"\bxxe\b|xml.*external.*entity", "xxe", 0.95),
        (r"default.*password|default.*cred", "default_credentials", 0.90),
        (r"open.?redirect|url.*redirect", "open_redirect", 0.85),
        (r"jwt.*expos|token.*leak|bearer.*token", "jwt_exposure", 0.85),
        (r"sensitive.*api|api.*expos|swagger.*expos", "sensitive_api", 0.80),
        (r"beacon|c2.*channel|command.*control", "beaconing", 0.85),
        (r"steganograph|hidden.*data|covert.*embed", "steganography", 0.90),
        (r"supply.?chain|dependency.*vuln", "supply_chain", 0.85),
        (r"dns.*enum|dns.*zone|subdomain.*discov", "dns_recon", 0.85),
        (r"tech.*finger|technology.*detect|framework.*detect", "tech_fingerprint", 0.80),
        (r"waf|web.?app.*firewall", "waf_detected", 0.80),
        (r"security.*header|http.*header", "header_analysis", 0.80),
        (r"certificate|tls.*cert|ssl.*cert", "certificate", 0.80),
        (r"wayback|archive|cached.*version", "wayback", 0.80),
        (r"honeypot|trap.*detect", "honeypot", 0.85),
        (r"dark.?web|credential.*dump|leak.*database", "dark_web", 0.85),
        (r"dead.?drop|crypto.*drop", "dead_drop", 0.85),
        (r"covert.*channel|exfil.*channel", "covert_channel", 0.85),
        (r"cve-\d{4}-\d+", "cve", 0.90),
        (r"api.*discovery|endpoint.*discov", "api_discovery", 0.80),
        (r"cloud.*infra|aws.*expos|s3.*bucket", "cloud_infrastructure", 0.85),
        (r"container.*expos|docker.*misconf|kubernetes.*expos", "container", 0.85),
        (r"information.*disclos|info.*leak", "info_disclosure", 0.80),
        (r"injection", "injection", 0.80),
    ]

    _MODULE_RULES: Dict[str, str] = {
        "chain": "ssrf",
        "auth": "auth_bypass",
        "quantum_fingerprint": "tech_fingerprint",
        "dark_web_monitor": "dark_web",
        "info_ops": "info_disclosure",
        "steganography_detector": "steganography",
        "covert_channel": "covert_channel",
        "zero_day_hunter": "cve",
        "infrastructure_ghost": "infrastructure",
        "signal_intelligence": "beaconing",
        "nation_state_attributor": "infrastructure",
        "weaponized_report": "supply_chain",
        "honeypot_dance": "honeypot",
        "dead_drop": "dead_drop",
        "pegasus": "credential_theft",
        "cloud_recon": "cloud_infrastructure",
        "container_sec": "container",
        "iac_audit": "misconfiguration",
        "ast_analyzer": "supply_chain",
    }

    def classify(self, finding: Dict[str, Any]) -> ClassificationResult:
        """Classify a single finding into an attack category.

        Returns ClassificationResult with attack_category, confidence, and
        matching indicators.
        """
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        evidence = finding.get("evidence", "").lower()
        category = finding.get("category", "").lower()
        module = finding.get("module", "").lower()
        severity = finding.get("severity", "info").lower()

        scores: Dict[str, float] = defaultdict(float)
        indicators: Dict[str, List[str]] = defaultdict(list)

        # Phase 1: Title pattern matching
        combined = f"{title} {description}"
        for pattern, cat, weight in self._TITLE_RULES:
            if re.search(pattern, combined, re.IGNORECASE):
                scores[cat] += weight
                indicators[cat].append(f"title_match:{pattern[:20]}")

        # Phase 2: Module-based classification
        if module in self._MODULE_RULES:
            cat = self._MODULE_RULES[module]
            scores[cat] += 0.75
            indicators[cat].append(f"module_source:{module}")

        # Phase 3: Category hint
        if category:
            for pattern, cat, weight in self._TITLE_RULES:
                if re.search(pattern, category, re.IGNORECASE):
                    scores[cat] += 0.5
                    indicators[cat].append(f"category_hint:{category}")

        # Phase 4: Evidence enrichment
        for pattern, cat, weight in self._TITLE_RULES:
            if re.search(pattern, evidence, re.IGNORECASE):
                scores[cat] += 0.3
                indicators[cat].append(f"evidence_match:{pattern[:20]}")

        if not scores:
            return ClassificationResult(
                attack_category="misc",
                confidence=0.3,
                indicators=["no_patterns_matched"],
            )

        # Select best category
        best_cat = max(scores, key=scores.get)
        best_score = scores[best_cat]

        # Normalize confidence: weight by evidence strength
        has_evidence = len(evidence) > 10
        has_description = len(description) > 20
        evidence_boost = 0.15 if has_evidence else 0.0
        desc_boost = 0.1 if has_description else 0.0
        severity_boost = _sev_val(severity) / 100.0

        raw_conf = min(1.0, best_score / 2.0 + evidence_boost + desc_boost + severity_boost)

        return ClassificationResult(
            attack_category=best_cat,
            confidence=round(raw_conf, 2),
            indicators=indicators[best_cat][:5],
        )

    def classify_batch(self, findings: List[Dict[str, Any]]) -> List[ClassificationResult]:
        """Classify a batch of findings."""
        return [self.classify(f) for f in findings]


# ═══════════════════════════════════════════════════════════════════════════
# FindingCorrelator
# ═══════════════════════════════════════════════════════════════════════════

# Known attack chain templates: (category_a, category_b, chain_name)
_ATTACK_CHAIN_TEMPLATES: List[Tuple[str, str, str]] = [
    ("subdomain", "open_redirect", "Phishing Vector"),
    ("open_redirect", "credential_theft", "Credential Harvesting"),
    ("credential_theft", "auth_bypass", "Account Takeover"),
    ("auth_bypass", "privilege_escalation", "Privilege Escalation Chain"),
    ("misconfiguration", "data_exposure", "Data Breach"),
    ("data_exposure", "credential_theft", "Credential from Data"),
    ("sqli", "rce", "SQL Injection to RCE"),
    ("xss", "credential_theft", "XSS Credential Theft"),
    ("default_credentials", "privilege_escalation", "Default Creds to Root"),
    ("jwt_exposure", "privilege_escalation", "JWT to Admin"),
    ("sensitive_api", "data_exposure", "API Data Leak"),
    ("info_disclosure", "credential_theft", "Info to Credentials"),
    ("tech_fingerprint", "cve", "Fingerprint to Exploit"),
    ("dns_recon", "infrastructure", "DNS to Infrastructure Map"),
    ("infrastructure", "beaconing", "Infrastructure to C2"),
    ("supply_chain", "rce", "Supply Chain to RCE"),
    ("xxe", "ssrf", "XXE to SSRF"),
    ("auth_bypass", "sensitive_api", "Auth Bypass to API"),
]


class FindingCorrelator:
    """Correlates findings across modules to detect relationships.

    Groups findings by shared assets, detects duplicates, and identifies
    attack chains.
    """

    def correlate(self, findings: List[Dict[str, Any]]) -> Tuple[List[CorrelationGroup], List[Dict[str, Any]]]:
        """Correlate findings. Returns (correlation_groups, deduplicated_findings)."""
        if not findings:
            return [], []

        # Phase 1: Deduplicate
        unique, dedup_count = self._deduplicate(findings)

        # Phase 2: Group by shared asset
        asset_groups = self._group_by_asset(unique)

        # Phase 3: Detect attack chains
        chain_groups = self._detect_chains(unique)

        # Merge asset groups with chain groups (avoid duplicates)
        all_groups = self._merge_groups(asset_groups, chain_groups)

        return all_groups, unique

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
        """Remove duplicate findings based on title + asset + category."""
        seen: Dict[str, Dict[str, Any]] = {}
        dup_count = 0
        for f in findings:
            key = self._finding_hash(f)
            if key in seen:
                dup_count += 1
                # Keep the one with more evidence
                existing = seen[key]
                if len(f.get("evidence", "")) > len(existing.get("evidence", "")):
                    seen[key] = f
            else:
                seen[key] = f
        return list(seen.values()), dup_count

    @staticmethod
    def _finding_hash(f: Dict[str, Any]) -> str:
        """Create a deterministic hash for dedup."""
        raw = f"{f.get('title', '')}:{f.get('asset', '')}:{f.get('category', '')}".lower().strip()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _group_by_asset(self, findings: List[Dict[str, Any]]) -> List[CorrelationGroup]:
        """Group findings that share the same asset."""
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            asset = f.get("asset", "unknown")
            groups[asset].append(f)

        result: List[CorrelationGroup] = []
        for asset, items in groups.items():
            if len(items) < 2:
                continue
            sevs = [f.get("severity", "info") for f in items]
            combined_risk = self._compute_combined_risk(sevs)
            result.append(CorrelationGroup(
                findings=items,
                correlation_type="shared_asset",
                combined_risk=combined_risk,
                combined_confidence=0.7,
            ))
        return result

    def _detect_chains(self, findings: List[Dict[str, Any]]) -> List[CorrelationGroup]:
        """Detect attack chains using templates and category analysis."""
        MAX_PAIRS = 50000
        # Classify all findings
        classifier = FindingClassifier()
        classified: List[Tuple[Dict[str, Any], ClassificationResult]] = []
        for f in findings:
            cr = classifier.classify(f)
            classified.append((f, cr))

        chains: List[CorrelationGroup] = []
        # Check all pairs against chain templates (capped to prevent O(n²) exhaustion)
        pair_count = 0
        for i, j in combinations(range(len(classified)), 2):
            if pair_count >= MAX_PAIRS:
                break
            f_a, cr_a = classified[i]
            f_b, cr_b = classified[j]
            pair_count += 1
            for cat_a, cat_b, chain_name in _ATTACK_CHAIN_TEMPLATES:
                if (cr_a.attack_category == cat_a and cr_b.attack_category == cat_b) or \
                   (cr_b.attack_category == cat_a and cr_a.attack_category == cat_b):
                    # Verify shared asset or related
                    shared = (f_a.get("asset", "") == f_b.get("asset", "") or
                              self._assets_related(f_a.get("asset", ""), f_b.get("asset", "")))
                    if shared:
                        conf = min(cr_a.confidence, cr_b.confidence) * 0.8
                        chains.append(CorrelationGroup(
                            findings=[f_a, f_b],
                            correlation_type="attack_chain",
                            attack_chain=[chain_name],
                            combined_risk=self._max_severity([f_a, f_b]),
                            combined_confidence=round(conf, 2),
                        ))
        return chains

    @staticmethod
    def _assets_related(a: str, b: str) -> bool:
        """Check if two assets are related (same domain, subdomain)."""
        a, b = a.lower(), b.lower()
        if a == b:
            return True
        # Same base domain
        parts_a = a.replace("www.", "").split(".")
        parts_b = b.replace("www.", "").split(".")
        if len(parts_a) >= 2 and len(parts_b) >= 2:
            return parts_a[-2:] == parts_b[-2:]
        return False

    @staticmethod
    def _compute_combined_risk(severities: List[str]) -> str:
        """Compute combined risk from multiple severities."""
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if any(s == "medium" for s in severities) and len(severities) >= 2:
            return "high"
        return max(severities, key=lambda s: _SEVERITY_WEIGHTS.get(s, 1.0)) if severities else "low"

    @staticmethod
    def _max_severity(findings: List[Dict[str, Any]]) -> str:
        sevs = [f.get("severity", "info") for f in findings]
        for s in ["critical", "high", "medium", "low", "info"]:
            if s in sevs:
                return s
        return "info"

    def _merge_groups(self, asset_groups: List[CorrelationGroup],
                      chain_groups: List[CorrelationGroup]) -> List[CorrelationGroup]:
        """Merge asset groups and chain groups, preferring chains."""
        seen_sets: set = set()
        result = list(chain_groups)
        chain_keys = set()
        for cg in chain_groups:
            for f in cg.findings:
                chain_keys.add(self._finding_hash(f))

        for ag in asset_groups:
            # Only add asset groups that don't overlap with existing chain findings
            ag_keys = {self._finding_hash(f) for f in ag.findings}
            if not ag_keys & chain_keys:
                result.append(ag)

        return result


# ═══════════════════════════════════════════════════════════════════════════
# ExploitabilityEstimator
# ═══════════════════════════════════════════════════════════════════════════

class ExploitabilityEstimator:
    """Estimates exploit difficulty based on finding characteristics."""

    # Category-based exploitability baselines
    _CATEGORY_EXPLOITABILITY: Dict[str, float] = {
        "sqli": 0.85, "xss": 0.80, "rce": 0.90, "ssrf": 0.75,
        "auth_bypass": 0.70, "privilege_escalation": 0.75,
        "credential_theft": 0.65, "data_exposure": 0.70,
        "misconfiguration": 0.60, "crypto_failure": 0.55,
        "dos": 0.80, "default_credentials": 0.90,
        "open_redirect": 0.85, "jwt_exposure": 0.75,
        "sensitive_api": 0.70, "injection": 0.80,
        "xxe": 0.70, "supply_chain": 0.65,
    }

    def estimate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate exploitability metrics for a finding.

        Returns dict with exploitability, attacker_effort, likelihood, confidence.
        """
        severity = finding.get("severity", "info").lower()
        category = finding.get("category", "").lower()
        evidence = finding.get("evidence", "")
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        dread = finding.get("dread_score", 0.0)
        module = finding.get("module", "").lower()

        # Classify for category-based baseline
        classifier = FindingClassifier()
        cls = classifier.classify(finding)
        cat = cls.attack_category

        # Base exploitability from severity + category
        sev_exploit = _sev_val(severity) / 10.0
        cat_exploit = self._CATEGORY_EXPLOITABILITY.get(cat, 0.5)
        base_exploitability = (sev_exploit * 0.4 + cat_exploit * 0.4 + min(dread / 10.0, 1.0) * 0.2)

        # Evidence strength boost
        evidence_strength = min(len(evidence) / 200.0, 1.0)
        description_strength = min(len(description) / 150.0, 1.0)
        evidence_boost = (evidence_strength * 0.3 + description_strength * 0.2)

        exploitability = min(1.0, base_exploitability + evidence_boost * 0.15)

        # Attacker effort (inverse of exploitability)
        if exploitability >= 0.8:
            effort = "low"
        elif exploitability >= 0.6:
            effort = "medium"
        elif exploitability >= 0.4:
            effort = "high"
        else:
            effort = "very_high"

        # Likelihood
        likelihood = min(1.0, exploitability * 0.8 + evidence_boost * 0.2)

        # Confidence
        confidence = min(1.0, cls.confidence * 0.6 + evidence_strength * 0.3 + 0.1)

        return {
            "exploitability": round(exploitability, 2),
            "attacker_effort": effort,
            "likelihood": round(likelihood, 2),
            "confidence": round(confidence, 2),
        }


# ═══════════════════════════════════════════════════════════════════════════
# BusinessImpactAnalyzer
# ═══════════════════════════════════════════════════════════════════════════

# Asset sensitivity hints
_ASSET_SENSITIVITY: Dict[str, float] = {
    "production": 1.0, "prod": 1.0, "api": 0.8, "admin": 0.95,
    "staging": 0.5, "dev": 0.3, "test": 0.2, "demo": 0.1,
}

_IMPACT_DIMENSIONS: List[str] = ["financial", "reputational", "operational", "compliance", "legal"]


class BusinessImpactAnalyzer:
    """Estimates business impact of findings."""

    def analyze(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze business impact of a finding.

        Returns dict with impact_score, impact_description, affected_dimensions.
        """
        severity = finding.get("severity", "info").lower()
        asset = finding.get("asset", "").lower()
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        category = finding.get("category", "").lower()

        classifier = FindingClassifier()
        cls = classifier.classify(finding)

        # Base impact from severity
        sev_impact = _sev_val(severity) / 10.0

        # Asset sensitivity
        asset_sensitivity = 0.5
        for hint, score in _ASSET_SENSITIVITY.items():
            if hint in asset:
                asset_sensitivity = max(asset_sensitivity, score)

        # Category impact modifier
        cat_impacts = {
            "data_exposure": 0.9, "credential_theft": 0.85, "rce": 0.95,
            "privilege_escalation": 0.9, "sqli": 0.85, "supply_chain": 0.8,
            "auth_bypass": 0.8, "crypto_failure": 0.7, "misconfiguration": 0.6,
            "info_disclosure": 0.65, "beaconing": 0.75, "dark_web": 0.7,
        }
        cat_impact = cat_impacts.get(cls.attack_category, 0.5)

        impact_score = sev_impact * 0.4 + asset_sensitivity * 0.3 + cat_impact * 0.3
        impact_score = min(1.0, impact_score)

        # Determine affected dimensions
        affected = []
        if cls.attack_category in ("data_exposure", "credential_theft", "dark_web", "crypto_failure"):
            affected.extend(["financial", "compliance", "legal"])
        if cls.attack_category in ("rce", "privilege_escalation", "auth_bypass", "sqli"):
            affected.extend(["financial", "operational", "reputational"])
        if cls.attack_category in ("misconfiguration", "info_disclosure", "beaconing"):
            affected.extend(["compliance", "operational"])
        if not affected:
            affected = ["operational"]

        # Generate description
        sev_word = severity.upper()
        cat_name = cls.attack_category.replace("_", " ")
        desc = (
            f"A {sev_word}-severity {cat_name} finding affecting {asset or 'the target'}. "
            f"This could result in {'significant' if impact_score > 0.7 else 'moderate' if impact_score > 0.4 else 'minor'} "
            f"business impact across {', '.join(affected[:3])} dimensions."
        )

        return {
            "impact_score": round(impact_score, 2),
            "impact_description": desc,
            "affected_dimensions": list(set(affected)),
        }


# ═══════════════════════════════════════════════════════════════════════════
# AttackPathDetector
# ═══════════════════════════════════════════════════════════════════════════

# Multi-step chain templates (ordered sequences of categories)
_MULTI_STEP_CHAINS: List[Tuple[List[str], str, str]] = [
    (["subdomain", "tech_fingerprint", "cve"], "Recon to Exploit", "high"),
    (["open_redirect", "credential_theft", "auth_bypass", "privilege_escalation"], "Full Account Takeover", "critical"),
    (["default_credentials", "privilege_escalation", "data_exposure"], "Creds to Data Breach", "critical"),
    (["misconfiguration", "sensitive_api", "data_exposure"], "Misconfig to Data Leak", "high"),
    (["info_disclosure", "credential_theft", "auth_bypass"], "Info to Account Compromise", "high"),
    (["xss", "credential_theft", "privilege_escalation"], "XSS to Privilege Esc", "high"),
    (["sqli", "rce", "credential_theft"], "SQLi to RCE to Credentials", "critical"),
    (["tech_fingerprint", "misconfiguration", "cve"], "Fingerprint to Misconfig to Exploit", "high"),
    (["supply_chain", "rce", "data_exposure"], "Supply Chain Attack", "critical"),
    (["dns_recon", "infrastructure", "beaconing"], "Recon to C2 Detection", "medium"),
    (["infrastructure", "credential_theft", "privilege_escalation"], "Infra Recon to Compromise", "high"),
]


class AttackPathDetector:
    """Detects attack paths across findings.

    Chains individual findings into multi-step attack sequences
    and estimates path complexity, likelihood, and impact.
    """

    def detect(self, findings: List[Dict[str, Any]]) -> List[AttackPath]:
        """Detect attack paths from a list of findings.

        Returns a list of AttackPath objects sorted by confidence.
        """
        if len(findings) < 2:
            return []

        classifier = FindingClassifier()
        classified: List[Tuple[Dict[str, Any], ClassificationResult]] = []
        for f in findings:
            cr = classifier.classify(f)
            classified.append((f, cr))

        paths: List[AttackPath] = []

        # Check multi-step chain templates
        for chain_cats, name, risk in _MULTI_STEP_CHAINS:
            matching = self._find_matching_sequence(chain_cats, classified)
            if matching and len(matching) >= 2:
                path = self._build_path(matching, name, risk)
                if path:
                    paths.append(path)

        # Detect two-step pairs
        for cat_a, cat_b, chain_name in _ATTACK_CHAIN_TEMPLATES:
            matching = self._find_pair(cat_a, cat_b, classified)
            if matching:
                path = self._build_two_step_path(matching, chain_name)
                if path:
                    paths.append(path)

        # Sort by confidence
        paths.sort(key=lambda p: p.confidence, reverse=True)
        return paths

    def _find_matching_sequence(
        self, chain_cats: List[str],
        classified: List[Tuple[Dict[str, Any], ClassificationResult]],
    ) -> List[Dict[str, Any]]:
        """Find findings that match a chain template sequence."""
        matched: List[Dict[str, Any]] = []
        for cat in chain_cats:
            for f, cr in classified:
                if cr.attack_category == cat and f not in matched:
                    matched.append(f)
                    break
        return matched

    def _find_pair(
        self, cat_a: str, cat_b: str,
        classified: List[Tuple[Dict[str, Any], ClassificationResult]],
    ) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Find a pair of findings matching a two-step chain."""
        a_match = None
        b_match = None
        for f, cr in classified:
            if cr.attack_category == cat_a and a_match is None:
                a_match = f
            elif cr.attack_category == cat_b and b_match is None:
                b_match = f
            if a_match and b_match:
                return (a_match, b_match)
        return None

    def _build_path(self, findings: List[Dict[str, Any]], name: str, risk: str) -> Optional[AttackPath]:
        """Build an AttackPath from a matched finding sequence."""
        if not findings:
            return None

        steps = [
            {
                "title": f.get("title", ""),
                "category": f.get("category", ""),
                "severity": f.get("severity", "info"),
                "asset": f.get("asset", ""),
            }
            for f in findings
        ]

        # Compute aggregate metrics
        severities = [f.get("severity", "info") for f in findings]
        avg_exploit = sum(_sev_val(s) for s in severities) / len(severities) / 10.0
        likelihood = min(1.0, avg_exploit * 0.7 + 0.2)
        impact = _sev_val(risk if risk in _SEVERITY_WEIGHTS else "high") / 10.0

        # Complexity based on chain length
        if len(findings) >= 4:
            complexity = "very_high"
        elif len(findings) >= 3:
            complexity = "high"
        elif len(findings) >= 2:
            complexity = "medium"
        else:
            complexity = "low"

        narrative = (
            f"Attack path '{name}': An attacker could progress through {len(findings)} "
            f"stages — starting with '{steps[0]['title']}' against {steps[0].get('asset', 'target')}, "
            f"progressing through intermediate vulnerabilities, "
            f"and achieving '{steps[-1]['title']}' as the final objective. "
            f"Overall risk: {risk}. Complexity: {complexity}."
        )

        return AttackPath(
            steps=steps,
            entry_point=steps[0].get("asset", ""),
            objective=name,
            complexity=complexity,
            likelihood=round(likelihood, 2),
            impact=round(impact, 2),
            confidence=round(min(1.0, likelihood * impact), 2),
            narrative=narrative,
        )

    def _build_two_step_path(self, pair: Tuple[Dict[str, Any], Dict[str, Any]],
                             name: str) -> Optional[AttackPath]:
        """Build a two-step AttackPath."""
        return self._build_path(list(pair), name, "high")


# ═══════════════════════════════════════════════════════════════════════════
# RemediationPrioritizer
# ═══════════════════════════════════════════════════════════════════════════


class RemediationPrioritizer:
    """Prioritizes remediation based on multiple risk factors."""

    def prioritize(self, extended_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by remediation priority.

        Considers: severity, exploitability, business impact, blast radius, fix complexity.
        Returns ordered list with priority_rank and reasoning.
        """
        if not extended_findings:
            return []

        scored: List[Tuple[float, int, Dict[str, Any]]] = []
        for i, ef in enumerate(extended_findings):
            priority = self._compute_priority(ef)
            scored.append((priority, i, ef))

        scored.sort(key=lambda x: x[0], reverse=True)

        result: List[Dict[str, Any]] = []
        for rank, (score, orig_idx, ef) in enumerate(scored, 1):
            entry = dict(ef)
            entry["priority_rank"] = rank
            entry["priority_score"] = round(score, 2)
            entry["priority_reasoning"] = self._reasoning(ef, score, rank)
            result.append(entry)

        return result

    def _compute_priority(self, ef: Dict[str, Any]) -> float:
        """Compute a priority score (higher = fix first)."""
        severity = ef.get("severity", "info").lower()
        exploitability = ef.get("exploitability", 0.5)
        impact = ef.get("business_impact_score", 0.5)
        confidence = ef.get("confidence_score", 0.5)

        sev_weight = _sev_val(severity) / 10.0
        return (sev_weight * 0.35 + exploitability * 0.25 +
                impact * 0.25 + confidence * 0.15)

    def _reasoning(self, ef: Dict[str, Any], score: float, rank: int) -> str:
        """Generate a human-readable reasoning for the priority."""
        severity = ef.get("severity", "info").upper()
        exploit = ef.get("exploitability", 0.5)
        impact = ef.get("business_impact_score", 0.5)
        title = ef.get("title", "Unknown")

        parts = [f"#{rank} priority"]
        if severity == "CRITICAL":
            parts.append("critical severity")
        elif severity == "HIGH":
            parts.append("high severity")
        if exploit >= 0.7:
            parts.append("easily exploitable")
        if impact >= 0.7:
            parts.append("high business impact")
        parts.append(f"(score: {score:.2f})")

        return f"{'; '.join(parts)} — {title}"


# ═══════════════════════════════════════════════════════════════════════════
# Mapping Resolver
# ═══════════════════════════════════════════════════════════════════════════


def resolve_mappings(attack_category: str) -> Tuple[Dict[str, str], List[str], List[str]]:
    """Resolve MITRE ATT&CK, CWE, and CAPEC mappings for a category.

    Returns (mitre_primary, cwe_list, capec_list).
    """
    mitre_entries = MITRE_ATTACK_MAP.get(attack_category, [])
    mitre_primary: Dict[str, str] = {}
    if mitre_entries:
        m = mitre_entries[0]
        mitre_primary = {"tactic": m["tactic"], "technique": m["technique"], "name": m["name"]}

    cwe_list = CWE_MAP.get(attack_category, [])
    capec_list = CAPEC_MAP.get(attack_category, [])

    return mitre_primary, cwe_list, capec_list


def generate_cvss(severity: str, exploitability: float = 0.5, impact: float = 0.5) -> Dict[str, Any]:
    """Generate a CVSS v3 interpretation from severity and metrics.

    Returns dict with base_score, severity, vector_string.
    """
    base = CVSS_BASE_SCORES.get(severity.lower(), 5.0)

    # Adjust based on exploitability and impact
    adj = base + (exploitability - 0.5) * 1.5 + (impact - 0.5) * 2.0
    base_score = round(max(0.0, min(10.0, adj)), 1)

    if base_score >= 9.0:
        sev = "CRITICAL"
    elif base_score >= 7.0:
        sev = "HIGH"
    elif base_score >= 4.0:
        sev = "MEDIUM"
    elif base_score > 0.0:
        sev = "LOW"
    else:
        sev = "NONE"

    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (typical remote vuln)
    if exploitability >= 0.7:
        av, ac, pr, ui = "N", "L", "N", "N"
    elif exploitability >= 0.4:
        av, ac, pr, ui = "N", "L", "L", "N"
    else:
        av, ac, pr, ui = "N", "H", "L", "R"

    c = "H" if impact >= 0.7 else ("L" if impact >= 0.3 else "N")
    i = "H" if impact >= 0.7 else ("L" if impact >= 0.4 else "N")
    a = "H" if impact >= 0.8 else ("L" if impact >= 0.3 else "N")

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:U/C:{c}/I:{i}/A:{a}"

    return {
        "base_score": base_score,
        "severity": sev,
        "vector_string": vector,
    }


def generate_remediation_plan(attack_category: str, severity: str, finding: Dict[str, Any]) -> List[str]:
    """Generate a remediation plan for a finding."""
    base_steps = {
        "sqli": [
            "Implement parameterized queries (prepared statements) for all database operations",
            "Apply input validation using allow-lists for expected data formats",
            "Deploy a Web Application Firewall (WAF) with SQL injection detection rules",
            "Conduct a full audit of all database interaction points",
        ],
        "xss": [
            "Implement context-aware output encoding for all user-supplied data",
            "Deploy Content Security Policy (CSP) headers with strict directive configuration",
            "Sanitize input on the server side using established HTML encoding libraries",
            "Enable XSS protection modes in browser response headers",
        ],
        "ssrf": [
            "Implement URL whitelist validation for all server-side HTTP requests",
            "Block requests to private IP ranges and internal hostnames",
            "Disable unnecessary URL schemes (file://, gopher://, etc.)",
            "Implement network segmentation to prevent SSRF reaching internal services",
        ],
        "rce": [
            "Implement strict input validation and sanitization for all user inputs",
            "Apply the principle of least privilege to application service accounts",
            "Deploy application sandboxing or container isolation",
            "Review and disable all unnecessary system commands and eval functions",
        ],
        "auth_bypass": [
            "Implement robust authentication with multi-factor authentication (MFA)",
            "Apply proper session management with secure, random session tokens",
            "Implement account lockout policies after failed authentication attempts",
            "Review all authentication endpoints for business logic bypasses",
        ],
        "default_credentials": [
            "Change all default credentials to strong, unique passwords",
            "Disable default accounts that are not required for operation",
            "Implement a credential rotation policy",
            "Add monitoring for login attempts using default credentials",
        ],
        "misconfiguration": [
            "Review and harden all security-related configuration settings",
            "Implement security headers (CSP, HSTS, X-Frame-Options, etc.)",
            "Disable directory listing and verbose error messages",
            "Establish a configuration management baseline and drift detection",
        ],
        "data_exposure": [
            "Implement encryption at rest for all sensitive data stores",
            "Review and restrict access controls on exposed data endpoints",
            "Enable data loss prevention (DLP) controls",
            "Conduct a data classification audit and apply appropriate controls",
        ],
    }

    steps = base_steps.get(attack_category, [
        f"Review and remediate the {attack_category.replace('_', ' ')} vulnerability",
        "Apply security best practices for the affected component",
        "Implement monitoring and alerting for related attack patterns",
        "Conduct a follow-up assessment to verify remediation effectiveness",
    ])

    if severity.lower() == "critical":
        steps.insert(0, "CRITICAL: Immediately isolate affected systems and assess active exploitation")
    elif severity.lower() == "high":
        steps.insert(0, "HIGH: Prioritize remediation within 24-48 hours")

    return steps


def generate_validation_steps(attack_category: str) -> List[str]:
    """Generate steps to validate a fix was successful."""
    return [
        f"Re-run the {attack_category.replace('_', ' ')} detection module against the target",
        "Verify the fix prevents the original attack vector",
        "Test with alternative attack payloads to ensure comprehensive coverage",
        "Review logs for any residual exploitation attempts",
        "Document the fix and add regression test cases",
    ]


# ═══════════════════════════════════════════════════════════════════════════
# AIAnalystEngine — Orchestrator
# ═══════════════════════════════════════════════════════════════════════════


class AIAnalystEngine:
    """Orchestrates all AI analyst components.

    Runs classification, correlation, exploitability analysis, business impact,
    attack path detection, and remediation prioritization on scan findings.
    Produces a comprehensive AnalysisReport.
    """

    def __init__(self) -> None:
        self.classifier = FindingClassifier()
        self.correlator = FindingCorrelator()
        self.exploit_estimator = ExploitabilityEstimator()
        self.impact_analyzer = BusinessImpactAnalyzer()
        self.path_detector = AttackPathDetector()
        self.prioritizer = RemediationPrioritizer()

    def analyze_scan(self, findings: List[Dict[str, Any]], target: str = "") -> AnalysisReport:
        """Run full AI analysis on scan findings.

        Parameters:
            findings: List of finding dicts (from ReconProResult.findings)
            target: Target hostname or URL

        Returns:
            AnalysisReport with all analysis results.
        """
        t0 = time.monotonic()

        report = AnalysisReport(target=target, total_findings=len(findings))

        if not findings:
            report.summary = "No findings to analyze."
            report.analysis_duration_ms = (time.monotonic() - t0) * 1000
            return report

        # Phase 1: Classify all findings
        classifications = self.classifier.classify_batch(findings)
        report.classified = [
            {**f, "classification": cr.to_dict() if hasattr(cr, 'to_dict') else {
                "attack_category": cr.attack_category,
                "confidence": cr.confidence,
                "indicators": cr.indicators,
                "sub_category": cr.sub_category,
            }}
            for f, cr in zip(findings, classifications)
        ]

        # Phase 1.5: Reduce false positives
        findings_before_fp = len(findings)
        findings = self._reduce_false_positives(findings)
        findings_after_fp = len(findings)
        report.false_positive_reduction = {
            "before": findings_before_fp,
            "after": findings_after_fp,
            "removed": findings_before_fp - findings_after_fp,
        }

        # Phase 2: Correlate and deduplicate
        correlation_groups, deduped = self.correlator.correlate(findings)
        report.dedup_count = len(findings) - len(deduped)
        report.correlated = [
            {
                "correlation_type": cg.correlation_type,
                "finding_count": len(cg.findings),
                "combined_risk": cg.combined_risk,
                "combined_confidence": cg.combined_confidence,
                "attack_chain": cg.attack_chain,
                "finding_titles": [f.get("title", "") for f in cg.findings],
            }
            for cg in correlation_groups
        ]

        # Phase 3: Detect attack paths
        attack_paths = self.path_detector.detect(deduped)
        report.attack_paths = [
            {
                "entry_point": ap.entry_point,
                "objective": ap.objective,
                "complexity": ap.complexity,
                "likelihood": ap.likelihood,
                "impact": ap.impact,
                "confidence": ap.confidence,
                "narrative": ap.narrative,
                "step_count": len(ap.steps),
                "steps": ap.steps,
            }
            for ap in attack_paths
        ]

        # Phase 4: Extend findings with full analysis
        extended: List[Dict[str, Any]] = []
        for f, cr in zip(deduped, self.classifier.classify_batch(deduped)):
            ef = self._enrich_finding(f, cr)
            extended.append(ef)
        report.extended_findings = extended

        # Phase 5: Prioritize remediation
        prioritized = self.prioritizer.prioritize(extended)
        report.prioritized = prioritized

        # Phase 6: Generate summary
        report.summary = self._generate_summary(deduped, attack_paths, correlation_groups, target)

        report.asset_criticality = self._analyze_asset_criticality(deduped)

        report.analysis_duration_ms = round((time.monotonic() - t0) * 1000, 2)
        return report

    def _enrich_finding(self, finding: Dict[str, Any],
                        classification: ClassificationResult) -> Dict[str, Any]:
        """Enrich a single finding with all analysis dimensions."""
        cat = classification.attack_category

        # Exploitability
        exploit = self.exploit_estimator.estimate(finding)

        # Business Impact
        impact = self.impact_analyzer.analyze(finding)

        # Mappings
        mitre, cwe, capec = resolve_mappings(cat)

        # CVSS
        cvss = generate_cvss(
            finding.get("severity", "info"),
            exploit.get("exploitability", 0.5),
            impact.get("impact_score", 0.5),
        )

        # Remediation plan
        remediation_steps = generate_remediation_plan(
            cat, finding.get("severity", "info"), finding
        )
        validation_steps = generate_validation_steps(cat)

        # Confidence
        evidence = finding.get("evidence", "")
        description = finding.get("description", "")
        evidence_strength = min(len(evidence) / 200.0, 1.0)
        desc_strength = min(len(description) / 150.0, 1.0)
        confidence = min(1.0, classification.confidence * 0.5 + evidence_strength * 0.3 + desc_strength * 0.2)

        # Root cause inference
        root_cause = self._infer_root_cause(cat, finding)

        # Executive summary
        severity = finding.get("severity", "info").upper()
        exec_summary = (
            f"A {severity}-severity {cat.replace('_', ' ')} vulnerability was identified "
            f"affecting {finding.get('asset', 'the target')}. "
            f"Exploitability is assessed as {exploit.get('attacker_effort', 'medium')} "
            f"with a business impact score of {impact.get('impact_score', 0.5):.0%}."
        )
        if confidence < 0.3:
            exec_summary += " NOTE: Limited evidence available; assessment is probabilistic."

        # Uncertainty note
        uncertainty = ""
        if confidence < 0.3:
            uncertainty = "Limited evidence; results are probabilistic and should be validated manually."
        elif confidence < 0.5:
            uncertainty = "Moderate evidence; some findings may require manual verification."

        # Supporting evidence
        supporting = []
        if evidence:
            supporting.append(f"Raw evidence: {evidence[:200]}")
        if finding.get("module"):
            supporting.append(f"Detected by module: {finding.get('module')}")
        if classification.indicators:
            supporting.append(f"Classification indicators: {', '.join(classification.indicators[:3])}")

        return {
            **finding,
            "attack_category": cat,
            "classification_confidence": classification.confidence,
            "executive_summary": exec_summary,
            "technical_explanation": self._technical_explanation(finding, cat, exploit, impact),
            "attack_narrative": self._attack_narrative(finding, cat),
            "risk_justification": f"Severity: {severity}, Exploitability: {exploit.get('exploitability', 0):.0%}, "
                                  f"Business Impact: {impact.get('impact_score', 0):.0%}, "
                                  f"Confidence: {confidence:.0%}",
            "business_impact": impact.get("impact_description", ""),
            "mitre_attack_mapping": mitre,
            "cwe_mapping": cwe,
            "capec_mapping": capec,
            "cvss_interpretation": cvss,
            "remediation_plan": remediation_steps,
            "validation_steps": validation_steps,
            "confidence_score": round(confidence, 2),
            "supporting_evidence": supporting,
            "exploitability": exploit.get("exploitability", 0.5),
            "business_impact_score": impact.get("impact_score", 0.5),
            "attacker_effort": exploit.get("attacker_effort", "medium"),
            "likelihood": exploit.get("likelihood", 0.5),
            "root_cause": root_cause,
            "uncertainty_note": uncertainty,
        }

    def _infer_root_cause(self, cat: str, finding: Dict[str, Any]) -> str:
        """Infer the root cause from the category and finding details."""
        root_causes = {
            "sqli": "Application constructs SQL queries by concatenating user-supplied input without parameterization",
            "xss": "Application renders user-supplied content without proper output encoding or sanitization",
            "ssrf": "Application makes server-side HTTP requests using user-controlled URLs without validation",
            "rce": "Application executes system commands or evaluates code derived from user input without sanitization",
            "auth_bypass": "Authentication mechanism contains a logic flaw or missing access control check",
            "default_credentials": "System or application deployed with factory-default credentials that were never changed",
            "misconfiguration": "Security controls, headers, or server settings not configured according to best practices",
            "data_exposure": "Sensitive data is stored, transmitted, or accessible without proper encryption or access controls",
            "privilege_escalation": "Insufficient privilege separation allows lower-privileged users to gain elevated access",
            "credential_theft": "Credentials are stored, transmitted, or displayed in an insecure manner",
            "crypto_failure": "Weak, deprecated, or improperly implemented cryptographic algorithms or protocols",
            "info_disclosure": "Application reveals sensitive information through error messages, responses, or metadata",
            "injection": "User-supplied data is interpreted as code or commands without proper sanitization",
            "xxe": "XML parser processes external entity references without disabling DTD processing",
            "supply_chain": "A dependency or upstream component contains a known vulnerability",
        }
        return root_causes.get(cat, "Insufficient security controls for the identified vulnerability class")

    def _technical_explanation(self, finding: Dict[str, Any], cat: str,
                               exploit: Dict[str, Any], impact: Dict[str, Any]) -> str:
        """Generate a technical explanation of the finding."""
        title = finding.get("title", "Unknown vulnerability")
        evidence = finding.get("evidence", "")
        module = finding.get("module", "")

        return (
            f"The {cat.replace('_', ' ')} finding '{title}' was detected by the {module} module. "
            f"The vulnerability allows an attacker to exploit the target with {exploit.get('attacker_effort', 'medium')} effort "
            f"(exploitability: {exploit.get('exploitability', 0):.0%}). "
            f"The business impact is assessed at {impact.get('impact_score', 0):.0%} "
            f"across {', '.join(impact.get('affected_dimensions', [])[:3])} dimensions. "
            f"{'Evidence: ' + evidence[:150] + '...' if len(evidence) > 10 else 'Limited evidence was captured.'}"
        )

    def _attack_narrative(self, finding: Dict[str, Any], cat: str) -> str:
        """Generate an attack narrative describing how an attacker might exploit this."""
        asset = finding.get("asset", "the target")
        severity = finding.get("severity", "info").upper()

        narratives = {
            "sqli": f"An attacker could craft a malicious SQL payload targeting {asset}, injecting arbitrary database commands to extract, modify, or delete sensitive data. In {severity} scenarios, this could lead to complete database compromise.",
            "xss": f"An attacker could inject malicious JavaScript into pages served by {asset}. When legitimate users visit these pages, the script executes in their browser, potentially stealing session tokens or performing actions on their behalf.",
            "ssrf": f"An attacker could manipulate server-side requests from {asset} to access internal services, cloud metadata endpoints, or other systems not directly exposed to the internet.",
            "rce": f"An attacker could execute arbitrary commands on the server hosting {asset}, potentially gaining full system access, installing malware, or pivoting to other systems in the network.",
            "auth_bypass": f"An attacker could circumvent authentication controls on {asset}, gaining unauthorized access to protected resources and functionality without valid credentials.",
            "default_credentials": f"An attacker could log into {asset} using well-known default credentials, gaining immediate unauthorized access with minimal effort.",
            "data_exposure": f"An attacker could access sensitive data from {asset} without authentication, potentially exposing customer records, credentials, proprietary information, or other confidential data.",
        }

        return narratives.get(cat, f"An attacker could exploit the {cat.replace('_', ' ')} vulnerability on {asset} to achieve unauthorized access or actions. The {severity} severity indicates significant potential impact.")

    def _generate_summary(self, findings: List[Dict[str, Any]],
                           attack_paths: List[AttackPath],
                           correlation_groups: List[CorrelationGroup],
                           target: str) -> str:
        """Generate an executive summary for the entire scan."""
        if not findings:
            return f"No security findings detected for {target}."

        total = len(findings)
        sev_counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            s = f.get("severity", "info").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        parts = [
            f"Scan of {target} identified {total} findings: "
            f"{sev_counts.get('critical', 0)} critical, "
            f"{sev_counts.get('high', 0)} high, "
            f"{sev_counts.get('medium', 0)} medium, "
            f"{sev_counts.get('low', 0)} low, "
            f"{sev_counts.get('info', 0)} informational.",
        ]

        if attack_paths:
            critical_paths = [p for p in attack_paths if p.impact >= 0.8]
            parts.append(
                f"{len(attack_paths)} potential attack paths detected"
                f"{', ' + str(len(critical_paths)) + ' of which are high-impact' if critical_paths else ''}."
            )

        if correlation_groups:
            parts.append(
                f"{len(correlation_groups)} correlation groups identified, "
                f"suggesting systematic weaknesses across multiple attack surfaces."
            )

        if sev_counts.get("critical", 0) > 0:
            parts.append(
                "CRITICAL findings require immediate remediation. "
                "These represent the highest risk to the organization."
            )
        elif sev_counts.get("high", 0) > 0:
            parts.append(
                "HIGH-severity findings should be prioritized for remediation "
                "within 24-48 hours."
            )

        return " ".join(parts)

    def _reduce_false_positives(self, findings: List[Dict]) -> List[Dict]:
        """Apply heuristic rules to identify likely false positives.
        
        Rules:
        1. Findings with very low severity and generic descriptions
        2. Duplicate findings with different titles but same asset+category
        3. Findings with empty or very short evidence
        4. Findings whose descriptions match common false-positive patterns
        """
        fp_indicators = [
            "example", "test", "sample", "demo", "placeholder",
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
            "staging", "development", "dev-", "test-",
        ]
        
        result = []
        seen_signatures = set()
        
        for f in findings:
            fp_score = 0  # 0 = definitely real, higher = more likely FP
            
            # Rule 1: Check for FP indicator terms in evidence
            evidence = f.get("evidence", "").lower()
            asset = f.get("asset", "").lower()
            title = f.get("title", "").lower()
            
            for indicator in fp_indicators:
                if indicator in evidence or indicator in asset:
                    fp_score += 2
                    break
            
            # Rule 2: Deduplicate by asset+category signature
            sig = f"{f.get('asset', '')}:{f.get('category', '')}:{str(f.get('severity', ''))}"
            if sig in seen_signatures and f.get("severity", "").lower() in ("info", "low"):
                fp_score += 3
            seen_signatures.add(sig)
            
            # Rule 3: Very short or empty evidence
            if len(evidence.strip()) < 10:
                fp_score += 2
            
            # Rule 4: Generic description patterns
            generic_patterns = [
                r'^a .* (was|is) (found|detected|discovered)$',
                r'^possible .*$',
                r'^potential .*$',
            ]
            import re
            desc = f.get("description", "").lower().strip()
            for pattern in generic_patterns:
                if re.match(pattern, desc):
                    fp_score += 1
                    break
            
            # Mark the finding with FP probability
            f["false_positive_probability"] = min(1.0, fp_score / 10.0)
            
            # Only exclude if very high FP score AND low severity
            if fp_score >= 6 and f.get("severity", "").lower() in ("info",):
                continue  # Skip likely false positive
            
            result.append(f)
        
        return result

    def _analyze_asset_criticality(self, findings: List[Dict]) -> Dict[str, float]:
        """Analyze asset criticality based on finding density and severity.
        
        Returns dict mapping asset names to criticality scores (0-100).
        Assets with more critical/high findings are more critical.
        """
        asset_data: Dict[str, Dict] = {}
        
        sev_weights = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0.5}
        
        for f in findings:
            asset = f.get("asset", "unknown")
            if asset not in asset_data:
                asset_data[asset] = {"findings": 0, "weighted_score": 0.0, "max_sev": 0}
            
            asset_data[asset]["findings"] += 1
            sev = f.get("severity", "info").lower()
            asset_data[asset]["weighted_score"] += sev_weights.get(sev, 0.5)
            asset_data[asset]["max_sev"] = max(
                asset_data[asset]["max_sev"],
                sev_weights.get(sev, 0.5)
            )
        
        # Normalize to 0-100
        max_weighted = max((d["weighted_score"] for d in asset_data.values()), default=1)
        
        criticality = {}
        for asset, data in asset_data.items():
            raw = (data["weighted_score"] / max(max_weighted, 1)) * 100
            # Boost if has critical findings
            if data["max_sev"] >= 10:
                raw = min(100, raw + 10)
            criticality[asset] = round(raw, 1)
        
        return criticality

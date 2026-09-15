"""ReconPro v11 — Threat Intelligence Center.

Centralized threat intelligence engine for enriching scan findings with
threat data from public standards (CVE, CWE, CAPEC, MITRE ATT&CK, CISA KEV,
EPSS, CVSS, OWASP). Supports offline operation with built-in mappings and
optional online enrichment via stdlib HTTP.

Pure Python. Zero external dependencies. All mappings are embedded.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from threading import Lock


# ═══════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ThreatRecord:
    """A single threat intelligence record."""
    source: str       # "CVE", "CWE", "CAPEC", "MITRE", "CISA_KEV", "EPSS", "OWASP"
    source_id: str
    name: str
    description: str = ""
    severity: str = "info"
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_updated: float = 0.0
    evidence_chain: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source, "source_id": self.source_id,
            "name": self.name, "description": self.description,
            "severity": self.severity, "confidence": round(self.confidence, 2),
            "metadata": self.metadata, "last_updated": self.last_updated,
            "evidence_chain": self.evidence_chain,
        }


@dataclass
class EnrichedFinding:
    """A finding enriched with threat intelligence."""
    original: Dict[str, Any]
    threat_records: List[Dict[str, Any]] = field(default_factory=list)
    cve_matches: List[str] = field(default_factory=list)
    cwe_matches: List[str] = field(default_factory=list)
    capec_matches: List[str] = field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    known_exploitation: bool = False
    active_exploitation: bool = False
    severity_evolution: str = "stable"  # "increasing", "stable", "decreasing"
    affected_technologies: List[str] = field(default_factory=list)
    threat_summary: str = ""
    enrichment_confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.original.get("title", ""),
            "severity": self.original.get("severity", "info"),
            "cve_matches": self.cve_matches,
            "cwe_matches": self.cwe_matches,
            "capec_matches": self.capec_matches,
            "mitre_techniques": self.mitre_techniques,
            "known_exploitation": self.known_exploitation,
            "active_exploitation": self.active_exploitation,
            "severity_evolution": self.severity_evolution,
            "affected_technologies": self.affected_technologies,
            "threat_summary": self.threat_summary,
            "enrichment_confidence": round(self.enrichment_confidence, 2),
            "threat_records": self.threat_records,
            "record_count": len(self.threat_records),
        }


@dataclass
class ThreatIntelReport:
    """Complete threat intelligence report for a scan."""
    target: str = ""
    enriched_findings: List[Dict[str, Any]] = field(default_factory=list)
    unique_cves: List[str] = field(default_factory=list)
    unique_cwes: List[str] = field(default_factory=list)
    unique_capecs: List[str] = field(default_factory=list)
    unique_mitre: List[Dict[str, str]] = field(default_factory=list)
    known_exploited_count: int = 0
    active_exploitation_count: int = 0
    technology_profile: Dict[str, int] = field(default_factory=dict)
    severity_trends: Dict[str, str] = field(default_factory=dict)
    threat_summary: str = ""
    cache_hits: int = 0
    cache_misses: int = 0
    online_queries: int = 0
    analysis_duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "enriched_count": len(self.enriched_findings),
            "unique_cves": self.unique_cves,
            "unique_cwes": self.unique_cwes,
            "unique_capecs": self.unique_capecs,
            "unique_mitre": self.unique_mitre,
            "known_exploited_count": self.known_exploited_count,
            "active_exploitation_count": self.active_exploitation_count,
            "technology_profile": self.technology_profile,
            "severity_trends": self.severity_trends,
            "threat_summary": self.threat_summary,
            "cache_stats": {"hits": self.cache_hits, "misses": self.cache_misses},
            "online_queries": self.online_queries,
            "analysis_duration_ms": self.analysis_duration_ms,
            "timestamp": self.timestamp,
            "enriched_findings": self.enriched_findings,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Built-in Threat Intelligence Database
# ═══════════════════════════════════════════════════════════════════════════

# CVE pattern → severity + description
_CVE_KNOWN_PATTERNS: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {"severity": "critical", "name": "Log4Shell",
                      "description": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI-related endpoints",
                      "affected": ["Apache Log4j 2.x"], "known_exploited": True},
    "CVE-2023-44487": {"severity": "high", "name": "HTTP/2 Rapid Reset",
                      "description": "HTTP/2 Rapid Reset attack can cause denial of service",
                      "affected": ["HTTP/2 servers"], "known_exploited": True},
    "CVE-2024-3094": {"severity": "critical", "name": "XZ Utils Backdoor",
                      "description": "Malicious code injection in xz-utils liblzma",
                      "affected": ["xz-utils", "liblzma", "OpenSSH"], "known_exploited": True},
    "CVE-2021-41773": {"severity": "high", "name": "Apache Path Traversal",
                      "description": "Path traversal and file disclosure vulnerability in Apache 2.4.49",
                      "affected": ["Apache HTTPD 2.4.49"], "known_exploited": True},
    "CVE-2023-38545": {"severity": "high", "name": "curl SOCKS5 Heap Buffer Overflow",
                      "description": "SOCKS5 heap buffer overflow in curl",
                      "affected": ["curl"], "known_exploited": True},
    "CVE-2023-36884": {"severity": "critical", "name": "Microsoft Office RCE",
                      "description": "RCE in Microsoft Office and Windows HTML",
                      "affected": ["Microsoft Office", "HTML"], "known_exploited": True},
    "CVE-2021-3449": {"severity": "high", "name": "OpenSSL ASN.1 Parsing",
                      "description": "Null pointer dereference in signature verification",
                      "affected": ["OpenSSL"], "known_exploited": False},
    "CVE-2023-22515": {"severity": "critical", "name": "Atlassian Confluence RCE",
                      "description": "Broken access control in Confluence Data Center and Server",
                      "affected": ["Atlassian Confluence"], "known_exploited": True},
    "CVE-2023-46604": {"severity": "critical", "name": "Apache ActiveMQ RCE",
                      "description": "Remote code execution in OpenWire protocol marshaller",
                      "affected": ["Apache ActiveMQ"], "known_exploited": True},
    "CVE-2024-0001": {"severity": "critical", "name": "Generic Critical CVE placeholder",
                      "description": "Critical vulnerability requiring immediate patching",
                      "affected": ["Unknown"], "known_exploited": False},
}

# CISA Known Exploited Vulnerabilities (KEV) catalog — subset
_CISA_KEV_CVE_LIST: set = {
    "CVE-2021-44228", "CVE-2023-44487", "CVE-2024-3094",
    "CVE-2021-41773", "CVE-2023-38545", "CVE-2023-36884",
    "CVE-2023-22515", "CVE-2023-46604",
}

# CWE detailed descriptions
_CWE_DATABASE: Dict[str, Dict[str, Any]] = {
    "CWE-89": {"name": "SQL Injection", "description": "Improper Neutralization of Special Elements used in an SQL Command", "risk": "high"},
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "description": "Improper Neutralization of Input During Web Page Generation", "risk": "high"},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "description": "Server-Side Request Forgery", "risk": "high"},
    "CWE-78": {"name": "OS Command Injection", "description": "Improper Neutralization of Special Elements used in an OS Command", "risk": "critical"},
    "CWE-287": {"name": "Improper Authentication", "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves the claim", "risk": "high"},
    "CWE-306": {"name": "Missing Authentication for Critical Function", "description": "The software does not perform authentication for functionality that requires a proven user identity", "risk": "critical"},
    "CWE-862": {"name": "Missing Authorization", "description": "The software does not perform an authorization check when an actor attempts to access a resource", "risk": "high"},
    "CWE-269": {"name": "Improper Privilege Management", "description": "The software does not assign or maintains privileges incorrectly", "risk": "high"},
    "CWE-522": {"name": "Insufficiently Protected Credentials", "description": "Credentials are stored in cleartext or inadequately protected", "risk": "high"},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "description": "The software contains hard-coded credentials for authentication", "risk": "high"},
    "CWE-200": {"name": "Information Exposure", "description": "Exposure of sensitive information to an actor that is not explicitly authorized", "risk": "medium"},
    "CWE-327": {"name": "Use of a Broken or Risky Cryptographic Algorithm", "description": "Use of a broken or risky cryptographic algorithm", "risk": "high"},
    "CWE-328": {"name": "Use of Weak Hash", "description": "Use of a weak hash algorithm for critical security decisions", "risk": "medium"},
    "CWE-400": {"name": "Uncontrolled Resource Consumption", "description": "The software does not properly control the allocation of resources", "risk": "medium"},
    "CWE-611": {"name": "XXE - XML External Entity", "description": "Processing of an XML document can cause the software to expose information or consume resources", "risk": "high"},
    "CWE-601": {"name": "URL Redirection to Untrusted Site", "description": "Open redirect vulnerability", "risk": "medium"},
    "CWE-94": {"name": "Code Injection", "description": "The software allows user input to be used as code", "risk": "critical"},
    "CWE-74": {"name": "Injection", "description": "The software constructs a command using externally-influenced input", "risk": "high"},
    "CWE-226": {"name": "Sensitive Information in Resource Not Removed Before Reuse", "description": "Sensitive data is not cleared before a resource is reused", "risk": "medium"},
    "CWE-218": {"name": "Sensitive Information in Resource Names", "description": "Resource names contain sensitive information", "risk": "medium"},
    "CWE-16": {"name": "Configuration", "description": "The software's configuration is insecure by default", "risk": "medium"},
    "CWE-2": {"name": "Environment", "description": "The software operates in an environment that is not properly secured", "risk": "medium"},
    "CWE-614": {"name": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", "description": "Cookie used in HTTPS session lacks Secure flag", "risk": "low"},
    "CWE-1357": {"name": "Reliance on Uncontrolled Component", "description": "The software relies on a third-party component without validating its integrity", "risk": "high"},
    "CWE-829": {"name": "Inclusion of Functionality from Untrusted Control Sphere", "description": "The software imports functionality from an untrusted control sphere", "risk": "high"},
    "CWE-494": {"name": "Download of Code Without Integrity Check", "description": "The software downloads code without verifying its integrity", "risk": "high"},
    "CWE-326": {"name": "Inadequate Encryption Strength", "description": "The algorithm uses insufficient encryption strength", "risk": "high"},
    "CWE-1004": {"name": "Sensitive Cookie Without 'HttpOnly' Flag", "description": "Cookie does not have HttpOnly flag set", "risk": "low"},
    "CWE-404": {"name": "Improper Resource Shutdown", "description": "The software does not release a resource properly", "risk": "low"},
    "CWE-350": {"name": "Reliance on Reverse DNS Resolution for Security", "description": "The software uses reverse DNS for security decisions", "risk": "medium"},
    "CWE-613": {"name": "Insufficient Session Expiration", "description": "Session tokens do not expire after a reasonable period", "risk": "medium"},
    "CWE-77": {"name": "Command Injection", "description": "The software constructs commands using user-controlled input", "risk": "critical"},
    "CWE-87": {"name": "Improper Neutralization of Alternate XSS Syntax", "description": "XSS via alternate encoding methods", "risk": "high"},
    "CWE-564": {"name": "SQL Injection: Hibernate", "description": "HQL/HQL injection in Hibernate ORM", "risk": "high"},
    "CWE-258": {"name": "Empty Password", "description": "Password field is empty", "risk": "high"},
    "CWE-259": {"name": "Use of Hard-coded Password", "description": "Hard-coded password in the software", "risk": "high"},
    "CWE-427": {"name": "Uncontrolled Search Path Element", "description": "Path traversal via uncontrolled search path", "risk": "high"},
}

# CAPEC detailed descriptions
_CAPEC_DATABASE: Dict[str, Dict[str, Any]] = {
    "CAPEC-66": {"name": "SQL Injection", "description": "Attacker injects SQL commands via input fields", "risk": "high"},
    "CAPEC-86": {"name": "Cross Site Scripting", "description": "Inject client-side scripts into web pages", "risk": "high"},
    "CAPEC-664": {"name": "Server Side Request Forgery", "description": "Force server to make requests to unintended locations", "risk": "high"},
    "CAPEC-131": {"name": "Resource Injection", "description": "Attacker injects resources that modify application behavior", "risk": "critical"},
    "CAPEC-165": {"name": "Flooding", "description": "Overwhelm target with excessive traffic or data", "risk": "medium"},
    "CAPEC-114": {"name": "Authentication Abuse", "description": "Exploit authentication mechanisms for unauthorized access", "risk": "high"},
    "CAPEC-600": {"name": "Unauthorized Active API Session", "description": "Reuse of authorized session tokens", "risk": "high"},
    "CAPEC-122": {"name": "Buffer Overflow", "description": "Write data past the end of allocated buffer", "risk": "critical"},
    "CAPEC-233": {"name": "Privilege Abuse", "description": "Abuse existing privileges to gain additional access", "risk": "high"},
    "CAPEC-16": {"name": "Dictionary Attack", "description": "Attempt to guess passwords from a dictionary", "risk": "medium"},
    "CAPEC-547": {"name": "Use of Known Default Credentials", "description": "Exploit default credentials on deployed systems", "risk": "high"},
    "CAPEC-201": {"name": "Data Filtration", "description": "Extract data through manipulation of query sequences", "risk": "medium"},
    "CAPEC-352": {"name": "Cross-Site Request Forgery", "description": "Force victim to execute unwanted actions on authenticated site", "risk": "medium"},
    "CAPEC-213": {"name": "Exploitation of Trust", "description": "Exploit implicit trust relationships between components", "risk": "high"},
    "CAPEC-97": {"name": "Data Interception", "description": "Intercept data transmitted between components", "risk": "high"},
    "CAPEC-18": {"name": "Cross-Site Scripting (XSS)", "description": "Inject malicious scripts via web application", "risk": "high"},
    "CAPEC-100": {"name": "OWASP Top Ten Manipulation", "description": "Exploit vulnerabilities from OWASP Top 10", "risk": "high"},
    "CAPEC-242": {"name": "Code Injection", "description": "Inject arbitrary code that is executed by the application", "risk": "critical"},
    "CAPEC-219": {"name": "XML External Entity Blowup", "description": "XXE attack causing resource exhaustion", "risk": "high"},
    "CAPEC-601": {"name": "URL Redirection to Malicious Site", "description": "Redirect victim to attacker-controlled URL", "risk": "medium"},
    "CAPEC-652": {"name": "Traffic Tunneling", "description": "Tunnel traffic through an allowed protocol", "risk": "high"},
    "CAPEC-600": {"name": "Session Sidejacking", "description": "Hijack an authenticated session", "risk": "high"},
    "CAPEC-166": {"name": "DOM-based Injection", "description": "Manipulate DOM environment from untrusted input", "risk": "high"},
    "CAPEC-441": {"name": "Malicious Dependency", "description": "Supply chain attack via malicious dependency", "risk": "critical"},
    "CAPEC-660": {"name": "Software Integrity Attack", "description": "Modify software supply chain to inject vulnerabilities", "risk": "critical"},
    "CAPEC-157": {"name": "Shared Data Manipulation", "description": "Modify shared data to exploit race conditions", "risk": "medium"},
    "CAPEC-604": {"name": "HTTP Request Splitting", "description": "Inject extra HTTP requests via malformed input", "risk": "medium"},
    "CAPEC-463": {"name": "HTTP Splitting", "description": "Manipulate HTTP request/response splitting", "risk": "medium"},
}

# MITRE ATT&CK Enterprise techniques (expanded)
_MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001", "risk": "critical"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002", "risk": "high"},
    "T1059.007": {"name": "JavaScript", "tactic": "TA0002", "risk": "high"},
    "T1189": {"name": "Drive-by Compromise", "tactic": "TA0001", "risk": "high"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001", "risk": "high"},
    "T1078.001": {"name": "Default Accounts", "tactic": "TA0001", "risk": "high"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "TA0004", "risk": "high"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004", "risk": "critical"},
    "T1110": {"name": "Brute Force", "tactic": "TA0006", "risk": "high"},
    "T1110.001": {"name": "Password Spraying", "tactic": "TA0006", "risk": "high"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "TA0006", "risk": "high"},
    "T1552.001": {"name": "Credentials in Files", "tactic": "TA0006", "risk": "high"},
    "T1566": {"name": "Phishing", "tactic": "TA0001", "risk": "high"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "TA0001", "risk": "high"},
    "T1046": {"name": "Network Service Discovery", "tactic": "TA0007", "risk": "medium"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "TA0007", "risk": "low"},
    "T1082": {"name": "System Information Discovery", "tactic": "TA0007", "risk": "medium"},
    "T1562": {"name": "Impair Defenses", "tactic": "TA0005", "risk": "high"},
    "T1573": {"name": "Encrypted Channel", "tactic": "TA0011", "risk": "medium"},
    "T1571": {"name": "Non-Standard Port", "tactic": "TA0011", "risk": "medium"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011", "risk": "medium"},
    "T1498": {"name": "Network Denial of Service", "tactic": "TA0040", "risk": "high"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040", "risk": "critical"},
    "T1001": {"name": "Data Obfuscation", "tactic": "TA0005", "risk": "medium"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010", "risk": "high"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010", "risk": "high"},
    "T1560": {"name": "Archive Collected Data", "tactic": "TA0009", "risk": "medium"},
    "T1213": {"name": "Data from Information Repositories", "tactic": "TA0009", "risk": "medium"},
    "T1595": {"name": "Active Scanning", "tactic": "TA0043", "risk": "low"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "TA0043", "risk": "low"},
    "T1590": {"name": "Gather Victim Org Information", "tactic": "TA0043", "risk": "low"},
    "T1590.002": {"name": "DNS", "tactic": "TA0043", "risk": "low"},
    "T1593": {"name": "Search Open Websites/Domains", "tactic": "TA0043", "risk": "low"},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "TA0043", "risk": "medium"},
    "T1583": {"name": "Acquire Infrastructure", "tactic": "TA0042", "risk": "medium"},
    "T1585": {"name": "Establish Accounts", "tactic": "TA0042", "risk": "medium"},
    "T1588.004": {"name": "Exploits", "tactic": "TA0042", "risk": "high"},
    "T1610": {"name": "Deploy Container", "tactic": "TA0002", "risk": "high"},
    "T1195.002": {"name": "Compromise Software Supply Chain", "tactic": "TA0042", "risk": "critical"},
    "T1580": {"name": "Cloud Infrastructure Discovery", "tactic": "TA0043", "risk": "medium"},
    "T1553": {"name": "Subvert Trust Controls", "tactic": "TA0003", "risk": "high"},
    "T1553.002": {"name": "Code Signing", "tactic": "TA0003", "risk": "high"},
    "T1070": {"name": "Indicator Removal", "tactic": "TA0005", "risk": "medium"},
    "T1070.005": {"name": "Network Traffic Capture", "tactic": "TA0005", "risk": "medium"},
}

# OWASP Top 10 (2021) mappings
_OWASP_TOP10: List[Dict[str, Any]] = [
    {"id": "A01", "name": "Broken Access Control", "categories": ["auth_bypass", "privilege_escalation", "jwt_exposure"], "cwe": ["CWE-287", "CWE-862", "CWE-306"]},
    {"id": "A02", "name": "Cryptographic Failures", "categories": ["crypto_failure"], "cwe": ["CWE-327", "CWE-328", "CWE-326"]},
    {"id": "A03", "name": "Injection", "categories": ["sqli", "xss", "injection", "xxe", "rce"], "cwe": ["CWE-89", "CWE-79", "CWE-78", "CWE-611"]},
    {"id": "A04", "name": "Insecure Design", "categories": ["misconfiguration", "info_disclosure"], "cwe": ["CWE-16", "CWE-200"]},
    {"id": "A05", "name": "Security Misconfiguration", "categories": ["misconfiguration", "default_credentials", "header_analysis"], "cwe": ["CWE-16", "CWE-2", "CWE-798"]},
    {"id": "A06", "name": "Vulnerable and Outdated Components", "categories": ["cve", "supply_chain"], "cwe": ["CWE-1357", "CWE-829", "CWE-494"]},
    {"id": "A07", "name": "Identification and Authentication Failures", "categories": ["auth_bypass", "credential_theft", "default_credentials"], "cwe": ["CWE-287", "CWE-522", "CWE-798"]},
    {"id": "A08", "name": "Software and Data Integrity Failures", "categories": ["supply_chain", "injection"], "cwe": ["CWE-1357", "CWE-494", "CWE-94"]},
    {"id": "A09", "name": "Security Logging and Monitoring Failures", "categories": ["info_disclosure"], "cwe": ["CWE-778"]},
    {"id": "A10", "name": "Server-Side Request Forgery", "categories": ["ssrf"], "cwe": ["CWE-918"]},
]


# ═══════════════════════════════════════════════════════════════════════════
# Category → Mapping Index (for quick lookup)
# ═══════════════════════════════════════════════════════════════════════════

_CATEGORY_TO_CWE: Dict[str, List[str]] = {
    "sqli": ["CWE-89", "CWE-564"],
    "xss": ["CWE-79", "CWE-87"],
    "ssrf": ["CWE-918"],
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
    "covert_channel": ["CWE-226", "CWE-311"],
    "cve": ["CWE-1357"],
}

_CATEGORY_TO_CAPEC: Dict[str, List[str]] = {
    "sqli": ["CAPEC-66"],
    "xss": ["CAPEC-86", "CAPEC-18"],
    "ssrf": ["CAPEC-664"],
    "rce": ["CAPEC-131", "CAPEC-242"],
    "auth_bypass": ["CAPEC-114", "CAPEC-600"],
    "privilege_escalation": ["CAPEC-122", "CAPEC-233"],
    "credential_theft": ["CAPEC-16", "CAPEC-547"],
    "info_disclosure": ["CAPEC-201"],
    "data_exposure": ["CAPEC-201", "CAPEC-601"],
    "misconfiguration": ["CAPEC-213"],
    "crypto_failure": ["CAPEC-97"],
    "dos": ["CAPEC-125", "CAPEC-463"],
    "injection": ["CAPEC-100", "CAPEC-242"],
    "xxe": ["CAPEC-219"],
    "default_credentials": ["CAPEC-16", "CAPEC-547"],
    "open_redirect": ["CAPEC-601"],
    "jwt_exposure": ["CAPEC-16"],
    "beaconing": ["CAPEC-664", "CAPEC-652"],
    "supply_chain": ["CAPEC-441", "CAPEC-660"],
}

_CATEGORY_TO_MITRE: Dict[str, List[str]] = {
    "sqli": ["T1190"],
    "xss": ["T1059.007", "T1189"],
    "ssrf": ["T1190", "T1046"],
    "rce": ["T1059", "T1548"],
    "auth_bypass": ["T1078", "T1110"],
    "privilege_escalation": ["T1548", "T1068"],
    "credential_theft": ["T1110.001", "T1552"],
    "info_disclosure": ["T1566", "T1083"],
    "data_exposure": ["T1560", "T1048"],
    "misconfiguration": ["T1082", "T1562"],
    "crypto_failure": ["T1573", "T1571"],
    "dos": ["T1498", "T1486"],
    "injection": ["T1059", "T1190"],
    "xxe": ["T1059.009", "T1190"],
    "default_credentials": ["T1110.001", "T1078.001"],
    "open_redirect": ["T1566.002"],
    "jwt_exposure": ["T1552.001", "T1553.002"],
    "beaconing": ["T1071", "T1573"],
    "steganography": ["T1001", "T1041"],
    "supply_chain": ["T1585", "T1195.002"],
    "cve": ["T1588.004"],
}

_CATEGORY_PATTERNS: List[Tuple[str, str, float]] = [
    (r"\bsql\b|\bsqli\b", "sqli", 0.95),
    (r"\bxss\b|cross.?site", "xss", 0.95),
    (r"\bssrf\b", "ssrf", 0.95),
    (r"\brce\b|remote.?code", "rce", 0.95),
    (r"auth.*bypass|unauthorized", "auth_bypass", 0.90),
    (r"privilege.*escal", "privilege_escalation", 0.90),
    (r"credential.*theft|password.*leak|default.*cred", "credential_theft", 0.90),
    (r"data.*expos|data.*leak", "data_exposure", 0.85),
    (r"misconfigur|security.*header", "misconfiguration", 0.85),
    (r"weak.*encrypt|crypto.*fail", "crypto_failure", 0.85),
    (r"denial.*service|\bdos\b", "dos", 0.85),
    (r"\bxxe\b", "xxe", 0.95),
    (r"default.*password|default.*cred", "default_credentials", 0.90),
    (r"open.?redirect", "open_redirect", 0.85),
    (r"jwt.*expos|token.*leak", "jwt_exposure", 0.85),
    (r"beacon|c2.*channel", "beaconing", 0.85),
    (r"steganograph|hidden.*data", "steganography", 0.90),
    (r"supply.?chain|dependency.*vuln", "supply_chain", 0.85),
    (r"injection", "injection", 0.80),
    (r"cve-\d{4}-\d+", "cve", 0.90),
]


def _quick_classify(finding: Dict[str, Any]) -> str:
    """Quick classification of a finding."""
    title = finding.get("title", "").lower()
    desc = finding.get("description", "").lower()
    evidence = finding.get("evidence", "").lower()
    combined = f"{title} {desc} {evidence}"
    best = "misc"
    best_score = 0.0
    for pattern, cat, weight in _CATEGORY_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            if weight > best_score:
                best_score = weight
                best = cat
    return best


# ═══════════════════════════════════════════════════════════════════════════
# ThreatIntelEngine
# ═══════════════════════════════════════════════════════════════════════════


class ThreatIntelEngine:
    """Centralized threat intelligence engine.

    Enriches findings with threat intelligence from built-in databases
    and optional online sources. Supports caching and deduplication.
    """

    def __init__(self, enable_online: bool = False, cache_ttl: int = 3600) -> None:
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._cache_ttl = cache_ttl
        self._cache_max_size = 10000  # Prevent cache memory exhaustion
        self._cache_lock = Lock()
        self._enable_online = enable_online
        self._online_queries = 0
        self._cache_hits = 0
        self._cache_misses = 0

    def enrich_scan(self, findings: List[Dict[str, Any]], target: str = "") -> ThreatIntelReport:
        """Enrich all findings from a scan with threat intelligence.

        Parameters:
            findings: List of finding dicts from ReconProResult
            target: Target hostname

        Returns:
            ThreatIntelReport with enriched findings and summary.
        """
        t0 = time.monotonic()
        report = ThreatIntelReport(target=target)

        if not findings:
            report.threat_summary = f"No findings to enrich for {target}."
            report.analysis_duration_ms = round((time.monotonic() - t0) * 1000, 2)
            return report

        all_cves: set = set()
        all_cwes: set = set()
        all_capecs: set = set()
        all_mitre: Dict[str, str] = {}
        tech_counts: Dict[str, int] = defaultdict(int)
        known_exploited = 0
        active_exploited = 0
        severity_trends: Dict[str, str] = {}

        for f in findings:
            enriched = self._enrich_finding(f)
            report.enriched_findings.append(enriched.to_dict())

            all_cves.update(enriched.cve_matches)
            all_cwes.update(enriched.cwe_matches)
            all_capecs.update(enriched.capec_matches)
            for t in enriched.mitre_techniques:
                all_mitre[t.get("technique", "")] = t.get("name", "")

            for tech in enriched.affected_technologies:
                tech_counts[tech] += 1

            if enriched.known_exploitation:
                known_exploited += 1
            if enriched.active_exploitation:
                active_exploited += 1

            severity = f.get("severity", "info").lower()
            severity_trends[f.get("title", "")[:50]] = enriched.severity_evolution

        report.unique_cves = sorted(all_cves)
        report.unique_cwes = sorted(all_cwes)
        report.unique_capecs = sorted(all_capecs)
        report.unique_mitre = [{"technique": k, "name": v} for k, v in sorted(all_mitre.items())]
        report.known_exploited_count = known_exploited
        report.active_exploitation_count = active_exploited
        report.technology_profile = dict(tech_counts)
        report.severity_trends = severity_trends
        report.cache_hits = self._cache_hits
        report.cache_misses = self._cache_misses
        report.online_queries = self._online_queries

        # Generate summary
        report.threat_summary = self._generate_summary(
            findings, all_cves, all_cwes, all_capecs,
            known_exploited, active_exploited, target,
        )

        report.analysis_duration_ms = round((time.monotonic() - t0) * 1000, 2)
        return report

    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CVE in the built-in database."""
        cve_upper = cve_id.upper()
        cached = self._cache_get(f"cve:{cve_upper}")
        if cached is not None:
            self._cache_hits += 1
            return cached

        self._cache_misses += 1
        record = _CVE_KNOWN_PATTERNS.get(cve_upper)

        if record:
            result = {
                "cve_id": cve_upper,
                "name": record["name"],
                "description": record["description"],
                "severity": record["severity"],
                "affected": record.get("affected", []),
                "known_exploited": record.get("known_exploited", False),
                "in_cisa_kev": cve_upper in _CISA_KEV_CVE_LIST,
            }
            self._cache_set(f"cve:{cve_upper}", result)
            return result

        # Try online lookup if enabled
        if self._enable_online:
            result = self._online_cve_lookup(cve_upper)
            if result:
                self._cache_set(f"cve:{cve_upper}", result)
                return result

        self._cache_set(f"cve:{cve_upper}", None)
        return None

    def lookup_cwe(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CWE in the built-in database."""
        cwe_upper = cwe_id.upper()
        cached = self._cache_get(f"cwe:{cwe_upper}")
        if cached is not None:
            self._cache_hits += 1
            return cached

        self._cache_misses += 1
        record = _CWE_DATABASE.get(cwe_upper)

        if record:
            result = {
                "cwe_id": cwe_upper,
                "name": record["name"],
                "description": record["description"],
                "risk": record["risk"],
            }
            self._cache_set(f"cwe:{cwe_upper}", result)
            return result

        self._cache_set(f"cwe:{cwe_upper}", None)
        return None

    def lookup_capec(self, capec_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CAPEC in the built-in database."""
        capec_upper = capec_id.upper()
        cached = self._cache_get(f"capec:{capec_upper}")
        if cached is not None:
            self._cache_hits += 1
            return cached

        self._cache_misses += 1
        record = _CAPEC_DATABASE.get(capec_upper)

        if record:
            result = {
                "capec_id": capec_upper,
                "name": record["name"],
                "description": record["description"],
                "risk": record["risk"],
            }
            self._cache_set(f"capec:{capec_upper}", result)
            return result

        self._cache_set(f"capec:{capec_upper}", None)
        return None

    def lookup_mitre(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Look up a MITRE ATT&CK technique."""
        tech_upper = technique_id.upper()
        cached = self._cache_get(f"mitre:{tech_upper}")
        if cached is not None:
            self._cache_hits += 1
            return cached

        self._cache_misses += 1
        record = _MITRE_TECHNIQUES.get(tech_upper)

        if record:
            result = {
                "technique_id": tech_upper,
                "name": record["name"],
                "tactic": record["tactic"],
                "risk": record["risk"],
            }
            self._cache_set(f"mitre:{tech_upper}", result)
            return result

        self._cache_set(f"mitre:{tech_upper}", None)
        return None

    def get_owasp_mapping(self, category: str) -> List[Dict[str, Any]]:
        """Get OWASP Top 10 mapping for a vulnerability category."""
        mapped = []
        for item in _OWASP_TOP10:
            if category in item.get("categories", []):
                mapped.append({
                    "owasp_id": item["id"],
                    "name": item["name"],
                    "related_cwe": item.get("cwe", []),
                })
        return mapped

    # -- Internal methods ---------------------------------------------------

    def _enrich_finding(self, finding: Dict[str, Any]) -> EnrichedFinding:
        """Enrich a single finding with threat intelligence."""
        cat = _quick_classify(finding)
        enriched = EnrichedFinding(original=finding)

        # Extract CVE references from evidence/title
        cve_refs = self._extract_cve_refs(finding)
        for cve in cve_refs:
            enriched.cve_matches.append(cve)
            record = self.lookup_cve(cve)
            if record:
                enriched.threat_records.append(ThreatRecord(
                    source="CVE", source_id=cve,
                    name=record.get("name", cve),
                    description=record.get("description", ""),
                    severity=record.get("severity", "info"),
                    confidence=0.9,
                    metadata=record,
                    evidence_chain=[f"CVE reference found in finding: {cve}"],
                ).to_dict())
                if record.get("known_exploited"):
                    enriched.known_exploitation = True
                if record.get("in_cisa_kev"):
                    enriched.active_exploitation = True
                    enriched.severity_evolution = "increasing"

        # CWE mapping
        cwe_ids = _CATEGORY_TO_CWE.get(cat, [])
        for cwe in cwe_ids:
            enriched.cwe_matches.append(cwe)
            record = self.lookup_cwe(cwe)
            if record:
                enriched.threat_records.append(ThreatRecord(
                    source="CWE", source_id=cwe,
                    name=record.get("name", cwe),
                    description=record.get("description", ""),
                    severity=record.get("risk", "info"),
                    confidence=0.8,
                    metadata=record,
                    evidence_chain=[f"Category '{cat}' maps to {cwe}"],
                ).to_dict())

        # CAPEC mapping
        capec_ids = _CATEGORY_TO_CAPEC.get(cat, [])
        for capec in capec_ids:
            enriched.capec_matches.append(capec)
            record = self.lookup_capec(capec)
            if record:
                enriched.threat_records.append(ThreatRecord(
                    source="CAPEC", source_id=capec,
                    name=record.get("name", capec),
                    description=record.get("description", ""),
                    severity=record.get("risk", "info"),
                    confidence=0.75,
                    metadata=record,
                    evidence_chain=[f"Category '{cat}' maps to {capec}"],
                ).to_dict())

        # MITRE mapping
        mitre_ids = _CATEGORY_TO_MITRE.get(cat, [])
        for tid in mitre_ids:
            record = self.lookup_mitre(tid)
            if record:
                enriched.mitre_techniques.append({
                    "technique": tid,
                    "name": record.get("name", ""),
                    "tactic": record.get("tactic", ""),
                })
                enriched.threat_records.append(ThreatRecord(
                    source="MITRE", source_id=tid,
                    name=record.get("name", ""),
                    description=f"ATT&CK technique {tid}",
                    severity=record.get("risk", "info"),
                    confidence=0.8,
                    metadata=record,
                    evidence_chain=[f"Category '{cat}' maps to technique {tid}"],
                ).to_dict())

        # OWASP mapping
        owasp_items = self.get_owasp_mapping(cat)
        for item in owasp_items:
            enriched.threat_records.append(ThreatRecord(
                source="OWASP", source_id=item["owasp_id"],
                name=item["name"],
                description=f"OWASP Top 10 - {item['owasp_id']}: {item['name']}",
                severity="medium",
                confidence=0.7,
                metadata=item,
                evidence_chain=[f"Category '{cat}' maps to {item['owasp_id']}"],
            ).to_dict())

        # Determine affected technologies
        enriched.affected_technologies = self._detect_technologies(finding)

        # Severity evolution
        if not enriched.severity_evolution:
            sev = finding.get("severity", "info").lower()
            if sev in ("critical", "high"):
                enriched.severity_evolution = "stable"  # Already severe
            else:
                enriched.severity_evolution = "stable"

        # Enrichment confidence
        total_records = len(enriched.threat_records)
        evidence_len = len(finding.get("evidence", ""))
        enriched.enrichment_confidence = min(1.0,
            (0.3 if total_records > 0 else 0.0) +
            (0.3 if evidence_len > 50 else 0.1) +
            (0.2 if enriched.cve_matches else 0.0) +
            (0.2 if enriched.mitre_techniques else 0.0)
        )

        # Threat summary
        enriched.threat_summary = self._finding_threat_summary(enriched, cat)

        return enriched

    def _extract_cve_refs(self, finding: Dict[str, Any]) -> List[str]:
        """Extract CVE identifiers from finding text."""
        text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('evidence', '')}"
        return list(set(re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)))

    def _detect_technologies(self, finding: Dict[str, Any]) -> List[str]:
        """Detect affected technologies from finding metadata."""
        text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('evidence', '')}".lower()
        techs: List[str] = []
        tech_patterns = [
            (r'\bapache\b', "Apache"),
            (r'\bnginx\b', "Nginx"),
            (r'\biis\b', "IIS"),
            (r'\bmysql\b', "MySQL"),
            (r'\bpostgresql\b', "PostgreSQL"),
            (r'\bmongodb\b', "MongoDB"),
            (r'\bredis\b', "Redis"),
            (r'\bnode\.?js\b', "Node.js"),
            (r'\bpython\b', "Python"),
            (r'\bjava\b', "Java"),
            (r'\bphp\b', "PHP"),
            (r'\bruby\b', "Ruby"),
            (r'\bdocker\b', "Docker"),
            (r'\bkubernetes\b', "Kubernetes"),
            (r'\baws\b', "AWS"),
            (r'\bazure\b', "Azure"),
            (r'\bgcp\b', "GCP"),
            (r'\blinux\b', "Linux"),
            (r'\bwindows\b', "Windows"),
            (r'\btomcat\b', "Tomcat"),
            (r'\bjenkins\b', "Jenkins"),
            (r'\bkafka\b', "Kafka"),
            (r'\bopenssl\b', "OpenSSL"),
            (r'\blog4j\b', "Log4j"),
            (r'\bspring\b', "Spring"),
            (r'\bdjango\b', "Django"),
            (r'\bflask\b', "Flask"),
            (r'\bexpress\b', "Express.js"),
            (r'\breact\b', "React"),
            (r'\bangular\b', "Angular"),
            (r'\bjoomla\b', "Joomla"),
            (r'\bwordpress\b', "WordPress"),
            (r'\bdrupal\b', "Drupal"),
            (r'\bcloudflare\b', "Cloudflare"),
        ]
        import re as _re
        for pattern, tech in tech_patterns:
            if _re.search(pattern, text):
                techs.append(tech)
        return list(set(techs))

    def _finding_threat_summary(self, enriched: EnrichedFinding, cat: str) -> str:
        """Generate a threat summary for a single finding."""
        parts = [f"Finding maps to category '{cat}'."]
        if enriched.cve_matches:
            parts.append(f"References {len(enriched.cve_matches)} CVE(s): {', '.join(enriched.cve_matches[:3])}")
        if enriched.known_exploitation:
            parts.append("Known exploitation detected — CRITICAL")
        if enriched.active_exploitation:
            parts.append("Active exploitation reported in CISA KEV")
        if enriched.mitre_techniques:
            techniques = [t.get("name", "") for t in enriched.mitre_techniques[:3]]
            parts.append(f"MITRE ATT&CK: {', '.join(techniques)}")
        if enriched.cwe_matches:
            parts.append(f"{len(enriched.cwe_matches)} CWE(s) mapped")
        if enriched.affected_technologies:
            parts.append(f"Affects: {', '.join(enriched.affected_technologies[:5])}")
        return ". ".join(parts) + "."

    def _generate_summary(self, findings: List[Dict[str, Any]],
                           cves: set, cwes: set, capecs: set,
                           known_exploited: int, active_exploited: int,
                           target: str) -> str:
        """Generate overall threat intelligence summary."""
        parts = [
            f"Threat intelligence analysis for {target} covered {len(findings)} findings.",
        ]

        if cves:
            parts.append(f"Identified {len(cves)} unique CVE references: {', '.join(sorted(cves)[:5])}")
        if cwes:
            parts.append(f"Mapped to {len(cwes)} CWE categories")
        if capecs:
            parts.append(f"Covered {len(capecs)} CAPEC attack patterns")

        if known_exploited > 0:
            parts.append(f"WARNING: {known_exploited} findings reference known exploited vulnerabilities")
        if active_exploited > 0:
            parts.append(f"CRITICAL: {active_exploited} findings are in CISA Known Exploited Vulnerabilities catalog")

        if not known_exploited and not active_exploited:
            parts.append("No known exploited vulnerabilities detected")

        return ". ".join(parts) + "."

    # -- Cache methods -------------------------------------------------------

    def _cache_get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        with self._cache_lock:
            if key in self._cache:
                ts, val = self._cache[key]
                if time.time() - ts < self._cache_ttl:
                    return val
                del self._cache[key]
        return None

    def _cache_set(self, key: str, value: Any) -> None:
        """Set cache value with timestamp. Enforces max cache size."""
        with self._cache_lock:
            if len(self._cache) >= self._cache_max_size:
                # Evict oldest entries
                sorted_keys = sorted(self._cache, key=lambda k: self._cache[k][0])
                evict_count = len(self._cache) // 4
                for k in sorted_keys[:evict_count]:
                    del self._cache[k]
            self._cache[key] = (time.time(), value)

    def clear_cache(self) -> None:
        """Clear all cached entries."""
        with self._cache_lock:
            self._cache.clear()

    # -- Online lookup (optional) --------------------------------------------

    _NVD_ALLOWED_HOSTS = ("services.nvd.nist.gov",)
    _MAX_RESPONSE_BYTES = 65536

    def _online_cve_lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Attempt online CVE lookup via NVD API (stdlib HTTP only).

        Validates the URL to prevent SSRF before making the request.
        """
        try:
            # Validate CVE ID format to prevent injection
            if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id, re.IGNORECASE):
                return None

            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            # SSRF protection: verify URL host
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname not in self._NVD_ALLOWED_HOSTS:
                return None
            if parsed.scheme not in ("https",):
                return None

            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={
                "User-Agent": "ReconPro/10.0 (Threat Intel Engine)",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                raw = resp.read(self._MAX_RESPONSE_BYTES)
                data = json.loads(raw.decode("utf-8", errors="replace"))
                self._online_queries += 1
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_item = vulns[0].get("cve", {})
                    desc = cve_item.get("descriptions", [{}])[0].get("value", "")
                    metrics = cve_item.get("metrics", {})
                    cvss = metrics.get("cvssMetricV31", [{}])
                    if cvss:
                        score = cvss[0].get("cvssData", {}).get("baseScore", 0)
                        severity = cvss[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    else:
                        score, severity = 0, "UNKNOWN"
                    return {
                        "cve_id": cve_id,
                        "name": desc[:200],
                        "description": desc[:500],
                        "severity": str(severity).lower(),
                        "cvss_score": float(score) if score else 0.0,
                        "affected": [],
                        "known_exploited": cve_id in _CISA_KEV_CVE_LIST,
                        "in_cisa_kev": cve_id in _CISA_KEV_CVE_LIST,
                        "source": "NVD_API",
                    }
        except Exception:
            pass
        return None

    @property
    def cache_stats(self) -> Dict[str, int]:
        """Return cache hit/miss statistics."""
        return {"hits": self._cache_hits, "misses": self._cache_misses,
                "size": len(self._cache), "online_queries": self._online_queries}

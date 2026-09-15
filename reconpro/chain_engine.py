"""
ReconPro v7.5 — Multi-Vector Attack Path Chaining Engine

Links individual, seemingly minor findings into dangerous compound attack
paths.  Operates in three modes:

1. **Rule-based** — pattern matching against 50+ predefined ChainPattern
   rules that model real-world compound attack scenarios.
2. **Graph-based** — traverses the knowledge graph to discover paths
   between vulnerabilities that share assets, ports, or technologies.
3. **LLM-assisted** (optional) — sends findings to an LLM for
   creative/nuanced chain discovery beyond predefined rules.

Zero hard dependencies.  LLM integration uses try/except imports so the
engine works fully offline.
"""

from __future__ import annotations

import json
import re
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .knowledge_graph import SEVERITY_ORDER

# Try to import the memory store for type hints / optional graph use
try:
    from .memory import UnifiedMemoryStore
except ImportError:
    UnifiedMemoryStore = None  # type: ignore[assignment,misc]

# Optional LLM clients — never required
try:
    import openai as _openai_mod

    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    import anthropic as _anthropic_mod

    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_SCORES: Dict[str, float] = {
    "info": 1.0,
    "low": 3.0,
    "medium": 6.0,
    "high": 8.0,
    "critical": 10.0,
}

# MITRE ATT&CK Enterprise Tactics (v14.1)
MITRE_TACTICS: Dict[str, Dict[str, Any]] = {
    "TA0043": {"name": "Reconnaissance", "phase": 1},
    "TA0042": {"name": "Resource Development", "phase": 2},
    "TA0001": {"name": "Initial Access", "phase": 3},
    "TA0002": {"name": "Execution", "phase": 4},
    "TA0003": {"name": "Persistence", "phase": 5},
    "TA0004": {"name": "Privilege Escalation", "phase": 6},
    "TA0005": {"name": "Defense Evasion", "phase": 7},
    "TA0006": {"name": "Credential Access", "phase": 8},
    "TA0007": {"name": "Discovery", "phase": 9},
    "TA0008": {"name": "Lateral Movement", "phase": 10},
    "TA0009": {"name": "Collection", "phase": 11},
    "TA0011": {"name": "Command and Control", "phase": 12},
    "TA0010": {"name": "Exfiltration", "phase": 13},
    "TA0040": {"name": "Impact", "phase": 14},
}

# Kill Chain phases
KILL_CHAIN_PHASES: List[str] = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command & Control", "Actions on Objectives"
]

# Finding category → MITRE technique mapping
MITRE_TECHNIQUE_MAP: Dict[str, Dict[str, Any]] = {
    "open_ports": {"technique": "T1046", "name": "Network Service Discovery", "tactic": "TA0007"},
    "subdomain": {"technique": "T1595", "name": "Active Scanning", "tactic": "TA0043"},
    "dns_zone": {"technique": "T1590", "name": "Gather Victim Org Info", "tactic": "TA0043"},
    "wayback": {"technique": "T1593", "name": "Search Open Websites/Domains", "tactic": "TA0043"},
    "cert_transparency": {"technique": "T1590.002", "name": "DNS", "tactic": "TA0043"},
    "tech_fingerprint": {"technique": "T1592", "name": "Gather Victim Host Info", "tactic": "TA0043"},
    "waf_detected": {"technique": "T1595.002", "name": "Software Vulnerability Scanning", "tactic": "TA0043"},
    "sqli": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "xss": {"technique": "T1059.007", "name": "JavaScript Execution", "tactic": "TA0002"},
    "ssrf": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "xxe": {"technique": "T1059.009", "name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "rce": {"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "auth_bypass": {"technique": "T1078", "name": "Valid Accounts", "tactic": "TA0001"},
    "broken_auth": {"technique": "T1110", "name": "Brute Force", "tactic": "TA0006"},
    "session_management": {"technique": "T1539", "name": "Steal Web Session Cookie", "tactic": "TA0006"},
    "jwt_vulnerability": {"technique": "T1550.001", "name": "Use Alternate Authentication Material", "tactic": "TA0005"},
    "idor": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "path_traversal": {"technique": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007"},
    "open_redirect": {"technique": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "TA0001"},
    "info_disclosure": {"technique": "T1592.004", "name": "Client Config", "tactic": "TA0043"},
    "missing_headers": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "mixed_content": {"technique": "T1189", "name": "Drive-by Compromise", "tactic": "TA0001"},
    "csp_analysis": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "tls_weak": {"technique": "T1573", "name": "Encrypted Channel", "tactic": "TA0011"},
    "sensitive_cookie": {"technique": "T1539", "name": "Steal Web Session Cookie", "tactic": "TA0006"},
    "directory_listing": {"technique": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007"},
    "backup_files": {"technique": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007"},
    "cors_misconfig": {"technique": "T1189", "name": "Drive-by Compromise", "tactic": "TA0001"},
    "graphql_exposure": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "api_exposure": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "admin_panel": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "TA0009"},
    "lfi": {"technique": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007"},
    "rfi": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "cmd_injection": {"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "email_harvest": {"technique": "T1589", "name": "Gather Victim Identity Info", "tactic": "TA0043"},
    "suid_binary": {"technique": "T1548.001", "name": "Setuid and Setgid", "tactic": "TA0004"},
    "kernel_exploit": {"technique": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},
    "default_creds": {"technique": "T1078.001", "name": "Default Accounts", "tactic": "TA0001"},
    "misconfiguration": {"technique": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "TA0004"},
    "threat_intel": {"technique": "T1585", "name": "Gather Victim Info", "tactic": "TA0043"},
    "abuse_ch": {"technique": "T1589.002", "name": "Social Media Accounts", "tactic": "TA0043"},
}

_LLIM_PROMPT = """\
You are a senior penetration tester reviewing security scan findings.
Given the following findings for target "{target}", identify realistic
compound attack chains — scenarios where two or more individual findings
combine to create a more dangerous vulnerability.

For each chain, respond with a JSON object in this exact format:
{{
  "chains": [
    {{
      "name": "Short chain name",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "findings_indices": [0, 2],
      "narrative": "A realistic attack description explaining how the findings chain together",
      "steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
      "remediation": "How to break the chain",
      "confidence": 0.85
    }}
  ]
}}

Findings:
{findings_json}

Return ONLY the JSON, no explanation."""


# ======================================================================
#  Data classes
# ======================================================================


@dataclass
class ChainPattern:
    """A rule that describes how specific finding categories combine
    into a compound attack path.

    Parameters
    ----------
    name:
        Human-readable name for the compound attack.
    description:
        One-line description of the attack scenario.
    severity:
        Resulting severity of the compound attack (uppercase).
    required_categories:
        The finding categories that must all be present to trigger this chain.
        A finding matches if its ``category`` or ``type`` field contains
        the pattern as a substring (case-insensitive).
    required_tags:
        Optional additional tags that at least one finding must carry.
        Tags are checked against the ``tags`` list field of findings.
    severity_multiplier:
        Score multiplier applied on top of the base severity.
    narrative_template:
        A template string describing the compound attack.  May contain
        ``{findings}`` placeholder (replaced with finding titles).
    steps:
        Ordered attack steps describing the exploit sequence.
    remediation:
        How to break this specific chain.
    """

    name: str
    description: str
    severity: str
    required_categories: List[str]
    required_tags: List[str] = field(default_factory=list)
    severity_multiplier: float = 1.5
    narrative_template: str = ""
    steps: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class ChainReport:
    """A realized compound attack path, produced when a ChainPattern
    matches against actual findings.

    Parameters
    ----------
    name:
        Chain name (from pattern or LLM).
    severity:
        Computed severity (one of info/low/medium/high/critical).
    score:
        Numeric risk score for ranking.
    findings:
        The individual finding dicts that form this chain.
    narrative:
        Human-readable attack story.
    steps:
        Ordered attack steps.
    remediation:
        How to break the chain.
    confidence:
        0.0 – 1.0 confidence that this chain is real and exploitable.
    """

    name: str
    severity: str
    score: float
    findings: List[Dict[str, Any]]
    narrative: str
    steps: List[str]
    remediation: str
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict for JSON output / display."""
        return {
            "name": self.name,
            "severity": self.severity,
            "score": round(self.score, 2),
            "finding_count": len(self.findings),
            "finding_titles": [f.get("title", f.get("name", "")) for f in self.findings],
            "narrative": self.narrative,
            "steps": self.steps,
            "remediation": self.remediation,
            "confidence": round(self.confidence, 2),
            "is_chain": True,
        }


# ======================================================================
#  CHAIN_RULES — 55 predefined compound-attack patterns
# ======================================================================

CHAIN_RULES: List[ChainPattern] = [
    # ── 1. Phishing & Social Engineering ─────────────────────────────
    ChainPattern(
        name="Credential Phishing via Open Redirect",
        description="Information leak combined with open redirect enables credential phishing",
        severity="HIGH",
        required_categories=["info_leak", "open_redirect"],
        narrative_template=(
            "An information leak on {findings[0]} reveals internal structure and user details, "
            "while {findings[1]} allows an attacker to craft a convincing phishing URL that "
            "redirects victims through the trusted domain. Combined, these enable highly "
            "effective credential harvesting campaigns that bypass email filters."
        ),
        steps=[
            "Recon: Extract internal structure and user info from information leak",
            "Craft phishing URL using the open redirect to bounce through the trusted domain",
            "Send targeted phishing emails that appear to originate from the legitimate service",
            "Capture credentials when victims follow the redirect to the attacker's clone",
        ],
        remediation="Fix the open redirect with strict URL allow-listing and patch the information leak endpoint.",
    ),
    ChainPattern(
        name="Spear Phishing via Email Header Injection",
        description="Email header injection combined with information disclosure enables targeted phishing",
        severity="HIGH",
        required_categories=["email_header_injection", "information_disclosure"],
        required_tags=["email", "smtp"],
        narrative_template=(
            "{findings[0]} allows crafting emails that spoof internal senders. "
            "{findings[1]} provides employee names and roles for highly targeted spear phishing."
        ),
        steps=[
            "Gather employee names and internal structure from information disclosure",
            "Exploit email header injection to spoof internal senders",
            "Send spear-phishing emails impersonating executives or IT staff",
        ],
        remediation="Sanitize all email headers and restrict information disclosure endpoints.",
    ),

    # ── 2. XSS Chains ────────────────────────────────────────────────
    ChainPattern(
        name="Stored XSS via CSP Bypass",
        description="Missing CSP combined with reflected XSS enables persistent stored attacks",
        severity="CRITICAL",
        required_categories=["missing_csp", "xss_reflected"],
        narrative_template=(
            "The application lacks a Content Security Policy ({findings[0]}), meaning there are no "
            "restrictions on script execution. Combined with the reflected XSS in {findings[1]}, "
            "an attacker can inject persistent JavaScript payloads that execute in every visitor's "
            "browser session, enabling account takeover, data theft, and worm propagation."
        ),
        steps=[
            "Identify the reflected XSS injection point",
            "Craft a payload that stores itself (e.g., via localStorage or a writable endpoint)",
            "Without CSP, the browser executes the injected script without restriction",
            "Stolen session tokens or credentials are exfiltrated to the attacker",
        ],
        remediation="Implement a strict Content Security Policy and sanitize all reflected input.",
    ),
    ChainPattern(
        name="DOM XSS via Angular/React Template Injection",
        description="Template injection combined with DOM-based sinks leads to XSS",
        severity="CRITICAL",
        required_categories=["template_injection", "dom_xss"],
        narrative_template=(
            "{findings[0]} allows an attacker to inject template expressions, while {findings[1]} "
            "confirms the application renders user input in DOM sinks without sanitization. "
            "This combination enables arbitrary JavaScript execution within the Angular/React context."
        ),
        steps=[
            "Identify the template injection point",
            "Craft a template expression that triggers client-side code execution",
            "Leverage DOM sinks to achieve persistent XSS",
        ],
        remediation="Sanitize template inputs and avoid rendering user content in innerHTML or similar sinks.",
    ),
    ChainPattern(
        name="XSS to Account Takeover via Session Fixation",
        description="XSS combined with session fixation allows full account compromise",
        severity="CRITICAL",
        required_categories=["xss_reflected", "session_fixation"],
        narrative_template=(
            "{findings[0]} provides the execution context, while {findings[1]} means the "
            "application does not rotate session IDs after login. An attacker injects a script "
            "that fixes a known session ID, then waits for the victim to log in, gaining full access."
        ),
        steps=[
            "Set a known session cookie on the victim via the XSS payload",
            "Victim logs in; session ID is not rotated (session fixation)",
            "Attacker uses the now-authenticated session ID to take over the account",
        ],
        remediation="Rotate session IDs upon authentication and patch the XSS vulnerability.",
    ),

    # ── 3. CORS & Data Theft ─────────────────────────────────────────
    ChainPattern(
        name="Cross-Origin Data Theft",
        description="CORS wildcard with authenticated API endpoints exposes user data",
        severity="HIGH",
        required_categories=["cors_wildcard", "authenticated_api"],
        narrative_template=(
            "The API returns Access-Control-Allow-Origin: * ({findings[0]}) and serves "
            "authenticated data ({findings[1]}). Any malicious website can make cross-origin "
            "requests with the victim's cookies and read the response, silently exfiltrating "
            "private data including profile information, documents, and API tokens."
        ),
        steps=[
            "Victim visits a malicious or compromised website",
            "The site makes a cross-origin XHR/fetch to the API with victim's credentials",
            "CORS wildcard allows the response to be read by the attacking origin",
            "Private data is exfiltrated to the attacker's server",
        ],
        remediation="Restrict CORS to specific trusted origins and require explicit credentials mode.",
    ),
    ChainPattern(
        name="CORS Misconfiguration + Sensitive API = Data Breach",
        description="CORS reflecting Origin with sensitive endpoints enables targeted data theft",
        severity="HIGH",
        required_categories=["cors_origin_reflect", "sensitive_api"],
        narrative_template=(
            "{findings[0]} echoes back any Origin header, and {findings[1]} exposes "
            "sensitive data. An attacker hosts a page on a subdomain or related domain and "
            "the reflected CORS policy grants access, enabling cross-origin data theft."
        ),
        steps=[
            "Attacker sets up a page on a domain that will pass Origin checks",
            "Victim visits the page, which makes requests to the sensitive API",
            "Reflected CORS grants access to the response",
            "Sensitive data is exfiltrated",
        ],
        remediation="Implement an Origin allow-list and do not reflect arbitrary Origin headers.",
    ),

    # ── 4. Cloud & Infrastructure ─────────────────────────────────────
    ChainPattern(
        name="Cloud Instance Takeover via SSRF + IAM",
        description="SSRF to cloud metadata combined with IAM misconfiguration leads to full cloud takeover",
        severity="CRITICAL",
        required_categories=["cloud_metadata_ssrf", "iam_misconfig"],
        required_tags=["aws", "gcp", "azure", "cloud"],
        severity_multiplier=2.0,
        narrative_template=(
            "{findings[0]} allows querying the cloud metadata service (169.254.169.254) to "
            "retrieve temporary IAM credentials. {findings[1]} means these credentials are "
            "over-privileged, granting access to additional services. An attacker can escalate "
            "from a single SSRF to full cloud environment compromise."
        ),
        steps=[
            "Trigger the SSRF to request the cloud metadata endpoint",
            "Extract temporary IAM credentials from the metadata response",
            "Use over-privileged credentials to enumerate and access other cloud resources",
            "Escalate to other services, potentially pivoting to the entire cloud account",
        ],
        remediation="Block requests to internal/metadata IPs and apply least-privilege IAM policies.",
    ),
    ChainPattern(
        name="S3 Bucket Data Exfiltration",
        description="Public S3 bucket with wildcard IAM policy leads to mass data exfiltration",
        severity="CRITICAL",
        required_categories=["s3_public", "iam_wildcard"],
        required_tags=["aws", "s3", "cloud"],
        narrative_template=(
            "{findings[0]} exposes an S3 bucket to the internet, and {findings[1]} means "
            "the associated IAM role has broad permissions. An attacker can list, read, and "
            "potentially write to not just this bucket but other resources in the account."
        ),
        steps=[
            "Identify the publicly accessible S3 bucket",
            "Enumerate bucket contents using the wildcard IAM permissions",
            "Download sensitive data files (backups, credentials, PII)",
            "Use the wildcard IAM role to pivot to other AWS services",
        ],
        remediation="Restrict S3 bucket access policies and apply least-privilege IAM.",
    ),
    ChainPattern(
        name="Cloud Metadata SSRF to Internal Network Pivot",
        description="SSRF via cloud metadata enables scanning and pivoting through the internal network",
        severity="HIGH",
        required_categories=["cloud_metadata_ssrf", "internal_network_exposure"],
        narrative_template=(
            "{findings[0]} provides access to the cloud metadata service, while "
            "{findings[1]} shows internal services are reachable. The attacker uses "
            "the SSRF as a proxy to scan and attack internal network segments."
        ),
        steps=[
            "Use SSRF to query cloud metadata for network configuration",
            "Identify internal IP ranges and services from metadata",
            "Use the SSRF as a pivoting point to scan internal services",
            "Attack internal databases, admin panels, or other services",
        ],
        remediation="Block SSRF to internal IPs and segment internal networks.",
    ),
    ChainPattern(
        name="Serverless Function Injection to Cloud Compromise",
        description="Serverless injection combined with over-privileged execution role",
        severity="CRITICAL",
        required_categories=["serverless_injection", "iam_misconfig"],
        required_tags=["lambda", "serverless", "cloud"]
    ),

    # ── 5. Authentication & Token Attacks ─────────────────────────────
    ChainPattern(
        name="JWT Token Forgery",
        description="JWT with no signature verification combined with weak signing key",
        severity="CRITICAL",
        required_categories=["jwt_no_verify", "weak_signing_key"],
        narrative_template=(
            "The application does not verify JWT signatures ({findings[0]}) and uses a "
            "weak or leaked signing key ({findings[1]}). An attacker can forge arbitrary "
            "JWTs, including admin tokens, granting full unauthorized access to any account."
        ),
        steps=[
            "Obtain or crack the weak JWT signing key",
            "Craft a JWT with elevated privileges (e.g., admin role)",
            "The server accepts the forged token without signature verification",
            "Full account takeover with arbitrary privilege escalation",
        ],
        remediation="Enforce JWT signature verification with strong keys and use RS256 instead of HS256.",
    ),
    ChainPattern(
        name="Session Hijacking via Insecure Transport",
        description="Missing HSTS with cleartext HTTP allows session cookie interception",
        severity="HIGH",
        required_categories=["missing_hsts", "cleartext_http"],
        narrative_template=(
            "{findings[0]} means the browser may send session cookies over HTTP. "
            "{findings[1]} confirms the site accepts unencrypted connections. An attacker on "
            "the same network can perform SSL stripping to intercept and hijack user sessions."
        ),
        steps=[
            "Attacker performs a man-in-the-middle attack (e.g., ARP spoofing)",
            "Downgrade HTTPS connections to HTTP via SSL stripping",
            "Without HSTS, the browser accepts the downgrade silently",
            "Intercept session cookies from HTTP traffic and hijack user sessions",
        ],
        remediation="Enable HSTS with a long max-age and redirect all HTTP to HTTPS.",
    ),
    ChainPattern(
        name="Password Reset Poisoning",
        description="Password reset token in URL combined with host header injection",
        severity="HIGH",
        required_categories=["password_reset_token_url", "host_header_injection"],
        narrative_template=(
            "{findings[0]} means password reset tokens are delivered via URL parameters, "
            "and {findings[1]} allows manipulating the Host header. An attacker can poison "
            "the password reset link to point to their server, capturing the reset token."
        ),
        steps=[
            "Initiate a password reset for the victim's account",
            "Manipulate the Host header so the reset email links to the attacker's server",
            "Victim clicks the poisoned link, sending the reset token to the attacker",
            "Attacker uses the token to set a new password and take over the account",
        ],
        remediation="Deliver reset tokens via the body (not URL) and validate the Host header.",
    ),
    ChainPattern(
        name="Brute Force via Weak Password Policy",
        description="Exposed SSH with weak password policy enables credential brute-forcing",
        severity="CRITICAL",
        required_categories=["open_port_ssh", "weak_password_policy"],
        narrative_template=(
            "SSH is exposed to the internet ({findings[0]}) and the password policy "
            "is weak ({findings[1]}), allowing short or common passwords. An attacker "
            "can brute-force credentials and gain shell access to the server."
        ),
        steps=[
            "Identify the open SSH port on the target",
            "Generate a password list based on the weak policy constraints",
            "Perform automated brute-force login attempts",
            "Gain shell access with valid credentials",
        ],
        remediation="Enforce strong password policies, use key-based authentication, and restrict SSH access with firewalls.",
    ),
    ChainPattern(
        name="Authentication Bypass via IDOR + Session Prediction",
        description="IDOR combined with predictable session tokens allows account switching",
        severity="HIGH",
        required_categories=["idor", "session_prediction"],
        narrative_template=(
            "{findings[0]} allows accessing other users' resources by changing IDs, while "
            "{findings[1]} means session tokens are predictable. Together, an attacker can "
            "enumerate and predict valid sessions to access any user's data."
        ),
        steps=[
            "Analyze session token generation for predictability",
            "Generate valid session tokens for target users",
            "Use IDOR to access those users' data with the predicted sessions",
        ],
        remediation="Use cryptographically random session tokens and enforce proper authorization checks.",
    ),

    # ── 6. Container & Orchestration ──────────────────────────────────
    ChainPattern(
        name="Container Escape to Host",
        description="Privileged container with host PID namespace allows full host compromise",
        severity="CRITICAL",
        required_categories=["docker_privileged", "host_pid"],
        required_tags=["docker", "kubernetes", "container"],
        severity_multiplier=2.0,
        narrative_template=(
            "{findings[0]} means the container runs with full host privileges, and "
            "{findings[1]} shares the host's PID namespace. An attacker who gains access "
            "inside the container can escape to the host, access all processes, and "
            "potentially compromise the entire node and cluster."
        ),
        steps=[
            "Gain initial access inside the container (e.g., via vulnerable web app)",
            "Use host PID access to observe and manipulate host processes",
            "Leverage privileged mode to mount the host filesystem",
            "Write SSH keys or cron jobs to maintain persistent host access",
        ],
        remediation="Never run containers in privileged mode, avoid host PID sharing, and use pod security policies.",
    ),
    ChainPattern(
        name="Kubernetes API Server Exposure + RBAC Bypass",
        description="Exposed K8s API with permissive RBAC enables cluster takeover",
        severity="CRITICAL",
        required_categories=["k8s_api_exposed", "rbac_misconfig"],
        required_tags=["kubernetes", "k8s"],
        narrative_template=(
            "{findings[0]} exposes the Kubernetes API server, and {findings[1]} grants "
            "excessive permissions. An attacker can interact with the API directly to "
            "create pods, read secrets, and take over the entire cluster."
        ),
        steps=[
            "Connect to the exposed Kubernetes API server",
            "Use permissive RBAC bindings to list and access cluster resources",
            "Create a privileged pod or extract secrets from etcd",
            "Pivot to other workloads and nodes in the cluster",
        ],
        remediation="Restrict API server access, enforce least-privilege RBAC, and use network policies.",
    ),
    ChainPattern(
        name="Container Registry Pull + Image Tampering",
        description="Insecure container registry with writable access enables supply chain attack",
        severity="CRITICAL",
        required_categories=["container_registry_exposed", "insecure_deserialization"],
        narrative_template=(
            "{findings[0]} exposes the container registry, and {findings[1]} indicates "
            "the application deserializes untrusted data. An attacker can push a malicious "
            "image to the registry that will be deployed by the CI/CD pipeline."
        ),
        steps=[
            "Access the exposed container registry without authentication",
            "Push a tampered image with a backdoor embedded",
            "The CI/CD pipeline pulls and deploys the malicious image",
            "Backdoor executes within the cluster, granting persistent access",
        ],
        remediation="Secure the container registry with authentication and sign images.",
    ),

    # ── 7. Injection Chains ───────────────────────────────────────────
    ChainPattern(
        name="Log Poisoning to Remote Code Execution",
        description="Sensitive logging combined with path traversal enables log poisoning RCE",
        severity="HIGH",
        required_categories=["sensitive_logging", "path_traversal"],
        narrative_template=(
            "{findings[0]} means user input is written to log files, and {findings[1]} "
            "allows reading arbitrary files. An attacker poisons logs with PHP/JSP "
            "payloads, then uses the path traversal to include the log file for code execution."
        ),
        steps=[
            "Inject a code payload into a logged field (e.g., User-Agent header)",
            "The application writes the payload to a log file (sensitive logging)",
            "Use path traversal to include/require the log file",
            "The web server executes the injected code from the log",
        ],
        remediation="Sanitize all data before logging and prevent path traversal with allow-lists.",
    ),
    ChainPattern(
        name="SQL Injection to Database Exfiltration",
        description="SQL injection combined with verbose debug mode exposes full database",
        severity="CRITICAL",
        required_categories=["sql_injection", "debug_mode"],
        narrative_template=(
            "{findings[0]} provides direct database access, while {findings[1]} leaks "
            "table names, column structures, and query results in error messages. "
            "An attacker maps the full database schema and exfiltrates all sensitive data."
        ),
        steps=[
            "Trigger SQL errors to reveal database schema (debug mode leaks structure)",
            "Map all tables and columns from verbose error messages",
            "Use UNION-based or blind SQL injection to extract data",
            "Exfiltrate the entire database contents",
        ],
        remediation="Disable debug mode in production, use parameterized queries, and restrict database permissions.",
    ),
    ChainPattern(
        name="Remote Code Execution via Eval Injection",
        description="Dangerous eval function with user-reachable input leads to RCE",
        severity="CRITICAL",
        required_categories=["dangerous_eval", "user_input_reachable"],
        severity_multiplier=2.0,
        narrative_template=(
            "{findings[0]} identifies an eval() or similar dynamic code execution sink, and "
            "{findings[1]} confirms user input can reach that sink without sanitization. "
            "An attacker can inject arbitrary code that executes on the server with the application's privileges."
        ),
        steps=[
            "Identify the eval/exec/code execution sink in the application",
            "Trace user input to confirm it reaches the sink without sanitization",
            "Inject arbitrary code (e.g., system commands, file operations)",
            "Execute code on the server, potentially gaining a reverse shell",
        ],
        remediation="Remove all eval/exec calls and use safe alternatives; sanitize all user inputs.",
    ),
    ChainPattern(
        name="SSTI to RCE",
        description="Server-Side Template Injection combined with file write leads to RCE",
        severity="CRITICAL",
        required_categories=["ssti", "file_upload"],
        narrative_template=(
            "{findings[0]} allows injecting template expressions that execute server-side, "
            "and {findings[1]} means the attacker can upload files. Combined, the attacker "
            "can write a malicious template and trigger its execution for full RCE."
        ),
        steps=[
            "Identify the template injection point and the template engine",
            "Upload a malicious template file via the file upload vulnerability",
            "Trigger rendering of the uploaded template to execute arbitrary code",
        ],
        remediation="Sanitize template inputs, use sandboxed template engines, and restrict file uploads.",
    ),
    ChainPattern(
        name="XXE to SSRF Chain",
        description="XML External Entity injection used to pivot to internal services",
        severity="HIGH",
        required_categories=["xxe", "ssrf"],
        narrative_template=(
            "{findings[0]} allows defining external entities in XML input, and {findings[1]} "
            "confirms internal services are reachable. An attacker uses XXE to make the server "
            "send requests to internal services, bypassing firewalls."
        ),
        steps=[
            "Craft a malicious XML payload with an external entity pointing to an internal service",
            "The server parses the XML and makes the internal request (XXE)",
            "Read the response from internal services through the XML parsing error or output",
            "Use the SSRF capability to scan and attack other internal systems",
        ],
        remediation="Disable external entity processing in XML parsers and restrict outbound connections.",
    ),
    ChainPattern(
        name="Command Injection via File Upload",
        description="Unrestricted file upload with command injection in filename leads to RCE",
        severity="CRITICAL",
        required_categories=["file_upload_unrestricted", "command_injection"],
        narrative_template=(
            "{findings[0]} allows uploading arbitrary files, and {findings[1]} indicates "
            "the server executes commands based on file names or metadata. An attacker uploads "
            "a file with a malicious name that triggers command execution."
        ),
        steps=[
            "Upload a file with a specially crafted filename containing shell metacharacters",
            "The server processes the filename in an unsafe context (e.g., system call, exec)",
            "Injected command executes on the server",
            "Attacker gains shell access or exfiltrates data",
        ],
        remediation="Validate and sanitize all filenames; avoid passing filenames to shell commands.",
    ),
    ChainPattern(
        name="LDAP Injection to Authentication Bypass",
        description="LDAP injection in login form combined with verbose errors enables auth bypass",
        severity="HIGH",
        required_categories=["ldap_injection", "verbose_errors"],
        narrative_template=(
            "{findings[0]} allows injecting LDAP query syntax, and {findings[1]} reveals "
            "internal LDAP structure in error messages. An attacker crafts a query that "
            "bypasses authentication entirely."
        ),
        steps=[
            "Use verbose errors to map the LDAP directory schema",
            "Craft an LDAP injection payload that always evaluates to true (e.g., admin*))",
            "Bypass authentication and log in as an administrator",
        ],
        remediation="Use parameterized LDAP queries and suppress verbose error messages.",
    ),

    # ── 8. CSRF & State Manipulation ───────────────────────────────────
    ChainPattern(
        name="CSRF with CORS Wildcard",
        description="CSRF protection disabled with open CORS allows cross-origin state manipulation",
        severity="HIGH",
        required_categories=["csrf_disabled", "cors_wildcard"],
        narrative_template=(
            "{findings[0]} means state-changing requests have no anti-CSRF protection, and "
            "{findings[1]} allows any origin to read responses. An attacker's website can "
            "submit requests on behalf of authenticated users and read the results."
        ),
        steps=[
            "Victim visits the attacker's website while authenticated to the target",
            "Attacker's JavaScript submits state-changing requests (no CSRF token needed)",
            "CORS wildcard allows reading the response to confirm success",
            "Attacker can change password, email, or transfer data on behalf of the victim",
        ],
        remediation="Implement anti-CSRF tokens and restrict CORS to specific trusted origins.",
    ),
    ChainPattern(
        name="CSRF + IDOR = Forced Data Modification",
        description="CSRF combined with IDOR allows forcing victims to modify other users' data",
        severity="HIGH",
        required_categories=["csrf_disabled", "idor"],
        narrative_template=(
            "{findings[0]} allows cross-origin requests without tokens, and {findings[1]} "
            "means object IDs can be manipulated. An attacker tricks a victim into "
            "submitting a request that modifies another user's resources."
        ),
        steps=[
            "Craft a CSRF payload that changes an object ID to target another user's data",
            "Trick an admin or privileged user into visiting the attacker's page",
            "The browser submits the request with the victim's session",
            "Another user's data is modified without their knowledge",
        ],
        remediation="Implement CSRF protection and proper authorization checks on all state-changing endpoints.",
    ),

    # ── 9. Information Disclosure & Reconnaissance ─────────────────────
    ChainPattern(
        name="Full System Fingerprint",
        description="Debug mode combined with information disclosure reveals complete system internals",
        severity="MEDIUM",
        required_categories=["debug_mode", "information_disclosure"],
        narrative_template=(
            "{findings[0]} exposes detailed error messages and stack traces, and "
            "{findings[1]} reveals configuration details, software versions, and internal paths. "
            "Together they provide a complete blueprint of the system for targeted attacks."
        ),
        steps=[
            "Collect version information and technology stack from disclosure",
            "Map internal file paths, database structure, and API endpoints from debug output",
            "Search for known exploits against the identified versions",
            "Use the complete system map to plan a targeted attack",
        ],
        remediation="Disable debug mode in production and restrict information disclosure.",
    ),
    ChainPattern(
        name="Source Code Exposure + Hardcoded Secrets",
        description="Source code leak combined with hardcoded credentials enables direct system access",
        severity="CRITICAL",
        required_categories=["source_code_exposure", "hardcoded_credentials"],
        narrative_template=(
            "{findings[0]} exposes application source code, and {findings[1]} reveals "
            "embedded credentials. An attacker reads the source to understand business logic, "
            "then uses the hardcoded secrets to access databases, APIs, or cloud services."
        ),
        steps=[
            "Download exposed source code from the disclosure point",
            "Search for hardcoded credentials, API keys, and connection strings",
            "Use extracted credentials to access backend systems directly",
            "Analyze source code for additional vulnerabilities",
        ],
        remediation="Remove all hardcoded secrets, use secrets management, and block source code access.",
    ),
    ChainPattern(
        name="Git Exposure + Database Credentials",
        description="Exposed .git directory combined with database connection strings",
        severity="CRITICAL",
        required_categories=["git_exposure", "database_credentials_exposed"],
        narrative_template=(
            "{findings[0]} allows downloading the full git repository, and {findings[1]} "
            "means database credentials are embedded in the codebase. An attacker reconstructs "
            "the codebase and extracts database credentials from commit history."
        ),
        steps=[
            "Download the exposed .git directory",
            "Reconstruct the full repository including commit history",
            "Search all commits and branches for database credentials",
            "Connect directly to the database using extracted credentials",
        ],
        remediation="Block access to .git directories and rotate all exposed credentials.",
    ),
    ChainPattern(
        name="Directory Traversal + Backup File Exposure",
        description="Path traversal combined with exposed backup files reveals full application data",
        severity="HIGH",
        required_categories=["path_traversal", "backup_file_exposed"],
        narrative_template=(
            "{findings[0]} allows reading files outside the web root, and {findings[1]} "
            "means backup files (SQL dumps, config archives) are accessible. An attacker "
            "uses the traversal to locate and download complete backups."
        ),
        steps=[
            "Use path traversal to enumerate directories above the web root",
            "Locate backup files (.sql, .tar.gz, .bak, .zip)",
            "Download the backup files containing full data dumps or configs",
        ],
        remediation="Restrict file system access and remove or protect backup files.",
    ),
    ChainPattern(
        name="Error-Based Reconnaissance to Targeted Exploitation",
        description="Verbose errors combined with technology fingerprinting enable precision attacks",
        severity="MEDIUM",
        required_categories=["verbose_errors", "tech_fingerprint"],
        narrative_template=(
            "{findings[0]} reveals internal implementation details in error messages, and "
            "{findings[1]} identifies exact software versions. Together they allow an attacker "
            "to select the perfect exploit for the identified stack."
        ),
        steps=[
            "Identify exact versions of all technologies from fingerprinting",
            "Trigger errors to confirm internal paths and query structures",
            "Match versions against known CVE databases",
            "Deploy targeted exploits with high confidence of success",
        ],
        remediation="Suppress verbose errors and minimize technology version disclosure.",
    ),

    # ── 10. Dependency & Supply Chain ──────────────────────────────────
    ChainPattern(
        name="Exploitable Dependency with Known CVE",
        description="Outdated component with a known CVE enables direct exploitation",
        severity="HIGH",
        required_categories=["outdated_component", "known_cve"],
        narrative_template=(
            "{findings[0]} identifies an outdated software component, and {findings[1]} "
            "links it to a known CVE with public exploit code. An attacker can use "
            "the published exploit to compromise the application."
        ),
        steps=[
            "Identify the outdated component and its exact version",
            "Look up the associated CVE and available exploit code",
            "Adapt and execute the exploit against the target",
        ],
        remediation="Update the affected component to the patched version immediately.",
    ),
    ChainPattern(
        name="Dependency Confusion Attack",
        description="Internal package name with public registry access enables dependency confusion",
        severity="HIGH",
        required_categories=["internal_package_name", "package_registry_exposed"],
        narrative_template=(
            "{findings[0]} reveals internal/private package names, and {findings[1]} means "
            "the build process can pull from public registries. An attacker publishes a "
            "malicious package with a higher version number on the public registry."
        ),
        steps=[
            "Identify internal package names from source code or error messages",
            "Publish a malicious package with the same name on the public registry",
            "The build system pulls the public version due to higher version number",
            "Malicious code executes during the next build or deployment",
        ],
        remediation="Use scoped/private registries and configure package resolution order explicitly.",
    ),

    # ── 11. Network & Infrastructure ───────────────────────────────────
    ChainPattern(
        name="DNS Rebinding + Internal Service Access",
        description="DNS rebinding combined with internal network access bypasses Same-Origin Policy",
        severity="HIGH",
        required_categories=["dns_rebinding", "internal_service"],
        narrative_template=(
            "{findings[0]} shows the DNS configuration is vulnerable to rebinding, and "
            "{findings[1]} confirms internal services are accessible. An attacker bypasses "
            "the browser's Same-Origin Policy to interact directly with internal services."
        ),
        steps=[
            "Set up a DNS server that initially resolves to the attacker's IP",
            "After the browser loads the page, rebind to an internal service IP",
            "JavaScript on the page makes requests to the (now internal) IP address",
            "Same-Origin Policy allows the request since the origin matches",
        ],
        remediation="Implement DNS pinning and restrict internal service access.",
    ),
    ChainPattern(
        name="WebSocket Hijacking + Insufficient Origin Check",
        description="WebSocket connection without origin validation enables cross-site hijacking",
        severity="HIGH",
        required_categories=["websocket_no_origin_check", "sensitive_websocket"],
        narrative_template=(
            "{findings[0]} means WebSocket connections accept any origin, and {findings[1]} "
            "carries sensitive data. A malicious site can establish a WebSocket connection "
            "and read or inject messages."
        ),
        steps=[
            "Victim visits attacker's website while having an active session",
            "Attacker's JavaScript opens a WebSocket to the target (no origin check)",
            "Read sensitive data from the WebSocket messages",
            "Inject commands or data into the WebSocket stream",
        ],
        remediation="Validate the Origin header on WebSocket handshake and use token-based auth.",
    ),
    ChainPattern(
        name="SMTP Open Relay + Email Spoofing",
        description="Open mail relay combined with SPF/DKIM misconfiguration enables spam",
        severity="MEDIUM",
        required_categories=["smtp_open_relay", "spf_dkim_misconfig"],
        narrative_template=(
            "{findings[0]} allows sending email through the server without authentication, and "
            "{findings[1]} means email authenticity checks are broken. An attacker sends "
            "phishing emails that appear to come from the target domain."
        ),
        steps=[
            "Connect to the open SMTP relay without credentials",
            "Send emails spoofing the target domain (SPF/DKIM checks fail to reject)",
            "Phishing emails reach victims with a trusted sender address",
        ],
        remediation="Close the open relay and properly configure SPF, DKIM, and DMARC.",
    ),
    ChainPattern(
        name="FTP Anonymous + Sensitive File Access",
        description="Anonymous FTP with sensitive file exposure enables data breach",
        severity="MEDIUM",
        required_categories=["ftp_anonymous", "sensitive_file_exposed"],
        narrative_template=(
            "{findings[0]} allows unauthenticated FTP access, and {findings[1]} means "
            "sensitive files are accessible. An attacker logs in anonymously and downloads "
            "confidential data directly."
        ),
        steps=[
            "Connect to the FTP server with anonymous credentials",
            "Navigate to directories containing sensitive files",
            "Download confidential documents, backups, or configuration files",
        ],
        remediation="Disable anonymous FTP access and restrict file permissions.",
    ),

    # ── 12. File-Based Attacks ─────────────────────────────────────────
    ChainPattern(
        name="Arbitrary File Read via LFI + Log Contamination",
        description="Local file inclusion with user-controlled log file leads to data exfiltration",
        severity="HIGH",
        required_categories=["lfi", "sensitive_logging"],
        narrative_template=(
            "{findings[0]} allows including arbitrary local files, and {findings[1]} means "
            "sensitive data (session tokens, request parameters) is logged. An attacker "
            "includes the log file to read other users' session data."
        ),
        steps=[
            "Trigger requests with sensitive data that gets logged",
            "Use LFI to include the application's log file",
            "Extract session tokens and credentials from the log contents",
        ],
        remediation="Prevent LFI with allow-lists and avoid logging sensitive data.",
    ),
    ChainPattern(
        name="Zip Slip via File Upload + Path Traversal",
        description="Malicious zip upload with path traversal overwrites critical files",
        severity="HIGH",
        required_categories=["file_upload_unrestricted", "path_traversal"],
        required_tags=["zip", "archive", "extract"],
        narrative_template=(
            "{findings[0]} allows uploading arbitrary files, and {findings[1]} indicates "
            "path traversal is possible. An attacker uploads a zip with path-traversal "
            "filenames to overwrite critical system files during extraction."
        ),
        steps=[
            "Create a zip archive with entries containing path traversal (e.g., ../../etc/cron.d/backdoor)",
            "Upload the zip through the unrestricted file upload",
            "The server extracts the archive, writing files to unintended locations",
            "Overwritten files execute code or grant persistent access",
        ],
        remediation="Validate archive entries before extraction and restrict upload file types.",
    ),

    # ── 13. Cryptography ───────────────────────────────────────────────
    ChainPattern(
        name="Weak Crypto + Sensitive Data Transmission",
        description="Weak cipher suites combined with sensitive data in transit",
        severity="HIGH",
        required_categories=["weak_cipher", "sensitive_data_in_transit"],
        narrative_template=(
            "{findings[0]} allows the connection to be downgraded to weak encryption, and "
            "{findings[1]} confirms sensitive data traverses the link. An attacker performs "
            "a cipher-downgrade attack and decrypts the intercepted traffic."
        ),
        steps=[
            "Force a cipher suite negotiation to a weak algorithm (e.g., RC4, DES)",
            "Perform a man-in-the-middle attack to intercept the encrypted traffic",
            "Decrypt the weakly encrypted traffic to extract sensitive data",
        ],
        remediation="Disable all weak cipher suites and use TLS 1.2+ with strong ciphers.",
    ),
    ChainPattern(
        name="Hardcoded Crypto Key + Encrypted Data Exposure",
        description="Hardcoded encryption key with accessible encrypted data enables decryption",
        severity="CRITICAL",
        required_categories=["hardcoded_crypto_key", "encrypted_data_exposed"],
        narrative_template=(
            "{findings[0]} reveals the encryption key used by the application, and "
            "{findings[1]} means encrypted data files or database fields are accessible. "
            "An attacker downloads the encrypted data and decrypts it with the recovered key."
        ),
        steps=[
            "Extract the hardcoded encryption key from source code or configuration",
            "Locate and download encrypted data files or database entries",
            "Decrypt the data using the extracted key",
        ],
        remediation="Use a proper key management system and rotate all exposed keys.",
    ),

    # ── 14. API Security ───────────────────────────────────────────────
    ChainPattern(
        name="API Rate Limit Bypass + Credential Stuffing",
        description="Missing rate limiting with leaked credentials enables mass account takeover",
        severity="HIGH",
        required_categories=["no_rate_limit", "credential_leak"],
        narrative_template=(
            "{findings[0]} means there is no throttling on authentication endpoints, and "
            "{findings[1]} provides a list of leaked credentials. An attacker rapidly tests "
            "all leaked credentials without being blocked."
        ),
        steps=[
            "Obtain leaked credential list from the data exposure",
            "Script automated login attempts against the API (no rate limiting)",
            "Identify valid credentials that grant access to user accounts",
            "Mass account takeover across the user base",
        ],
        remediation="Implement rate limiting on authentication endpoints and notify affected users of credential leaks.",
    ),
    ChainPattern(
        name="GraphQL Introspection + Over-Permissioned Queries",
        description="GraphQL introspection with excessive data exposure enables full data extraction",
        severity="HIGH",
        required_categories=["graphql_introspection", "excessive_data_exposure"],
        narrative_template=(
            "{findings[0]} reveals the complete GraphQL schema, and {findings[1]} means "
            "queries return more data than intended. An attacker maps the entire schema "
            "and extracts sensitive fields from every query."
        ),
        steps=[
            "Query the GraphQL introspection endpoint to dump the full schema",
            "Identify all types, queries, and mutations including hidden ones",
            "Craft queries that extract sensitive fields from every accessible type",
            "Mass-extract data from all resolvers without proper authorization",
        ],
        remediation="Disable introspection in production and implement field-level authorization.",
    ),
    ChainPattern(
        name="Broken Object-Level Authorization + Mass Assignment",
        description="BOLA combined with mass assignment allows privilege escalation",
        severity="HIGH",
        required_categories=["bola", "mass_assignment"],
        narrative_template=(
            "{findings[0]} allows accessing other users' objects by changing IDs, and "
            "{findings[1]} means the API accepts unexpected fields. An attacker modifies "
            "another user's object and elevates their privileges via mass assignment."
        ),
        steps=[
            "Identify an API endpoint that returns user objects (BOLA)",
            "Change the object ID to target another user's record",
            "Include privileged fields (e.g., role=admin) in the update request",
            "The server applies the mass-assigned fields, escalating privileges",
        ],
        remediation="Implement proper object-level authorization and use allow-lists for input fields.",
    ),

    # ── 15. Race Conditions & Logic Flaws ──────────────────────────────
    ChainPattern(
        name="Race Condition + Business Logic Bypass",
        description="TOCTOU race condition with business logic flaw enables financial exploitation",
        severity="HIGH",
        required_categories=["race_condition", "business_logic_flaw"],
        narrative_template=(
            "{findings[0]} means requests can be processed concurrently without locks, and "
            "{findings[1]} shows the business logic has validation gaps. An attacker sends "
            "overlapping requests to exploit timing windows and bypass limits."
        ),
        steps=[
            "Identify a state-changing operation with insufficient locking (e.g., balance transfer)",
            "Send multiple concurrent requests that each pass validation individually",
            "The race condition causes the server to process all requests before updating state",
            "Bypass withdrawal limits, coupon reuse, or balance checks",
        ],
        remediation="Implement database-level locks and atomic operations for critical business logic.",
    ),
    ChainPattern(
        name="Integer Overflow + Payment Bypass",
        description="Integer overflow combined with payment logic allows free transactions",
        severity="HIGH",
        required_categories=["integer_overflow", "payment_logic"],
        narrative_template=(
            "{findings[0]} allows numeric values to overflow, and {findings[1]} processes "
            "payments based on these values. An attacker triggers an overflow to make the "
            "payment amount negative or zero."
        ),
        steps=[
            "Identify a numeric field used in payment calculations",
            "Submit a value that causes integer overflow (e.g., very large quantity)",
            "The overflow results in a negative or zero total amount",
            "Complete the transaction without payment",
        ],
        remediation="Use arbitrary-precision integers and validate numeric ranges server-side.",
    ),

    # ── 16. Mobile & Client-Side ───────────────────────────────────────
    ChainPattern(
        name="Insecure Deep Link + WebView RCE",
        description="Insecure deep link handler combined with WebView JavaScript interface leads to RCE",
        severity="CRITICAL",
        required_categories=["insecure_deep_link", "webview_javascript_interface"],
        narrative_template=(
            "{findings[0]} accepts deep links without proper validation, and {findings[1]} "
            "exposes a JavaScript interface in the WebView. An attacker crafts a malicious "
            "deep link that loads attacker-controlled content in the WebView and calls "
            "native methods through the JavaScript bridge."
        ),
        steps=[
            "Craft a deep link with a URL pointing to attacker-controlled content",
            "The app opens the URL in a WebView with an exposed JavaScript interface",
            "Attacker's JavaScript calls native methods through the bridge",
            "Execute native code or access sensitive data on the device",
        ],
        remediation="Validate deep link schemas/hosts and remove or restrict WebView JavaScript interfaces.",
    ),
    ChainPattern(
        name="Insecure Data Storage + Rooted Device",
        description="Insecure local storage combined with device root access exposes all app data",
        severity="HIGH",
        required_categories=["insecure_data_storage", "device_rooted_or_jailbroken"],
        narrative_template=(
            "{findings[0]} stores sensitive data unencrypted on the device, and {findings[1]} "
            "means the device has root access. An attacker with physical or remote access "
            "can read all stored credentials and tokens."
        ),
        steps=[
            "Access the device's filesystem (using root privileges)",
            "Locate the app's data directory and database files",
            "Extract stored credentials, session tokens, and personal data",
        ],
        remediation="Encrypt sensitive data at rest using the device keystore and implement root detection.",
    ),

    # ── 17. Cache & CDN ────────────────────────────────────────────────
    ChainPattern(
        name="Cache Poisoning via Unkeyed Input",
        description="Unkeyed parameter combined with cacheable response enables cache poisoning",
        severity="HIGH",
        required_categories=["unkeyed_parameter", "cacheable_response"],
        narrative_template=(
            "{findings[0]} means the application processes an input parameter without "
            "including it in the cache key, and {findings[1]} confirms responses are cached. "
            "An attacker poisons the cache with malicious content served to all users."
        ),
        steps=[
            "Identify a parameter that is processed but not included in the cache key (e.g., X-Forwarded-Host)",
            "Send a request with a malicious value for the unkeyed parameter",
            "The response (containing the malicious value) is cached",
            "All subsequent users receive the poisoned cached response",
        ],
        remediation="Ensure all user-controlled inputs are included in the cache key.",
    ),
    ChainPattern(
        name="CDN Bypass + Origin IP Exposure",
        description="CDN bypass reveals origin server IP, bypassing WAF protections",
        severity="MEDIUM",
        required_categories=["cdn_bypass", "origin_ip_exposed"],
        narrative_template=(
            "{findings[0]} allows requests to bypass the CDN, and {findings[1]} reveals the "
            "origin server's IP address. An attacker sends attacks directly to the origin, "
            "bypassing all CDN/WAF protections."
        ),
        steps=[
            "Discover the origin IP through DNS history, SSL certificates, or other means",
            "Send malicious requests directly to the origin IP, bypassing the CDN",
            "Exploit vulnerabilities that the CDN/WAF would have blocked",
        ],
        remediation="Restrict origin server access to CDN IP ranges only.",
    ),

    # ── 18. File Inclusion & Deserialization ────────────────────────────
    ChainPattern(
        name="Phar Deserialization to RCE",
        description="Phar file upload combined with file operation leads to deserialization RCE",
        severity="CRITICAL",
        required_categories=["file_upload_unrestricted", "insecure_deserialization"],
        required_tags=["php", "phar"],
        narrative_template=(
            "{findings[0]} allows uploading files, and {findings[1]} indicates PHP's phar:// "
            "wrapper is usable. An attacker uploads a malicious .phar file and triggers "
            "deserialization through any file operation (file_exists, is_file, etc.)."
        ),
        steps=[
            "Create a malicious PHP archive (.phar) with a serialized payload",
            "Upload the .phar file through the unrestricted file upload",
            "Trigger a file operation that processes the uploaded phar (e.g., file_exists)",
            "The deserialized payload executes, achieving RCE",
        ],
        remediation="Restrict file uploads, disable phar deserialization, and update PHP.",
    ),

    # ── 19. Misconfiguration Chains ────────────────────────────────────
    ChainPattern(
        name="Default Credentials + Exposed Admin Panel",
        description="Default credentials with an exposed admin interface enables full admin access",
        severity="CRITICAL",
        required_categories=["default_credentials", "admin_panel_exposed"],
        narrative_template=(
            "{findings[0]} means the system uses factory default credentials, and "
            "{findings[1]} makes the admin interface accessible. An attacker logs in with "
            "default credentials and gains full administrative control."
        ),
        steps=[
            "Locate the exposed admin panel or management interface",
            "Try default/known credentials (admin/admin, root/root, etc.)",
            "Gain full administrative access to the system",
            "Configure the system to maintain persistent access",
        ],
        remediation="Change all default credentials and restrict admin interface access.",
    ),
    ChainPattern(
        name="Missing Authentication + Sensitive Endpoint",
        description="Unauthenticated access to a sensitive API or endpoint",
        severity="CRITICAL",
        required_categories=["missing_authentication", "sensitive_endpoint"],
        narrative_template=(
            "{findings[0]} means the endpoint requires no authentication, and {findings[1]} "
            "confirms it exposes sensitive operations or data. Anyone can access and "
            "manipulate the sensitive functionality directly."
        ),
        steps=[
            "Identify the sensitive endpoint that lacks authentication",
            "Access the endpoint directly without credentials",
            "Perform sensitive operations or exfiltrate data",
        ],
        remediation="Implement authentication and authorization on all sensitive endpoints.",
    ),
    ChainPattern(
        name="CORS + TLS Misconfiguration = Mixed Content Attack",
        description="CORS wildcard combined with weak TLS allows interception of cross-origin data",
        severity="MEDIUM",
        required_categories=["cors_wildcard", "weak_tls"],
        narrative_template=(
            "{findings[0]} allows cross-origin requests, and {findings[1]} means the TLS "
            "configuration is weak. An attacker performs a MITM attack to intercept "
            "cross-origin data flows."
        ),
        steps=[
            "Perform a man-in-the-middle attack exploiting weak TLS",
            "Intercept cross-origin requests and responses (CORS allows them)",
            "Read sensitive data from the intercepted traffic",
        ],
        remediation="Strengthen TLS configuration and restrict CORS policies.",
    ),
    ChainPattern(
        name="HTTP Method Override + Access Control Bypass",
        description="HTTP method override support combined with access control gaps",
        severity="MEDIUM",
        required_categories=["http_method_override", "access_control_bypass"],
        narrative_template=(
            "{findings[0]} allows overriding the HTTP method via headers, and {findings[1]} "
            "means certain methods bypass access controls. An attacker overrides the method "
            "to bypass security checks."
        ),
        steps=[
            "Identify that the application accepts X-HTTP-Method-Override or similar headers",
            "Discover that the overridden method bypasses access control checks",
            "Send a request with the override header to perform unauthorized actions",
        ],
        remediation="Validate the actual HTTP method used and apply consistent access controls.",
    ),

    # ── 20. Additional Compound Patterns ───────────────────────────────
    ChainPattern(
        name="Subdomain Takeover + DNS Hijack",
        description="Dangling DNS record combined with registrar access enables domain takeover",
        severity="CRITICAL",
        required_categories=["subdomain_takeover", "dns_hijack"],
        narrative_template=(
            "{findings[0]} identifies a dangling CNAME pointing to a deprovisioned service, "
            "and {findings[1]} shows DNS records can be modified. An attacker claims the "
            "dangling subdomain and serves malicious content."
        ),
        steps=[
            "Identify dangling CNAME records pointing to deprovisioned cloud services",
            "Claim the subdomain on the cloud provider",
            "Serve a malicious page or collect cookies on the subdomain",
            "The trusted domain status makes phishing highly effective",
        ],
        remediation="Remove dangling DNS records and monitor DNS configurations continuously.",
    ),
    ChainPattern(
        name="WebSocket + CSRF = Real-Time Data Manipulation",
        description="Unauthenticated WebSocket with state-changing messages enables cross-site attacks",
        severity="HIGH",
        required_categories=["websocket_no_auth", "csrf_disabled"],
        narrative_template=(
            "{findings[0]} means WebSocket connections require no authentication, and "
            "{findings[1]} shows state-changing requests lack CSRF protection. An attacker's "
            "page establishes a WebSocket and sends malicious messages."
        ),
        steps=[
            "Establish a WebSocket connection from a malicious page (no auth needed)",
            "Send state-changing messages through the WebSocket (no CSRF token needed)",
            "Manipulate application state in real-time on behalf of the victim",
        ],
        remediation="Authenticate WebSocket connections and validate message origins.",
    ),
    ChainPattern(
        name="PDF Injection + XSS to Account Compromise",
        description="PDF upload combined with XSS enables server-side PDF-based attacks",
        severity="HIGH",
        required_categories=["pdf_upload", "xss_stored"],
        narrative_template=(
            "{findings[0]} allows uploading PDF files, and {findings[1]} indicates stored "
            "XSS is possible. An attacker uploads a malicious PDF containing JavaScript "
            "that executes when other users view or download the file."
        ),
        steps=[
            "Create a PDF with embedded JavaScript (PDF XSS)",
            "Upload the malicious PDF through the file upload endpoint",
            "When the PDF is rendered in-browser or processed, JavaScript executes",
            "Stored XSS payload steals session data or performs actions as the victim",
        ],
        remediation="Sanitize uploaded PDFs and disable JavaScript in PDF viewers.",
    ),
    ChainPattern(
        name="SSRF + File Protocol = Local File Read",
        description="SSRF with file:// protocol support enables reading arbitrary local files",
        severity="HIGH",
        required_categories=["ssrf", "file_protocol_enabled"],
        narrative_template=(
            "{findings[0]} allows the server to make requests on behalf of the attacker, and "
            "{findings[1]} means the file:// protocol is not blocked. An attacker reads "
            "arbitrary files from the server filesystem."
        ),
        steps=[
            "Identify the SSRF-capable parameter or endpoint",
            "Supply a file:// URL pointing to a sensitive file (e.g., /etc/passwd)",
            "The server reads the local file and returns its contents",
            "Extract configuration files, credentials, or other sensitive data",
        ],
        remediation="Block all non-HTTP/HTTPS protocols in SSRF-sink URLs and use allow-lists.",
    ),
    ChainPattern(
        name="Open Redirect + OAuth Token Theft",
        description="Open redirect in OAuth flow enables token theft",
        severity="HIGH",
        required_categories=["open_redirect", "oauth_misconfig"],
        required_tags=["oauth", "sso", "authentication"],
        narrative_template=(
            "{findings[0]} allows redirecting to arbitrary URLs, and {findings[1]} shows "
            "the OAuth flow is vulnerable. An attacker redirects the OAuth callback to "
            "their server, capturing the authorization code or token."
        ),
        steps=[
            "Identify the OAuth callback URL and the open redirect parameter",
            "Craft a link that redirects the OAuth callback to the attacker's server",
            "Victim authenticates, and the token/code is sent to the attacker",
            "Attacker exchanges the stolen token for access to the victim's account",
        ],
        remediation="Validate redirect URIs strictly in the OAuth flow and fix the open redirect.",
    ),
    ChainPattern(
        name="Prototype Pollution + RCE",
        description="JavaScript prototype pollution combined with code execution sink leads to RCE",
        severity="CRITICAL",
        required_categories=["prototype_pollution", "dangerous_eval"],
        narrative_template=(
            "{findings[0]} allows polluting JavaScript object prototypes, and {findings[1]} "
            "provides a code execution sink that processes the polluted property. "
            "An attacker achieves remote code execution through the pollution chain."
        ),
        steps=[
            "Identify a deep merge or recursive merge operation vulnerable to prototype pollution",
            "Pollute Object.prototype with a malicious property (e.g., __proto__.exec)",
            "Trigger the code execution sink (eval, Function constructor, child_process.exec)",
            "The polluted property is processed as code, achieving RCE",
        ],
        remediation="Avoid deep merge of untrusted input and sandbox code execution contexts.",
    ),
]


# ======================================================================
#  Helpers
# ======================================================================


def _normalise_severity(raw: Any) -> str:
    """Return a normalised lowercase severity string."""
    if raw is None:
        return "info"
    s = str(raw).strip().lower()
    return s if s in SEVERITY_ORDER else "info"


def _sev_score(severity: str) -> float:
    """Map a severity string to a numeric score."""
    return _SEVERITY_SCORES.get(_normalise_severity(severity), 1.0)


def _finding_category(finding: Dict[str, Any]) -> str:
    """Extract the category or type from a finding dict."""
    cat = finding.get("category", "") or finding.get("type", "") or finding.get("finding_type", "")
    return str(cat).strip().lower()


def _finding_tags(finding: Dict[str, Any]) -> List[str]:
    """Extract tags from a finding dict."""
    tags = finding.get("tags", [])
    if isinstance(tags, str):
        return [t.strip().lower() for t in tags.split(",") if t.strip()]
    return [str(t).strip().lower() for t in tags if t]


def _finding_title(finding: Dict[str, Any]) -> str:
    """Get a human-readable title for a finding."""
    return (
        finding.get("title", "")
        or finding.get("name", "")
        or finding.get("description", "")[:80]
        or "Unknown finding"
    )


def _format_narrative(template: str, matched_findings: List[Dict[str, Any]]) -> str:
    """Fill in a narrative template with finding titles.

    Supports ``{findings[N]}`` placeholders where N is a 0-based index.
    Falls back to a plain concatenation if the template is empty.
    """
    if not template:
        titles = [_finding_title(f) for f in matched_findings]
        return "Combined findings: " + ", ".join(titles)
    try:
        return template.format(findings=[_finding_title(f) for f in matched_findings])
    except (KeyError, IndexError):
        titles = [_finding_title(f) for f in matched_findings]
        return "Combined findings: " + ", ".join(titles)


# ======================================================================
#  AttackPathFinder
# ======================================================================


class AttackPathFinder:
    """Discovers compound attack paths by combining rule-based pattern
    matching, graph-based traversal, and optional LLM-assisted analysis.

    Parameters
    ----------
    memory_store :
        Optional :class:`~reconpro.memory.UnifiedMemoryStore` instance for
        graph-based chain discovery.  When ``None``, only rule-based
        analysis is available.
    """

    def __init__(self, memory_store: UnifiedMemoryStore | None = None) -> None:
        self._memory = memory_store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_chains(
        self,
        target: str,
        findings: List[Dict[str, Any]],
    ) -> List[ChainReport]:
        """Run rule-based chain discovery against *findings* for *target*.

        Groups findings by category, matches against all ``CHAIN_RULES``,
        and returns a ranked list of :class:`ChainReport` objects.
        """
        # Index findings by normalised category
        by_cat: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            cat = _finding_category(f)
            if cat:
                by_cat[cat].append(f)

        # Also index by tags
        by_tag: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            for tag in _finding_tags(f):
                by_tag[tag].append(f)

        reports: List[ChainReport] = []
        seen_rule_names: Set[str] = set()

        for pattern in CHAIN_RULES:
            if pattern.name in seen_rule_names:
                continue

            # Check all required categories are present
            matched_findings: List[Dict[str, Any]] = []
            all_cats_present = True
            for req_cat in pattern.required_categories:
                req_lower = req_cat.lower()
                # Check if any finding category contains the required category as substring
                found = False
                for existing_cat, cat_findings in by_cat.items():
                    if req_lower in existing_cat or existing_cat in req_lower:
                        if cat_findings:
                            matched_findings.append(cat_findings[0])
                            found = True
                            break
                if not found:
                    all_cats_present = False
                    break

            if not all_cats_present:
                continue

            # Check required tags (at least one finding must have at least one tag)
            if pattern.required_tags:
                req_tags_lower = [t.lower() for t in pattern.required_tags]
                tag_match = False
                for f in matched_findings:
                    f_tags = _finding_tags(f)
                    for rt in req_tags_lower:
                        if rt in f_tags or any(rt in ft for ft in f_tags):
                            tag_match = True
                            break
                    if tag_match:
                        break
                if not tag_match:
                    # Also check all findings, not just matched ones
                    for f in findings:
                        f_tags = _finding_tags(f)
                        for rt in req_tags_lower:
                            if rt in f_tags or any(rt in ft for ft in f_tags):
                                tag_match = True
                                break
                        if tag_match:
                            break
                if not tag_match:
                    continue

            # Compute score
            max_child_sev = max(_sev_score(f.get("severity", "info")) for f in matched_findings)
            path_length_bonus = (len(matched_findings) - 2) * 1.5  # bonus for longer chains
            score = max_child_sev * pattern.severity_multiplier + max(path_length_bonus, 0.0)

            # Build confidence based on how specific the match is
            confidence = 0.7 + (0.05 * len(pattern.required_categories))
            if pattern.required_tags:
                confidence += 0.1
            confidence = min(confidence, 0.95)

            # Build the narrative
            narrative = _format_narrative(pattern.narrative_template, matched_findings)

            # Build steps (use pattern steps if available)
            steps = pattern.steps if hasattr(pattern, "steps") and pattern.steps else []
            if not steps:
                steps = [f"Step {i+1}: Exploit {_finding_title(f)}" for i, f in enumerate(matched_findings)]

            # Build remediation
            remediation = pattern.remediation if hasattr(pattern, "remediation") and pattern.remediation else (
                "Address each individual finding in the chain to break the compound attack path."
            )

            report = ChainReport(
                name=pattern.name,
                severity=_normalise_severity(pattern.severity),
                score=round(score, 2),
                findings=list(matched_findings),
                narrative=narrative,
                steps=steps,
                remediation=remediation,
                confidence=round(confidence, 2),
            )
            reports.append(report)
            seen_rule_names.add(pattern.name)

        # Sort by score descending
        reports.sort(key=lambda r: r.score, reverse=True)
        return reports

    def find_compound_paths(self, target: str) -> List[ChainReport]:
        """Graph-based chain discovery using the memory store's knowledge graph.

        Combines structural graph chains with rule-based matching to
        produce compound path reports.

        Returns an empty list if no memory store is available.
        """
        if self._memory is None:
            return []

        reports: List[ChainReport] = []

        # 1. Get graph-based chains from the knowledge graph
        try:
            graph_chains = self._memory.find_chains(target)
        except Exception:
            graph_chains = []

        # 2. Get all findings for the target
        try:
            all_findings = self._memory.get_findings(target)
        except Exception:
            all_findings = []

        # Filter to actual vulnerability findings (not scan summaries)
        vuln_findings = [
            f for f in all_findings
            if f.get("severity", "info") not in ("info",)
            and f.get("title", "").find("Scan completed") == -1
        ]

        if not vuln_findings:
            # Try rule-based analysis on whatever we have
            return self.find_chains(target, all_findings)

        # 3. Rule-based chains
        rule_reports = self.find_chains(target, vuln_findings)
        reports.extend(rule_reports)

        # 4. Graph-based chain enrichment
        seen_rule_names = {r.name for r in rule_reports}
        for chain in graph_chains:
            if not chain or len(chain) < 2:
                continue

            # Extract finding nodes from the chain
            chain_findings = [
                step for step in chain
                if step.get("node_type") in ("finding", "vulnerability", "cve")
            ]

            if len(chain_findings) < 2:
                continue

            # Check if this chain is already covered by a rule
            chain_title_parts = [f.get("title", "") for f in chain_findings]
            covered = False
            for existing_name in seen_rule_names:
                # Simple check: if any two titles contain words from an existing rule's categories
                for part in chain_title_parts[:2]:
                    part_lower = part.lower()
                    if any(cat.lower() in part_lower for rule in CHAIN_RULES if rule.name == existing_name for cat in rule.required_categories):
                        covered = True
                        break
                if covered:
                    break

            if covered:
                continue

            # Build a generic graph-based chain report
            max_sev = max(_sev_score(f.get("severity", "info")) for f in chain_findings)
            path_len = len(chain_findings)
            score = max_sev * 1.3 + (path_len - 2) * 1.0

            # Determine chain type from the path
            types_in_chain = [
                f.get("finding_type", f.get("type", "unknown"))
                for f in chain_findings
            ]

            report = ChainReport(
                name=f"Graph Path: {' → '.join(types_in_chain[:3])}",
                severity=_normalise_severity(chain_findings[0].get("severity", "medium")),
                score=round(score, 2),
                findings=chain_findings,
                narrative=(
                    "Graph analysis discovered a multi-hop attack path: "
                    + " → ".join(f.get("title", "unknown") for f in chain_findings)
                    + ". These vulnerabilities are connected through shared assets "
                    "and can be chained for greater impact."
                ),
                steps=[
                    f"Step {i+1}: Exploit {_finding_title(f)} ({f.get('severity', '?')} severity)"
                    for i, f in enumerate(chain_findings)
                ],
                remediation=(
                    "Break this attack path by remediating the highest-severity finding "
                    f"in the chain: {chain_findings[0].get('title', 'unknown')}."
                ),
                confidence=0.5,  # Graph-based chains have lower confidence
            )
            reports.append(report)

        # Deduplicate and sort
        reports.sort(key=lambda r: r.score, reverse=True)
        return reports

    def llm_assisted_chains(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        llm_client: Any = None,
    ) -> List[ChainReport]:
        """Use an LLM (OpenAI or Anthropic) to discover additional chains.

        Parameters
        ----------
        target :
            The target being analysed.
        findings :
            List of finding dicts to analyse.
        llm_client :
            Optional pre-configured LLM client.  If ``None``, the method
            attempts to create one from environment variables
            (``OPENAI_API_KEY`` or ``ANTHROPIC_API_KEY``).  Falls back to
            rule-based analysis if no LLM is available.

        Returns
        -------
        List of :class:`ChainReport` — LLM chains first, then rule-based.
        """
        rule_reports = self.find_chains(target, findings)

        if not findings:
            return rule_reports

        llm_reports = self._call_llm(target, findings, llm_client)
        if llm_reports:
            # Merge: LLM chains first, then rule-based chains that aren't duplicates
            llm_names = {r.name.lower() for r in llm_reports}
            for rr in rule_reports:
                if rr.name.lower() not in llm_names:
                    llm_reports.append(rr)
            return llm_reports

        return rule_reports

    # ------------------------------------------------------------------
    # Internal: LLM interaction
    # ------------------------------------------------------------------

    def _call_llm(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        llm_client: Any = None,
    ) -> List[ChainReport]:
        """Attempt to call an LLM and parse the response into ChainReport objects.

        Returns an empty list on any failure (silently falls back to rules).
        """
        # Prepare findings for the prompt (truncate to avoid token limits)
        trimmed = []
        for f in findings[:30]:  # cap at 30 findings
            trimmed.append({
                "title": _finding_title(f),
                "severity": _normalise_severity(f.get("severity", "info")),
                "category": _finding_category(f),
                "description": str(f.get("description", ""))[:200],
            })

        prompt = _LLIM_PROMPT.format(
            target=target,
            findings_json=json.dumps(trimmed, indent=2),
        )

        response_text = ""

        # Try OpenAI
        if llm_client is not None and hasattr(llm_client, "chat"):  # type: ignore[union-attr]
            try:
                resp = llm_client.chat.completions.create(  # type: ignore[union-attr]
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=2000,
                )
                response_text = resp.choices[0].message.content or ""
            except Exception:
                response_text = ""
        elif HAS_OPENAI:
            try:
                import os
                api_key = os.environ.get("OPENAI_API_KEY")
                if not api_key:
                    return []
                client = _openai_mod.OpenAI(api_key=api_key)
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=2000,
                )
                response_text = resp.choices[0].message.content or ""
            except Exception:
                response_text = ""

        # Try Anthropic if OpenAI didn't work
        if not response_text and HAS_ANTHROPIC:
            try:
                import os
                api_key = os.environ.get("ANTHROPIC_API_KEY")
                if not api_key:
                    return []
                client = _anthropic_mod.Anthropic(api_key=api_key)
                resp = client.messages.create(
                    model="claude-haiku-4-5-20241022",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}],
                )
                response_text = resp.content[0].text if resp.content else ""
            except Exception:
                response_text = ""

        if not response_text:
            return []

        return self._parse_llm_response(response_text, findings)

    @staticmethod
    def _parse_llm_response(
        response_text: str,
        findings: List[Dict[str, Any]],
    ) -> List[ChainReport]:
        """Parse an LLM JSON response into ChainReport objects.

        Gracefully handles malformed JSON, missing fields, and out-of-range indices.
        """
        reports: List[ChainReport] = []

        # Try to extract JSON from the response (handle markdown code blocks)
        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1).strip()
        else:
            # Try to find a top-level JSON object
            brace_match = re.search(r"\{.*\}", response_text, re.DOTALL)
            json_str = brace_match.group(0) if brace_match else response_text.strip()

        try:
            data = json.loads(json_str)
        except (json.JSONDecodeError, AttributeError):
            return reports

        chains = data.get("chains", [])
        if not isinstance(chains, list):
            return reports

        for chain in chains:
            if not isinstance(chain, dict):
                continue

            try:
                name = str(chain.get("name", "LLM-Discovered Chain"))
                severity = _normalise_severity(chain.get("severity", "medium"))
                confidence = float(chain.get("confidence", 0.6))
                confidence = max(0.0, min(1.0, confidence))
                narrative = str(chain.get("narrative", "LLM-identified compound attack path."))
                steps = chain.get("steps", [])
                if not isinstance(steps, list):
                    steps = []
                steps = [str(s) for s in steps]
                remediation = str(chain.get("remediation", "Address the identified vulnerability chain."))

                # Resolve findings by index
                indices = chain.get("findings_indices", [])
                if not isinstance(indices, list):
                    indices = []
                matched_findings = []
                for idx in indices:
                    if isinstance(idx, (int, float)) and 0 <= int(idx) < len(findings):
                        matched_findings.append(findings[int(idx)])

                if not matched_findings:
                    continue

                score = max(_sev_score(f.get("severity", "info")) for f in matched_findings) * 1.4

                reports.append(ChainReport(
                    name=name,
                    severity=severity,
                    score=round(score, 2),
                    findings=matched_findings,
                    narrative=narrative,
                    steps=steps if steps else [
                        f"Step {i+1}: Exploit {_finding_title(f)}"
                        for i, f in enumerate(matched_findings)
                    ],
                    remediation=remediation,
                    confidence=round(confidence, 2),
                ))
            except Exception:
                continue

        return reports




# ======================================================================
#  MITRE ATT&CK Mapping & Attack Surface Scoring
# ======================================================================


class MitreMapper:
    """Maps scan findings to MITRE ATT&CK techniques and Kill Chain phases."""

    def __init__(self, findings: List[Dict[str, Any]]) -> None:
        self.findings = findings
        self._technique_hits: Dict[str, List[str]] = defaultdict(list)
        self._tactic_hits: Dict[str, List[str]] = defaultdict(list)
        self._kill_chain_hits: Dict[str, List[str]] = defaultdict(list)
        self._map_findings()

    def _map_findings(self) -> None:
        """Map each finding to MITRE techniques."""
        for f in self.findings:
            cat = f.get("category", "").lower()
            if cat in MITRE_TECHNIQUE_MAP:
                tech = MITRE_TECHNIQUE_MAP[cat]
                self._technique_hits[tech["technique"]].append(f.get("title", ""))
                self._tactic_hits[tech["tactic"]].append(f.get("title", ""))
                phase_idx = MITRE_TACTICS.get(tech["tactic"], {}).get("phase", 0)
                if 0 < phase_idx <= len(KILL_CHAIN_PHASES):
                    self._kill_chain_hits[KILL_CHAIN_PHASES[phase_idx - 1]].append(f.get("title", ""))

    @property
    def techniques(self) -> Dict[str, List[str]]:
        """Technique IDs mapped to finding titles."""
        return dict(self._technique_hits)

    @property
    def tactics(self) -> Dict[str, List[str]]:
        """Tactic IDs mapped to finding titles."""
        return dict(self._tactic_hits)

    @property
    def kill_chain(self) -> Dict[str, List[str]]:
        """Kill Chain phase names mapped to finding titles."""
        return dict(self._kill_chain_hits)

    def technique_summary(self) -> List[Dict[str, Any]]:
        """Return list of {technique_id, name, tactic, tactic_name, finding_titles, severity}."""
        summary: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for f in self.findings:
            cat = f.get("category", "").lower()
            if cat not in MITRE_TECHNIQUE_MAP:
                continue
            tech = MITRE_TECHNIQUE_MAP[cat]
            tid = tech["technique"]
            if tid in seen:
                continue
            seen.add(tid)
            tactic_id = tech["tactic"]
            tactic_name = MITRE_TACTICS.get(tactic_id, {}).get("name", tactic_id)
            # Determine worst severity among findings that map to this technique
            titles = self._technique_hits.get(tid, [])
            sev = "info"
            for f2 in self.findings:
                if f2.get("title", "") in titles:
                    s = _normalise_severity(f2.get("severity", "info"))
                    if _sev_score(s) > _sev_score(sev):
                        sev = s
            summary.append({
                "technique_id": tid,
                "name": tech["name"],
                "tactic": tactic_id,
                "tactic_name": tactic_name,
                "finding_titles": titles,
                "severity": sev,
            })
        return summary

    def kill_chain_narrative(self) -> str:
        """Generate a narrative describing the attack chain."""
        active_phases = [
            (KILL_CHAIN_PHASES.index(phase), phase, titles)
            for phase, titles in self._kill_chain_hits.items()
        ]
        active_phases.sort(key=lambda x: x[0])

        if not active_phases:
            return "No attack chain phases are covered by the current findings."

        lines: List[str] = ["The following Lockheed Martin Kill Chain phases are covered:"]
        for _idx, phase, titles in active_phases:
            lines.append(f"  • {phase}: {len(titles)} finding(s)")

        coverage = self.coverage_score()
        lines.append(f"\nKill Chain coverage: {coverage:.1f}%")

        if coverage >= 80:
            lines.append("WARNING: High kill chain coverage indicates a mature attack path exists.")
        elif coverage >= 40:
            lines.append("MODERATE: Partial kill chain coverage; several phases are demonstrable.")
        else:
            lines.append("LOW: Minimal kill chain coverage; findings are isolated.")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Full mapping as dict for JSON serialization."""
        return {
            "techniques": self.techniques,
            "tactics": self.tactics,
            "kill_chain": self.kill_chain,
            "technique_summary": self.technique_summary(),
            "kill_chain_narrative": self.kill_chain_narrative(),
            "coverage_score": round(self.coverage_score(), 1),
        }

    def coverage_score(self) -> float:
        """What % of the kill chain is covered (0-100)."""
        if not KILL_CHAIN_PHASES:
            return 0.0
        hit_count = sum(1 for p in KILL_CHAIN_PHASES if p in self._kill_chain_hits)
        return (hit_count / len(KILL_CHAIN_PHASES)) * 100.0


class AttackSurfaceScorer:
    """5-factor attack surface scoring (0-100).

    Factors
    -------
    exposure : weight 0.25
        Counts findings related to information disclosure, open ports,
        exposed panels, and directory listings.
    authentication : weight 0.25
        Counts findings related to auth bypass, broken auth, session
        management, JWT issues, and default credentials.
    data_protection : weight 0.20
        Counts findings related to TLS weakness, missing headers, sensitive
        cookies, mixed content, and CSP issues.
    infrastructure : weight 0.15
        Counts findings related to misconfigurations, WAF detection, tech
        fingerprinting, and kernel/SUID exploits.
    monitoring : weight 0.15
        Penalises when NO findings suggest active monitoring/WAF. Also
        considers whether CSP or security headers are present.
    """

    FACTORS: List[str] = ["exposure", "authentication", "data_protection", "infrastructure", "monitoring"]
    WEIGHTS: Dict[str, float] = {
        "exposure": 0.25,
        "authentication": 0.25,
        "data_protection": 0.20,
        "infrastructure": 0.15,
        "monitoring": 0.15,
    }

    # Category → factor mapping
    _FACTOR_CATEGORIES: Dict[str, List[str]] = {
        "exposure": [
            "info_disclosure", "open_ports", "admin_panel", "directory_listing",
            "backup_files", "api_exposure", "graphql_exposure", "wayback",
            "subdomain", "dns_zone", "cert_transparency", "threat_intel", "abuse_ch",
        ],
        "authentication": [
            "auth_bypass", "broken_auth", "session_management", "jwt_vulnerability",
            "default_creds", "idor", "email_harvest",
        ],
        "data_protection": [
            "tls_weak", "missing_headers", "sensitive_cookie", "mixed_content",
            "csp_analysis", "cors_misconfig",
        ],
        "infrastructure": [
            "misconfiguration", "waf_detected", "tech_fingerprint", "suid_binary",
            "kernel_exploit", "sqli", "xss", "ssrf", "xxe", "rce",
            "path_traversal", "lfi", "rfi", "cmd_injection", "open_redirect",
        ],
        "monitoring": [
            "waf_detected", "csp_analysis", "missing_headers",
        ],
    }

    def __init__(self, findings: List[Dict[str, Any]]) -> None:
        self.findings = findings

    def _factor_findings(self, factor: str) -> List[Dict[str, Any]]:
        """Return findings that belong to *factor*."""
        cats = self._FACTOR_CATEGORIES.get(factor, [])
        return [
            f for f in self.findings
            if f.get("category", "").lower() in cats
        ]

    def _factor_score(self, factor: str) -> float:
        """Compute a 0-100 score for a single factor."""
        factor_findings = self._factor_findings(factor)

        if factor == "monitoring":
            # Monitoring is inverse: presence of WAF/CSP = GOOD (lower score)
            # Missing headers = BAD (higher score).  Start at 50, penalise or reward.
            base = 50.0
            for f in self.findings:
                cat = f.get("category", "").lower()
                sev = _sev_score(f.get("severity", "info"))
                if cat == "waf_detected":
                    base -= 15.0  # WAF present is good
                elif cat == "csp_analysis":
                    base -= 10.0 if sev >= 6.0 else 5.0  # Weak CSP is worse
                elif cat == "missing_headers":
                    base += sev * 3.0  # Missing headers is bad
            return max(0.0, min(100.0, base))

        if not factor_findings:
            return 0.0

        # Score based on count and severity
        total_sev = sum(_sev_score(f.get("severity", "info")) for f in factor_findings)
        count = len(factor_findings)
        # Weighted: severity dominates, count provides a boost
        raw = (total_sev / 10.0) * 60.0 + min(count, 10) * 4.0
        return min(100.0, raw)

    # DEAD CODE: consider removal
    def score(self) -> Dict[str, Any]:
        """Calculate 5-factor score.

        Returns
        -------
        dict with keys: total, factors (dict of name → {score, weight}), risk_level.
        """
        factor_scores: Dict[str, Dict[str, Any]] = {}
        total = 0.0

        for factor in self.FACTORS:
            fs = self._factor_score(factor)
            w = self.WEIGHTS[factor]
            factor_scores[factor] = {"score": round(fs, 1), "weight": w}
            total += fs * w

        total = round(min(100.0, total), 1)

        if total >= 75:
            risk_level = "CRITICAL"
        elif total >= 55:
            risk_level = "HIGH"
        elif total >= 35:
            risk_level = "MEDIUM"
        elif total >= 15:
            risk_level = "LOW"
        else:
            risk_level = "INFO"

        return {
            "total": total,
            "factors": factor_scores,
            "risk_level": risk_level,
        }


# ======================================================================
#  Standalone convenience functions
# ======================================================================


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def analyze_chains(
    target: str,
    findings: List[Dict[str, Any]],
) -> List[ChainReport]:
    """Convenience function: run rule-based chain analysis on *findings*.

    This is the quickest way to use the chain engine without needing a
    :class:`UnifiedMemoryStore`::

        from reconpro.chain_engine import analyze_chains
        chains = analyze_chains("example.com", my_findings)
        for chain in chains:
            print(f"  [{chain.severity.upper()}] {chain.name} (score={chain.score})")
    """
    finder = AttackPathFinder()
    return finder.find_chains(target, findings)


def chains_to_findings(chains: List[ChainReport]) -> List[Dict[str, Any]]:
    """Convert chain reports to flat finding dicts suitable for display.

    Each chain becomes a single "finding" dict with additional keys
    ``is_chain``, ``chain_findings``, and ``chain_steps`` so that
    downstream display code can render them distinctly.
    """
    result: List[Dict[str, Any]] = []
    for chain in chains:
        d = chain.to_dict()
        d["chain_findings"] = chain.findings
        d["chain_steps"] = chain.steps
        d["type"] = "attack_chain"
        d["category"] = "attack_chain"
        d["module"] = "chain_engine"
        d["description"] = chain.narrative
        d["evidence"] = "; ".join(_finding_title(f) for f in chain.findings)
        d["severity"] = chain.severity
        d["cvss_score"] = chain.score
        result.append(d)
    return result

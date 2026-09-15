"""ReconPro v11 — Enhanced CLI Help.

Module-specific help, examples, and usage guidance.
"""
from __future__ import annotations

from typing import Dict, List

# ── Module Help Database ────────────────────────────────────────────────
MODULE_HELP: Dict[str, Dict[str, str]] = {
    # ── Core Remote Modules ─────────────────────────────────────────
    "recon": {
        "description": "Full 13-category surface reconnaissance — headers, cookies, "
                       "JS analysis, security headers, mixed content, CORS, and more.",
        "examples": [
            "reconpro scan example.com",
            "reconpro scan example.com --json",
            "reconpro scan example.com --timeout 15 --insecure",
        ],
        "details": (
            "Runs a comprehensive web surface scan covering 13 categories: "
            "security headers, cookie analysis, JavaScript frameworks, "
            "mixed content, CORS policies, CSP analysis, form detection, "
            "tech fingerprinting, and more. Returns structured findings "
            "with severity ratings and remediation advice."
        ),
        "see_also": ["vibesec", "auth", "chain"],
        "output": (
            "Table of findings with severity (critical/high/medium/low/info), "
            "overall score (0-100), and grade (A+ through F). "
            "Each finding includes title, evidence, and remediation."
        ),
    },
    "auth": {
        "description": "15 auth bypass techniques — testing session handling, "
                       "JWT validation, OAuth misconfigurations, and more.",
        "examples": [
            "reconpro scan example.com -m auth",
            "reconpro scan example.com -m auth --json",
            "reconpro scan example.com -m auth --timeout 20",
        ],
        "details": (
            "Tests 15 authentication and authorization bypass techniques "
            "including session fixation, JWT algorithm confusion, "
            "OAuth misconfigurations, IDOR patterns, and privilege "
            "escalation vectors. Pure Python — no external tools."
        ),
        "see_also": ["chain", "recon", "gorgon"],
        "output": (
            "Findings list with each technique tested, results, and "
            "remediation guidance. Critical findings for broken auth flows."
        ),
    },
    "chain": {
        "description": "SSRF and redirect chain hunting — follows URLs "
                       "through proxies, internal services, and open redirects.",
        "examples": [
            "reconpro scan example.com -m chain",
            "reconpro scan example.com -m chain --json",
            "reconpro scan example.com -m chain --timeout 10",
        ],
        "details": (
            "Hunts for SSRF vulnerabilities by following URL chains through "
            "proxies, internal services, and redirects. Detects open redirect "
            "patterns, internal IP exposure, and cloud metadata endpoints."
        ),
        "see_also": ["auth", "recon", "oblivion"],
        "output": (
            "Chain of followed URLs with each hop analyzed, internal IPs "
            "flagged, and severity-rated findings for SSRF and open redirects."
        ),
    },
    "bot": {
        "description": "C2 and bot infrastructure detection — identifies "
                       "malicious bot networks, command-and-control patterns.",
        "examples": [
            "reconpro scan example.com -m bot",
            "reconpro scan example.com -m bot --json",
            "reconpro scan example.com -m bot --rate-limit 5",
        ],
        "details": (
            "Detects bot and C2 infrastructure indicators including known "
            "malicious user agents, suspicious headers, beaconing patterns, "
            "and botnet-associated IP ranges. Pure signal analysis."
        ),
        "see_also": ["recon", "sigint", "honeypot"],
        "output": (
            "C2 indicators with severity ratings, botnet family identification, "
            "and detailed evidence from HTTP traffic analysis."
        ),
    },
    "gorgon": {
        "description": "15-stage AI red team — advanced multi-phase attack "
                       "simulation combining reconnaissance with exploitation logic.",
        "examples": [
            "reconpro scan example.com -m gorgon",
            "reconpro scan example.com -m gorgon --json",
            "reconpro scan example.com -m gorgon --timeout 30",
        ],
        "details": (
            "15-stage AI-driven red team assessment that chains multiple "
            "attack phases: recon → fingerprint → enumerate → probe → "
            "exploit logic → impact analysis. Zero external dependencies."
        ),
        "see_also": ["oblivion", "auth", "quantum-fingerprint"],
        "output": (
            "Stage-by-stage results with cumulative findings, attack "
            "chain visualization, and comprehensive impact assessment."
        ),
    },
    "oblivion": {
        "description": "23-stage analytical dissolution — DREAD-scored threat "
                       "assessment with deep vulnerability analysis.",
        "examples": [
            "reconpro scan example.com -m oblivion",
            "reconpro scan example.com -m oblivion --json",
            "reconpro scan example.com -m oblivion --timeout 25",
        ],
        "details": (
            "23-stage analytical dissolution that applies DREAD scoring "
            "(Damage, Reproducibility, Exploitability, Affected users, "
            "Discoverability) to every finding. Produces detailed threat "
            "assessment with risk quantification."
        ),
        "see_also": ["gorgon", "chain", "zero-day"],
        "output": (
            "DREAD-scored findings with risk ratings, threat analysis, "
            "and prioritized remediation recommendations."
        ),
    },
    "vibesec": {
        "description": "AI/vibe-coding vulnerability benchmark — specifically "
                       "designed to find vulnerabilities in AI-generated code.",
        "examples": [
            "reconpro vibesec example.com",
            "reconpro vibesec example.com --json",
            "reconpro vibesec example.com --timeout 12",
        ],
        "details": (
            "Benchmark module targeting AI/vibe-coded applications. Tests "
            "common patterns from AI-generated code: missing auth, hardcoded "
            "secrets, insecure defaults, and logic errors."
        ),
        "see_also": ["recon", "ast", "dev"],
        "output": (
            "VibeSec-specific findings with AI code pattern detection "
            "and severity scores. Fast — completes in seconds."
        ),
    },
    "nhi": {
        "description": "Non-Human Identity and blast-radius mapping — detects "
                       "machine identities, service accounts, and API keys.",
        "examples": [
            "reconpro scan example.com -m nhi",
            "reconpro scan example.com -m nhi --json",
            "reconpro scan example.com -m nhi --timeout 15",
        ],
        "details": (
            "Maps non-human identities across a target: service accounts, "
            "API keys, machine credentials, and their blast radius. "
            "Identifies identity sprawl and privilege concentration."
        ),
        "see_also": ["auth", "cloud-recon", "recon"],
        "output": (
            "Identity map with blast radius scores, privilege levels, "
            "and exposure risk ratings for each discovered identity."
        ),
    },
    "pegasus": {
        "description": "Pegasus spyware/surveillance detection — identifies "
                       "indicators of Pegasus and similar mobile spyware.",
        "examples": [
            "reconpro scan example.com -m pegasus",
            "reconpro scan example.com -m pegasus --json",
            "reconpro scan example.com -m pegasus --timeout 10",
        ],
        "details": (
            "Detects indicators associated with Pegasus and similar "
            "advanced mobile surveillance tools. Analyzes domain patterns, "
            "TLS fingerprints, and known IOC patterns."
        ),
        "see_also": ["bot", "sigint", "attributor"],
        "output": (
            "Surveillance indicators with confidence scores, "
            "IOC matches, and attribution hints."
        ),
    },
    "cloud_recon": {
        "description": "Cloud infrastructure reconnaissance — AWS, Azure, GCP "
                       "metadata endpoints, storage buckets, and cloud assets.",
        "examples": [
            "reconpro cloud-recon example.com",
            "reconpro cloud-recon example.com --json",
            "reconpro cloud-recon example.com --timeout 15",
        ],
        "details": (
            "Reconnaissance of cloud infrastructure including metadata "
            "endpoint probing, bucket enumeration, cloud service detection, "
            "and multi-cloud asset discovery. Zero API keys needed."
        ),
        "see_also": ["iac", "container", "recon"],
        "output": (
            "Cloud asset inventory with provider identification, "
            "exposed service alerts, and metadata findings."
        ),
    },
    "team": {
        "description": "Team collaboration and shared scans — multi-user "
                       "scan management with result sharing.",
        "examples": [
            "reconpro scan example.com -m team",
            "reconpro scan example.com -m team --json",
            "reconpro scan example.com -m team --timeout 20",
        ],
        "details": (
            "Enables collaborative scanning with shared scan results, "
            "team baselines, and comparative analysis across team members' "
            "findings."
        ),
        "see_also": ["blitz", "history", "benchmark"],
        "output": (
            "Shared findings, team baselines, and comparative results "
            "with per-member analysis summaries."
        ),
    },

    # ── Advanced Modules (v9.2.0) ──────────────────────────────────
    "quantum_fingerprint": {
        "description": "OS/kernel fingerprinting via HTTP timing analysis — "
                       "passive OS detection through 7 orthogonal timing signals.",
        "examples": [
            "reconpro quantum-fingerprint example.com",
            "reconpro quantum-fingerprint example.com --json",
            "reconpro quantum-fingerprint example.com --timeout 15",
        ],
        "details": (
            "Uses 7 orthogonal timing signals from HTTP responses to "
            "fingerprint the underlying OS and kernel version. "
            "Passive technique — no active probes. Analyzes response "
            "timing patterns, TCP initial window, and header order."
        ),
        "see_also": ["sigint", "ghost"],
        "output": (
            "OS/kernel identification with confidence score, timing "
            "analysis details, and fingerprint comparison data."
        ),
    },
    "dark_web_monitor": {
        "description": "Credential leak and exposure scanner — monitors paste "
                       "sites and threat feeds for leaked credentials.",
        "examples": [
            "reconpro dark-web example.com",
            "reconpro dark-web example.com --json",
            "reconpro dark-web example.com --timeout 20",
        ],
        "details": (
            "Scans paste sites, threat feeds, and data breach sources "
            "for leaked credentials related to the target domain. "
            "Passive monitoring — no direct interaction with dark web."
        ),
        "see_also": ["bot", "threat-feeds", "passive"],
        "output": (
            "Leak alerts with source, timestamp, credential type, "
            "and exposure severity rating."
        ),
    },
    "info_ops": {
        "description": "Information operations and deception analysis — "
                       "detects and analyzes disinformation patterns.",
        "examples": [
            "reconpro info-ops example.com",
            "reconpro info-ops example.com --json",
            "reconpro info-ops example.com --timeout 15",
        ],
        "details": (
            "Defensive module for detecting information operations and "
            "deception campaigns. Analyzes content patterns, metadata "
            "anomalies, and coordination indicators."
        ),
        "see_also": ["attributor", "sigint"],
        "output": (
            "IO indicators with campaign classification, coordination "
            "metrics, and confidence scores."
        ),
    },
    "steganography_detector": {
        "description": "Hidden data and covert channel detection — detects "
                       "steganography in HTTP responses and images.",
        "examples": [
            "reconpro steg example.com",
            "reconpro steg example.com --json",
            "reconpro steg example.com --timeout 12",
        ],
        "details": (
            "Detects steganographic content hidden in HTTP responses, "
            "images, and metadata fields. Analyzes LSB patterns, "
            "file size anomalies, and encoding artifacts."
        ),
        "see_also": ["covert", "dead-drop"],
        "output": (
            "Stego detection results with technique identification, "
            "carrier medium, and extraction feasibility."
        ),
    },
    "covert_channel": {
        "description": "Covert channel detection and simulation — identifies "
                       "DNS, ICMP, and timing-based covert channels.",
        "examples": [
            "reconpro covert example.com",
            "reconpro covert example.com --json",
            "reconpro covert example.com --timeout 15",
        ],
        "details": (
            "Detects and simulates covert communication channels "
            "including DNS tunneling, ICMP exfiltration, and timing "
            "channels. Analyzes traffic patterns for anomalies."
        ),
        "see_also": ["steg", "sigint", "exfil"],
        "output": (
            "Channel detection results with protocol, throughput "
            "estimate, and exfiltration risk rating."
        ),
    },
    "zero_day_hunter": {
        "description": "Anomaly-based zero-day pattern detection — hunts "
                       "for unknown vulnerabilities in response patterns.",
        "examples": [
            "reconpro zero-day example.com",
            "reconpro zero-day example.com --json",
            "reconpro zero-day example.com --timeout 20",
        ],
        "details": (
            "Hunts for zero-day vulnerability patterns by analyzing "
            "HTTP response anomalies, error handling differences, "
            "and behavioral inconsistencies across endpoints."
        ),
        "see_also": ["oblivion", "gorgon", "fuzzer"],
        "output": (
            "Anomaly findings with zero-day probability scores, "
            "affected endpoints, and reproduction steps."
        ),
    },
    "infrastructure_ghost": {
        "description": "Complete infrastructure ghosting — clones and mirrors "
                       "target infrastructure for deception analysis.",
        "examples": [
            "reconpro ghost example.com",
            "reconpro ghost example.com --json",
            "reconpro ghost example.com --timeout 20",
        ],
        "details": (
            "Creates a ghost/clone profile of the target's infrastructure "
            "including DNS, IP ranges, certificates, hosting patterns, "
            "and technology fingerprints for deception analysis."
        ),
        "see_also": ["quantum-fingerprint", "honeypot"],
        "output": (
            "Infrastructure clone map with technology profile, "
            "certificate inventory, and hosting analysis."
        ),
    },
    "signal_intelligence": {
        "description": "SIGINT for HTTP — beaconing detection, C2 traffic "
                       "analysis, and communication pattern identification.",
        "examples": [
            "reconpro sigint example.com",
            "reconpro sigint example.com --json",
            "reconpro sigint example.com --timeout 15",
        ],
        "details": (
            "Applies signal intelligence techniques to HTTP traffic: "
            "beaconing pattern detection, C2 heartbeat analysis, "
            "communication interval identification, and traffic analysis."
        ),
        "see_also": ["bot", "covert", "quantum-fingerprint"],
        "output": (
            "SIGINT findings with beacon intervals, C2 indicators, "
            "and communication pattern classifications."
        ),
    },
    "nation_state_attributor": {
        "description": "Nation-state attack attribution engine — attributes "
                       "attack infrastructure to known APT groups.",
        "examples": [
            "reconpro attributor example.com",
            "reconpro attributor example.com --json",
            "reconpro attributor example.com --timeout 15",
        ],
        "details": (
            "Attribution engine that compares attack infrastructure "
            "signatures against known APT group profiles. Analyzes "
            "TTPs, tooling patterns, and operational characteristics."
        ),
        "see_also": ["bot", "pegasus", "info-ops"],
        "output": (
            "Attribution results with APT group identification, "
            "confidence scores, and supporting evidence chains."
        ),
    },
    "weaponized_report": {
        "description": "Tracking and beacon detection in documents — identifies "
                       "malicious payloads in exported reports and documents.",
        "examples": [
            "reconpro weaponized-report example.com",
            "reconpro weaponized-report example.com --json",
            "reconpro weaponized-report example.com --timeout 15",
        ],
        "details": (
            "Generates and analyzes reports for tracking beacons, "
            "malicious macros, and weaponized content. Defensive "
            "use: verify documents are safe before distribution."
        ),
        "see_also": ["steg", "dead-drop", "honeypot"],
        "output": (
            "Document safety report with beacon detections, "
            "macro analysis, and threat classification."
        ),
    },
    "honeypot_dance": {
        "description": "Honeypot detection and effectiveness scoring — "
                       "identifies decoy infrastructure and scores legitimacy.",
        "examples": [
            "reconpro honeypot example.com",
            "reconpro honeypot example.com --json",
            "reconpro honeypot example.com --timeout 15",
        ],
        "details": (
            "Detects honeypot and decoy infrastructure through "
            "behavioral analysis, response pattern analysis, and "
            "legitimacy scoring. Helps verify target authenticity."
        ),
        "see_also": ["ghost", "infrastructure_ghost"],
        "output": (
            "Honeypot detection results with legitimacy scores, "
            "behavioral anomalies, and confidence ratings."
        ),
    },
    "dead_drop": {
        "description": "Cryptographic dead drop detection — identifies dead "
                       "drops in DNS, HTTP headers, and CT logs.",
        "examples": [
            "reconpro dead-drop example.com",
            "reconpro dead-drop example.com --json",
            "reconpro dead-drop example.com --timeout 15",
        ],
        "details": (
            "Detects cryptographic dead drops embedded in DNS TXT records, "
            "HTTP headers, certificate transparency logs, and other "
            "seemingly benign channels. Analyzes encoding patterns."
        ),
        "see_also": ["steg", "covert", "sigint"],
        "output": (
            "Dead drop detections with channel type, encoding method, "
            "payload analysis, and risk assessment."
        ),
    },

    # ── Local Modules ───────────────────────────────────────────────
    "host": {
        "description": "Full laptop/machine security audit — ports, firewall, "
                       "SSH config, Docker, environment variables, and file permissions.",
        "examples": [
            "reconpro audit",
            "reconpro audit --json",
            "reconpro audit -m host",
        ],
        "details": (
            "Comprehensive machine security audit covering open ports, "
            "firewall rules, SSH configuration, Docker containers, "
            "environment variables, file permissions, and user accounts."
        ),
        "see_also": ["dev", "doctor"],
        "output": (
            "Machine audit report with findings per category, "
            "overall security score, and fix commands."
        ),
    },
    "dev": {
        "description": "Developer security scan — secrets in code, dependency "
                       "vulnerabilities, git history, and Dockerfile analysis.",
        "examples": [
            "reconpro dev",
            "reconpro dev /path/to/project",
            "reconpro dev --json",
        ],
        "details": (
            "Scans developer projects for hardcoded secrets, vulnerable "
            "dependencies, git history leaks, Dockerfile misconfigurations, "
            "and common developer security anti-patterns."
        ),
        "see_also": ["host", "ast", "doctor"],
        "output": (
            "Developer findings with file paths, secret types, "
            "dependency vulnerabilities, and remediation steps."
        ),
    },
    "doctor": {
        "description": "Security health check with fix commands — diagnoses "
                       "security issues and provides actionable fixes.",
        "examples": [
            "reconpro doctor",
            "reconpro doctor --json",
            "reconpro audit -m doctor",
        ],
        "details": (
            "Quick health check that diagnoses common security issues "
            "and provides one-line fix commands for each finding. "
            "Great for CI/CD integration."
        ),
        "see_also": ["host", "dev"],
        "output": (
            "Health findings with severity, description, and "
            "copy-paste fix commands."
        ),
    },
}

# ── CLI Command Help (non-module commands) ──────────────────────────────
CLI_COMMANDS: Dict[str, Dict[str, str]] = {
    "scan": {
        "description": "Full remote security scan with all default modules.",
        "examples": [
            "reconpro scan example.com",
            "reconpro scan example.com --json -o results.json",
            "reconpro scan example.com -m recon,auth,chain",
        ],
    },
    "vibesec": {
        "description": "Quick AI/vibe-coding vulnerability benchmark.",
        "examples": [
            "reconpro vibesec example.com",
            "reconpro vibesec example.com --json",
        ],
    },
    "audit": {
        "description": "Full local machine security audit.",
        "examples": [
            "reconpro audit",
            "reconpro audit --json",
            "reconpro audit -m host,dev",
        ],
    },
    "blitz": {
        "description": "Parallel multi-target scan across multiple domains.",
        "examples": [
            "reconpro blitz t1.com t2.com t3.com",
            "reconpro blitz --targets targets.txt --workers 8",
        ],
    },
    "agent": {
        "description": "Autonomous AI agent — give it a goal and let it plan & execute.",
        "examples": [
            'reconpro agent "fully recon example.com and generate SARIF"',
            'reconpro agent "find all CVEs for myapp.com"',
            "reconpro agent scan --local",
        ],
    },
    "swarm": {
        "description": "Multi-agent attack swarm: SCOUT → HACKER → CODER → GUARDIAN.",
        "examples": [
            "reconpro swarm example.com",
            "reconpro swarm example.com --mode attack",
            "reconpro swarm example.com --rounds 5",
        ],
    },
    "adversarial": {
        "description": "Adversarial self-play: hacker vs coder fix-verify loop.",
        "examples": [
            "reconpro adversarial example.com",
            "reconpro adversarial example.com --rounds 5",
            "reconpro adversarial example.com --modules auth,chain",
        ],
    },
    "nexus": {
        "description": "Launch NEXUS — mind-blowing agent TUI with mouse, keyboard, and split-screen.",
        "examples": [
            "reconpro nexus",
            "reconpro nexus --theme dark",
        ],
    },
    "chat": {
        "description": "Interactive REPL — talk to ReconPro naturally.",
        "examples": [
            "reconpro chat",
            "reconpro chat --no-banner",
        ],
    },
    "subdomains": {
        "description": "Discover subdomains via CT logs and DNS enumeration.",
        "examples": [
            "reconpro subdomains example.com",
            "reconpro subdomains example.com --json",
        ],
    },
    "cve": {
        "description": "CVE/NVD threat intelligence lookup.",
        "examples": [
            "reconpro cve SQL injection",
            "reconpro cve CVE-2024-1234",
            "reconpro cve log4j --json",
        ],
    },
    "graph": {
        "description": "Knowledge graph: attack surface, blast radius, and attack chains.",
        "examples": [
            "reconpro graph example.com",
            "reconpro graph example.com --format json",
        ],
    },
    "history": {
        "description": "View scan history with diff and comparison.",
        "examples": [
            "reconpro history",
            "reconpro history --target example.com",
            "reconpro history --limit 5",
        ],
    },
    "export": {
        "description": "Export last scan to SARIF, Markdown, JSON, or HTML.",
        "examples": [
            "reconpro export report.sarif",
            "reconpro export report.md",
            "reconpro export report.json",
        ],
    },
    "defense": {
        "description": "Generate deployable defenses: WAF rules, patches, and IaC fixes.",
        "examples": [
            "reconpro defense",
            "reconpro defense --input scan.json",
        ],
    },
    "fuzzer": {
        "description": "Context-aware payload fuzzing with tech detection.",
        "examples": [
            "reconpro fuzzer https://example.com/api/search",
            "reconpro fuzzer https://example.com --category xss",
        ],
    },
    "profile": {
        "description": "Target fingerprinting and auto scan plan generation.",
        "examples": [
            "reconpro profile example.com",
            "reconpro profile example.com --json",
        ],
    },
    "compliance": {
        "description": "Compliance mapping: SOC2, ISO27001, PCI-DSS, HIPAA, GDPR, CIS.",
        "examples": [
            "reconpro compliance example.com",
            "reconpro compliance --framework soc2",
        ],
    },
    "iac": {
        "description": "Infrastructure-as-Code audit for Terraform, CloudFormation, Docker, K8s.",
        "examples": [
            "reconpro iac /path/to/terraform",
            "reconpro iac /path/to/k8s --json",
        ],
    },
    "container": {
        "description": "Container escape analysis for Dockerfile and Kubernetes configs.",
        "examples": [
            "reconpro container /path/to/docker",
            "reconpro container /path/to/k8s --json",
        ],
    },
    "cloud-recon": {
        "description": "Cloud infrastructure reconnaissance for AWS, Azure, and GCP.",
        "examples": [
            "reconpro cloud-recon example.com",
            "reconpro cloud-recon example.com --json",
        ],
    },
    "schedule": {
        "description": "Schedule recurring scans with cron-like timing.",
        "examples": [
            "reconpro schedule example.com --every 1h",
            "reconpro schedule example.com --every 6h --modules recon,auth",
        ],
    },
    "serve": {
        "description": "Start REST API server for programmatic access.",
        "examples": [
            "reconpro serve",
            "reconpro serve --port 7890",
        ],
    },
    "report": {
        "description": "Generate HTML report from last scan.",
        "examples": [
            "reconpro report",
            "reconpro report --output report.html",
        ],
    },
    "passive": {
        "description": "Passive DNS and historical OSINT (VirusTotal, Wayback).",
        "examples": [
            "reconpro passive example.com",
            "reconpro passive example.com --json",
        ],
    },
    "netmap": {
        "description": "Network topology, trust mapping, and lateral movement paths.",
        "examples": [
            "reconpro netmap 192.168.1.0/24",
            "reconpro netmap --json",
        ],
    },
    "ast": {
        "description": "AST code analysis for Python/JS/TS vulnerability patterns.",
        "examples": [
            "reconpro ast /path/to/code",
            "reconpro ast /path/to/code --json",
        ],
    },
    "rate": {
        "description": "Rate all v11 modules against industry tools (score /100).",
        "examples": [
            "reconpro rate",
            "reconpro rate quantum-fingerprint",
            "reconpro rate --json",
        ],
    },
}


# ── Renderers ─────────────────────────────────────────────────────────

def render_module_help(module_id: str) -> str:
    """Render formatted help for a specific module."""
    # Try module_id as-is, then with underscores
    mid = module_id.replace("-", "_")
    help_data = MODULE_HELP.get(mid)
    if not help_data:
        help_data = CLI_COMMANDS.get(module_id.replace("-", "-"))
    if not help_data:
        return f"Unknown module: {module_id}\n\nRun 'reconpro list' to see available modules."

    lines: List[str] = []
    lines.append("")
    lines.append(f"  ╔══════════════════════════════════════════════════╗")
    lines.append(f"  ║  {module_id.upper():^50}║")
    lines.append(f"  ╚══════════════════════════════════════════════════╝")
    lines.append("")

    # Description
    lines.append(f"  DESCRIPTION")
    lines.append(f"  {'─' * 50}")
    lines.append(f"  {help_data.get('description', 'No description.')}")
    lines.append("")

    # Details
    if "details" in help_data:
        lines.append(f"  DETAILS")
        lines.append(f"  {'─' * 50}")
        for detail_line in help_data["details"].split(". "):
            lines.append(f"  {detail_line.strip()}.")
            if not detail_line.endswith("."):
                pass
        lines.append("")

    # Examples
    if "examples" in help_data:
        lines.append(f"  EXAMPLES")
        lines.append(f"  {'─' * 50}")
        for ex in help_data["examples"]:
            lines.append(f"    $ {ex}")
        lines.append("")

    # Output
    if "output" in help_data:
        lines.append(f"  OUTPUT")
        lines.append(f"  {'─' * 50}")
        lines.append(f"  {help_data['output']}")
        lines.append("")

    # See also
    if "see_also" in help_data:
        related = help_data["see_also"]
        lines.append(f"  SEE ALSO")
        lines.append(f"  {'─' * 50}")
        lines.append(f"  {', '.join(related)}")
        lines.append("")

    return "\n".join(lines)


def render_all_modules() -> str:
    """Render summary of all available modules."""
    lines: List[str] = []
    lines.append("")
    lines.append("  ReconPro v11 — Module Reference")
    lines.append(f"  {len(MODULE_HELP) + len(CLI_COMMANDS)} commands available")
    lines.append("")

    # Remote modules
    lines.append(f"  {'─' * 60}")
    lines.append(f"  REMOTE SCANNING MODULES")
    lines.append(f"  {'─' * 60}")
    remote_ids = [
        "recon", "auth", "chain", "bot", "gorgon", "oblivion",
        "vibesec", "nhi", "pegasus", "cloud_recon", "team",
    ]
    for mid in remote_ids:
        h = MODULE_HELP.get(mid, {})
        desc = h.get("description", "").split("—")[0].strip()
        lines.append(f"  {mid:<24} {desc}")
    lines.append("")

    # Advanced modules
    lines.append(f"  {'─' * 60}")
    lines.append(f"  ADVANCED MODULES (v9.2.0)")
    lines.append(f"  {'─' * 60}")
    advanced_ids = [
        "quantum_fingerprint", "dark_web_monitor", "info_ops",
        "steganography_detector", "covert_channel", "zero_day_hunter",
        "infrastructure_ghost", "signal_intelligence",
        "nation_state_attributor", "weaponized_report",
        "honeypot_dance", "dead_drop",
    ]
    for mid in advanced_ids:
        h = MODULE_HELP.get(mid, {})
        desc = h.get("description", "").split("—")[0].strip()
        lines.append(f"  {mid:<24} {desc}")
    lines.append("")

    # Local modules
    lines.append(f"  {'─' * 60}")
    lines.append(f"  LOCAL MODULES")
    lines.append(f"  {'─' * 60}")
    local_ids = ["host", "dev", "doctor"]
    for mid in local_ids:
        h = MODULE_HELP.get(mid, {})
        desc = h.get("description", "").split("—")[0].strip()
        lines.append(f"  {mid:<24} {desc}")
    lines.append("")

    # CLI commands
    lines.append(f"  {'─' * 60}")
    lines.append(f"  COMMANDS & POWERS")
    lines.append(f"  {'─' * 60}")
    for cid in sorted(CLI_COMMANDS.keys()):
        h = CLI_COMMANDS[cid]
        desc = h.get("description", "").split("—")[0].strip()
        lines.append(f"  {cid:<24} {desc}")
    lines.append("")

    lines.append(f"  Use 'reconpro info --module <name>' for detailed help on any module.")
    lines.append("")

    return "\n".join(lines)


def render_quick_start() -> str:
    """Render quick-start guide."""
    lines: List[str] = []
    lines.append("")
    lines.append("  ╔══════════════════════════════════════════════════════╗")
    lines.append("  ║          RECONPRO v11 — QUICK START GUIDE           ║")
    lines.append("  ╚══════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append("  GETTING STARTED")
    lines.append("  ──────────────")
    lines.append("  1. Scan a target:")
    lines.append("       $ reconpro scan example.com")
    lines.append("")
    lines.append("  2. Quick benchmark:")
    lines.append("       $ reconpro vibesec example.com")
    lines.append("")
    lines.append("  3. Visual dashboard:")
    lines.append("       $ reconpro nexus")
    lines.append("")
    lines.append("  4. Interactive chat:")
    lines.append("       $ reconpro chat")
    lines.append("")
    lines.append("  5. AI agent:")
    lines.append('       $ reconpro agent "scan everything for example.com"')
    lines.append("")
    lines.append("  LOCAL AUDITS")
    lines.append("  ──────────────")
    lines.append("  6. Machine audit:")
    lines.append("       $ reconpro audit")
    lines.append("")
    lines.append("  7. Developer scan:")
    lines.append("       $ reconpro dev")
    lines.append("")
    lines.append("  8. Health check:")
    lines.append("       $ reconpro doctor")
    lines.append("")
    lines.append("  ADVANCED")
    lines.append("  ──────────────")
    lines.append("  9. Parallel scan:")
    lines.append("       $ reconpro blitz t1.com t2.com t3.com")
    lines.append("")
    lines.append("  10. Swarm attack:")
    lines.append("       $ reconpro swarm example.com")
    lines.append("")
    lines.append("  11. Export results:")
    lines.append("       $ reconpro export report.sarif")
    lines.append("")
    lines.append("  12. Module help:")
    lines.append("       $ reconpro info --module quantum-fingerprint")
    lines.append("")
    lines.append("  COMMON FLAGS")
    lines.append("  ──────────────")
    lines.append("    --json         Output as JSON")
    lines.append("    -o <file>      Save output to file")
    lines.append("    --timeout <s>  Request timeout (default: 8s)")
    lines.append("    --insecure     Skip TLS verification")
    lines.append("    --modules <m>  Select specific modules")
    lines.append("    --all          Run all modules")
    lines.append("")
    lines.append("  GET MORE HELP")
    lines.append("  ──────────────")
    lines.append("    reconpro info --modules       List all modules")
    lines.append("    reconpro info --diagnose       Run diagnostics")
    lines.append("    reconpro info --health         Quick health check")
    lines.append("    reconpro info --version        Detailed version info")
    lines.append("    reconpro info --examples       Usage examples")
    lines.append("")
    return "\n".join(lines)


def render_examples() -> str:
    """Render usage examples for common scenarios."""
    lines: List[str] = []
    lines.append("")
    lines.append("  ╔══════════════════════════════════════════════════════╗")
    lines.append("  ║          RECONPRO v11 — USAGE EXAMPLES              ║")
    lines.append("  ╚══════════════════════════════════════════════════════╝")
    lines.append("")

    scenarios = [
        ("QUICK SECURITY CHECK", [
            "reconpro vibesec example.com",
            "reconpro doctor",
        ]),
        ("FULL REMOTE SCAN", [
            "reconpro scan example.com",
            "reconpro scan example.com --json -o results.json",
            "reconpro scan example.com --all",
        ]),
        ("SELECTIVE MODULE SCAN", [
            "reconpro scan example.com -m recon,auth,chain",
            "reconpro scan example.com -m quantum_fingerprint,sigint",
        ]),
        ("LOCAL MACHINE AUDIT", [
            "reconpro audit",
            "reconpro audit --json",
            "reconpro dev /path/to/project",
        ]),
        ("CI/CD PIPELINE", [
            "reconpro scan example.com --json > results.json",
            "reconpro export report.sarif",
            "reconpro doctor --json | jq '.findings | length'",
        ]),
        ("MULTI-TARGET", [
            "reconpro blitz t1.com t2.com t3.com",
            "reconpro subdomains example.com",
        ]),
        ("AI-POWERED", [
            'reconpro agent "recon example.com, find CVEs, generate SARIF"',
            "reconpro chat",
            "reconpro nexus",
        ]),
        ("ADVANCED ATTACK", [
            "reconpro swarm example.com --mode attack",
            "reconpro adversarial example.com --rounds 5",
        ]),
        ("ADVANCED MODULES", [
            "reconpro quantum-fingerprint example.com",
            "reconpro sigint example.com",
            "reconpro zero-day example.com",
            "reconpro honeypot example.com",
        ]),
        ("THREAT INTELLIGENCE", [
            "reconpro cve SQL injection",
            "reconpro graph example.com",
            "reconpro passive example.com",
            "reconpro threat-feeds 1.2.3.4",
        ]),
        ("INFRASTRUCTURE SECURITY", [
            "reconpro iac /path/to/terraform",
            "reconpro container /path/to/docker",
            "reconpro cloud-recon example.com",
        ]),
        ("POST-SCAN WORKFLOW", [
            "reconpro history",
            "reconpro diff scan1.json scan2.json",
            "reconpro defense",
            "reconpro compliance",
        ]),
    ]

    for title, cmds in scenarios:
        lines.append(f"  {title}")
        lines.append(f"  {'─' * 55}")
        for cmd in cmds:
            lines.append(f"    $ {cmd}")
        lines.append("")

    return "\n".join(lines)

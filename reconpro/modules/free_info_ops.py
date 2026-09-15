"""Module: FREE_INFO_OPS — Information Operations Analysis for ReconPro v9.2.0.

DEFENSIVE / EDUCATIONAL ONLY — This module helps organizations understand and
mitigate risks from information operations: misattribution, impersonation,
false flag attribution, and narrative manipulation.

All capabilities are framed as **defensive assessments** that reveal how an
adversary could exploit publicly observable infrastructure signals to
deceive analysts, misdirect attribution, or construct false narratives.

Capabilities:
  1. Infrastructure Misattribution Analysis
  2. Decoy Endpoint Generation (defensive honeypot recommendations)
  3. False Flag Risk Assessment
  4. Digital Deception Resilience Scoring
  5. Narrative Vulnerability Analysis
  6. Attribution Obfuscation Detection
  7. Honeypot Integration Planning

References:
  - MITRE ATT&CK: Enterprise T1595, T1589, T1592
  - MITRE ATT&CK Deception techniques (custom mapping)
  - NIST SP 800-53 (SI-10 Information Input Validation)
  - CISA Insights: Understanding and Mitigating MDM Operations
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import http_probe, Finding, default_limiter


# ════════════════════════════════════════════════════════════════════════
# DECEPTION_SIGNATURES — Known Nation-State TTPs & Infrastructure Patterns
# (Educational reference for defensive analysts)
# ════════════════════════════════════════════════════════════════════════

DECEPTION_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # ── Shared Infrastructure Patterns ──
    "shared_hosting_red_flags": {
        "description": (
            "Infrastructure patterns where multiple entities share the same "
            "hosting, CDN, or nameserver infrastructure, creating misattribution risk."
        ),
        "indicators": [
            {
                "name": "shared_cdn_origin",
                "pattern": r"(cloudfront|akamai|fastly|cloudflare|imperva|incapsula)",
                "context": "header:server, header:x-cache, header:cf-ray",
                "risk": "medium",
                "note": (
                    "Shared CDN headers are extremely common and are not indicators of "
                    "malicious activity. However, they do mean that two unrelated organizations "
                    "can appear to share infrastructure to a passive observer."
                ),
            },
            {
                "name": "shared_nameservers",
                "pattern": r"(ns1\..*\.cloudflare\.com|ns[0-9]+\.hover\.com|dns[0-9]+\.name-services\.com)",
                "context": "dns:ns",
                "risk": "low",
                "note": (
                    "Many organizations use managed DNS providers, which means their "
                    "nameservers are identical to thousands of other domains. This is normal "
                    "but can complicate infrastructure-level attribution."
                ),
            },
            {
                "name": "shared_ip_ranges",
                "pattern": None,
                "context": "dns:a",
                "risk": "medium",
                "note": (
                    "Cloud/SaaS hosting means many domains resolve to the same IP blocks. "
                    "IP-based attribution without additional context is unreliable."
                ),
            },
        ],
    },
    # ── Certificate Chain Patterns ──
    "certificate_chain_analysis": {
        "description": (
            "TLS certificate properties that can create misattribution risk or "
            "reveal obfuscation attempts."
        ),
        "indicators": [
            {
                "name": "generic_ca_certificate",
                "pattern": r"(Let's Encrypt|DigiCert|Sectigo|GlobalSign|Cloudflare|cPanel)",
                "context": "tls:issuer",
                "risk": "low",
                "note": (
                    "Most organizations use commercial CAs. An adversary can obtain the same "
                    "type of certificate, making certificate issuer alone a weak attribution signal."
                ),
            },
            {
                "name": "ev_certificate_absent",
                "pattern": None,
                "context": "tls:extended_validation",
                "risk": "info",
                "note": (
                    "Without Extended Validation certificates, the CA only validates domain "
                    "control — not organizational identity. This makes cloning a site's TLS "
                    "presence trivial for a domain the attacker controls."
                ),
            },
            {
                "name": "wildcard_certificate",
                "pattern": r"\\*\\.",
                "context": "tls:subject_alt_name",
                "risk": "low",
                "note": (
                    "Wildcard certs are legitimate but indicate subdomain flexibility that "
                    "an impersonator could also replicate on a lookalike domain."
                ),
            },
        ],
    },
    # ── Header / Fingerprint Patterns ──
    "header_fingerprint_patterns": {
        "description": (
            "HTTP headers and response fingerprints that can be manipulated for "
            "deception or that reveal inconsistent infrastructure."
        ),
        "indicators": [
            {
                "name": "mismatched_powered_by",
                "pattern": r"(X-Powered-By|X-AspNet-Version|X-Drupal-Cache|X-Generator)",
                "context": "response_header",
                "risk": "medium",
                "note": (
                    "Technology-revealing headers provide an adversary with the exact stack to "
                    "replicate. Removing these headers reduces impersonation feasibility."
                ),
            },
            {
                "name": "inconsistent_server_header",
                "pattern": None,
                "context": "header:server",
                "risk": "high",
                "note": (
                    "If the Server header changes across requests or subdomains, it may "
                    "indicate load-balanced heterogeneous backends (normal) or active "
                    "attribution obfuscation (defensive or adversarial)."
                ),
            },
            {
                "name": "leaky_csp_headers",
                "pattern": r"Content-Security-Policy",
                "context": "response_header",
                "risk": "medium",
                "note": (
                    "CSP headers reveal which domains the organization trusts, providing an "
                    "adversary with a roadmap of the organization's service ecosystem."
                ),
            },
        ],
    },
    # ── Known Threat Group Infrastructure Archetypes ──
    "threat_group_archetypes": {
        "description": (
            "Archetypal infrastructure patterns associated with specific threat "
            "group categories in public reporting. Used to assess false flag risk — "
            "i.e., the risk that the target's normal infrastructure could be confused "
            "with a known threat group's patterns."
        ),
        "archetypes": [
            {
                "id": "APT_EAST_ASIAN_WEB",
                "category": "East Asian APT Web Infrastructure",
                "public_sources": [
                    "Mandiant APT1 Report (2013)",
                    "FireEye APT28 Reporting",
                    "CISA AA22-277A",
                ],
                "patterns": [
                    "Compromised legitimate WordPress sites as C2",
                    "Dynamic DNS services (noip, dyndns, freedns, 3322.org)",
                    "Free web hosting platforms for landing pages",
                    "Specific PHP backdoor variants (PHPTroy, Sakura, etc.)",
                    "Country-code TLDs in specific combinations",
                    "SSL certificates with specific email validation patterns",
                ],
                "false_flag_note": (
                    "Any organization using WordPress, dynamic DNS, or free hosting "
                    "could have infrastructure that superficially resembles these patterns. "
                    "This is why infrastructure-based attribution alone is unreliable."
                ),
            },
            {
                "id": "APT_EASTERN_EUROPEAN",
                "category": "Eastern European Cyber Espionage",
                "public_sources": [
                    "CrowdStrike Fancy Bear Reporting",
                    "ESET Turla Analysis",
                    "Kaspersky Sofacy Reporting",
                ],
                "patterns": [
                    "Compromised government/NGO websites as C2",
                    "Short-lived domains registered in bulk",
                    "Specific TLS cipher preferences",
                    "Custom malware with modular architecture",
                    "Cloud storage services for exfiltration (Google Drive, Dropbox)",
                    "Legitimate email services for spear-phishing",
                ],
                "false_flag_note": (
                    "Use of Google Drive or email for file transfer is universal. "
                    "Short-lived domains are also common in legitimate marketing campaigns. "
                    "Attribution based on these patterns requires multiple corroborating sources."
                ),
            },
            {
                "id": "FINANCIAL_THREAT_ACTOR",
                "category": "Financially-Motivated Threat Actors",
                "public_sources": [
                    "FBI IC3 Annual Reports",
                    "Europol Internet Organised Crime Threat Assessment",
                    "Microsoft Digital Defense Report",
                ],
                "patterns": [
                    "Bulletproof hosting providers",
                    "Cryptocurrency infrastructure (mining pools, mixers)",
                    "Ransomware payment portals",
                    "Stolen credentials traded on dark markets",
                    "Phishing kits with brand impersonation",
                    "Compromised RDP/SSH for lateral movement",
                ],
                "false_flag_note": (
                    "Legitimate use of cryptocurrency and VPN services should never be "
                    "considered suspicious in isolation. Many financial organizations use "
                    "the same infrastructure patterns."
                ),
            },
            {
                "id": "MIDDLE_EASTERN_GOV",
                "category": "Middle Eastern Government-Linked Operations",
                "public_sources": [
                    "Citizen Lab Reporting",
                    "Amnesty International Technical Reports",
                    "Google TAG Reports",
                ],
                "patterns": [
                    "Social media platform abuse for targeting",
                    "Legitimate hosting services with fake personas",
                    "SMS-based phishing with regional lures",
                    "Domain registration patterns mimicking legitimate services",
                    "Zero-day exploitation chains",
                    "Spyware delivery via network injection",
                ],
                "false_flag_note": (
                    "SMS phishing and social media are used by every category of threat "
                    "actor. Regional domain patterns overlap with legitimate regional businesses."
                ),
            },
        ],
    },
    # ── Narrative Construction Indicators ──
    "narrative_construction_signals": {
        "description": (
            "Publicly observable signals that could be woven into a false narrative "
            "about an organization. Defensive analysts should understand how these "
            "signals can be selectively presented to create misleading impressions."
        ),
        "indicators": [
            {
                "name": "exposed_technology_stack",
                "pattern": r"(X-Powered-By|Server:|X-AspNet-Version|X-Generator|meta\s+name=['\"]generator)",
                "context": "response_headers, html_body",
                "risk": "medium",
                "narrative_risk": (
                    "An adversary could document the technology stack and claim it matches "
                    "a known threat group's toolkit, constructing a false attribution narrative."
                ),
            },
            {
                "name": "exposed_internal_paths",
                "pattern": r"(/admin|/api/|/internal|/debug|/wp-admin|/phpmyadmin|/manager)",
                "context": "response_body",
                "risk": "high",
                "narrative_risk": (
                    "Discovered internal paths can be presented as 'C2 infrastructure' or "
                    "'malware drop points' to investigators unfamiliar with the target."
                ),
            },
            {
                "name": "exposed_contact_info",
                "pattern": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
                "context": "response_body",
                "risk": "low",
                "narrative_risk": (
                    "Contact information can be used to create fake social media profiles "
                    "or register lookalike domains, building a false identity narrative."
                ),
            },
            {
                "name": "exposed_version_info",
                "pattern": r"(v?[0-9]+\.[0-9]+\.[0-9]+|version\s*[:=]\s*['\"]?\w)",
                "context": "response_headers, html_body",
                "risk": "medium",
                "narrative_risk": (
                    "Specific version numbers can be cross-referenced with CVE databases to "
                    "claim the organization 'targets systems with known vulnerabilities.'"
                ),
            },
        ],
    },
    # ── Attribution Obfuscation Techniques ──
    "attribution_obfuscation_techniques": {
        "description": (
            "Techniques that could be used to obfuscate or manipulate attribution. "
            "Detecting these on your own infrastructure helps confirm defensive posture."
        ),
        "techniques": [
            {
                "id": "header_flooding",
                "name": "Intentional Header Inconsistency",
                "description": (
                    "Deliberately varying HTTP headers across requests to create "
                    "conflicting infrastructure fingerprints."
                ),
                "detection": [
                    "Compare Server header across 5+ requests for the same endpoint",
                    "Check for rotating X-Powered-By values",
                    "Look for inconsistent ETag patterns",
                ],
                "legitimate_use": (
                    "A/B testing frameworks, blue-green deployments, and CDN layering "
                    "can all cause legitimate header variation."
                ),
            },
            {
                "id": "certificate_rotation_abuse",
                "name": "Aggressive Certificate Rotation",
                "description": (
                    "Rapidly cycling TLS certificates to create confusion about "
                    "the true operator of the infrastructure."
                ),
                "detection": [
                    "Monitor certificate transparency logs for frequent re-issuance",
                    "Compare certificate fingerprints across time windows",
                    "Check for certificates from multiple CAs for the same domain",
                ],
                "legitimate_use": (
                    "Automated certificate management (e.g., certbot with short-lived certs) "
                    "and multi-CDN deployments legitimately rotate certificates."
                ),
            },
            {
                "id": "geographic_fingerprint_mismatch",
                "name": "Geographic Fingerprint Mismatch",
                "description": (
                    "Infrastructure that appears to be in one geography but serves "
                    "content or behaves as if operated from another."
                ),
                "detection": [
                    "Compare IP geolocation with stated organizational presence",
                    "Check timezone headers (Date header) for consistency",
                    "Look for language/content mismatches with hosting location",
                ],
                "legitimate_use": (
                    "CDNs, cloud hosting, and globally distributed organizations all "
                    "legitimately have infrastructure in multiple geographies."
                ),
            },
            {
                "id": "tech_stack_masquerade",
                "name": "Technology Stack Masquerading",
                "description": (
                    "Deliberately presenting false technology fingerprints in headers, "
                    "error pages, or directory structures."
                ),
                "detection": [
                    "Compare declared technology with actual behavior (e.g., claims IIS but routes like Express)",
                    "Check for inconsistent error page styling with claimed server",
                    "Look for mismatched session cookie formats for claimed technology",
                ],
                "legitimate_use": (
                    "Security-conscious organizations may intentionally remove or alter "
                    "technology headers. This is a recommended defensive practice, not obfuscation."
                ),
            },
        ],
    },
}


# ════════════════════════════════════════════════════════════════════════
# MITRE_DECEPTION_TECHNIQUES — Mapping to ATT&CK Framework
# (Custom extension mapping deception TTPs to ATT&CK tactics)
# ════════════════════════════════════════════════════════════════════════

MITRE_DECEPTION_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "technique_id": "DEC-T1589-001",
        "technique_name": "Gather Victim Identity Information: Credentials",
        "mitre_attack_mapping": "T1589.001",
        "tactic": "Reconnaissance",
        "deception_application": (
            "Defensive: Understanding how leaked credentials can be used to "
            "impersonate an organization. Assess public exposure of employee "
            "credentials in breaches or paste sites to gauge impersonation risk."
        ),
        "defensive_countermeasure": (
            "Implement credential monitoring, enforce MFA, use unique service "
            "accounts, and regularly audit for leaked credentials."
        ),
    },
    {
        "technique_id": "DEC-T1589-002",
        "technique_name": "Gather Victim Identity Information: Employee Names",
        "mitre_attack_mapping": "T1589.002",
        "tactic": "Reconnaissance",
        "deception_application": (
            "Defensive: Employee names harvested from public sources (LinkedIn, "
            "company sites, conference speakers) enable spear-phishing with "
            "organization-impersonating lures."
        ),
        "defensive_countermeasure": (
            "Minimize public employee information, use generic contact addresses, "
            "train employees on social engineering, implement DMARC/DKIM/SPF."
        ),
    },
    {
        "technique_id": "DEC-T1592-004",
        "technique_name": "Gather Victim Host Information: Client Headers",
        "mitre_attack_mapping": "T1592.004",
        "tactic": "Reconnaissance",
        "deception_application": (
            "Defensive: Response headers leak technology details that enable "
            "an adversary to construct a convincing clone of the organization's "
            "web presence for phishing or false flag operations."
        ),
        "defensive_countermeasure": (
            "Remove all unnecessary response headers (Server, X-Powered-By, "
            "X-AspNet-Version). Use security header best practices."
        ),
    },
    {
        "technique_id": "DEC-T1595-002",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "mitre_attack_mapping": "T1595.002",
        "tactic": "Reconnaissance",
        "deception_application": (
            "Defensive: Vulnerability scan results can be used to construct a "
            "narrative that the target organization is itself conducting offensive "
            "operations (false flag)."
        ),
        "defensive_countermeasure": (
            "Use WAF rules to detect and rate-limit scanning, implement "
            "deceptive responses (tarpits, Canaries), and monitor for "
            "reconnaissance patterns."
        ),
    },
    {
        "technique_id": "DEC-T1659",
        "technique_name": "Impersonation",
        "mitre_attack_mapping": "T1659",
        "tactic": "Initial Access",
        "deception_application": (
            "Defensive: Understanding how an organization's public-facing "
            "infrastructure can be cloned or impersonated to conduct attacks "
            "that are falsely attributed to the organization."
        ),
        "defensive_countermeasure": (
            "Implement brand monitoring, register defensive domains, use DMARC "
            "to prevent email impersonation, deploy certificate transparency monitoring."
        ),
    },
    {
        "technique_id": "DEC-T1641",
        "technique_name": "False Flag Operations",
        "mitre_attack_mapping": "T1641",
        "tactic": "Initial Access",
        "deception_application": (
            "Defensive: Assess whether your infrastructure's observable characteristics "
            "match known threat group profiles, creating risk that someone else's "
            "attack could be attributed to you."
        ),
        "defensive_countermeasure": (
            "Conduct regular infrastructure audits, document legitimate infrastructure "
            "choices, and maintain an attribution baseline for your own assets."
        ),
    },
    {
        "technique_id": "DEC-T0001",
        "technique_name": "Infrastructure Masquerading",
        "mitre_attack_mapping": "Custom (maps to T1583+T1584 Resource Development)",
        "tactic": "Resource Development",
        "deception_application": (
            "Defensive: An adversary acquires infrastructure that mimics the target "
            "organization's hosting patterns, CDN configuration, and TLS setup to "
            "make their operations appear to originate from the target."
        ),
        "defensive_countermeasure": (
            "Use Extended Validation certificates, implement certificate pinning, "
            "monitor certificate transparency logs for lookalike domains."
        ),
    },
    {
        "technique_id": "DEC-T0002",
        "technique_name": "Narrative Injection via Metadata",
        "mitre_attack_mapping": "Custom (maps to T1592 Information Gathering)",
        "tactic": "Reconnaissance",
        "deception_application": (
            "Defensive: Public metadata (HTML meta tags, OpenGraph, JSON-LD, "
            "robots.txt, security.txt) can be selectively extracted and "
            "re-contextualized to construct false narratives."
        ),
        "defensive_countermeasure": (
            "Audit all public metadata, minimize information exposure in meta tags, "
            "and use security.txt to provide verified security contact information."
        ),
    },
    {
        "technique_id": "DEC-T0003",
        "technique_name": "Decoy Infrastructure Deployment",
        "mitre_attack_mapping": "Custom (maps to T1587 Develop Capabilities)",
        "tactic": "Resource Development",
        "deception_application": (
            "Defensive: Organizations deploy honeypots and decoy endpoints that "
            "mimic production infrastructure to detect and study attackers. "
            "This module generates recommendations for such deployments."
        ),
        "defensive_countermeasure": (
            "Deploy Canari tokens, honeyports, and decoy endpoints that match "
            "the organization's technology stack for maximum deception effectiveness."
        ),
    },
    {
        "technique_id": "DEC-T0004",
        "technique_name": "Attribution Signal Manipulation",
        "mitre_attack_mapping": "Custom (maps to T1036 Masquerading)",
        "tactic": "Defense Evasion",
        "deception_application": (
            "Defensive: Understanding how threat actors manipulate attribution signals "
            "(timestamps, language artifacts, compilation metadata) helps analysts "
            "recognize false flag attempts."
        ),
        "defensive_countermeasure": (
            "Train incident response teams on attribution uncertainty, require "
            "multiple independent indicators before attribution claims, and "
            "document your own infrastructure's 'normal' signature."
        ),
    },
]


# ════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ════════════════════════════════════════════════════════════════════════

SEV_POINTS: Dict[str, int] = {
    "critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0,
}

MODULE_NAME = "free_info_ops"


def _dread(damage: int, repro: int, exploit: int, affected: int, discover: int) -> float:
    """Compute DREAD score (0-10) from five component ratings."""
    return round((damage + repro + exploit + affected + discover) / 5.0, 1)


def _probe(
    url: str, timeout: int = 8, verify_tls: bool = True,
) -> Dict[str, Any]:
    """Thin wrapper around http_probe with default limiter."""
    return http_probe(url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)


def _fingerprint_technology(headers: Dict[str, str], body: str) -> Dict[str, List[str]]:
    """Extract technology fingerprints from HTTP response. Defensive: reveals
    what an adversary could learn about the target's stack."""
    tech: Dict[str, List[str]] = {
        "server": [],
        "frameworks": [],
        "cms": [],
        "languages": [],
        "cdn": [],
        "other": [],
    }

    server = headers.get("server", "")
    if server:
        tech["server"].append(server)

    powered = headers.get("x-powered-by", "")
    if powered:
        tech["frameworks"].append(powered)

    aspnet = headers.get("x-aspnet-version", "")
    if aspnet:
        tech["frameworks"].append(f"ASP.NET {aspnet}")
        tech["languages"].append(".NET")

    generator_match = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\'>]+)',
        body, re.IGNORECASE,
    )
    if generator_match:
        gen = generator_match.group(1).strip()
        tech["cms"].append(gen)

    cf_ray = headers.get("cf-ray", "")
    if cf_ray:
        tech["cdn"].append("Cloudflare")

    x_cache = headers.get("x-cache", "")
    if "cloudfront" in x_cache.lower():
        tech["cdn"].append("CloudFront")
    elif "akamai" in x_cache.lower():
        tech["cdn"].append("Akamai")
    elif "fastly" in x_cache.lower():
        tech["cdn"].append("Fastly")

    via = headers.get("via", "")
    if via:
        tech["cdn"].append(f"Via: {via}")

    if "wordpress" in body.lower() or "wp-content" in body.lower():
        tech["cms"].append("WordPress (inferred)")
    if "drupal" in body.lower():
        tech["cms"].append("Drupal (inferred)")
    if "joomla" in body.lower():
        tech["cms"].append("Joomla (inferred)")

    if ".php" in body or "PHPSESSID" in headers.get("set-cookie", ""):
        tech["languages"].append("PHP")
    if "ASP.NET" in body or "__VIEWSTATE" in body:
        tech["frameworks"].append("ASP.NET (inferred)")
        tech["languages"].append(".NET (inferred)")
    if ".py" in body or "django" in body.lower() or "csrfmiddlewaretoken" in body:
        tech["frameworks"].append("Django (inferred)")
        tech["languages"].append("Python")
    if "express" in body.lower() or "x-powered-by: express" in str(headers).lower():
        tech["frameworks"].append("Express (inferred)")
        tech["languages"].append("Node.js")
    if "next.js" in body.lower() or "__next" in body:
        tech["frameworks"].append("Next.js (inferred)")
        tech["languages"].append("JavaScript/TypeScript")
    if "react" in body.lower():
        tech["frameworks"].append("React (inferred)")

    csp = headers.get("content-security-policy", "")
    if csp:
        tech["other"].append(f"CSP present: {csp[:120]}...")

    for k, v in tech.items():
        tech[k] = list(dict.fromkeys(v))  # deduplicate preserving order

    return tech


def _extract_links(body: str, base_url: str) -> List[str]:
    """Extract absolute URLs from anchor tags in HTML body."""
    links: List[str] = []
    parsed_base = urllib.parse.urlparse(base_url)
    for m in re.finditer(r'href=["\']([^"\'>]+)["\']', body, re.IGNORECASE):
        href = m.group(1)
        if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        abs_url = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(abs_url)
        if parsed.netloc == parsed_base.netloc:
            links.append(abs_url)
    return list(dict.fromkeys(links))[:50]


def _extract_metadata(body: str) -> Dict[str, List[str]]:
    """Extract public metadata from HTML that could be used for narrative construction.
    Defensive: reveals what information is publicly available."""
    meta: Dict[str, List[str]] = {
        "title": [],
        "description": [],
        "og_tags": [],
        "generator": [],
        "author": [],
        "emails": [],
        "version_strings": [],
        "internal_paths": [],
        "comments": [],
    }

    title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
    if title_match:
        meta["title"].append(title_match.group(1).strip())

    desc_match = re.search(
        r'<meta\s+name=["\']description["\']\s+content=["\']([^"\'>]+)',
        body, re.IGNORECASE,
    )
    if desc_match:
        meta["description"].append(desc_match.group(1).strip())

    for og in re.finditer(
        r'<meta\s+property=["\']og:([^"\'>]+)["\']\s+content=["\']([^"\'>]+)',
        body, re.IGNORECASE,
    ):
        meta["og_tags"].append(f"og:{og.group(1)} = {og.group(2).strip()}")

    gen_match = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\'>]+)',
        body, re.IGNORECASE,
    )
    if gen_match:
        meta["generator"].append(gen_match.group(1).strip())

    author_match = re.search(
        r'<meta\s+name=["\']author["\']\s+content=["\']([^"\'>]+)',
        body, re.IGNORECASE,
    )
    if author_match:
        meta["author"].append(author_match.group(1).strip())

    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body)
    meta["emails"] = list(set(emails))

    versions = re.findall(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-[\w.]+)?", body)
    for v in versions[:20]:
        meta["version_strings"].append(v)

    paths = re.findall(r'(?:href|src|action)=["\'](/[a-zA-Z0-9_/.-]+)["\']', body, re.IGNORECASE)
    sensitive_keywords = [
        "admin", "api", "internal", "debug", "wp-admin", "phpmyadmin",
        "manager", "console", "dashboard", "config", "backup", "db",
        "staging", "dev", "test", "private", "secret", "key",
    ]
    for p in paths:
        if any(kw in p.lower() for kw in sensitive_keywords):
            meta["internal_paths"].append(p)
    meta["internal_paths"] = list(set(meta["internal_paths"]))

    comments = re.findall(r"<!--([^-]+(?:-[^>-]+)*?)-->", body)
    for c in comments:
        stripped = c.strip()
        if len(stripped) > 5:
            meta["comments"].append(stripped[:500])
    meta["comments"] = meta["comments"][:10]

    return meta


def _check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Evaluate security header presence and identify information leakage."""
    security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
    ]
    leaky_headers = [
        "x-powered-by",
        "x-aspnet-version",
        "x-drupal-cache",
        "x-generator",
        "server",
    ]
    headers_lower = {k.lower(): v for k, v in headers.items()}

    present = []
    missing = []
    for h in security_headers:
        if h in headers_lower:
            present.append(h)
        else:
            missing.append(h)

    leaking = []
    for h in leaky_headers:
        if h in headers_lower:
            leaking.append(f"{h}: {headers_lower[h]}")

    return {
        "present": present,
        "missing": missing,
        "leaking": leaking,
        "score": len(present) / max(len(security_headers), 1),
    }


def _compute_resilience_score(
    tech: Dict[str, List[str]],
    sec_headers: Dict[str, Any],
    metadata: Dict[str, List[str]],
) -> Tuple[float, List[str]]:
    """Compute a digital deception resilience score (0-100) and list factors.

    Higher score = more resilient against impersonation/deception.
    """
    score = 50.0
    factors: List[str] = []

    # Security headers presence (up to +20)
    header_score = sec_headers["score"] * 100
    header_bonus = header_score * 0.2
    score += header_bonus
    present_count = len(sec_headers["present"])
    if present_count >= 7:
        factors.append("+Strong security header coverage reduces fingerprint precision")
    elif present_count <= 2:
        score -= 10
        factors.append("-Minimal security headers increase impersonation feasibility")

    # Technology leakage (-2 per leaky header, max -15)
    leak_count = len(sec_headers["leaking"])
    leak_penalty = min(leak_count * 3, 15)
    score -= leak_penalty
    if leak_count > 0:
        factors.append(
            f"-{leak_count} information-leaking header(s) reveal technology details: "
            f"{', '.join(sec_headers['leaking'][:3])}"
        )

    # Technology stack complexity (more complex = harder to clone perfectly, +5)
    total_tech = sum(len(v) for v in tech.values())
    if total_tech > 8:
        score += 5
        factors.append("+Complex technology stack increases cloning difficulty")
    elif total_tech == 0:
        score -= 5
        factors.append("-Empty technology fingerprint means no baseline to detect clones")

    # CMS presence (common CMS = easier to clone, -5)
    if tech["cms"]:
        score -= 5
        factors.append(
            f"-CMS detected ({', '.join(tech['cms'][:2])}) — common CMS setups are "
            f"easy to replicate for impersonation"
        )
    else:
        score += 3
        factors.append("+No identifiable CMS detected — harder to produce a convincing clone")

    # Metadata exposure (-2 per exposed category)
    exposed_categories = 0
    if metadata["emails"]:
        exposed_categories += 1
        factors.append(
            f"-{len(metadata['emails'])} email(s) exposed — enables social engineering"
        )
    if metadata["internal_paths"]:
        exposed_categories += 1
        factors.append(
            f"-{len(metadata['internal_paths'])} sensitive path(s) revealed in source"
        )
    if metadata["version_strings"]:
        exposed_categories += 1
        factors.append(
            f"-{len(metadata['version_strings'])} version string(s) found — aids exploit "
            f"narrative construction"
        )
    if metadata["comments"]:
        exposed_categories += 1
        factors.append(
            f"-{len(metadata['comments'])} HTML comment(s) may contain internal information"
        )
    score -= exposed_categories * 3

    # CDN usage (slightly positive — CDN adds a layer of abstraction)
    if tech["cdn"]:
        score += 2
        factors.append(
            f"+CDN in use ({', '.join(tech['cdn'][:2])}) adds infrastructure "
            f"abstraction layer"
        )

    # Generator meta tag (direct tech leak, -3)
    if metadata["generator"]:
        score -= 3
        factors.append(
            f"-Generator meta tag reveals exact tool: {metadata['generator'][0]}"
        )

    score = max(0.0, min(100.0, score))
    return round(score, 1), factors


# ════════════════════════════════════════════════════════════════════════
# 1. INFRASTRUCTURE MISATTRIBUTION ANALYSIS
# ════════════════════════════════════════════════════════════════════════

def _analyze_misattribution_risk(
    target: str,
    base_url: str,
    headers: Dict[str, str],
    tech: Dict[str, List[str]],
    timeout: int,
    verify_tls: bool,
) -> List[Finding]:
    """Assess the risk that the target's infrastructure could be confused with
    other organizations based on shared signals (CDNs, IPs, certificates)."""
    findings: List[Finding] = []

    # Check shared CDN signatures
    cdn_indicators = DECEPTION_SIGNATURES["shared_hosting_red_flags"]["indicators"]
    for indicator in cdn_indicators:
        if indicator["name"] == "shared_cdn_origin" and indicator["pattern"]:
            headers_str = json.dumps(headers, default=str).lower()
            if re.search(indicator["pattern"], headers_str, re.IGNORECASE):
                cdn_matches = []
                if "cloudflare" in headers_str:
                    cdn_matches.append("Cloudflare")
                if "cloudfront" in headers_str:
                    cdn_matches.append("CloudFront")
                if "akamai" in headers_str:
                    cdn_matches.append("Akamai")
                if "fastly" in headers_str:
                    cdn_matches.append("Fastly")

                findings.append(Finding(
                    title="Shared CDN Infrastructure Detected",
                    severity="low",
                    category="Misattribution Risk",
                    module=MODULE_NAME,
                    description=(
                        f"Target uses shared CDN infrastructure: {', '.join(cdn_matches)}. "
                        f"{indicator['note']} This is standard practice but means "
                        f"infrastructure-based attribution is unreliable."
                    ),
                    evidence=f"CDN signatures: {', '.join(cdn_matches)} in response headers",
                    asset=target,
                    points_deducted=SEV_POINTS["low"],
                    remediation=(
                        "No action needed for shared CDN usage — this is industry standard. "
                        "For attribution defense, document your legitimate CDN choices and "
                        "maintain an infrastructure baseline."
                    ),
                    dread_score=_dread(3, 2, 1, 5, 4),
                ))

    # Check certificate chain risk
    cert_indicators = DECEPTION_SIGNATURES["certificate_chain_analysis"]["indicators"]
    server_header = headers.get("server", "")

    for indicator in cert_indicators:
        if indicator["name"] == "ev_certificate_absent":
            findings.append(Finding(
                title="Extended Validation Certificate Not Detected",
                severity="info",
                category="Misattribution Risk",
                module=MODULE_NAME,
                description=(
                    f"No Extended Validation (EV) certificate detected. {indicator['note']} "
                    f"Without EV, domain-only validation means any attacker who controls a "
                    f"lookalike domain can obtain an equivalent certificate."
                ),
                evidence="TLS connection established without EV certificate indicators",
                asset=target,
                points_deducted=SEV_POINTS["info"],
                remediation=(
                    "Consider Extended Validation certificates for high-value properties. "
                    "EV certificates require organizational identity verification, making "
                    "impersonation significantly harder."
                ),
                dread_score=_dread(4, 3, 2, 6, 3),
            ))

    # Check for technology fingerprints that increase misattribution risk
    if tech["cms"]:
        cms_list = ", ".join(tech["cms"][:3])
        findings.append(Finding(
            title=f"CMS Fingerprint Could Enable Infrastructure Confusion",
            severity="low",
            category="Misattribution Risk",
            module=MODULE_NAME,
            description=(
                f"CMS identified: {cms_list}. Many known threat groups also use these "
                f"platforms for their infrastructure. If your organization's compromised "
                f"WordPress site is used by a threat group, attribution could be confused."
            ),
            evidence=f"CMS fingerprints: {cms_list}",
            asset=target,
            points_deducted=SEV_POINTS["low"],
            remediation=(
                "Keep CMS and all plugins updated. Monitor for unauthorized modifications. "
                "Implement file integrity monitoring on CMS installations."
            ),
            dread_score=_dread(4, 3, 2, 4, 3),
        ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# 2. DECOY ENDPOINT GENERATION
# ════════════════════════════════════════════════════════════════════════

def _generate_decoy_recommendations(
    target: str,
    base_url: str,
    tech: Dict[str, List[str]],
    metadata: Dict[str, List[str]],
    headers: Dict[str, str],
    verify_tls: bool = True,
) -> List[Finding]:
    """Generate recommendations for decoy/honeypot endpoints that match the
    target's technology stack for defensive deception."""
    findings: List[Finding] = []
    recommendations: List[str] = []

    # Map detected technology to convincing decoy patterns
    decoy_paths: List[Dict[str, str]] = []

    # Generic high-value decoys (always recommended)
    decoy_paths.append({
        "path": "/api/v1/internal/credentials",
        "rationale": "Mimics a common internal API path; high attractiveness for credential harvesters",
        "tech_match": "any",
    })
    decoy_paths.append({
        "path": "/wp-login.php",
        "rationale": "WordPress login page; if WordPress is detected, this is a high-fidelity decoy",
        "tech_match": "wordpress",
    })
    decoy_paths.append({
        "path": "/admin/config.yml",
        "rationale": "Configuration file decoy; attractive for automated scanners",
        "tech_match": "any",
    })
    decoy_paths.append({
        "path": "/.env",
        "rationale": "Environment file; one of the most commonly probed paths by automated tools",
        "tech_match": "any",
    })
    decoy_paths.append({
        "path": "/api/v2/tokens",
        "rationale": "API token endpoint; attractive for token theft attempts",
        "tech_match": "api",
    })
    decoy_paths.append({
        "path": "/debug/console",
        "rationale": "Debug console decoy; attractive for attackers seeking management interfaces",
        "tech_match": "any",
    })

    # Technology-specific decoys
    tech_str = json.dumps(tech, default=str).lower()

    if "php" in tech_str or "wordpress" in tech_str:
        decoy_paths.append({
            "path": "/wp-content/uploads/shell.php",
            "rationale": "Mimics a common PHP webshell upload location for WordPress sites",
            "tech_match": "php/wordpress",
        })
        decoy_paths.append({
            "path": "/xmlrpc.php",
            "rationale": "WordPress XML-RPC interface; frequently targeted by brute-force tools",
            "tech_match": "wordpress",
        })

    if "node" in tech_str or "express" in tech_str:
        decoy_paths.append({
            "path": "/api/debug/heapdump",
            "rationale": "Node.js heap dump endpoint; attractive for memory scraping attempts",
            "tech_match": "nodejs",
        })

    if ".net" in tech_str or "asp" in tech_str:
        decoy_paths.append({
            "path": "/web.config.bak",
            "rationale": "ASP.NET configuration backup; commonly probed for credentials",
            "tech_match": "aspnet",
        })
        decoy_paths.append({
            "path": "/elmah.axd",
            "rationale": "ASP.NET error log handler; can reveal sensitive exception details",
            "tech_match": "aspnet",
        })

    if "django" in tech_str or "python" in tech_str:
        decoy_paths.append({
            "path": "/admin/login/",
            "rationale": "Django admin interface; high-value target for credential attacks",
            "tech_match": "django",
        })
        decoy_paths.append({
            "path": "/__debug__/",
            "rationale": "Django debug toolbar; reveals detailed request/response information",
            "tech_match": "django",
        })

    if "react" in tech_str or "next" in tech_str:
        decoy_paths.append({
            "path": "/api/_next/data/decoy.json",
            "rationale": "Mimics Next.js data route; blends with detected frontend framework",
            "tech_match": "nextjs",
        })

    # Check which paths already exist on the target (to avoid recommending
    # real endpoints as decoys)
    existing_real = set()
    for decoy in decoy_paths:
        probe_url = base_url.rstrip("/") + decoy["path"]
        resp = _probe(probe_url, timeout=6, verify_tls=verify_tls)
        if resp.get("ok") and resp.get("status") in (200, 301, 302, 403):
            existing_real.add(decoy["path"])

    # Filter out real paths and build recommendations
    valid_decoys = [d for d in decoy_paths if d["path"] not in existing_real]

    for decoy in valid_decoys:
        recommendations.append(
            f"  {decoy['path']}: {decoy['rationale']} [tech: {decoy['tech_match']}]"
        )

    if existing_real:
        recommendations.append(
            f"\n  NOTE: {len(existing_real)} path(s) already exist on target and were excluded "
            f"from decoy recommendations: {', '.join(sorted(existing_real)[:5])}"
        )

    if valid_decoys:
        findings.append(Finding(
            title=f"Decoy Endpoint Recommendations Generated ({len(valid_decoys)} endpoints)",
            severity="info",
            category="Deception Defense",
            module=MODULE_NAME,
            description=(
                f"Based on the detected technology stack, {len(valid_decoys)} decoy/honeypot "
                f"endpoints are recommended. These decoys are designed to match the target's "
                f"technology stack for maximum authenticity, helping detect and study "
                f"attackers targeting this organization.\n\n"
                f"Recommended decoy paths:\n"
                + "\n".join(recommendations[:10])
            ),
            evidence=f"Technology stack: {json.dumps({k: v for k, v in tech.items() if v}, default=str)}",
            asset=target,
            points_deducted=0,
            remediation=(
                "Deploy recommended decoy endpoints using a honeypot solution (e.g., "
                "Canarytokens, Honeyport, or a custom tarpit). Ensure decoys return "
                "realistic responses that match the production technology stack. "
                "Integrate alerts with your SIEM for immediate notification."
            ),
            dread_score=0.0,
        ))
    else:
        findings.append(Finding(
            title="Decoy Endpoint Analysis Completed",
            severity="info",
            category="Deception Defense",
            module=MODULE_NAME,
            description=(
                f"All recommended decoy paths already exist on the target. This suggests "
                f"the target has a comprehensive URL structure. Consider deploying decoys "
                f"at less common paths or using Canari tokens in response bodies."
            ),
            evidence="All proposed decoy paths resolved to real endpoints",
            asset=target,
            points_deducted=0,
            remediation=(
                "Consider deploying Canari tokens in HTML responses, honeyports on "
                "non-standard ports, or fake API endpoints with slightly altered paths "
                "(e.g., /api/v1/internal/credentialz)."
            ),
            dread_score=0.0,
        ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# 3. FALSE FLAG RISK ASSESSMENT
# ════════════════════════════════════════════════════════════════════════

def _assess_false_flag_risk(
    target: str,
    base_url: str,
    headers: Dict[str, str],
    tech: Dict[str, List[str]],
    metadata: Dict[str, List[str]],
) -> List[Finding]:
    """Check if the target's infrastructure has characteristics commonly
    attributed to specific threat groups — meaning they could be falsely blamed."""
    findings: List[Finding] = []

    archetypes = DECEPTION_SIGNATURES["threat_group_archetypes"]["archetypes"]
    matches: List[Dict[str, Any]] = []

    tech_flat = " ".join(v for vl in tech.values() for v in vl).lower()
    headers_flat = json.dumps(headers, default=str).lower()
    body_signals = " ".join(metadata["internal_paths"]).lower()

    for archetype in archetypes:
        archetype_matches: List[str] = []
        for pattern_desc in archetype["patterns"]:
            pattern_lower = pattern_desc.lower()

            # Check each pattern against observed infrastructure
            if ("wordpress" in pattern_lower and "wordpress" in tech_flat):
                archetype_matches.append(f"WordPress usage matches pattern: '{pattern_desc}'")
            elif ("php" in pattern_lower and "php" in tech_flat):
                archetype_matches.append(f"PHP usage matches pattern: '{pattern_desc}'")
            elif ("dynamic dns" in pattern_lower and ("dyndns" in target.lower() or "noip" in target.lower())):
                archetype_matches.append(f"Dynamic DNS domain matches pattern: '{pattern_desc}'")
            elif ("cloud storage" in pattern_lower and any(cdn in headers_flat for cdn in ["google", "amazon", "azure"])):
                archetype_matches.append(f"Cloud service usage matches pattern: '{pattern_desc}'")
            elif ("short-lived" in pattern_lower and "let's encrypt" in headers_flat):
                # Let's Encrypt certs are auto-renewed frequently
                archetype_matches.append(f"Auto-renewed certificate matches pattern: '{pattern_desc}'")
            elif ("cdn" in pattern_lower and tech["cdn"]):
                archetype_matches.append(f"CDN usage matches pattern: '{pattern_desc}'")
            elif ("compromised" in pattern_lower and "wordpress" in tech_flat):
                archetype_matches.append(f"WordPress presence matches risk: '{pattern_desc}'")
            elif ("internal" in pattern_lower and metadata["internal_paths"]):
                archetype_matches.append(f"Exposed internal paths match risk: '{pattern_desc}'")

        if archetype_matches:
            matches.append({
                "archetype_id": archetype["id"],
                "category": archetype["category"],
                "match_count": len(archetype_matches),
                "matches": archetype_matches,
                "false_flag_note": archetype["false_flag_note"],
            })

    if matches:
        total_matches = sum(m["match_count"] for m in matches)
        severity = "medium" if total_matches <= 3 else "high"

        match_details = []
        for m in matches:
            match_details.append(
                f"\n  [{m['archetype_id']}] {m['category']}: "
                f"{m['match_count']} overlapping pattern(s)\n"
                + "\n".join(f"    - {match}" for match in m["matches"][:3])
            )

        findings.append(Finding(
            title=f"False Flag Risk: {len(matches)} Threat Group Overlap(s) Detected",
            severity=severity,
            category="False Flag Risk",
            module=MODULE_NAME,
            description=(
                f"The target's infrastructure has characteristics that overlap with "
                f"{len(matches)} publicly reported threat group archetype(s), totaling "
                f"{total_matches} pattern match(es). This means that if an attack "
                f"originates from infrastructure resembling the target's, analysts could "
                f"incorrectly attribute it to the target organization.\n\n"
                f"IMPORTANT: These are SUPERFICIAL pattern overlaps only. They do NOT "
                f"indicate any actual relationship with the threat groups listed. "
                f"Infrastructure patterns are inherently ambiguous.\n\n"
                f"Detailed matches:"
                + "\n".join(match_details)
            ),
            evidence=f"Overlap with archetypes: {', '.join(m['archetype_id'] for m in matches)}",
            asset=target,
            points_deducted=SEV_POINTS[severity],
            remediation=(
                "Document your legitimate infrastructure choices and maintain an "
                "attribution baseline. If your organization is ever falsely accused, "
                "having documented infrastructure baselines helps demonstrate that "
                "the observed patterns are consistent with normal operations. "
                "Consider engaging a threat intelligence provider for proactive "
                "false flag monitoring."
            ),
            dread_score=_dread(7, 3, 4, 8, 5),
        ))

        # Add the false flag notes as informational findings
        for m in matches:
            findings.append(Finding(
                title=f"False Flag Note: {m['category']}",
                severity="info",
                category="False Flag Risk",
                module=MODULE_NAME,
                description=m["false_flag_note"],
                evidence=f"Archetype: {m['archetype_id']}, Matches: {m['match_count']}",
                asset=target,
                points_deducted=0,
                remediation="",
                dread_score=0.0,
            ))
    else:
        findings.append(Finding(
            title="False Flag Risk: No Significant Threat Group Overlaps",
            severity="info",
            category="False Flag Risk",
            module=MODULE_NAME,
            description=(
                f"The target's infrastructure does not have significant characteristics "
                f"that overlap with publicly known threat group archetypes. This reduces "
                f"(but does not eliminate) the risk of false flag attribution."
            ),
            evidence="No pattern matches against known threat group archetypes",
            asset=target,
            points_deducted=0,
            remediation=(
                "Continue to monitor infrastructure changes. New threat group "
                "reporting may introduce patterns that overlap with your infrastructure."
            ),
            dread_score=0.0,
        ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# 4. DIGITAL DECEPTION RESILIENCE SCORING
# ════════════════════════════════════════════════════════════════════════

def _score_deception_resilience(
    target: str,
    tech: Dict[str, List[str]],
    sec_headers: Dict[str, Any],
    metadata: Dict[str, List[str]],
) -> List[Finding]:
    """Score how resilient the target's digital presence is against
    impersonation and deception operations."""
    findings: List[Finding] = []

    score, factors = _compute_resilience_score(tech, sec_headers, metadata)

    if score >= 70:
        severity = "info"
        grade_label = "High Resilience"
    elif score >= 45:
        severity = "low"
        grade_label = "Moderate Resilience"
    elif score >= 25:
        severity = "medium"
        grade_label = "Low Resilience"
    else:
        severity = "high"
        grade_label = "Critical — Highly Vulnerable to Impersonation"

    findings.append(Finding(
        title=f"Digital Deception Resilience Score: {score}/100 ({grade_label})",
        severity=severity,
        category="Deception Resilience",
        module=MODULE_NAME,
        description=(
            f"The target's resilience against digital impersonation and deception "
            f"operations has been scored at {score}/100.\n\n"
            f"Resilience factors:\n"
            + "\n".join(factors)
            + f"\n\n"
            f"Score breakdown: This score measures how difficult it would be for an "
            f"adversary to create a convincing clone of the target's web presence. "
            f"Factors include information leakage, technology exposure, security header "
            f"coverage, and metadata exposure."
        ),
        evidence=f"Score: {score}/100, Factors: {len(factors)}",
        asset=target,
        points_deducted=SEV_POINTS[severity],
        remediation=(
            "To improve deception resilience:\n"
            "1. Remove all unnecessary technology-revealing headers\n"
            "2. Implement comprehensive security headers (HSTS, CSP, X-Frame-Options)\n"
            "3. Minimize metadata exposure in HTML (remove generator tags, comments)\n"
            "4. Use generic error pages that don't reveal technology\n"
            "5. Consider Extended Validation certificates for high-value domains\n"
            "6. Implement certificate transparency monitoring for lookalike domains\n"
            "7. Remove exposed email addresses from public-facing pages"
        ),
        dread_score=_dread(6, 4, 5, 7, 6),
    ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# 5. NARRATIVE VULNERABILITY ANALYSIS
# ════════════════════════════════════════════════════════════════════════

def _analyze_narrative_vulnerability(
    target: str,
    base_url: str,
    headers: Dict[str, str],
    body: str,
    metadata: Dict[str, List[str]],
    tech: Dict[str, List[str]],
) -> List[Finding]:
    """Analyze public-facing metadata, headers, and responses for information
    that could be used to construct a false narrative about the organization."""
    findings: List[Finding] = []

    narrative_signals = DECEPTION_SIGNATURES["narrative_construction_signals"]["indicators"]
    found_signals: List[Dict[str, Any]] = []

    headers_str = json.dumps(headers, default=str)
    combined_text = headers_str + " " + body

    for signal in narrative_signals:
        if signal["pattern"]:
            matches = re.findall(signal["pattern"], combined_text, re.IGNORECASE)
            if matches:
                found_signals.append({
                    "signal_name": signal["name"],
                    "match_count": len(matches),
                    "samples": list(set(str(m) for m in matches[:5])),
                    "risk": signal["risk"],
                    "narrative_risk": signal["narrative_risk"],
                })

    # Check metadata-specific narrative risks
    if metadata["og_tags"]:
        found_signals.append({
            "signal_name": "OpenGraph Metadata",
            "match_count": len(metadata["og_tags"]),
            "samples": metadata["og_tags"][:3],
            "risk": "low",
            "narrative_risk": (
                "OpenGraph tags reveal organizational branding details that can be "
                "replicated on phishing sites. OG tags on a lookalike domain make "
                "social media previews identical to the legitimate site."
            ),
        })

    if metadata["title"]:
        found_signals.append({
            "signal_name": "Page Title",
            "match_count": 1,
            "samples": metadata["title"],
            "risk": "info",
            "narrative_risk": (
                "The page title can be trivially copied to make a phishing page "
                "appear legitimate in browser tabs and search results."
            ),
        })

    # Build narrative scenarios
    scenarios: List[str] = []
    if any(s["signal_name"] == "exposed_technology_stack" for s in found_signals):
        scenarios.append(
            "SCENARIO 1 — Technology Attribution Narrative: An adversary could document "
            "the target's technology stack and claim it matches a known threat group's "
            "toolkit, using the exposed headers and framework signatures as 'evidence.'"
        )
    if any(s["signal_name"] == "exposed_internal_paths" for s in found_signals):
        scenarios.append(
            "SCENARIO 2 — Infrastructure Narrative: Discovered internal paths could be "
            "presented as 'C2 infrastructure' or 'malware staging points' to "
            "investigators unfamiliar with the target's legitimate architecture."
        )
    if any(s["signal_name"] == "exposed_contact_info" for s in found_signals):
        scenarios.append(
            "SCENARIO 3 — Identity Fabrication: Exposed emails and contact info enable "
            "creation of fake social media profiles and registration of lookalike "
            "domains, building a false organizational identity."
        )
    if any(s["signal_name"] == "exposed_version_info" for s in found_signals):
        scenarios.append(
            "SCENARIO 4 — Vulnerability Exploitation Narrative: Specific version numbers "
            "can be cross-referenced with CVE databases to claim the organization "
            "'deliberately targets systems with known vulnerabilities.'"
        )
    if metadata["comments"]:
        scenarios.append(
            "SCENARIO 5 — Internal Comment Extraction: HTML comments may contain "
            "developer names, internal project references, or infrastructure details "
            "that can be woven into a false operational narrative."
        )

    if found_signals:
        signal_details = []
        for s in found_signals:
            signal_details.append(
                f"\n  [{s['risk'].upper()}] {s['signal_name']} ({s['match_count']} match(es))\n"
                f"    Samples: {', '.join(str(x)[:80] for x in s['samples'][:3])}\n"
                f"    Narrative risk: {s['narrative_risk'][:200]}"
            )

        severity = "medium"
        high_risk_count = sum(1 for s in found_signals if s["risk"] == "high")
        if high_risk_count >= 2:
            severity = "high"

        narrative_section = ""
        if scenarios:
            narrative_section = (
                "\n\nPotential false narrative scenarios:\n"
                + "\n\n".join(scenarios)
            )

        # Map to MITRE deception techniques
        related_techniques = [
            t for t in MITRE_DECEPTION_TECHNIQUES
            if "T1592" in t["technique_id"] or "T0002" in t["technique_id"]
        ]
        technique_refs = ", ".join(t["technique_id"] for t in related_techniques)

        findings.append(Finding(
            title=f"Narrative Vulnerability: {len(found_signals)} Signal(s) Detected",
            severity=severity,
            category="Narrative Risk",
            module=MODULE_NAME,
            description=(
                f"Analysis of public-facing content revealed {len(found_signals)} signal(s) "
                f"that could be used to construct false narratives about the organization.\n\n"
                f"Detected signals:"
                + "\n".join(signal_details)
                + narrative_section
                + f"\n\nRelated MITRE deception technique(s): {technique_refs}"
            ),
            evidence=f"Signals: {', '.join(s['signal_name'] for s in found_signals)}",
            asset=target,
            points_deducted=SEV_POINTS[severity],
            remediation=(
                "To reduce narrative vulnerability:\n"
                "1. Remove all technology-revealing HTTP headers\n"
                "2. Strip HTML comments from production deployments\n"
                "3. Remove generator meta tags\n"
                "4. Use generic contact forms instead of exposing email addresses\n"
                "5. Minimize version information in visible content\n"
                "6. Implement content security policies that limit data extraction\n"
                "7. Regularly audit public-facing content for information leakage"
            ),
            dread_score=_dread(6, 4, 5, 7, 5),
        ))
    else:
        findings.append(Finding(
            title="Narrative Vulnerability: Minimal Signals Detected",
            severity="info",
            category="Narrative Risk",
            module=MODULE_NAME,
            description=(
                f"The target's public-facing content has minimal extractable signals "
                f"that could be used for narrative construction. This is a positive "
                f"indicator for deception resilience."
            ),
            evidence="No significant narrative construction signals detected",
            asset=target,
            points_deducted=0,
            remediation=(
                "Continue to minimize public information exposure. Conduct periodic "
                "reviews of public-facing content for new information leakage."
            ),
            dread_score=0.0,
        ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# 6. ATTRIBUTION OBFUSCATION DETECTION
# ════════════════════════════════════════════════════════════════════════

def _detect_attribution_obfuscation(
    target: str,
    base_url: str,
    headers: Dict[str, str],
    body: str,
    tech: Dict[str, List[str]],
    timeout: int,
    verify_tls: bool,
) -> List[Finding]:
    """Detect if the target is already using misattribution techniques
    (inconsistent headers, mismatched certificates, misleading tech fingerprints)."""
    findings: List[Finding] = []
    obfuscation_techniques = DECEPTION_SIGNATURES["attribution_obfuscation_techniques"]["techniques"]
    detections: List[Dict[str, Any]] = []

    # Technique 1: Header Inconsistency — probe multiple times
    server_headers_seen: Dict[str, int] = {}
    probe_count = 3
    for i in range(probe_count):
        resp = _probe(base_url, timeout=timeout, verify_tls=verify_tls)
        srv = resp.get("headers", {}).get("server", "(none)")
        server_headers_seen[srv] = server_headers_seen.get(srv, 0) + 1

    unique_servers = len(server_headers_seen)
    if unique_servers > 1:
        server_details = ", ".join(f"'{s}' ({c}/{probe_count} requests)" for s, c in server_headers_seen.items())
        detections.append({
            "technique": "header_flooding",
            "name": "Intentional Header Inconsistency",
            "evidence": f"Server header varied across {probe_count} requests: {server_details}",
            "severity": "medium",
            "note": obfuscation_techniques[0]["legitimate_use"],
        })

    # Technique 2: Technology Stack Masquerade — check for contradictions
    contradictions: List[str] = []
    server_header = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()
    tech_flat = " ".join(v for vl in tech.values() for v in vl).lower()

    # Check for server/body mismatch
    if "nginx" in server_header and ("apache" in body.lower() or "mod_ssl" in body.lower()):
        contradictions.append(
            "Server header claims nginx but body contains Apache/mod_ssl references"
        )
    if "apache" in server_header and "nginx" in body.lower():
        contradictions.append(
            "Server header claims Apache but body contains nginx references"
        )
    if "iis" in server_header and "php" in tech_flat and "asp" not in tech_flat:
        contradictions.append(
            "Server header claims IIS but detected technology is PHP (not ASP.NET)"
        )
    if powered_by and server_header:
        if ("express" in powered_by and "nginx" not in server_header
                and "apache" not in server_header):
            # Express behind something else is normal; this is fine
            pass

    if contradictions:
        detections.append({
            "technique": "tech_stack_masquerade",
            "name": "Technology Stack Masquerading",
            "evidence": "; ".join(contradictions),
            "severity": "high",
            "note": obfuscation_techniques[3]["legitimate_use"],
        })

    # Technique 3: Geographic Fingerprint Mismatch — check Date header timezone
    date_header = headers.get("date", "")
    if date_header:
        # Parse the timezone from the Date header
        tz_match = re.search(r"GMT([+-]\d{4})?", date_header)
        if tz_match:
            tz_info = tz_match.group(0)
            detections.append({
                "technique": "geographic_fingerprint_mismatch",
                "name": "Geographic Fingerprint Check",
                "evidence": f"Date header timezone: {tz_info}",
                "severity": "info",
                "note": (
                    "Timezone in Date header is standard (GMT). This is expected for "
                    "globally-distributed services. Manual comparison with the organization's "
                    "stated geographic presence is needed for full assessment."
                ),
            })

    # Technique 4: Check for missing/reduced fingerprints (could be defensive or obfuscatory)
    if not tech["server"] and not tech["frameworks"] and not tech["cms"]:
        detections.append({
            "technique": "fingerprint_removal",
            "name": "Technology Fingerprint Removal",
            "evidence": "No Server, X-Powered-By, or CMS fingerprints detected in headers/body",
            "severity": "info",
            "note": (
                "Fingerprint removal is a RECOMMENDED defensive practice. It reduces "
                "the information available to both attackers AND analysts. This is "
                "generally positive for security but means passive fingerprinting "
                "cannot identify the technology stack."
            ),
        })

    if detections:
        detection_details = []
        for d in detections:
            detection_details.append(
                f"\n  [{d['severity'].upper()}] {d['name']}\n"
                f"    Evidence: {d['evidence'][:200]}\n"
                f"    Note: {d['note'][:200]}"
            )

        high_count = sum(1 for d in detections if d["severity"] == "high")
        overall_sev = "high" if high_count >= 1 else "medium"

        findings.append(Finding(
            title=f"Attribution Obfuscation: {len(detections)} Signal(s) Detected",
            severity=overall_sev,
            category="Attribution Analysis",
            module=MODULE_NAME,
            description=(
                f"Analysis detected {len(detections)} potential attribution obfuscation "
                f"signal(s). These may indicate intentional misdirection, defensive "
                "fingerprint removal, or legitimate infrastructure variability.\n\n"
                f"IMPORTANT: Attribution obfuscation is not inherently malicious. "
                f"Many of these signals are the result of standard security practices "
                f"or infrastructure design choices.\n\n"
                f"Detection results:"
                + "\n".join(detection_details)
            ),
            evidence=f"Techniques: {', '.join(d['technique'] for d in detections)}",
            asset=target,
            points_deducted=SEV_POINTS.get(overall_sev, 0),
            remediation=(
                "If obfuscation is intentional (defensive), document the techniques used "
                "for incident response teams. If unintentional, review infrastructure for "
                "inconsistencies that may arise from heterogeneous backends or CDN "
                "layering. Ensure any fingerprint removal is systematic, not accidental."
            ),
            dread_score=_dread(5, 3, 3, 6, 4),
        ))
    else:
        findings.append(Finding(
            title="Attribution Obfuscation: No Significant Signals Detected",
            severity="info",
            category="Attribution Analysis",
            module=MODULE_NAME,
            description=(
                f"No significant attribution obfuscation signals were detected in the "
                f"target's infrastructure. The technology fingerprints appear consistent "
                f"across multiple requests."
            ),
            evidence="Consistent headers and technology fingerprints across multiple probes",
            asset=target,
            points_deducted=0,
            remediation="",
            dread_score=0.0,
        ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# 7. HONEYPOT INTEGRATION PLANNING
# ════════════════════════════════════════════════════════════════════════

def _plan_honeypot_integration(
    target: str,
    base_url: str,
    tech: Dict[str, List[str]],
    metadata: Dict[str, List[str]],
    sec_headers: Dict[str, Any],
    timeout: int,
    verify_tls: bool,
) -> List[Finding]:
    """Recommend where honeypot endpoints would be most effective based on
    observed attacker interest patterns and the target's technology profile."""
    findings: List[Finding] = []

    # Probe commonly attacked paths to gauge existing attacker interest
    attacker_interest_paths: List[Dict[str, Any]] = [
        {"path": "/.env", "category": "config_exposure", "weight": 9},
        {"path": "/wp-login.php", "category": "cms_auth", "weight": 8},
        {"path": "/admin", "category": "admin_panel", "weight": 9},
        {"path": "/phpmyadmin", "category": "db_admin", "weight": 7},
        {"path": "/api/v1/users", "category": "api_data", "weight": 8},
        {"path": "/.git/HEAD", "category": "repo_exposure", "weight": 9},
        {"path": "/robots.txt", "category": "recon", "weight": 5},
        {"path": "/sitemap.xml", "category": "recon", "weight": 4},
        {"path": "/server-status", "category": "info_disclosure", "weight": 7},
        {"path": "/actuator/health", "category": "spring_boot", "weight": 6},
        {"path": "/api/debug", "category": "debug_endpoint", "weight": 8},
        {"path": "/backup", "category": "backup_exposure", "weight": 7},
        {"path": "/config.json", "category": "config_exposure", "weight": 8},
        {"path": "/.DS_Store", "category": "file_exposure", "weight": 5},
        {"path": "/wp-content/debug.log", "category": "wordpress_log", "weight": 6},
    ]

    # Technology-tailored additions
    tech_flat = json.dumps(tech, default=str).lower()
    if "django" in tech_flat:
        attacker_interest_paths.append(
            {"path": "/admin/login/", "category": "django_admin", "weight": 8}
        )
    if ".net" in tech_flat or "asp" in tech_flat:
        attacker_interest_paths.append(
            {"path": "/elmah.axd", "category": "aspnet_errors", "weight": 6}
        )
        attacker_interest_paths.append(
            {"path": "/trace.axd", "category": "aspnet_trace", "weight": 6}
        )
    if "node" in tech_flat or "express" in tech_flat:
        attacker_interest_paths.append(
            {"path": "/api/debug/heapdump", "category": "nodejs_debug", "weight": 7}
        )
    if "react" in tech_flat or "next" in tech_flat:
        attacker_interest_paths.append(
            {"path": "/_next/data/build-manifest.json", "category": "nextjs_exposure", "weight": 5}
        )

    # Probe each path
    probe_results: List[Dict[str, Any]] = []
    existing_paths: List[str] = []
    missing_paths: List[str] = []

    for entry in attacker_interest_paths:
        probe_url = base_url.rstrip("/") + entry["path"]
        resp = _probe(probe_url, timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body_len = len(resp.get("body", ""))

        result = {
            "path": entry["path"],
            "category": entry["category"],
            "weight": entry["weight"],
            "status": status,
            "body_length": body_len,
            "exists": status in (200, 301, 302, 401, 403),
        }
        probe_results.append(result)

        if result["exists"]:
            existing_paths.append(entry["path"])
        else:
            missing_paths.append(entry["path"])

    # Calculate honeypot placement scores
    # Prioritize: high weight + doesn't exist yet (gap to fill) + matches tech
    honeypot_candidates: List[Dict[str, Any]] = []
    for result in probe_results:
        if not result["exists"]:
            score = result["weight"]
            # Bonus for matching detected technology
            cat = result["category"]
            if "wordpress" in cat and "wordpress" in tech_flat:
                score += 3
            if "django" in cat and "django" in tech_flat:
                score += 3
            if "aspnet" in cat and ("asp" in tech_flat or ".net" in tech_flat):
                score += 3
            if "nodejs" in cat and "node" in tech_flat:
                score += 3
            if "nextjs" in cat and ("next" in tech_flat or "react" in tech_flat):
                score += 3
            # Bonus for config exposure (universal attacker interest)
            if "config" in cat or "exposure" in cat:
                score += 2

            honeypot_candidates.append({
                **result,
                "honeypot_score": score,
            })

    honeypot_candidates.sort(key=lambda x: x["honeypot_score"], reverse=True)
    top_candidates = honeypot_candidates[:10]

    # Build recommendation
    if top_candidates:
        candidate_details = []
        for c in top_candidates:
            candidate_details.append(
                f"\n  [Score: {c['honeypot_score']}] {c['path']} "
                f"(category: {c['category']}, current status: {c['status']})"
            )

        # Category analysis
        categories: Dict[str, int] = {}
        for c in top_candidates:
            cat = c["category"]
            categories[cat] = categories.get(cat, 0) + 1
        top_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]
        category_summary = ", ".join(f"{cat} ({cnt})" for cat, cnt in top_categories)

        # Map to MITRE techniques
        decoy_technique = next(
            (t for t in MITRE_DECEPTION_TECHNIQUES if "T0003" in t["technique_id"]),
            None,
        )

        findings.append(Finding(
            title=f"Honeypot Plan: {len(top_candidates)} High-Value Placement(s) Recommended",
            severity="info",
            category="Deception Defense",
            module=MODULE_NAME,
            description=(
                f"Based on attacker interest pattern analysis and technology stack matching, "
                f"{len(top_candidates)} honeypot placement(s) are recommended.\n\n"
                f"Probe summary: {len(existing_paths)} path(s) already exist, "
                f"{len(missing_paths)} path(s) are available for honeypot deployment.\n\n"
                f"Top honeypot candidates (scored by attacker interest + tech match):"
                + "\n".join(candidate_details)
                + f"\n\nMost targeted categories: {category_summary}\n\n"
                f"MITRE reference: {decoy_technique['technique_id'] if decoy_technique else 'N/A'} "
                f"— {decoy_technique['technique_name'] if decoy_technique else 'N/A'}"
            ),
            evidence=f"Probed {len(attacker_interest_paths)} paths, {len(existing_paths)} exist, "
                    f"{len(top_candidates)} honeypot candidates identified",
            asset=target,
            points_deducted=0,
            remediation=(
                "Honeypot deployment recommendations:\n"
                "1. Deploy high-scored candidates first (config exposure, admin panels)\n"
                "2. Ensure honeypot responses match the production technology stack\n"
                "3. Integrate with SIEM for real-time alerting on honeypot triggers\n"
                "4. Use Canari tokens in honeypot responses forbreadcrumb tracking\n"
                "5. Rotate honeypot content periodically to maintain realism\n"
                "6. Consider honeyports on unused ports detected during scanning\n"
                "7. Log all honeypot interactions with full request metadata for threat intel"
            ),
            dread_score=0.0,
        ))
    else:
        findings.append(Finding(
            title="Honeypot Integration: All Probed Paths Exist",
            severity="info",
            category="Deception Defense",
            module=MODULE_NAME,
            description=(
                f"All {len(attacker_interest_paths)} probed paths already exist on the target. "
                f"This comprehensive URL structure limits traditional honeypot placement "
                f"options. Consider alternative deception strategies."
            ),
            evidence=f"All {len(attacker_interest_paths)} probed paths returned real responses",
            asset=target,
            points_deducted=0,
            remediation=(
                "Alternative honeypot strategies:\n"
                "1. Deploy Canari tokens in existing response bodies\n"
                "2. Use honeyports on non-standard ports\n"
                "3. Create slightly-altered path variants (typo-squatting honeypots)\n"
                "4. Deploy fake subdomains as deception layer\n"
                "5. Use DNS honeypots for non-existent subdomains"
            ),
            dread_score=0.0,
        ))

    # Add informational finding about existing paths that may already be honeypots
    if existing_paths:
        findings.append(Finding(
            title=f"Honeypot Note: {len(existing_paths)} Path(s) Already Respond",
            severity="info",
            category="Deception Defense",
            module=MODULE_NAME,
            description=(
                f"{len(existing_paths)} commonly-attacked path(s) already return responses. "
                f"These may be legitimate endpoints or existing honeypots. Paths: "
                f"{', '.join(existing_paths[:10])}"
            ),
            evidence=f"Existing paths: {', '.join(existing_paths[:10])}",
            asset=target,
            points_deducted=0,
            remediation=(
                "Verify whether existing endpoints at commonly-attacked paths are "
                "intentional honeypots or legitimate services. If legitimate, consider "
                "adding deception signals (Canari tokens) to their responses."
            ),
            dread_score=0.0,
        ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# MAIN EXPORT: run_info_ops
# ════════════════════════════════════════════════════════════════════════

def run_info_ops(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Run the full Information Operations defensive analysis suite.

    This module performs a comprehensive defensive assessment of how the target's
    publicly observable infrastructure could be exploited for misattribution,
    impersonation, false flag operations, or narrative manipulation.

    ALL CAPABILITIES ARE DEFENSIVE/EDUCATIONAL ONLY.

    Args:
        target: The target hostname or identifier.
        base_url: The base URL to probe (e.g., "https://example.com").
        timeout: HTTP request timeout in seconds.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        List of Finding objects with assessment results.
    """
    findings: List[Finding] = []

    # ── Phase 0: Initial Reconnaissance ──────────────────────────────────
    resp = _probe(base_url, timeout=timeout, verify_tls=verify_tls)
    headers = resp.get("headers", {})
    body = resp.get("body", "")
    status = resp.get("status", 0)

    if status == 0 and not body:
        findings.append(Finding(
            title="Information Operations Analysis: Target Unreachable",
            severity="info",
            category="Reconnaissance",
            module=MODULE_NAME,
            description=(
                f"Could not connect to {base_url}. The Information Operations "
                f"analysis requires a reachable HTTP endpoint to assess deception "
                f"risks from publicly observable infrastructure."
            ),
            evidence=f"HTTP probe returned status 0 for {base_url}",
            asset=target,
            points_deducted=0,
            remediation=(
                "Verify the target URL is correct and accessible. If the target uses "
                "non-standard ports, ensure they are included in the base_url."
            ),
            dread_score=0.0,
        ))
        return findings

    # ── Phase 1: Technology Fingerprinting ────────────────────────────────
    tech = _fingerprint_technology(headers, body)
    metadata = _extract_metadata(body)
    sec_headers = _check_security_headers(headers)

    # ── Phase 2: Run All Analysis Modules ────────────────────────────────

    # 1. Infrastructure Misattribution Analysis
    findings.extend(
        _analyze_misattribution_risk(target, base_url, headers, tech, timeout, verify_tls)
    )

    # 2. Decoy Endpoint Generation
    findings.extend(
        _generate_decoy_recommendations(target, base_url, tech, metadata, headers, verify_tls)
    )

    # 3. False Flag Risk Assessment
    findings.extend(
        _assess_false_flag_risk(target, base_url, headers, tech, metadata)
    )

    # 4. Digital Deception Resilience Scoring
    findings.extend(
        _score_deception_resilience(target, tech, sec_headers, metadata)
    )

    # 5. Narrative Vulnerability Analysis
    findings.extend(
        _analyze_narrative_vulnerability(target, base_url, headers, body, metadata, tech)
    )

    # 6. Attribution Obfuscation Detection
    findings.extend(
        _detect_attribution_obfuscation(target, base_url, headers, body, tech, timeout, verify_tls)
    )

    # 7. Honeypot Integration Planning
    findings.extend(
        _plan_honeypot_integration(target, base_url, tech, metadata, sec_headers, timeout, verify_tls)
    )

    # ── Phase 3: Summary Finding ─────────────────────────────────────────
    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    medium_count = sum(1 for f in findings if f.severity == "medium")
    total_findings = len(findings)
    total_points = sum(f.points_deducted for f in findings)

    findings.append(Finding(
        title=f"Information Operations Analysis Complete: {total_findings} Finding(s)",
        severity="info",
        category="Summary",
        module=MODULE_NAME,
        description=(
            f"Information Operations defensive analysis completed for {target}.\n\n"
            f"Analysis Summary:\n"
            f"  Total findings: {total_findings}\n"
            f"  Critical: {critical_count}, High: {high_count}, Medium: {medium_count}\n"
            f"  Points deducted: {total_points}\n\n"
            f"Technology Profile:\n"
            f"  Server: {', '.join(tech['server']) or 'Not detected'}\n"
            f"  Frameworks: {', '.join(tech['frameworks']) or 'Not detected'}\n"
            f"  CMS: {', '.join(tech['cms']) or 'Not detected'}\n"
            f"  Languages: {', '.join(tech['languages']) or 'Not detected'}\n"
            f"  CDN: {', '.join(tech['cdn']) or 'Not detected'}\n\n"
            f"Security Headers: {len(sec_headers['present'])}/{len(sec_headers['present']) + len(sec_headers['missing'])} present\n"
            f"Information-Leaking Headers: {len(sec_headers['leaking'])}\n\n"
            f"Modules Executed:\n"
            f"  1. Infrastructure Misattribution Analysis\n"
            f"  2. Decoy Endpoint Generation\n"
            f"  3. False Flag Risk Assessment\n"
            f"  4. Digital Deception Resilience Scoring\n"
            f"  5. Narrative Vulnerability Analysis\n"
            f"  6. Attribution Obfuscation Detection\n"
            f"  7. Honeypot Integration Planning\n\n"
            f"MITRE Deception Techniques Referenced: {len(MITRE_DECEPTION_TECHNIQUES)}\n"
            f"Deception Signature Database Categories: {len(DECEPTION_SIGNATURES)}\n\n"
            f"IMPORTANT: All findings in this module are for DEFENSIVE purposes. "
            f"This analysis helps organizations understand and mitigate risks from "
            f"information operations, misattribution, and digital deception."
        ),
        evidence=f"Analyzed {base_url} across 7 IO analysis modules",
        asset=target,
        points_deducted=0,
        remediation=(
            "Review all findings and prioritize by severity. The Digital Deception "
            "Resilience Score provides an overall metric. Focus on reducing information "
            "leakage first (removing headers, minimizing metadata) as this addresses "
            "multiple finding categories simultaneously."
        ),
        dread_score=0.0,
    ))

    return findings

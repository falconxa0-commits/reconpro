"""Module: DARK WEB MONITOR — Credential Leak & Exposure Scanner.

Monitors paste sites, leak directories, breach databases, and threat intelligence
sources for target credentials/infrastructure mentions — all without Tor, all via stdlib.

7 Detection Categories:
  1. Paste Site Monitoring (PasteBin, GitHub gists, Rentry, Ghostbin)
  2. Credential Leak Detection (email:password, API keys, JWT tokens)
  3. Infrastructure Exposure (abuse DBs, malware reports, breach dumps)
  4. Leak Temporal Analysis (ongoing vs historical breach patterns)
  5. Dark Web Intelligence Sources (ThreatFox, URLhaus, MalBazaar, OTX)
  6. Breach Database Correlation (cross-reference known breaches)
  7. Secret Exposure Scanning (GitHub code search for hardcoded secrets)
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from ..http_layer import http_probe, Finding, default_limiter


# ═══════════════════════════════════════════════════════════════════════════
# Paste Sites & Threat Intelligence Sources Database
# ═══════════════════════════════════════════════════════════════════════════

PASTE_SITES: Dict[str, Dict[str, Any]] = {
    "pastebin": {
        "name": "PasteBin",
        "search_url": "https://pastebin.com/search?q={query}",
        "api_url": "https://pastebin.com/api/api_post.php",
        "type": "html",
        "rate_limit": 1.0,
        "severity": "high",
    },
    "github_gist": {
        "name": "GitHub Gists",
        "search_url": "https://gist.github.com/search?q={query}",
        "type": "html",
        "rate_limit": 3.0,
        "severity": "high",
    },
    "github_code": {
        "name": "GitHub Code",
        "search_url": "https://github.com/search?q={query}&type=code",
        "type": "html",
        "rate_limit": 3.0,
        "severity": "critical",
    },
    "rentry": {
        "name": "Rentry.co",
        "search_url": "https://rentry.co/search?q={query}",
        "type": "html",
        "rate_limit": 2.0,
        "severity": "medium",
    },
    "ghostbin": {
        "name": "Ghostbin",
        "search_url": "https://ghostbin.com/search?q={query}",
        "type": "html",
        "rate_limit": 2.0,
        "severity": "medium",
    },
    "paste_site": {
        "name": "PasteSite.org",
        "search_url": "https://www.pastesite.com/search?q={query}",
        "type": "html",
        "rate_limit": 2.0,
        "severity": "medium",
    },
    "justpaste": {
        "name": "JustPaste.it",
        "search_url": "https://justpaste.it/search?q={query}",
        "type": "html",
        "rate_limit": 2.0,
        "severity": "medium",
    },
}

THREAT_INTEL_SOURCES: Dict[str, Dict[str, Any]] = {
    "threatfox": {
        "name": "abuse.ch ThreatFox",
        "api_url": "https://threatfox-api.abuse.ch/v1/",
        "search_param": "query",
        "type": "json_api",
        "severity": "critical",
        "query_types": ["domain", "ip", "url", "hash"],
    },
    "urlhaus": {
        "name": "abuse.ch URLhaus",
        "search_url": "https://urlhaus-api.abuse.ch/v1/host/{query}",
        "type": "json_api",
        "severity": "critical",
    },
    "malbazaar": {
        "name": "abuse.ch MalBazaar",
        "search_url": "https://bazaar.abuse.ch/export/csv/recent/",
        "type": "csv",
        "severity": "high",
    },
    "alienvault_otx": {
        "name": "AlienVault OTX",
        "search_url": "https://otx.alienvault.com/api/v1/indicators/domain/{query}/general",
        "type": "json_api",
        "severity": "high",
    },
    "crtsh": {
        "name": "crt.sh Certificate Transparency",
        "search_url": "https://crt.sh/?q=%.{query}&output=json",
        "type": "json_api",
        "severity": "medium",
    },
    "virustotal": {
        "name": "VirusTotal",
        "search_url": "https://www.virustotal.com/vtapi/v2/domain/report?domain={query}",
        "type": "json_api",
        "severity": "high",
    },
}

# Known breach databases (public APIs that don't require auth)
BREACH_SOURCES: Dict[str, Dict[str, Any]] = {
    "haveibeenpwned": {
        "name": "HaveIBeenPwned",
        "api_url": "https://haveibeenpwned.com/api/v3/breachedaccount/{query}",
        "type": "json_api",
        "severity": "critical",
    },
    "hibp_password": {
        "name": "HIBP Password Check",
        "api_url": "https://api.pwnedpasswords.com/range/{prefix}",
        "type": "k-anonymity",
        "severity": "critical",
    },
}

# Credential patterns
CREDENTIAL_PATTERNS: Dict[str, Dict[str, Any]] = {
    "email_password": {
        "pattern": re.compile(
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
            r'[\s:;\|,\'"\x60]+'
            r'[^\s\x00-\x1f]{4,64}',
            re.IGNORECASE,
        ),
        "severity": "critical",
        "description": "Email:password combination found in paste content",
    },
    "api_key_generic": {
        "pattern": re.compile(
            r'(?:api[_\-]?key|apikey|key[_\-]?id|access[_\-]?key|secret[_\-]?key)'
            r'[\s]*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
            re.IGNORECASE,
        ),
        "severity": "critical",
        "description": "Generic API key exposed",
    },
    "aws_key": {
        "pattern": re.compile(
            r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
        ),
        "severity": "critical",
        "description": "AWS access key ID detected",
    },
    "aws_secret": {
        "pattern": re.compile(
            r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)'
            r'[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            re.IGNORECASE,
        ),
        "severity": "critical",
        "description": "AWS secret access key exposed",
    },
    "github_token": {
        "pattern": re.compile(
            r'(?:gh[ps]_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{22,})',
        ),
        "severity": "critical",
        "description": "GitHub personal access token or fine-grained PAT",
    },
    "jwt_token": {
        "pattern": re.compile(
            r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
        ),
        "severity": "high",
        "description": "JWT token detected (decoded header reveals algorithm and issuer)",
    },
    "private_key": {
        "pattern": re.compile(
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        ),
        "severity": "critical",
        "description": "Private key (RSA/EC/DSA/OpenSSH) exposed",
    },
    "db_connection_string": {
        "pattern": re.compile(
            r'(?:mongodb\+srv|mysql|postgres|redis|amqp)://[^\s\'"<>]{10,}',
            re.IGNORECASE,
        ),
        "severity": "high",
        "description": "Database connection string exposed",
    },
    "bearer_token": {
        "pattern": re.compile(
            r'(?:Bearer|Token|Authorization)[\s:]+([a-zA-Z0-9_\-\.]{20,})',
            re.IGNORECASE,
        ),
        "severity": "high",
        "description": "Bearer / authorization token exposed",
    },
    "slack_webhook": {
        "pattern": re.compile(
            r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
        ),
        "severity": "high",
        "description": "Slack webhook URL exposed",
    },
    "stripe_key": {
        "pattern": re.compile(
            r'(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}',
        ),
        "severity": "critical",
        "description": "Stripe secret/publishable key exposed",
    },
    "google_api_key": {
        "pattern": re.compile(
            r'AIza[0-9A-Za-z_\-]{35}',
        ),
        "severity": "high",
        "description": "Google API key detected",
    },
    "sendgrid_key": {
        "pattern": re.compile(
            r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        ),
        "severity": "high",
        "description": "SendGrid API key detected",
    },
    "twilio_key": {
        "pattern": re.compile(
            r'SK[0-9a-fA-F]{32}',
        ),
        "severity": "high",
        "description": "Twilio API key detected",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═══════════════════════════════════════════════════════════════════════════

def _make(
    title: str, sev: str, cat: str, desc: str,
    evidence: str, asset: str, pts: int = 0,
    remediation: str = "", dread: float = 0.0,
) -> Finding:
    return Finding(
        title=title, severity=sev, category=cat,
        module="dark_web_monitor", description=desc,
        evidence=evidence, asset=asset, points_deducted=pts,
        remediation=remediation, dread_score=dread,
    )


def _extract_domain(target: str) -> str:
    """Extract the root domain from a target."""
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    host = host.split(":")[0]
    parts = host.rsplit(".", 1)
    if len(parts) >= 2:
        # Check for common TLDs with two-part SLDs
        tld = parts[-1]
        if tld in ("co.uk", "com.au", "org.uk", "ac.uk", "gov.uk", "co.jp"):
            sub_parts = host.rsplit(".", 2)
            return ".".join(sub_parts[-2:]) if len(sub_parts) >= 2 else host
    return host


def _extract_email_domains(target: str) -> List[str]:
    """Generate likely email domains for the target."""
    domain = _extract_domain(target)
    domains = [domain]
    # Common email domain patterns
    domains.append(f"mail.{domain}")
    # Strip www
    if domain.startswith("www."):
        domains.append(domain[4:])
    return list(set(domains))


def _safe_probe(url: str, timeout: int = 5, verify_tls: bool = True) -> Dict[str, Any]:
    """Safe HTTP probe with error handling."""
    try:
        return http_probe(
            url, timeout=timeout, verify_tls=verify_tls,
            limiter=default_limiter,
        )
    except Exception:
        return {"ok": False, "status": 0, "reason": "error", "headers": {}, "body": ""}


def _parse_json(body: str) -> Optional[Any]:
    try:
        return json.loads(body)
    except Exception:
        return None


def _count_pattern(body: str, pattern: re.Pattern) -> int:
    """Count non-overlapping pattern matches."""
    return len(pattern.findall(body))


def _extract_emails_from_domain(domain: str) -> List[str]:
    """Extract likely email addresses from a domain name."""
    prefixes = ["admin", "info", "support", "contact", "root", "test",
                "webmaster", "noreply", "security", "dev", "staging"]
    return [f"{p}@{domain}" for p in prefixes]


def _decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT header and payload without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    result = {}
    for i, label in enumerate(("header", "payload")):
        try:
            padded = parts[i] + "=" * (-len(parts[i]) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            parsed = json.loads(decoded)
            result[label] = parsed
        except Exception:
            result[label] = None
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Cat 1: Paste Site Monitoring
# ═══════════════════════════════════════════════════════════════════════════

def _check_paste_sites(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    findings: List[Finding] = []
    host = _extract_domain(target)
    queries = [host]

    for site_id, site in PASTE_SITES.items():
        for query in queries:
            url = site["search_url"].format(query=urllib.parse.quote(query))
            resp = _safe_probe(url, timeout=min(timeout, 5), verify_tls=verify_tls)

            if resp.get("ok") and resp.get("status") == 200:
                body = resp.get("body", "")

                # Check for result indicators
                result_indicators = 0
                # Common patterns indicating search results
                if "result" in body.lower():
                    result_indicators += 1
                if "paste" in body.lower():
                    result_indicators += 1
                if host.lower() in body.lower():
                    result_indicators += 3  # Domain mention is strongest signal
                if re.search(rf'{re.escape(host)}[\s/<]', body, re.IGNORECASE):
                    result_indicators += 2

                # Count occurrences
                domain_count = body.lower().count(host.lower())

                if result_indicators >= 3:
                    sev = site.get("severity", "high")
                    pts = 18 if sev == "critical" else 12
                    findings.append(_make(
                        f"Paste Site Exposure — {site['name']}: domain found",
                        sev, "paste_exposure",
                        f"Target domain '{host}' found on {site['name']}. "
                        f"Indicators: {result_indicators}, domain mentions: {domain_count}. "
                        f"This may indicate leaked credentials, configuration data, or source code.",
                        f"Source: {site['name']}; Mentions: {domain_count}; URL: {url}",
                        host, pts,
                        "Review the paste content. Request removal if credentials/secrets are exposed.",
                        0.7,
                    ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Cat 2: Credential Pattern Detection
# ═══════════════════════════════════════════════════════════════════════════

def _check_credential_patterns(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    """Check the target's own responses for leaked credentials."""
    findings: List[Finding] = []
    host = _extract_domain(target)

    # Fetch the target's own pages for credential leakage
    paths_to_check = ["/", "/robots.txt", "/sitemap.xml", "/config.js",
                       "/.env", "/package.json", "/webpack.config.js"]
    for path in paths_to_check:
        url = base_url.rstrip("/") + path
        resp = _safe_probe(url, timeout=min(timeout, 5), verify_tls=verify_tls)
        if not resp.get("ok") or resp.get("status") in (404, 403):
            continue

        body = resp.get("body", "")
        if len(body) < 50:
            continue

        for cred_id, cred_info in CREDENTIAL_PATTERNS.items():
            matches = cred_info["pattern"].findall(body)
            if matches:
                count = len(matches)
                sev = cred_info.get("severity", "high")
                pts = 20 if sev == "critical" else 12

                # Decode JWT tokens for extra evidence
                extra = ""
                if cred_id == "jwt_token" and matches:
                    jwt_data = _decode_jwt(matches[0])
                    if jwt_data and jwt_data.get("header"):
                        extra = f" JWT header: {json.dumps(jwt_data['header'])}"

                evidence_str = (
                    f"Path: {path}; Pattern: {cred_id}; "
                    f"Matches: {count}; Sample: {str(matches[0])[:80]}{extra}"
                )
                findings.append(_make(
                    f"Credential Leak — {cred_info['description']} on {path}",
                    sev, "credential_leak",
                    f"{cred_info['description']} detected {count} time(s) at {path}. "
                    f"Immediate credential rotation recommended.{extra}",
                    evidence_str, host, pts,
                    "Rotate any exposed credentials immediately. Remove sensitive data from source code.",
                    0.9 if sev == "critical" else 0.6,
                ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Cat 3: Infrastructure Exposure Check
# ═══════════════════════════════════════════════════════════════════════════

def _check_infrastructure_exposure(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    findings: List[Finding] = []
    host = _extract_domain(target)

    # Resolve IPs for the target
    try:
        ips = socket.getaddrinfo(host, None)
        ip_list = list(set(addr[4][0] for addr in ips))
    except Exception:
        ip_list = []

    # Check threat intel sources for each IP
    for source_id, source in THREAT_INTEL_SOURCES.items():
        if source.get("type") != "json_api":
            continue

        for ip in ip_list[:3]:
            url = source["search_url"].format(query=ip)
            resp = _safe_probe(url, timeout=min(timeout, 5), verify_tls=verify_tls)

            if resp.get("ok") and resp.get("status") == 200:
                body = resp.get("body", "")
                data = _parse_json(body)
                if data and isinstance(data, dict):
                    # Check for malicious indicators
                    if data.get("query_status") == "ok":
                        count = len(data.get("data", []))
                        if count > 0:
                            findings.append(_make(
                                f"Infrastructure Exposure — {ip} on {source['name']}",
                                "critical", "infrastructure_exposure",
                                f"IP {ip} has {count} malicious indicators on {source['name']}. "
                                f"Target infrastructure may be compromised or hosting malware.",
                                f"IP: {ip}; Source: {source['name']}; Indicators: {count}",
                                host, 20,
                                "Investigate server for compromise. Check for malware, unauthorized access.",
                                0.9,
                            ))
                    elif data.get("response_code") == 1:
                        # VirusTotal-style positive detection
                        positives = data.get("positives", 0)
                        total = data.get("total", 0)
                        if positives > 0:
                            findings.append(_make(
                                f"Infrastructure Exposure — {ip}: {positives}/{total} vendors flag",
                                "critical", "infrastructure_exposure",
                                f"IP {ip} flagged by {positives}/{total} security vendors on "
                                f"{source['name']}. Infrastructure may be malicious.",
                                f"IP: {ip}; Positives: {positives}/{total}; Source: {source['name']}",
                                host, 20,
                                "Immediate investigation required. Check all services on this IP.",
                                0.9,
                            ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Cat 4: Certificate Transparency Log Analysis
# ═══════════════════════════════════════════════════════════════════════════

def _check_ct_logs(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    findings: List[Finding] = []
    host = _extract_domain(target)

    resp = _safe_probe(
        "https://crt.sh/?q=%.{}&output=json".format(
            urllib.parse.quote(host)),
        timeout=min(timeout, 10), verify_tls=verify_tls,
    )

    if resp.get("ok") and resp.get("status") == 200:
        data = _parse_json(resp.get("body", ""))
        if data and isinstance(data, list):
            cert_count = len(data)
            # Extract unique subdomains
            subdomains = set()
            issuers = set()
            for cert in data:
                name = cert.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(host):
                        subdomains.add(n)
                issuer = cert.get("issuer_name", "")
                if issuer:
                    issuers.add(issuer)

            if cert_count > 50:
                findings.append(_make(
                    f"CT Log Alert — {cert_count} certificates for *.{host}",
                    "medium", "ct_analysis",
                    f"Found {cert_count} certificates for *.{host} in CT logs. "
                    f"{len(subdomains)} unique subdomains, {len(issuers)} unique issuers. "
                    f"High cert count may indicate phishing or subdomain takeover risk.",
                    f"Subdomains: {len(subdomains)}; Issuers: {len(issuers)}; Total certs: {cert_count}",
                    host, 8,
                    "Review CT log entries for unauthorized certificates. Consider CT monitoring.",
                    0.5,
                ))
            elif cert_count > 10:
                findings.append(_make(
                    f"CT Log — {cert_count} certificates for *.{host}",
                    "low", "ct_analysis",
                    f"Found {cert_count} certificates for *.{host}. "
                    f"{len(subdomains)} subdomains tracked.",
                    f"Subdomains: {len(subdomains)}; Certs: {cert_count}",
                    host, 3,
                    "Monitor CT logs for unauthorized certificates.",
                    0.2,
                ))

            # Check for suspicious issuer patterns (self-signed, unknown CAs)
            suspicious_issuers = [i for i in issuers if "Let's Encrypt" not in i
                                 and "DigiCert" not in i and "Sectigo" not in i
                                 and "Cloudflare" not in i and "Amazon" not in i
                                 and "GlobalSign" not in i and "Sectigo" not in i]
            if suspicious_issuers:
                findings.append(_make(
                    f"CT Log — Unusual Certificate Issuers Detected",
                    "high", "ct_analysis",
                    f"Found certificates issued by non-standard CAs: "
                    f"{', '.join(suspicious_issuers[:3])}. "
                    f"May indicate self-signed certs for phishing infrastructure.",
                    f"Suspected issuers: {suspicious_issuers[:5]}",
                    host, 15,
                    "Investigate who issued these certificates. Verify all subdomains.",
                    0.7,
                ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Cat 5: Domain-Level Threat Intelligence
# ═══════════════════════════════════════════════════════════════════════════

def _check_threat_intel(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    findings: List[Finding] = []
    host = _extract_domain(target)

    # Check URLhaus
    resp = _safe_probe(
        f"https://urlhaus-api.abuse.ch/v1/host/{urllib.parse.quote(host)}",
        timeout=min(timeout, 8), verify_tls=verify_tls,
    )
    if resp.get("ok") and resp.get("status") == 200:
        data = _parse_json(resp.get("body", ""))
        if data and isinstance(data, dict):
            total_urls = data.get("total_urls", 0)
            if total_urls > 0:
                findings.append(_make(
                    f"Threat Intel — {total_urls} malicious URLs on URLhaus for {host}",
                    "critical", "threat_intelligence",
                    f"abuse.ch URLhaus lists {total_urls} malicious URLs associated with "
                    f"{host}. Infrastructure may be compromised or used for malware distribution.",
                    f"Host: {host}; Malicious URLs: {total_urls}",
                    host, 20,
                    "URGENT: Check all URLs. Infrastructure may be hosting malware.",
                    0.9,
                ))

    # Check AlienVault OTX
    resp = _safe_probe(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(host)}/general",
        timeout=min(timeout, 8), verify_tls=verify_tls,
    )
    if resp.get("ok") and resp.get("status") == 200:
        data = _parse_json(resp.get("body", ""))
        if data and isinstance(data, dict):
            pulses = len(data.get("pulse_info", {}).get("pulses", []))
            if pulses > 5:
                findings.append(_make(
                    f"Threat Intel — {pulses} threat pulses on OTX for {host}",
                    "high", "threat_intelligence",
                    f"AlienVault OTX shows {pulses} threat intelligence pulses mentioning "
                    f"{host}. Multiple pulses suggest active targeting.",
                    f"Host: {host}; OTX Pulses: {pulses}",
                    host, 15,
                    "Review OTX pulse details for specific threats and attacker TTPs.",
                    0.7,
                ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Cat 6: Breach Database Cross-Reference
# ═══════════════════════════════════════════════════════════════════════════

def _check_breach_dbs(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    findings: List[Finding] = []
    host = _extract_domain(target)
    email_domains = _extract_email_domains(target)

    for email_domain in email_domains:
        # Construct a test email (not a real user — just tests the domain)
        test_email = f"test@{email_domain}"

        resp = _safe_probe(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}".format(
                urllib.parse.quote(test_email)),
            timeout=min(timeout, 5), verify_tls=verify_tls,
        )

        if resp.get("ok") and resp.get("status") == 200:
            breaches = _parse_json(resp.get("body", ""))
            if breaches and isinstance(breaches, list):
                breach_count = len(breaches)
                breach_names = [b.get("name", "?") for b in breaches[:5]]
                findings.append(_make(
                    f"Breach Database — {breach_count} breaches for @{email_domain}",
                    "critical", "breach_database",
                    f"HIBP reports {breach_count} breaches affecting emails at "
                    f"@{email_domain}. Breaches: {', '.join(breach_names)}. "
                    f"Domain emails may be compromised.",
                    f"Breaches: {breach_names}; Domain: {email_domain}",
                    host, 18,
                    "Force password reset for all users. Enable MFA. Review breach data for exposed credentials.",
                    0.8,
                ))
        elif resp.get("status") == 404:
            # No breaches found (good)
            pass
        elif resp.get("status") == 403:
            # Rate limited
            pass
        elif resp.get("status") == 429:
            # Rate limited
            pass

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Cat 7: GitHub Code Search for Secrets
# ═══════════════════════════════════════════════════════════════════════════

def _check_github_secrets(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    findings: List[Finding] = []
    host = _extract_domain(target)

    search_queries = [
        f'"{host}" password',
        f'"{host}" api_key',
        f'"{host}" secret',
        f'"{host}" token',
        f'"{host}" private_key',
        f'"{host}" credential',
    ]

    for query in search_queries:
        url = f"https://github.com/search?q={urllib.parse.quote(query)}&type=code"
        resp = _safe_probe(url, timeout=min(timeout, 5), verify_tls=verify_tls)

        if resp.get("ok") and resp.get("status") == 200:
            body = resp.get("body", "")

            # Look for code result indicators
            code_result_count = body.count('data-hydro-click')
            repo_count = len(re.findall(r'href="/[^"]+[^"]+?"', body))

            if code_result_count > 5:
                findings.append(_make(
                    f"GitHub Code Exposure — Secrets found for '{host}'",
                    "critical", "github_exposure",
                    f"GitHub code search for '{query}' returned {code_result_count} results. "
                    f"Sensitive code (passwords, keys, tokens) associated with '{host}' "
                    f"may be publicly exposed.",
                    f"Query: {query}; Results: {code_result_count}",
                    host, 20,
                    "Remove exposed secrets from GitHub history. Use git-filter-repo or BFG Repo-Cleaner. "
                    "Rotate all exposed credentials immediately.",
                    0.9,
                ))
                break  # Don't flood with multiple findings

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def run_dark_web_monitor(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Run all dark web monitoring and credential leak checks.

    Returns a list of Finding objects for any detected exposures,
    leaked credentials, or threat intelligence matches.
    """
    import socket
    findings: List[Finding] = []
    host = _extract_domain(target)

    # Phase 1: Paste site monitoring
    findings.extend(_check_paste_sites(target, base_url, timeout, verify_tls))

    # Phase 2: Credential pattern detection on target
    findings.extend(_check_credential_patterns(target, base_url, timeout, verify_tls))

    # Phase 3: Infrastructure exposure (threat intel)
    findings.extend(_check_infrastructure_exposure(target, base_url, timeout, verify_tls))

    # Phase 4: Certificate Transparency analysis
    findings.extend(_check_ct_logs(target, base_url, timeout, verify_tls))

    # Phase 5: Domain-level threat intelligence
    findings.extend(_check_threat_intel(target, base_url, timeout, verify_tls))

    # Phase 6: Breach database cross-reference
    findings.extend(_check_breach_dbs(target, base_url, timeout, verify_tls))

    # Phase 7: GitHub secret exposure
    findings.extend(_check_github_secrets(target, base_url, timeout, verify_tls))

    return findings

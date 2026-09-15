"""Module: RECON — 25-category surface reconnaissance.

Checks:
  1.  DNS resolution (A, AAAA, CNAME, MX, NS, TXT) via Cloudflare DoH
  2.  HTTP headers analysis (security headers)
  3.  Technology fingerprinting (40+ technologies)
  4.  robots.txt / sitemap.xml
  5.  TLS/SSL certificate info + cipher analysis
  6.  Open ports (top 20)
  7.  Sensitive path exposure (.env, .git, configs)
  8.  API endpoint discovery
  9.  CORS policy analysis
 10.  Cookie security flags
 11.  Redirect chain analysis
 12.  WAF detection (15 providers)
 13.  Email / SPF / DMARC
 14.  Certificate Transparency (crt.sh)
 15.  Threat Intelligence (abuse.ch)
 16.  Enhanced TLS Cipher Analysis
 17.  Enhanced Technology Fingerprinting
 18.  Enhanced WAF Detection
 19.  Content Security Policy Deep Analysis
 20.  HTTP/2 and Protocol Analysis
 21.  Subdomain Enumeration via Passive DNS
 22.  Email Harvesting
 23.  Open Redirect Deep Check
 24.  Mixed Content Detection
 25.  Meta Tag Security
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional
from ..http_layer import http_probe, Finding, default_limiter


SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/docker-compose.yml", "/config.json", "/config.yaml",
    "/package.json", "/.npmrc", "/vercel.json", "/netlify.toml",
    "/.aws/credentials", "/.ssh/id_rsa",
    "/.github/workflows/secret", "/.gitlab-ci.yml",
]

API_PATHS = [
    "/api/webhooks", "/api/trpc", "/api/v1/admin", "/api/v1/users",
    "/api/v1/config", "/api/internal", "/api/debug",
    "/api/graphql", "/api/upload", "/admin", "/dashboard",
]

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "high", 8),
    ("content-security-policy", "CSP", "medium", 6),
    ("x-content-type-options", "X-Content-Type-Options", "medium", 4),
    ("x-frame-options", "X-Frame-Options", "medium", 5),
    ("referrer-policy", "Referrer-Policy", "low", 3),
    ("permissions-policy", "Permissions-Policy", "low", 2),
]

WAF_SIGNATURES = [
    ("Cloudflare", ["cf-ray", "__cfduid", "cloudflare"]),
    ("AWS WAF", ["awselb", "x-amzn-requestid"]),
    ("Akamai", ["akamai", "x-akamai"]),
    ("Sucuri", ["sucuri", "x-sucuri-id"]),
    ("Imperva", ["x-iinfo", "incap_ses_"]),
    ("Fastly", ["x-fastly-request-id", "x-fastly-debug"]),
    ("Cloudfront", ["x-amz-cf-id", "via: *.cloudfront.net"]),
    ("F5 BIG-IP", ["bigipserver", "f5"]),
    ("Barracuda", ["bnmsg", "barracloud"]),
    ("Fortinet", ["fortiwafid", "fortinet"]),
    ("Radware", ["x-sl-compstate"]),
    ("Comodo CWS", ["cws"]),
    ("Wordfence", ["x-wp-sec"]),
    ("StackPath", ["stackpath"]),
    ("Azure Front Door", ["x-azurefdid", "x-fd-intro-version"]),
]

TOP_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587,
             993, 995, 1433, 3306, 5432, 8080, 8443, 8888, 9090, 27017]

TECH_SIGNATURES = [
    # Frontend frameworks
    ("Next.js", ["_next/", "__next", "x-nextjs"]),
    ("React", ["react", "__react", "_reactRootContainer"]),
    ("Vue.js", ["vue.", "/vue", "v-cloak", "v-bind", "v-if", "data-v-"]),
    ("Angular", ["ng-version", "ng-content", ".ng-", "angular"]),
    ("Svelte", ["svelte", "__svelte"]),
    ("SvelteKit", ["sveltekit", "__sveltekit"]),
    ("Astro", ["astro", "astro-island", "data-astro"]),
    ("Remix", ["remix", "__remix"]),
    # CMS platforms
    ("WordPress", ["wp-content", "wp-includes", "wordpress"]),
    ("Drupal", ["drupal", "sites/default/files", "x-drupal-cache"]),
    ("Joomla", ["joomla", "/media/jui/", "components/com_"]),
    ("Magento", ["magento", "mage-cache", "mage-cookies"]),
    ("Ghost", ["ghost", "ghost-portal"]),
    ("Strapi", ["strapi", "x-strapi"]),
    # E-commerce
    ("Shopify", ["shopify", "cdn.shopify.com", "shopify-section"]),
    ("WooCommerce", ["woocommerce", "wc-cart"]),
    ("Bubble", ["bubble", "bubble.io"]
    ),
    ("Wix", ["wix", "wix.com", "static.parastorage.com"]),
    ("Squarespace", ["squarespace", "sqsp"]),
    ("Webflow", ["webflow", "webflow.com", "data-wf-page"]),
    # Backend frameworks
    ("Laravel", ["laravel_session", "x-laravel"]),
    ("Django", ["csrfmiddlewaretoken", "django"]),
    ("Express", ["x-powered-by: express"]),
    ("FastAPI", ["fastapi", "openapi.json"]),
    ("Flask", ["flask", "werkzeug"]),
    ("Ruby on Rails", ["rails", "x-rack-cache", "csrf-token"]),
    ("Spring Boot", ["spring boot", "x-application-context"]),
    ("ASP.NET", ["asp.net", "__viewstate", "aspnetcore"]),
    ("PHP", ["php", "phpsessid", "x-powered-by: php"]),
    ("Java", ["java", "x-powered-by: jsf", "jsessionid"]),
    ("Go", ["go-http", "x-go-backend"]),
    ("Rust (Actix)", ["actix", "actix-web"]),
    # Servers
    ("Nginx", ["nginx"]),
    ("Apache", ["apache", "mod_"]),
    # Platforms
    ("Vercel", ["vercel", "x-vercel"]),
    ("Cloudflare", ["cloudflare"]),
    ("Supabase", ["supabase"]),
    ("Firebase", ["firebaseapp", "firebase"]),
    # Data / API layers
    ("Apollo GraphQL", ["apollo", "__apollo"]),
    ("tRPC", ["trpc", "/api/trpc"]),
    ("Prisma", ["prisma", "x-prisma"]),
    ("Sanity", ["sanity", "cdn.sanity.io"]),
    # Databases (detectable via headers/errors)
    ("PostgreSQL", ["postgresql", "postgres"]
    ),
    ("MySQL", ["mysql"]),
    ("MongoDB", ["mongodb"]),
    ("Redis", ["redis"]),
    ("Elasticsearch", ["elasticsearch"]),
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "ci", "cdn", "static", "media", "m", "mobile", "app", "portal",
    "dashboard", "internal", "vpn", "s3", "storage", "gateway", "proxy",
    "ns1", "ns2", "mx", "mx1", "mx2",
]

REDIRECT_ENDPOINTS = [
    "/redirect", "/logout", "/login", "/auth/callback",
    "/oauth/callback", "/api/redirect", "/next", "/return",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "\\evil.com",
    "https://evil.com%00",
    "https://evil.com%0d%0a",
]

CONTACT_PATHS = ["/contact", "/about", "/team", "/staff"]

TEST_CA_KEYWORDS = [
    "let's encrypt staging", "staging", "test ca", "self-signed",
    "fake ca", "dummy ca", "testing",
]

WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "NULL", "EXP-", "EXPORT",
    "RC2", "MD5", "IDEA",
]


# ── Helper: Cloudflare DoH JSON lookup ───────────────────────────────────

def _doh_lookup(name: str, rtype: str) -> List[str]:
    """Resolve a DNS record via Cloudflare DoH JSON API."""
    url = (
        f"https://cloudflare-dns.com/dns-query?"
        f"name={urllib.parse.quote(name, safe='')}&type={rtype}"
    )
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            data = json.loads(resp.read(65536).decode())
        answers = data.get("Answer", [])
        return [a.get("data", "") for a in answers]
    except Exception:
        return []


def _dns_lookup(host: str) -> Dict[str, Any]:
    result = {"a": [], "aaaa": [], "cname": [], "mx": [], "ns": [], "txt": []}
    # Try Cloudflare DoH for proper record types
    for qtype, attr in [("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname"),
                         ("MX", "mx"), ("NS", "ns"), ("TXT", "txt")]:
        try:
            records = _doh_lookup(host, qtype)
            if records:
                result[attr] = records
        except Exception:
            pass

    # Fallback to socket for A/AAAA if DoH returned nothing
    if not result["a"] and not result["aaaa"]:
        try:
            answers = socket.getaddrinfo(host, None, socket.AF_UNSPEC,
                                          socket.SOCK_STREAM)
            seen = set()
            for fam, _, _, _, sockaddr in answers:
                ip = sockaddr[0]
                if ip not in seen:
                    seen.add(ip)
                    if ":" in ip:
                        result["aaaa"].append(ip)
                    else:
                        result["a"].append(ip)
        except Exception:
            pass
    return result


# ── Port scanner ─────────────────────────────────────────────────────────

def _check_ports(host: str, timeout: float = 1.0) -> List[Dict[str, Any]]:
    open_ports = []
    for port in TOP_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                open_ports.append({"port": port, "state": "open"})
            s.close()
        except Exception:
            pass
    return open_ports


# ── TLS checks ───────────────────────────────────────────────────────────

def _check_tls(host: str) -> Dict[str, Any]:
    info = {
        "version": None, "issuer": None, "expiry": None,
        "days_left": None, "cipher_name": None, "cipher_bits": None,
        "cipher_protocol": None, "shared_ciphers": [],
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                info["version"] = s.version()
                # Cipher details
                cipher = s.cipher()
                if cipher:
                    info["cipher_name"] = cipher[0]
                    info["cipher_protocol"] = cipher[1]
                    info["cipher_bits"] = cipher[2]
                # Shared ciphers
                try:
                    shared = s.shared_ciphers()
                    if shared:
                        info["shared_ciphers"] = [
                            {"name": c[0], "protocol": c[1], "bits": c[2]}
                            for c in shared
                        ]
                except Exception:
                    pass
                if cert:
                    for rdn in cert.get("issuer", ()): 
                        for k, v in rdn:
                            if k == "organizationName":
                                info["issuer"] = v
                    not_after = cert.get("notAfter")
                    if not_after:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        info["expiry"] = exp.isoformat()
                        info["days_left"] = (exp - datetime.utcnow()).days
    except Exception:
        pass
    return info


# ── Technology detection ──────────────────────────────────────────────────

def _detect_tech(body: str, headers: Dict[str, str]) -> List[str]:
    found = []
    haystack = (body + " " + " ".join(headers.values())).lower()
    for name, sigs in TECH_SIGNATURES:
        if any(s.lower() in haystack for s in sigs):
            found.append(name)
    # Additional header-based detection
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    if "x-powered-by" in h_lower:
        powered = h_lower["x-powered-by"]
        # Check if we already detected via signatures
        already = [t.lower() for t in found]
        for tech_name in ["Express", "PHP", "ASP.NET", "FastAPI", "Flask",
                          "Next.js", "Ruby on Rails"]:
            if tech_name.lower() not in already and any(
                kw in powered for kw in TECH_SIGNATURES[[t[0] for t in TECH_SIGNATURES].index(tech_name)][1]
            ):
                found.append(tech_name)
    if "x-generator" in h_lower:
        gen = h_lower["x-generator"]
        for tech_name in ["WordPress", "Drupal", "Joomla", "Ghost", "Wix",
                          "Squarespace", "Webflow"]:
            idx = [t[0] for t in TECH_SIGNATURES].index(tech_name) if tech_name in [t[0] for t in TECH_SIGNATURES] else -1
            if idx >= 0 and any(kw.lower() in gen for kw in TECH_SIGNATURES[idx][1]):
                if tech_name not in found:
                    found.append(tech_name)
    if "server" in h_lower:
        srv = h_lower["server"]
        for tech_name in ["Nginx", "Apache", "Cloudflare"]:
            idx = [t[0] for t in TECH_SIGNATURES].index(tech_name) if tech_name in [t[0] for t in TECH_SIGNATURES] else -1
            if idx >= 0 and any(kw.lower() in srv for kw in TECH_SIGNATURES[idx][1]):
                if tech_name not in found:
                    found.append(tech_name)
    if "via" in h_lower:
        via = h_lower["via"]
        if "fastly" in via and "Fastly" not in found:
            found.append("Fastly")
        if "cloudfront" in via and "Cloudfront" not in found:
            found.append("Cloudfront")
    return found


# ── WAF detection ────────────────────────────────────────────────────────

def _detect_waf(headers: Dict[str, str], body: str) -> List[str]:
    found = []
    haystack = (" ".join(headers.keys()) + " " +
                " ".join(headers.values()) + " " + body[:4096]).lower()
    for name, sigs in WAF_SIGNATURES:
        if any(s.lower() in haystack for s in sigs):
            found.append(name)
    return found


# ── CORS ──────────────────────────────────────────────────────────────────

def _check_cors(base_url: str) -> List[Finding]:
    findings = []
    resp = http_probe(base_url)
    h = resp.get("headers", {})
    acao = h.get("Access-Control-Allow-Origin", "")

    if acao == "*":
        findings.append(Finding(
            title="Permissive CORS (wildcard origin)",
            severity="high", category="cors", module="recon",
            description="Access-Control-Allow-Origin: * — any domain can make cross-origin requests",
            evidence=f"CORS: {acao}", asset="",
    ))
    elif acao:
        probe = http_probe(base_url, headers={"Origin": "https://evil-attacker.com"})
        reflected = probe.get("headers", {}).get("Access-Control-Allow-Origin", "")
        if "evil-attacker" in reflected:
            findings.append(Finding(
                title="CORS origin reflection",
                severity="critical", category="cors", module="recon",
                description="Server reflects any Origin header back",
                evidence=f"Sent Origin: evil-attacker.com, got: {reflected}", asset="",
    ))
    return findings


# ── Cookie security ───────────────────────────────────────────────────────

def _check_cookies(headers: Dict[str, str]) -> List[Finding]:
    findings = []
    set_cookie = headers.get("set-cookie", "")
    if not set_cookie:
        return findings
    # Cookies may be separated by \n or \r\n in some HTTP libs; also by comma.
    # Split by common delimiters and process each individually.
    cookies = re.split(r'[\n\r]+', set_cookie)
    for raw_cookie in cookies:
        raw_cookie = raw_cookie.strip()
        if not raw_cookie or "=" not in raw_cookie:
            continue
        # Only take the part before any comma that might be part of same line
        cookie = raw_cookie.split(",")[0].strip()
        name = cookie.split("=")[0].strip()
        cookie_lower = cookie.lower()

        if "httponly" not in cookie_lower and name:
            findings.append(Finding(
                title=f"Missing HttpOnly on cookie: {name[:40]}",
                severity="medium", category="cookies", module="recon",
                description=f"Cookie '{name}' lacks HttpOnly flag — vulnerable to XSS theft",
                evidence=f"Cookie: {cookie[:80]}", asset="",
        ))
        if "secure" not in cookie_lower and name:
            findings.append(Finding(
                title=f"Missing Secure flag on cookie: {name[:40]}",
                severity="medium", category="cookies", module="recon",
                description=f"Cookie '{name}' lacks Secure flag — sent over HTTP",
                evidence=f"Cookie: {cookie[:80]}", asset="",
        ))
        if "samesite" not in cookie_lower and name:
            findings.append(Finding(
                title=f"Missing SameSite on cookie: {name[:40]}",
                severity="low", category="cookies", module="recon",
                description=f"Cookie '{name}' lacks SameSite attribute — CSRF risk",
                evidence=f"Cookie: {cookie[:80]}", asset="",
        ))
    return findings


# ── 14. Certificate Transparency (crt.sh) ────────────────────────────────

def _check_cert_transparency(host: str) -> List[Finding]:
    findings = []
    try:
        url = f"https://crt.sh/?q=%.{host}&output=json"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ReconPro/2.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read(1048576).decode())

        if not isinstance(data, list) or len(data) == 0:
            return findings

        subdomains = set()
        issuers = set()
        for entry in data:
            name_val = entry.get("name_value", "")
            for name in name_val.split("\n"):
                n = name.strip().lstrip("*.").lower()
                if n and n != host:
                    subdomains.add(n)
            issuer = entry.get("issuer_name", "")
            if issuer:
                issuers.add(issuer)

        if len(subdomains) > 50:
            findings.append(Finding(
                title=f"Large certificate attack surface ({len(subdomains)} subdomains)",
                severity="medium", category="cert_transparency", module="recon",
                description=f"crt.sh reveals {len(subdomains)} unique subdomains via CT logs — large attack surface",
                evidence=f"Subdomain count: {len(subdomains)}",
                asset=host, points_deducted=4,
            ))

        # Check for test/self-signed CAs
        for issuer in issuers:
            issuer_lower = issuer.lower()
            for kw in TEST_CA_KEYWORDS:
                if kw in issuer_lower:
                    findings.append(Finding(
                        title=f"Certificate issued by test CA: {issuer[:80]}",
                        severity="high", category="cert_transparency", module="recon",
                        description=f"A certificate was issued by a test/staging CA: {issuer[:100]}",
                        evidence=f"Issuer: {issuer[:100]}",
                        asset=host, points_deducted=8,
                    ))
                    break

    except Exception:
        pass
    return findings


# ── 15. Threat Intelligence (abuse.ch) ────────────────────────────────────

def _check_threat_intel(host: str, ip_list: List[str]) -> List[Finding]:
    findings = []

    # Check ThreatFox for domain
    try:
        tf_url = "https://threatfox-api.abuse.ch/api/v1/query/search-term"
        tf_data = json.dumps({"query": "search_domain", "search_term": host}).encode()
        tf_req = urllib.request.Request(tf_url, data=tf_data,
                                        headers={"Content-Type": "application/json"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(tf_req, timeout=10, context=ctx) as resp:
            tf_result = json.loads(resp.read(65536).decode())
        if tf_result.get("data") and isinstance(tf_result["data"], list):
            hit_count = len(tf_result["data"])
            if hit_count > 0:
                findings.append(Finding(
                    title=f"Domain flagged in ThreatFox ({hit_count} hits)",
                    severity="critical", category="threat_intel", module="recon",
                    description=f"Domain {host} appears in abuse.ch ThreatFox malware database ({hit_count} entries)",
                    evidence=f"ThreatFox hits: {hit_count}",
                    asset=host, points_deducted=12,
                ))
    except Exception:
        pass

    # Check URLhaus for IP addresses
    for ip in ip_list[:3]:  # Check first 3 IPs
        try:
            uh_url = f"https://urlhaus-api.abuse.ch/v1/host/{ip}/"
            uh_req = urllib.request.Request(uh_url, headers={"Accept": "application/json"})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(uh_req, timeout=10, context=ctx) as resp:
                uh_result = json.loads(resp.read(65536).decode())
            if uh_result.get("status") == "ok" and isinstance(uh_result.get("urls"), list):
                url_count = len(uh_result["urls"])
                if url_count > 0:
                    findings.append(Finding(
                        title=f"IP {ip} hosts malware URLs (URLhaus)",
                        severity="critical", category="threat_intel", module="recon",
                        description=f"IP {ip} has {url_count} malware URLs in URLhaus database",
                        evidence=f"IP: {ip}, Malware URLs: {url_count}",
                        asset=host, points_deducted=12,
                    ))
        except Exception:
            pass

    return findings


# ── 16. Enhanced TLS Cipher Analysis ─────────────────────────────────────

def _check_tls_ciphers(tls_info: Dict[str, Any], host: str) -> List[Finding]:
    findings = []
    version = tls_info.get("version", "")

    # Check for deprecated protocols
    if version and ("TLSv1." in version and "TLSv1.2" not in version and "TLSv1.3" not in version):
        if "1.0" in version or "1.1" in version:
            findings.append(Finding(
                title=f"Deprecated TLS protocol: {version}",
                severity="high", category="tls_cipher", module="recon",
                description=f"Server negotiates {version} — deprecated protocol, vulnerable to attacks",
                evidence=f"TLS Version: {version}",
                asset=host, points_deducted=10,
            ))

    # Check negotiated cipher
    cipher_name = tls_info.get("cipher_name", "")
    if cipher_name:
        for weak in WEAK_CIPHER_PATTERNS:
            if weak.lower() in cipher_name.lower():
                findings.append(Finding(
                    title=f"Weak cipher negotiated: {cipher_name}",
                    severity="high", category="tls_cipher", module="recon",
                    description=f"Server negotiated weak cipher {cipher_name} containing {weak}",
                    evidence=f"Cipher: {cipher_name} ({tls_info.get('cipher_bits', 0)}-bit)",
                    asset=host, points_deducted=10,
                ))
                break

    # Check shared ciphers for weak ones
    for sc in tls_info.get("shared_ciphers", []):
        sc_name = sc.get("name", "")
        for weak in WEAK_CIPHER_PATTERNS:
            if weak.lower() in sc_name.lower():
                findings.append(Finding(
                    title=f"Weak cipher supported: {sc_name}",
                    severity="medium", category="tls_cipher", module="recon",
                    description=f"Server supports weak cipher {sc_name} — could be downgraded",
                    evidence=f"Shared cipher: {sc_name} ({sc.get('bits', 0)}-bit)",
                    asset=host, points_deducted=5,
                ))
                break

    return findings


# ── 19. CSP Deep Analysis ────────────────────────────────────────────────

def _check_csp_deep(headers: Dict[str, str], host: str) -> List[Finding]:
    findings = []
    csp = None
    for k, v in headers.items():
        if k.lower() == "content-security-policy":
            csp = v
            break

    if not csp:
        return findings

    # Parse CSP directives
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    # Check for missing default-src
    if "default-src" not in directives:
        findings.append(Finding(
            title="CSP missing default-src directive",
            severity="medium", category="csp_analysis", module="recon",
            description="Content-Security-Policy lacks default-src — fallback behavior is unpredictable",
            evidence=f"CSP: {csp[:120]}",
            asset=host, points_deducted=5,
        ))

    # Check script-src
    script_src = directives.get("script-src", [])
    if script_src:
        if "'unsafe-inline'" in script_src:
            findings.append(Finding(
                title="CSP allows unsafe-inline in script-src",
                severity="high", category="csp_analysis", module="recon",
                description="'unsafe-inline' in script-src defeats XSS protection of CSP",
                evidence=f"script-src includes 'unsafe-inline'",
                asset=host, points_deducted=8,
            ))
        if "'unsafe-eval'" in script_src:
            findings.append(Finding(
                title="CSP allows unsafe-eval in script-src",
                severity="high", category="csp_analysis", module="recon",
                description="'unsafe-eval' in script-src allows eval() — code injection risk",
                evidence=f"script-src includes 'unsafe-eval'",
                asset=host, points_deducted=8,
            ))

    # Check for wildcard sources
    for directive_name, values in directives.items():
        if "*" in values:
            findings.append(Finding(
                title=f"CSP wildcard in {directive_name}",
                severity="medium", category="csp_analysis", module="recon",
                description=f"CSP {directive_name} uses wildcard (*) — overly permissive",
                evidence=f"{directive_name}: {' '.join(values[:5])}",
                asset=host, points_deducted=5,
            ))
            break

    # Check for data: URIs
    for directive_name, values in directives.items():
        if "data:" in values:
            findings.append(Finding(
                title=f"CSP allows data: URIs in {directive_name}",
                severity="medium", category="csp_analysis", module="recon",
                description=f"data: URIs in {directive_name} can bypass CSP for script injection",
                evidence=f"{directive_name} includes 'data:'",
                asset=host, points_deducted=5,
            ))
            break

    # Check for missing report-uri / report-to
    if "report-uri" not in directives and "report-to" not in directives:
        findings.append(Finding(
            title="CSP missing report-uri/report-to",
            severity="low", category="csp_analysis", module="recon",
            description="CSP has no report-uri or report-to — CSP violations are not monitored",
            evidence=f"CSP lacks reporting directive",
            asset=host, points_deducted=2,
        ))

    return findings


# ── 20. HTTP/2 and Protocol Analysis ─────────────────────────────────────

def _check_http2(host: str, base_url: str, timeout: int, verify_tls: bool) -> List[Finding]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        # Set ALPN to advertise HTTP/2
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                negotiated = s.selected_alpn_protocol()
                if negotiated == 'h2':
                    findings.append(Finding(
                        title="HTTP/2 supported via ALPN",
                        severity="info", category="http2", module="recon",
                        description="Server supports HTTP/2 via ALPN negotiation",
                        evidence=f"ALPN: h2",
                        asset=host,
                    ))
                else:
                    findings.append(Finding(
                        title="HTTP/2 not supported (HTTP/1.1 only)",
                        severity="low", category="http2", module="recon",
                        description="Server does not support HTTP/2 — slower performance and missing features",
                        evidence=f"ALPN: {negotiated or 'none'}",
                        asset=host, points_deducted=2,
                    ))
    except Exception:
        # Fallback: check response headers for HTTP/2 indication
        try:
            resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
            # No reliable way to tell HTTP/2 from urllib, skip silently
            pass
        except Exception:
            pass
    return findings


# ── 21. Subdomain Enumeration ────────────────────────────────────────────

def _check_subdomains(host: str, crt_subdomains: set) -> List[Finding]:
    findings = []
    found_subdomains = []
    wildcard_detected = False

    # First check for DNS wildcard by resolving a random subdomain
    try:
        test_sub = f"xzyrandomtest123.{host}"
        try:
            socket.gethostbyname(test_sub)
            wildcard_detected = True
        except socket.gaierror:
            pass
    except Exception:
        pass

    if wildcard_detected:
        findings.append(Finding(
            title="DNS wildcard detected",
            severity="medium", category="subdomain_enum", module="recon",
            description="DNS wildcard resolves all subdomains — active enumeration unreliable",
            evidence=f"Random subdomain xzyrandomtest123.{host} resolved",
            asset=host, points_deducted=3,
        ))

    # Resolve common subdomains
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{host}"
        try:
            ip = socket.gethostbyname(fqdn)
            if ip:
                found_subdomains.append(fqdn)
        except socket.gaierror:
            pass
        except Exception:
            pass

    # Merge with crt.sh results
    for s in crt_subdomains:
        if s not in found_subdomains:
            found_subdomains.append(s)

    if found_subdomains:
        findings.append(Finding(
            title=f"Subdomains discovered: {len(found_subdomains)}",
            severity="info", category="subdomain_enum", module="recon",
            description=f"Found {len(found_subdomains)} subdomains: {', '.join(found_subdomains[:15])}"
                + (f" ... and {len(found_subdomains)-15} more" if len(found_subdomains) > 15 else ""),
            evidence=f"Subdomains: {', '.join(found_subdomains[:10])}",
            asset=host,
        ))

    return findings


# ── 22. Email Harvesting ─────────────────────────────────────────────────

def _check_email_harvest(base_url: str, body: str, timeout: int,
                         verify_tls: bool) -> List[Finding]:
    findings = []
    email_pattern = re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    )
    all_emails = set()

    # Check main page
    emails = email_pattern.findall(body)
    all_emails.update(emails)

    # Check contact paths
    for path in CONTACT_PATHS:
        url = base_url.rstrip("/") + path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        if resp.get("status") in (200, 301, 302):
            page_body = resp.get("body", "")
            found = email_pattern.findall(page_body)
            all_emails.update(found)

    if all_emails:
        # Filter out common non-human / obfuscated-looking patterns
        email_list = sorted(all_emails)
        findings.append(Finding(
            title=f"Email addresses harvested: {len(email_list)}",
            severity="medium", category="email_harvest", module="recon",
            description=f"Found {len(email_list)} email addresses in page content: {', '.join(email_list[:10])}"
                + (f" ... and {len(email_list)-10} more" if len(email_list) > 10 else ""),
            evidence=f"Emails: {', '.join(email_list[:5])}",
            asset="", points_deducted=4,
        ))

    return findings


# ── 23. Open Redirect Deep Check ────────────────────────────────────────

def _check_open_redirect(base_url: str, timeout: int,
                         verify_tls: bool) -> List[Finding]:
    findings = []
    for endpoint in REDIRECT_ENDPOINTS:
        for payload in OPEN_REDIRECT_PAYLOADS:
            target_url = base_url.rstrip("/") + endpoint + "?url=" + urllib.parse.quote(payload, safe="")
            try:
                resp = http_probe(target_url, timeout=timeout, verify_tls=verify_tls)
                location = resp.get("headers", {}).get("location", "")
                status = resp.get("status", 0)
                # Check if redirect leads to evil.com
                if status in (301, 302, 303, 307, 308) and "evil.com" in location:
                    findings.append(Finding(
                        title=f"Open redirect: {endpoint}",
                        severity="high", category="open_redirect", module="recon",
                        description=f"Open redirect at {endpoint} — redirects to attacker-controlled URL",
                        evidence=f"GET {endpoint}?url=... -> 302 {location[:80]}",
                        asset="", points_deducted=8,
                    ))
                    break  # One hit per endpoint is enough
            except Exception:
                pass
    return findings


# ── 24. Mixed Content Detection ──────────────────────────────────────────

def _check_mixed_content(base_url: str, body: str, host: str) -> List[Finding]:
    findings = []
    # Only check if the base URL is HTTPS
    if not base_url.startswith("https://"):
        return findings

    mixed_patterns = [
        (r'<img[^>]+src=["\']http://[^"\']*["\']', "image"),
        (r'<script[^>]+src=["\']http://[^"\']*["\']', "script"),
        (r'<link[^>]+href=["\']http://[^"\']*["\']', "stylesheet"),
        (r'<iframe[^>]+src=["\']http://[^"\']*["\']', "iframe"),
        (r'<video[^>]+src=["\']http://[^"\']*["\']', "video"),
        (r'<audio[^>]+src=["\']http://[^"\']*["\']', "audio"),
    ]

    mixed_count = 0
    mixed_types = set()
    for pattern, resource_type in mixed_patterns:
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            mixed_count += len(matches)
            mixed_types.add(resource_type)

    if mixed_count > 0:
        sev = "high" if "script" in mixed_types else "medium"
        findings.append(Finding(
            title=f"Mixed content: {mixed_count} HTTP resource(s) on HTTPS page",
            severity=sev, category="mixed_content", module="recon",
            description=f"HTTPS page loads {mixed_count} HTTP resource(s) of type(s): {', '.join(sorted(mixed_types))} — insecure content",
            evidence=f"Mixed content types: {', '.join(sorted(mixed_types))}, count: {mixed_count}",
            asset=host, points_deducted=6 if sev == "high" else 3,
        ))

    return findings


# ── 25. Meta Tag Security ────────────────────────────────────────────────

def _check_meta_tags(body: str, host: str) -> List[Finding]:
    findings = []

    # Extract all meta tags
    meta_pattern = re.compile(r'<meta\s+([^>]+)/?>', re.IGNORECASE)
    metas = meta_pattern.findall(body)

    meta_dict = {}
    for meta_attrs in metas:
        name_match = re.search(r'(?:name|property|http-equiv)=["\']([^"\']+)["\']', meta_attrs, re.IGNORECASE)
        content_match = re.search(r'content=["\']([^"\']*)["\']', meta_attrs, re.IGNORECASE)
        if name_match and content_match:
            key = name_match.group(1).lower()
            val = content_match.group(1)
            meta_dict[key] = val

    # Check for missing viewport
    has_viewport = any(k.lower() == "viewport" for k in meta_dict)
    if not has_viewport:
        findings.append(Finding(
            title="Missing viewport meta tag",
            severity="info", category="meta_tags", module="recon",
            description="No viewport meta tag found — page may not render properly on mobile devices",
            evidence="No <meta name=viewport> found",
            asset=host,
        ))

    # Check for missing charset
    has_charset = any(k.lower() == "charset" for k in meta_dict)
    charset_in_head = re.search(r'<meta\s+charset=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if not has_charset and not charset_in_head:
        findings.append(Finding(
            title="Missing charset declaration",
            severity="low", category="meta_tags", module="recon",
            description="No charset meta tag found — may cause rendering issues",
            evidence="No charset declaration found in meta tags",
            asset=host, points_deducted=1,
        ))

    # Check for sensitive meta tags
    sensitive_metas = {
        "generator": ("Generator meta tag leaks technology", "info", 0),
        "author": ("Author meta tag leaks personnel info", "low", 1),
        "keywords": ("Keywords meta tag may leak sensitive info", "low", 1),
    }
    for meta_name, (title, sev, pts) in sensitive_metas.items():
        val = meta_dict.get(meta_name)
        if val:
            findings.append(Finding(
                title=f"Sensitive meta tag: {meta_name}",
                severity=sev, category="meta_tags", module="recon",
                description=f"{title}: '{val[:80]}'",
                evidence=f"<{meta_name}: {val[:60]}",
                asset=host, points_deducted=pts,
            ))

    return findings


# ── Main recon runner ─────────────────────────────────────────────────────

def run_recon(target: str, base_url: str, timeout: int = 8,
              verify_tls: bool = True) -> List[Finding]:
    """Run full 25-category reconnaissance. Returns list of Findings."""
    findings: List[Finding] = []
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    def add(title, severity, category, desc, evidence, pts=0):
        findings.append(Finding(
            title=title, severity=severity, category=category,
            module="recon", description=desc, evidence=evidence,
            asset=host, points_deducted=pts,
    ))

    # ── 1. DNS (Cloudflare DoH + socket fallback) ─────────────────────────
    dns = _dns_lookup(host)

    # v9.1.0: Inject ReconPro Signature into DNS-check probe
    _sig_headers = {}
    try:
        from ..wishes import SignatureBroadcaster
        _sig_headers = SignatureBroadcaster().broadcast()
    except Exception:
        pass

    if not dns["a"] and not dns["aaaa"]:
        add("DNS resolution failed", "critical", "dns",
            f"No A or AAAA records found for {host}", "DNS lookup: no results")
    else:
        # Report DNS records found
        record_summary = []
        if dns["a"]:
            record_summary.append(f"A: {'; '.join(dns['a'][:5])}")
        if dns["aaaa"]:
            record_summary.append(f"AAAA: {'; '.join(dns['aaaa'][:5])}")
        if dns["cname"]:
            record_summary.append(f"CNAME: {'; '.join(dns['cname'][:3])}")
        if dns["mx"]:
            record_summary.append(f"MX: {'; '.join(dns['mx'][:5])}")
        if dns["ns"]:
            record_summary.append(f"NS: {'; '.join(dns['ns'][:5])}")
        if dns["txt"]:
            record_summary.append(f"TXT: {len(dns['txt'])} record(s)")
        if record_summary:
            add(f"DNS records: {len(record_summary)} type(s)", "info", "dns",
                f"DNS resolution returned: {'; '.join(record_summary)}",
                f"{' | '.join(record_summary[:4])}", 0)

    # Collect IPs for threat intel
    ip_list = dns.get("a", []) + dns.get("aaaa", [])

    # ── 2. Security headers ───────────────────────────────────────────────
    root = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, extra_headers=_sig_headers)
    root_h = root.get("headers", {})
    for hdr, display, sev, pts in SECURITY_HEADERS:
        if hdr.lower() not in {k.lower() for k in root_h}:
            add(f"Missing {display} header", sev, "security_headers",
                f"{display} ({hdr}) not set", f"Header {hdr} absent", pts)

    # ── 3. Technology fingerprinting ───────────────────────────────────────
    body = root.get("body", "")[:16384]
    tech = _detect_tech(body, root_h)
    if tech:
        add(f"Technologies detected: {', '.join(tech[:10])}"
            + (f" +{len(tech)-10} more" if len(tech) > 10 else ""),
            "info", "tech",
            f"Detected {len(tech)} technologies: {', '.join(tech[:15])}",
            f"Tech: {', '.join(tech[:8])}", 0)

    # ── 4. robots.txt / sitemap.xml ───────────────────────────────────────
    for path in ["/robots.txt", "/sitemap.xml"]:
        resp = http_probe(base_url.rstrip("/") + path, timeout=timeout, verify_tls=verify_tls)
        if resp.get("status") == 200:
            add(f"{path} accessible", "info", "discovery",
                f"{path} is publicly accessible ({len(resp.get('body', ''))} bytes)",
                f"GET {path} -> 200", 0)

    # ── 5. TLS / SSL certificate info ─────────────────────────────────────
    tls = _check_tls(host)
    if tls.get("days_left") is not None and tls["days_left"] < 30:
        add(f"TLS cert expiring in {tls['days_left']} days", "high", "tls",
            f"Certificate expires {tls['expiry']}",
            f"Days left: {tls['days_left']}", 8)
    if tls.get("version") and "3.0" in tls["version"]:
        add("Deprecated TLS version", "critical", "tls",
            f"Server uses {tls['version']}", f"TLS: {tls['version']}", 12)

    # ── 6. Port scan (top 20) ─────────────────────────────────────────────
    open_p = _check_ports(host)
    for p in open_p:
        if p["port"] not in (80, 443):
            add(f"Open port: {p['port']}", "medium", "ports",
                f"Port {p['port']} is open", f"Port {p['port']}: open", 3)

    # ── 6b. ASN lookup ────────────────────────────────────────────────────
    try:
        whois_result = subprocess.run(
            ["whois", host],
            capture_output=True, text=True, timeout=10
        )
        whois_text = whois_result.stdout
        asn_match = re.search(r'(?:ASN|AS)(?:\t|[ :]+)(\d+)', whois_text, re.IGNORECASE)
        org_match = re.search(r'(?:OrgName|Organization|org-name)[:\s]+(.+)', whois_text, re.IGNORECASE)
        if asn_match:
            asn = asn_match.group(1)
            org = org_match.group(1).strip()[:80] if org_match else "Unknown"
            add(f"ASN: AS{asn} ({org})", "info", "asn",
                f"Hosted on AS{asn}, operated by {org}",
                f"ASN: AS{asn}, Org: {org[:50]}", 0)
        elif org_match:
            add(f"Hosting: {org_match.group(1).strip()[:60]}", "info", "asn",
                f"Operated by: {org_match.group(1).strip()[:80]}",
                f"Org: {org_match.group(1).strip()[:50]}", 0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # ── 7. Sensitive paths ────────────────────────────────────────────────
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        if resp.get("status") == 200 and len(resp.get("body", "")) > 10:
            add(f"Exposed: {path}", "high", "exposed_files",
                f"Sensitive path accessible: {path}", f"GET {path} -> 200", 10)

    # ── 8. API endpoints ──────────────────────────────────────────────────
    for path in API_PATHS:
        url = base_url.rstrip("/") + path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        if resp.get("status") == 200:
            b = resp.get("body", "").lower()
            if not any(kw in b for kw in ["unauthorized", "401", "forbidden", "login required"]):
                add(f"Unauthenticated API: {path}", "high", "api",
                    f"API route accessible without auth", f"GET {path} -> 200", 10)

    # ── 9. CORS ───────────────────────────────────────────────────────────
    findings.extend(_check_cors(base_url))

    # ── 10. Cookies ───────────────────────────────────────────────────────
    findings.extend(_check_cookies(root_h))

    # ── 11. WAF detection ─────────────────────────────────────────────────
    waf = _detect_waf(root_h, body)
    if not waf:
        add("No WAF detected", "medium", "waf",
            "No Web Application Firewall signatures found", "No WAF headers/signatures", 4)
    else:
        add(f"WAF detected: {', '.join(waf)}", "info", "waf",
            f"Web Application Firewall(s) found: {', '.join(waf)}",
            f"WAF: {', '.join(waf)}", 0)

    # ── 12. Redirect chain ────────────────────────────────────────────────
    if root.get("status") in (301, 302, 307, 308):
        loc = root_h.get("location", "")
        add(f"Redirect: {root['status']} -> {loc[:80]}", "info", "redirects",
            f"Root URL redirects to {loc}", f"Status {root['status']}", 0)

    # ── 13. Email / SPF / DMARC ───────────────────────────────────────────
    try:
        for qtype in ["TXT", "MX"]:
            try:
                result = subprocess.run(
                    ["dig", "+short", host, qtype],
                    capture_output=True, text=True, timeout=5
                )
                output = result.stdout.strip()
                if qtype == "MX" and output:
                    mx_records = [l.strip() for l in output.split("\n") if l.strip()]
                    add(f"MX records found ({len(mx_records)})", "info", "email",
                        f"Mail servers: {'; '.join(mx_records[:5])}",
                        f"MX: {'; '.join(mx_records[:3])}", 0)
                elif qtype == "TXT" and output:
                    lines = output.split("\n")
                    has_spf = any('v=spf1' in l.lower() for l in lines)
                    has_dmarc = False
                    for l in lines:
                        if 'v=dmarc1' in l.lower():
                            has_dmarc = True
                    if not has_spf:
                        add("Missing SPF record", "medium", "email",
                            "No SPF (Sender Policy Framework) TXT record found — email spoofing possible",
                            "dig TXT: no v=spf1", 5)
                    if not has_dmarc:
                        # Check _dmarc subdomain
                        try:
                            dmarc_result = subprocess.run(
                                ["dig", "+short", f"_dmarc.{host}", "TXT"],
                                capture_output=True, text=True, timeout=5
                            )
                            if 'v=dmarc1' not in dmarc_result.stdout.lower():
                                add("Missing DMARC record", "medium", "email",
                                    "No DMARC record found — no email authentication policy",
                                    "dig _dmarc TXT: no v=dmarc1", 5)
                        except Exception:
                            add("Missing DMARC record", "medium", "email",
                                "Could not check DMARC record",
                                "DMARC check failed", 3)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
    except Exception:
        pass

    # ── 14. Certificate Transparency (crt.sh) ─────────────────────────────
    findings.extend(_check_cert_transparency(host))

    # ── 15. Threat Intelligence (abuse.ch) ────────────────────────────────
    findings.extend(_check_threat_intel(host, ip_list))

    # ── 16. Enhanced TLS Cipher Analysis ──────────────────────────────────
    findings.extend(_check_tls_ciphers(tls, host))

    # ── 17. Enhanced Technology Fingerprinting ────────────────────────────
    # (already handled in step 3 with expanded TECH_SIGNATURES)

    # ── 18. Enhanced WAF Detection ────────────────────────────────────────
    # (already handled in step 11 with expanded WAF_SIGNATURES)

    # ── 19. Content Security Policy Deep Analysis ─────────────────────────
    findings.extend(_check_csp_deep(root_h, host))

    # ── 20. HTTP/2 and Protocol Analysis ──────────────────────────────────
    findings.extend(_check_http2(host, base_url, timeout, verify_tls))

    # ── 21. Subdomain Enumeration via Passive DNS ─────────────────────────
    # Gather crt.sh subdomains first
    crt_subdomains = set()
    try:
        crt_url = f"https://crt.sh/?q=%.{host}&output=json"
        crt_req = urllib.request.Request(crt_url,
            headers={"Accept": "application/json", "User-Agent": "ReconPro/2.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(crt_req, timeout=15, context=ctx) as resp:
            crt_data = json.loads(resp.read(1048576).decode())
        if isinstance(crt_data, list):
            for entry in crt_data:
                name_val = entry.get("name_value", "")
                for name in name_val.split("\n"):
                    n = name.strip().lstrip("*.").lower()
                    if n and n != host:
                        crt_subdomains.add(n)
    except Exception:
        pass
    findings.extend(_check_subdomains(host, crt_subdomains))

    # ── 22. Email Harvesting ──────────────────────────────────────────────
    findings.extend(_check_email_harvest(base_url, body, timeout, verify_tls))

    # ── 23. Open Redirect Deep Check ──────────────────────────────────────
    findings.extend(_check_open_redirect(base_url, timeout, verify_tls))

    # ── 24. Mixed Content Detection ───────────────────────────────────────
    findings.extend(_check_mixed_content(base_url, body, host))

    # ── 25. Meta Tag Security ─────────────────────────────────────────────
    findings.extend(_check_meta_tags(body, host))

    # ── v9.2.0: Social Graph + Sovereignty ─────────────────────────────
    findings.extend(_check_social_graph(target, base_url, timeout=timeout, verify_tls=verify_tls))
    findings.extend(_check_sovereignty(target, base_url, ip_list, timeout=timeout))

    return findings


def _check_social_graph(target: str, base_url: str, timeout: int = 8,
                         verify_tls: bool = True) -> List[Finding]:
    """v9.2.0: Build social graph and identify critical bridge entities."""
    findings: List[Finding] = []
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        from ..social_graph import GraphIntelligence
        gi = GraphIntelligence()
        graph = gi.build_graph(host, base_url)
        stats = graph.stats()
        if stats.get("entity_count", 0) > 3:
            clusters = stats.get("cluster_count", 0)
            bridges = graph.find_bridge_entities()
            findings.append(Finding(
                title="Social graph: {} entities, {} clusters".format(
                    stats["entity_count"], clusters),
                severity="medium", category="social_graph",
                module="recon",
                description="OSINT relationship graph: {} entities, {} relationships, "
                            "{} clusters, {} bridge entities.".format(
                    stats["entity_count"], stats.get("relationship_count", 0),
                    clusters, len(bridges)),
                evidence="Bridges: {}".format(", ".join(str(b) for b in bridges[:5])),
                asset=host, points_deducted=5 if len(bridges) > 2 else 3,
                remediation="Bridge entities are critical nodes — securing them collapses multiple attack paths.",
            ))
    except Exception:
        pass

    return findings


def _check_sovereignty(target: str, base_url: str, ip_list: list,
                        timeout: int = 8) -> List[Finding]:
    """v9.2.0: Digital sovereignty and jurisdiction mapping."""
    findings: List[Finding] = []
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        from ..sovereignty import SovereigntyMapper
        sm = SovereigntyMapper()
        profile = sm.map_sovereignty(host, base_url, timeout=min(timeout, 5))
        jurisdictions = profile.get("jurisdictions", [])
        surveillance = profile.get("surveillance_risk", "low")
        if jurisdictions:
            countries = [j.get("country", "?") for j in jurisdictions[:3]]
            findings.append(Finding(
                title="Digital sovereignty: {}".format(", ".join(countries)),
                severity="medium" if surveillance == "high" else "low",
                category="sovereignty",
                module="recon",
                description="Infrastructure sovereignty spans: {}. Surveillance risk: {}.".format(
                    ", ".join(countries), surveillance),
                evidence="Jurisdictions: {}".format(len(jurisdictions)),
                asset=host, points_deducted=5 if surveillance == "high" else 2,
                remediation="Review data residency compliance for identified jurisdictions.",
            ))
    except Exception:
        pass

    return findings

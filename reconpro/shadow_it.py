"""
econpro.shadow_it — Shadow IT & Abandoned Infrastructure Discovery

ReconPro v9.2.0 | Pure Python security scanner — ZERO external dependencies.

Discovers infrastructure that security teams forgot exists: forgotten subdomains,
staging environments, abandoned installs, shadow APIs, orphaned DNS, forgotten
services, cloud credential leaks, and accidentally exposed internal tools.
"""

from __future__ import annotations

import socket
import ssl
import hashlib
import json
import re
import time
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, urljoin, quote
from urllib.request import Request, urlopen, URLError
from urllib.error import HTTPError, URLError as UrlLibURLError
import http.client


# ---------------------------------------------------------------------------
# DecayIndicators — constant signatures of abandonment
# ---------------------------------------------------------------------------

class DecayIndicators:
    """Canonical list of indicators that suggest an asset has been abandoned."""

    DEFAULT_PAGE_TITLES: List[str] = [
        "Welcome to nginx",
        "Welcome to nginx!",
        "Apache2 Ubuntu Default Page",
        "Apache2 Debian Default Page",
        "Apache HTTP Server Test Page",
        "Test Page for the Apache HTTP Server",
        "It works!",
        "Apache Tomcat",
        "Welcome to IIS",
        "Internet Information Services",
        "Welcome to Your New Website",
        "Default Web Site Page",
        "Bluehost",
        "cPanel",
        "Coming Soon",
        "Site under construction",
        "This site is under development",
        "Index of /",
        "Directory Listing For",
        "Default Parallels Plesk Page",
        "Plesk Default Page",
        "Hestia Control Panel",
        "1&1 IONOS",
        "Welcome",
        "placeholder",
    ]

    OUTDATED_SERVER_HEADERS: List[str] = [
        "Apache/2.2",
        "Apache/2.4.7",
        "Apache/2.4.6",
        "Apache/2.4.18",
        "Apache/2.4.25",
        "Apache/2.4.29",
        "Apache/2.4.33",
        "Apache/2.4.34",
        "Apache/2.4.39",
        "nginx/1.4",
        "nginx/1.6",
        "nginx/1.8",
        "nginx/1.10",
        "nginx/1.12",
        "nginx/1.14",
        "nginx/1.16",
        "nginx/1.18",
        "Microsoft-IIS/7.0",
        "Microsoft-IIS/7.5",
        "Microsoft-IIS/8.0",
        "Microsoft-IIS/8.5",
        "Microsoft-HTTPAPI/2.0",
        "lighttpd/1.4",
        "openresty/1.15",
        "openresty/1.17",
        "cloudflare",
        "Apache/1.3",
        "Apache-Coyote/1.1",
    ]

    MISSING_SECURITY_HEADERS: List[str] = [
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

    WORDPRESS_OLD_SIGNATURES: List[re.Pattern] = [
        re.compile(r'wp-content/themes/twenty(ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen)', re.I),
        re.compile(r'<meta name="generator" content="WordPress ([0-4]\\.|5\\.[0-4]\\.)', re.I),
        re.compile(r'wp-includes/js/jquery/jquery\.js', re.I),
        re.compile(r'wp-json/wp/v2', re.I),
        re.compile(r'/wp-admin/admin-ajax\.php', re.I),
    ]

    OUTDATED_JS_SIGNATURES: List[re.Pattern] = [
        re.compile(r'jquery/[12]\\.', re.I),
        re.compile(r'jquery-1\\.', re.I),
        re.compile(r'jquery-2\\.', re.I),
        re.compile(r'bootstrap/3\\.', re.I),
        re.compile(r'bootstrap\\.min\\.js.*3\\.', re.I),
        re.compile(r'angular\\.js/1\\.', re.I),
        re.compile(r'angular.*1\\.[0-5]\\.', re.I),
        re.compile(r'prototype\\.js', re.I),
        re.compile(r'mootools', re.I),
    ]

    CERTIFICATE_ISSUES: List[str] = [
        "cert_expired",
        "cert_self_signed",
        "cert_hostname_mismatch",
        "cert_near_expiry",
        "cert_not_valid_yet",
    ]

    INFRASTRUCTURE_DECAY_MARKERS: List[str] = [
        "no_robots_txt",
        "no_favicon",
        "http_only_no_redirect",
        "no_hsts",
        "no_csp",
        "default_install_page",
        "directory_listing",
        "server_header_outdated",
        "outdated_js_libs",
        "old_wordpress",
        "expired_cert",
        "self_signed_cert",
        "near_expiry_cert",
        "no_last_modified",
        "stale_content",
        "debug_mode_on",
        "error_page_exposed",
        "php_errors_visible",
        "stack_trace_exposed",
    ]

    @classmethod
    def all_indicators(cls) -> List[str]:
        """Return every known decay indicator string."""
        return list(cls.INFRASTRUCTURE_DECAY_MARKERS)


# ---------------------------------------------------------------------------
# AssetProfile — dataclass for individual findings
# ---------------------------------------------------------------------------

@dataclass
class AssetProfile:
    """Profile of a single discovered asset with decay analysis."""
    url: str
    asset_type: str
    status_code: Optional[int]
    decay_score: int
    indicators: List[str] = field(default_factory=list)
    last_modified: Optional[str] = None
    risk_level: str = "low"
    server_header: Optional[str] = None
    title: Optional[str] = None
    cert_info: Optional[Dict[str, Any]] = None
    tech_stack: List[str] = field(default_factory=list)
    discovered_by: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.decay_score >= 75:
            self.risk_level = "critical"
        elif self.decay_score >= 55:
            self.risk_level = "high"
        elif self.decay_score >= 35:
            self.risk_level = "medium"
        elif self.decay_score >= 15:
            self.risk_level = "low"
        else:
            self.risk_level = "info"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "url": self.url,
            "asset_type": self.asset_type,
            "status_code": self.status_code,
            "decay_score": self.decay_score,
            "indicators": self.indicators,
            "last_modified": self.last_modified,
            "risk_level": self.risk_level,
            "server_header": self.server_header,
            "title": self.title,
            "cert_info": self.cert_info,
            "tech_stack": self.tech_stack,
            "discovered_by": self.discovered_by,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _make_request(
    url: str,
    timeout: int = 8,
    method: str = "GET",
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[Dict[str, str]], Optional[int], Optional[str], Optional[str]]:
    """
    Perform an HTTP request using stdlib urllib and return
    (response_headers, status_code, body_snippet, final_url).

    Returns (None, None, None, None) on any failure.
    """
    default_headers = {
        "User-Agent": "ReconPro/9.2.0 (Security Scanner; https://reconpro.dev)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }
    if headers:
        default_headers.update(headers)

    try:
        req = Request(url, headers=default_headers, method=method)
        resp = urlopen(req, timeout=timeout, context=None)
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        status_code = resp.getcode()
        final_url = resp.geturl()
        body = resp.read(65536)
        try:
            body_text = body.decode("utf-8", errors="replace")[:16384]
        except Exception:
            body_text = ""
        return resp_headers, status_code, body_text, final_url
    except HTTPError as exc:
        resp_headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        try:
            body = exc.read(65536)
            body_text = body.decode("utf-8", errors="replace")[:16384]
        except Exception:
            body_text = ""
        return resp_headers, exc.code, body_text, url
    except (URLError, UrlLibURLError, OSError, Exception):
        return None, None, None, None


def _probe_path(base_url: str, path: str, timeout: int = 8) -> AssetProfile:
    """Probe a single path under *base_url* and return an AssetProfile."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    resp_headers, status_code, body, final_url = _make_request(url, timeout=timeout)
    cert_info = _check_certificate_age(urlparse(url).hostname or "")
    title = _extract_title(body or "")
    indicators: List[str] = []
    tech_stack: List[str] = _detect_tech_stack(resp_headers, body or "")

    asset_type = _classify_asset(resp_headers, body or "", title, cert_info)
    indicators.extend(_assess_indicators(resp_headers, body or "", title, cert_info))
    last_mod = resp_headers.get("last-modified") if resp_headers else None

    decay = _calculate_decay_from_indicators(indicators, resp_headers, cert_info)

    profile = AssetProfile(
        url=url,
        asset_type=asset_type,
        status_code=status_code,
        decay_score=decay,
        indicators=indicators,
        last_modified=last_mod,
        server_header=(resp_headers.get("server", "") if resp_headers else None),
        title=title,
        cert_info=cert_info,
        tech_stack=tech_stack,
        discovered_by="path_probe",
    )
    return profile


def _extract_title(html: str) -> str:
    """Extract <title> content from HTML."""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        return m.group(1).strip()[:256]
    return ""


def _detect_tech_stack(headers: Optional[Dict[str, str]], body: str) -> List[str]:
    """Detect technology stack from headers and body."""
    stack: List[str] = []
    if headers:
        server = headers.get("server", "")
        if "nginx" in server.lower():
            stack.append("nginx")
        if "apache" in server.lower():
            stack.append("Apache")
        if "iis" in server.lower() or "Microsoft-HTTPAPI" in server:
            stack.append("IIS")
        if "tomcat" in server.lower() or "Apache-Coyote" in server:
            stack.append("Tomcat")
        powered_by = headers.get("x-powered-by", "")
        if "php" in powered_by.lower():
            stack.append("PHP")
        if "express" in powered_by.lower():
            stack.append("Express.js")
        if "asp.net" in powered_by.lower():
            stack.append("ASP.NET")
        if "next" in powered_by.lower():
            stack.append("Next.js")
    if body:
        if "wp-content" in body or "wp-includes" in body:
            stack.append("WordPress")
        if re.search(r'wp-content/themes/\w+', body):
            stack.append("WordPress (themed)")
        if "drupal" in body.lower():
            stack.append("Drupal")
        if "Joomla" in body:
            stack.append("Joomla")
        if "django" in body.lower() or "csrfmiddlewaretoken" in body:
            stack.append("Django")
        if "laravel" in body.lower() or "laravel_session" in body:
            stack.append("Laravel")
        if "react" in body.lower() and "__NEXT_DATA__" in body:
            stack.append("React/Next.js")
        if re.search(r'angular[^.]', body, re.I):
            stack.append("Angular")
        if "vue" in body.lower() or "__vue" in body:
            stack.append("Vue.js")
        if "jquery" in body.lower():
            stack.append("jQuery")
        if "bootstrap" in body.lower():
            stack.append("Bootstrap")
        if "/api-docs" in body or "swagger" in body.lower():
            stack.append("Swagger")
        if "graphql" in body.lower():
            stack.append("GraphQL")
    return list(dict.fromkeys(stack))


def _check_certificate_age(host: str) -> Optional[Dict[str, Any]]:
    """Check TLS certificate details using stdlib ssl. Returns cert info dict."""
    if not host:
        return None
    from .http_layer import inspection_context
    # certificate inspection (audited helper — not data transport)
    ctx = inspection_context()
    port = 443
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
                cert_dict = tls_sock.getpeercert()
                if not cert_dict:
                    return {"host": host, "error": "no_certificate"}
                now = datetime.now(timezone.utc)
                not_before = None
                not_after = None
                if "notBefore" in cert_dict:
                    not_before = datetime.strptime(cert_dict["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                if "notAfter" in cert_dict:
                    not_after = datetime.strptime(cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_until_expiry = None
                expired = False
                near_expiry = False
                if not_after:
                    delta = not_after - now
                    days_until_expiry = delta.days
                    expired = delta.total_seconds() < 0
                    near_expiry = 0 < delta.days <= 30

                age_days = None
                if not_before:
                    age_days = (now - not_before).days

                issuer = ""
                subject = ""
                for pair in cert_dict.get("issuer", []):
                    if pair[0][0] == "organizationName":
                        issuer = pair[0][1]
                for pair in cert_dict.get("subject", []):
                    if pair[0][0] == "commonName":
                        subject = pair[0][1]

                hostname_match = False
                for san_type, san_value in cert_dict.get("subjectAltName", []):
                    if san_type == "DNS" and san_value.lower() == host.lower():
                        hostname_match = True
                        break
                if not hostname_match and subject.lower() == host.lower():
                    hostname_match = True

                self_signed = issuer == subject or "Let's Encrypt" not in issuer and not any(
                    known in issuer for known in ["DigiCert", "Sectigo", "GlobalSign", "Cloudflare", "Amazon", "Google"]
                )

                serial_hex = ""
                if cert_der:
                    serial_hex = hashlib.sha256(cert_der).hexdigest()[:16]

                return {
                    "host": host,
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before.isoformat() if not_before else None,
                    "not_after": not_after.isoformat() if not_after else None,
                    "days_until_expiry": days_until_expiry,
                    "age_days": age_days,
                    "expired": expired,
                    "near_expiry": near_expiry,
                    "self_signed": self_signed,
                    "hostname_match": hostname_match,
                    "serial_fingerprint": serial_hex,
                }
    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, Exception):
        return {"host": host, "error": "connection_failed"}


def _classify_asset(
    headers: Optional[Dict[str, str]],
    body: str,
    title: str,
    cert_info: Optional[Dict[str, Any]],
) -> str:
    """Classify an asset into a type string based on response signals."""
    if not headers and not body:
        return "unreachable"
    if body:
        bl = body.lower()
        if "phpmyadmin" in bl or "pma" in bl:
            return "database_admin"
        if "jenkins" in bl:
            return "ci_cd"
        if "grafana" in bl:
            return "monitoring"
        if "kibana" in bl:
            return "monitoring"
        if "redis commander" in bl or "redis-commander" in bl:
            return "database_admin"
        if "pgadmin" in bl:
            return "database_admin"
        if "mongo express" in bl or "mongo-express" in bl:
            return "database_admin"
        if "solr" in bl and "admin" in bl:
            return "search_admin"
        if "tomcat manager" in bl or "/manager/html" in bl:
            return "app_server"
        if "swagger" in bl or "openapi" in bl or "/api-docs" in bl:
            return "api_documentation"
        if "graphql" in bl:
            return "api_graphql"
        if "/api/" in bl or re.search(r'api[_-]?key|apikey|api-key', bl):
            return "api_endpoint"
        if "sentry" in bl and ("dsn" in bl or "project" in bl):
            return "error_tracking"
        if "aws_access_key" in bl or "AKIA" in body:
            return "cloud_credentials"
        if "firebase" in bl and "config" in bl:
            return "cloud_config"
        if "wordpress" in bl or "wp-content" in bl:
            return "cms_wordpress"
        if "drupal" in bl:
            return "cms_drupal"
        if "joomla" in bl:
            return "cms_joomla"
        for default in DecayIndicators.DEFAULT_PAGE_TITLES:
            if default.lower() in title.lower():
                return "default_install"
        if "directory listing" in bl or "index of /" in title.lower():
            return "directory_listing"
        if "staging" in bl or "development" in title.lower() or "dev" in title.lower():
            return "staging_environment"
    if headers:
        ct = headers.get("content-type", "")
        if "application/json" in ct:
            return "api_response"
        if "text/xml" in ct or "application/xml" in ct:
            return "xml_endpoint"
    return "web_application"


def _assess_indicators(
    headers: Optional[Dict[str, str]],
    body: str,
    title: str,
    cert_info: Optional[Dict[str, Any]],
) -> List[str]:
    """Assess decay indicators from response signals."""
    indicators: List[str] = []
    if headers:
        server = headers.get("server", "")
        for old in DecayIndicators.OUTDATED_SERVER_HEADERS:
            if old.lower() in server.lower():
                indicators.append("server_header_outdated")
                break
        header_names = {k.lower() for k in headers}
        if "strict-transport-security" not in header_names:
            indicators.append("no_hsts")
        if "content-security-policy" not in header_names:
            indicators.append("no_csp")
        for sec_h in DecayIndicators.MISSING_SECURITY_HEADERS:
            if sec_h not in header_names:
                pass  # already captured the most critical
        if "last-modified" not in header_names:
            indicators.append("no_last_modified")
    if title:
        for default_title in DecayIndicators.DEFAULT_PAGE_TITLES:
            if default_title.lower() in title.lower():
                indicators.append("default_install_page")
                break
        if "index of" in title.lower():
            indicators.append("directory_listing")
    if body:
        if "wp-content" in body or "wp-includes" in body:
            for pat in DecayIndicators.WORDPRESS_OLD_SIGNATURES:
                if pat.search(body):
                    indicators.append("old_wordpress")
                    break
        for pat in DecayIndicators.OUTDATED_JS_SIGNATURES:
            if pat.search(body):
                indicators.append("outdated_js_libs")
                break
        if re.search(r'<[^>]+(?:notice|warning|error|fatal|deprecated)[^>]*>.*?(?:on line \d+|in .*\.php)', body, re.I | re.S):
            indicators.append("php_errors_visible")
        if "stack trace" in body.lower() or "traceback (most recent" in body.lower():
            indicators.append("stack_trace_exposed")
        if "debug" in body.lower() and ("debug_mode" in body.lower() or "DEBUG" in body):
            indicators.append("debug_mode_on")
        if not re.search(r'<link[^>]+favicon', body, re.I):
            indicators.append("no_favicon")
    if cert_info:
        if cert_info.get("expired"):
            indicators.append("expired_cert")
        if cert_info.get("self_signed"):
            indicators.append("self_signed_cert")
        if cert_info.get("near_expiry"):
            indicators.append("near_expiry_cert")
        if not cert_info.get("hostname_match", False) and cert_info.get("subject"):
            indicators.append("cert_hostname_mismatch")
    return list(dict.fromkeys(indicators))


def _calculate_decay_from_indicators(
    indicators: List[str],
    headers: Optional[Dict[str, str]],
    cert_info: Optional[Dict[str, Any]],
) -> int:
    """Calculate a 0-100 decay score based on collected indicators."""
    score = 0
    weight_map: Dict[str, int] = {
        "expired_cert": 25,
        "self_signed_cert": 15,
        "near_expiry_cert": 12,
        "cert_hostname_mismatch": 10,
        "default_install_page": 20,
        "directory_listing": 18,
        "server_header_outdated": 15,
        "old_wordpress": 18,
        "outdated_js_libs": 10,
        "no_hsts": 5,
        "no_csp": 5,
        "no_favicon": 3,
        "no_last_modified": 2,
        "no_robots_txt": 3,
        "http_only_no_redirect": 8,
        "php_errors_visible": 15,
        "stack_trace_exposed": 20,
        "debug_mode_on": 18,
    }
    for ind in indicators:
        score += weight_map.get(ind, 5)
    if cert_info and cert_info.get("days_until_expiry") is not None:
        days = cert_info["days_until_expiry"]
        if days < 0:
            score = max(score, 60)
        elif days <= 7:
            score += 20
        elif days <= 30:
            score += 10
    if cert_info and cert_info.get("age_days") is not None:
        age = cert_info["age_days"]
        if age > 730:
            score += 8
        elif age > 365:
            score += 5
    return min(score, 100)


# ---------------------------------------------------------------------------
# ShadowITScanner
# ---------------------------------------------------------------------------

class ShadowITScanner:
    """
    Scans a target for Shadow IT and abandoned/decaying infrastructure.

    Pure Python, zero external dependencies — uses only the standard library.

    Usage::

        from reconpro.shadow_it import ShadowITScanner
        scanner = ShadowITScanner()
        results = scanner.scan("example.com", "https://example.com")
    """

    # Common subdomain prefixes for brute-force enumeration
    COMMON_SUBDOMAIN_PREFIXES: List[str] = [
        "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh", "vpn",
        "api", "api-v2", "api2", "v2", "v3", "app", "apps", "portal",
        "admin", "administrator", "manage", "manager", "management", "cpanel",
        "staging", "stage", "stg", "dev", "development", "devel", "test",
        "testing", "qa", "uat", "pre-prod", "preprod", "pre-production",
        "ci", "cd", "ci-cd", "cicd", "build", "jenkins", "gitlab", "github",
        "bitbucket", "runner", "deploy", "deployment", "release",
        "devops", "infra", "infra-internal", "ops", "monitoring", "grafana",
        "kibana", "prometheus", "alert", "alerts", "alertmanager",
        "log", "logs", "logging", "elk", "elasticsearch", "splunk",
        "sentry", "rollbar", "datadog", "newrelic", "pagerduty",
        "db", "database", "db-admin", "phpmyadmin", "pgadmin", "redis",
        "mongo", "mongodb", "memcached", "redis-commander",
        "search", "solr", "elastic",
        "static", "assets", "cdn", "media", "images", "img", "files",
        "docs", "documentation", "wiki", "kb", "knowledge",
        "blog", "news", "press", "marketing", "shop", "store", "pay",
        "auth", "login", "sso", "oauth", "oidc", "identity",
        "crm", "erp", "hr", "finance", "billing", "support", "help",
        "chat", "webhook", "webhooks", "hook", "hooks",
        "internal", "private", "intranet", "backoffice", "back-office",
        "demo", "sandbox", "poc", "prototype", "mock",
        "old", "legacy", "archive", "backup", "bak", "migrate", "migration",
        "ns1", "ns2", "ns3", "mx", "mx1", "mx2",
        "status", "health", "ping", "ready", "live", "prod",
        "stg1", "stg2", "dev1", "dev2", "test1", "test2",
        "us", "eu", "uk", "asia", "emea", "apac",
        "dashboard", "dash", "panel", "console", "control",
        "mqtt", "amqp", "rabbitmq", "kafka", "queue",
        "minio", "s3", "storage", "bucket",
        "trace", "jaeger", "zipkin",
        "vault", "secrets", "config", "settings",
    ]

    # Staging / non-production subdomain patterns
    STAGING_PATTERNS: List[str] = [
        "staging", "stage", "stg", "stg1", "stg2", "stg3",
        "dev", "dev1", "dev2", "dev3", "development", "devel",
        "test", "test1", "test2", "test3", "testing",
        "uat", "uat1", "uat2", "pre-prod", "preprod", "preproduction",
        "ci", "ci1", "ci2", "cd", "build", "builds", "jenkins",
        "gitlab", "runner", "runners", "deploy", "deployment",
        "demo", "sandbox", "poc", "prototype", "mock", "mockup",
        "qa", "qa1", "qa2", "review", "staging-internal",
        "dev-api", "test-api", "staging-api",
        "ci-api", "dev-admin", "test-admin", "staging-admin",
    ]

    # Known shadow API / debug / documentation paths
    SHADOW_API_PATHS: List[str] = [
        "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v1/",
        "/api/v2/", "/api/internal", "/api/admin", "/api/debug",
        "/api-docs", "/api/docs", "/swagger", "/swagger.json",
        "/swagger-ui", "/swagger-ui/", "/openapi.json", "/openapi.yaml",
        "/graphql", "/graphql/explorer", "/graphiql", "/playground",
        "/api/graphql", "/api/v1/graphql", "/query",
        "/debug", "/debug/", "/debug/pprof", "/debug/vars",
        "/healthz", "/health", "/healthcheck", "/ready", "/readyz",
        "/metrics", "/metrics/", "/prometheus/metrics",
        "/status", "/status.php", "/status.json", "/server-status",
        "/info", "/info.php", "/phpinfo", "/phpinfo.php",
        "/.env", "/.env.example", "/.env.local", "/.env.production",
        "/wp-json", "/wp-json/wp/v2", "/wp-json/oembed/1.0/embed",
        "/robots.txt", "/sitemap.xml", "/humans.txt",
        "/config.json", "/config.yml", "/config.yaml", "/settings.json",
        "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
        "/management", "/management/health", "/management/info",
        "/_status", "/_health", "/__status", "/__health",
        "/trace", "/traces", "/spans",
        "/console", "/debug/console", "/_debug", "/_debug/",
        "/server-info", "/server-info.php", "/test", "/test/",
        "/version", "/version.json", "/revision", "/build-info",
        "/.well-known/security.txt", "/security.txt",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/cgi-bin/", "/cgi-sys/",
        "/elmah.axd", "/trace.axd",
    ]

    # Paths for known admin / management services
    FORGOTTEN_SERVICE_PATHS: List[str] = [
        "/phpmyadmin", "/phpMyAdmin", "/pma", "/php-my-admin",
        "/phpmyadmin/index.php", "/pma/index.php",
        "/jenkins", "/jenkins/", "/jenkins/login",
        "/grafana", "/grafana/", "/grafana/login",
        "/kibana", "/kibana/", "/kibana/app/kibana",
        "/app/kibana", "/kibana#/discover",
        "/redis-commander", "/redis-commander/", "/redis/commander",
        "/pgadmin4", "/pgadmin", "/pgadmin4/browser",
        "/mongo-express", "/mongo-express/", "/me",
        "/solr", "/solr/", "/solr/admin", "/solr/#/",
        "/manager/html", "/manager/status", "/host-manager/html",
        "/admin", "/admin/", "/admin/login",
        "/adminer", "/adminer.php", "/_adminer",
        "/portainer", "/portainer/", "/portainer/#/dashboard",
        "/registry", "/v2/_catalog", "/v2/",
        "/rabbitmq", "/rabbitmq/#/", "/rabbitmq/management",
        "/#bucket", "/minio", "/minio/", "/minio/login",
        "/strapi", "/strapi/admin", "/directus",
        "/prisma", "/prisma/studio",
        "/_dash", "/dashboards", "/dashboard",
        "/sonarqube", "/sonar/", "/sonarqube/dashboard",
        "/nexus", "/nexus/", "/nexus/#browse",
        "/artifactory", "/artifactory/", "/artifactory/webapp/",
        "/gitlab", "/gitlab/", "/gitlab/users/sign_in",
    ]

    # Cloud leak indicator paths and patterns
    CLOUD_LEAK_PATHS: List[str] = [
        "/.aws/credentials", "/.aws/config",
        "/s3.amazonaws.com", "/s3-website", "/.s3cfg",
        "/_aws", "/aws-config.json", "/aws-credentials.json",
        "/service-account.json", "/gcp-key.json", "/gcp-credentials.json",
        "/appsettings.json", "/appsettings.Development.json",
        "/firebase-config.json", "/firebase.js", "/firebase-init.js",
        "/supabase", "/supabase/", "/.supabase",
        "/.env.production", "/.env.staging", "/.env.local",
        "/credentials.json", "/key.json", "/private-key.pem",
        "/id_rsa", "/id_dsa", "/.ssh/",
        "/config/secrets.json", "/secrets.json", "/secrets.yaml",
        "/terraform.tfstate", "/.terraform", "/tfstate.json",
        "/docker-compose.yml", "/docker-compose.override.yml",
        "/kubeconfig", "/.kube/config", "/k8s/config",
        "/vault", "/vault/", "/vault/secrets",
        "/.npmrc", "/.pypirc", "/.gradle",
        "/wp-config.php.bak", "/wp-config.php.save", "/wp-config.php~",
        "/database.yml", "/database.yml.bak", "/secrets.yml",
        "/application.properties", "/application.yml",
        "/connection-string", "/connection.json", "/connection.yml",
        "/web.config", "/web.config.bak",
    ]

    # Internal tool / dashboard paths
    INTERNAL_EXPOSURE_PATHS: List[str] = [
        "/internal", "/internal/", "/internal/dashboard",
        "/admin/dashboard", "/admin/panel", "/admin/console",
        "/monitor", "/monitoring", "/monitoring/",
        "/alertmanager", "/alertmanager/", "/alerts",
        "/prometheus", "/prometheus/graph", "/prometheus/",
        "/sentry", "/sentry/", "/sentry/dashboard",
        "/rollbar", "/rollbar/", "/bugsnag",
        "/datadog", "/datadog/", "/newrelic",
        "/elk", "/elk/", "/kibana", "/kibana/",
        "/logstash", "/logstash/", "/elasticsearch",
        "/jenkins", "/jenkins/", "/jenkins/job",
        "/gitlab", "/gitlab/", "/gitlab/admin",
        "/sonar", "/sonarqube", "/sonarqube/",
        "/jira", "/jira/", "/confluence",
        "/backoffice", "/backoffice/", "/intranet",
        "/helpdesk", "/helpdesk/", "/zendesk",
        "/statuspage", "/status", "/uptime",
        "/adminer", "/adminer/", "/pgadmin/",
        "/netdata", "/netdata/", "/netdata/dashboard",
        "/cockpit", "/cockpit/", "/webmin",
        "/cpanel", "/cpanel/", "/whm", "/plesk",
        "/portainer", "/portainer/",
        "/rancher", "/rancher/",
        "/argocd", "/argocd/", "/argo-cd",
        "/traefik", "/traefik/", "/traefik/dashboard",
        "/consul", "/consul/", "/consul/ui",
        "/nomad", "/nomad/", "/fabio",
        "/vault", "/vault/", "/vault/ui",
        "/_internal", "/_admin", "/_monitoring",
    ]

    # Patterns in response body that indicate cloud credential exposure
    CLOUD_CREDENTIAL_PATTERNS: List[re.Pattern] = [
        re.compile(r'AKIA[0-9A-Z]{16}'),                              # AWS Access Key
        re.compile(r'(?:A3T[A-Z0-9]|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
        re.compile(r'"type"\s*:\s*"service_account"'),             # GCP Service Account
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                        # Firebase/Google API key
        re.compile(r'ya29\.[0-9A-Za-z\-_]+'),                        # Google OAuth token
        re.compile(r'xox[bpras]-[0-9a-zA-Z-]+'),                       # Slack tokens
        re.compile(r'ghp_[0-9a-zA-Z]{36}'),                             # GitHub PAT
        re.compile(r'gho_[0-9a-zA-Z]{36}'),                             # GitHub OAuth
        re.compile(r'ghs_[0-9a-zA-Z]{36}'),                             # GitHub App token
        re.compile(r'glpat-[0-9a-zA-Z\-_]{20}'),                      # GitLab PAT
        re.compile(r'glptt-[0-9a-zA-Z\-_]{20}'),                      # GitLab trigger token
        re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),  # JWT
        re.compile(r'sk-[0-9a-zA-Z]{48}'),                              # OpenAI-style key
        re.compile(r'sk_live_[0-9a-zA-Z]{24}'),                         # Stripe live key
        re.compile(r'rk_live_[0-9a-zA-Z]{24}'),                         # Stripe restricted key
        re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),   # Private keys
        re.compile(r'AZURE_CLIENT_SECRET\s*[=:]\s*["\']?[a-zA-Z0-9_-]{20,}'),
        re.compile(r'SUPABASE_URL\s*[=:]\s*["\']?https://[a-z0-9]+\.supabase\.co'),
        re.compile(r'FIREBASE_API_KEY\s*[=:]\s*["\']?AIza'),
        re.compile(r'NEXT_PUBLIC_SUPABASE'),
        re.compile(r'VITE_SUPABASE'),
        re.compile(r'REACT_APP_FIREBASE'),
        re.compile(r'mongodb(?:\\+srv)?://[^\s""]+'),               # MongoDB URI
        re.compile(r'postgres(?:ql)?://[^\s""]+'),                    # PostgreSQL URI
        re.compile(r'redis://[^\s""]+'),                              # Redis URI
        re.compile(r'amqp://[^\s""]+'),                                # AMQP URI
        re.compile(r'mysql://[^\s""]+'),                               # MySQL URI
    ]

    def __init__(self, timeout: int = 8) -> None:
        """Initialise the scanner with a default connection timeout."""
        self.timeout = timeout
        self._session_headers = {
            "User-Agent": "ReconPro/9.2.0 (Security Scanner; https://reconpro.dev)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }

    # ---------------------------------------------------------------------
    # Main orchestrator
    # ---------------------------------------------------------------------

    def scan(self, target: str, base_url: str, timeout: int = 8) -> Dict[str, Any]:
        """
        Run a full Shadow IT scan against *target* (domain) and *base_url*.

        Returns a dictionary with keys for every scan category, each containing
        a list of :class:`AssetProfile` dicts.
        """
        self.timeout = timeout
        timestamp = datetime.now(timezone.utc).isoformat()

        results: Dict[str, Any] = {
            "target": target,
            "base_url": base_url,
            "timestamp": timestamp,
            "scanner": "ReconPro ShadowIT v9.2.0",
            "summary": {
                "total_assets": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "categories_with_findings": 0,
            },
            "findings": {},
        }

        categories = [
            ("forgotten_subdomains", self.discover_forgotten_subdomains, [target]),
            ("staging_environments", self.discover_staging_environments, [target]),
            ("abandoned_infrastructure", self.discover_abandoned_infrastructure, [base_url]),
            ("shadow_apis", self.discover_shadow_apis, [base_url]),
            ("orphaned_dns", self.discover_orphaned_dns, [target]),
            ("forgotten_services", self.discover_forgotten_services, [base_url]),
            ("cloud_leaks", self.discover_cloud_leaks, [base_url]),
            ("internal_exposure", self.discover_internal_exposure, [base_url]),
        ]

        for cat_name, cat_func, cat_args in categories:
            try:
                assets = cat_func(*cat_args)
                if isinstance(assets, list):
                    results["findings"][cat_name] = [a.to_dict() if isinstance(a, AssetProfile) else a for a in assets]
                elif isinstance(assets, dict):
                    results["findings"][cat_name] = assets
                else:
                    results["findings"][cat_name] = assets
            except Exception as exc:
                results["findings"][cat_name] = {"error": str(exc)}

        # Build summary counts
        total = 0
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        cats_with_findings = 0
        for cat_key, cat_val in results["findings"].items():
            if isinstance(cat_val, list):
                for item in cat_val:
                    if isinstance(item, dict):
                        total += 1
                        rl = item.get("risk_level", "info")
                        if rl in risk_counts:
                            risk_counts[rl] += 1
                if cat_val:
                    cats_with_findings += 1
            elif isinstance(cat_val, dict) and "assets" in cat_val:
                for item in cat_val["assets"]:
                    if isinstance(item, dict):
                        total += 1
                        rl = item.get("risk_level", "info")
                        if rl in risk_counts:
                            risk_counts[rl] += 1
                if cat_val["assets"]:
                    cats_with_findings += 1

        results["summary"]["total_assets"] = total
        results["summary"]["critical"] = risk_counts["critical"]
        results["summary"]["high"] = risk_counts["high"]
        results["summary"]["medium"] = risk_counts["medium"]
        results["summary"]["low"] = risk_counts["low"]
        results["summary"]["info"] = risk_counts["info"]
        results["summary"]["categories_with_findings"] = cats_with_findings

        return results

    # ---------------------------------------------------------------------
    # 1. Forgotten subdomains
    # ---------------------------------------------------------------------

    def discover_forgotten_subdomains(self, target: str) -> List[AssetProfile]:
        """
        Enumerate subdomains via cert transparency (crt.sh) and common-prefix
        brute-force DNS resolution.
        """
        found: List[AssetProfile] = []
        resolved_hosts: Dict[str, str] = {}

        # --- Phase 1: crt.sh certificate transparency ---
        ct_hosts = self._query_crtsh(target)
        for host in ct_hosts:
            if host not in resolved_hosts:
                ip = self._resolve_host(host)
                if ip:
                    resolved_hosts[host] = ip

        # --- Phase 2: Brute-force common prefixes ---
        for prefix in self.COMMON_SUBDOMAIN_PREFIXES:
            fqdn = f"{prefix}.{target}"
            if fqdn not in resolved_hosts:
                ip = self._resolve_host(fqdn)
                if ip:
                    resolved_hosts[fqdn] = ip

        # --- Phase 3: Profile each discovered subdomain ---
        for host, ip in resolved_hosts.items():
            if host == target or host == f"www.{target}":
                continue
            profile = self._profile_host(host, ip)
            profile.discovered_by = "subdomain_enum"
            found.append(profile)

        return found

    def _query_crtsh(self, domain: str) -> List[str]:
        """Query crt.sh for certificate transparency subdomains."""
        hosts: List[str] = []
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp_headers, status, body, final_url = _make_request(
                url, timeout=12, headers=self._session_headers
            )
            if body and status == 200:
                try:
                    entries = json.loads(body)
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lstrip("*.")
                            if name and name.endswith(f".{domain}") and name != domain:
                                if name not in hosts:
                                    hosts.append(name)
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass
                # Fallback: regex extraction
                if not hosts:
                    pattern = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9-]*\.' + re.escape(domain) + r')')
                    matches = pattern.findall(body)
                    for m in matches:
                        m = m.lstrip("*.")
                        if m not in hosts and m != domain:
                            hosts.append(m)
        except Exception:
            pass
        return hosts

    def _resolve_host(self, host: str) -> Optional[str]:
        """Resolve a hostname to an IP address via DNS. Returns IP or None."""
        try:
            result = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            if result:
                return result[0][4][0]
        except (socket.gaierror, socket.herror, OSError):
            pass
        return None

    def _profile_host(self, host: str, ip: str) -> AssetProfile:
        """Build an AssetProfile for a discovered host."""
        cert_info = _check_certificate_age(host)
        # Try HTTPS first, then HTTP
        resp_headers = None
        status_code = None
        body = ""
        title = ""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            resp_headers, status_code, body, final_url = _make_request(url, self.timeout, headers=self._session_headers)
            if status_code is not None:
                break
        title = _extract_title(body)
        tech_stack = _detect_tech_stack(resp_headers, body)
        indicators = _assess_indicators(resp_headers, body, title, cert_info)
        asset_type = _classify_asset(resp_headers, body, title, cert_info)
        decay = _calculate_decay_from_indicators(indicators, resp_headers, cert_info)
        return AssetProfile(
            url=f"https://{host}/" if status_code else f"http://{host}/",
            asset_type=asset_type,
            status_code=status_code,
            decay_score=decay,
            indicators=indicators,
            last_modified=resp_headers.get("last-modified") if resp_headers else None,
            server_header=resp_headers.get("server") if resp_headers else None,
            title=title,
            cert_info=cert_info,
            tech_stack=tech_stack,
            discovered_by="dns_resolution",
        )

    # ---------------------------------------------------------------------
    # 2. Staging environments
    # ---------------------------------------------------------------------

    def discover_staging_environments(self, target: str) -> List[AssetProfile]:
        """
        Probe for staging / dev / test / UAT / CI environments using
        well-known subdomain prefixes.
        """
        found: List[AssetProfile] = []
        checked: set = set()

        for prefix in self.STAGING_PATTERNS:
            fqdn = f"{prefix}.{target}"
            if fqdn in checked:
                continue
            checked.add(fqdn)
            ip = self._resolve_host(fqdn)
            if ip:
                profile = self._profile_host(fqdn, ip)
                if profile.status_code is not None:
                    profile.discovered_by = "staging_subdomain"
                    profile.asset_type = "staging_environment"
                    found.append(profile)

        return found

    # ---------------------------------------------------------------------
    # 3. Abandoned infrastructure
    # ---------------------------------------------------------------------

    def discover_abandoned_infrastructure(self, base_url: str) -> List[AssetProfile]:
        """
        Check the base URL and common paths for signs of abandonment:
        old WordPress, default pages, expired certificates, outdated headers,
        missing HSTS, HTTP-only.
        """
        found: List[AssetProfile] = []
        parsed = urlparse(base_url)
        host = parsed.hostname or ""

        # Check the base URL itself
        profile = _probe_path(base_url, "/", self.timeout)
        if profile.status_code is not None:
            profile.discovered_by = "abandoned_infrastructure_scan"
            # Additional: check HTTP-only
            if parsed.scheme == "http":
                https_url = f"https://{host}/"
                _, https_status, _, _ = _make_request(https_url, self.timeout)
                if https_status is None or https_status >= 400:
                    if "http_only_no_redirect" not in profile.indicators:
                        profile.indicators.append("http_only_no_redirect")
                    profile.decay_score = _calculate_decay_from_indicators(
                        profile.indicators, None, profile.cert_info
                    )
                    # Re-evaluate risk level
                    if profile.decay_score >= 75:
                        profile.risk_level = "critical"
                    elif profile.decay_score >= 55:
                        profile.risk_level = "high"
                    elif profile.decay_score >= 35:
                        profile.risk_level = "medium"
                    elif profile.decay_score >= 15:
                        profile.risk_level = "low"
                    else:
                        profile.risk_level = "info"
            found.append(profile)

        # Probe common abandoned paths
        abandoned_paths = [
            "/", "/index.html", "/index.php", "/default.html",
            "/old/", "/archive/", "/backup/", "/legacy/", "/deprecated/",
            "/wordpress/wp-login.php", "/wp-login.php",
            "/wp-admin/", "/wp-admin/install.php",
            "/server-status", "/server-info",
            "/info.php", "/phpinfo.php", "/test.php",
            "/README.md", "/README.txt", "/CHANGELOG.md",
            "/.git/HEAD", "/.git/config", "/.svn/entries",
            "/.DS_Store", "/Thumbs.db",
            "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
        ]
        for path in abandoned_paths:
            if path == "/":
                continue  # already probed
            p = _probe_path(base_url, path, self.timeout)
            if p.status_code is not None and p.status_code < 400:
                p.discovered_by = "abandoned_infrastructure_scan"
                found.append(p)

        return found

    # ---------------------------------------------------------------------
    # 4. Shadow APIs
    # ---------------------------------------------------------------------

    def discover_shadow_apis(self, base_url: str) -> List[AssetProfile]:
        """
        Find undocumented / hidden APIs: common API paths, debug endpoints,
        Swagger/OpenAPI specs, GraphQL introspection.
        """
        found: List[AssetProfile] = []
        probed_urls: set = set()

        for path in self.SHADOW_API_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if url in probed_urls:
                continue
            probed_urls.add(url)
            resp_headers, status_code, body, final_url = _make_request(url, self.timeout, headers=self._session_headers)
            if status_code is None:
                continue
            # Skip 404s, focus on real hits
            if status_code == 404:
                continue
            cert_info = _check_certificate_age(urlparse(url).hostname or "")
            title = _extract_title(body or "")
            tech_stack = _detect_tech_stack(resp_headers, body or "")
            indicators = _assess_indicators(resp_headers, body or "", title, cert_info)
            asset_type = _classify_asset(resp_headers, body or "", title, cert_info)
            decay = _calculate_decay_from_indicators(indicators, resp_headers, cert_info)
            profile = AssetProfile(
                url=url,
                asset_type=asset_type,
                status_code=status_code,
                decay_score=decay,
                indicators=indicators,
                last_modified=resp_headers.get("last-modified") if resp_headers else None,
                server_header=resp_headers.get("server") if resp_headers else None,
                title=title,
                cert_info=cert_info,
                tech_stack=tech_stack,
                discovered_by="shadow_api_scan",
            )
            found.append(profile)

            # GraphQL introspection probe
            if "graphql" in path.lower() and status_code == 200:
                introspection = self._probe_graphql_introspection(url)
                if introspection:
                    profile.indicators.append("graphql_introspection_enabled")
                    profile.tech_stack.append("GraphQL (introspection open)")

            # Swagger schema extraction
            if status_code == 200 and body and ("swagger" in path.lower() or "openapi" in path.lower()):
                try:
                    schema = json.loads(body)
                    if schema.get("swagger") or schema.get("openapi"):
                        paths_count = len(schema.get("paths", {}))
                        profile.indicators.append(f"openapi_spec_exposed ({paths_count} endpoints)")
                        profile.tech_stack.append(f"OpenAPI ({paths_count} paths)")
                except (json.JSONDecodeError, TypeError):
                    pass

        return found

    def _probe_graphql_introspection(self, graphql_url: str) -> bool:
        """Send a GraphQL introspection query and check for a valid response."""
        introspection_query = {
            "query": """{
                __schema {
                    types {
                        name
                        kind
                        fields {
                            name
                        }
                    }
                }
            }"""
        }
        data = json.dumps(introspection_query).encode("utf-8")
        try:
            req = Request(
                graphql_url,
                data=data,
                headers={
                    **self._session_headers,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            resp = urlopen(req, timeout=self.timeout)
            body = resp.read(65536).decode("utf-8", errors="replace")
            result = json.loads(body)
            return "data" in result and "__schema" in result.get("data", {})
        except Exception:
            return False

    # ---------------------------------------------------------------------
    # 5. Orphaned DNS
    # ---------------------------------------------------------------------

    def discover_orphaned_dns(self, target: str) -> Dict[str, Any]:
        """
        Check for DNS records pointing to dead infrastructure, orphaned NS
        records, and stale MX records.
        """
        findings: Dict[str, Any] = {
            "target": target,
            "records": {},
            "assets": [],
        }

        # Resolve A / AAAA
        ipv4 = self._resolve_host(target)
        findings["records"]["A"] = ipv4

        # NS records
        ns_records = self._dns_lookup(target, "NS")
        findings["records"]["NS"] = ns_records

        # MX records
        mx_records = self._dns_lookup(target, "MX")
        findings["records"]["MX"] = mx_records

        # TXT records
        txt_records = self._dns_lookup(target, "TXT")
        findings["records"]["TXT"] = txt_records

        # CNAME records
        cname_records = self._dns_lookup(target, "CNAME")
        findings["records"]["CNAME"] = cname_records

        # Check for orphaned NS: NS records pointing to hosts that don't resolve
        orphaned_ns: List[str] = []
        for ns in ns_records:
            ns_host = ns.rstrip(".")
            if not self._resolve_host(ns_host):
                orphaned_ns.append(ns_host)
        findings["orphaned_ns"] = orphaned_ns

        # Check for stale MX: MX records pointing to unreachable hosts
        stale_mx: List[Dict[str, Any]] = []
        for mx in mx_records:
            mx_host = mx.rstrip(".")
            ip = self._resolve_host(mx_host)
            if ip:
                # Check if SMTP port is open
                smtp_open = self._check_port_open(mx_host, 25, timeout=4)
                if not smtp_open:
                    stale_mx.append({"host": mx_host, "ip": ip, "issue": "smtp_port_closed"})
            else:
                stale_mx.append({"host": mx_host, "ip": None, "issue": "unresolvable"})
        findings["stale_mx"] = stale_mx

        # Check for dangling CNAME
        dangling_cname: List[str] = []
        for cname in cname_records:
            cname_target = cname.rstrip(".")
            if not self._resolve_host(cname_target):
                dangling_cname.append(cname_target)
        findings["dangling_cname"] = dangling_cname

        # Build asset profiles for orphaned records
        for ns_host in orphaned_ns:
            profile = AssetProfile(
                url=f"dns://{ns_host}",
                asset_type="orphaned_ns",
                status_code=None,
                decay_score=70,
                indicators=["orphaned_ns_record"],
                discovered_by="dns_analysis",
            )
            findings["assets"].append(profile.to_dict())

        for mx_info in stale_mx:
            profile = AssetProfile(
                url=f"dns://{mx_info['host']}",
                asset_type="stale_mx",
                status_code=None,
                decay_score=60 if mx_info["issue"] == "smtp_port_closed" else 80,
                indicators=[f"stale_mx_{mx_info['issue']}"],
                discovered_by="dns_analysis",
            )
            findings["assets"].append(profile.to_dict())

        for cname_host in dangling_cname:
            profile = AssetProfile(
                url=f"dns://{cname_host}",
                asset_type="dangling_cname",
                status_code=None,
                decay_score=75,
                indicators=["dangling_cname_record"],
                discovered_by="dns_analysis",
            )
            findings["assets"].append(profile.to_dict())

        return findings

    def _dns_lookup(self, domain: str, record_type: str) -> List[str]:
        """Perform a DNS lookup using system resolver (dig fallback or getaddrinfo)."""
        results: List[str] = []
        if record_type in ("A", "AAAA"):
            try:
                family = socket.AF_INET if record_type == "A" else socket.AF_INET6
                addrs = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                for addr in addrs:
                    ip = addr[4][0]
                    if ip not in results:
                        results.append(ip)
            except (socket.gaierror, OSError):
                pass
            return results

        # For NS, MX, TXT, CNAME — try system dig/host commands
        try:
            cmd = ["dig", "+short", record_type, domain]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=8,
                stdin=subprocess.DEVNULL,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and line not in results:
                        results.append(line)
                return results
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        # Fallback: try host command
        try:
            cmd = ["host", "-t", record_type, domain]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=8,
                stdin=subprocess.DEVNULL,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().split("\n"):
                    line = line.strip()
                    # Extract the value from host output (typically after "is an alias for" or "mail is handled by")
                    parts = line.split()
                    if len(parts) >= 2:
                        value = parts[-1].rstrip(".")
                        if value and value not in results:
                            results.append(value + ".")
                return results
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return results

    def _check_port_open(self, host: str, port: int, timeout: int = 4) -> bool:
        """Check if a TCP port is open on a host."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, socket.gaierror, OSError):
            return False

    # ---------------------------------------------------------------------
    # 6. Forgotten services
    # ---------------------------------------------------------------------

    def discover_forgotten_services(self, base_url: str) -> List[AssetProfile]:
        """
        Check for services left running: phpMyAdmin, Jenkins, Grafana, Kibana,
        Redis Commander, pgAdmin, MongoDB Express, Solr admin, Tomcat manager.
        """
        found: List[AssetProfile] = []
        probed_urls: set = set()

        for path in self.FORGOTTEN_SERVICE_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if url in probed_urls:
                continue
            probed_urls.add(url)
            resp_headers, status_code, body, final_url = _make_request(url, self.timeout, headers=self._session_headers)
            if status_code is None or status_code == 404:
                continue
            # Focus on hits that look like real services (2xx, 3xx, 401, 403)
            if status_code not in (200, 201, 202, 301, 302, 303, 307, 308, 401, 403):
                continue
            cert_info = _check_certificate_age(urlparse(url).hostname or "")
            title = _extract_title(body or "")
            tech_stack = _detect_tech_stack(resp_headers, body or "")
            indicators = _assess_indicators(resp_headers, body or "", title, cert_info)
            asset_type = _classify_asset(resp_headers, body or "", title, cert_info)
            decay = _calculate_decay_from_indicators(indicators, resp_headers, cert_info)
            profile = AssetProfile(
                url=url,
                asset_type=asset_type,
                status_code=status_code,
                decay_score=decay,
                indicators=indicators,
                last_modified=resp_headers.get("last-modified") if resp_headers else None,
                server_header=resp_headers.get("server") if resp_headers else None,
                title=title,
                cert_info=cert_info,
                tech_stack=tech_stack,
                discovered_by="forgotten_services_scan",
            )
            found.append(profile)

        return found

    # ---------------------------------------------------------------------
    # 7. Cloud leaks
    # ---------------------------------------------------------------------

    def discover_cloud_leaks(self, base_url: str) -> List[AssetProfile]:
        """
        Probe for cloud storage / config exposure: AWS credentials, GCP service
        accounts, Azure app config, S3 bucket references, Firebase config,
        Supabase URL, and embedded secrets in page source.
        """
        found: List[AssetProfile] = []
        probed_urls: set = set()

        # Phase 1: Probe cloud-related paths
        for path in self.CLOUD_LEAK_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if url in probed_urls:
                continue
            probed_urls.add(url)
            resp_headers, status_code, body, final_url = _make_request(url, self.timeout, headers=self._session_headers)
            if status_code is None or status_code == 404:
                continue
            cert_info = _check_certificate_age(urlparse(url).hostname or "")
            title = _extract_title(body or "")
            tech_stack = _detect_tech_stack(resp_headers, body or "")
            indicators = _assess_indicators(resp_headers, body or "", title, cert_info)
            asset_type = _classify_asset(resp_headers, body or "", title, cert_info)

            # Check for credential patterns in the body
            credential_hits = self._scan_for_credentials(body or "")
            for hit in credential_hits:
                if hit not in indicators:
                    indicators.append(hit)
                if asset_type == "web_application":
                    asset_type = "cloud_credentials"

            decay = _calculate_decay_from_indicators(indicators, resp_headers, cert_info)
            # Cloud leaks are inherently high risk
            if credential_hits:
                decay = max(decay, 80)

            profile = AssetProfile(
                url=url,
                asset_type=asset_type,
                status_code=status_code,
                decay_score=decay,
                indicators=indicators,
                last_modified=resp_headers.get("last-modified") if resp_headers else None,
                server_header=resp_headers.get("server") if resp_headers else None,
                title=title,
                cert_info=cert_info,
                tech_stack=tech_stack,
                discovered_by="cloud_leak_scan",
            )
            found.append(profile)

        # Phase 2: Scan the main page for leaked credentials in JS/HTML
        resp_headers, status_code, body, _ = _make_request(base_url, self.timeout, headers=self._session_headers)
        if body and status_code in (200, 301, 302):
            credential_hits = self._scan_for_credentials(body)
            if credential_hits:
                cert_info = _check_certificate_age(urlparse(base_url).hostname or "")
                title = _extract_title(body)
                profile = AssetProfile(
                    url=base_url,
                    asset_type="cloud_credentials",
                    status_code=status_code,
                    decay_score=max(80, len(credential_hits) * 15),
                    indicators=credential_hits[:10],
                    title=title,
                    cert_info=cert_info,
                    discovered_by="cloud_leak_body_scan",
                )
                found.append(profile)

        return found

    def _scan_for_credentials(self, body: str) -> List[str]:
        """Scan response body for known credential/secret patterns."""
        hits: List[str] = []
        seen_types: set = set()
        for pattern in self.CLOUD_CREDENTIAL_PATTERNS:
            matches = pattern.findall(body)
            if matches:
                # Determine credential type from pattern
                match_str = matches[0][:20]  # truncated for safety
                # Classify the type
                for label, detect_pat in [
                    ("aws_access_key_detected", re.compile(r'AKIA')),
                    ("gcp_service_account_detected", re.compile(r'"type"\s*:\s*"service_account"')),
                    ("firebase_api_key_detected", re.compile(r'AIza')),
                    ("google_oauth_detected", re.compile(r'ya29\\.')),
                    ("slack_token_detected", re.compile(r'xox[bpras]-')),
                    ("github_pat_detected", re.compile(r'ghp_')),
                    ("github_oauth_detected", re.compile(r'gho_')),
                    ("gitlab_pat_detected", re.compile(r'glpat-')),
                    ("jwt_token_detected", re.compile(r'^eyJ', re.M)),
                    ("private_key_detected", re.compile(r'BEGIN.*PRIVATE KEY')),
                    ("stripe_key_detected", re.compile(r'sk_live_')),
                    ("azure_secret_detected", re.compile(r'AZURE_CLIENT_SECRET')),
                    ("supabase_url_detected", re.compile(r'supabase\\.co')),
                    ("mongodb_uri_detected", re.compile(r'mongodb://')),
                    ("postgres_uri_detected", re.compile(r'postgres://')),
                    ("redis_uri_detected", re.compile(r'redis://')),
                    ("amqp_uri_detected", re.compile(r'amqp://')),
                    ("mysql_uri_detected", re.compile(r'mysql://')),
                    ("openai_key_detected", re.compile(r'sk-[0-9a-zA-Z]{48}')),
                ]:
                    if detect_pat.search(body) and label not in seen_types:
                        hits.append(label)
                        seen_types.add(label)
        return hits

    # ---------------------------------------------------------------------
    # 8. Internal exposure
    # ---------------------------------------------------------------------

    def discover_internal_exposure(self, base_url: str) -> List[AssetProfile]:
        """
        Find accidentally exposed internal tools: internal dashboards, monitoring
        panels, error tracking (Sentry), logging (ELK), CI/CD dashboards.
        """
        found: List[AssetProfile] = []
        probed_urls: set = set()

        for path in self.INTERNAL_EXPOSURE_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if url in probed_urls:
                continue
            probed_urls.add(url)
            resp_headers, status_code, body, final_url = _make_request(url, self.timeout, headers=self._session_headers)
            if status_code is None or status_code == 404:
                continue
            if status_code not in (200, 201, 202, 301, 302, 303, 307, 308, 401, 403):
                continue
            cert_info = _check_certificate_age(urlparse(url).hostname or "")
            title = _extract_title(body or "")
            tech_stack = _detect_tech_stack(resp_headers, body or "")
            indicators = _assess_indicators(resp_headers, body or "", title, cert_info)
            asset_type = _classify_asset(resp_headers, body or "", title, cert_info)
            decay = _calculate_decay_from_indicators(indicators, resp_headers, cert_info)

            # Internal tools exposed publicly are high risk regardless of decay
            if status_code in (200, 401, 403):
                decay = max(decay, 50)
                if asset_type == "web_application":
                    # Try to infer internal tool type from path/title
                    bl = (body or "").lower()
                    tl = title.lower()
                    if any(kw in bl or kw in tl for kw in ["monitoring", "grafana", "kibana", "prometheus", "alert"]):
                        asset_type = "monitoring_exposed"
                        indicators.append("internal_monitoring_exposed")
                        decay = max(decay, 70)
                    elif any(kw in bl or kw in tl for kw in ["jenkins", "gitlab", "ci", "pipeline", "build"]):
                        asset_type = "cicd_exposed"
                        indicators.append("internal_cicd_exposed")
                        decay = max(decay, 70)
                    elif any(kw in bl or kw in tl for kw in ["sentry", "rollbar", "bugsnag", "datadog", "newrelic"]):
                        asset_type = "error_tracking_exposed"
                        indicators.append("internal_error_tracking_exposed")
                        decay = max(decay, 60)
                    elif any(kw in bl or kw in tl for kw in ["admin", "dashboard", "backoffice", "intranet"]):
                        asset_type = "internal_dashboard_exposed"
                        indicators.append("internal_dashboard_exposed")
                        decay = max(decay, 65)
                    elif any(kw in bl or kw in tl for kw in ["log", "elk", "elasticsearch", "logstash"]):
                        asset_type = "logging_exposed"
                        indicators.append("internal_logging_exposed")
                        decay = max(decay, 65)

            profile = AssetProfile(
                url=url,
                asset_type=asset_type,
                status_code=status_code,
                decay_score=min(decay, 100),
                indicators=indicators,
                last_modified=resp_headers.get("last-modified") if resp_headers else None,
                server_header=resp_headers.get("server") if resp_headers else None,
                title=title,
                cert_info=cert_info,
                tech_stack=tech_stack,
                discovered_by="internal_exposure_scan",
            )
            found.append(profile)

        return found

    # ---------------------------------------------------------------------
    # Decay scoring
    # ---------------------------------------------------------------------

    # DEAD CODE: consider removal
    def calculate_decay_score(self, asset_info: Dict[str, Any]) -> int:
        """
        Calculate how "abandoned" an asset is on a 0-100 scale.

        Factors:
        - Certificate expiry proximity (expired = +25, near expiry = +12)
        - Outdated server headers (+15)
        - Default content pages (+20)
        - Missing security headers (HSTS, CSP) (+5 each)
        - HTTP-only with no redirect (+8)
        - No robots.txt (+3), no favicon (+3)
        - Old WordPress version signatures (+18)
        - Outdated JS libraries (jQuery 1.x, Bootstrap 3.x) (+10)
        - Visible PHP errors (+15)
        - Stack traces exposed (+20)
        - Debug mode indicators (+18)
        - Directory listings (+18)
        - Self-signed certificates (+15)
        - Certificate age > 1 year (+5), > 2 years (+8)
        - No Last-Modified header (+2)

        :param asset_info: Dictionary with keys like ``headers``, ``body``,
            ``title``, ``cert_info``, ``status_code``.
        :returns: Integer 0-100 where 100 means fully abandoned/decayed.
        """
        headers = asset_info.get("headers") or {}
        body = asset_info.get("body", "")
        title = asset_info.get("title", "")
        cert_info = asset_info.get("cert_info")
        status_code = asset_info.get("status_code")

        indicators = _assess_indicators(headers, body, title, cert_info)
        score = _calculate_decay_from_indicators(indicators, headers, cert_info)

        # Additional: check for HTTP-only
        if asset_info.get("http_only") and not asset_info.get("has_https_redirect"):
            score += 8

        # Check for no robots.txt
        if asset_info.get("no_robots_txt"):
            score += 3

        # High status codes suggest degradation
        if status_code and status_code >= 500:
            score += 10
        elif status_code and status_code == 403:
            score += 5

        return min(score, 100)


# ---------------------------------------------------------------------------
# Convenience entry-point
# ---------------------------------------------------------------------------

# DEAD CODE: consider removal
def quick_scan(target: str, base_url: Optional[str] = None, timeout: int = 8) -> Dict[str, Any]:
    """
    Convenience function: run a full shadow IT scan with minimal setup.

    >>> from reconpro.shadow_it import quick_scan
    >>> results = quick_scan("example.com")
    """
    if base_url is None:
        base_url = f"https://{target}"
    scanner = ShadowITScanner(timeout=timeout)
    return scanner.scan(target, base_url, timeout)

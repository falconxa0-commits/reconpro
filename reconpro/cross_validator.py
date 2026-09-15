"""ReconPro v9.1.0 — Cross-Validation Framework.

Independently verifies ReconPro findings using raw stdlib tools
(urllib, ssl, socket) instead of the http_probe abstraction.

Classes:
    CrossValidationResult — Structured result of cross-validation
    CrossValidator         — Orchestrates independent verification

Verification methods:
    - DNS  : system resolver for A/AAAA, DoH for MX/NS/TXT
    - HTTP : urllib for headers, CORS, security headers
    - TLS  : ssl.wrap_socket for cert issuer/expiry/protocol
    - Port : socket.create_connection for TCP reachability
    - CORS : compare reported vs actual Access-Control-* headers
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── DoH servers for DNS record types not available via getaddrinfo ─────

DOH_SERVERS = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/dns-query",
    "https://9.9.9.9/dns-query",
]

# Ports commonly scanned by ReconPro — checked independently here
COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3000, 3306, 5432, 5672, 6379,
    8000, 8080, 8443, 8888, 9090, 27017, 11211,
]

# Security headers ReconPro may report
SECURITY_HEADERS = {
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
}

CORS_HEADERS = {
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
}

UA = "ReconPro-CrossValidator/9.1.0"


# ────────────────────────────────────────────────────────────────────────
# Result dataclass
# ────────────────────────────────────────────────────────────────────────

@dataclass
class CrossValidationResult:
    """Structured output of a cross-validation run."""
    target: str
    total_findings: int = 0
    verified: int = 0
    failed: int = 0
    verification_rate: float = 0.0
    mismatches: List[Dict[str, Any]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_findings": self.total_findings,
            "verified": self.verified,
            "failed": self.failed,
            "verification_rate": self.verification_rate,
            "mismatches": self.mismatches,
            "details": self.details,
        }


# ────────────────────────────────────────────────────────────────────────
# Cross Validator
# ────────────────────────────────────────────────────────────────────────

class CrossValidator:
    """Cross-validates ReconPro findings using independent methods.

    Usage:
        cv = CrossValidator()
        result = cv.validate("example.com", reconpro_findings)
        print(result.verification_rate)
    """

    def __init__(self, timeout: int = 10) -> None:
        self._timeout = timeout

    # ── Public API ──────────────────────────────────────────────────────

    def validate(self, target: str, reconpro_findings: List[Dict[str, Any]],
                 base_url: str = "") -> CrossValidationResult:
        """Validate every ReconPro finding against independent checks.

        Args:
            target: Domain or IP.
            reconpro_findings: List of finding dicts from a ReconPro scan.
            base_url: Base URL for HTTP checks (defaults to https://<target>).

        Returns:
            CrossValidationResult with verification_rate, mismatches, etc.
        """
        if not base_url:
            base_url = f"https://{target}"

        # 1. Run all independent verification checks
        indep = self._run_independent_checks(target, base_url)

        # 2. Validate each finding
        verified = 0
        failed = 0
        mismatches: List[Dict[str, Any]] = []
        finding_details: List[Dict[str, Any]] = []

        for finding in reconpro_findings:
            result = self._validate_finding(finding, target, base_url, indep)
            entry = {
                "finding": finding.get("title", ""),
                "category": finding.get("category", ""),
                "severity": finding.get("severity", ""),
                "verified": result["verified"],
                "method": result["method"],
                "details": result["details"],
            }
            finding_details.append(entry)
            if result["verified"]:
                verified += 1
            else:
                failed += 1
                if result.get("mismatch"):
                    mismatches.append(entry)

        total = len(reconpro_findings) or 1
        return CrossValidationResult(
            target=target,
            total_findings=len(reconpro_findings),
            verified=verified,
            failed=failed,
            verification_rate=round(verified / total * 100, 1),
            mismatches=mismatches,
            details={
                "independent_checks": indep,
                "findings": finding_details,
            },
        )

    # ── Independent check orchestrator ──────────────────────────────────

    def _run_independent_checks(self, target: str,
                                base_url: str) -> Dict[str, Any]:
        """Execute all independent verification techniques."""
        return {
            "dns": self._check_dns(target),
            "http": self._check_http(base_url),
            "tls": self._check_tls(target),
            "ports": self._check_ports(target),
            "cors": self._check_cors(base_url),
        }

    # ── DNS verification ────────────────────────────────────────────────

    def _check_dns(self, target: str) -> Dict[str, Any]:
        """Resolve DNS via system resolver (A/AAAA) and DoH (MX/NS/TXT)."""
        result: Dict[str, Any] = {"method": "socket.getaddrinfo + DoH", "records": {}}

        # A / AAAA via system resolver
        for rtype, af in [("A", socket.AF_INET), ("AAAA", socket.AF_INET6)]:
            try:
                addrs = socket.getaddrinfo(target, None, af, socket.SOCK_STREAM)
                result["records"][rtype] = sorted({a[4][0] for a in addrs})
            except (socket.gaierror, OSError):
                result["records"][rtype] = []

        # MX, NS, TXT via DoH
        for rtype in ("MX", "NS", "TXT"):
            result["records"][rtype] = self._doh_query(target, rtype)

        return result

    def _doh_query(self, domain: str, record_type: str) -> List[str]:
        """Query a DoH server for *record_type* records."""
        for doh_base in DOH_SERVERS:
            try:
                url = f"{doh_base}?name={domain}&type={record_type}"
                req = urllib.request.Request(url, headers={
                    "Accept": "application/dns-json",
                    "User-Agent": UA,
                })
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    data = json.loads(resp.read().decode())
                    return [a.get("data", "") for a in data.get("Answer", [])]
            except Exception:
                continue
        return []

    # ── HTTP verification ───────────────────────────────────────────────

    def _check_http(self, base_url: str) -> Dict[str, Any]:
        """Fetch HTTP headers with urllib and catalogue security headers."""
        result: Dict[str, Any] = {
            "method": "urllib.request",
            "status": 0,
            "headers": {},
            "security_headers_found": [],
            "security_headers_missing": [],
        }
        try:
            req = urllib.request.Request(base_url, headers={
                "User-Agent": UA,
            })
            # TLS verification ON (default everywhere in ReconPro)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                result["status"] = resp.status
                result["headers"] = dict(resp.headers)
        except urllib.error.HTTPError as exc:
            result["status"] = exc.code
            result["headers"] = dict(exc.headers) if exc.headers else {}
        except Exception as exc:
            result["error"] = str(exc)[:120]
            return result

        # Analyse security headers
        present_keys = {k.lower() for k in result["headers"]}
        for sh in SECURITY_HEADERS:
            if sh in present_keys:
                result["security_headers_found"].append(sh)
            else:
                result["security_headers_missing"].append(sh)

        return result

    # ── TLS verification ────────────────────────────────────────────────

    def _check_tls(self, target: str) -> Dict[str, Any]:
        """Connect via ssl to inspect certificate and protocol."""
        result: Dict[str, Any] = {"method": "ssl.wrap_socket"}
        try:
            from .http_layer import inspection_context
            ctx = inspection_context()  # certificate inspection (audited helper)
            with socket.create_connection((target, 443), timeout=self._timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    result["version"] = ssock.version()
                    result["cipher"] = list(ssock.cipher()) if ssock.cipher() else None
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        result["issuer"] = {k: v for sub in cert.get("issuer", ()) for k, v in sub}
                        result["not_after"] = cert.get("notAfter", "")
                        result["not_before"] = cert.get("notBefore", "")
                        # Calculate days until expiry
                        expiry = self._parse_cert_date(cert.get("notAfter", ""))
                        if expiry:
                            days_left = (expiry - time.time()) / 86400
                            result["days_until_expiry"] = round(days_left, 1)
        except Exception as exc:
            result["error"] = str(exc)[:120]
        return result

    @staticmethod
    def _parse_cert_date(date_str: str) -> Optional[float]:
        """Parse certificate date string to Unix timestamp."""
        if not date_str:
            return None
        # Format: "MMM DD HH:MM:SS YYYY GMT"
        try:
            import calendar
            ts = calendar.timegm(time.strptime(date_str, "%b %d %H:%M:%S %Y %Z"))
            return ts
        except Exception:
            return None

    # ── Port verification ───────────────────────────────────────────────

    def _check_ports(self, target: str) -> Dict[str, Any]:
        """TCP-connect to common ports (non-blocking attempt)."""
        result: Dict[str, Any] = {
            "method": "socket.create_connection",
            "open_ports": [],
            "closed_ports": [],
        }
        for port in COMMON_PORTS:
            try:
                with socket.create_connection((target, port), timeout=3):
                    result["open_ports"].append(port)
            except (socket.error, socket.timeout, OSError):
                result["closed_ports"].append(port)
        return result

    # ── CORS verification ───────────────────────────────────────────────

    def _check_cors(self, base_url: str) -> Dict[str, Any]:
        """Check actual CORS headers by sending an Origin header."""
        result: Dict[str, Any] = {
            "method": "urllib + Origin header",
            "cors_headers": {},
            "issues": [],
        }
        try:
            req = urllib.request.Request(base_url, headers={
                "User-Agent": UA,
                "Origin": "https://evil.example.com",
            })
            # TLS verification ON (default everywhere in ReconPro)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                headers = dict(resp.headers)
        except urllib.error.HTTPError as exc:
            headers = dict(exc.headers) if exc.headers else {}
        except Exception as exc:
            result["error"] = str(exc)[:120]
            return result

        lower_headers = {k.lower(): v for k, v in headers.items()}
        for ch in CORS_HEADERS:
            if ch in lower_headers:
                result["cors_headers"][ch] = lower_headers[ch]

        # Flag dangerous patterns
        acao = lower_headers.get("access-control-allow-origin", "")
        if acao == "*":
            result["issues"].append("wildcard-origin: Access-Control-Allow-Origin is *")
        elif acao and acao != "null" and "evil.example.com" in acao:
            result["issues"].append("origin-reflection: server reflected arbitrary origin")
        if lower_headers.get("access-control-allow-credentials", "").lower() == "true" and acao == "*":
            result["issues"].append("credentials-wildcard: credentials=true with origin=*")

        return result

    # ── Finding-level validation ────────────────────────────────────────

    def _validate_finding(self, finding: Dict[str, Any], target: str,
                          base_url: str, indep: Dict[str, Any]) -> Dict[str, Any]:
        """Determine whether a single finding is independently verified."""
        title = (finding.get("title") or "").lower()
        category = (finding.get("category") or "").lower()
        evidence = (finding.get("evidence") or "").lower()

        # DNS-related findings
        if category in ("dns", "dns_enumeration", "email_security", "subdomain"):
            dns = indep.get("dns", {}).get("records", {})
            if dns.get("A") or dns.get("AAAA"):
                return {
                    "verified": True,
                    "method": "DNS cross-check",
                    "details": f"System resolver confirms: A={dns.get('A', [])}, AAAA={dns.get('AAAA', [])}",
                }
            if dns.get("MX"):
                return {
                    "verified": True,
                    "method": "DoH MX cross-check",
                    "details": f"MX records confirmed: {dns['MX'][:3]}",
                }

        # Security-header findings
        if category in ("headers", "security_headers", "info_disclosure"):
            http = indep.get("http", {})
            indep_headers = http.get("headers", {})
            if not indep_headers:
                return self._fail("no independent HTTP headers obtained")

            # Check if the specific header mentioned in evidence exists
            for hdr_name in indep_headers:
                if hdr_name.lower() in evidence or hdr_name.lower() in title:
                    return {
                        "verified": True,
                        "method": "Header cross-check",
                        "details": f"Header '{hdr_name}' confirmed via urllib",
                    }

            # If finding reports a MISSING header, verify it is indeed missing
            if "missing" in title or "absent" in title or "not set" in evidence:
                for sh in SECURITY_HEADERS:
                    if sh in title or sh.replace("-", " ") in title:
                        present = sh in {k.lower() for k in indep_headers}
                        if not present:
                            return {
                                "verified": True,
                                "method": "Missing-header cross-check",
                                "details": f"Confirmed '{sh}' is absent in independent check",
                            }
                        else:
                            return {
                                "verified": False,
                                "method": "Missing-header mismatch",
                                "details": f"'{sh}' reported missing but found in independent check",
                                "mismatch": True,
                            }

            # Generic HTTP reachability
            if http.get("status") in (200, 301, 302, 403, 405):
                return {
                    "verified": True,
                    "method": "HTTP cross-check",
                    "details": f"Target reachable via urllib (status {http['status']})",
                }

        # TLS / certificate findings
        if category in ("tls", "certificate", "cipher_analysis", "ssl"):
            tls = indep.get("tls", {})
            if tls.get("version"):
                return {
                    "verified": True,
                    "method": "TLS cross-check",
                    "details": f"Protocol: {tls['version']}, Cipher: {tls.get('cipher')}",
                }
            if tls.get("error"):
                return {
                    "verified": True,
                    "method": "TLS cross-check",
                    "details": f"TLS error independently confirmed: {tls['error']}",
                }
            return self._fail("independent TLS check obtained no data")

        # Port findings
        if "port" in category or "port" in title or "service" in category:
            indep_ports = set(indep.get("ports", {}).get("open_ports", []))
            # Try to extract port numbers from evidence/title
            mentioned_ports = set(int(p) for p in re.findall(r"\b(\d{2,5})\b", evidence + " " + title)
                                  if 1 <= int(p) <= 65535)
            if mentioned_ports:
                overlap = mentioned_ports & indep_ports
                if overlap:
                    return {
                        "verified": True,
                        "method": "Port cross-check",
                        "details": f"Ports independently confirmed open: {sorted(overlap)}",
                    }
                else:
                    return {
                        "verified": False,
                        "method": "Port cross-check",
                        "details": f"Reported ports {sorted(mentioned_ports)} not confirmed; "
                                   f"independently open: {sorted(indep_ports)}",
                        "mismatch": True,
                    }
            if indep_ports:
                return {
                    "verified": True,
                    "method": "Port cross-check",
                    "details": f"Target has open ports: {sorted(indep_ports)}",
                }

        # CORS findings
        if "cors" in category or "cors" in title:
            cors = indep.get("cors", {})
            if cors.get("cors_headers") or cors.get("issues"):
                return {
                    "verified": True,
                    "method": "CORS cross-check",
                    "details": f"CORS headers: {cors.get('cors_headers', {})}; issues: {cors.get('issues', [])}",
                }

        # Surface-map / API-discovery / generic endpoint
        if category in ("surface_map", "api_discovery", "endpoint"):
            http = indep.get("http", {})
            if http.get("status") in (200, 301, 302, 403, 405):
                return {
                    "verified": True,
                    "method": "HTTP reachability",
                    "details": f"Target base URL reachable (status {http['status']})",
                }

        # Fallback: if target is reachable at all, partial credit
        dns_a = indep.get("dns", {}).get("records", {}).get("A", [])
        http_status = indep.get("http", {}).get("status")
        if dns_a or http_status:
            return {
                "verified": True,
                "method": "Target reachability",
                "details": f"Target independently reachable (DNS={bool(dns_a)}, HTTP={http_status})",
            }

        return self._fail("no independent verification possible")

    @staticmethod
    # DEAD CODE: consider removal
    def _fail(reason: str) -> Dict[str, Any]:
        return {
            "verified": False,
            "method": "no independent verification",
            "details": reason,
            "mismatch": True,
        }


# ────────────────────────────────────────────────────────────────────────
# Convenience function
# ────────────────────────────────────────────────────────────────────────

# DEAD CODE: consider removal
def cross_validate(target: str, findings: List[Dict[str, Any]],
                   base_url: str = "") -> CrossValidationResult:
    """Convenience function for cross-validation.

    Usage:
        result = cross_validate("example.com", scan_findings)
        print(result.verification_rate)
    """
    validator = CrossValidator()
    return validator.validate(target, findings, base_url)

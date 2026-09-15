from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set
from ..http_layer import http_probe, Finding


def _follow_redirects(base_url: str, max_hops: int = 15, timeout: int = 8,
                       verify_tls: bool = True) -> List[Dict[str, Any]]:
    """Follow HTTP redirect chains and record each hop."""
    chain = []
    url = base_url
    visited: Set[str] = set()

    for _ in range(max_hops):
        if url in visited:
            break
        visited.add(url)

        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        headers = resp.get("headers", {})
        location = headers.get("location", "")

        chain.append({
            "url": url,
            "status": status,
            "location": location,
            "headers": {k: v for k, v in headers.items()
                       if k.lower().startswith(("x-", "server", "cf-"))},
        })

        if status not in (301, 302, 303, 307, 308) or not location:
            break

        # Resolve relative URLs
        if location.startswith("/"):
            from urllib.parse import urljoin
            location = urljoin(url, location)
        elif not location.startswith("http"):
            location = urljoin(url, location)
        url = location

    return chain


def _check_ssrf(base_url: str, timeout: int = 8, verify_tls: bool = True) -> List[Finding]:
    """Check for SSRF via parameter injection."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    ssrf_params = [
        "url", "uri", "redirect", "next", "returnTo", "return_url",
        "callback", "continue", "target", "dest", "destination",
        "route", "path", "forward",
    ]

    ssrf_payloads = [
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/instance?api-version=2021-02-01",
        "http://localhost:8080",
        "http://[::1]",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    ssrf_endpoints = [
        "/api/fetch", "/api/proxy", "/api/preview",
        "/api/redirect", "/api/webhook", "/api/url",
        "/api/callback", "/api/forward",
    ]

    import urllib.parse

    for endpoint in ssrf_endpoints:
        url = base_url.rstrip("/") + endpoint
        for param in ssrf_params:
            for payload in ssrf_payloads:
                try:
                    encoded = urllib.parse.urlencode({param: payload})
                    full_url = f"{url}?{encoded}"
                    resp = http_probe(full_url, timeout=timeout, verify_tls=verify_tls)
                    body = resp.get("body", "")[:4096]
                    status = resp.get("status", 0)

                    if status == 200 and len(body) > 20:
                        internal_sigs = [
                            "ami-id", "instance-id", "root:",
                            "127.0.0.1", "localhost", "meta-data",
                            "computeMetadata", "metadata/v1",
                            "redis_version", "redis",
                        ]
                        if any(sig in body.lower() for sig in internal_sigs):
                            findings.append(Finding(
                                title=f"SSRF via {endpoint}?{param}",
                                severity="critical", category="ssrf",
                                module="chain",
                                description="Server-side request forgery: {} reflects internal content".format(endpoint),
                                evidence="Payload: {} via param {}, internal data in response".format(payload, param),
                                asset=host, points_deducted=15,
                                remediation="Validate and sanitize all URL inputs. Block internal IP ranges.",
                            ))
                            break
                except Exception:
                    pass
            else:
                continue
            break

    # DNS rebinding check
    try:
        import socket
        results = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(set(addr[4][0] for addr in results))
        if len(ips) >= 2:
            findings.append(Finding(
                title="Potential DNS rebinding susceptibility",
                severity="medium", category="ssrf",
                module="chain",
                description="Host resolves to multiple A records ({}), which may enable DNS rebinding attacks".format(
                    "; ".join(ips[:4])),
                evidence="A records: {}".format("; ".join(ips[:4])),
                asset=host, points_deducted=8,
                remediation="Ensure application-level IP validation after DNS resolution to prevent DNS rebinding.",
            ))
    except Exception:
        pass

    return findings


def _check_open_redirect(base_url: str, timeout: int = 8, verify_tls: bool = True) -> List[Finding]:
    """Check for open redirect vulnerabilities."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    redirect_endpoints = ["/login", "/auth/login", "/redirect", "/logout",
                         "/api/redirect", "/callback", "/auth/callback"]
    evil_targets = [
        "https://evil-attacker.com",
        "//evil-attacker.com",
        "\\\\evil-attacker.com",
        "https://evil-attacker.com@" + host,
    ]

    for endpoint in redirect_endpoints:
        url = base_url.rstrip("/") + endpoint
        for evil in evil_targets:
            try:
                import urllib.parse
                full_url = f"{url}?next={urllib.parse.quote(evil)}&redirect={urllib.parse.quote(evil)}&url={urllib.parse.quote(evil)}&returnTo={urllib.parse.quote(evil)}"
                resp = http_probe(full_url, timeout=timeout, verify_tls=verify_tls)
                location = resp.get("headers", {}).get("location", "")

                if "evil-attacker" in location:
                    findings.append(Finding(
                        title=f"Open redirect: {endpoint}",
                        severity="high", category="open_redirect",
                        module="chain",
                        description=f"Unvalidated redirect: {endpoint} redirects to attacker-controlled URL",
                        evidence=f"Location: {location}",
                        asset=host, points_deducted=10,
                        remediation="Whitelist allowed redirect destinations.",
                    ))
                    break
            except Exception:
                pass

    return findings


def run_chain(target: str, base_url: str, timeout: int = 8,
              verify_tls: bool = True) -> List[Finding]:
    """SSRF + redirect chain hunting with cross-validation. Returns list of Findings.

    v9.1.0: After chain analysis, optionally cross-validates DNS/HTTP/TLS findings
    using independent verification from the CrossValidator module.
    """
    findings: List[Finding] = []
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    # Follow redirect chains
    chain = _follow_redirects(base_url, timeout=timeout, verify_tls=verify_tls)
    if len(chain) > 3:
        from ..http_layer import Finding as F
        findings.append(F(
            title=f"Long redirect chain ({len(chain)} hops)",
            severity="medium", category="redirect_chain",
            module="chain",
            description=f"URL redirects through {len(chain)} intermediate hosts — potential data leakage",
            evidence=" -> ".join(f"{h['status']} {h['url'][:60]}" for h in chain[:5]),
            asset=host, points_deducted=5,
            remediation="Minimize redirect chains. Each hop is a potential attack surface.",
        ))

    # Check for redirect to HTTP (TLS downgrade)
    for hop in chain:
        loc = hop.get("location", "")
        if loc.startswith("http://") and base_url.startswith("https://"):
            findings.append(Finding(
                title="TLS downgrade via redirect",
                severity="high", category="redirect_chain",
                module="chain",
                description="HTTPS redirects to HTTP — TLS protection stripped",
                evidence=f"Redirect to: {loc[:80]}",
                asset=host, points_deducted=10,
                remediation="Never redirect from HTTPS to HTTP.",
            ))
            break

    # SSRF checks
    findings.extend(_check_ssrf(base_url, timeout=timeout, verify_tls=verify_tls))

    # Open redirect checks
    findings.extend(_check_open_redirect(base_url, timeout=timeout, verify_tls=verify_tls))

    # v9.1.0: Cross-validate findings with independent verification
    try:
        from ..cross_validator import CrossValidator
        cv = CrossValidator()
        findings_dicts = [f.to_dict() for f in findings]
        cv_results = cv.validate(host, findings_dicts, base_url=base_url)
        if cv_results and cv_results.total_findings > 0:
            total = cv_results.total_findings
            confirmed = cv_results.verified
            disputed = cv_results.failed
            rate = cv_results.verification_rate
            # Report cross-validation summary
            sev = "info"
            pts = 0
            if disputed > 0:
                sev = "medium"
                pts = 3
                desc = ("Cross-validation: {}/{} confirmed, {}/{} disputed ({:.0f}% rate). "
                        "Disputed findings may be false positives — manual review recommended.".format(
                            confirmed, total, disputed, total, rate * 100))
            else:
                desc = ("Cross-validation: {}/{} findings independently confirmed, "
                        "0 disputed ({:.0f}% rate). Results are reliable.".format(confirmed, total, rate * 100))
            findings.append(Finding(
                title="Cross-validation: {}/{} confirmed".format(confirmed, total),
                severity=sev, category="cross_validation",
                module="chain",
                description=desc,
                evidence="Confirmed: {}, Disputed: {}, Rate: {:.0f}%".format(
                    confirmed, disputed, rate * 100),
                asset=host, points_deducted=pts,
                remediation="Review disputed findings manually. Confirmed findings are reliable.",
            ))
            # Add individual mismatch notices
            for mm in cv_results.mismatches:
                findings.append(Finding(
                    title="Disputed: {}".format(mm.get("title", mm.get("original_title", "unknown"))),
                    severity="low", category="cross_validation",
                    module="chain",
                    description="Cross-validation disputes this finding: {}".format(
                        mm.get("reason", "Independent verification failed")),
                    evidence="Check: {} = {}".format(mm.get("check", mm.get("check_type", "?"))),
                    asset=host, points_deducted=0,
                    remediation="Manual verification recommended for this finding.",
                ))
    except Exception:
        pass  # Cross-validation is supplementary; don't fail the scan

    # v9.2.0: Infrastructure drift detection
    try:
        from ..drift_monitor import InfrastructureDriftMonitor
        dm = InfrastructureDriftMonitor()
        drift_result = dm.detect_drift(host, base_url, timeout=min(timeout, 5))
        drift_events = drift_result.get("drift_events", [])
        drift_risk = drift_result.get("drift_risk_score", 0)
        if drift_events:
            sev = "high" if drift_risk >= 60 else "medium" if drift_risk >= 30 else "low"
            findings.append(Finding(
                title="Infrastructure drift: {} changes detected (risk {})".format(
                    len(drift_events), drift_risk),
                severity=sev, category="infrastructure_drift",
                module="chain",
                description="Infrastructure changes detected since last scan: {}".format(
                    ", ".join(e.get("field_changed", "?") for e in drift_events[:5])),
                evidence="Risk score: {}, Changes: {}".format(
                    drift_risk, ", ".join(e.get("severity", "?") for e in drift_events[:5])),
                asset=host, points_deducted=int(drift_risk / 10),
                remediation="Review infrastructure changes. Unauthorized drift may indicate compromise.",
            ))
    except Exception:
        pass

    return findings

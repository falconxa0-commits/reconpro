from __future__ import annotations

import json
import re
from typing import Any, Dict, List
from ..http_layer import http_probe, Finding


# Cloud provider metadata endpoints
CLOUD_METADATA = {
    "AWS": [
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "IAM role credentials"),
        ("http://169.254.169.254/latest/meta-data/instance-id/", "Instance ID"),
        ("http://169.254.169.254/latest/user-data/", "User data (may contain secrets)"),
    ],
    "GCP": [
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata (X-Goog-Metadata-Request header needed)"),
    ],
    "Azure": [
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure instance metadata"),
    ],
}

# Common NHI-related paths and tokens
NHI_PATHS = [
    "/.aws/credentials", "/.aws/config",
    "/.kube/config", "/.config/gcloud/application_default_credentials.json",
    "/.azure/credentials", "/.azure/accessTokens.json",
    "/app/credentials.json", "/secrets/service-account.json",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/etc/kubernetes/admin.conf",
]

# OAuth/service token patterns in responses
TOKEN_PATTERNS = [
    (r'ya29\.[a-zA-Z0-9_-]+', "Google OAuth token"),
    (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT token"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub PAT"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth token"),
    (r'ghs_[a-zA-Z0-9]{36}', "GitHub App token"),
    (r'glpat-[a-zA-Z0-9-]{20,}', "GitLab PAT"),
    (r'xox[bpsa]-[a-zA-Z0-9-]+', "Slack token"),
    (r'sk-[a-zA-Z0-9]{48}', "OpenAI API key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'AIza[0-9A-Za-z_-]{35}', "Google API key"),
]


def _check_cloud_metadata(base_url: str, timeout: int = 8,
                           verify_tls: bool = True) -> List[Finding]:
    """Check if cloud metadata endpoints are accessible via SSRF."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    for provider, endpoints in CLOUD_METADATA.items():
        for endpoint, desc in endpoints:
            # Try SSRF via common parameter names
            ssrf_params = ["url", "redirect", "next", "returnUrl", "callback",
                          "fetch", "proxy", "target", "dest", "goto"]

            for param in ssrf_params:
                import urllib.parse
                url = base_url.rstrip("/") + f"?{param}={urllib.parse.quote(endpoint)}"
                resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
                body = resp.get("body", "")[:4096]
                status = resp.get("status", 0)

                if status == 200 and len(body) > 20:
                    meta_sigs = ["ami-id", "instance-id", "access-key", "security-credentials",
                                "iam", "serviceaccount", "subscription", "computeMetadata"]
                    if any(sig.lower() in body.lower() for sig in meta_sigs):
                        findings.append(Finding(
                            title=f"SSRF -> {provider} metadata",
                            severity="critical", category="nhi_ssrf",
                            module="nhi",
                            description=f"Cloud metadata ({provider}) accessible via SSRF through '{param}' parameter",
                            evidence=f"Param: {param}, endpoint: {endpoint[:60]}",
                            asset=host, points_deducted=15,
                            remediation="Block all internal/cloud metadata IP ranges. Validate URL inputs.",
                        ))
                        break
            else:
                continue
            break

    return findings


def _scan_for_tokens(base_url: str, timeout: int = 8,
                     verify_tls: bool = True) -> List[Finding]:
    """Scan page source for leaked tokens/credentials."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    body = resp.get("body", "")[:131072]
    headers_str = " ".join(f"{k}: {v}" for k, v in resp.get("headers", {}).items())
    haystack = body + " " + headers_str

    for pattern, name in TOKEN_PATTERNS:
        matches = re.findall(pattern, haystack)
        if matches:
            masked = matches[0][:8] + "..." + matches[0][-4:] if len(matches[0]) > 12 else "***"
            findings.append(Finding(
                title=f"Leaked {name}",
                severity="critical", category="leaked_credentials",
                module="nhi",
                description=f"{name} found in page source — non-human identity exposure",
                evidence=f"Match: {masked} ({len(matches)} total)",
                asset=host, points_deducted=15,
                remediation="Remove hardcoded tokens. Use secret management (Vault, AWS Secrets Manager, etc.).",
            ))
            break  # One token type per scan is enough

    return findings


def _check_nhi_paths(base_url: str, timeout: int = 8,
                     verify_tls: bool = True) -> List[Finding]:
    """Check for exposed NHI credential files."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    for path in NHI_PATHS:
        url = base_url.rstrip("/") + path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body = resp.get("body", "")[:4096]

        if status == 200 and len(body) > 10:
            cred_sigs = ["access_key", "secret_key", "token", "password",
                        "credentials", "private_key", "service_account"]
            has_creds = any(sig in body.lower() for sig in cred_sigs)
            sev = "critical" if has_creds else "high"
            pts = 15 if has_creds else 10

            findings.append(Finding(
                title=f"Exposed NHI creds: {path}",
                severity=sev, category="nhi_exposure",
                module="nhi",
                description=f"Non-human identity credential file accessible: {path}",
                evidence=f"GET {path} -> 200 ({len(body)} bytes, creds: {has_creds})",
                asset=host, points_deducted=pts,
                remediation="Restrict access to credential files. Use cloud secret stores.",
            ))

    return findings


def run_nhi(target: str, base_url: str, timeout: int = 8,
            verify_tls: bool = True) -> List[Finding]:
    """Non-Human Identity & blast-radius mapping. Returns list of Findings."""
    findings: List[Finding] = []

    findings.extend(_check_cloud_metadata(base_url, timeout=timeout, verify_tls=verify_tls))
    findings.extend(_scan_for_tokens(base_url, timeout=timeout, verify_tls=verify_tls))
    findings.extend(_check_nhi_paths(base_url, timeout=timeout, verify_tls=verify_tls))

    return findings

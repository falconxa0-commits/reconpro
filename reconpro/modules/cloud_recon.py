"""Module: CLOUD_RECON — Cloud Infrastructure Reconnaissance for ReconPro v8.0.

Probes cloud provider metadata endpoints (AWS, Azure, GCP, DigitalOcean),
discovers cloud-hosted storage assets (S3, Azure Blob, GCS), and checks
DNS records for cloud-service indicators.

Probes:
  1. AWS IMDSv1 / IMDSv2 metadata
  2. Azure Instance Metadata Service
  3. GCP Compute Metadata
  4. DigitalOcean Metadata

Discovery:
  5. AWS S3 public buckets
  6. Azure Blob storage containers
  7. GCP Cloud Storage buckets

DNS:
  8. CNAME records to cloud providers
  9. TXT records (SPF, DKIM, DMARC, verification)
 10. SRV records for cloud services
 11. NS records for cloud-hosted DNS
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import http_probe, Finding, compute_grade, badge_markdown, default_limiter


# ── DREAD scoring helper ────────────────────────────────────────────────

def _dread(damage: int, repro: int, exploit: int, affected: int, discover: int) -> float:
    """Compute DREAD score (0–10) from five component ratings."""
    return round((damage + repro + exploit + affected + discover) / 5.0, 1)


# ── Severity → points mapping ───────────────────────────────────────────

SEV_POINTS = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}


# ════════════════════════════════════════════════════════════════════════
# 1. CLOUD METADATA PROBERS
# ════════════════════════════════════════════════════════════════════════

def probe_aws_metadata(timeout: int = 5, verify_tls: bool = True) -> Dict[str, Any]:
    """Probe AWS EC2 Instance Metadata Service (IMDSv1 and IMDSv2).

    Returns {accessible: bool, data: dict, findings: list}.
    """
    result: Dict[str, Any] = {
        "accessible": False,
        "data": {},
        "findings": [],
    }
    base = "http://169.254.169.254/latest/meta-data/"

    # --- IMDSv1: direct GET ---
    v1_resp = http_probe(base, timeout=timeout, verify_tls=verify_tls)
    if v1_resp.get("ok") and v1_resp.get("status") == 200:
        result["accessible"] = True
        result["data"]["imds_v1"] = {
            "status": v1_resp["status"],
            "index": v1_resp.get("body", "")[:2048].strip(),
        }
        result["findings"].append({
            "title": "AWS IMDSv1 accessible (token-less)",
            "severity": "critical",
            "dread": _dread(10, 10, 10, 8, 9),
            "evidence": f"GET {base} -> 200",
        })

        # Probe common IMDSv1 sub-paths
        sub_paths = [
            ("iam/security-credentials/", "iam_roles"),
            ("hostname", "hostname"),
            ("local-ipv4", "local_ipv4"),
            ("instance-id", "instance_id"),
            ("instance-type", "instance_type"),
            ("ami-id", "ami_id"),
            ("placement/availability-zone", "az"),
        ]
        for path, key in sub_paths:
            resp = http_probe(base + path, timeout=timeout, verify_tls=verify_tls)
            if resp.get("ok") and resp.get("status") == 200:
                body = resp.get("body", "").strip()
                result["data"][key] = body[:1024]
                if key == "iam_roles":
                    roles = [r.strip() for r in body.splitlines() if r.strip()]
                    for role in roles:
                        role_resp = http_probe(
                            base + "iam/security-credentials/" + role,
                            timeout=timeout, verify_tls=verify_tls,
                        )
                        if role_resp.get("ok") and role_resp.get("status") == 200:
                            result["findings"].append({
                                "title": f"AWS IAM role credentials exposed: {role}",
                                "severity": "critical",
                                "dread": _dread(10, 10, 9, 9, 8),
                                "evidence": f"GET iam/security-credentials/{role} -> 200"
                                           f" ({len(role_resp.get('body', ''))} bytes)",
                            })
                            # Try to parse credential JSON safely
                            try:
                                cred = json.loads(role_resp.get("body", ""))
                                result["data"][f"cred_{role}"] = {
                                    k: v for k, v in cred.items()
                                    if k not in ("SecretAccessKey", "Token")
                                }
                            except (json.JSONDecodeError, ValueError):
                                pass

    # --- IMDSv2: PUT to get token, then GET with token ---
    token_url = "http://169.254.169.254/latest/api/token"
    token_resp = http_probe(
        token_url, method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        timeout=timeout, verify_tls=verify_tls,
    )
    if token_resp.get("ok") and token_resp.get("status") == 200:
        token = token_resp.get("body", "").strip()
        if token:
            v2_resp = http_probe(
                base, timeout=timeout, verify_tls=verify_tls,
                headers={"X-aws-ec2-metadata-token": token},
            )
            if v2_resp.get("ok") and v2_resp.get("status") == 200:
                result["data"]["imds_v2"] = {
                    "status": v2_resp["status"],
                    "index": v2_resp.get("body", "")[:2048].strip(),
                }
                if not result["accessible"]:
                    result["accessible"] = True
                result["findings"].append({
                    "title": "AWS IMDSv2 accessible (token obtained)",
                    "severity": "high",
                    "dread": _dread(8, 8, 8, 7, 7),
                    "evidence": f"PUT {token_url} -> 200, GET {base} -> 200",
                })

    return result


def probe_azure_metadata(timeout: int = 5, verify_tls: bool = True) -> Dict[str, Any]:
    """Probe Azure Instance Metadata Service.

    Returns {accessible: bool, data: dict, findings: list}.
    """
    result: Dict[str, Any] = {
        "accessible": False,
        "data": {},
        "findings": [],
    }
    url = (
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    )
    resp = http_probe(
        url, timeout=timeout, verify_tls=verify_tls,
        headers={"Metadata": "true"},
    )

    if resp.get("ok") and resp.get("status") == 200:
        result["accessible"] = True
        body = resp.get("body", "")[:4096]
        result["data"]["instance"] = body

        # Parse JSON to extract key fields
        try:
            data = json.loads(body)
            compute_data = data.get("compute", {})
            result["data"]["vm_id"] = compute_data.get("vmId", "")
            result["data"]["vm_size"] = compute_data.get("vmSize", "")
            result["data"]["location"] = compute_data.get("location", "")
            result["data"]["os_type"] = compute_data.get("osType", "")
            result["data"]["subscription_id"] = data.get("compute", {}).get("subscriptionId", "")
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass

        result["findings"].append({
            "title": "Azure Instance Metadata Service accessible",
            "severity": "high",
            "dread": _dread(8, 9, 8, 7, 7),
            "evidence": f"GET {url} -> 200 ({len(body)} bytes)",
        })

        # Probe additional Azure metadata endpoints
        extra_endpoints = [
            ("/metadata/identity/oauth2/token?api-version=2018-02-01"
             "&resource=https://management.azure.com/", "managed_identity_token"),
            ("/metadata/instance/network/interface?api-version=2021-02-01", "network"),
        ]
        for endpoint, key in extra_endpoints:
            full_url = f"http://169.254.169.254{endpoint}"
            extra_resp = http_probe(
                full_url, timeout=timeout, verify_tls=verify_tls,
                headers={"Metadata": "true"},
            )
            if extra_resp.get("ok") and extra_resp.get("status") == 200:
                extra_body = extra_resp.get("body", "")[:2048]
                result["data"][key] = extra_body
                if key == "managed_identity_token":
                    result["findings"].append({
                        "title": "Azure managed identity token obtained",
                        "severity": "critical",
                        "dread": _dread(10, 10, 9, 9, 8),
                        "evidence": (f"GET {full_url} -> 200 "
                                     f"({len(extra_body)} bytes)"),
                    })

    return result


def probe_gcp_metadata(timeout: int = 5, verify_tls: bool = True) -> Dict[str, Any]:
    """Probe Google Compute Engine Metadata Service.

    Returns {accessible: bool, data: dict, findings: list}.
    """
    result: Dict[str, Any] = {
        "accessible": False,
        "data": {},
        "findings": [],
    }
    base = "http://metadata.google.internal/computeMetadata/v1/"
    hdr = {"Metadata-Flavor": "Google"}

    # Probe the metadata index
    resp = http_probe(base, timeout=timeout, verify_tls=verify_tls, headers=hdr)

    if resp.get("ok") and resp.get("status") == 200:
        result["accessible"] = True
        result["data"]["index"] = resp.get("body", "")[:2048].strip()

        # Check for correct Metadata-Flavor response header
        flavor = resp.get("headers", {}).get("Metadata-Flavor", "")
        if flavor == "Google":
            result["findings"].append({
                "title": "GCP Compute Metadata accessible",
                "severity": "high",
                "dread": _dread(8, 9, 8, 7, 7),
                "evidence": f"GET {base} -> 200, Metadata-Flavor: Google",
            })

        # Probe specific paths
        sub_paths = [
            ("instance/id", "instance_id"),
            ("instance/zone", "zone"),
            ("instance/machine-type", "machine_type"),
            ("instance/image", "image"),
            ("instance/service-accounts/", "service_accounts"),
            ("project/project-id", "project_id"),
            ("project/numeric-project-id", "numeric_project_id"),
        ]
        for path, key in sub_paths:
            sub_resp = http_probe(
                base + path, timeout=timeout, verify_tls=verify_tls, headers=hdr,
            )
            if sub_resp.get("ok") and sub_resp.get("status") == 200:
                body = sub_resp.get("body", "").strip()
                result["data"][key] = body[:1024]

                if key == "service_accounts":
                    accounts = [a.strip() for a in body.splitlines() if a.strip()]
                    for acct in accounts:
                        # Check if the service account has a default token
                        token_resp = http_probe(
                            base + f"service-accounts/{acct}token",
                            timeout=timeout, verify_tls=verify_tls, headers=hdr,
                        )
                        if token_resp.get("ok") and token_resp.get("status") == 200:
                            result["findings"].append({
                                "title": (f"GCP service account token obtained: "
                                          f"{acct}"
),
                                "severity": "critical",
                                "dread": _dread(10, 10, 9, 9, 8),
                                "evidence": (f"GET service-accounts/{acct}token "
                                             f"-> 200 "
                                             f"({len(token_resp.get('body', ''))} bytes)"),
                            })
                        # Check for service account scopes
                        scopes_resp = http_probe(
                            base + f"service-accounts/{acct}scopes",
                            timeout=timeout, verify_tls=verify_tls, headers=hdr,
                        )
                        if scopes_resp.get("ok") and scopes_resp.get("status") == 200:
                            scopes_body = scopes_resp.get("body", "")[:2048]
                            result["data"][f"scopes_{acct}"] = scopes_body

    return result


def probe_digitalocean_metadata(timeout: int = 5, verify_tls: bool = True) -> Dict[str, Any]:
    """Probe DigitalOcean Metadata Service (Droplet Metadata).

    Returns {accessible: bool, data: dict, findings: list}.
    """
    result: Dict[str, Any] = {
        "accessible": False,
        "data": {},
        "findings": [],
    }
    base = "http://169.254.169.254/metadata/v1/"
    hdr = {"Metadata-Flavor": "digitalocean"}

    resp = http_probe(base, timeout=timeout, verify_tls=verify_tls, headers=hdr)

    if resp.get("ok") and resp.get("status") == 200:
        result["accessible"] = True
        body = resp.get("body", "")[:4096]
        result["data"]["index"] = body.strip()

        result["findings"].append({
            "title": "DigitalOcean Metadata Service accessible",
            "severity": "high",
            "dread": _dread(8, 9, 8, 7, 7),
            "evidence": f"GET {base} -> 200 ({len(body)} bytes)",
        })

        # Probe specific DO metadata paths
        do_paths = [
            ("id", "droplet_id"),
            ("hostname", "hostname"),
            ("region", "region"),
            ("interfaces/private/0/ipv4/address", "private_ipv4"),
            ("interfaces/public/0/ipv4/address", "public_ipv4"),
            ("dns/nameservers/0", "dns_ns"),
            ("tags", "tags"),
        ]
        for path, key in do_paths:
            sub_resp = http_probe(
                base + path, timeout=timeout, verify_tls=verify_tls, headers=hdr,
            )
            if sub_resp.get("ok") and sub_resp.get("status") == 200:
                result["data"][key] = sub_resp.get("body", "").strip()[:1024]

        # Check for user-data (may contain secrets/scripts)
        user_data_resp = http_probe(
            base + "user-data", timeout=timeout, verify_tls=verify_tls, headers=hdr,
        )
        if user_data_resp.get("ok") and user_data_resp.get("status") == 200:
            ud_body = user_data_resp.get("body", "")[:4096]
            if ud_body.strip():
                result["data"]["user_data"] = ud_body
                has_secrets = any(
                    kw in ud_body.lower()
                    for kw in ["password", "secret", "api_key", "token", "private_key"]
                )
                if has_secrets:
                    result["findings"].append({
                        "title": "DigitalOcean user-data contains potential secrets",
                        "severity": "critical",
                        "dread": _dread(9, 9, 9, 8, 8),
                        "evidence": f"user-data: {len(ud_body)} bytes (secrets detected)",
                    })

    return result


# ════════════════════════════════════════════════════════════════════════
# 2. CLOUD ASSET DISCOVERY
# ════════════════════════════════════════════════════════════════════════

AWS_BUCKET_SUFFIXES = [
    "-assets", "-logs", "-backups", "-config", "-data",
    "-public", "-private", "-static", "-media", "-uploads",
    "-deploy", "-releases", "-staging", "-prod", "-dev",
]


def discover_aws_s3_buckets(domain: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Discover AWS S3 buckets associated with a domain.

    Checks {domain}.s3.amazonaws.com and common bucket name patterns.
    Each result: {bucket, url, accessible, status, evidence}.
    """
    buckets: List[Dict[str, Any]] = []
    clean = re.sub(r"^https?://", "", domain).split("/")[0].lower()
    base_name = re.sub(r"[^a-z0-9]", "", clean)

    # Candidate bucket names
    candidates = {
        clean: f"https://{clean}.s3.amazonaws.com",
        f"www.{clean}": f"https://www.{clean}.s3.amazonaws.com",
    }
    for suffix in AWS_BUCKET_SUFFIXES:
        name = base_name + suffix
        candidates[name] = f"https://{name}.s3.amazonaws.com"

    # Also try {domain} as a bucket hosting a website
    candidates[f"{clean}-website"] = f"https://{clean}-website.s3-website-us-east-1.amazonaws.com"

    for bucket_name, url in candidates.items():
        resp = http_probe(url, method="HEAD", timeout=timeout, verify_tls=True)
        status = resp.get("status", 0)
        headers = resp.get("headers", {})

        # S3 returns 200 for public buckets, 403 for existent-but-private,
        # 404 for non-existent
        if status in (200, 301, 302):
            is_listing = False
            listing_indicators = ["ListBucketResult", "<Key>", "<Contents>"]
            if status == 200:
                body = resp.get("body", "")[:4096]
                is_listing = any(ind in body for ind in listing_indicators)
            buckets.append({
                "bucket": bucket_name,
                "url": url,
                "accessible": True,
                "status": status,
                "is_listing": is_listing,
                "evidence": f"HEAD {url} -> {status}",
            })
        elif status == 403:
            # Bucket exists but access denied — still a finding
            buckets.append({
                "bucket": bucket_name,
                "url": url,
                "accessible": False,
                "status": 403,
                "is_listing": False,
                "evidence": f"HEAD {url} -> 403 (bucket exists, access denied)",
            })

    return buckets


def discover_azure_storage(domain: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Discover Azure Blob Storage accounts associated with a domain.

    Checks {name}.blob.core.windows.net patterns.
    Each result: {account, url, accessible, status, evidence}.
    """
    results: List[Dict[str, Any]] = []
    clean = re.sub(r"^https?://", "", domain).split("/")[0].lower()
    base_name = re.sub(r"[^a-z0-9]", "", clean)

    # Azure storage account names must be 3-24 chars, lowercase alphanumeric only
    candidates = {
        base_name[:24]: f"https://{base_name[:24]}.blob.core.windows.net",
        f"{base_name}static"[:24]: f"https://{base_name}static"[:24] + ".blob.core.windows.net",
        f"{base_name}media"[:24]: f"https://{base_name}media"[:24] + ".blob.core.windows.net",
        f"{base_name}data"[:24]: f"https://{base_name}data"[:24] + ".blob.core.windows.net",
        f"{base_name}backups"[:24]: f"https://{base_name}backups"[:24] + ".blob.core.windows.net",
        f"{base_name}assets"[:24]: f"https://{base_name}assets"[:24] + ".blob.core.windows.net",
    }

    for acct_name, url in candidates.items():
        if len(acct_name) < 3:
            continue
        resp = http_probe(url, method="HEAD", timeout=timeout, verify_tls=True)
        status = resp.get("status", 0)

        if status in (200, 301, 302, 400):
            # 400 from Azure can indicate the account exists but container is unspecified
            results.append({
                "account": acct_name,
                "url": url,
                "accessible": status in (200, 301, 302),
                "status": status,
                "evidence": f"HEAD {url} -> {status}",
            })
        elif status == 403:
            results.append({
                "account": acct_name,
                "url": url,
                "accessible": False,
                "status": 403,
                "evidence": f"HEAD {url} -> 403 (storage account exists, access denied)",
            })

    return results


def discover_gcp_storage(domain: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Discover GCP Cloud Storage buckets associated with a domain.

    Checks storage.googleapis.com/{bucket} patterns.
    Each result: {bucket, url, accessible, status, evidence}.
    """
    results: List[Dict[str, Any]] = []
    clean = re.sub(r"^https?://", "", domain).split("/")[0].lower()
    base_name = re.sub(r"[^a-z0-9]", "", clean)

    # GCP bucket naming: lowercase, letters/numbers/dashes/hyphens, 3-63 chars
    candidates = [
        clean,
        f"www-{clean}",
        f"{base_name}-assets",
        f"{base_name}-static",
        f"{base_name}-media",
        f"{base_name}-data",
        f"{base_name}-backups",
        f"{base_name}-public",
        f"{base_name}-config",
        f"{base_name}-logs",
    ]

    for bucket_name in candidates:
        bucket_name = bucket_name[:63].strip("-")
        if len(bucket_name) < 3:
            continue
        url = f"https://storage.googleapis.com/{bucket_name}"
        resp = http_probe(url, method="GET", timeout=timeout, verify_tls=True)
        status = resp.get("status", 0)
        body = resp.get("body", "")[:4096]
        headers = resp.get("headers", {})

        # GCS returns 200 for public buckets, 401/403 for auth-required
        if status == 200 and len(body) > 10:
            is_listing = any(
                ind in body for ind in ["<ListBucketResult>", "<Contents>", "<Key>"]
            )
            results.append({
                "bucket": bucket_name,
                "url": url,
                "accessible": True,
                "status": status,
                "is_listing": is_listing,
                "evidence": f"GET {url} -> 200 ({len(body)} bytes)",
            })
        elif status in (401, 403):
            # Bucket exists but requires authentication
            results.append({
                "bucket": bucket_name,
                "url": url,
                "accessible": False,
                "status": status,
                "is_listing": False,
                "evidence": f"GET {url} -> {status} (bucket exists, auth required)",
            })

    return results


# ════════════════════════════════════════════════════════════════════════
# 3. CLOUD DNS RECORD CHECKS
# ════════════════════════════════════════════════════════════════════════

CLOUD_CNAME_PATTERNS: Dict[str, re.Pattern] = {
    "CloudFront": re.compile(r"\.(?:cloudfront|cloudfront\.net)$", re.I),
    "AWS S3": re.compile(r"\.s3(?:-website)?(?:-[\w-]+)?\.amazonaws\.com$", re.I),
    "AWS ELB/ALB": re.compile(r"\.(?:elb|elasticloadbalancing)\.amazonaws\.com$", re.I),
    "Azure CDN": re.compile(r"\.azureedge\.net$", re.I),
    "Azure Blob": re.compile(r"\.blob\.core\.windows\.net$", re.I),
    "Cloudflare": re.compile(r"\.cloudflare\.com$", re.I),
    "GCP Load Balancer": re.compile(r"\..appspot\.com$", re.I),
    "Fastly": re.compile(r"\.fastly\.net$", re.I),
    "Heroku": re.compile(r"\.herokudns\.com$", re.I),
    "Vercel": re.compile(r"\.vercel-dns\.com$", re.I),
    "Netlify": re.compile(r"\.netlify\.com$", re.I),
}


def _dns_resolve(host: str) -> List[str]:
    """Resolve hostname to list of IP addresses."""
    ips: List[str] = []
    seen: set = set()
    try:
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _fam, _type, _proto, _canonname, sockaddr in results:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    except (socket.gaierror, OSError):
        pass
    return ips


def _dns_cname(host: str) -> List[str]:
    """Get CNAME chain for a hostname via gethostbyname_ex."""
    aliases: List[str] = []
    try:
        _hostname, aliaslist, _ipaddrlist = socket.gethostbyname_ex(host)
        aliases.extend(aliaslist)
    except (socket.gaierror, OSError, socket.herror):
        pass
    return aliases


def _dns_query(host: str, rtype: str) -> List[str]:
    """Query DNS records using system `dig` command. Falls back to empty list."""
    results: List[str] = []
    try:
        proc = subprocess.run(
            ["dig", "+short", host, rtype],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().splitlines():
                line = line.strip().strip('"').strip()
                if line:
                    results.append(line)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return results


def _dns_query_host(host: str, rtype: str) -> List[str]:
    """Query DNS records using system `host` command. Falls back to empty list."""
    results: List[str] = []
    try:
        proc = subprocess.run(
            ["host", "-t", rtype, host],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if line and "NS" not in line.upper().split()[0] if line.split() else True:
                    results.append(line)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return results


def check_cloud_dns(domain: str) -> List[Dict[str, Any]]:
    """Check DNS records for cloud-service indicators.

    Checks CNAMEs, TXT records (SPF, DKIM, DMARC, verification),
    SRV records, and NS records for cloud-hosted DNS.

    Returns list of dicts with check type and details.
    """
    results: List[Dict[str, Any]] = []
    clean = re.sub(r"^https?://", "", domain).split("/")[0].lower()

    # --- CNAME records ---
    cnames = _dns_cname(clean)
    # Also check www subdomain
    if clean != f"www.{clean}":
        cnames.extend(_dns_cname(f"www.{clean}"))

    for cname in cnames:
        for provider, pattern in CLOUD_CNAME_PATTERNS.items():
            if pattern.search(cname):
                results.append({
                    "type": "cname",
                    "provider": provider,
                    "host": clean,
                    "cname": cname,
                    "evidence": f"CNAME: {cname} -> {provider}",
                })

    # --- TXT records ---
    txt_records = _dns_query(clean, "TXT")
    for txt in txt_records:
        txt_lower = txt.lower()
        # SPF detection
        if "v=spf1" in txt_lower:
            results.append({
                "type": "txt",
                "subtype": "spf",
                "host": clean,
                "value": txt[:300],
                "evidence": f"SPF record: {txt[:200]}",
            })
            # Check for overly permissive SPF
            if "+all" in txt_lower or "?all" in txt_lower:
                results.append({
                    "type": "txt",
                    "subtype": "spf_permissive",
                    "host": clean,
                    "value": txt[:300],
                    "evidence": f"Permissive SPF: {txt[:200]}",
                })

        # DKIM detection
        if "v=dkim1" in txt_lower:
            results.append({
                "type": "txt",
                "subtype": "dkim",
                "host": clean,
                "value": txt[:300],
                "evidence": f"DKIM record found: {txt[:200]}",
            })

        # DMARC detection
        if "v=dmarc1" in txt_lower:
            results.append({
                "type": "txt",
                "subtype": "dmarc",
                "host": clean,
                "value": txt[:300],
                "evidence": f"DMARC record: {txt[:200]}",
            })
            if "p=none" in txt_lower:
                results.append({
                    "type": "txt",
                    "subtype": "dmarc_weak",
                    "host": clean,
                    "value": txt[:300],
                    "evidence": f"Weak DMARC policy (p=none): {txt[:200]}",
                })

        # Cloud verification records
        for provider_name, indicator in [
            ("Google", "google-site-verification"),
            ("AWS", "amazonses"),
            ("Azure", "ms"),
            ("Shopify", "shopify"),
            ("Stripe", "stripe"),
        ]:
            if indicator in txt_lower:
                results.append({
                    "type": "txt",
                    "subtype": "verification",
                    "provider": provider_name,
                    "host": clean,
                    "value": txt[:300],
                    "evidence": f"{provider_name} verification TXT: {txt[:200]}",
                })
                break

    # --- DMARC explicit check (._dmarc subdomain) ---
    dmarc_records = _dns_query(f"_dmarc.{clean}", "TXT")
    if not dmarc_records:
        results.append({
            "type": "txt",
            "subtype": "dmarc_missing",
            "host": clean,
            "value": "",
            "evidence": f"No DMARC record found for _dmarc.{clean}",
        })

    # --- SRV records for cloud services ---
    srv_queries = [
        ("_sip._tcp", "SIP/VoIP"),
        ("_xmpp-server._tcp", "XMPP Chat"),
        ("_autodiscover._tcp", "Exchange/Office365"),
        ("_sftp._ssh", "SFTP"),
    ]
    for prefix, service_name in srv_queries:
        srv_records = _dns_query(f"{prefix}.{clean}", "SRV")
        for srv in srv_records:
            results.append({
                "type": "srv",
                "service": service_name,
                "host": clean,
                "value": srv[:300],
                "evidence": f"SRV {prefix}.{clean}: {srv[:200]}",
            })

    # --- NS records ---
    ns_records = _dns_query(clean, "NS")
    cloud_ns_patterns = {
        "AWS Route53": re.compile(r"awsdns\-|route53", re.I),
        "Cloudflare DNS": re.compile(r"cloudflare\.com$", re.I),
        "Google Cloud DNS": re.compile(r"google\.com$|cloud\.google", re.I),
        "Azure DNS": re.compile(r"azure-dns|azure\.net", re.I),
        "DigitalOcean DNS": re.compile(r"digitalocean\.com$", re.I),
    }
    for ns in ns_records:
        ns_clean = ns.strip().rstrip(".")
        for provider, pattern in cloud_ns_patterns.items():
            if pattern.search(ns_clean):
                results.append({
                    "type": "ns",
                    "provider": provider,
                    "host": clean,
                    "nameserver": ns_clean,
                    "evidence": f"NS: {ns_clean} -> {provider}",
                })
                break

    # --- A/AAAA resolution check ---
    ips = _dns_resolve(clean)
    if ips:
        results.append({
            "type": "resolution",
            "host": clean,
            "ips": ips,
            "evidence": f"Resolved {clean} -> {', '.join(ips[:5])}",
        })

    return results


# ════════════════════════════════════════════════════════════════════════
# 4. MAIN RUN FUNCTION
# ════════════════════════════════════════════════════════════════════════

def run_cloud_recon(target: str, base_url: str = "", timeout: int = 8,
        verify_tls: bool = True) -> List[Finding]:
    """Run cloud infrastructure reconnaissance.

    For local targets (127.0.0.1, localhost, metadata IPs): probe cloud
    metadata endpoints.

    For remote domain targets: DNS checks + cloud asset discovery.

    Returns (findings, score, grade, badge_md).
    """
    findings: List[Finding] = []
    deductions = 0
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    def add(title: str, severity: str, category: str, desc: str,
            evidence: str, pts: int, dread: float = 0.0,
            remediation: str = "") -> None:
        nonlocal deductions
        deductions += pts
        findings.append(Finding(
            title=title, severity=severity, category=category,
            module="cloud_recon", description=desc, evidence=evidence,
            asset=host, points_deducted=pts,
            dread_score=dread if dread else _dread(
                10 if severity == "critical" else (8 if severity == "high" else 5),
                8, 7, 6, 7,
            ),
            remediation=remediation,
        ))

    # Determine if target is local (metadata probe) or remote (DNS + assets)
    local_indicators = ("127.0.0.1", "localhost", "::1", "169.254.169.254",
                        "metadata.google.internal")
    is_local = host in local_indicators or host.startswith("127.") or host.startswith("10.")

    if is_local:
        # ── Metadata endpoint probing ──
        # AWS
        aws = probe_aws_metadata(timeout=timeout, verify_tls=verify_tls)
        if aws["accessible"]:
            for f in aws["findings"]:
                sev = f["severity"]
                pts = SEV_POINTS.get(sev, 5)
                add(
                    f["title"], sev, "cloud_metadata",
                    f"AWS EC2 metadata is accessible from this environment. "
                    f"This may expose instance configuration, IAM credentials, "
                    f"and network details.",
                    f["evidence"], pts, f["dread"],
                    remediation=(
                        "Disable IMDSv1: set MetadataOptions.HttpTokens=required. "
                        "Restrict IMDSv2 via IAM conditions and hop-limit=1. "
                        "Network ACLs should block 169.254.169.254 for "
                        "non-EC2 instances."
                    ),
                )

        # Azure
        azure = probe_azure_metadata(timeout=timeout, verify_tls=verify_tls)
        if azure["accessible"]:
            for f in azure["findings"]:
                sev = f["severity"]
                pts = SEV_POINTS.get(sev, 5)
                add(
                    f["title"], sev, "cloud_metadata",
                    "Azure Instance Metadata Service is accessible. "
                    "This exposes VM configuration and potentially managed "
                    "identity tokens.",
                    f["evidence"], pts, f["dread"],
                    remediation=(
                        "Restrict managed identity token access. "
                        "Use Azure Policy to enforce IMDS restrictions. "
                        "Apply network security groups to limit metadata access."
                    ),
                )

        # GCP
        gcp = probe_gcp_metadata(timeout=timeout, verify_tls=verify_tls)
        if gcp["accessible"]:
            for f in gcp["findings"]:
                sev = f["severity"]
                pts = SEV_POINTS.get(sev, 5)
                add(
                    f["title"], sev, "cloud_metadata",
                    "GCP Compute Metadata is accessible. This may expose "
                    "instance details, service account tokens, and project "
                    "information.",
                    f["evidence"], pts, f["dread"],
                    remediation=(
                        "Restrict metadata access with IAM conditions. "
                        "Disable default service account token access. "
                        "Use VPC Service Controls to limit metadata API reach."
                    ),
                )

        # DigitalOcean
        do = probe_digitalocean_metadata(timeout=timeout, verify_tls=verify_tls)
        if do["accessible"]:
            for f in do["findings"]:
                sev = f["severity"]
                pts = SEV_POINTS.get(sev, 5)
                add(
                    f["title"], sev, "cloud_metadata",
                    "DigitalOcean Metadata Service is accessible. This "
                    "exposes droplet configuration and potentially user-data "
                    "with secrets.",
                    f["evidence"], pts, f["dread"],
                    remediation=(
                        "Review droplet metadata access. Remove sensitive data "
                        "from user-data. Use cloud firewalls to restrict "
                        "169.254.169.254 if not needed."
                    ),
                )

        if not any(p["accessible"] for p in [aws, azure, gcp, do]):
            add(
                "No cloud metadata endpoints accessible",
                "info", "cloud_metadata",
                "No cloud provider metadata services responded at "
                "169.254.169.254 or metadata.google.internal. The host does "
                "not appear to be running on a major cloud provider, or "
                "metadata access is properly restricted.",
                "All metadata probes returned no response", 0,
                remediation="",
            )

    else:
        # ── Remote target: DNS checks + asset discovery ──

        # DNS record checks
        dns_results = check_cloud_dns(host)

        for r in dns_results:
            rtype = r["type"]

            if rtype == "cname":
                add(
                    f"CNAME points to {r['provider']}: {r['host']}",
                    "info", "cloud_dns",
                    f"Host {r['host']} has a CNAME record pointing to "
                    f"{r['provider']} ({r['cname']}). This confirms use of "
                    f"{r['provider']} infrastructure.",
                    r["evidence"], 0,
                    _dread(3, 5, 2, 2, 8),
                    remediation="",
                )

            elif rtype == "txt":
                subtype = r.get("subtype", "")
                if subtype == "spf_permissive":
                    add(
                        "Permissive SPF record (+all or ?all)",
                        "medium", "cloud_dns",
                        f"SPF record for {r['host']} uses a permissive 'all' "
                        f"mechanism, allowing any mail server to send on behalf "
                        f"of the domain. This enables email spoofing.",
                        r["evidence"], 5,
                        _dread(6, 8, 8, 7, 6),
                        remediation=(
                            "Change SPF 'all' mechanism from +all/?all to "
                            "-all or ~all to reject or soft-fail unauthorized "
                            "senders."
                        ),
                    )
                elif subtype == "dmarc_missing":
                    add(
                        "No DMARC record configured",
                        "medium", "cloud_dns",
                        f"No DMARC TXT record found for _dmarc.{r['host']}. "
                        f"Without DMARC, email receivers cannot verify the "
                        f"domain's email authentication policy.",
                        r["evidence"], 5,
                        _dread(5, 9, 7, 6, 8),
                        remediation=(
                            "Publish a DMARC record: _dmarc.{host} IN TXT "
                            '"v=DMARC1; p=reject; rua=mailto:dmarc@{host}"'
                        ),
                    )
                elif subtype == "dmarc_weak":
                    add(
                        "Weak DMARC policy (p=none)",
                        "medium", "cloud_dns",
                        f"DMARC policy for {r['host']} is set to p=none, which "
                        f"means no action is taken on failed authentication. "
                        f"This provides no protection against email spoofing.",
                        r["evidence"], 5,
                        _dread(5, 8, 7, 6, 7),
                        remediation=(
                            "Change DMARC policy to p=quarantine or p=reject "
                            f"for {host}."
                        ),
                    )
                elif subtype == "verification":
                    provider = r.get("provider", "unknown")
                    add(
                        f"{provider} domain verification TXT record",
                        "info", "cloud_dns",
                        f"Domain {r['host']} has a {provider} verification TXT "
                        f"record. This confirms use of {provider} services.",
                        r["evidence"], 0,
                        _dread(2, 5, 1, 2, 7),
                        remediation="",
                    )
                elif subtype in ("spf", "dkim", "dmarc"):
                    add(
                        f"{subtype.upper()} record present",
                        "info", "cloud_dns",
                        f"{r['host']} has a {subtype.upper()} record configured.",
                        r["evidence"], 0,
                        remediation="",
                    )

            elif rtype == "srv":
                add(
                    f"SRV record: {r['service']}",
                    "info", "cloud_dns",
                    f"{r['host']} has an SRV record for {r['service']}: "
                    f"{r.get('value', '')[:200]}",
                    r["evidence"], 0,
                    remediation="",
                )

            elif rtype == "ns":
                add(
                    f"DNS hosted on {r['provider']}: {r['nameserver']}",
                    "info", "cloud_dns",
                    f"{r['host']} uses {r['provider']} for DNS hosting "
                    f"(nameserver: {r['nameserver']}).",
                    r["evidence"], 0,
                    remediation="",
                )

        # Cloud asset discovery
        # AWS S3
        s3_buckets = discover_aws_s3_buckets(host, timeout=timeout)
        for bucket in s3_buckets:
            if bucket["accessible"] and bucket.get("is_listing"):
                add(
                    f"Public S3 bucket with directory listing: {bucket['bucket']}",
                    "critical", "cloud_storage",
                    f"AWS S3 bucket '{bucket['bucket']}' is publicly accessible "
                    f"and has directory listing enabled. All objects may be "
                    f"enumerated and downloaded by anyone.",
                    bucket["evidence"], 15,
                    _dread(10, 10, 10, 8, 9),
                    remediation=(
                        f"Disable public access on S3 bucket '{bucket['bucket']}'. "
                        f"Block all public access in S3 settings. Apply "
                        f"bucket policies that deny s3:* to '*' principal."
                    ),
                )
            elif bucket["accessible"]:
                add(
                    f"Public S3 bucket: {bucket['bucket']}",
                    "high", "cloud_storage",
                    f"AWS S3 bucket '{bucket['bucket']}' is publicly accessible "
                    f"(status {bucket['status']}). Contents may be retrievable.",
                    bucket["evidence"], 10,
                    _dread(8, 9, 9, 7, 8),
                    remediation=(
                        f"Review and restrict access to S3 bucket "
                        f"'{bucket['bucket']}'. Enable Block Public Access."
                    ),
                )
            elif bucket["status"] == 403:
                add(
                    f"S3 bucket exists (access denied): {bucket['bucket']}",
                    "low", "cloud_storage",
                    f"AWS S3 bucket '{bucket['bucket']}' exists but returns "
                    f"403 Forbidden. Bucket name is disclosed.",
                    bucket["evidence"], 2,
                    _dread(3, 8, 4, 3, 7),
                    remediation=(
                        f"Consider renaming the bucket or using a CloudFront "
                        f"origin with WAF to obscure the direct S3 endpoint."
                    ),
                )

        # Azure Blob Storage
        azure_storage = discover_azure_storage(host, timeout=timeout)
        for acct in azure_storage:
            if acct["accessible"]:
                add(
                    f"Public Azure storage account: {acct['account']}",
                    "high", "cloud_storage",
                    f"Azure Blob Storage account '{acct['account']}' is "
                    f"publicly accessible (status {acct['status']}).",
                    acct["evidence"], 10,
                    _dread(8, 9, 9, 7, 8),
                    remediation=(
                        f"Restrict access to storage account '{acct['account']}'. "
                        f"Disable public access. Use SAS tokens or managed "
                        f"identities for authorized access."
                    ),
                )
            elif acct["status"] == 403:
                add(
                    f"Azure storage account exists (access denied): {acct['account']}",
                    "low", "cloud_storage",
                    f"Azure Blob Storage account '{acct['account']}' exists "
                    f"but returns 403. Account name is disclosed.",
                    acct["evidence"], 2,
                    _dread(3, 8, 4, 3, 7),
                    remediation=(
                        f"Use Azure Private Endpoints and disable public "
                        f"access for storage account '{acct['account']}'."
                    ),
                )

        # GCP Cloud Storage
        gcp_buckets = discover_gcp_storage(host, timeout=timeout)
        for bucket in gcp_buckets:
            if bucket["accessible"] and bucket.get("is_listing"):
                add(
                    f"Public GCS bucket with listing: {bucket['bucket']}",
                    "critical", "cloud_storage",
                    f"GCP Cloud Storage bucket '{bucket['bucket']}' is public "
                    f"with directory listing. All objects are enumerable.",
                    bucket["evidence"], 15,
                    _dread(10, 10, 10, 8, 9),
                    remediation=(
                        f"Set uniform bucket-level access on '{bucket['bucket']}'. "
                        f"Remove allUsers/allAuthenticatedUsers from IAM. "
                        f"Enable public access prevention."
                    ),
                )
            elif bucket["accessible"]:
                add(
                    f"Public GCS bucket: {bucket['bucket']}",
                    "high", "cloud_storage",
                    f"GCP Cloud Storage bucket '{bucket['bucket']}' is publicly "
                    f"accessible (status {bucket['status']}).",
                    bucket["evidence"], 10,
                    _dread(8, 9, 9, 7, 8),
                    remediation=(
                        f"Restrict access to '{bucket['bucket']}'. Remove public "
                        f"IAM bindings. Use signed URLs for temporary access."
                    ),
                )
            elif bucket["status"] in (401, 403):
                add(
                    f"GCS bucket exists (auth required): {bucket['bucket']}",
                    "low", "cloud_storage",
                    f"GCP Cloud Storage bucket '{bucket['bucket']}' exists "
                    f"but requires authentication (status {bucket['status']}).",
                    bucket["evidence"], 2,
                    _dread(3, 8, 4, 3, 7),
                    remediation="",
                )

    # ── Scoring ──
    score = max(0, min(100, 100 - deductions))
    if not findings:
        score = 100
    grade = compute_grade(score)
    badge_md = badge_markdown(host, grade)

    return findings

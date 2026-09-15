"""Infrastructure-as-Code Security Auditor for ReconPro v8.0.

Scans Terraform (.tf), CloudFormation (.yaml/.json), Dockerfiles,
and Kubernetes manifests for security misconfigurations.

Zero external dependencies — stdlib only (re, json, pathlib, os).
For YAML parsing, attempts ``import yaml`` and falls back to a
lightweight line-based parser when PyYAML is not installed.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import Finding


# ── Severity / score helpers ─────────────────────────────────────────

_SEV_WEIGHT: Dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 1.0,
}

_PTS_MAP: Dict[str, int] = {
    "critical": 15,
    "high": 10,
    "medium": 6,
    "low": 3,
    "info": 1,
}


def _dread(severity: str) -> float:
    return _SEV_WEIGHT.get(severity.lower(), 2.5)


def _pts(severity: str) -> int:
    return _PTS_MAP.get(severity.lower(), 3)


def _ev(file: str, line: int) -> str:
    return f"{file}:{line}"


# ── Simple YAML fallback parser ──────────────────────────────────────

def _simple_yaml_load(text: str) -> Any:
    """Attempt to import yaml; if unavailable, parse top-level JSON-like structures.

    This fallback handles most CloudFormation and Kubernetes manifests that use
    simple key-value or list-of-dicts structures.
    """
    try:
        import yaml  # type: ignore[import-untyped]
        return yaml.safe_load(text)
    except Exception:
        pass

    # Fallback: try JSON first (many YAML files are valid JSON subsets)
    try:
        return json.loads(text)
    except Exception:
        pass

    # Ultra-simple line-based extractor for key: value and - key: value
    result: Dict[str, Any] = {}
    current_list_key: Optional[str] = None
    list_items: List[Dict[str, Any]] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # List item
        if stripped.startswith("- "):
            item = stripped[2:]
            if ":" in item:
                k, v = item.split(":", 1)
                entry = {k.strip(): v.strip().strip('"\'')}
                if current_list_key:
                    list_items.append(entry)
                else:
                    result.setdefault(k.strip(), []).append(v.strip().strip('"\''))
            continue

        # Key: Value
        if ":" in stripped and not stripped.endswith(":"):
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip()
            if v:
                if v.lower() in ("true", "false"):
                    result[k] = v.lower() == "true"
                elif v.isdigit():
                    result[k] = int(v)
                else:
                    result[k] = v.strip('"\'')
            else:
                result[k] = None
                current_list_key = k
                list_items = []
                result[f"_{k}_items"] = list_items

    if list_items and current_list_key:
        result[current_list_key] = list_items

    return result


def _yaml_load_all(text: str) -> List[Any]:
    """Load all YAML documents from a multi-doc stream."""
    try:
        import yaml  # type: ignore[import-untyped]
        docs = list(yaml.safe_load_all(text))
        return [d for d in docs if d is not None]
    except Exception:
        pass

    # Fallback: split on "---" and parse individually
    parts = re.split(r"^---\s*$", text, flags=re.MULTILINE)
    results: List[Any] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        try:
            results.append(json.loads(part))
        except Exception:
            parsed = _simple_yaml_load(part)
            if parsed:
                results.append(parsed)
    return results


# ══════════════════════════════════════════════════════════════════════
# 1. TERRAFORM / HCL PARSER
# ══════════════════════════════════════════════════════════════════════


def _tf_block_ranges(text: str) -> List[Tuple[str, int, int, List[str]]]:
    """Extract top-level HCL blocks as (block_type, start, end, lines)."""
    lines = text.splitlines()
    blocks: List[Tuple[str, int, int, List[str]]] = []
    i = 0
    while i < len(lines):
        m = re.match(r'^(\w+)\s+(?:"([^"]+)")?\s*\{', lines[i])
        if m:
            block_type = m.group(1)
            label = m.group(2) or ""
            depth = 1
            start = i + 1
            block_lines = [lines[i]]
            i += 1
            while i < len(lines) and depth > 0:
                block_lines.append(lines[i])
                for ch in lines[i]:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                i += 1
            blocks.append((block_type, start, start + len(block_lines) - 1, block_lines))
        else:
            i += 1
    return blocks


def _tf_in_block(block_lines: List[str], pattern: str) -> Optional[int]:
    """Return 1-based line number within *block_lines* matching *pattern*, or None."""
    for idx, line in enumerate(block_lines):
        if re.search(pattern, line, re.I):
            return idx + 1
    return None


def _tf_not_in_block(block_lines: List[str], pattern: str) -> bool:
    """Return True if *pattern* is NOT found anywhere in *block_lines*."""
    return not any(re.search(pattern, line, re.I) for line in block_lines)


def parse_tf_file(path: str) -> List[Dict[str, Any]]:
    """Parse a .tf / .tfstate file and return a list of issue dicts."""
    issues: List[Dict[str, Any]] = []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return issues

    blocks = _tf_block_ranges(text)

    for block_type, start, end, blines in blocks:
        label_match = re.search(r'"([^"]+)"', blines[0])
        label = label_match.group(1) if label_match else ""
        joined = "\n".join(blines)
        fname = os.path.basename(path)

        # ── S3 Bucket Checks ─────────────────────────────────────────

        if "aws_s3_bucket" in block_type and "policy" not in block_type:
            # Check 1: No versioning block
            if _tf_not_in_block(blines, r'versioning'):
                ln = _tf_in_block(blines, r'aws_s3_bucket') or start
                issues.append({
                    "title": "S3 Bucket Missing Versioning",
                    "severity": "medium", "category": "s3_misconfiguration",
                    "description": f"S3 bucket '{label}' does not enable versioning, making it vulnerable to accidental or malicious data deletion.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": 'Add a versioning block: versioning { enabled = true }',
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

            # Check 2: public-read ACL
            acl_ln = _tf_in_block(blines, r'acl\s*=\s*"public-read"')
            if acl_ln:
                issues.append({
                    "title": "S3 Bucket with Public-Read ACL",
                    "severity": "high", "category": "s3_misconfiguration",
                    "description": f"S3 bucket '{label}' has ACL set to 'public-read', exposing objects to the internet.",
                    "evidence": _ev(fname, start + acl_ln - 1),
                    "remediation": 'Set acl = "private" and use bucket policies for controlled access.',
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

            # Check 3: public-read-write ACL
            acl_ln2 = _tf_in_block(blines, r'acl\s*=\s*"public-read-write"')
            if acl_ln2:
                issues.append({
                    "title": "S3 Bucket with Public-Read-Write ACL",
                    "severity": "critical", "category": "s3_misconfiguration",
                    "description": f"S3 bucket '{label}' has ACL set to 'public-read-write', allowing anyone to read AND write.",
                    "evidence": _ev(fname, start + acl_ln2 - 1),
                    "remediation": 'Set acl = "private" immediately. Use IAM policies for access control.',
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

            # Check 4: No server-side encryption
            if _tf_not_in_block(blines, r'(server_side_encryption_configuration|aws_kms_key)'):
                ln = _tf_in_block(blines, r'aws_s3_bucket') or start
                issues.append({
                    "title": "S3 Bucket Missing Encryption",
                    "severity": "medium", "category": "s3_misconfiguration",
                    "description": f"S3 bucket '{label}' has no server-side encryption configured.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": 'Add aws_s3_bucket_server_side_encryption_configuration with SSE-S3 or SSE-KMS.',
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

            # Check 5: No logging
            if _tf_not_in_block(blines, r'aws_s3_bucket_logging'):
                ln = _tf_in_block(blines, r'aws_s3_bucket') or start
                issues.append({
                    "title": "S3 Bucket Missing Access Logging",
                    "severity": "low", "category": "s3_misconfiguration",
                    "description": f"S3 bucket '{label}' has no access logging enabled, reducing audit capability.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": 'Add an aws_s3_bucket_logging resource targeting this bucket.',
                    "dread_score": _dread("low"), "points_deducted": _pts("low"),
                })

        # Check 6: S3 Bucket Policy with Principal: "*"
        if "aws_s3_bucket_policy" in block_type:
            if re.search(r'Principal\s*=\s*"\*"', joined):
                ln = _tf_in_block(blines, r'Principal') or start
                issues.append({
                    "title": "S3 Bucket Policy with Wildcard Principal",
                    "severity": "critical", "category": "s3_misconfiguration",
                    "description": "Bucket policy allows access from any principal ('*'), potentially exposing all objects.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Restrict Principal to specific AWS accounts, users, or roles.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

        # ── Security Group Checks ─────────────────────────────────────

        if "aws_security_group" in block_type or "aws_security_group_rule" in block_type:
            # Check 7: 0.0.0.0/0 ingress
            if re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"', joined):
                ln = _tf_in_block(blines, r'0\.0\.0\.0/0') or start
                port_ln = _tf_in_block(blines, r'from_port|to_port')
                port_info = ""
                if port_ln and port_ln - 1 < len(blines):
                    port_info = " " + blines[port_ln - 1].strip()
                issues.append({
                    "title": f"Security Group Open to 0.0.0.0/0{port_info}",
                    "severity": "high", "category": "network_exposure",
                    "description": f"Security group '{label}' allows ingress from 0.0.0.0/0 (entire internet).{port_info}",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Restrict cidr_blocks to specific IP ranges. Use VPN/security groups for admin access.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

            # Check 8: SSH (port 22) open to the world
            if re.search(r'from_port\s*=\s*22', joined) and re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"', joined):
                ln = _tf_in_block(blines, r'from_port\s*=\s*22') or start
                issues.append({
                    "title": "SSH (Port 22) Open to Internet",
                    "severity": "critical", "category": "network_exposure",
                    "description": "SSH access (port 22) is exposed to 0.0.0.0/0, allowing brute-force attacks.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Restrict SSH ingress to known IP ranges or a bastion host.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

            # Check 9: RDP (port 3389) open to the world
            if re.search(r'from_port\s*=\s*3389', joined) and re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"', joined):
                ln = _tf_in_block(blines, r'from_port\s*=\s*3389') or start
                issues.append({
                    "title": "RDP (Port 3389) Open to Internet",
                    "severity": "critical", "category": "network_exposure",
                    "description": "RDP access (port 3389) is exposed to 0.0.0.0/0, a prime target for attackers.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Restrict RDP to known IP ranges. Use AWS Systems Manager Session Manager instead.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

            # Check 10: No egress rules (default allow all)
            if _tf_not_in_block(blines, r'egress') and "aws_security_group" in block_type:
                ln = _tf_in_block(blines, r'aws_security_group') or start
                issues.append({
                    "title": "Security Group Missing Egress Rules",
                    "severity": "medium", "category": "network_exposure",
                    "description": f"Security group '{label}' has no explicit egress rules, defaulting to allow all outbound.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Add an explicit egress rule restricting outbound traffic to required endpoints.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── IAM Policy Checks ─────────────────────────────────────────

        if "aws_iam_policy" in block_type or "aws_iam_policy_document" in block_type or "aws_iam_role_policy" in block_type:
            # Check 11: Full admin Action: "*"
            has_star_action = bool(re.search(r'"Action"\s*=\s*"\*"', joined))
            has_star_action2 = bool(re.search(r'actions\s*=\s*\[\s*"\*"', joined))
            has_star_resource = bool(re.search(r'"Resource"\s*=\s*"\*"', joined))
            has_star_resource2 = bool(re.search(r'resources\s*=\s*\[\s*"\*"', joined))

            if (has_star_action or has_star_action2) and (has_star_resource or has_star_resource2):
                ln = _tf_in_block(blines, r'"\*"') or start
                issues.append({
                    "title": "IAM Policy with Full Admin Access",
                    "severity": "critical", "category": "iam_misconfiguration",
                    "description": "IAM policy grants Action: '*' on Resource: '*' — full administrative access.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Apply least-privilege: specify explicit actions and restrict resources to ARN patterns.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

            # Check 12: Wildcard action without wildcard resource (still risky)
            if (has_star_action or has_star_action2) and not (has_star_resource or has_star_resource2):
                ln = _tf_in_block(blines, r'"Action"\s*=\s*"\*"') or _tf_in_block(blines, r'actions\s*=\s*\[\s*"\*"') or start
                issues.append({
                    "title": "IAM Policy with Wildcard Action",
                    "severity": "high", "category": "iam_misconfiguration",
                    "description": "IAM policy uses Action: '*' which grants all actions on specified resources.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Replace '*' with explicit action names (e.g., 's3:GetObject', 's3:PutObject').",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # ── RDS / Database Checks ─────────────────────────────────────

        if "aws_db_instance" in block_type or "aws_rds_cluster" in block_type:
            # Check 13: No encryption
            if _tf_not_in_block(blines, r'storage_encrypted\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_db_instance|aws_rds_cluster') or start
                issues.append({
                    "title": "RDS Instance Missing Encryption",
                    "severity": "high", "category": "encryption",
                    "description": f"Database instance '{label}' does not have storage encryption enabled.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set storage_encrypted = true and optionally specify kms_key_id.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

            # Check 14: Publicly accessible
            pub_ln = _tf_in_block(blines, r'publicly_accessible\s*=\s*true')
            if pub_ln:
                issues.append({
                    "title": "RDS Instance Publicly Accessible",
                    "severity": "critical", "category": "network_exposure",
                    "description": f"Database '{label}' is publicly accessible, exposing data to the internet.",
                    "evidence": _ev(fname, start + pub_ln - 1),
                    "remediation": "Set publicly_accessible = false and use VPC security groups for access.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

            # Check 15: No IAM DB authentication
            if _tf_not_in_block(blines, r'iam_database_authentication_enabled\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_db_instance') or start
                issues.append({
                    "title": "RDS Instance Missing IAM Authentication",
                    "severity": "low", "category": "iam_misconfiguration",
                    "description": f"Database '{label}' does not use IAM database authentication.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Enable iam_database_authentication_enabled = true to use IAM for DB credentials.",
                    "dread_score": _dread("low"), "points_deducted": _pts("low"),
                })

        # ── EC2 Instance Checks ───────────────────────────────────────

        if "aws_instance" in block_type:
            # Check 16: No IAM instance profile
            if _tf_not_in_block(blines, r'iam_instance_profile'):
                ln = _tf_in_block(blines, r'aws_instance') or start
                issues.append({
                    "title": "EC2 Instance Without IAM Profile",
                    "severity": "medium", "category": "iam_misconfiguration",
                    "description": f"EC2 instance '{label}' has no IAM instance profile, preventing fine-grained AWS access control.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Attach an IAM instance profile with least-privilege permissions.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

            # Check 17: No monitoring / detailed monitoring
            if _tf_not_in_block(blines, r'monitoring\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_instance') or start
                issues.append({
                    "title": "EC2 Instance Missing Detailed Monitoring",
                    "severity": "low", "category": "monitoring",
                    "description": f"EC2 instance '{label}' does not have detailed monitoring enabled.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set monitoring = true for enhanced metrics (additional cost applies).",
                    "dread_score": _dread("low"), "points_deducted": _pts("low"),
                })

            # Check 18: No user data (potentially no hardening)
            if _tf_not_in_block(blines, r'user_data'):
                ln = _tf_in_block(blines, r'aws_instance') or start
                issues.append({
                    "title": "EC2 Instance Without Hardening User Data",
                    "severity": "info", "category": "hardening",
                    "description": f"EC2 instance '{label}' has no user_data script for OS-level hardening.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Add a user_data script to install security updates and configure the OS.",
                    "dread_score": _dread("info"), "points_deducted": _pts("info"),
                })

        # ── EBS Volume Checks ─────────────────────────────────────────

        if "aws_ebs_volume" in block_type:
            # Check 19: No encryption
            if _tf_not_in_block(blines, r'encrypted\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_ebs_volume') or start
                issues.append({
                    "title": "EBS Volume Unencrypted",
                    "severity": "high", "category": "encryption",
                    "description": f"EBS volume '{label}' is not encrypted at rest.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set encrypted = true. For existing volumes, create a snapshot, copy with encryption, and replace.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # ── Lambda Checks ─────────────────────────────────────────────

        if "aws_lambda_function" in block_type:
            # Check 20: No reserved concurrent executions
            if _tf_not_in_block(blines, r'reserved_concurrent_executions'):
                ln = _tf_in_block(blines, r'aws_lambda_function') or start
                issues.append({
                    "title": "Lambda Function Without Concurrency Limit",
                    "severity": "medium", "category": "resource_limit",
                    "description": f"Lambda '{label}' has no reserved_concurrent_executions, risking runaway costs from DoS.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set reserved_concurrent_executions to a reasonable limit.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

            # Check 21: No VPC configuration (internet-facing)
            if _tf_not_in_block(blines, r'vpc_config'):
                ln = _tf_in_block(blines, r'aws_lambda_function') or start
                issues.append({
                    "title": "Lambda Function Not in VPC",
                    "severity": "low", "category": "network_exposure",
                    "description": f"Lambda '{label}' runs in the default VPC with direct internet access.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Place Lambda in a private VPC subnet with VPC endpoints for AWS services.",
                    "dread_score": _dread("low"), "points_deducted": _pts("low"),
                })

        # ── TLS Provider Checks ───────────────────────────────────────

        if "tls" in block_type.lower() and ("provider" in block_type.lower() or "min_protocol_version" in joined.lower()):
            weak_versions = [
                (r'TLSv1[_\s]?0', "TLS 1.0"),
                (r'TLSv1[_\s]?1', "TLS 1.1"),
                (r'SSLv3', "SSL 3.0"),
            ]
            for pat, ver_name in weak_versions:
                ln = _tf_in_block(blines, pat)
                if ln:
                    issues.append({
                        "title": f"TLS Provider with Weak Protocol ({ver_name})",
                        "severity": "high", "category": "weak_crypto",
                        "description": f"TLS provider uses {ver_name}, which has known vulnerabilities (BEAST, POODLE, etc.).",
                        "evidence": _ev(fname, start + ln - 1),
                        "remediation": "Set min_protocol_version = \"TLSv1.2\" or \"TLSv1.3\".",
                        "dread_score": _dread("high"), "points_deducted": _pts("high"),
                    })

        # ── Google Cloud Checks ───────────────────────────────────────

        if "google_compute_firewall" in block_type:
            if re.search(r'0\.0\.0\.0/0', joined):
                ln = _tf_in_block(blines, r'0\.0\.0\.0/0') or start
                issues.append({
                    "title": "GCP Firewall Rule Open to 0.0.0.0/0",
                    "severity": "high", "category": "network_exposure",
                    "description": f"GCP firewall '{label}' allows traffic from 0.0.0.0/0 (entire internet).",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Restrict source_ranges to specific IP ranges or use target tags/service accounts.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        if "google_storage_bucket" in block_type:
            if re.search(r'uniform_bucket_level_access\s*=\s*false', joined):
                ln = _tf_in_block(blines, r'uniform_bucket_level_access') or start
                issues.append({
                    "title": "GCP Storage Bucket Without Uniform Access",
                    "severity": "medium", "category": "storage_misconfiguration",
                    "description": f"GCP bucket '{label}' has uniform_bucket_level_access disabled, allowing ACL-based access.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set uniform_bucket_level_access = true and use IAM for access control.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── Azure Checks ──────────────────────────────────────────────

        if "azurerm_network_security_rule" in block_type:
            if re.search(r'0\.0\.0\.0/0', joined):
                ln = _tf_in_block(blines, r'0\.0\.0\.0/0') or start
                issues.append({
                    "title": "Azure NSG Rule Open to 0.0.0.0/0",
                    "severity": "high", "category": "network_exposure",
                    "description": f"Azure NSG rule '{label}' allows traffic from 0.0.0.0/0.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Restrict source_address_prefix to specific IP ranges.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        if "azurerm_storage_account" in block_type:
            if re.search(r'allow_blob_public_access\s*=\s*true', joined):
                ln = _tf_in_block(blines, r'allow_blob_public_access') or start
                issues.append({
                    "title": "Azure Storage Account Allows Public Blob Access",
                    "severity": "high", "category": "storage_misconfiguration",
                    "description": f"Storage account '{label}' allows public blob access.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set allow_blob_public_access = false.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # ── ECS Task Definition ────────────────────────────────────────

        if "aws_ecs_task_definition" in block_type:
            priv_ln = _tf_in_block(blines, r'privileged\s*=\s*true')
            if priv_ln:
                issues.append({
                    "title": "ECS Task Definition with Privileged Container",
                    "severity": "critical", "category": "container_privilege",
                    "description": "ECS task definition has privileged = true, giving the container full host access.",
                    "evidence": _ev(fname, start + priv_ln - 1),
                    "remediation": "Set privileged = false and grant only specific Linux capabilities.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

        # ── EFS Checks ────────────────────────────────────────────────

        if "aws_efs_file_system" in block_type:
            if _tf_not_in_block(blines, r'encrypted\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_efs_file_system') or start
                issues.append({
                    "title": "EFS File System Unencrypted",
                    "severity": "high", "category": "encryption",
                    "description": f"EFS file system '{label}' is not encrypted at rest.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set encrypted = true.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # ── ElastiCache Checks ────────────────────────────────────────

        if "aws_elasticache_cluster" in block_type:
            if _tf_not_in_block(blines, r'at_rest_encryption_enabled\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_elasticache_cluster') or start
                issues.append({
                    "title": "ElastiCache Cluster Without At-Rest Encryption",
                    "severity": "high", "category": "encryption",
                    "description": f"ElastiCache cluster '{label}' does not encrypt data at rest.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set at_rest_encryption_enabled = true.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

            if _tf_not_in_block(blines, r'transit_encryption_enabled\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_elasticache_cluster') or start
                issues.append({
                    "title": "ElastiCache Cluster Without Transit Encryption",
                    "severity": "high", "category": "encryption",
                    "description": f"ElastiCache cluster '{label}' does not encrypt data in transit.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set transit_encryption_enabled = true.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # ── SNS Topic Checks ──────────────────────────────────────────

        if "aws_sns_topic" in block_type:
            if _tf_not_in_block(blines, r'kms_key_id'):
                ln = _tf_in_block(blines, r'aws_sns_topic') or start
                issues.append({
                    "title": "SNS Topic Without Server-Side Encryption",
                    "severity": "medium", "category": "encryption",
                    "description": f"SNS topic '{label}' has no KMS key for server-side encryption.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Specify kms_key_id to encrypt SNS messages at rest.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── SQS Queue Checks ──────────────────────────────────────────

        if "aws_sqs_queue" in block_type:
            if _tf_not_in_block(blines, r'kms_data_key_reuse_period_seconds|kms_master_key_id|sqs_managed_sse_enabled'):
                ln = _tf_in_block(blines, r'aws_sqs_queue') or start
                issues.append({
                    "title": "SQS Queue Without Encryption",
                    "severity": "medium", "category": "encryption",
                    "description": f"SQS queue '{label}' has no encryption configured.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set sqs_managed_sse_enabled = true or specify kms_master_key_id.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── KMS Key Checks ────────────────────────────────────────────

        if "aws_kms_key" in block_type:
            if _tf_not_in_block(blines, r'enable_key_rotation\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_kms_key') or start
                issues.append({
                    "title": "KMS Key Without Automatic Rotation",
                    "severity": "medium", "category": "key_management",
                    "description": f"KMS key '{label}' does not have automatic key rotation enabled.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set enable_key_rotation = true to automatically rotate the key material.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── Secrets Manager Checks ────────────────────────────────────

        if "aws_secretsmanager_secret" in block_type:
            if _tf_not_in_block(blines, r'rotation_rules'):
                ln = _tf_in_block(blines, r'aws_secretsmanager_secret') or start
                issues.append({
                    "title": "Secrets Manager Secret Without Rotation",
                    "severity": "medium", "category": "secrets_management",
                    "description": f"Secret '{label}' has no automatic rotation configured.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Add a rotation_rules block with AutomaticallyAfterDays (min 1, max 365).",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── CloudTrail Checks ─────────────────────────────────────────

        if "aws_cloudtrail" in block_type:
            if _tf_not_in_block(blines, r'kms_key_id'):
                ln = _tf_in_block(blines, r'aws_cloudtrail') or start
                issues.append({
                    "title": "CloudTrail Without KMS Encryption",
                    "severity": "medium", "category": "encryption",
                    "description": f"CloudTrail '{label}' logs are not encrypted with a customer-managed KMS key.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Specify kms_key_id to encrypt CloudTrail log files with a CMK.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

            if _tf_not_in_block(blines, r'is_multi_region_trail\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_cloudtrail') or start
                issues.append({
                    "title": "CloudTrail Not Multi-Region",
                    "severity": "low", "category": "monitoring",
                    "description": f"CloudTrail '{label}' is not configured as a multi-region trail.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set is_multi_region_trail = true to capture events from all AWS regions.",
                    "dread_score": _dread("low"), "points_deducted": _pts("low"),
                })

            log_file_ln = _tf_in_block(blines, r'enable_log_file_validation\s*=\s*false')
            if log_file_ln:
                issues.append({
                    "title": "CloudTrail Log File Validation Disabled",
                    "severity": "medium", "category": "integrity",
                    "description": "CloudTrail log file validation is disabled, allowing tampering.",
                    "evidence": _ev(fname, start + log_file_ln - 1),
                    "remediation": "Set enable_log_file_validation = true.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── S3 Bucket Object Lock (WORM) ──────────────────────────────

        if "aws_s3_bucket" in block_type and "policy" not in block_type:
            if _tf_not_in_block(blines, r'object_lock_configuration'):
                # Only flag if bucket appears to hold sensitive data
                if re.search(r'(data|backup|log|audit|secret|pii)', label, re.I):
                    ln = _tf_in_block(blines, r'aws_s3_bucket') or start
                    issues.append({
                        "title": f"Sensitive S3 Bucket '{label}' Without Object Lock",
                        "severity": "medium", "category": "data_protection",
                        "description": f"S3 bucket '{label}' (appears sensitive) has no object lock configuration for WORM protection.",
                        "evidence": _ev(fname, start + ln - 1),
                        "remediation": "Add object_lock_configuration with ObjectLockEnabled = Enabled.",
                        "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                    })

        # ── Generic: hardcoded credentials in any block ────────────────

        for idx, line in enumerate(blines):
            if re.search(r'(?:password|secret|token|api_key|private_key)\s*=\s*["\'][^"\']{8,}["\']', line, re.I):
                issues.append({
                    "title": "Hardcoded Secret in Terraform",
                    "severity": "critical", "category": "hardcoded_secret",
                    "description": "A password, secret, or key is hardcoded in the Terraform file.",
                    "evidence": _ev(fname, start + idx),
                    "remediation": "Use variables, SSM Parameter Store, or Vault for secrets. Reference with data sources.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })
                break  # One per block

        # ── AWS Redshift Checks ──────────────────────────────────────

        if "aws_redshift_cluster" in block_type:
            if _tf_not_in_block(blines, r'encrypted\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_redshift_cluster') or start
                issues.append({
                    "title": "Redshift Cluster Unencrypted",
                    "severity": "high", "category": "encryption",
                    "description": f"Redshift cluster '{label}' does not have encryption enabled.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set encrypted = true.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

            if _tf_not_in_block(blines, r'require_ssl\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_redshift_cluster') or start
                issues.append({
                    "title": "Redshift Cluster Without Require SSL",
                    "severity": "medium", "category": "encryption",
                    "description": f"Redshift cluster '{label}' does not require SSL for connections.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set require_ssl = true in the parameter group.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── AWS ALB/NLB Checks ────────────────────────────────────────

        if "aws_lb_listener" in block_type or "aws_alb_listener" in block_type:
            if _tf_not_in_block(blines, r'certificate_arn|default_action.*fixed-response'):
                ln = _tf_in_block(blines, r'aws_lb_listener|aws_alb_listener') or start
                if re.search(r'port\s*=\s*"?80', joined):
                    issues.append({
                        "title": "ALB Listener on HTTP (Port 80) Without Redirect",
                        "severity": "medium", "category": "network_exposure",
                        "description": f"Load balancer listener '{label}' accepts HTTP (port 80) traffic without redirect to HTTPS.",
                        "evidence": _ev(fname, start + ln - 1),
                        "remediation": "Add a redirect action from port 80 to port 443, or use certificate_arn for HTTPS.",
                        "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                    })

        # ── AWS IAM User Login Profile ───────────────────────────────

        if "aws_iam_user_login_profile" in block_type:
            if _tf_not_in_block(blines, r'password_reset_required\s*=\s*true'):
                ln = _tf_in_block(blines, r'aws_iam_user_login_profile') or start
                issues.append({
                    "title": "IAM User Login Without Password Reset Required",
                    "severity": "medium", "category": "iam_misconfiguration",
                    "description": f"IAM user login profile '{label}' does not require password reset on first login.",
                    "evidence": _ev(fname, start + ln - 1),
                    "remediation": "Set password_reset_required = true.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

    return issues


# ══════════════════════════════════════════════════════════════════════
# 2. CLOUDFORMATION / YAML PARSER
# ══════════════════════════════════════════════════════════════════════


def _cf_check_security_group(resource: Dict[str, Any], fname: str) -> List[Dict[str, Any]]:
    """Check CloudFormation SecurityGroup resources."""
    issues: List[Dict[str, Any]] = []
    res_name = resource.get("_cf_name", "unknown")

    props = resource.get("Properties", {})
    if not isinstance(props, dict):
        return issues

    ingress_rules = props.get("SecurityGroupIngress", [])
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]

    for rule in ingress_rules:
        if not isinstance(rule, dict):
            continue
        cidr = rule.get("CidrIp", "")
        if isinstance(cidr, str) and cidr == "0.0.0.0/0":
            port = rule.get("FromPort", "any")
            issues.append({
                "title": f"CloudFormation SecurityGroup Open to Internet (port {port})",
                "severity": "high", "category": "network_exposure",
                "description": f"SecurityGroup '{res_name}' allows ingress from 0.0.0.0/0 on port {port}.",
                "evidence": f"{fname}: {res_name}.SecurityGroupIngress CidrIp=0.0.0.0/0",
                "remediation": "Restrict CidrIp to specific IP ranges or use VPC CIDR.",
                "dread_score": _dread("high"), "points_deducted": _pts("high"),
            })

            # SSH specifically
            if str(port) == "22":
                issues.append({
                    "title": "CloudFormation: SSH (Port 22) Open to Internet",
                    "severity": "critical", "category": "network_exposure",
                    "description": f"SecurityGroup '{res_name}' exposes SSH to the entire internet.",
                    "evidence": f"{fname}: {res_name}.SecurityGroupIngress port 22 CidrIp=0.0.0.0/0",
                    "remediation": "Restrict SSH CidrIp to bastion host or VPN IP range.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

            # RDP specifically
            if str(port) == "3389":
                issues.append({
                    "title": "CloudFormation: RDP (Port 3389) Open to Internet",
                    "severity": "critical", "category": "network_exposure",
                    "description": f"SecurityGroup '{res_name}' exposes RDP to the entire internet.",
                    "evidence": f"{fname}: {res_name}.SecurityGroupIngress port 3389 CidrIp=0.0.0.0/0",
                    "remediation": "Use AWS Systems Manager Session Manager instead of RDP.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

    return issues


def _cf_check_bucket_policy(resource: Dict[str, Any], fname: str) -> List[Dict[str, Any]]:
    """Check CloudFormation S3 BucketPolicy resources."""
    issues: List[Dict[str, Any]] = []
    res_name = resource.get("_cf_name", "unknown")
    props = resource.get("Properties", {})
    if not isinstance(props, dict):
        return issues

    policy_doc = props.get("PolicyDocument", {})
    if not isinstance(policy_doc, dict):
        return issues

    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal", {})
        if isinstance(principal, dict) and principal.get("AWS") == "*":
            issues.append({
                "title": "CloudFormation: S3 BucketPolicy with Wildcard Principal",
                "severity": "critical", "category": "s3_misconfiguration",
                "description": f"BucketPolicy '{res_name}' has Principal: '*' allowing any AWS account access.",
                "evidence": f"{fname}: {res_name} Principal: *",
                "remediation": "Restrict Principal to specific AWS account ARNs.",
                "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
            })

        action = stmt.get("Action", "")
        resource = stmt.get("Resource", "")
        if action == "*" and resource == "*":
            issues.append({
                "title": "CloudFormation: IAM Policy with Full Access",
                "severity": "critical", "category": "iam_misconfiguration",
                "description": f"Policy in '{res_name}' grants Action: '*' on Resource: '*'.",
                "evidence": f"{fname}: {res_name} Action: * Resource: *",
                "remediation": "Apply least-privilege with explicit actions and ARN patterns.",
                "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
            })

    return issues


def _cf_check_rds(resource: Dict[str, Any], fname: str) -> List[Dict[str, Any]]:
    """Check CloudFormation RDS resources."""
    issues: List[Dict[str, Any]] = []
    res_name = resource.get("_cf_name", "unknown")
    props = resource.get("Properties", {})
    if not isinstance(props, dict):
        return issues

    if not props.get("StorageEncrypted", False):
        issues.append({
            "title": "CloudFormation: RDS Instance Unencrypted",
            "severity": "high", "category": "encryption",
            "description": f"RDS instance '{res_name}' does not have StorageEncrypted enabled.",
            "evidence": f"{fname}: {res_name} StorageEncrypted not set",
            "remediation": 'Set StorageEncrypted: true in the RDS resource properties.',
            "dread_score": _dread("high"), "points_deducted": _pts("high"),
        })

    if props.get("PubliclyAccessible", False):
        issues.append({
            "title": "CloudFormation: RDS Instance Publicly Accessible",
            "severity": "critical", "category": "network_exposure",
            "description": f"RDS instance '{res_name}' is PubliclyAccessible.",
            "evidence": f"{fname}: {res_name} PubliclyAccessible: true",
            "remediation": 'Set PubliclyAccessible: false.',
            "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
        })

    return issues


def _cf_check_s3_bucket(resource: Dict[str, Any], fname: str) -> List[Dict[str, Any]]:
    """Check CloudFormation S3 Bucket resources."""
    issues: List[Dict[str, Any]] = []
    res_name = resource.get("_cf_name", "unknown")
    props = resource.get("Properties", {})
    if not isinstance(props, dict):
        return issues

    acl = props.get("AccessControl", "")
    if acl in ("PublicRead", "PublicReadWrite"):
        sev = "high" if acl == "PublicRead" else "critical"
        issues.append({
            "title": f"CloudFormation: S3 Bucket with {acl} ACL",
            "severity": sev, "category": "s3_misconfiguration",
            "description": f"S3 bucket '{res_name}' has AccessControl: {acl}.",
            "evidence": f"{fname}: {res_name} AccessControl: {acl}",
            "remediation": 'Set AccessControl: Private and use bucket policies for access.',
            "dread_score": _dread(sev), "points_deducted": _pts(sev),
        })

    if not props.get("BucketEncryption"):
        issues.append({
            "title": "CloudFormation: S3 Bucket Without Encryption",
            "severity": "medium", "category": "encryption",
            "description": f"S3 bucket '{res_name}' has no BucketEncryption property.",
            "evidence": f"{fname}: {res_name} missing BucketEncryption",
            "remediation": "Add BucketEncryption with ServerSideEncryptionConfiguration.",
            "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
        })

    versioning = props.get("VersioningConfiguration", {})
    if not isinstance(versioning, dict) or not versioning.get("Status"):
        issues.append({
            "title": "CloudFormation: S3 Bucket Without Versioning",
            "severity": "medium", "category": "s3_misconfiguration",
            "description": f"S3 bucket '{res_name}' has no VersioningConfiguration enabled.",
            "evidence": f"{fname}: {res_name} missing VersioningConfiguration",
            "remediation": "Add VersioningConfiguration with Status: Enabled.",
            "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
        })

    return issues


def _cf_check_iam(resource: Dict[str, Any], fname: str) -> List[Dict[str, Any]]:
    """Check CloudFormation IAM resources."""
    issues: List[Dict[str, Any]] = []
    res_name = resource.get("_cf_name", "unknown")
    props = resource.get("Properties", {})
    if not isinstance(props, dict):
        return issues

    policies = props.get("Policies", [])
    if not isinstance(policies, list):
        policies = [policies]

    for pol in policies:
        if not isinstance(pol, dict):
            continue
        pol_doc = pol.get("PolicyDocument", {})
        if not isinstance(pol_doc, dict):
            continue
        statements = pol_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            action = stmt.get("Action", "")
            resource = stmt.get("Resource", "")
            if action == "*" and resource == "*":
                issues.append({
                    "title": "CloudFormation: IAM ManagedPolicy with Full Access",
                    "severity": "critical", "category": "iam_misconfiguration",
                    "description": f"IAM role/policy '{res_name}' has a statement with Action: '*' and Resource: '*'.",
                    "evidence": f"{fname}: {res_name} Policy Action: * Resource: *",
                    "remediation": "Replace wildcard with explicit actions and resource ARNs.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

    # Check ManagedPolicyDocument directly
    doc = props.get("PolicyDocument", {})
    if isinstance(doc, dict):
        statements = doc.get("Statement", [])
        if isinstance(statements, list):
            for stmt in statements:
                if isinstance(stmt, dict):
                    action = stmt.get("Action", "")
                    resource = stmt.get("Resource", "")
                    if action == "*" and resource == "*":
                        issues.append({
                            "title": "CloudFormation: ManagedPolicyDocument with Full Access",
                            "severity": "critical", "category": "iam_misconfiguration",
                            "description": f"Policy '{res_name}' grants full admin access via PolicyDocument.",
                            "evidence": f"{fname}: {res_name} PolicyDocument Action: * Resource: *",
                            "remediation": "Apply least-privilege: specify explicit actions and resource ARNs.",
                            "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                        })

    return issues


def parse_cf_file(path: str) -> List[Dict[str, Any]]:
    """Parse a CloudFormation YAML/JSON template and return a list of issue dicts."""
    issues: List[Dict[str, Any]] = []
    fname = os.path.basename(path)

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return issues

    template = _simple_yaml_load(text)
    if not isinstance(template, dict):
        return issues

    resources = template.get("Resources", {})
    if not isinstance(resources, dict):
        return issues

    for res_name, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        resource["_cf_name"] = res_name
        res_type = str(resource.get("Type", ""))

        if "SecurityGroup" in res_type:
            issues.extend(_cf_check_security_group(resource, fname))
        if "BucketPolicy" in res_type:
            issues.extend(_cf_check_bucket_policy(resource, fname))
        if "DBInstance" in res_type or "RDS" in res_type:
            issues.extend(_cf_check_rds(resource, fname))
        if res_type == "AWS::S3::Bucket":
            issues.extend(_cf_check_s3_bucket(resource, fname))
        if "IAM" in res_type and ("Role" in res_type or "Policy" in res_type or "User" in res_type):
            issues.extend(_cf_check_iam(resource, fname))

        # Generic: Lambda without VPC
        if "Lambda" in res_type and "Function" in res_type:
            props = resource.get("Properties", {})
            if isinstance(props, dict) and not props.get("VpcConfig"):
                issues.append({
                    "title": f"CloudFormation: Lambda '{res_name}' Not in VPC",
                    "severity": "low", "category": "network_exposure",
                    "description": f"Lambda function '{res_name}' has no VpcConfig, running with direct internet access.",
                    "evidence": f"{fname}: {res_name} missing VpcConfig",
                    "remediation": "Add VpcConfig with SubnetIds and SecurityGroupIds.",
                    "dread_score": _dread("low"), "points_deducted": _pts("low"),
                })

        # EC2 Instance without IAM instance profile
        if res_type == "AWS::EC2::Instance":
            props = resource.get("Properties", {})
            if isinstance(props, dict) and not props.get("IamInstanceProfile"):
                issues.append({
                    "title": f"CloudFormation: EC2 '{res_name}' Without IAM Profile",
                    "severity": "medium", "category": "iam_misconfiguration",
                    "description": f"EC2 instance '{res_name}' has no IamInstanceProfile for fine-grained AWS access.",
                    "evidence": f"{fname}: {res_name} missing IamInstanceProfile",
                    "remediation": "Add an IamInstanceProfile property referencing an IAM instance profile.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # SecurityGroup missing egress
        if "SecurityGroup" in res_type and "Ingress" not in res_type:
            props = resource.get("Properties", {})
            if isinstance(props, dict):
                has_egress = props.get("SecurityGroupEgress", [])
                if not has_egress:
                    issues.append({
                        "title": f"CloudFormation: SecurityGroup '{res_name}' Missing Egress Rules",
                        "severity": "medium", "category": "network_exposure",
                        "description": f"SecurityGroup '{res_name}' has no egress rules, defaulting to allow all outbound.",
                        "evidence": f"{fname}: {res_name} missing SecurityGroupEgress",
                        "remediation": "Add explicit SecurityGroupEgress rules to restrict outbound traffic.",
                        "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                    })

    return issues


# ══════════════════════════════════════════════════════════════════════
# 3. DOCKERFILE ANALYZER
# ══════════════════════════════════════════════════════════════════════


# Sensitive file patterns that should never be COPY/ADDed
_SENSITIVE_FILE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\.env", re.I), ".env file"),
    (re.compile(r"\.aws", re.I), ".aws credentials directory"),
    (re.compile(r"(id_rsa|id_dsa|id_ecdsa|id_ed25519)", re.I), "SSH private key"),
    (re.compile(r"\.ssh", re.I), ".ssh directory"),
    (re.compile(r"\.npmrc", re.I), ".npmrc (may contain auth tokens)"),
    (re.compile(r"\.pem", re.I), ".pem certificate/key file"),
    (re.compile(r"\.key", re.I), ".key private key file"),
    (re.compile(r"\.p12|\.pfx", re.I), "PKCS#12 certificate bundle"),
    (re.compile(r"credentials\.json|service-account", re.I), "GCP service account credentials"),
]

# Secret environment variable patterns
_SECRET_ENV_PATTERNS = re.compile(
    r'(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_KEY)'
    r'\s*=\s*["\x27]\S{1,}["\x27]',
    re.I,
)

# Dangerous ports to expose
_DANGEROUS_PORTS: Dict[str, str] = {
    "22": "SSH",
    "2375": "Docker daemon (unencrypted)",
    "2376": "Docker daemon (TLS)",
    "6379": "Redis",
    "27017": "MongoDB",
    "5432": "PostgreSQL",
    "3306": "MySQL",
    "9200": "Elasticsearch",
    "11211": "Memcached",
}


def parse_dockerfile(path: str) -> List[Dict[str, Any]]:
    """Parse a Dockerfile and return a list of issue dicts."""
    issues: List[Dict[str, Any]] = []
    fname = os.path.basename(path)

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return issues

    lines = text.splitlines()
    has_user = False
    has_healthcheck = False
    has_from = False
    from_line = 0
    user_line_num = 0

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        ln = idx + 1

        # ── FROM checks ───────────────────────────────────────────────
        if stripped.upper().startswith("FROM "):
            has_from = True
            from_line = ln
            from_val = stripped[5:].strip()

            # Check: FROM scratch
            if from_val.lower() == "scratch":
                issues.append({
                    "title": "Dockerfile Uses FROM scratch",
                    "severity": "medium", "category": "container_image",
                    "description": "FROM scratch produces a minimal image but provides no package management or shell for debugging.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Use a minimal base like alpine or distroless if possible.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })
            # Check: FROM without tag (mutable image)
            elif ":" not in from_val.split("@")[0]:
                issues.append({
                    "title": "Dockerfile FROM Without Specific Tag",
                    "severity": "medium", "category": "container_image",
                    "description": f"Base image '{from_val}' has no specific tag, using 'latest' which is mutable.",
                    "evidence": _ev(fname, ln),
                    "remediation": f"Pin the image: {from_val}:<specific-tag> or use a digest @{from_val}@sha256:...",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })
            # Check: FROM using :latest tag
            elif from_val.endswith(":latest"):
                issues.append({
                    "title": "Dockerfile FROM Uses :latest Tag",
                    "severity": "medium", "category": "container_image",
                    "description": f"Base image uses ':latest' tag which is mutable and non-reproducible.",
                    "evidence": _ev(fname, ln),
                    "remediation": f"Pin to a specific version tag instead of :latest.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

        # ── USER checks ───────────────────────────────────────────────
        if stripped.upper().startswith("USER "):
            user_val = stripped[5:].strip()
            has_user = True
            user_line_num = ln

            if user_val in ("root", "0"):
                issues.append({
                    "title": "Dockerfile Explicitly Runs as Root",
                    "severity": "high", "category": "container_privilege",
                    "description": "USER root/0 is explicitly set, running the container with full root privileges.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Create a non-root user and set USER <username>.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # ── COPY / ADD checks ─────────────────────────────────────────
        if stripped.upper().startswith(("COPY ", "ADD ")):
            # Check for sensitive files
            for pat, desc in _SENSITIVE_FILE_PATTERNS:
                if pat.search(stripped):
                    issues.append({
                        "title": f"Dockerfile Copies Sensitive File ({desc})",
                        "severity": "critical", "category": "secrets_leak",
                        "description": f"COPY or ADD instruction includes {desc} in the image.",
                        "evidence": _ev(fname, ln),
                        "remediation": f"Do not copy {desc} into the image. Use runtime secrets or multi-stage builds.",
                        "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                    })
                    break

            # Check: ADD with remote URL (supply chain risk)
            if re.search(r'ADD\s+https?://', stripped, re.I):
                issues.append({
                    "title": "Dockerfile ADD from Remote URL",
                    "severity": "high", "category": "supply_chain",
                    "description": "ADD instruction fetches from a remote URL, creating a supply chain risk.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Use RUN curl/wget with checksum verification instead of ADD for remote URLs.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # ── ENV checks ────────────────────────────────────────────────
        if stripped.upper().startswith("ENV "):
            env_val = stripped[4:].strip()
            if _SECRET_ENV_PATTERNS.search(env_val):
                issues.append({
                    "title": "Dockerfile ENV Contains Secret",
                    "severity": "high", "category": "hardcoded_secret",
                    "description": "An ENV variable appears to contain a hardcoded secret/password/token.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Use Docker secrets, Kubernetes secrets, or runtime environment injection.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # ── RUN checks ────────────────────────────────────────────────
        if stripped.upper().startswith("RUN "):
            run_val = stripped[4:].strip()

            # curl|wget piped to bash/sh
            if re.search(r'(?:curl|wget)\s+.*\|\s*(?:ba)?sh', run_val):
                issues.append({
                    "title": "Dockerfile RUN Pipes Remote Script to Shell",
                    "severity": "high", "category": "supply_chain",
                    "description": "RUN instruction pipes curl/wget output directly to shell — supply chain risk.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Download the script first, verify its checksum, then execute it.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

            # --privileged in RUN (docker run inside docker)
            if "--privileged" in run_val:
                issues.append({
                    "title": "Dockerfile RUN with --privileged Flag",
                    "severity": "critical", "category": "container_privilege",
                    "description": "RUN instruction uses --privileged, granting full host access to the build container.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Remove --privileged flag. Grant only specific capabilities.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

            # Running as root in RUN (sudo/su)
            if re.search(r'\b(?:sudo|su\s)\b', run_val):
                issues.append({
                    "title": "Dockerfile RUN Uses sudo/su",
                    "severity": "medium", "category": "container_privilege",
                    "description": "RUN uses sudo/su, indicating the container may need root privileges at runtime.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Avoid sudo/su. If root is needed for install, switch back to non-root user.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })

            # apt-get without no-install-recommends
            if re.search(r'apt-get\s+install', run_val) and "--no-install-recommends" not in run_val:
                issues.append({
                    "title": "Dockerfile apt-get Without --no-install-recommends",
                    "severity": "low", "category": "image_size",
                    "description": "apt-get install without --no-install-recommends increases image size and attack surface.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Add --no-install-recommends to apt-get install and combine RUN layers.",
                    "dread_score": _dread("low"), "points_deducted": _pts("low"),
                })

            # apt-get update without cache cleanup in same layer
            if re.search(r'apt-get\s+update', run_val) and not re.search(r'rm\s+-rf\s+/var/lib/apt', run_val):
                issues.append({
                    "title": "Dockerfile apt-get Cache Not Cleaned",
                    "severity": "low", "category": "image_size",
                    "description": "apt-get update without cache cleanup in the same layer increases image size.",
                    "evidence": _ev(fname, ln),
                    "remediation": "Add '&& rm -rf /var/lib/apt/lists/*' in the same RUN instruction.",
                    "dread_score": _dread("low"), "points_deducted": _pts("low"),
                })

        # ── EXPOSE checks ─────────────────────────────────────────────
        if stripped.upper().startswith("EXPOSE "):
            ports = stripped[7:].strip().split()
            for port in ports:
                port_clean = port.split("/")[0]
                if port_clean in _DANGEROUS_PORTS:
                    svc = _DANGEROUS_PORTS[port_clean]
                    issues.append({
                        "title": f"Dockerfile Exposes {svc} (Port {port_clean})",
                        "severity": "medium", "category": "network_exposure",
                        "description": f"Dockerfile exposes port {port_clean} ({svc}) which should not be publicly accessible.",
                        "evidence": _ev(fname, ln),
                        "remediation": f"Do not EXPOSE {svc} in production. Use Docker networks for internal communication.",
                        "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                    })

        # ── HEALTHCHECK checks ────────────────────────────────────────
        if stripped.upper().startswith("HEALTHCHECK"):
            has_healthcheck = True

    # ── Post-scan checks ──────────────────────────────────────────────

    # Check: No USER directive (runs as root)
    if has_from and not has_user:
        issues.append({
            "title": "Dockerfile Has No USER Directive (Runs as Root)",
            "severity": "high", "category": "container_privilege",
            "description": "No USER instruction found — the container process runs as root by default.",
            "evidence": _ev(fname, from_line or 1),
            "remediation": "Add 'USER <non-root-user>' before the ENTRYPOINT/CMD.",
            "dread_score": _dread("high"), "points_deducted": _pts("high"),
        })

    # Check: No HEALTHCHECK
    if has_from and not has_healthcheck:
        issues.append({
            "title": "Dockerfile Has No HEALTHCHECK Instruction",
            "severity": "low", "category": "monitoring",
            "description": "No HEALTHCHECK instruction — the orchestrator cannot determine if the container is healthy.",
            "evidence": _ev(fname, 1),
            "remediation": "Add a HEALTHCHECK instruction (e.g., HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1).",
            "dread_score": _dread("low"), "points_deducted": _pts("low"),
        })

    # Check: No .dockerignore (info-level — check if .dockerignore exists alongside)
    parent = Path(path).parent
    dockerignore = parent / ".dockerignore"
    if parent.exists() and not dockerignore.exists():
        issues.append({
            "title": "No .dockerignore File Detected",
            "severity": "info", "category": "best_practice",
            "description": "No .dockerignore found in the Dockerfile's directory — sensitive files may be included in the build context.",
            "evidence": _ev(fname, 1),
            "remediation": "Create a .dockerignore file excluding .git, .env, *.pem, node_modules, etc.",
            "dread_score": _dread("info"), "points_deducted": _pts("info"),
        })

    return issues


# ══════════════════════════════════════════════════════════════════════
# 4. KUBERNETES MANIFEST ANALYZER
# ══════════════════════════════════════════════════════════════════════


def _k8s_get_containers(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract all container definitions from a K8s manifest."""
    containers: List[Dict[str, Any]] = []
    spec = doc.get("spec", {})
    if not isinstance(spec, dict):
        return containers

    for c in spec.get("containers", []):
        if isinstance(c, dict):
            containers.append(c)
    for c in spec.get("initContainers", []):
        if isinstance(c, dict):
            containers.append(c)
    return containers


def _k8s_get_pods(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract pod specs from a K8s manifest (handles Deployments, StatefulSets, etc.)."""
    specs: List[Dict[str, Any]] = []
    spec = doc.get("spec", {})
    if not isinstance(spec, dict):
        return specs

    # Direct Pod spec
    if spec.get("containers") or spec.get("initContainers"):
        specs.append(spec)
    # Template spec (Deployment, StatefulSet, DaemonSet, Job, CronJob)
    template = spec.get("template", {})
    if isinstance(template, dict):
        pod_spec = template.get("spec", {})
        if isinstance(pod_spec, dict) and (pod_spec.get("containers") or pod_spec.get("initContainers")):
            specs.append(pod_spec)
        # CronJob nested template
        job_spec = template.get("spec", {})
        if isinstance(job_spec, dict):
            inner_template = job_spec.get("template", {})
            if isinstance(inner_template, dict):
                inner_spec = inner_template.get("spec", {})
                if isinstance(inner_spec, dict) and (inner_spec.get("containers") or inner_spec.get("initContainers")):
                    specs.append(inner_spec)

    return specs


def _k8s_check_security_context(pod_spec: Dict[str, Any], doc_name: str, fname: str) -> List[Dict[str, Any]]:
    """Check pod and container security contexts."""
    issues: List[Dict[str, Any]] = []

    # Pod-level security context
    pod_sc = pod_spec.get("securityContext", {})
    if not isinstance(pod_sc, dict):
        pod_sc = {}

    # Check: privileged at pod level
    if pod_sc.get("privileged") is True:
        issues.append({
            "title": f"K8s: '{doc_name}' Pod securityContext.privileged=true",
            "severity": "critical", "category": "container_privilege",
            "description": f"Pod '{doc_name}' has privileged=true at pod level — full host access.",
            "evidence": f"{fname}: {doc_name} securityContext.privileged: true",
            "remediation": "Remove privileged: true. Grant only specific Linux capabilities.",
            "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
        })

    # Check: allowPrivilegeEscalation at pod level
    if pod_sc.get("allowPrivilegeEscalation") is True:
        issues.append({
            "title": f"K8s: '{doc_name}' Pod allowPrivilegeEscalation=true",
            "severity": "high", "category": "container_privilege",
            "description": f"Pod '{doc_name}' allows privilege escalation.",
            "evidence": f"{fname}: {doc_name} allowPrivilegeEscalation: true",
            "remediation": "Set allowPrivilegeEscalation: false.",
            "dread_score": _dread("high"), "points_deducted": _pts("high"),
        })

    # Check: runAsUser: 0 at pod level
    if pod_sc.get("runAsUser") == 0:
        issues.append({
            "title": f"K8s: '{doc_name}' Pod Runs as Root (runAsUser: 0)",
            "severity": "high", "category": "container_privilege",
            "description": f"Pod '{doc_name}' explicitly runs as root (runAsUser: 0).",
            "evidence": f"{fname}: {doc_name} runAsUser: 0",
            "remediation": "Set runAsUser to a non-zero UID (e.g., 1000).",
            "dread_score": _dread("high"), "points_deducted": _pts("high"),
        })

    # Check: readOnlyRootFilesystem not true at pod level
    if pod_sc.get("readOnlyRootFilesystem") is not True and "readOnlyRootFilesystem" in str(pod_sc):
        pass  # explicitly false — handled below
    elif "readOnlyRootFilesystem" not in pod_sc and pod_sc:
        issues.append({
            "title": f"K8s: '{doc_name}' Pod Writable Root Filesystem",
            "severity": "medium", "category": "container_hardening",
            "description": f"Pod '{doc_name}' does not set readOnlyRootFilesystem: true.",
            "evidence": f"{fname}: {doc_name} missing readOnlyRootFilesystem: true",
            "remediation": "Set readOnlyRootFilesystem: true in securityContext.",
            "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
        })

    # Container-level checks
    for container in _k8s_get_containers_from_spec(pod_spec):
        cname = container.get("name", "<unnamed>")
        csc = container.get("securityContext", {})
        if not isinstance(csc, dict):
            csc = {}

        # Privileged at container level
        if csc.get("privileged") is True:
            issues.append({
                "title": f"K8s: '{doc_name}/{cname}' Container privileged=true",
                "severity": "critical", "category": "container_privilege",
                "description": f"Container '{cname}' in '{doc_name}' has privileged=true — full host access.",
                "evidence": f"{fname}: {doc_name}/{cname} securityContext.privileged: true",
                "remediation": "Remove privileged: true. Grant only specific Linux capabilities.",
                "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
            })

        # allowPrivilegeEscalation at container level
        if csc.get("allowPrivilegeEscalation") is True:
            issues.append({
                "title": f"K8s: '{doc_name}/{cname}' allowPrivilegeEscalation=true",
                "severity": "high", "category": "container_privilege",
                "description": f"Container '{cname}' allows privilege escalation.",
                "evidence": f"{fname}: {doc_name}/{cname} allowPrivilegeEscalation: true",
                "remediation": "Set allowPrivilegeEscalation: false.",
                "dread_score": _dread("high"), "points_deducted": _pts("high"),
            })

        # runAsUser: 0 at container level
        if csc.get("runAsUser") == 0:
            issues.append({
                "title": f"K8s: '{doc_name}/{cname}' Runs as Root (runAsUser: 0)",
                "severity": "high", "category": "container_privilege",
                "description": f"Container '{cname}' explicitly runs as root.",
                "evidence": f"{fname}: {doc_name}/{cname} runAsUser: 0",
                "remediation": "Set runAsUser to a non-zero UID.",
                "dread_score": _dread("high"), "points_deducted": _pts("high"),
            })

        # Writable root filesystem at container level
        if csc.get("readOnlyRootFilesystem") is not True and pod_sc.get("readOnlyRootFilesystem") is not True:
            issues.append({
                "title": f"K8s: '{doc_name}/{cname}' Writable Root Filesystem",
                "severity": "medium", "category": "container_hardening",
                "description": f"Container '{cname}' has a writable root filesystem.",
                "evidence": f"{fname}: {doc_name}/{cname} missing readOnlyRootFilesystem: true",
                "remediation": "Set readOnlyRootFilesystem: true and use emptyDir for writable paths.",
                "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
            })

        # Capabilities check
        cap = csc.get("capabilities", {})
        if isinstance(cap, dict):
            adds = cap.get("add", [])
            if isinstance(adds, list):
                dangerous_caps = ["ALL", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
                                  "DAC_OVERRIDE", "NET_ADMIN", "SYSLOG", "KILL"]
                for c in adds:
                    if c in dangerous_caps:
                        sev = "critical" if c == "ALL" else "high"
                        issues.append({
                            "title": f"K8s: '{doc_name}/{cname}' Adds Capability {c}",
                            "severity": sev, "category": "container_privilege",
                            "description": f"Container '{cname}' adds Linux capability {c}, expanding its privilege.",
                            "evidence": f"{fname}: {doc_name}/{cname} capabilities.add: [{c}]",
                            "remediation": f"Remove {c} from capabilities.add. Drop all capabilities and add only those needed.",
                            "dread_score": _dread(sev), "points_deducted": _pts(sev),
                        })

        # No resource limits
        resources = container.get("resources", {})
        if isinstance(resources, dict):
            limits = resources.get("limits", {})
            if not limits:
                issues.append({
                    "title": f"K8s: '{doc_name}/{cname}' No Resource Limits",
                    "severity": "medium", "category": "resource_limit",
                    "description": f"Container '{cname}' has no resource limits — can consume all node resources.",
                    "evidence": f"{fname}: {doc_name}/{cname} missing resources.limits",
                    "remediation": "Set resources.limits for cpu and memory.",
                    "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                })
            else:
                # Check for no memory limit specifically
                if not limits.get("memory"):
                    issues.append({
                        "title": f"K8s: '{doc_name}/{cname}' No Memory Limit",
                        "severity": "medium", "category": "resource_limit",
                        "description": f"Container '{cname}' has resource limits but no memory limit.",
                        "evidence": f"{fname}: {doc_name}/{cname} resources.limits missing memory",
                        "remediation": "Set resources.limits.memory (e.g., '256Mi').",
                        "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                    })
                # Check for no CPU limit
                if not limits.get("cpu"):
                    issues.append({
                        "title": f"K8s: '{doc_name}/{cname}' No CPU Limit",
                        "severity": "low", "category": "resource_limit",
                        "description": f"Container '{cname}' has no CPU limit.",
                        "evidence": f"{fname}: {doc_name}/{cname} resources.limits missing cpu",
                        "remediation": "Set resources.limits.cpu (e.g., '500m').",
                        "dread_score": _dread("low"), "points_deducted": _pts("low"),
                    })

        # Secrets in env (plain text) vs envFrom/secretRef
        env_list = container.get("env", [])
        if isinstance(env_list, list):
            secret_env_names = []
            for env_var in env_list:
                if isinstance(env_var, dict):
                    name = env_var.get("name", "")
                    value = env_var.get("value", "")
                    if value and re.search(r'(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)', name, re.I):
                        secret_env_names.append(name)
            if secret_env_names:
                issues.append({
                    "title": f"K8s: '{doc_name}/{cname}' Secrets in Plain ENV",
                    "severity": "high", "category": "secrets_management",
                    "description": f"Container '{cname}' has secret values in plain env: {', '.join(secret_env_names[:3])}",
                    "evidence": f"{fname}: {doc_name}/{cname} env contains secrets",
                    "remediation": "Use envFrom with a SecretRef or use valueFrom.secretKeyRef.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

        # imagePullPolicy: Always (supply chain risk)
        pull_policy = container.get("imagePullPolicy", "")
        if pull_policy == "Always":
            issues.append({
                "title": f"K8s: '{doc_name}/{cname}' imagePullPolicy: Always",
                "severity": "low", "category": "supply_chain",
                "description": f"Container '{cname}' uses imagePullPolicy: Always, pulling latest on every pod start.",
                "evidence": f"{fname}: {doc_name}/{cname} imagePullPolicy: Always",
                "remediation": "Use imagePullPolicy: IfNotPresent with pinned image tags, or verify image digests.",
                "dread_score": _dread("low"), "points_deducted": _pts("low"),
            })

    return issues


def _k8s_get_containers_from_spec(pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract containers from a pod spec."""
    containers: List[Dict[str, Any]] = []
    for c in pod_spec.get("containers", []):
        if isinstance(c, dict):
            containers.append(c)
    for c in pod_spec.get("initContainers", []):
        if isinstance(c, dict):
            containers.append(c)
    return containers


def _k8s_check_host_settings(pod_spec: Dict[str, Any], doc_name: str, fname: str) -> List[Dict[str, Any]]:
    """Check host namespace and IPC settings."""
    issues: List[Dict[str, Any]] = []

    if pod_spec.get("hostPID") is True:
        issues.append({
            "title": f"K8s: '{doc_name}' hostPID=true",
            "severity": "high", "category": "container_privilege",
            "description": f"Pod '{doc_name}' shares the host's PID namespace — can see all host processes.",
            "evidence": f"{fname}: {doc_name} hostPID: true",
            "remediation": "Set hostPID: false (or remove it, as false is default).",
            "dread_score": _dread("high"), "points_deducted": _pts("high"),
        })

    if pod_spec.get("hostNetwork") is True:
        issues.append({
            "title": f"K8s: '{doc_name}' hostNetwork=true",
            "severity": "high", "category": "network_exposure",
            "description": f"Pod '{doc_name}' uses the host's network namespace — bypasses network policies.",
            "evidence": f"{fname}: {doc_name} hostNetwork: true",
            "remediation": "Set hostNetwork: false and use CNI networking.",
            "dread_score": _dread("high"), "points_deducted": _pts("high"),
        })

    if pod_spec.get("hostIPC") is True:
        issues.append({
            "title": f"K8s: '{doc_name}' hostIPC=true",
            "severity": "medium", "category": "container_privilege",
            "description": f"Pod '{doc_name}' shares the host's IPC namespace — potential information leakage.",
            "evidence": f"{fname}: {doc_name} hostIPC: true",
            "remediation": "Set hostIPC: false (or remove it, as false is default).",
            "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
        })

    return issues


def _k8s_check_volumes(pod_spec: Dict[str, Any], doc_name: str, fname: str) -> List[Dict[str, Any]]:
    """Check volume mounts for dangerous host paths."""
    issues: List[Dict[str, Any]] = []

    for container in _k8s_get_containers_from_spec(pod_spec):
        cname = container.get("name", "<unnamed>")
        mounts = container.get("volumeMounts", [])
        if not isinstance(mounts, list):
            continue

        for mount in mounts:
            if not isinstance(mount, dict):
                continue
            mpath = mount.get("mountPath", "")

            # Docker socket
            if "/var/run/docker.sock" in mpath:
                issues.append({
                    "title": f"K8s: '{doc_name}/{cname}' Mounts Docker Socket",
                    "severity": "critical", "category": "container_privilege",
                    "description": f"Container '{cname}' mounts /var/run/docker.sock — full host container escape.",
                    "evidence": f"{fname}: {doc_name}/{cname} mountPath: {mpath}",
                    "remediation": "Never mount docker.sock into workloads. Use Kubernetes APIs directly.",
                    "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                })

            # Root filesystem mounts
            dangerous_roots = ["/", "/etc", "/root", "/var", "/usr", "/bin", "/sbin", "/lib"]
            if mpath in dangerous_roots:
                issues.append({
                    "title": f"K8s: '{doc_name}/{cname}' Mounts Host Path {mpath}",
                    "severity": "high", "category": "container_privilege",
                    "description": f"Container '{cname}' mounts host path '{mpath}' — potential host file access/tampering.",
                    "evidence": f"{fname}: {doc_name}/{cname} mountPath: {mpath}",
                    "remediation": f"Avoid mounting host path '{mpath}'. Use ConfigMaps, Secrets, or emptyDir instead.",
                    "dread_score": _dread("high"), "points_deducted": _pts("high"),
                })

    return issues


def _k8s_check_service_account(pod_spec: Dict[str, Any], doc_name: str, fname: str) -> List[Dict[str, Any]]:
    """Check service account token settings."""
    issues: List[Dict[str, Any]] = []

    auto_mount = pod_spec.get("automountServiceAccountToken")
    if auto_mount is True:
        issues.append({
            "title": f"K8s: '{doc_name}' automountServiceAccountToken=true",
            "severity": "medium", "category": "iam_misconfiguration",
            "description": f"Pod '{doc_name}' auto-mounts the service account token — exposed to the container.",
            "evidence": f"{fname}: {doc_name} automountServiceAccountToken: true",
            "remediation": "Set automountServiceAccountToken: false unless the pod needs to call the K8s API.",
            "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
        })

    return issues


def _k8s_check_tolerations(pod_spec: Dict[str, Any], doc_name: str, fname: str) -> List[Dict[str, Any]]:
    """Check for overly permissive tolerations."""
    issues: List[Dict[str, Any]] = []

    tolerations = pod_spec.get("tolerations", [])
    if not isinstance(tolerations, list):
        return issues

    for tol in tolerations:
        if not isinstance(tol, dict):
            continue
        operator = tol.get("operator", "")
        effect = tol.get("effect", "")
        key = tol.get("key", "")
        if operator == "Exists" and not key:
            sev = "medium" if effect else "high"
            effect_desc = f" with effect '{effect}'" if effect else ""
            issues.append({
                "title": f"K8s: '{doc_name}' Toleration With operator=Exists (No Key)",
                "severity": sev, "category": "scheduling",
                "description": f"Pod '{doc_name}' tolerates all taints{effect_desc} — may schedule on dedicated/master nodes.",
                "evidence": f"{fname}: {doc_name} toleration operator: Exists, key: (empty)",
                "remediation": "Specify a specific taint key or restrict tolerations to known taints.",
                "dread_score": _dread(sev), "points_deducted": _pts(sev),
            })

    return issues


def parse_k8s_yaml(path: str) -> List[Dict[str, Any]]:
    """Parse a Kubernetes YAML manifest and return a list of issue dicts."""
    issues: List[Dict[str, Any]] = []
    fname = os.path.basename(path)

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return issues

    docs = _yaml_load_all(text)

    for doc in docs:
        if not isinstance(doc, dict):
            continue

        kind = str(doc.get("kind", ""))
        metadata = doc.get("metadata", {})
        doc_name = metadata.get("name", "<unnamed>") if isinstance(metadata, dict) else "<unnamed>"

        pod_specs = _k8s_get_pods(doc)
        if not pod_specs:
            continue

        for pod_spec in pod_specs:
            # Security context checks
            issues.extend(_k8s_check_security_context(pod_spec, doc_name, fname))
            # Host namespace checks
            issues.extend(_k8s_check_host_settings(pod_spec, doc_name, fname))
            # Volume mount checks
            issues.extend(_k8s_check_volumes(pod_spec, doc_name, fname))
            # Service account checks
            issues.extend(_k8s_check_service_account(pod_spec, doc_name, fname))
            # Toleration checks
            issues.extend(_k8s_check_tolerations(pod_spec, doc_name, fname))

    return issues


# ══════════════════════════════════════════════════════════════════════
# 5. RUN FUNCTION
# ══════════════════════════════════════════════════════════════════════


# File extensions and names we scan
_TF_EXTS = {".tf", ".tfstate", ".tfvars"}
_CF_EXTS = {".yaml", ".yml", ".json"}
_DOCKERFILE_NAMES = {"Dockerfile", "dockerfile", "DockerFile"}
_DOCKER_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "docker-compose"}


def _is_likely_cloudformation(path: Path, text: str) -> bool:
    """Heuristic to determine if a YAML/JSON file is a CloudFormation template."""
    if re.search(r'AWSTemplateFormatVersion|AWS::', text):
        return True
    if re.search(r'Resources:\s*$', text, re.M):
        # Could be K8s or CF — check for CF-specific keys
        if re.search(r'Type:\s*AWS::|Description:\s*', text):
            return True
    return False


def _is_likely_k8s(path: Path, text: str) -> bool:
    """Heuristic to determine if a YAML file is a Kubernetes manifest."""
    return bool(re.search(r'apiVersion:\s*(?:v1|apps/|extensions/|batch/|networking\.k8s\.io|rbac\.authorization)', text))


def _is_likely_docker_compose(path: Path, text: str) -> bool:
    """Heuristic to determine if a YAML file is a docker-compose file."""
    return bool(re.search(r'version:\s*["\']?3|services:\s*$', text, re.M))


def run_iac_audit(target: str, base_url: str, **kwargs) -> List[Finding]:
    """Scan a directory for IaC security issues.

    Recursively discovers Terraform, CloudFormation, Dockerfile, and
    Kubernetes manifest files, runs the appropriate parser, and
    converts all issues to Finding objects.

    Returns:
        List[Finding]
    """
    findings: List[Finding] = []
    target_path = Path(target)

    if not target_path.is_dir():
        # Single file mode
        _scan_file(target_path, findings)
    else:
        # Recursive directory scan
        for p in sorted(target_path.rglob("*")):
            if not p.is_file():
                continue
            # Skip hidden dirs and common non-IaC dirs
            parts = p.parts
            if any(part.startswith(".") for part in parts if part != "."):
                continue
            if any(part in ("node_modules", "vendor", "__pycache__", ".git", "venv") for part in parts):
                continue
            _scan_file(p, findings)

    # Deduplicate by title + evidence
    seen: set = set()
    deduped: List[Finding] = []
    for f in findings:
        key = (f.title, f.evidence)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def _scan_file(p: Path, findings: List[Finding]) -> None:
    """Route a file to the appropriate parser."""
    name = p.name
    ext = p.suffix.lower()

    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    # ── Terraform ─────────────────────────────────────────────────────
    if ext in _TF_EXTS:
        for issue in parse_tf_file(str(p)):
            findings.append(Finding(
                title=issue["title"],
                severity=issue["severity"],
                category=issue["category"],
                module="iac_audit",
                description=issue["description"],
                evidence=issue["evidence"],
                asset=str(p),
                points_deducted=issue["points_deducted"],
                remediation=issue["remediation"],
                dread_score=issue["dread_score"],
            ))
        return

    # ── Dockerfile ─────────────────────────────────────────────────────
    if name in _DOCKERFILE_NAMES:
        for issue in parse_dockerfile(str(p)):
            findings.append(Finding(
                title=issue["title"],
                severity=issue["severity"],
                category=issue["category"],
                module="iac_audit",
                description=issue["description"],
                evidence=issue["evidence"],
                asset=str(p),
                points_deducted=issue["points_deducted"],
                remediation=issue["remediation"],
                dread_score=issue["dread_score"],
            ))
        return

    # ── Docker Compose ────────────────────────────────────────────────
    if name in _DOCKER_COMPOSE_NAMES:
        # Analyze docker-compose files for security issues
        for issue in _parse_docker_compose(str(p), text):
            findings.append(Finding(
                title=issue["title"],
                severity=issue["severity"],
                category=issue["category"],
                module="iac_audit",
                description=issue["description"],
                evidence=issue["evidence"],
                asset=str(p),
                points_deducted=issue["points_deducted"],
                remediation=issue["remediation"],
                dread_score=issue["dread_score"],
            ))
        return

    # ── YAML / JSON: CloudFormation or Kubernetes ──────────────────────
    if ext in _CF_EXTS:
        if _is_likely_cloudformation(p, text):
            for issue in parse_cf_file(str(p)):
                findings.append(Finding(
                    title=issue["title"],
                    severity=issue["severity"],
                    category=issue["category"],
                    module="iac_audit",
                    description=issue["description"],
                    evidence=issue["evidence"],
                    asset=str(p),
                    points_deducted=issue["points_deducted"],
                    remediation=issue["remediation"],
                    dread_score=issue["dread_score"],
                ))
        elif _is_likely_k8s(p, text):
            for issue in parse_k8s_yaml(str(p)):
                findings.append(Finding(
                    title=issue["title"],
                    severity=issue["severity"],
                    category=issue["category"],
                    module="iac_audit",
                    description=issue["description"],
                    evidence=issue["evidence"],
                    asset=str(p),
                    points_deducted=issue["points_deducted"],
                    remediation=issue["remediation"],
                    dread_score=issue["dread_score"],
                ))
        # If neither CF nor K8s, skip silently (not an IaC file)


# ── Docker Compose Analyzer ──────────────────────────────────────────


def _parse_docker_compose(path: str, text: str) -> List[Dict[str, Any]]:
    """Analyze docker-compose files for security issues."""
    issues: List[Dict[str, Any]] = []
    fname = os.path.basename(path)
    doc = _simple_yaml_load(text)
    if not isinstance(doc, dict):
        return issues

    services = doc.get("services", {})
    if not isinstance(services, dict):
        return issues

    for svc_name, svc_config in services.items():
        if not isinstance(svc_config, dict):
            continue

        # Check: privileged
        if svc_config.get("privileged") is True:
            issues.append({
                "title": f"Docker Compose: '{svc_name}' Runs Privileged",
                "severity": "critical", "category": "container_privilege",
                "description": f"Service '{svc_name}' runs with --privileged flag.",
                "evidence": f"{fname}: services.{svc_name}.privileged: true",
                "remediation": "Remove privileged: true from the service.",
                "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
            })

        # Check: security_opt with no-new-privileges missing
        sec_opts = svc_config.get("security_opt", [])
        if isinstance(sec_opts, list) and "no-new-privileges:true" not in sec_opts and "no-new-privileges" not in sec_opts:
            issues.append({
                "title": f"Docker Compose: '{svc_name}' Missing no-new-privileges",
                "severity": "medium", "category": "container_privilege",
                "description": f"Service '{svc_name}' does not set security_opt: no-new-privileges:true.",
                "evidence": f"{fname}: services.{svc_name} missing security_opt",
                "remediation": "Add 'security_opt: [no-new-privileges:true]' to the service.",
                "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
            })

        # Check: sensitive ports exposed to host
        ports = svc_config.get("ports", [])
        if isinstance(ports, list):
            for port_mapping in ports:
                port_str = str(port_mapping)
                for port_num, svc_desc in _DANGEROUS_PORTS.items():
                    if port_num in port_str and (":" in port_str or port_str == port_num):
                        issues.append({
                            "title": f"Docker Compose: '{svc_name}' Exposes {svc_desc} (Port {port_num})",
                            "severity": "medium", "category": "network_exposure",
                            "description": f"Service '{svc_name}' exposes port {port_num} ({svc_desc}) to the host.",
                            "evidence": f"{fname}: services.{svc_name}.ports: {port_str}",
                            "remediation": f"Do not bind port {port_num} to the host. Use Docker internal networking.",
                            "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                        })

        # Check: environment secrets
        env_vars = svc_config.get("environment", {})
        if isinstance(env_vars, dict):
            for k, v in env_vars.items():
                if v and re.search(r'(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)', k, re.I) and not str(v).startswith("$"):
                    issues.append({
                        "title": f"Docker Compose: '{svc_name}' Hardcoded Secret in Environment",
                        "severity": "high", "category": "hardcoded_secret",
                        "description": f"Service '{svc_name}' has a hardcoded secret in env variable '{k}'.",
                        "evidence": f"{fname}: services.{svc_name}.environment.{k}",
                        "remediation": "Use env_file or Docker secrets instead of hardcoded values.",
                        "dread_score": _dread("high"), "points_deducted": _pts("high"),
                    })
                    break  # One per service

        # Check: no resource limits
        deploy = svc_config.get("deploy", {})
        if isinstance(deploy, dict):
            resources = deploy.get("resources", {})
            if isinstance(resources, dict):
                limits = resources.get("limits", {})
                if not limits:
                    issues.append({
                        "title": f"Docker Compose: '{svc_name}' No Resource Limits",
                        "severity": "medium", "category": "resource_limit",
                        "description": f"Service '{svc_name}' has no deploy.resources.limits.",
                        "evidence": f"{fname}: services.{svc_name}.deploy.resources.limits missing",
                        "remediation": "Add deploy.resources.limits with cpus and memory.",
                        "dread_score": _dread("medium"), "points_deducted": _pts("medium"),
                    })
        else:
            # No deploy block at all
            issues.append({
                "title": f"Docker Compose: '{svc_name}' No Deploy Resource Limits",
                "severity": "low", "category": "resource_limit",
                "description": f"Service '{svc_name}' has no deploy block — no resource limits defined.",
                "evidence": f"{fname}: services.{svc_name} missing deploy.resources.limits",
                "remediation": "Add deploy.resources.limits with cpus and memory.",
                "dread_score": _dread("low"), "points_deducted": _pts("low"),
            })

        # Check: /var/run/docker.sock mount
        volumes = svc_config.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                vol_str = str(vol)
                if "/var/run/docker.sock" in vol_str:
                    issues.append({
                        "title": f"Docker Compose: '{svc_name}' Mounts Docker Socket",
                        "severity": "critical", "category": "container_privilege",
                        "description": f"Service '{svc_name}' mounts docker.sock — full host container escape.",
                        "evidence": f"{fname}: services.{svc_name}.volumes: {vol_str}",
                        "remediation": "Never mount docker.sock. Use Docker APIs directly.",
                        "dread_score": _dread("critical"), "points_deducted": _pts("critical"),
                    })

        # Check: read_only not set
        if not svc_config.get("read_only"):
            issues.append({
                "title": f"Docker Compose: '{svc_name}' Writable Root Filesystem",
                "severity": "low", "category": "container_hardening",
                "description": f"Service '{svc_name}' does not set read_only: true.",
                "evidence": f"{fname}: services.{svc_name} missing read_only: true",
                "remediation": "Set read_only: true and use tmpfs/volumes for writable directories.",
                "dread_score": _dread("low"), "points_deducted": _pts("low"),
            })

        # Check: user: root
        if str(svc_config.get("user", "")).strip() in ("root", "0"):
            issues.append({
                "title": f"Docker Compose: '{svc_name}' Runs as Root",
                "severity": "high", "category": "container_privilege",
                "description": f"Service '{svc_name}' explicitly runs as root (user: root/0).",
                "evidence": f"{fname}: services.{svc_name}.user: root",
                "remediation": "Set user to a non-root user or add a USER directive in the Dockerfile.",
                "dread_score": _dread("high"), "points_deducted": _pts("high"),
            })

        # Check: no healthcheck
        if not svc_config.get("healthcheck"):
            issues.append({
                "title": f"Docker Compose: '{svc_name}' No Healthcheck",
                "severity": "low", "category": "monitoring",
                "description": f"Service '{svc_name}' has no healthcheck defined.",
                "evidence": f"{fname}: services.{svc_name} missing healthcheck",
                "remediation": "Add a healthcheck with test, interval, and retries.",
                "dread_score": _dread("low"), "points_deducted": _pts("low"),
            })

    return issues

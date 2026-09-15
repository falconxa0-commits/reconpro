"""ReconPro Age III — Auto Fix Proposal Engine.

Analyzes detected issues and proposes automated fixes.  Every fix is a
*proposal* that must be explicitly approved before it is applied.
Dry-run mode is the default — nothing is ever written to disk without
the caller's consent.

Classes:
    FixProposal      — Dataclass for a single fix proposal.
    FixAnalyzer      — Generates fix proposals from issue patterns.
    FixStore         — Persistent JSON-backed proposal storage.
    AutoFixEngine    — Top-level orchestrator.

Lifecycle of a proposal:
    proposed → approved → applied → verified  (or  rejected / failed)
"""
from __future__ import annotations

import ast
import json
import logging
import re
import shutil
import textwrap
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import MEMORY_DIR, RECONPRO_HOME, SEVERITY_LEVELS, VALID_SEVERITIES


# ── Logging ─────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)


# ── Proposal lifecycle ──────────────────────────────────────────────────

class ProposalStatus(str, Enum):
    PROPOSED  = "proposed"
    APPROVED  = "approved"
    APPLIED   = "applied"
    VERIFIED  = "verified"
    REJECTED  = "rejected"
    FAILED    = "failed"
    ROLLED_BACK = "rolled_back"


class RiskLevel(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class FixCategory(str, Enum):
    SECURITY     = "security"
    PERFORMANCE  = "performance"
    CODE_QUALITY = "code_quality"
    CONFIG       = "config"
    DEPENDENCY   = "dependency"
    INFRASTRUCTURE = "infrastructure"


# ═══════════════════════════════════════════════════════════════════════════
# FixProposal dataclass
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class FixProposal:
    """A single proposed fix for a detected issue.

    Attributes:
        id:               Unique identifier (UUID4-based).
        title:            Short human-readable title.
        description:      Detailed explanation of the fix.
        severity:         Severity of the *underlying issue* (critical/high/…).
        category:         FixCategory enum value.
        affected_file:    Absolute path to the file (or "").
        affected_lines:   1-based line numbers impacted.
        original_code:    Original source lines (may be empty for config fixes).
        proposed_code:    Proposed replacement lines.
        risk_level:       Risk of applying the fix.
        confidence:       0.0–1.0 confidence that the fix is correct.
        automated:        True if the fix can be applied without human review.
        verification_steps: List of steps to confirm the fix worked.
        rollback_plan:    How to undo the fix.
        status:           Current ProposalStatus.
        source_issue:     The original issue dict that triggered this proposal.
        created_at:       ISO-8601 timestamp.
        applied_at:       ISO-8601 timestamp (empty until applied).
        verified_at:      ISO-8601 timestamp (empty until verified).
        error_message:    If status is FAILED, the error text.
    """
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    description: str = ""
    severity: str = "medium"
    category: str = FixCategory.CODE_QUALITY.value
    affected_file: str = ""
    affected_lines: List[int] = field(default_factory=list)
    original_code: str = ""
    proposed_code: str = ""
    risk_level: str = RiskLevel.MEDIUM.value
    confidence: float = 0.5
    automated: bool = False
    verification_steps: List[str] = field(default_factory=list)
    rollback_plan: str = ""
    status: str = ProposalStatus.PROPOSED.value
    source_issue: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    applied_at: str = ""
    verified_at: str = ""
    error_message: str = ""

    # ── Serialisation ────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "affected_file": self.affected_file,
            "affected_lines": self.affected_lines,
            "original_code": self.original_code,
            "proposed_code": self.proposed_code,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "automated": self.automated,
            "verification_steps": self.verification_steps,
            "rollback_plan": self.rollback_plan,
            "status": self.status,
            "source_issue": self.source_issue,
            "created_at": self.created_at,
            "applied_at": self.applied_at,
            "verified_at": self.verified_at,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FixProposal:
        return cls(
            id=data.get("id", uuid.uuid4().hex[:12]),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            category=data.get("category", FixCategory.CODE_QUALITY.value),
            affected_file=data.get("affected_file", ""),
            affected_lines=data.get("affected_lines", []),
            original_code=data.get("original_code", ""),
            proposed_code=data.get("proposed_code", ""),
            risk_level=data.get("risk_level", RiskLevel.MEDIUM.value),
            confidence=data.get("confidence", 0.5),
            automated=data.get("automated", False),
            verification_steps=data.get("verification_steps", []),
            rollback_plan=data.get("rollback_plan", ""),
            status=data.get("status", ProposalStatus.PROPOSED.value),
            source_issue=data.get("source_issue", {}),
            created_at=data.get("created_at", ""),
            applied_at=data.get("applied_at", ""),
            verified_at=data.get("verified_at", ""),
            error_message=data.get("error_message", ""),
        )


# ═══════════════════════════════════════════════════════════════════════════
# FixAnalyzer — pattern matching + code transformation
# ═══════════════════════════════════════════════════════════════════════════


# Known issue → fix templates.
# Each tuple: (matcher_category, matcher_pattern, fix_title, fix_desc,
#              fix_category, risk, confidence, automated, code_transform_fn_name)

_SECURITY_FIX_TEMPLATES: List[Dict[str, Any]] = [
    {
        "match_category": "dangerous_eval",
        "match_pattern": r"\beval\s*\(",
        "title": "Replace eval() with ast.literal_eval() or explicit parsing",
        "description": (
            "eval() permits arbitrary code execution. Replace with "
            "ast.literal_eval() for literal values, or a purpose-built parser."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.85,
        "automated": False,
    },
    {
        "match_category": "dangerous_exec",
        "match_pattern": r"\bexec\s*\(",
        "title": "Remove or sandbox exec() call",
        "description": (
            "exec() permits arbitrary code execution. Remove if unused, "
            "or restrict to a whitelist of allowed callables."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.75,
        "automated": False,
    },
    {
        "match_category": "command_injection",
        "match_pattern": r"shell\s*=\s*True",
        "title": "Remove shell=True from subprocess call",
        "description": (
            "shell=True enables shell injection. Pass arguments as a list "
            "to avoid shell interpretation."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.90,
        "automated": True,
    },
    {
        "match_category": "unsafe_deserialization",
        "match_pattern": r"pickle\.loads",
        "title": "Replace pickle.loads() with safe deserialization",
        "description": (
            "pickle.loads() can execute arbitrary code during deserialization. "
            "Use JSON, msgpack, or signed payloads instead."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.80,
        "automated": False,
    },
    {
        "match_category": "sql_injection",
        "match_pattern": r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)",
        "title": "Use parameterized queries instead of string formatting",
        "description": (
            "SQL queries built via string formatting are vulnerable to injection. "
            "Use cursor.execute(query, params) with placeholders."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.85,
        "automated": False,
    },
    {
        "match_category": "hardcoded_secret",
        "match_pattern": r"(?:password|secret|token|api_key)\s*=\s*['\"][^'\"]{6,}['\"]",
        "title": "Move hardcoded secret to environment variable",
        "description": (
            "Hardcoded secrets in source code are a security risk. "
            "Move to environment variables or a secrets manager."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.80,
        "automated": True,
    },
    {
        "match_category": "weak_crypto",
        "match_pattern": r"(?:md5|sha1|DES|RC4|Blowfish)",
        "title": "Upgrade to strong cryptographic algorithm",
        "description": (
            "Weak cryptographic algorithms (MD5, SHA1, DES, RC4) are broken. "
            "Use SHA-256, SHA-3, AES-256-GCM, or ChaCha20."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.80,
        "automated": False,
    },
    {
        "match_category": "cors_wildcard",
        "match_pattern": r"Access-Control-Allow-Origin.*\*",
        "title": "Restrict CORS origin to trusted domains",
        "description": (
            "CORS wildcard (*) allows any origin. Restrict to a whitelist "
            "of trusted origins."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.85,
        "automated": False,
    },
    {
        "match_category": "csrf_disabled",
        "match_pattern": r"CSRF.*(?:false|False|disabled)",
        "title": "Enable CSRF protection",
        "description": (
            "CSRF protection is disabled, exposing the application to "
            "cross-site request forgery attacks. Enable it for all "
            "state-changing endpoints."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.90,
        "automated": True,
    },
    {
        "match_category": "debug_mode",
        "match_pattern": r"DEBUG\s*=\s*True",
        "title": "Disable debug mode in production",
        "description": (
            "Debug mode exposes detailed error pages and can leak sensitive "
            "information. Disable in production environments."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.90,
        "automated": True,
    },
    {
        "match_category": "sensitive_logging",
        "match_pattern": r"(?:logger|logging|log)\.\w+\(.*?(?:password|secret|token|api_key)",
        "title": "Remove sensitive data from log statements",
        "description": (
            "Logging passwords, tokens, or PII violates security best practices. "
            "Redact or remove sensitive values before logging."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.80,
        "automated": False,
    },
    {
        "match_category": "path_traversal",
        "match_pattern": r"open\s*\(.*[\+\$\{]",
        "title": "Add path validation to prevent directory traversal",
        "description": (
            "Dynamic path construction in open() can lead to directory "
            "traversal. Validate and resolve paths with os.path.realpath() "
            "and check they are within an allowed base directory."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.75,
        "automated": False,
    },
    {
        "match_category": "temp_file_race",
        "match_pattern": r"mktemp\s*\(",
        "title": "Replace mktemp() with mkstemp() or NamedTemporaryFile()",
        "description": (
            "tempfile.mktemp() is vulnerable to race conditions. Use "
            "tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.90,
        "automated": True,
    },
    {
        "match_category": "cleartext_http",
        "match_pattern": r"http://",
        "title": "Upgrade HTTP URL to HTTPS",
        "description": (
            "Cleartext HTTP exposes data to interception. Switch to HTTPS."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.85,
        "automated": True,
    },
    {
        "match_category": "jwt_no_verify",
        "match_pattern": r"jwt\.decode\s*\(",
        "title": "Add signature verification to JWT decode",
        "description": (
            "JWT decoded without signature verification. Always pass a "
            "secret or public key and specify allowed algorithms."
        ),
        "category": FixCategory.SECURITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.85,
        "automated": False,
    },
]


# Performance fix templates
_PERFORMANCE_FIX_TEMPLATES: List[Dict[str, Any]] = [
    {
        "match_category": "n_plus_one_query",
        "match_pattern": r"for\s+.*in\s+.*:\s*\n\s+.*(?:execute|query|find)",
        "title": "Eliminate N+1 query with batch fetch",
        "description": (
            "A query inside a loop causes N+1 database round-trips. "
            "Fetch all needed data in a single batch query before the loop."
        ),
        "category": FixCategory.PERFORMANCE.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.70,
        "automated": False,
    },
    {
        "match_category": "missing_caching",
        "match_pattern": r"(?:requests\.get|urllib\.request\.urlopen|http_probe)\s*\(",
        "title": "Add caching for repeated HTTP requests",
        "description": (
            "Repeated HTTP requests to the same URL waste bandwidth and time. "
            "Add response caching with an appropriate TTL."
        ),
        "category": FixCategory.PERFORMANCE.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.60,
        "automated": False,
    },
    {
        "match_category": "inefficient_concat",
        "match_pattern": r"(?:\+=\s*['\"])|(?:result\s*\+=\s*result)",
        "title": "Use list-join instead of string concatenation in loop",
        "description": (
            "String concatenation in a loop creates O(n²) copies. "
            "Collect parts in a list and use ''.join(parts)."
        ),
        "category": FixCategory.PERFORMANCE.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.65,
        "automated": False,
    },
]


# Code quality fix templates
_CODE_QUALITY_TEMPLATES: List[Dict[str, Any]] = [
    {
        "match_category": "missing_type_hints",
        "match_pattern": r"^def \w+\([^)]*\):\s*$",
        "title": "Add return type hint to function definition",
        "description": (
            "Function definitions without return type hints reduce IDE support "
            "and static analysis effectiveness. Add -> None or the appropriate type."
        ),
        "category": FixCategory.CODE_QUALITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.75,
        "automated": False,
    },
    {
        "match_category": "missing_docstring",
        "match_pattern": r"^(class |def )\w+.*:\s*\n(\s*\n|\s*pass|\s*\"\"\")",
        "title": "Add docstring to public function or class",
        "description": (
            "Public functions and classes should have docstrings for API "
            "documentation and developer clarity."
        ),
        "category": FixCategory.CODE_QUALITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.70,
        "automated": False,
    },
    {
        "match_category": "bare_except",
        "match_pattern": r"except\s*:\s*$",
        "title": "Replace bare except with specific exception types",
        "description": (
            "Bare 'except:' clauses silently swallow all exceptions including "
            "KeyboardInterrupt and SystemExit. Use 'except Exception:' at minimum."
        ),
        "category": FixCategory.CODE_QUALITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.90,
        "automated": True,
    },
    {
        "match_category": "mutable_default",
        "match_pattern": r"def \w+\([^)]*=\s*(?:\[\]|\{\})",
        "title": "Replace mutable default argument with None sentinel",
        "description": (
            "Mutable default arguments (list/dict) are shared across calls, "
            "causing subtle bugs. Use None and initialise inside the function."
        ),
        "category": FixCategory.CODE_QUALITY.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.90,
        "automated": True,
    },
]


# Config fix templates — matched against diagnostics/validate_config issues
_CONFIG_FIX_TEMPLATES: List[Dict[str, Any]] = [
    {
        "match_category": "paths",
        "match_pattern": r"directory does not exist",
        "title": "Create missing ReconPro directory",
        "description": "Create the missing directory with appropriate permissions.",
        "category": FixCategory.CONFIG.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.95,
        "automated": True,
    },
    {
        "match_category": "config",
        "match_pattern": r"invalid JSON",
        "title": "Fix malformed config.json",
        "description": (
            "The config.json file contains invalid JSON. Fix syntax errors "
            "or regenerate the file with defaults."
        ),
        "category": FixCategory.CONFIG.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.70,
        "automated": False,
    },
    {
        "match_category": "config",
        "match_pattern": r"not a valid JSON object",
        "title": "Replace config.json with valid object",
        "description": (
            "config.json should contain a JSON object at the top level. "
            "Replace the contents with a valid empty object or defaults."
        ),
        "category": FixCategory.CONFIG.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.80,
        "automated": True,
    },
    {
        "match_category": "disk",
        "match_pattern": r"Low disk space",
        "title": "Free disk space for scan data",
        "description": (
            "Insufficient disk space for scan data. Clean old scans, "
            "remove temporary files, or expand the volume."
        ),
        "category": FixCategory.INFRASTRUCTURE.value,
        "risk": RiskLevel.HIGH.value,
        "confidence": 0.60,
        "automated": False,
    },
    {
        "match_category": "network",
        "match_pattern": r"DNS resolution failed",
        "title": "Check network connectivity",
        "description": (
            "DNS resolution failed, indicating a network issue. Check the "
            "network connection, DNS configuration, and firewall rules."
        ),
        "category": FixCategory.INFRASTRUCTURE.value,
        "risk": RiskLevel.LOW.value,
        "confidence": 0.70,
        "automated": False,
    },
    {
        "match_category": "modules",
        "match_pattern": r"broken runners",
        "title": "Repair broken module registry entries",
        "description": (
            "Some modules have broken or missing runner functions. "
            "Reinstall ReconPro or check module file integrity."
        ),
        "category": FixCategory.DEPENDENCY.value,
        "risk": RiskLevel.MEDIUM.value,
        "confidence": 0.50,
        "automated": False,
    },
    {
        "match_category": "python",
        "match_pattern": r"below minimum",
        "title": "Upgrade Python to 3.9 or higher",
        "description": (
            "Python version is below the minimum supported (3.9). "
            "Upgrade Python to the latest stable release."
        ),
        "category": FixCategory.DEPENDENCY.value,
        "risk": RiskLevel.HIGH.value,
        "confidence": 0.95,
        "automated": False,
    },
]


# Merge all templates for fast lookup
_ALL_FIX_TEMPLATES: List[Dict[str, Any]] = (
    _SECURITY_FIX_TEMPLATES
    + _PERFORMANCE_FIX_TEMPLATES
    + _CODE_QUALITY_TEMPLATES
    + _CONFIG_FIX_TEMPLATES
)


# ═══════════════════════════════════════════════════════════════════════════
# FixAnalyzer
# ═══════════════════════════════════════════════════════════════════════════


class FixAnalyzer:
    """Analyses issues and generates FixProposal objects.

    Uses pattern matching against a knowledge base of known issue → fix
    mappings, plus AST-based code analysis for Python source files.
    """

    def __init__(self) -> None:
        self._template_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._build_template_index()

    def _build_template_index(self) -> None:
        """Index templates by match_category for O(1) lookup."""
        for tmpl in _ALL_FIX_TEMPLATES:
            cat = tmpl["match_category"]
            self._template_cache.setdefault(cat, []).append(tmpl)

    # ── Public API ────────────────────────────────────────────────────

    def analyze_issue(self, issue: Dict[str, Any]) -> Optional[FixProposal]:
        """Analyse a single issue dict and return a FixProposal (or None)."""
        # Determine which kind of issue this is
        category = issue.get("category", "")
        message = issue.get("message", "")
        evidence = issue.get("evidence", "")
        title = issue.get("title", "")
        severity = issue.get("severity", "medium")
        description = issue.get("description", "")
        file_path = issue.get("asset", issue.get("file", ""))

        # Combine searchable text
        search_text = " ".join([title, message, evidence, description]).lower()

        # 1. Try exact category match first
        proposals = self._match_by_category(category, issue)
        if proposals:
            proposal = proposals[0]
            proposal.severity = self._normalise_severity(severity)
            proposal.source_issue = issue
            proposal.affected_file = str(file_path) if file_path else ""
            return proposal

        # 2. Try pattern match on the text
        proposals = self._match_by_pattern(search_text, issue)
        if proposals:
            proposal = proposals[0]
            proposal.severity = self._normalise_severity(severity)
            proposal.source_issue = issue
            proposal.affected_file = str(file_path) if file_path else ""
            return proposal

        # 3. Generate a generic proposal if we have any issue at all
        if message or title:
            return self._generic_proposal(issue)

        return None

    def propose_code_fixes(
        self,
        file_path: str,
        issues: List[Dict[str, Any]],
    ) -> List[FixProposal]:
        """Generate code-level fix proposals for issues in a file.

        Uses AST analysis to propose concrete code changes when possible.
        """
        proposals: List[FixProposal] = []
        path = Path(file_path)

        if not path.is_file():
            logger.warning("Cannot propose code fixes for non-existent file: %s", file_path)
            return proposals

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.error("Failed to read %s: %s", file_path, exc)
            return proposals

        lines = source.splitlines()

        for issue in issues:
            proposal = self._generate_code_proposal(file_path, source, lines, issue)
            if proposal is not None:
                proposals.append(proposal)

        return proposals

    def propose_config_fixes(
        self,
        config_issues: List[Dict[str, Any]],
    ) -> List[FixProposal]:
        """Generate configuration fix proposals."""
        proposals: List[FixProposal] = []
        for issue in config_issues:
            proposal = self.analyze_issue(issue)
            if proposal is not None:
                proposals.append(proposal)
        return proposals

    # ── Internal matching ─────────────────────────────────────────────

    def _match_by_category(
        self,
        category: str,
        issue: Dict[str, Any],
    ) -> List[FixProposal]:
        """Find fix templates matching the issue category."""
        results: List[FixProposal] = []
        templates = self._template_cache.get(category, [])
        for tmpl in templates:
            proposal = self._template_to_proposal(tmpl, issue)
            if proposal is not None:
                results.append(proposal)
        return results

    def _match_by_pattern(
        self,
        text: str,
        issue: Dict[str, Any],
    ) -> List[FixProposal]:
        """Find fix templates whose regex pattern matches the text."""
        results: List[FixProposal] = []
        seen_categories: Set[str] = set()
        for tmpl in _ALL_FIX_TEMPLATES:
            cat = tmpl["match_category"]
            if cat in seen_categories:
                continue
            try:
                pattern = re.compile(tmpl["match_pattern"], re.IGNORECASE)
                if pattern.search(text):
                    proposal = self._template_to_proposal(tmpl, issue)
                    if proposal is not None:
                        results.append(proposal)
                        seen_categories.add(cat)
            except re.error:
                continue
        return results

    def _template_to_proposal(
        self,
        tmpl: Dict[str, Any],
        issue: Dict[str, Any],
    ) -> Optional[FixProposal]:
        """Convert a fix template + issue into a FixProposal."""
        title = tmpl.get("title", "")
        if not title:
            return None

        evidence = issue.get("evidence", "")
        file_path = issue.get("asset", issue.get("file", ""))

        proposal = FixProposal(
            title=title,
            description=tmpl.get("description", ""),
            severity=self._normalise_severity(issue.get("severity", "medium")),
            category=tmpl.get("category", FixCategory.CODE_QUALITY.value),
            affected_file=str(file_path) if file_path else "",
            original_code=evidence,
            risk_level=tmpl.get("risk", RiskLevel.MEDIUM.value),
            confidence=tmpl.get("confidence", 0.5),
            automated=tmpl.get("automated", False),
            source_issue=issue,
            rollback_plan=self._generate_rollback(tmpl, issue),
            verification_steps=self._generate_verification(tmpl, issue),
        )
        return proposal

    def _generic_proposal(self, issue: Dict[str, Any]) -> FixProposal:
        """Create a generic fix proposal when no template matches."""
        title = issue.get("title", "") or issue.get("message", "")
        suggestion = issue.get("suggestion", "") or issue.get("remediation", "")
        description = issue.get("description", "")
        category = issue.get("category", "")

        # Map issue category to fix category
        fix_cat = FixCategory.CODE_QUALITY.value
        if category in ("security", "headers", "tls", "ssl"):
            fix_cat = FixCategory.SECURITY.value
        elif category in ("performance", "speed"):
            fix_cat = FixCategory.PERFORMANCE.value
        elif category in ("paths", "config", "disk", "network", "python", "modules"):
            fix_cat = FixCategory.CONFIG.value
        elif category in ("deps", "dependencies"):
            fix_cat = FixCategory.DEPENDENCY.value

        return FixProposal(
            title=f"Review and fix: {title}",
            description=description or f"Address the issue: {title}",
            severity=self._normalise_severity(issue.get("severity", "medium")),
            category=fix_cat,
            affected_file=issue.get("asset", ""),
            proposed_code=suggestion,
            risk_level=RiskLevel.MEDIUM.value,
            confidence=0.3,
            automated=False,
            source_issue=issue,
            verification_steps=[
                f"Manually review the issue: {title}",
                f"Apply the suggested fix: {suggestion}" if suggestion else "Determine and apply the appropriate fix",
                "Re-run diagnostics or scan to confirm resolution",
            ],
            rollback_plan="Revert manual changes. No automated rollback available for generic proposals.",
        )

    # ── Code-level proposal generation ────────────────────────────────

    def _generate_code_proposal(
        self,
        file_path: str,
        source: str,
        lines: List[str],
        issue: Dict[str, Any],
    ) -> Optional[FixProposal]:
        """Generate a concrete code fix proposal using AST analysis."""
        category = issue.get("category", "")
        evidence = issue.get("evidence", "")

        # Try AST-based transformations for Python files
        if file_path.endswith(".py"):
            proposal = self._ast_code_proposal(file_path, source, lines, issue)
            if proposal is not None:
                return proposal

        # Fall back to text-based proposals
        proposal = self.analyze_issue(issue)
        if proposal is not None and not proposal.original_code and evidence:
            proposal.original_code = evidence
            proposal.affected_file = file_path
        return proposal

    def _ast_code_proposal(
        self,
        file_path: str,
        source: str,
        lines: List[str],
        issue: Dict[str, Any],
    ) -> Optional[FixProposal]:
        """Use AST analysis to generate a concrete code fix."""
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return None

        category = issue.get("category", "")
        title = issue.get("title", "")
        evidence = issue.get("evidence", "")

        # Find the relevant node
        finder = _IssueNodeFinder(category, evidence, title)
        finder.visit(tree)

        if not finder.matched_nodes:
            return None

        node = finder.matched_nodes[0]
        start_line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", start_line)

        # Extract original code lines
        orig_lines = lines[start_line - 1 : end_line]
        original_code = "\n".join(orig_lines)

        # Generate proposed code based on category
        proposed_code = self._transform_node(category, node, lines, start_line, end_line)
        if proposed_code is None:
            return None

        # Look up template for metadata
        templates = self._template_cache.get(category, [])
        tmpl = templates[0] if templates else {}

        return FixProposal(
            title=tmpl.get("title", f"Fix: {title}"),
            description=tmpl.get("description", f"Address the {category} issue in {file_path}"),
            severity=self._normalise_severity(issue.get("severity", "medium")),
            category=tmpl.get("category", FixCategory.SECURITY.value),
            affected_file=file_path,
            affected_lines=list(range(start_line, end_line + 1)),
            original_code=original_code,
            proposed_code=proposed_code,
            risk_level=tmpl.get("risk", RiskLevel.MEDIUM.value),
            confidence=tmpl.get("confidence", 0.7),
            automated=tmpl.get("automated", False),
            source_issue=issue,
            verification_steps=[
                f"Verify the fix in {file_path} lines {start_line}-{end_line}",
                "Run the AST analyzer again to confirm the issue is resolved",
                "Run tests to ensure no regressions",
            ],
            rollback_plan=f"Restore original code at lines {start_line}-{end_line} in {file_path}",
        )

    def _transform_node(
        self,
        category: str,
        node: ast.AST,
        lines: List[str],
        start_line: int,
        end_line: int,
    ) -> Optional[str]:
        """Transform an AST node into fixed code.

        Returns the proposed replacement code as a string, or None if no
        transformation is possible.
        """
        indent = self._get_indent(lines, start_line - 1)

        if category == "dangerous_eval" and isinstance(node, ast.Call):
            return self._transform_eval(node, indent, lines, start_line)

        if category == "dangerous_exec" and isinstance(node, ast.Call):
            return self._transform_exec(node, indent, lines, start_line)

        if category == "command_injection" and isinstance(node, ast.Call):
            return self._transform_shell_true(node, indent, lines, start_line, end_line)

        if category == "hardcoded_secret" and isinstance(node, ast.Assign):
            return self._transform_hardcoded_secret(node, indent, lines, start_line)

        if category == "bare_except":
            return self._transform_bare_except(indent, lines, start_line)

        if category == "debug_mode":
            return self._transform_debug_mode(indent, lines, start_line)

        if category == "cleartext_http":
            return self._transform_http_to_https(indent, lines, start_line, end_line)

        if category == "temp_file_race":
            return self._transform_mktemp(indent, lines, start_line)

        if category == "csrf_disabled":
            return self._transform_csrf_disabled(indent, lines, start_line)

        return None

    # ── AST transform helpers ─────────────────────────────────────────

    @staticmethod
    def _get_indent(lines: List[str], index: int) -> str:
        """Extract leading whitespace from a line."""
        if 0 <= index < len(lines):
            line = lines[index]
            return line[: len(line) - len(line.lstrip())]
        return ""

    def _transform_eval(
        self,
        node: ast.Call,
        indent: str,
        lines: List[str],
        start_line: int,
    ) -> Optional[str]:
        """Propose replacing eval() with ast.literal_eval()."""
        func_name = _get_call_name(node)
        if func_name != "eval":
            return None

        # Reconstruct the call argument
        if node.args:
            arg_src = self._extract_arg_source(node.args[0], lines)
        else:
            arg_src = "..."

        return (
            f"{indent}import ast as _ast  # noqa: added for safe evaluation\n"
            f"{indent}_ast.literal_eval({arg_src})"
        )

    def _transform_exec(
        self,
        node: ast.Call,
        indent: str,
        lines: List[str],
        start_line: int,
    ) -> Optional[str]:
        """Propose removing exec() or marking it as dangerous."""
        func_name = _get_call_name(node)
        if func_name != "exec":
            return None

        arg_src = ""
        if node.args:
            arg_src = self._extract_arg_source(node.args[0], lines)
        else:
            arg_src = "..."

        return (
            f"{indent}# WARNING: exec() removed — arbitrary code execution risk\n"
            f"{indent}# If this is needed, use a restricted sandbox or whitelist approach\n"
            f"{indent}# Original: exec({arg_src})\n"
            f"{indent}raise NotImplementedError(\"exec() was removed for security reasons\")"
        )

    def _transform_shell_true(
        self,
        node: ast.Call,
        indent: str,
        lines: List[str],
        start_line: int,
        end_line: int,
    ) -> Optional[str]:
        """Remove shell=True from a subprocess call."""
        func_name = _get_call_name(node)
        if func_name not in ("run", "call", "Popen", "check_output", "check_call"):
            return None

        # Find and remove shell=True keyword
        new_lines: List[str] = []
        for i in range(start_line - 1, end_line):
            line = lines[i]
            if "shell=True" in line:
                # Remove the shell=True keyword argument
                line = re.sub(r",?\s*shell\s*=\s*True\s*,?", ",", line)
                line = re.sub(r",\s*,", ",", line)  # Clean double commas
                # If shell=True was the only keyword, clean up
                line = re.sub(r"\(\s*,", "(", line)
                line = re.sub(r",\s*\)", ")", line)
            new_lines.append(line)

        return "\n".join(new_lines)

    def _transform_hardcoded_secret(
        self,
        node: ast.Assign,
        indent: str,
        lines: List[str],
        start_line: int,
    ) -> Optional[str]:
        """Replace hardcoded secret with os.environ.get()."""
        # Get variable name
        targets = node.targets
        if not targets or not isinstance(targets[0], ast.Name):
            return None

        var_name = targets[0].id
        return (
            f"{indent}import os  # noqa: added for secret loading\n"
            f"{indent}{var_name} = os.environ.get(\"{var_name.upper()}\", \"\")  "
            f"# was hardcoded secret"
        )

    def _transform_bare_except(
        self,
        indent: str,
        lines: List[str],
        start_line: int,
    ) -> Optional[str]:
        """Replace bare 'except:' with 'except Exception:'."""
        if start_line - 1 < len(lines):
            line = lines[start_line - 1]
            if re.search(r"except\s*:\s*$", line):
                new_line = re.sub(r"except\s*:", "except Exception:", line)
                return new_line
        return None

    def _transform_debug_mode(
        self,
        indent: str,
        lines: List[str],
        start_line: int,
    ) -> Optional[str]:
        """Replace DEBUG=True with DEBUG=False."""
        if start_line - 1 < len(lines):
            line = lines[start_line - 1]
            new_line = re.sub(
                r"(DEBUG\s*=\s*)True",
                r"\1False  # disabled in production",
                line,
                flags=re.IGNORECASE,
            )
            if new_line != line:
                return new_line
        return None

    def _transform_http_to_https(
        self,
        indent: str,
        lines: List[str],
        start_line: int,
        end_line: int,
    ) -> Optional[str]:
        """Replace http:// with https:// in the matched lines."""
        new_lines: List[str] = []
        changed = False
        for i in range(start_line - 1, end_line):
            line = lines[i]
            new_line = re.sub(r'"http://', '"https://', line)
            new_line = re.sub(r"'http://", "'https://", new_line)
            if new_line != line:
                changed = True
            new_lines.append(new_line)
        return "\n".join(new_lines) if changed else None

    def _transform_mktemp(
        self,
        indent: str,
        lines: List[str],
        start_line: int,
    ) -> Optional[str]:
        """Replace mktemp() with mkstemp() or NamedTemporaryFile()."""
        if start_line - 1 < len(lines):
            line = lines[start_line - 1]
            if re.search(r"mktemp\s*\(", line):
                new_line = re.sub(
                    r"mktemp\s*\([^)]*\)",
                    "NamedTemporaryFile(delete=False).name",
                    line,
                )
                # Add import if needed
                return (
                    f"{indent}from tempfile import NamedTemporaryFile  # noqa: safe replacement\n"
                    f"{new_line}"
                )
        return None

    def _transform_csrf_disabled(
        self,
        indent: str,
        lines: List[str],
        start_line: int,
    ) -> Optional[str]:
        """Replace CSRF_ENABLED=False with CSRF_ENABLED=True."""
        if start_line - 1 < len(lines):
            line = lines[start_line - 1]
            new_line = re.sub(
                r"(CSRF_ENABLED\s*=\s*|WTF_CSRF_ENABLED\s*=\s*)False",
                r"\1True  # re-enabled for security",
                line,
                flags=re.IGNORECASE,
            )
            if new_line != line:
                return new_line
        return None

    @staticmethod
    def _extract_arg_source(node: ast.AST, lines: List[str]) -> str:
        """Best-effort extraction of source text for an AST node."""
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        col_start = getattr(node, "col_offset", 0)
        col_end = getattr(node, "end_col_offset", None)

        if 0 < start <= len(lines):
            line = lines[start - 1]
            if col_end is not None:
                return line[col_start:col_end]
            # Fallback: take from col_start to end of line
            return line[col_start:]
        return "..."

    @staticmethod
    def _normalise_severity(severity: str) -> str:
        """Normalise a severity string to a valid value."""
        sev = severity.lower().strip()
        if sev in VALID_SEVERITIES:
            return sev
        # Map common alternatives
        mapping = {
            "error": "high",
            "warn": "medium",
            "warning": "medium",
        }
        return mapping.get(sev, "medium")

    @staticmethod
    def _generate_rollback(tmpl: Dict[str, Any], issue: Dict[str, Any]) -> str:
        """Generate a rollback plan for a template-based fix."""
        file_path = issue.get("asset", "") or issue.get("file", "")
        if file_path:
            return f"Restore original code in {file_path} using version control (git checkout -- {file_path}) or the backup created before applying the fix."
        cat = tmpl.get("match_category", "")
        if cat == "config":
            return "Restore the previous configuration from backup or version control."
        if cat in ("paths", "disk", "network"):
            return "Infrastructure changes may require manual rollback. Consult the system documentation."
        return "Revert changes using version control or restore from the backup created before applying."

    @staticmethod
    def _generate_verification(tmpl: Dict[str, Any], issue: Dict[str, Any]) -> List[str]:
        """Generate verification steps for a template-based fix."""
        cat = tmpl.get("match_category", "")
        steps = ["Re-run the scan or diagnostics that detected this issue."]
        if cat in ("dangerous_eval", "dangerous_exec", "command_injection",
                    "unsafe_deserialization", "sql_injection"):
            steps.append("Run the AST analyzer to confirm the vulnerable pattern is gone.")
            steps.append("Run the application test suite to ensure no regressions.")
        elif cat in ("hardcoded_secret", "sensitive_logging"):
            steps.append("Search the codebase for any remaining hardcoded secrets.")
            steps.append("Verify the environment variable or secret manager is configured.")
        elif cat == "cleartext_http":
            steps.append("Verify all HTTP URLs now use HTTPS.")
            steps.append("Test that the application connects successfully over HTTPS.")
        elif cat in ("debug_mode", "csrf_disabled"):
            steps.append("Verify the configuration change in the running application.")
            steps.append("Test that the application still functions correctly.")
        elif cat == "config":
            steps.append("Validate the configuration file with: python -m json.tool config.json")
        return steps


# ── AST helper: find nodes matching an issue ──────────────────────────


class _IssueNodeFinder(ast.NodeVisitor):
    """Walks the AST and collects nodes that match a given issue."""

    def __init__(self, category: str, evidence: str, title: str) -> None:
        self.category = category
        self.evidence = evidence.lower()
        self.title = title.lower()
        self.matched_nodes: List[ast.AST] = []
        self._imported: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._imported.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._imported.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        fname = _get_call_name(node)
        func_full = _get_call_full_name(node)

        if self.category == "dangerous_eval" and fname == "eval":
            self.matched_nodes.append(node)
        elif self.category == "dangerous_exec" and fname == "exec":
            self.matched_nodes.append(node)
        elif self.category == "command_injection":
            if fname in ("run", "call", "Popen", "check_output", "check_call"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.matched_nodes.append(node)
                        break
        elif self.category == "unsafe_deserialization":
            if func_full and ("pickle.loads" in func_full or "marshal.loads" in func_full):
                self.matched_nodes.append(node)
            elif func_full and "yaml.load" in func_full:
                self.matched_nodes.append(node)
        elif self.category == "jwt_no_verify":
            if func_full and "jwt.decode" in func_full:
                self.matched_nodes.append(node)
        elif self.category == "temp_file_race":
            if func_full and "mktemp" in func_full:
                self.matched_nodes.append(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.category == "hardcoded_secret":
            # Get the source text for the line
            start = getattr(node, "lineno", 0)
            end = getattr(node, "end_lineno", start)
            # We'll match by the parent logic
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id.lower()
                    secret_names = ("password", "passwd", "secret", "token",
                                    "api_key", "apikey", "private_key")
                    if any(s in name for s in secret_names):
                        # Check if value is a string constant
                        if isinstance(node.value, (ast.Constant,)) and isinstance(node.value.value, str):
                            self.matched_nodes.append(node)

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if self.category == "bare_except":
            if node.type is None:
                self.matched_nodes.append(node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if self.category == "sql_injection":
            parts: List[str] = []
            for val in node.values:
                if isinstance(val, ast.Constant):
                    parts.append(str(val.value))
                elif isinstance(val, ast.FormattedValue):
                    parts.append("{}")
            combined = " ".join(parts)
            sql_kw = re.compile(
                r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b", re.I,
            )
            if sql_kw.search(combined):
                self.matched_nodes.append(node)
        self.generic_visit(node)

    def _line_based_match(self, node: ast.stmt) -> None:
        """Additional line-based matching for statement nodes."""
        # Handled in parent methods
        pass

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.stmt):
            # Check for line-based patterns
            lineno = getattr(node, "lineno", 0)
            # debug_mode
            if self.category == "debug_mode" and lineno > 0:
                pass  # Handled by parent
        super().generic_visit(node)


# ── AST utilities ─────────────────────────────────────────────────────


def _get_call_name(node: ast.Call) -> str:
    """Get the simple function name from a Call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _get_call_full_name(node: ast.Call) -> str:
    """Get the full dotted function name from a Call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        current = func.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return ".".join(parts)
    return ""


# ═══════════════════════════════════════════════════════════════════════════
# FixStore — Persistent JSON storage
# ═══════════════════════════════════════════════════════════════════════════


class FixStore:
    """Persistent storage for fix proposals.

    Stores proposals in ``RECONPRO_HOME/memory/fix_proposals.json``.
    Tracks the full lifecycle: proposed → approved → applied → verified.
    """

    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._path = store_path or (MEMORY_DIR / "fix_proposals.json")
        self._proposals: Dict[str, FixProposal] = {}
        self._history: List[Dict[str, Any]] = []
        self._load()

    # ── Persistence ───────────────────────────────────────────────────

    def _ensure_dir(self) -> None:
        """Ensure the storage directory exists."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("Cannot create fix store directory %s: %s", self._path.parent, exc)

    def _load(self) -> None:
        """Load proposals from disk."""
        if not self._path.exists():
            self._proposals = {}
            self._history = []
            return
        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
            proposals_data = data.get("proposals", {})
            self._proposals = {
                pid: FixProposal.from_dict(pdata)
                for pid, pdata in proposals_data.items()
            }
            self._history = data.get("history", [])
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.warning("Failed to load fix store from %s: %s", self._path, exc)
            self._proposals = {}
            self._history = []

    def _save(self) -> None:
        """Persist proposals to disk."""
        self._ensure_dir()
        try:
            data = {
                "proposals": {
                    pid: p.to_dict() for pid, p in self._proposals.items()
                },
                "history": self._history[-500:],  # Keep last 500 history entries
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            tmp_path = self._path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp_path.replace(self._path)
        except OSError as exc:
            logger.error("Failed to save fix store to %s: %s", self._path, exc)

    # ── CRUD ──────────────────────────────────────────────────────────

    def add(self, proposal: FixProposal) -> None:
        """Add a new proposal to the store."""
        self._proposals[proposal.id] = proposal
        self._add_history_entry("added", proposal)
        self._save()

    def get(self, proposal_id: str) -> Optional[FixProposal]:
        """Retrieve a proposal by ID."""
        return self._proposals.get(proposal_id)

    def update(self, proposal: FixProposal) -> None:
        """Update an existing proposal."""
        if proposal.id in self._proposals:
            old_status = self._proposals[proposal.id].status
            self._proposals[proposal.id] = proposal
            if old_status != proposal.status:
                self._add_history_entry(f"status_changed:{old_status}->{proposal.status}", proposal)
            self._save()
        else:
            logger.warning("Attempted to update non-existent proposal: %s", proposal.id)

    def remove(self, proposal_id: str) -> bool:
        """Remove a proposal from the store. Returns True if found."""
        if proposal_id in self._proposals:
            proposal = self._proposals.pop(proposal_id)
            self._add_history_entry("removed", proposal)
            self._save()
            return True
        return False

    def list_all(self) -> List[FixProposal]:
        """List all proposals."""
        return list(self._proposals.values())

    def list_by_status(self, status: str) -> List[FixProposal]:
        """Filter proposals by status."""
        return [p for p in self._proposals.values() if p.status == status]

    def list_by_category(self, category: str) -> List[FixProposal]:
        """Filter proposals by category."""
        return [p for p in self._proposals.values() if p.category == category]

    def list_by_severity(self, severity: str) -> List[FixProposal]:
        """Filter proposals by severity."""
        return [p for p in self._proposals.values() if p.severity == severity]

    def approve(self, proposal_id: str) -> bool:
        """Approve a proposal. Returns True if successful."""
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            return False
        if proposal.status != ProposalStatus.PROPOSED.value:
            logger.warning("Cannot approve proposal %s in status %s", proposal_id, proposal.status)
            return False
        proposal.status = ProposalStatus.APPROVED.value
        self.update(proposal)
        return True

    def reject(self, proposal_id: str) -> bool:
        """Reject a proposal. Returns True if successful."""
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            return False
        if proposal.status != ProposalStatus.PROPOSED.value:
            logger.warning("Cannot reject proposal %s in status %s", proposal_id, proposal.status)
            return False
        proposal.status = ProposalStatus.REJECTED.value
        self.update(proposal)
        return True

    # ── History ────────────────────────────────────────────────────────

    def _add_history_entry(self, action: str, proposal: FixProposal) -> None:
        """Append an entry to the history log."""
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "proposal_id": proposal.id,
            "proposal_title": proposal.title,
            "status": proposal.status,
            "severity": proposal.severity,
            "category": proposal.category,
        }
        self._history.append(entry)

    def get_history(self) -> List[Dict[str, Any]]:
        """Return the full history log."""
        return list(self._history)

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics."""
        proposals = list(self._proposals.values())
        status_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        automated_count = 0
        total_confidence = 0.0

        for p in proposals:
            status_counts[p.status] = status_counts.get(p.status, 0) + 1
            severity_counts[p.severity] = severity_counts.get(p.severity, 0) + 1
            category_counts[p.category] = category_counts.get(p.category, 0) + 1
            if p.automated:
                automated_count += 1
            total_confidence += p.confidence

        avg_confidence = round(total_confidence / len(proposals), 2) if proposals else 0.0

        return {
            "total_proposals": len(proposals),
            "by_status": status_counts,
            "by_severity": severity_counts,
            "by_category": category_counts,
            "automated_count": automated_count,
            "average_confidence": avg_confidence,
            "history_entries": len(self._history),
        }


# ═══════════════════════════════════════════════════════════════════════════
# AutoFixEngine — Top-level orchestrator
# ═══════════════════════════════════════════════════════════════════════════


class AutoFixEngine:
    """Top-level engine that analyses scan results and proposes automated fixes.

    The engine is **dry-run by default** — it only *proposes* fixes.
    Applying a fix requires explicit approval via :meth:`apply_fix` with
    ``dry_run=False``.

    Usage::

        engine = AutoFixEngine()
        proposals = engine.propose_fixes(scan_result)
        for p in proposals:
            print(f"[{p.severity}] {p.title} (confidence={p.confidence})")

        # Apply a specific approved fix
        result = engine.apply_fix(proposals[0], dry_run=False)
        print(result)
    """

    def __init__(
        self,
        store: Optional[FixStore] = None,
        dry_run: bool = True,
    ) -> None:
        self._analyzer = FixAnalyzer()
        self._store = store or FixStore()
        self._dry_run = dry_run
        logger.info("AutoFixEngine initialised (dry_run=%s)", dry_run)

    # ── Public API ────────────────────────────────────────────────────

    def analyze_issue(self, issue: Dict[str, Any]) -> Optional[FixProposal]:
        """Analyse a single issue and return a fix proposal."""
        try:
            proposal = self._analyzer.analyze_issue(issue)
            if proposal is not None:
                self._store.add(proposal)
                logger.info(
                    "Proposed fix %s: %s (confidence=%.2f)",
                    proposal.id, proposal.title, proposal.confidence,
                )
            return proposal
        except Exception as exc:
            logger.error("Failed to analyze issue: %s", exc, exc_info=True)
            return None

    def propose_fixes(self, scan_result: Dict[str, Any]) -> List[FixProposal]:
        """Analyse a full scan result and propose fixes for all findings.

        The scan_result dict can contain:
        - ``findings``: List of finding dicts (from http_layer.Finding.to_dict())
        - ``diagnostics``: Dict from diagnostics.run_diagnostics()
        - ``config_issues``: List from diagnostics.validate_config()
        - ``cross_validation``: Dict from cross_validator

        Any combination of the above keys is supported.
        """
        proposals: List[FixProposal] = []

        # 1. Process scan findings
        findings = scan_result.get("findings", [])
        if findings:
            proposals.extend(self._process_findings(findings))

        # 2. Process diagnostics failures
        diagnostics = scan_result.get("diagnostics", {})
        if diagnostics:
            proposals.extend(self._process_diagnostics(diagnostics))

        # 3. Process config issues
        config_issues = scan_result.get("config_issues", [])
        if config_issues:
            proposals.extend(self._process_config_issues(config_issues))

        # 4. Process cross-validation mismatches
        cv = scan_result.get("cross_validation", {})
        if cv:
            proposals.extend(self._process_cross_validation(cv))

        logger.info(
            "Generated %d fix proposals from scan result (%d findings, %d diagnostics, %d config, %d cv)",
            len(proposals),
            len(findings),
            len(diagnostics.get("checks", [])) if diagnostics else 0,
            len(config_issues),
            len(cv.get("mismatches", [])) if cv else 0,
        )

        return proposals

    def propose_code_fixes(
        self,
        file_path: str,
        issues: List[Dict[str, Any]],
    ) -> List[FixProposal]:
        """Propose code-level fixes for issues in a specific file."""
        try:
            proposals = self._analyzer.propose_code_fixes(file_path, issues)
            for p in proposals:
                self._store.add(p)
            return proposals
        except Exception as exc:
            logger.error("Failed to propose code fixes for %s: %s", file_path, exc)
            return []

    def propose_config_fixes(
        self,
        config_issues: List[Dict[str, Any]],
    ) -> List[FixProposal]:
        """Propose configuration fixes."""
        try:
            proposals = self._analyzer.propose_config_fixes(config_issues)
            for p in proposals:
                self._store.add(p)
            return proposals
        except Exception as exc:
            logger.error("Failed to propose config fixes: %s", exc)
            return []

    def apply_fix(
        self,
        fix_proposal: FixProposal,
        dry_run: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Apply an approved fix.

        Args:
            fix_proposal: The proposal to apply.
            dry_run: Override the engine's dry_run setting. Defaults to the
                    engine's setting. Pass False to actually apply.

        Returns:
            Dict with keys: success, message, dry_run, proposal_id, changes.
        """
        is_dry = dry_run if dry_run is not None else self._dry_run

        result: Dict[str, Any] = {
            "success": False,
            "message": "",
            "dry_run": is_dry,
            "proposal_id": fix_proposal.id,
            "changes": [],
        }

        # Validate proposal state
        if fix_proposal.status == ProposalStatus.APPLIED.value:
            result["message"] = "Proposal has already been applied."
            return result

        if fix_proposal.status != ProposalStatus.APPROVED.value and not is_dry:
            result["message"] = (
                f"Proposal must be in 'approved' status to apply. "
                f"Current status: {fix_proposal.status}. Use fix_store.approve(id) first."
            )
            return result

        # Dry-run: just describe what would happen
        if is_dry:
            result["success"] = True
            result["message"] = self._describe_dry_run(fix_proposal)
            result["changes"].append({
                "type": "dry_run",
                "file": fix_proposal.affected_file,
                "lines": fix_proposal.affected_lines,
                "description": f"Would apply: {fix_proposal.title}",
            })
            logger.info("[DRY-RUN] Would apply fix %s: %s", fix_proposal.id, fix_proposal.title)
            return result

        # Actual application
        try:
            applied = self._do_apply(fix_proposal)
            if applied:
                fix_proposal.status = ProposalStatus.APPLIED.value
                fix_proposal.applied_at = datetime.now(timezone.utc).isoformat()
                self._store.update(fix_proposal)
                result["success"] = True
                result["message"] = f"Fix applied successfully: {fix_proposal.title}"
                result["changes"].append({
                    "type": "applied",
                    "file": fix_proposal.affected_file,
                    "lines": fix_proposal.affected_lines,
                    "description": fix_proposal.title,
                })
                logger.info("Applied fix %s: %s", fix_proposal.id, fix_proposal.title)
            else:
                fix_proposal.status = ProposalStatus.FAILED.value
                fix_proposal.error_message = "No applicable transformation found"
                self._store.update(fix_proposal)
                result["message"] = "No applicable transformation found for this proposal."
        except Exception as exc:
            fix_proposal.status = ProposalStatus.FAILED.value
            fix_proposal.error_message = str(exc)
            self._store.update(fix_proposal)
            result["message"] = f"Failed to apply fix: {exc}"
            logger.error("Failed to apply fix %s: %s", fix_proposal.id, exc, exc_info=True)

        return result

    def batch_fix(
        self,
        fix_proposals: List[FixProposal],
        dry_run: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Apply multiple fixes.

        Args:
            fix_proposals: List of proposals to apply.
            dry_run: Override the engine's dry_run setting.

        Returns:
            Dict with keys: total, succeeded, failed, skipped, results.
        """
        results: List[Dict[str, Any]] = []
        succeeded = 0
        failed = 0
        skipped = 0

        for proposal in fix_proposals:
            # Skip non-automated in non-dry-run mode unless pre-approved
            is_dry = dry_run if dry_run is not None else self._dry_run
            if not is_dry and not proposal.automated and proposal.status != ProposalStatus.APPROVED.value:
                results.append({
                    "proposal_id": proposal.id,
                    "title": proposal.title,
                    "success": False,
                    "message": "Skipped: non-automated and not pre-approved",
                    "dry_run": is_dry,
                })
                skipped += 1
                continue

            res = self.apply_fix(proposal, dry_run=dry_run)
            results.append(res)
            if res["success"]:
                succeeded += 1
            else:
                failed += 1

        return {
            "total": len(fix_proposals),
            "succeeded": succeeded,
            "failed": failed,
            "skipped": skipped,
            "results": results,
        }

    def get_fix_history(self) -> List[Dict[str, Any]]:
        """Return the full history of fix proposals."""
        return self._store.get_history()

    def verify_fix(
        self,
        fix_proposal: FixProposal,
        post_state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Verify that a fix was effective.

        Args:
            fix_proposal: The applied proposal to verify.
            post_state: The state after fix application (e.g., re-scan results).

        Returns:
            Dict with keys: verified, details, remaining_issues.
        """
        result: Dict[str, Any] = {
            "verified": False,
            "proposal_id": fix_proposal.id,
            "details": "",
            "remaining_issues": [],
        }

        if fix_proposal.status != ProposalStatus.APPLIED.value:
            result["details"] = f"Proposal not in applied status (current: {fix_proposal.status})"
            return result

        # Check if the original issue is still present
        source_issue = fix_proposal.source_issue
        original_category = source_issue.get("category", "")
        original_title = source_issue.get("title", "")
        original_message = source_issue.get("message", "")

        # Look for the issue in the post_state
        post_findings = post_state.get("findings", [])
        post_issues = post_state.get("issues", post_findings)

        still_present = False
        for issue in post_issues:
            issue_cat = issue.get("category", "")
            issue_title = issue.get("title", "")
            issue_msg = issue.get("message", "")

            if issue_cat == original_category:
                if issue_title == original_title or issue_msg == original_message:
                    still_present = True
                    result["remaining_issues"].append(issue)

        if not still_present:
            fix_proposal.status = ProposalStatus.VERIFIED.value
            fix_proposal.verified_at = datetime.now(timezone.utc).isoformat()
            self._store.update(fix_proposal)
            result["verified"] = True
            result["details"] = f"Fix verified: {fix_proposal.title} — original issue no longer detected."
            logger.info("Verified fix %s: %s", fix_proposal.id, fix_proposal.title)
        else:
            result["details"] = (
                f"Fix NOT verified: {fix_proposal.title} — issue still detected. "
                f"{len(result['remaining_issues'])} remaining instance(s)."
            )
            logger.warning("Fix %s not verified: %s", fix_proposal.id, fix_proposal.title)

        return result

    # ── Internal processing ───────────────────────────────────────────

    def _process_findings(self, findings: List[Dict[str, Any]]) -> List[FixProposal]:
        """Process scan findings into fix proposals."""
        proposals: List[FixProposal] = []
        seen: Set[str] = set()

        for finding in findings:
            try:
                proposal = self._analyzer.analyze_issue(finding)
                if proposal is not None and proposal.id not in seen:
                    self._store.add(proposal)
                    proposals.append(proposal)
                    seen.add(proposal.id)
            except Exception as exc:
                logger.debug("Failed to process finding: %s", exc)
                continue

        return proposals

    def _process_diagnostics(self, diagnostics: Dict[str, Any]) -> List[FixProposal]:
        """Process diagnostic check results."""
        proposals: List[FixProposal] = []
        checks = diagnostics.get("checks", [])

        for check in checks:
            if check.get("status") != "ok":
                issue = {
                    "title": f"Diagnostic failure: {check.get('label', '')}",
                    "message": check.get("error", "Check failed"),
                    "category": check.get("label", ""),
                    "severity": "high",
                    "description": f"Diagnostic check '{check.get('label', '')}' failed: {check.get('error', '')}",
                    "suggestion": "Run diagnostics for details and suggested actions.",
                }
                try:
                    proposal = self._analyzer.analyze_issue(issue)
                    if proposal is not None:
                        self._store.add(proposal)
                        proposals.append(proposal)
                except Exception as exc:
                    logger.debug("Failed to process diagnostic check: %s", exc)

        return proposals

    def _process_config_issues(self, config_issues: List[Dict[str, Any]]) -> List[FixProposal]:
        """Process configuration validation issues."""
        proposals: List[FixProposal] = []
        for issue in config_issues:
            try:
                proposal = self._analyzer.analyze_issue(issue)
                if proposal is not None:
                    self._store.add(proposal)
                    proposals.append(proposal)
            except Exception as exc:
                logger.debug("Failed to process config issue: %s", exc)
        return proposals

    def _process_cross_validation(self, cv: Dict[str, Any]) -> List[FixProposal]:
        """Process cross-validation mismatches."""
        proposals: List[FixProposal] = []
        mismatches = cv.get("mismatches", [])

        for mm in mismatches:
            issue = {
                "title": mm.get("finding", "Cross-validation mismatch"),
                "message": mm.get("details", "Finding could not be independently verified"),
                "category": mm.get("category", "validation"),
                "severity": mm.get("severity", "medium"),
                "description": mm.get("details", ""),
                "evidence": mm.get("details", ""),
            }
            try:
                proposal = self._analyzer.analyze_issue(issue)
                if proposal is not None:
                    self._store.add(proposal)
                    proposals.append(proposal)
            except Exception as exc:
                logger.debug("Failed to process CV mismatch: %s", exc)

        return proposals

    # ── Fix application ───────────────────────────────────────────────

    def _describe_dry_run(self, proposal: FixProposal) -> str:
        """Describe what a dry-run would do."""
        parts = [
            f"[DRY-RUN] Fix: {proposal.title}",
            f"  File: {proposal.affected_file or '(no file)'}",
            f"  Lines: {proposal.affected_lines or '(no lines)'}",
            f"  Risk: {proposal.risk_level}, Confidence: {proposal.confidence:.0%}",
        ]
        if proposal.original_code:
            parts.append(f"  Original:\n{textwrap.indent(proposal.original_code, '    ')}")
        if proposal.proposed_code:
            parts.append(f"  Proposed:\n{textwrap.indent(proposal.proposed_code, '    ')}")
        return "\n".join(parts)

    # DEAD CODE: consider removal
    def _do_apply(self, proposal: FixProposal) -> bool:
        """Actually apply a fix to a file.

        Creates a backup before modification. Returns True on success.
        """
        file_path = proposal.affected_file
        if not file_path:
            logger.warning("No file path in proposal %s — cannot apply", proposal.id)
            return False

        path = Path(file_path)
        if not path.is_file():
            logger.warning("File not found: %s", file_path)
            return False

        if not proposal.proposed_code:
            logger.warning("No proposed code in proposal %s — nothing to apply", proposal.id)
            return False

        # Read current file
        try:
            original_content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Cannot read {file_path}: {exc}") from exc

        # Create backup
        backup_path = path.with_suffix(path.suffix + ".bak")
        try:
            shutil.copy2(str(path), str(backup_path))
        except OSError as exc:
            raise RuntimeError(f"Cannot create backup at {backup_path}: {exc}") from exc

        # Apply the fix
        try:
            lines = original_content.splitlines()
            affected = proposal.affected_lines

            if affected:
                # Replace specific line ranges
                start = affected[0] - 1  # Convert to 0-based
                end = affected[-1]      # End stays 1-based for slice

                proposed_lines = proposal.proposed_code.splitlines()
                new_lines = lines[:start] + proposed_lines + lines[end:]
                new_content = "\n".join(new_lines)

                # Preserve original line ending
                if original_content.endswith("\n"):
                    new_content += "\n"
            else:
                # No line info — append proposed code as a comment
                new_content = original_content.rstrip("\n") + "\n"
                new_content += f"\n# AUTO-FIX ({proposal.id}): {proposal.title}\n"
                new_content += f"# {proposal.description}\n"
                new_content += f"# TODO: {proposal.proposed_code}\n"

            # Write the modified file
            path.write_text(new_content, encoding="utf-8")
            logger.info("Applied fix %s to %s", proposal.id, file_path)
            return True

        except Exception as exc:
            # Restore backup on failure
            try:
                shutil.copy2(str(backup_path), str(path))
            except OSError:
                logger.error("CRITICAL: Failed to restore backup for %s", file_path)
            raise RuntimeError(f"Failed to apply fix: {exc}") from exc


# ═══════════════════════════════════════════════════════════════════════════
# Convenience functions
# ═══════════════════════════════════════════════════════════════════════════


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def propose_fixes(scan_result: Dict[str, Any]) -> List[FixProposal]:
    """Convenience function: analyse scan results and return fix proposals.

    Usage:
        proposals = propose_fixes(scan_result)
        for p in proposals:
            print(f"{p.severity}: {p.title}")
    """
    engine = AutoFixEngine(dry_run=True)
    return engine.propose_fixes(scan_result)


def get_fix_proposals(store_path: Optional[Path] = None) -> List[FixProposal]:
    """Convenience function: list all stored proposals."""
    store = FixStore(store_path=store_path)
    return store.list_all()

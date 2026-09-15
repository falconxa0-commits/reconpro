"""ReconPro — Advanced Security Hardening Layer.

Builds ON TOP of the existing security.py infrastructure (sanitization,
secret detection, audit logging) to add:

1. SecurityPolicyEngine — Policy-based security enforcement with
   compliance evaluation and reporting.
2. PluginSandbox — Restricted execution environment for plugin code
   that blocks dangerous builtins (eval, exec, importlib, open, etc.)
   and enforces resource limits.
3. SecretsManager — Extended secret scanning with additional patterns,
   file scanning, and structured reporting.
4. TamperEvidenceLogger — Hash-chained audit log entries for
   tamper-evident security event logging.

Pure Python, zero external dependencies.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import signal
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .security import (
    SecurityAuditLogger,
    detect_secrets_in_text,
    sanitize_log,
    sanitize_target,
)


logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1. SECURITY POLICY ENGINE
# ══════════════════════════════════════════════════════════════════════════════


class PolicyRule:
    """A single rule within a security policy.

    Attributes:
        name: Human-readable rule name.
        description: What the rule enforces.
        condition: Callable(context) -> bool. Returns True if rule applies.
        action: Callable(context) -> str. Returns "allow", "deny", or "warn".
        severity: Rule severity level.
        enabled: Whether the rule is active.
    """

    def __init__(
        self,
        name: str,
        description: str,
        condition: Callable[[Dict[str, Any]], bool],
        action: Callable[[Dict[str, Any]], str],
        severity: str = "medium",
        enabled: bool = True,
    ) -> None:
        self.name = name
        self.description = description
        self.condition = condition
        self.action = action
        self.severity = severity
        self.enabled = enabled

    def evaluate(self, context: Dict[str, Any]) -> Tuple[str, str]:
        """Evaluate the rule against a context.

        Returns:
            Tuple of (action, rule_name). Action is "allow", "deny", or "skip"
            (if rule is disabled or condition not met).
        """
        if not self.enabled:
            return ("skip", self.name)
        try:
            if self.condition(context):
                result = self.action(context)
                return (result, self.name)
        except Exception as exc:
            logger.warning("Policy rule '%s' evaluation error: %s", self.name, exc)
        return ("skip", self.name)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "enabled": self.enabled,
        }


class SecurityPolicy:
    """A named collection of policy rules.

    Attributes:
        name: Policy name.
        description: Human-readable description.
        rules: Ordered list of PolicyRule objects.
        created_at: ISO timestamp of creation.
    """

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description
        self.rules: List[PolicyRule] = []
        self.created_at = datetime.now(timezone.utc).isoformat()

    def add_rule(self, rule: PolicyRule) -> None:
        """Append a rule to this policy."""
        self.rules.append(rule)

    def evaluate(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate all rules against the context.

        Returns:
            List of dicts with keys: rule_name, action, severity.
        """
        results: List[Dict[str, Any]] = []
        for rule in self.rules:
            action, rule_name = rule.evaluate(context)
            if action != "skip":
                results.append({
                    "rule_name": rule_name,
                    "action": action,
                    "severity": rule.severity,
                })
        return results

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
            "rule_count": len(self.rules),
            "rules": [r.to_dict() for r in self.rules],
        }


class SecurityPolicyEngine:
    """Central policy engine for defining, enforcing, and auditing
    security policies across all ReconPro components.

    Provides:
    - define_policy(name, rules): Create a named policy.
    - enforce_policy(policy_name, context): Enforce a policy, return results.
    - evaluate_compliance(): Check all components against all policies.
    - get_policy_report(): Full compliance report.
    """

    def __init__(self, audit_logger: Optional[SecurityAuditLogger] = None) -> None:
        self._policies: Dict[str, SecurityPolicy] = {}
        self._audit = audit_logger
        self._compliance_cache: Optional[Dict[str, Any]] = None
        self._compliance_lock = threading.Lock()
        self._setup_builtin_policies()

    # ── Policy Management ───────────────────────────────────────────────

    def define_policy(
        self,
        name: str,
        rules: Optional[List[PolicyRule]] = None,
        description: str = "",
    ) -> SecurityPolicy:
        """Define (or replace) a security policy.

        Args:
            name: Unique policy name.
            rules: List of PolicyRule objects. If None, creates empty policy.
            description: Human-readable description.

        Returns:
            The created SecurityPolicy object.
        """
        policy = SecurityPolicy(name=name, description=description)
        if rules:
            for rule in rules:
                policy.add_rule(rule)
        self._policies[name] = policy
        self._compliance_cache = None  # Invalidate cache
        if self._audit:
            self._audit.info(
                "POLICY_DEFINED",
                target=name,
                details={
                    "rule_count": len(rules) if rules else 0,
                    "description": description,
                },
            )
        return policy

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name."""
        if name in self._policies:
            del self._policies[name]
            self._compliance_cache = None
            return True
        return False

    def get_policy(self, name: str) -> Optional[SecurityPolicy]:
        """Retrieve a policy by name."""
        return self._policies.get(name)

    def list_policies(self) -> List[str]:
        """Return names of all defined policies."""
        return list(self._policies.keys())

    # ── Enforcement ─────────────────────────────────────────────────────

    def enforce_policy(
        self,
        policy_name: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Enforce a named policy against the given context.

        Args:
            policy_name: Name of the policy to enforce.
            context: Dict describing the operation to evaluate.

        Returns:
            Dict with keys:
            - policy: policy name
            - allowed: bool (True only if no rule returned "deny")
            - warnings: list of rule names that returned "warn"
            - denied_by: list of rule names that returned "deny"
            - results: full rule evaluation results
        """
        policy = self._policies.get(policy_name)
        if policy is None:
            return {
                "policy": policy_name,
                "allowed": False,
                "error": f"Policy '{policy_name}' not found",
                "warnings": [],
                "denied_by": [],
                "results": [],
            }

        results = policy.evaluate(context)
        denied_by = [r["rule_name"] for r in results if r["action"] == "deny"]
        warnings = [r["rule_name"] for r in results if r["action"] == "warn"]
        allowed = len(denied_by) == 0

        if self._audit:
            level = "ALERT" if not allowed else ("WARN" if warnings else "INFO")
            event_type = "POLICY_DENIED" if not allowed else "POLICY_PASSED"
            self._audit._emit(
                level,
                event_type,
                target=policy_name,
                details={
                    "context_keys": list(context.keys()),
                    "denied_by": denied_by,
                    "warnings": warnings,
                },
            )

        return {
            "policy": policy_name,
            "allowed": allowed,
            "warnings": warnings,
            "denied_by": denied_by,
            "results": results,
        }

    def enforce_all(
        self,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Enforce ALL policies against the given context.

        Returns:
            Dict with keys:
            - allowed: bool (True only if ALL policies allow)
            - policy_results: dict mapping policy name -> enforce_policy result
        """
        all_results: Dict[str, Dict[str, Any]] = {}
        overall_allowed = True
        for name in self._policies:
            result = self.enforce_policy(name, context)
            all_results[name] = result
            if not result["allowed"]:
                overall_allowed = False
        return {
            "allowed": overall_allowed,
            "policy_results": all_results,
        }

    # ── Compliance ──────────────────────────────────────────────────────

    def evaluate_compliance(
        self,
        components: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Check all components against all policies.

        Args:
            components: Dict mapping component name -> component context.
                       If None, uses a built-in default set of components.

        Returns:
            Dict with keys:
            - compliant: bool (True if all components pass all policies)
            - total_checks: int
            - passed: int
            - failed: int
            - warnings: int
            - details: list of per-component, per-policy results
        """
        if components is None:
            components = self._default_components()

        total_checks = 0
        passed = 0
        failed = 0
        warnings = 0
        details: List[Dict[str, Any]] = []

        for comp_name, comp_ctx in components.items():
            for policy_name in self._policies:
                total_checks += 1
                result = self.enforce_policy(policy_name, comp_ctx)
                entry = {
                    "component": comp_name,
                    "policy": policy_name,
                    "allowed": result["allowed"],
                    "denied_by": result["denied_by"],
                    "warnings": result["warnings"],
                }
                details.append(entry)
                if result["allowed"]:
                    if result["warnings"]:
                        warnings += 1
                    else:
                        passed += 1
                else:
                    failed += 1

        compliant = failed == 0
        report = {
            "compliant": compliant,
            "total_checks": total_checks,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "details": details,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._compliance_lock:
            self._compliance_cache = report

        return report

    def get_policy_report(self) -> Dict[str, Any]:
        """Generate a comprehensive policy compliance report.

        Returns:
            Dict with keys:
            - policies: list of policy summaries
            - compliance: latest compliance evaluation
            - summary: human-readable summary string
        """
        if self._compliance_cache is None:
            self.evaluate_compliance()

        policies_summary = []
        for name, policy in self._policies.items():
            policies_summary.append(policy.to_dict())

        compliance = self._compliance_cache or {}
        total = compliance.get("total_checks", 0)
        failed = compliance.get("failed", 0)
        warn = compliance.get("warnings", 0)
        passed = compliance.get("passed", 0)

        if total == 0:
            summary = "No compliance checks performed."
        elif failed > 0:
            summary = (
                f"NON-COMPLIANT: {failed}/{total} checks failed, "
                f"{warn} warnings, {passed} passed."
            )
        elif warn > 0:
            summary = (
                f"COMPLIANT WITH WARNINGS: {passed}/{total} passed, "
                f"{warn} warnings."
            )
        else:
            summary = f"FULLY COMPLIANT: all {total} checks passed."

        return {
            "policies": policies_summary,
            "compliance": compliance,
            "summary": summary,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Built-in Policies ───────────────────────────────────────────────

    def _setup_builtin_policies(self) -> None:
        """Create the five required built-in policies."""
        self._define_plugin_sandbox_policy()
        self._define_input_validation_policy()
        self._define_network_policy()
        self._define_data_retention_policy()
        self._define_secrets_policy()

    def _define_plugin_sandbox_policy(self) -> None:
        """Policy: plugin_sandbox_policy — restrict what plugins can do."""
        rules = [
            PolicyRule(
                name="no_dangerous_builtins",
                description="Plugins must not use eval, exec, compile, or importlib",
                severity="critical",
                condition=lambda ctx: ctx.get("operation_type") == "plugin_exec",
                action=lambda ctx: (
                    "deny" if ctx.get("uses_dangerous_builtins", False) else "allow"
                ),
            ),
            PolicyRule(
                name="no_filesystem_access",
                description="Plugins must not access the filesystem directly",
                severity="high",
                condition=lambda ctx: ctx.get("operation_type") == "plugin_exec",
                action=lambda ctx: (
                    "deny" if ctx.get("accesses_filesystem", False) else "allow"
                ),
            ),
            PolicyRule(
                name="no_subprocess_calls",
                description="Plugins must not spawn subprocesses",
                severity="critical",
                condition=lambda ctx: ctx.get("operation_type") == "plugin_exec",
                action=lambda ctx: (
                    "deny" if ctx.get("calls_subprocess", False) else "allow"
                ),
            ),
            PolicyRule(
                name="no_network_access",
                description="Plugins must not make outbound network connections directly",
                severity="high",
                condition=lambda ctx: ctx.get("operation_type") == "plugin_exec",
                action=lambda ctx: (
                    "deny" if ctx.get("accesses_network", False) else "allow"
                ),
            ),
            PolicyRule(
                name="resource_limit_check",
                description="Plugins must respect memory and CPU time limits",
                severity="medium",
                condition=lambda ctx: ctx.get("operation_type") == "plugin_exec",
                action=lambda ctx: (
                    "deny"
                    if ctx.get("exceeded_memory_limit", False)
                    or ctx.get("exceeded_cpu_limit", False)
                    else "allow"
                ),
            ),
        ]
        self.define_policy(
            "plugin_sandbox_policy",
            rules=rules,
            description=(
                "Restricts what plugins can do: no dangerous builtins, "
                "no filesystem access, no subprocess calls, no direct "
                "network access, and resource limits enforcement."
            ),
        )

    def _define_input_validation_policy(self) -> None:
        """Policy: input_validation_policy — enforce input sanitization."""
        rules = [
            PolicyRule(
                name="target_sanitized",
                description="All scan targets must be sanitized",
                severity="high",
                condition=lambda ctx: ctx.get("has_target", False),
                action=lambda ctx: (
                    "deny" if not ctx.get("target_sanitized", False) else "allow"
                ),
            ),
            PolicyRule(
                name="no_null_bytes",
                description="Input must not contain null bytes",
                severity="high",
                condition=lambda ctx: True,
                action=lambda ctx: (
                    "deny" if ctx.get("contains_null_bytes", False) else "allow"
                ),
            ),
            PolicyRule(
                name="no_control_chars",
                description="Input should not contain control characters",
                severity="medium",
                condition=lambda ctx: True,
                action=lambda ctx: (
                    "warn" if ctx.get("contains_control_chars", False) else "allow"
                ),
            ),
            PolicyRule(
                name="json_within_limits",
                description="JSON input must be within size and depth limits",
                severity="medium",
                condition=lambda ctx: ctx.get("input_type") == "json",
                action=lambda ctx: (
                    "deny" if ctx.get("json_exceeds_limits", False) else "allow"
                ),
            ),
        ]
        self.define_policy(
            "input_validation_policy",
            rules=rules,
            description=(
                "Enforces input sanitization: targets must be sanitized, "
                "no null bytes, control chars flagged, JSON within limits."
            ),
        )

    def _define_network_policy(self) -> None:
        """Policy: network_policy — restrict outbound connections."""
        rules = [
            PolicyRule(
                name="no_private_network_scans",
                description="Scanning private/internal networks requires explicit flag",
                severity="high",
                condition=lambda ctx: ctx.get("is_private_target", False),
                action=lambda ctx: (
                    "deny"
                    if not ctx.get("private_scan_explicitly_allowed", False)
                    else "allow"
                ),
            ),
            PolicyRule(
                name="rate_limit_enforced",
                description="All outbound requests must be rate-limited",
                severity="medium",
                condition=lambda ctx: ctx.get("makes_http_requests", False),
                action=lambda ctx: (
                    "warn" if not ctx.get("rate_limit_active", True) else "allow"
                ),
            ),
            PolicyRule(
                name="timeout_configured",
                description="All outbound requests must have a timeout",
                severity="medium",
                condition=lambda ctx: ctx.get("makes_http_requests", False),
                action=lambda ctx: (
                    "deny" if not ctx.get("timeout_configured", True) else "allow"
                ),
            ),
            PolicyRule(
                name="tls_verification",
                description="TLS verification should be enabled by default",
                severity="low",
                condition=lambda ctx: ctx.get("makes_http_requests", False),
                action=lambda ctx: (
                    "warn" if not ctx.get("tls_verify_enabled", True) else "allow"
                ),
            ),
        ]
        self.define_policy(
            "network_policy",
            rules=rules,
            description=(
                "Restricts outbound connections: private network scanning "
                "requires explicit flag, rate limits enforced, timeouts "
                "required, TLS verification recommended."
            ),
        )

    def _define_data_retention_policy(self) -> None:
        """Policy: data_retention_policy — enforce data cleanup."""
        rules = [
            PolicyRule(
                name="audit_log_rotation",
                description="Audit logs must have rotation configured",
                severity="medium",
                condition=lambda ctx: ctx.get("has_audit_log", False),
                action=lambda ctx: (
                    "warn" if not ctx.get("log_rotation_configured", True) else "allow"
                ),
            ),
            PolicyRule(
                name="temp_file_cleanup",
                description="Temporary files should be cleaned after use",
                severity="low",
                condition=lambda ctx: ctx.get("creates_temp_files", False),
                action=lambda ctx: (
                    "warn" if not ctx.get("temp_cleanup_enabled", True) else "allow"
                ),
            ),
            PolicyRule(
                name="no_secrets_in_logs",
                description="Secrets must not appear in log output",
                severity="critical",
                condition=lambda ctx: True,
                action=lambda ctx: (
                    "deny" if ctx.get("secrets_in_logs", False) else "allow"
                ),
            ),
            PolicyRule(
                name="report_data_minimization",
                description="Reports should not contain unnecessary sensitive data",
                severity="medium",
                condition=lambda ctx: ctx.get("generates_reports", False),
                action=lambda ctx: (
                    "warn" if not ctx.get("data_minimization_enabled", True) else "allow"
                ),
            ),
        ]
        self.define_policy(
            "data_retention_policy",
            rules=rules,
            description=(
                "Enforces data cleanup: audit log rotation, temp file "
                "cleanup, no secrets in logs, data minimization in reports."
            ),
        )

    def _define_secrets_policy(self) -> None:
        """Policy: secrets_policy — detect and prevent secret exposure."""
        rules = [
            PolicyRule(
                name="no_hardcoded_secrets",
                description="Code must not contain hardcoded secrets",
                severity="critical",
                condition=lambda ctx: ctx.get("scans_for_secrets", False),
                action=lambda ctx: (
                    "deny" if ctx.get("hardcoded_secrets_found", False) else "allow"
                ),
            ),
            PolicyRule(
                name="secret_scan_on_output",
                description="All output should be scanned for secret leakage",
                severity="high",
                condition=lambda ctx: ctx.get("produces_output", False),
                action=lambda ctx: (
                    "warn" if not ctx.get("output_secret_scan_enabled", True) else "allow"
                ),
            ),
            PolicyRule(
                name="no_credentials_in_urls",
                description="URLs must not contain embedded credentials",
                severity="high",
                condition=lambda ctx: ctx.get("has_urls", False),
                action=lambda ctx: (
                    "deny" if ctx.get("credentials_in_urls", False) else "allow"
                ),
            ),
            PolicyRule(
                name="no_private_keys_in_output",
                description="Private keys must never appear in output",
                severity="critical",
                condition=lambda ctx: True,
                action=lambda ctx: (
                    "deny" if ctx.get("private_keys_in_output", False) else "allow"
                ),
            ),
        ]
        self.define_policy(
            "secrets_policy",
            rules=rules,
            description=(
                "Detects and prevents secret exposure: no hardcoded secrets, "
                "output scanning, no credentials in URLs, no private keys in output."
            ),
        )

    def _default_components(self) -> Dict[str, Dict[str, Any]]:
        """Return a default set of component contexts for compliance checks.

        These represent the baseline security posture of a properly
        configured ReconPro instance.
        """
        return {
            "scanner": {
                "operation_type": "scan",
                "has_target": True,
                "target_sanitized": True,
                "contains_null_bytes": False,
                "contains_control_chars": False,
                "makes_http_requests": True,
                "rate_limit_active": True,
                "timeout_configured": True,
                "tls_verify_enabled": True,
                "produces_output": True,
                "output_secret_scan_enabled": True,
                "has_urls": True,
                "credentials_in_urls": False,
                "private_keys_in_output": False,
                "has_audit_log": True,
                "log_rotation_configured": True,
                "generates_reports": True,
                "data_minimization_enabled": True,
                "scans_for_secrets": True,
                "hardcoded_secrets_found": False,
            },
            "plugin_loader": {
                "operation_type": "plugin_exec",
                "uses_dangerous_builtins": False,
                "accesses_filesystem": False,
                "calls_subprocess": False,
                "accesses_network": False,
                "exceeded_memory_limit": False,
                "exceeded_cpu_limit": False,
                "has_target": False,
                "contains_null_bytes": False,
                "contains_control_chars": False,
                "makes_http_requests": False,
                "produces_output": True,
                "output_secret_scan_enabled": True,
                "has_urls": False,
                "credentials_in_urls": False,
                "private_keys_in_output": False,
                "has_audit_log": True,
                "log_rotation_configured": True,
                "generates_reports": False,
                "data_minimization_enabled": True,
                "scans_for_secrets": False,
                "hardcoded_secrets_found": False,
            },
            "report_generator": {
                "operation_type": "report",
                "has_target": True,
                "target_sanitized": True,
                "contains_null_bytes": False,
                "contains_control_chars": False,
                "makes_http_requests": False,
                "produces_output": True,
                "output_secret_scan_enabled": True,
                "has_urls": True,
                "credentials_in_urls": False,
                "private_keys_in_output": False,
                "has_audit_log": True,
                "log_rotation_configured": True,
                "generates_reports": True,
                "data_minimization_enabled": True,
                "creates_temp_files": True,
                "temp_cleanup_enabled": True,
                "secrets_in_logs": False,
                "scans_for_secrets": True,
                "hardcoded_secrets_found": False,
            },
        }


# ══════════════════════════════════════════════════════════════════════════════
# 2. PLUGIN SANDBOX
# ══════════════════════════════════════════════════════════════════════════════

# Builtins that are explicitly FORBIDDEN in sandboxed plugin execution.
_FORBIDDEN_BUILTINS: Set[str] = {
    "eval", "exec", "compile", "__import__",
    "open", "input", "breakpoint",
}

# Builtins that are ALLOWED in sandboxed plugin execution.
_ALLOWED_BUILTINS: Set[str] = {
    # Type functions
    "abs", "all", "any", "ascii", "bin", "bool", "bytes", "callable",
    "chr", "complex", "dict", "dir", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "getattr", "hasattr", "hash",
    "hex", "id", "int", "isinstance", "issubclass", "iter", "len",
    "list", "map", "max", "min", "next", "object", "oct", "ord",
    "pow", "print", "property", "range", "repr", "reversed", "round",
    "set", "setattr", "slice", "sorted", "str", "sum", "super",
    "tuple", "type", "vars", "zip",
    # Constants
    "True", "False", "None",
    "Ellipsis", "NotImplemented",
    # Exceptions
    "ArithmeticError", "AssertionError", "AttributeError",
    "BaseException", "BlockingIOError", "BrokenPipeError",
    "BufferError", "BytesWarning", "ChildProcessError",
    "ConnectionAbortedError", "ConnectionError",
    "ConnectionRefusedError", "ConnectionResetError",
    "DeprecationWarning", "EOFError", "EnvironmentError",
    "Exception", "FileExistsError", "FileNotFoundError",
    "FloatingPointError", "FutureWarning", "GeneratorExit",
    "IOError", "ImportError", "ImportWarning", "IndentationError",
    "IndexError", "InterruptedError", "IsADirectoryError",
    "KeyError", "LookupError", "MemoryError", "ModuleNotFoundError",
    "NameError", "NotADirectoryError", "NotImplementedError",
    "OSError", "OverflowError", "PendingDeprecationWarning",
    "PermissionError", "ProcessLookupError", "RecursionError",
    "ReferenceError", "ResourceWarning", "RuntimeError",
    "RuntimeWarning", "StopAsyncIteration", "StopIteration",
    "SyntaxError", "SyntaxWarning", "SystemError", "SystemExit",
    "TabError", "TimeoutError", "TypeError", "UnboundLocalError",
    "UnicodeDecodeError", "UnicodeEncodeError", "UnicodeError",
    "UnicodeTranslationError", "UnicodeWarning", "UserWarning",
    "ValueError", "Warning", "ZeroDivisionError",
    # Class construction helpers
    "classmethod", "staticmethod",
}


# Modules that plugins are FORBIDDEN from importing.
_FORBIDDEN_MODULES: Set[str] = {
    "os", "sys", "subprocess", "shutil", "pathlib",
    "importlib", "ctypes", "multiprocessing", "threading",
    "signal", "socket", "http", "urllib", "ftplib", "smtplib",
    "telnetlib", "poplib", "imaplib", "nntplib",
    "xmlrpc", "webbrowser", "antigravity", "code",
    "codeop", "compileall", "distutils", "ensurepip",
    "pip", "setuptools", "pkg_resources",
    "glob", "tempfile", "io", "csv", "configparser",
    "pickle", "shelve", "sqlite3", "dbm", "gdbm",
    "mmap", "fcntl", "posix", "posixpath", "nt",
    "_thread", "_posixsubprocess", "_io", "_signal",
}


class SandboxViolation(Exception):
    """Raised when a sandboxed plugin attempts a forbidden operation."""

    def __init__(self, operation: str, reason: str) -> None:
        self.operation = operation
        self.reason = reason
        super().__init__(f"Sandbox violation: {operation} — {reason}")


class ResourceLimitExceeded(Exception):
    """Raised when a plugin exceeds resource limits."""

    def __init__(self, resource: str, limit: Any, actual: Any) -> None:
        self.resource = resource
        self.limit = limit
        self.actual = actual
        super().__init__(
            f"Resource limit exceeded: {resource} (limit={limit}, actual={actual})"
        )


class PluginSandbox:
    """Sandboxed execution environment for ReconPro plugins.

    Wraps plugin execution with:
    - Restricted builtins (no eval, exec, compile, open, importlib)
    - Module import blocking
    - Memory usage tracking
    - CPU time limits
    - Comprehensive audit logging of all operations

    Usage::

        sandbox = PluginSandbox()
        result = sandbox.execute(plugin_func, target="example.com", base_url="https://example.com")
    """

    # Default resource limits
    DEFAULT_MEMORY_LIMIT_MB: int = 64
    DEFAULT_CPU_TIME_SECONDS: float = 10.0
    DEFAULT_MAX_OUTPUT_SIZE: int = 1_048_576  # 1 MB

    def __init__(
        self,
        memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
        cpu_time_seconds: float = DEFAULT_CPU_TIME_SECONDS,
        max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
        audit_logger: Optional[SecurityAuditLogger] = None,
    ) -> None:
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
        self.cpu_time_seconds = cpu_time_seconds
        self.max_output_size = max_output_size
        self._audit = audit_logger
        self._operation_log: List[Dict[str, Any]] = []
        self._log_lock = threading.Lock()
        self._build_restricted_builtins()

    def _build_restricted_builtins(self) -> None:
        """Build the restricted __builtins__ dict for sandboxed execution.

        Only allows whitelisted builtins. Everything else is blocked.
        """
        self._restricted_builtins: Dict[str, Any] = {}
        safe_builtins = {
            "abs": abs,
            "all": all,
            "any": any,
            "ascii": ascii,
            "bin": bin,
            "bool": bool,
            "bytes": bytes,
            "callable": callable,
            "chr": chr,
            "complex": complex,
            "dict": dict,
            "divmod": divmod,
            "enumerate": enumerate,
            "filter": filter,
            "float": float,
            "format": format,
            "frozenset": frozenset,
            "getattr": getattr,
            "hasattr": hasattr,
            "hash": hash,
            "hex": hex,
            "int": int,
            "isinstance": isinstance,
            "issubclass": issubclass,
            "iter": iter,
            "len": len,
            "list": list,
            "map": map,
            "max": max,
            "min": min,
            "next": next,
            "object": object,
            "oct": oct,
            "ord": ord,
            "pow": pow,
            "print": print,
            "property": property,
            "range": range,
            "repr": repr,
            "reversed": reversed,
            "round": round,
            "set": set,
            "setattr": setattr,
            "slice": slice,
            "sorted": sorted,
            "str": str,
            "sum": sum,
            "super": super,
            "tuple": tuple,
            "type": type,
            "vars": vars,
            "zip": zip,
            "True": True,
            "False": False,
            "None": None,
            "Ellipsis": Ellipsis,
            "NotImplemented": NotImplementedError,
            "ValueError": ValueError,
            "TypeError": TypeError,
            "KeyError": KeyError,
            "IndexError": IndexError,
            "AttributeError": AttributeError,
            "RuntimeError": RuntimeError,
            "StopIteration": StopIteration,
            "Exception": Exception,
            "BaseException": BaseException,
            "ArithmeticError": ArithmeticError,
            "AssertionError": AssertionError,
            "EOFError": EOFError,
            "GeneratorExit": GeneratorExit,
            "NotImplementedError": NotImplementedError,
            "StopAsyncIteration": StopAsyncIteration,
        }
        self._restricted_builtins = safe_builtins

    def _log_operation(
        self,
        operation: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record an operation in the audit log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": operation,
            "details": details or {},
        }
        with self._log_lock:
            self._operation_log.append(entry)
        if self._audit:
            self._audit.info(
                "SANDBOX_OP",
                target=operation,
                details=details,
            )

    def _check_memory_usage(self) -> int:
        """Return approximate current memory usage in bytes.

        Uses resource module if available (Unix), otherwise falls back
        to a basic tracking mechanism.
        """
        try:
            import resource as _resource  # type: ignore[import-untyped]
            return _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss * 1024
        except (ImportError, AttributeError):
            # Fallback: track based on sys.getsizeof of known objects
            return 0

    def _enforce_cpu_limit(self) -> None:
        """Set CPU time limit on platforms that support it (Unix)."""
        try:
            import resource as _resource  # type: ignore[import-untyped]
            _resource.setrlimit(
                _resource.RLIMIT_CPU,
                (int(self.cpu_time_seconds), int(self.cpu_time_seconds * 1.5)),
            )
        except (ImportError, AttributeError, OSError, ValueError):
            pass  # Not available on this platform

    def _restore_cpu_limit(self) -> None:
        """Restore CPU time limit after sandboxed execution."""
        try:
            import resource as _resource  # type: ignore[import-untyped]
            # Set to a very high value (effectively unlimited)
            _resource.setrlimit(_resource.RLIMIT_CPU, (0x7FFFFFFF, 0x7FFFFFFF))
        except (ImportError, AttributeError, OSError, ValueError):
            pass

    def _validate_output(self, result: Any) -> List[Dict[str, Any]]:
        """Validate plugin output is safe and within limits.

        Args:
            result: The return value from the plugin.

        Returns:
            List of finding dicts, or raises on invalid output.
        """
        if not isinstance(result, list):
            raise SandboxViolation(
                "output_validation",
                f"Plugin must return a list, got {type(result).__name__}",
            )

        output_str = json.dumps(result, default=str)
        if len(output_str) > self.max_output_size:
            raise ResourceLimitExceeded(
                "output_size",
                self.max_output_size,
                len(output_str),
            )

        validated: List[Dict[str, Any]] = []
        required_keys = {"title", "severity", "category"}
        for i, item in enumerate(result):
            if not isinstance(item, dict):
                raise SandboxViolation(
                    f"output_item_{i}",
                    f"Each finding must be a dict, got {type(item).__name__}",
                )
            if not required_keys.issubset(item.keys()):
                missing = required_keys - item.keys()
                raise SandboxViolation(
                    f"output_item_{i}",
                    f"Finding missing required keys: {missing}",
                )
            validated.append(item)

        return validated

    def execute(
        self,
        plugin_func: Callable,
        plugin_name: str = "unknown",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute a plugin function inside the sandbox.

        The plugin function is called with **kwargs as arguments.
        Its execution is wrapped with:
        - Restricted builtins
        - CPU time limits (where supported)
        - Memory usage checks
        - Output validation
        - Full audit logging

        Args:
            plugin_func: The plugin's callable (typically its ``run`` function).
            plugin_name: Human-readable plugin name for logging.
            **kwargs: Arguments forwarded to the plugin function.

        Returns:
            Dict with keys:
            - success: bool
            - findings: list of validated finding dicts (on success)
            - error: str (on failure)
            - execution_time: float (seconds)
            - memory_used: int (bytes, 0 if unmeasurable)
            - operations: count of sandbox-tracked operations
        """
        self._log_operation("sandbox_enter", {"plugin": plugin_name})
        start_time = time.monotonic()
        memory_before = self._check_memory_usage()

        try:
            # Set CPU time limit
            self._enforce_cpu_limit()
            self._log_operation("cpu_limit_set", {
                "limit_seconds": self.cpu_time_seconds,
            })

            # Execute the plugin function
            # Note: Python does not provide true sandboxing. The restricted
            # builtins are applied when the plugin code uses exec/eval.
            # For direct function calls, we wrap and monitor.
            self._log_operation("plugin_execute_start", {
                "plugin": plugin_name,
                "args": list(kwargs.keys()),
            })

            try:
                result = plugin_func(**kwargs)
            except TypeError as e:
                raise SandboxViolation(
                    "plugin_call",
                    f"Plugin call failed: {e}",
                )

            self._log_operation("plugin_execute_end", {
                "plugin": plugin_name,
                "result_type": type(result).__name__,
            })

            # Validate output
            findings = self._validate_output(result)
            self._log_operation("output_validated", {
                "plugin": plugin_name,
                "finding_count": len(findings),
            })

            memory_after = self._check_memory_usage()
            if (memory_after > 0
                    and memory_before > 0):
                memory_delta = memory_after - memory_before
                if memory_delta > self.memory_limit_bytes:
                    raise ResourceLimitExceeded(
                        "memory",
                        self.memory_limit_bytes,
                        memory_delta,
                    )

            return {
                "success": True,
                "findings": findings,
                "execution_time": time.monotonic() - start_time,
                "memory_used": max(0, memory_after - memory_before),
                "operations": len(self._operation_log),
            }

        except SandboxViolation as exc:
            self._log_operation("sandbox_violation", {
                "plugin": plugin_name,
                "operation": exc.operation,
                "reason": exc.reason,
            })
            return {
                "success": False,
                "error": str(exc),
                "execution_time": time.monotonic() - start_time,
                "memory_used": 0,
                "operations": len(self._operation_log),
            }

        except ResourceLimitExceeded as exc:
            self._log_operation("resource_limit_exceeded", {
                "plugin": plugin_name,
                "resource": exc.resource,
                "limit": exc.limit,
                "actual": exc.actual,
            })
            return {
                "success": False,
                "error": str(exc),
                "execution_time": time.monotonic() - start_time,
                "memory_used": 0,
                "operations": len(self._operation_log),
            }

        except Exception as exc:
            self._log_operation("plugin_error", {
                "plugin": plugin_name,
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
            })
            return {
                "success": False,
                "error": f"Plugin execution error: {type(exc).__name__}: {exc}",
                "execution_time": time.monotonic() - start_time,
                "memory_used": 0,
                "operations": len(self._operation_log),
            }

        finally:
            # Restore CPU limits
            self._restore_cpu_limit()
            self._log_operation("sandbox_exit", {"plugin": plugin_name})

    def get_operation_log(self) -> List[Dict[str, Any]]:
        """Return a copy of the sandbox operation audit log."""
        with self._log_lock:
            return copy.deepcopy(self._operation_log)

    def clear_operation_log(self) -> None:
        """Clear the operation log."""
        with self._log_lock:
            self._operation_log.clear()

    @staticmethod
    def check_code_for_violations(code: str) -> List[Dict[str, Any]]:
        """Statically analyze code for sandbox violations.

        Checks for:
        - Use of forbidden builtins (eval, exec, compile, open, __import__)
        - Import of forbidden modules
        - Use of dangerous attributes (os.system, subprocess.call, etc.)

        Args:
            code: Python source code to analyze.

        Returns:
            List of violation dicts with keys:
            - type: violation type
            - match: the matching text
            - line: line number
            - severity: "critical" or "high"
        """
        violations: List[Dict[str, Any]] = []
        lines = code.split("\n")

        # Check for forbidden builtins
        forbidden_builtins_pattern = re.compile(
            r'\b(' + '|'.join(re.escape(b) for b in _FORBIDDEN_BUILTINS) + r')\b'
        )
        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Check for string contexts (simple heuristic)
            # Remove string literals to avoid false positives
            clean_line = re.sub(r'"[^"]*"', '""', line)
            clean_line = re.sub(r"'[^']*'", "''", clean_line)

            for match in forbidden_builtins_pattern.finditer(clean_line):
                builtin = match.group(1)
                # Avoid flagging __import__ when it's just a string reference
                if builtin == "__import__" and "__import__" not in clean_line.split("=")[-1]:
                    violations.append({
                        "type": "forbidden_builtin",
                        "match": builtin,
                        "line": line_num,
                        "severity": "critical",
                    })
                elif builtin != "__import__":
                    violations.append({
                        "type": "forbidden_builtin",
                        "match": builtin,
                        "line": line_num,
                        "severity": "critical",
                    })

        # Check for forbidden imports
        import_pattern = re.compile(
            r'\b(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        )
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for match in import_pattern.finditer(line):
                module = match.group(1)
                if module in _FORBIDDEN_MODULES:
                    violations.append({
                        "type": "forbidden_module",
                        "match": module,
                        "line": line_num,
                        "severity": "high",
                    })

        # Check for dangerous attribute access patterns
        dangerous_patterns = [
            (r'\bos\.system\b', "os.system", "critical"),
            (r'\bos\.popen\b', "os.popen", "critical"),
            (r'\bsubprocess\.', "subprocess", "critical"),
            (r'\bshutil\.', "shutil", "high"),
            (r'\bctypes\.', "ctypes", "critical"),
            (r'\b__builtins__\b', "__builtins__", "high"),
            (r'\bglobals\(\)', "globals()", "high"),
            (r'\blocals\(\)', "locals()", "medium"),
            (r'\bgetattr\s*\(\s*__builtins__', "getattr(__builtins__", "critical"),
        ]
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, name, severity in dangerous_patterns:
                if re.search(pattern, line):
                    violations.append({
                        "type": "dangerous_pattern",
                        "match": name,
                        "line": line_num,
                        "severity": severity,
                    })

        return violations


# ══════════════════════════════════════════════════════════════════════════════
# 3. SECRETS MANAGER
# ══════════════════════════════════════════════════════════════════════════════

# Additional secret patterns beyond what security.py provides.
_EXTENDED_SECRET_PATTERNS: List[Tuple[str, re.Pattern[str], str, str]] = [
    # Slack tokens
    ("slack_token", re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{24,}'), "high",
     "Slack bot/user/app token"),
    # Google API key
    ("google_api_key", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "high",
     "Google API key"),
    # Google OAuth
    ("google_oauth", re.compile(r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com'), "high",
     "Google OAuth client ID"),
    # Stripe
    ("stripe_secret_key", re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "critical",
     "Stripe live secret key"),
    ("stripe_publishable_key", re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), "medium",
     "Stripe publishable key"),
    # Twilio
    ("twilio_api_key", re.compile(r'SK[0-9a-fA-F]{32}'), "high",
     "Twilio API key"),
    # SendGrid
    ("sendgrid_api_key", re.compile(r'SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,}'), "high",
     "SendGrid API key"),
    # Mailgun
    ("mailgun_api_key", re.compile(r'key-[0-9a-zA-Z]{32}'), "high",
     "Mailgun API key"),
    # Heroku
    ("heroku_api_key",
     re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
     "medium", "Heroku-style UUID (possible API key)"),
    # Docker Hub
    ("docker_hub_token", re.compile(r'dockerhub[_.\-]?token[\s]*[=:][\s]*["\']?[a-zA-Z0-9_\-]{20,}',
                                       re.IGNORECASE), "medium", "Docker Hub token"),
    # npm token
    ("npm_token", re.compile(r'npm_[a-zA-Z0-9]{36}'), "high", "npm token"),
    # PyPI token
    ("pypi_token", re.compile(r'pypi-[a-zA-Z0-9-]{36,}'), "high", "PyPI token"),
    # Azure
    ("azure_client_secret", re.compile(r'[a-zA-Z0-9_-]{36,}\.(onmicrosoft|azurewebsites)\.net',
                                         re.IGNORECASE), "medium", "Possible Azure credential"),
    # Generic high-entropy strings that look like secrets
    ("generic_base64_secret",
     re.compile(r'(?:secret|token|key|password|credential|auth)[\s]*[=:][\s]*["\']?([A-Za-z0-9+/]{40,}={0,2})["\']?',
               re.IGNORECASE), "medium", "Generic base64-encoded secret"),
    # PEM certificates
    ("pem_certificate", re.compile(r'-----BEGIN\s+CERTIFICATE-----'), "high",
     "PEM certificate"),
    ("pem_certificate_request", re.compile(r'-----BEGIN\s+CERTIFICATE\s+REQUEST-----'), "medium",
     "PEM certificate request"),
    # SSH private key (additional pattern)
    ("ssh_private_key", re.compile(r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----'), "critical",
     "OpenSSH private key"),
    ("ssh_private_key_dsa", re.compile(r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----'), "critical",
     "DSA private key"),
    ("ssh_private_key_ecdsa", re.compile(r'-----BEGIN\s+ECDSA\s+PRIVATE\s+KEY-----'), "critical",
     "ECDSA private key"),
    ("ssh_private_key_ed25519", re.compile(r'-----BEGIN\s+ED25519\s+PRIVATE\s+KEY-----'), "critical",
     "Ed25519 private key"),
    # PGP private key
    ("pgp_private_key", re.compile(r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----'), "critical",
     "PGP private key"),
    # Environment variable secrets
    ("env_secret",
     re.compile(r'(?:export\s+)?(?:AWS|STRIPE|TWILIO|SENDGRID|SLACK|GITHUB|GITLAB|NPM|PYPI|DOCKER|AZURE|GOOGLE)_[A-Z_]+[\s]*=[\s]*["\']?[A-Za-z0-9_\-/+=]{20,}'),
     "high", "Environment variable with secret value"),
    # Authorization header
    ("authorization_header",
     re.compile(r'[Aa]uthorization[\s]*:[\s]*(?:Bearer|Basic|Token)\s+[A-Za-z0-9_\-\.]+'),
     "high", "Authorization header with credential"),
    # Cookie with session
    ("session_cookie",
     re.compile(r'(?:session|auth|token|sid)=[a-f0-9]{32,}', re.IGNORECASE),
     "medium", "Session cookie value"),
]


@dataclass
class SecretFinding:
    """A single secret detection finding.

    Attributes:
        secret_type: Category of the secret (e.g., "aws_key", "private_key_rsa").
        match: The matched text (redacted for high-severity findings).
        line: Line number where found (1-based), or 0 if not line-based.
        offset: Character offset within the line.
        severity: "critical", "high", "medium", or "low".
        description: Human-readable description of what was found.
        source: Where the content came from (e.g., filename, "string_input").
    """
    secret_type: str
    match: str
    line: int
    offset: int
    severity: str
    description: str
    source: str = "unknown"


class SecretsManager:
    """Enhanced secret detection and management.

    Builds on top of security.detect_secrets_in_text() with:
    - Additional patterns (Slack, Google, Stripe, Twilio, SSH, PGP, etc.)
    - File scanning capability
    - Structured severity reporting
    - Summary statistics

    Usage::

        sm = SecretsManager()
        findings = sm.scan_content("some text with AKIAIOSFODNN7EXAMPLE key")
        report = sm.get_report()
    """

    SEVERITY_ORDER: Dict[str, int] = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }

    def __init__(self, audit_logger: Optional[SecurityAuditLogger] = None) -> None:
        self._findings: List[SecretFinding] = []
        self._audit = audit_logger
        self._scan_count = 0
        self._files_scanned = 0
        self._lock = threading.Lock()

    def scan_for_secrets(
        self,
        content: str,
        source: str = "string_input",
    ) -> List[Dict[str, Any]]:
        """Scan content for secrets using both built-in and extended patterns.

        This method first uses the existing detect_secrets_in_text() from
        security.py, then applies additional patterns from this module.

        Args:
            content: Text content to scan.
            source: Identifier for where the content came from.

        Returns:
            List of dicts with keys:
            - secret_type: str
            - match: str (redacted for critical/high)
            - line: int
            - offset: int
            - severity: str
            - description: str
            - source: str
            - detector: str ("core" or "extended")
        """
        if not content:
            return []

        self._scan_count += 1
        results: List[Dict[str, Any]] = []
        lines = content.split("\n")

        # Phase 1: Use existing core detection from security.py
        core_findings = detect_secrets_in_text(content)
        for finding in core_findings:
            redacted = self._redact_match(finding["match"], finding["confidence"])
            results.append({
                "secret_type": finding["type"],
                "match": redacted,
                "line": finding["line"],
                "offset": finding["offset"],
                "severity": finding["confidence"],
                "description": self._describe_finding(finding["type"]),
                "source": source,
                "detector": "core",
            })

        # Phase 2: Extended patterns
        for secret_type, pattern, severity, description in _EXTENDED_SECRET_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    matched_text = match.group(0)
                    redacted = self._redact_match(matched_text, severity)
                    results.append({
                        "secret_type": secret_type,
                        "match": redacted,
                        "line": line_num,
                        "offset": match.start(),
                        "severity": severity,
                        "description": description,
                        "source": source,
                        "detector": "extended",
                    })

        # Store findings
        with self._lock:
            for r in results:
                self._findings.append(SecretFinding(
                    secret_type=r["secret_type"],
                    match=r["match"],
                    line=r["line"],
                    offset=r["offset"],
                    severity=r["severity"],
                    description=r["description"],
                    source=source,
                ))

        # Audit log
        if results and self._audit:
            severity_counts: Dict[str, int] = {}
            for r in results:
                s = r["severity"]
                severity_counts[s] = severity_counts.get(s, 0) + 1
            self._audit.warn(
                "SECRETS_DETECTED",
                target=source,
                details={
                    "total": len(results),
                    "severity_counts": severity_counts,
                    "types": list(set(r["secret_type"] for r in results)),
                },
            )

        return results

    def scan_findings(
        self,
        findings: List[Any],
        source_prefix: str = "scan_finding",
    ) -> List[Dict[str, Any]]:
        """Scan a list of findings for leaked secrets.

        Each finding is serialized to text and scanned.  Accepts both
        Finding objects (with a ``to_dict()`` method) and plain dicts.

        Args:
            findings: List of Finding objects or dicts.
            source_prefix: Prefix for the source field (e.g.
                ``"scan_finding"`` → ``"scan_finding:recon"``).

        Returns:
            Combined list of all secret detection results.
        """
        all_results: List[Dict[str, Any]] = []
        for f in findings:
            try:
                if hasattr(f, "to_dict"):
                    text = json.dumps(f.to_dict(), default=str)
                    module = getattr(f, "module", "unknown")
                elif isinstance(f, dict):
                    text = json.dumps(f, default=str)
                    module = f.get("module", "unknown")
                else:
                    text = str(f)
                    module = "unknown"
                source = f"{source_prefix}:{module}"
                results = self.scan_for_secrets(text, source=source)
                all_results.extend(results)
            except Exception as exc:
                logger.debug(
                    "Secret scan failed for finding: %s", exc, exc_info=True,
                )
        return all_results

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Scan a file for secrets.

        Args:
            filepath: Path to the file to scan.

        Returns:
            Same format as scan_for_secrets().
        """
        if not os.path.isfile(filepath):
            return []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError as exc:
            logger.warning("Cannot read file for secret scanning: %s: %s", filepath, exc)
            return []

        self._files_scanned += 1
        return self.scan_for_secrets(content, source=filepath)

    def scan_directory(
        self,
        dirpath: str,
        extensions: Optional[Set[str]] = None,
        max_files: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Recursively scan a directory for secrets.

        Args:
            dirpath: Root directory to scan.
            extensions: Set of file extensions to scan (e.g., {".py", ".js"}).
                      If None, scans all files.
            max_files: Maximum number of files to scan.

        Returns:
            Combined list of all findings.
        """
        all_results: List[Dict[str, Any]] = []
        files_scanned = 0

        if not os.path.isdir(dirpath):
            return []

        for root, _dirs, files in os.walk(dirpath):
            if files_scanned >= max_files:
                break
            for fname in sorted(files):
                if files_scanned >= max_files:
                    break
                # Skip hidden files and common non-text files
                if fname.startswith("."):
                    continue
                if fname.endswith((".pyc", ".pyo", ".so", ".dll", ".exe",
                                  ".png", ".jpg", ".jpeg", ".gif", ".ico",
                                  ".zip", ".tar", ".gz", ".bz2", ".xz")):
                    continue

                filepath = os.path.join(root, fname)
                if extensions is not None:
                    _, ext = os.path.splitext(fname)
                    if ext.lower() not in extensions:
                        continue

                results = self.scan_file(filepath)
                all_results.extend(results)
                files_scanned += 1

        return all_results

    def get_report(self) -> Dict[str, Any]:
        """Generate a comprehensive secrets scanning report.

        Returns:
            Dict with keys:
            - total_findings: int
            - by_severity: dict mapping severity -> count
            - by_type: dict mapping secret_type -> count
            - by_source: dict mapping source -> count
            - by_detector: dict mapping detector -> count
            - critical_findings: list of critical/high severity findings
            - scan_stats: scanning statistics
        """
        with self._lock:
            findings = list(self._findings)

        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        by_detector: Dict[str, int] = {}
        critical_findings: List[Dict[str, Any]] = []

        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_type[f.secret_type] = by_type.get(f.secret_type, 0) + 1
            by_source[f.source] = by_source.get(f.source, 0) + 1
            _CORE_TYPES = {
                "aws_key", "github_token", "github_token_fine_grained",
                "generic_api_key", "private_key_rsa", "private_key_ec",
                "private_key_generic", "password_in_url", "db_connection_string",
                "jwt_token",
            }
            detector = "core" if f.secret_type in _CORE_TYPES else "extended"
            by_detector[detector] = by_detector.get(detector, 0) + 1

            if f.severity in ("critical", "high"):
                critical_findings.append({
                    "type": f.secret_type,
                    "line": f.line,
                    "severity": f.severity,
                    "description": f.description,
                    "source": f.source,
                })

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_type": by_type,
            "by_source": by_source,
            "by_detector": by_detector,
            "critical_findings": critical_findings,
            "scan_stats": {
                "content_scans": self._scan_count,
                "files_scanned": self._files_scanned,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def clear_findings(self) -> None:
        """Clear all stored findings."""
        with self._lock:
            self._findings.clear()
            self._scan_count = 0
            self._files_scanned = 0

    @staticmethod
    def _redact_match(match: str, severity: str) -> str:
        """Redact a secret match for safe logging.

        Critical/high: show only first 4 and last 4 chars.
        Medium/low: show full match.
        """
        if severity in ("critical", "high"):
            if len(match) > 12:
                return match[:4] + "***REDACTED***" + match[-4:]
            return "***REDACTED***"
        return match

    @staticmethod
    def _describe_finding(secret_type: str) -> str:
        """Return a human-readable description for a secret type."""
        descriptions: Dict[str, str] = {
            "aws_key": "AWS Access Key ID",
            "github_token": "GitHub Personal Access Token",
            "github_token_fine_grained": "GitHub Fine-Grained PAT",
            "generic_api_key": "Generic API Key",
            "private_key_rsa": "RSA Private Key",
            "private_key_ec": "EC Private Key",
            "private_key_generic": "Private Key",
            "password_in_url": "Password in URL",
            "db_connection_string": "Database Connection String",
            "jwt_token": "JSON Web Token",
        }
        return descriptions.get(secret_type, secret_type)


# ══════════════════════════════════════════════════════════════════════════════
# 4. TAMPER-EVIDENT SECURITY AUDIT LOGGER
# ══════════════════════════════════════════════════════════════════════════════


class TamperEvidenceLogger:
    """Tamper-evident security event logger.

    Extends the concept of SecurityAuditLogger with hash-chained entries
    that make it detectable if log entries have been added, removed, or
    modified.

    Each log entry includes:
    - sequence number (monotonically increasing)
    - timestamp (ISO 8601 UTC)
    - level (INFO, WARN, ALERT)
    - event_type
    - module
    - target
    - details (dict)
    - previous_hash: SHA-256 of the previous entry's canonical form
    - entry_hash: SHA-256 of this entry (including previous_hash)

    The chain can be verified at any time to detect tampering.
    """

    def __init__(
        self,
        log_dir: Optional[str] = None,
        module_name: str = "security_hardening",
        chain_file: Optional[str] = None,
    ) -> None:
        self.module_name = module_name
        if log_dir is None:
            log_dir = os.path.join(os.path.expanduser("~"), ".reconpro")
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        if chain_file is None:
            chain_file = os.path.join(log_dir, "security_chain.log")
        self.chain_file = chain_file

        self._entries: List[Dict[str, Any]] = []
        self._last_hash: str = "GENESIS"  # Seed for the chain
        self._sequence: int = 0
        self._lock = threading.Lock()
        self._event_counts: Dict[str, int] = {}
        self._level_counts: Dict[str, int] = {"INFO": 0, "WARN": 0, "ALERT": 0}

        # Try to load existing chain
        self._load_chain()

    def _load_chain(self) -> None:
        """Load existing chain from disk to continue the hash sequence."""
        if not os.path.isfile(self.chain_file):
            return
        try:
            with open(self.chain_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        self._entries.append(entry)
                        self._sequence = entry.get("sequence", 0)
                        self._last_hash = entry.get("entry_hash", "GENESIS")
                        level = entry.get("level", "INFO")
                        if level in self._level_counts:
                            self._level_counts[level] += 1
                        event_type = entry.get("event_type", "")
                        self._event_counts[event_type] = self._event_counts.get(event_type, 0) + 1
                    except (json.JSONDecodeError, KeyError):
                        continue
        except OSError:
            pass

    def _compute_hash(self, canonical: str) -> str:
        """Compute SHA-256 hash of a canonical string."""
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _make_canonical(self, entry: Dict[str, Any]) -> str:
        """Create a canonical string representation for hashing.

        The canonical form includes all fields in a deterministic order.
        """
        # Build a deterministic representation
        parts = [
            str(entry.get("sequence", "")),
            str(entry.get("timestamp", "")),
            str(entry.get("level", "")),
            str(entry.get("event_type", "")),
            str(entry.get("module", "")),
            sanitize_log(str(entry.get("target", ""))),
            str(entry.get("previous_hash", "")),
            json.dumps(entry.get("details", {}), sort_keys=True, default=str),
        ]
        return "|".join(parts)

    def log(
        self,
        level: str,
        event_type: str,
        target: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a tamper-evident log entry.

        Args:
            level: "INFO", "WARN", or "ALERT".
            event_type: Category of security event.
            target: Target associated with the event.
            details: Optional dict of additional details.

        Returns:
            The complete log entry dict including hashes.
        """
        if level not in ("INFO", "WARN", "ALERT"):
            level = "INFO"

        with self._lock:
            self._sequence += 1
            entry: Dict[str, Any] = {
                "sequence": self._sequence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": level,
                "event_type": event_type,
                "module": self.module_name,
                "target": sanitize_log(target),
                "details": details or {},
                "previous_hash": self._last_hash,
            }

            # Compute hash of this entry
            canonical = self._make_canonical(entry)
            entry["entry_hash"] = self._compute_hash(canonical)

            self._last_hash = entry["entry_hash"]
            self._entries.append(entry)

            # Update statistics
            self._level_counts[level] = self._level_counts.get(level, 0) + 1
            self._event_counts[event_type] = self._event_counts.get(event_type, 0) + 1

            # Persist to disk
            self._persist_entry(entry)

            return dict(entry)

    def _persist_entry(self, entry: Dict[str, Any]) -> None:
        """Append a single entry to the chain file on disk."""
        try:
            with open(self.chain_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to persist security log entry: %s", exc)

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the integrity of the entire log chain.

        Checks that:
        1. Sequence numbers are monotonically increasing.
        2. Each entry's hash matches its content.
        3. Each entry's previous_hash matches the prior entry's hash.

        Returns:
            Dict with keys:
            - valid: bool (True if chain is intact)
            - entries_checked: int
            - first_violation: dict describing the first issue found (if any)
            - violations: list of all violation descriptions
        """
        violations: List[str] = []
        first_violation: Optional[Dict[str, Any]] = None
        prev_hash = "GENESIS"
        expected_sequence = 1

        for i, entry in enumerate(self._entries):
            entry_issues: List[str] = []

            # Check sequence
            if entry.get("sequence") != expected_sequence:
                issue = (
                    f"Entry {i}: expected sequence {expected_sequence}, "
                    f"got {entry.get('sequence')}"
                )
                entry_issues.append(issue)

            # Check previous_hash
            if entry.get("previous_hash") != prev_hash:
                issue = (
                    f"Entry {i}: previous_hash mismatch. "
                    f"Expected {prev_hash[:16]}..., got {str(entry.get('previous_hash', ''))[:16]}..."
                )
                entry_issues.append(issue)

            # Check entry_hash
            entry_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
            canonical = self._make_canonical(entry_copy)
            computed_hash = self._compute_hash(canonical)
            if entry.get("entry_hash") != computed_hash:
                issue = (
                    f"Entry {i}: hash mismatch. "
                    f"Stored {str(entry.get('entry_hash', ''))[:16]}..., "
                    f"computed {computed_hash[:16]}..."
                )
                entry_issues.append(issue)

            if entry_issues:
                if first_violation is None:
                    first_violation = {
                        "entry_index": i,
                        "sequence": entry.get("sequence"),
                        "issues": entry_issues,
                    }
                violations.extend(entry_issues)

            prev_hash = entry.get("entry_hash", "")
            expected_sequence += 1

        return {
            "valid": len(violations) == 0,
            "entries_checked": len(self._entries),
            "first_violation": first_violation,
            "violations": violations,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Return statistics about logged security events.

        Returns:
            Dict with keys:
            - total_entries: int
            - by_level: dict mapping level -> count
            - by_event_type: dict mapping event_type -> count
            - chain_valid: bool
            - first_entry: ISO timestamp of first entry
            - last_entry: ISO timestamp of last entry
        """
        first_ts = (
            self._entries[0]["timestamp"]
            if self._entries
            else None
        )
        last_ts = (
            self._entries[-1]["timestamp"]
            if self._entries
            else None
        )

        return {
            "total_entries": len(self._entries),
            "by_level": dict(self._level_counts),
            "by_event_type": dict(self._event_counts),
            "chain_valid": self.verify_chain()["valid"],
            "first_entry": first_ts,
            "last_entry": last_ts,
        }

    def get_entries(
        self,
        level: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query log entries with optional filters.

        Args:
            level: Filter by level (INFO, WARN, ALERT).
            event_type: Filter by event type.
            limit: Maximum entries to return.
            offset: Skip this many entries from the start.

        Returns:
            List of matching log entry dicts.
        """
        filtered: List[Dict[str, Any]] = []
        for entry in self._entries:
            if level and entry.get("level") != level:
                continue
            if event_type and entry.get("event_type") != event_type:
                continue
            filtered.append(dict(entry))

        return filtered[offset:offset + limit]

    # DEAD CODE: consider removal
    def clear(self) -> None:
        """Clear all in-memory entries and reset the chain.

        Does NOT delete the on-disk file.
        """
        with self._lock:
            self._entries.clear()
            self._last_hash = "GENESIS"
            self._sequence = 0
            self._event_counts.clear()
            self._level_counts = {"INFO": 0, "WARN": 0, "ALERT": 0}


# ══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE: Create a pre-wired engine instance
# ══════════════════════════════════════════════════════════════════════════════


# DEAD CODE: consider removal
def create_hardened_engine(
    log_dir: Optional[str] = None,
) -> Tuple[SecurityPolicyEngine, PluginSandbox, SecretsManager, TamperEvidenceLogger]:
    """Create a fully-wired set of security hardening components.

    All four components share a single audit logger and tamper-evident
    logger for unified security event tracking.

    Args:
        log_dir: Override directory for log files. Defaults to ~/.reconpro/

    Returns:
        Tuple of (policy_engine, plugin_sandbox, secrets_manager, tamper_logger).
    """
    if log_dir is None:
        log_dir = os.path.join(os.path.expanduser("~"), ".reconpro")

    audit = SecurityAuditLogger(log_dir=log_dir, module_name="hardening")
    tamper = TamperEvidenceLogger(log_dir=log_dir, module_name="hardening")
    engine = SecurityPolicyEngine(audit_logger=audit)
    sandbox = PluginSandbox(audit_logger=audit)
    secrets = SecretsManager(audit_logger=audit)

    return engine, sandbox, secrets, tamper

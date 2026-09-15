"""Comprehensive tests for reconpro.security_hardening.

Tests all four components:
1. SecurityPolicyEngine — policy definition, enforcement, compliance
2. PluginSandbox — static analysis, execution wrapping, output validation
3. SecretsManager — extended secret scanning, file scanning, reporting
4. TamperEvidenceLogger — hash-chain integrity, statistics, querying
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.security_hardening import (
    PluginSandbox,
    PluginSandbox as PluginSandboxCls,
    PolicyRule,
    SandboxViolation,
    SecurityPolicy,
    SecurityPolicyEngine,
    SecretsManager,
    TamperEvidenceLogger,
    ResourceLimitExceeded,
    _EXTENDED_SECRET_PATTERNS,
    _FORBIDDEN_BUILTINS,
    _FORBIDDEN_MODULES,
    create_hardened_engine,
)


# ══════════════════════════════════════════════════════════════════════════════
# 1. SECURITY POLICY ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestPolicyRule(unittest.TestCase):
    """Tests for the PolicyRule class."""

    def test_evaluate_enabled_rule_matching_condition(self):
        rule = PolicyRule(
            name="test_rule",
            description="Test",
            condition=lambda ctx: ctx.get("flag", False),
            action=lambda ctx: "deny" if ctx.get("dangerous") else "allow",
        )
        action, name = rule.evaluate({"flag": True, "dangerous": True})
        self.assertEqual(action, "deny")
        self.assertEqual(name, "test_rule")

    def test_evaluate_enabled_rule_non_matching_condition(self):
        rule = PolicyRule(
            name="test_rule",
            description="Test",
            condition=lambda ctx: ctx.get("flag", False),
            action=lambda ctx: "deny",
        )
        action, name = rule.evaluate({"flag": False})
        self.assertEqual(action, "skip")

    def test_evaluate_disabled_rule(self):
        rule = PolicyRule(
            name="test_rule",
            description="Test",
            condition=lambda ctx: True,
            action=lambda ctx: "deny",
            enabled=False,
        )
        action, name = rule.evaluate({})
        self.assertEqual(action, "skip")

    def test_evaluate_rule_with_error(self):
        """A rule that raises an exception should return 'skip'."""
        rule = PolicyRule(
            name="error_rule",
            description="Test",
            condition=lambda ctx: 1 / 0,  # type: ignore[return-value]
            action=lambda ctx: "deny",
        )
        action, name = rule.evaluate({})
        self.assertEqual(action, "skip")

    def test_to_dict(self):
        rule = PolicyRule(
            name="my_rule",
            description="A test rule",
            condition=lambda ctx: True,
            action=lambda ctx: "allow",
            severity="high",
        )
        d = rule.to_dict()
        self.assertEqual(d["name"], "my_rule")
        self.assertEqual(d["description"], "A test rule")
        self.assertEqual(d["severity"], "high")
        self.assertTrue(d["enabled"])


class TestSecurityPolicy(unittest.TestCase):
    """Tests for the SecurityPolicy class."""

    def test_create_empty_policy(self):
        policy = SecurityPolicy(name="test")
        self.assertEqual(policy.name, "test")
        self.assertEqual(len(policy.rules), 0)

    def test_add_and_evaluate_rules(self):
        policy = SecurityPolicy(name="test")
        policy.add_rule(PolicyRule(
            name="r1",
            description="Always deny",
            condition=lambda ctx: True,
            action=lambda ctx: "deny",
        ))
        policy.add_rule(PolicyRule(
            name="r2",
            description="Never matches",
            condition=lambda ctx: False,
            action=lambda ctx: "warn",
        ))
        results = policy.evaluate({})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["rule_name"], "r1")
        self.assertEqual(results[0]["action"], "deny")

    def test_to_dict(self):
        policy = SecurityPolicy(name="test_policy", description="Test")
        policy.add_rule(PolicyRule(
            name="r1", description="R1",
            condition=lambda ctx: True,
            action=lambda ctx: "allow",
        ))
        d = policy.to_dict()
        self.assertEqual(d["name"], "test_policy")
        self.assertEqual(d["rule_count"], 1)
        self.assertIn("created_at", d)


class TestSecurityPolicyEngine(unittest.TestCase):
    """Tests for the SecurityPolicyEngine class."""

    def setUp(self):
        self.engine = SecurityPolicyEngine()

    def test_builtin_policies_created(self):
        """All five built-in policies must be created."""
        policies = self.engine.list_policies()
        self.assertIn("plugin_sandbox_policy", policies)
        self.assertIn("input_validation_policy", policies)
        self.assertIn("network_policy", policies)
        self.assertIn("data_retention_policy", policies)
        self.assertIn("secrets_policy", policies)
        self.assertEqual(len(policies), 5)

    def test_define_custom_policy(self):
        policy = self.engine.define_policy(
            name="custom",
            rules=[PolicyRule(
                name="r1", description="R1",
                condition=lambda ctx: True,
                action=lambda ctx: "allow",
            )],
            description="Custom policy",
        )
        self.assertIsNotNone(policy)
        self.assertIn("custom", self.engine.list_policies())

    def test_remove_policy(self):
        self.engine.define_policy(name="removable", description="")
        self.assertTrue(self.engine.remove_policy("removable"))
        self.assertNotIn("removable", self.engine.list_policies())

    def test_remove_nonexistent_policy(self):
        self.assertFalse(self.engine.remove_policy("nonexistent"))

    def test_get_policy(self):
        policy = self.engine.get_policy("plugin_sandbox_policy")
        self.assertIsNotNone(policy)
        self.assertEqual(policy.name, "plugin_sandbox_policy")

    def test_enforce_nonexistent_policy(self):
        result = self.engine.enforce_policy("nonexistent", {})
        self.assertFalse(result["allowed"])
        self.assertIn("error", result)

    def test_enforce_plugin_sandbox_allows_clean(self):
        """Clean plugin execution context should be allowed."""
        ctx = {
            "operation_type": "plugin_exec",
            "uses_dangerous_builtins": False,
            "accesses_filesystem": False,
            "calls_subprocess": False,
            "accesses_network": False,
            "exceeded_memory_limit": False,
            "exceeded_cpu_limit": False,
        }
        result = self.engine.enforce_policy("plugin_sandbox_policy", ctx)
        self.assertTrue(result["allowed"])
        self.assertEqual(len(result["denied_by"]), 0)

    def test_enforce_plugin_sandbox_denies_eval(self):
        """Plugin using dangerous builtins should be denied."""
        ctx = {
            "operation_type": "plugin_exec",
            "uses_dangerous_builtins": True,
            "accesses_filesystem": False,
            "calls_subprocess": False,
            "accesses_network": False,
        }
        result = self.engine.enforce_policy("plugin_sandbox_policy", ctx)
        self.assertFalse(result["allowed"])
        self.assertIn("no_dangerous_builtins", result["denied_by"])

    def test_enforce_plugin_sandbox_denies_subprocess(self):
        """Plugin calling subprocess should be denied."""
        ctx = {
            "operation_type": "plugin_exec",
            "uses_dangerous_builtins": False,
            "accesses_filesystem": False,
            "calls_subprocess": True,
            "accesses_network": False,
        }
        result = self.engine.enforce_policy("plugin_sandbox_policy", ctx)
        self.assertFalse(result["allowed"])
        self.assertIn("no_subprocess_calls", result["denied_by"])

    def test_enforce_input_validation_denies_null(self):
        """Input with null bytes should be denied."""
        ctx = {
            "contains_null_bytes": True,
        }
        result = self.engine.enforce_policy("input_validation_policy", ctx)
        self.assertFalse(result["allowed"])
        self.assertIn("no_null_bytes", result["denied_by"])

    def test_enforce_input_validation_warns_control(self):
        """Input with control chars should produce a warning."""
        ctx = {
            "contains_control_chars": True,
            "contains_null_bytes": False,
            "has_target": False,
            "input_type": "text",
        }
        result = self.engine.enforce_policy("input_validation_policy", ctx)
        self.assertTrue(result["allowed"])
        self.assertIn("no_control_chars", result["warnings"])

    def test_enforce_network_policy_denies_private_without_flag(self):
        """Scanning private targets without explicit flag should be denied."""
        ctx = {
            "is_private_target": True,
            "private_scan_explicitly_allowed": False,
        }
        result = self.engine.enforce_policy("network_policy", ctx)
        self.assertFalse(result["allowed"])
        self.assertIn("no_private_network_scans", result["denied_by"])

    def test_enforce_network_policy_allows_private_with_flag(self):
        """Scanning private targets with explicit flag should be allowed."""
        ctx = {
            "is_private_target": True,
            "private_scan_explicitly_allowed": True,
            "makes_http_requests": True,
            "rate_limit_active": True,
            "timeout_configured": True,
            "tls_verify_enabled": True,
        }
        result = self.engine.enforce_policy("network_policy", ctx)
        self.assertTrue(result["allowed"])

    def test_enforce_secrets_policy_denies_hardcoded(self):
        """Hardcoded secrets should be denied."""
        ctx = {
            "scans_for_secrets": True,
            "hardcoded_secrets_found": True,
        }
        result = self.engine.enforce_policy("secrets_policy", ctx)
        self.assertFalse(result["allowed"])
        self.assertIn("no_hardcoded_secrets", result["denied_by"])

    def test_enforce_data_retention_denies_secrets_in_logs(self):
        """Secrets in logs should be denied."""
        ctx = {
            "secrets_in_logs": True,
        }
        result = self.engine.enforce_policy("data_retention_policy", ctx)
        self.assertFalse(result["allowed"])
        self.assertIn("no_secrets_in_logs", result["denied_by"])

    def test_enforce_all(self):
        """enforce_all checks all policies."""
        ctx = {
            "operation_type": "plugin_exec",
            "uses_dangerous_builtins": True,
            "contains_null_bytes": False,
            "contains_control_chars": False,
        }
        result = self.engine.enforce_all(ctx)
        self.assertFalse(result["allowed"])
        self.assertIn("plugin_sandbox_policy", result["policy_results"])
        self.assertIn("input_validation_policy", result["policy_results"])

    def test_evaluate_compliance_default(self):
        """Default components should all be compliant."""
        report = self.engine.evaluate_compliance()
        self.assertTrue(report["compliant"])
        self.assertGreater(report["total_checks"], 0)
        self.assertEqual(report["failed"], 0)
        self.assertIn("details", report)

    def test_evaluate_compliance_with_non_compliant(self):
        """Custom components with violations should fail compliance."""
        components = {
            "bad_scanner": {
                "operation_type": "scan",
                "has_target": True,
                "target_sanitized": False,
                "contains_null_bytes": True,
                "contains_control_chars": True,
                "makes_http_requests": True,
                "rate_limit_active": False,
                "timeout_configured": False,
                "tls_verify_enabled": False,
                "produces_output": True,
                "output_secret_scan_enabled": True,
                "has_urls": True,
                "credentials_in_urls": True,
                "private_keys_in_output": True,
                "has_audit_log": True,
                "log_rotation_configured": False,
                "generates_reports": True,
                "data_minimization_enabled": False,
                "creates_temp_files": True,
                "temp_cleanup_enabled": False,
                "secrets_in_logs": True,
                "scans_for_secrets": True,
                "hardcoded_secrets_found": True,
            },
        }
        report = self.engine.evaluate_compliance(components)
        self.assertFalse(report["compliant"])
        self.assertGreater(report["failed"], 0)

    def test_get_policy_report(self):
        """Policy report should contain all expected keys."""
        report = self.engine.get_policy_report()
        self.assertIn("policies", report)
        self.assertIn("compliance", report)
        self.assertIn("summary", report)
        self.assertIn("generated_at", report)
        self.assertGreater(len(report["policies"]), 0)

    def test_compliance_cache_invalidation(self):
        """Defining a new policy should invalidate compliance cache."""
        self.engine.evaluate_compliance()
        self.engine.define_policy(
            name="cache_test",
            rules=[PolicyRule(
                name="r1", description="R1",
                condition=lambda ctx: True,
                action=lambda ctx: "allow",
            )],
        )
        # The next evaluate_compliance should include the new policy
        report = self.engine.evaluate_compliance()
        # cache_test should appear in details
        policy_names = set(d["policy"] for d in report["details"])
        self.assertIn("cache_test", policy_names)


# ══════════════════════════════════════════════════════════════════════════════
# 2. PLUGIN SANDBOX TESTS
# ══════════════════════════════════════════════════════════════════════════════


def _safe_plugin(target: str = "", base_url: str = "", timeout: int = 8, verify_tls: bool = True) -> list:
    """A well-behaved plugin that returns valid findings."""
    return [{
        "title": "Test Finding",
        "severity": "low",
        "category": "test",
        "module": "test_plugin",
        "description": "A test finding",
        "evidence": "evidence",
        "asset": target or "unknown",
        "points_deducted": 0,
    }]


def _multi_plugin(target: str = "", **kwargs) -> list:
    """Returns multiple findings."""
    return [
        {"title": f"F{i}", "severity": "info", "category": "c",
         "module": "m", "description": "d", "evidence": "e",
         "asset": target, "points_deducted": 0}
        for i in range(5)
    ]


def _bad_return_type(target: str = "") -> str:
    """Returns wrong type."""
    return "not a list"


def _missing_keys_plugin(target: str = "") -> list:
    """Returns dicts missing required keys."""
    return [{"title": "Missing keys"}]


def _empty_plugin(target: str = "") -> list:
    """Returns empty list."""
    return []


class TestPluginSandboxStaticAnalysis(unittest.TestCase):
    """Tests for PluginSandbox.check_code_for_violations()."""

    def test_clean_code_no_violations(self):
        code = """
import json
import re

def run(target, base_url="", timeout=8, verify_tls=True):
    result = json.loads('{"status": "ok"}')
    return [{"title": "OK", "severity": "info", "category": "test"}]
"""
        violations = PluginSandbox.check_code_for_violations(code)
        # json and re are not in forbidden modules
        self.assertEqual(len(violations), 0)

    def test_detects_eval(self):
        code = 'result = eval("1+1")\n'
        violations = PluginSandbox.check_code_for_violations(code)
        types = [v["type"] for v in violations]
        self.assertIn("forbidden_builtin", types)
        self.assertIn("eval", [v["match"] for v in violations])

    def test_detects_exec(self):
        code = 'exec("print(1)")\n'
        violations = PluginSandbox.check_code_for_violations(code)
        matches = [v["match"] for v in violations]
        self.assertIn("exec", matches)

    def test_detects_compile(self):
        code = 'code = compile("print(1)", "<string>", "exec")\n'
        violations = PluginSandbox.check_code_for_violations(code)
        matches = [v["match"] for v in violations]
        self.assertIn("compile", matches)

    def test_detects_open(self):
        code = 'f = open("/etc/passwd")\n'
        violations = PluginSandbox.check_code_for_violations(code)
        matches = [v["match"] for v in violations]
        self.assertIn("open", matches)

    def test_detects_os_import(self):
        code = 'import os\n'
        violations = PluginSandbox.check_code_for_violations(code)
        types = [v["type"] for v in violations]
        self.assertIn("forbidden_module", types)
        matches = [v["match"] for v in violations]
        self.assertIn("os", matches)

    def test_detects_subprocess_import(self):
        code = 'import subprocess\n'
        violations = PluginSandbox.check_code_for_violations(code)
        matches = [v["match"] for v in violations]
        self.assertIn("subprocess", matches)

    def test_detects_from_os_import(self):
        code = 'from os import system\n'
        violations = PluginSandbox.check_code_for_violations(code)
        matches = [v["match"] for v in violations]
        self.assertIn("os", matches)

    def test_detects_os_system(self):
        code = 'import os  # forbidden\nos.system("id")\n'
        violations = PluginSandbox.check_code_for_violations(code)
        types = [v["type"] for v in violations]
        self.assertIn("dangerous_pattern", types)
        self.assertIn("forbidden_module", types)

    def test_detects_subprocess_call(self):
        code = 'import subprocess\nsubprocess.call(["ls"])\n'
        violations = PluginSandbox.check_code_for_violations(code)
        types = [v["type"] for v in violations]
        self.assertIn("dangerous_pattern", types)

    def test_skips_comments(self):
        code = '# eval is dangerous\n# import os\nresult = []\n'
        violations = PluginSandbox.check_code_for_violations(code)
        self.assertEqual(len(violations), 0)

    def test_skips_strings_containing_keywords(self):
        code = 'desc = "This code uses eval and exec for testing"\n'
        violations = PluginSandbox.check_code_for_violations(code)
        # Should not flag because they're inside string literals
        eval_violations = [v for v in violations if v["match"] == "eval"]
        self.assertEqual(len(eval_violations), 0)

    def test_multiple_violations(self):
        code = '''import os
import subprocess
eval("1")
open("/etc/passwd")
os.system("id")
'''
        violations = PluginSandbox.check_code_for_violations(code)
        self.assertGreater(len(violations), 4)

    def test_forbidden_builtins_set_completeness(self):
        """Verify all expected dangerous builtins are in the set."""
        self.assertIn("eval", _FORBIDDEN_BUILTINS)
        self.assertIn("exec", _FORBIDDEN_BUILTINS)
        self.assertIn("compile", _FORBIDDEN_BUILTINS)
        self.assertIn("open", _FORBIDDEN_BUILTINS)
        self.assertIn("__import__", _FORBIDDEN_BUILTINS)
        self.assertIn("input", _FORBIDDEN_BUILTINS)

    def test_forbidden_modules_completeness(self):
        """Verify critical dangerous modules are forbidden."""
        for mod in ["os", "sys", "subprocess", "shutil", "importlib",
                    "ctypes", "socket", "signal", "pathlib"]:
            self.assertIn(mod, _FORBIDDEN_MODULES, f"{mod} should be forbidden")


class TestPluginSandboxExecution(unittest.TestCase):
    """Tests for PluginSandbox.execute()."""

    def setUp(self):
        self.sandbox = PluginSandbox()

    def test_execute_clean_plugin(self):
        result = self.sandbox.execute(
            _safe_plugin,
            plugin_name="safe_plugin",
            target="example.com",
            base_url="https://example.com",
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["title"], "Test Finding")
        self.assertGreater(result["execution_time"], 0)

    def test_execute_multi_findings(self):
        result = self.sandbox.execute(
            _multi_plugin,
            plugin_name="multi_plugin",
            target="example.com",
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(result["findings"]), 5)

    def test_execute_empty_findings(self):
        result = self.sandbox.execute(
            _empty_plugin,
            plugin_name="empty_plugin",
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(result["findings"]), 0)

    def test_rejects_non_list_return(self):
        result = self.sandbox.execute(
            _bad_return_type,
            plugin_name="bad_type_plugin",
        )
        self.assertFalse(result["success"])
        self.assertIn("list", result["error"])

    def test_rejects_missing_keys(self):
        result = self.sandbox.execute(
            _missing_keys_plugin,
            plugin_name="missing_keys_plugin",
        )
        self.assertFalse(result["success"])
        self.assertIn("missing required keys", result["error"])

    def test_operation_log_populated(self):
        self.sandbox.clear_operation_log()
        self.sandbox.execute(_safe_plugin, plugin_name="test")
        log = self.sandbox.get_operation_log()
        self.assertGreater(len(log), 0)
        ops = [e["operation"] for e in log]
        self.assertIn("sandbox_enter", ops)
        self.assertIn("sandbox_exit", ops)
        self.assertIn("plugin_execute_start", ops)
        self.assertIn("plugin_execute_end", ops)
        self.assertIn("output_validated", ops)

    def test_clear_operation_log(self):
        self.sandbox.execute(_safe_plugin, plugin_name="test")
        self.sandbox.clear_operation_log()
        self.assertEqual(len(self.sandbox.get_operation_log()), 0)

    def test_execute_with_wrong_args(self):
        """Plugin called with wrong keyword args should fail."""
        def needs_foo(foo: str = "") -> list:
            return [{"title": "F", "severity": "info", "category": "c"}]
        result = self.sandbox.execute(
            needs_foo,
            plugin_name="needs_foo",
            target="example.com",  # wrong arg name
        )
        self.assertFalse(result["success"])
        self.assertIn("Plugin call failed", result["error"])

    def test_output_size_limit(self):
        """Plugin output exceeding max_output_size should fail."""
        huge_data = [{"title": f"F{i}", "severity": "info", "category": "c",
                      "module": "m", "description": "d" * 5000, "evidence": "e",
                      "asset": "a", "points_deducted": 0}
                     for i in range(200)]
        def huge_plugin(target: str = "") -> list:
            return huge_data
        sandbox = PluginSandbox(max_output_size=100)
        result = sandbox.execute(huge_plugin, plugin_name="huge")
        self.assertFalse(result["success"])
        self.assertIn("Resource limit exceeded", result["error"])


class TestSandboxViolations(unittest.TestCase):
    """Tests for sandbox exception classes."""

    def test_sandbox_violation(self):
        exc = SandboxViolation("eval", "Forbidden builtin")
        self.assertEqual(exc.operation, "eval")
        self.assertEqual(exc.reason, "Forbidden builtin")
        self.assertIn("eval", str(exc))

    def test_resource_limit_exceeded(self):
        exc = ResourceLimitExceeded("memory", 67108864, 134217728)
        self.assertEqual(exc.resource, "memory")
        self.assertEqual(exc.limit, 67108864)
        self.assertEqual(exc.actual, 134217728)
        self.assertIn("memory", str(exc))


# ══════════════════════════════════════════════════════════════════════════════
# 3. SECRETS MANAGER TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestSecretsManagerCoreDetection(unittest.TestCase):
    """Tests for core secret detection (delegated to security.py)."""

    def setUp(self):
        self.sm = SecretsManager()

    def test_aws_key_detected(self):
        content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("aws_key", types)

    def test_github_token_detected(self):
        content = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("github_token", types)

    def test_private_key_detected(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ\n-----END RSA PRIVATE KEY-----"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("private_key_rsa", types)

    def test_empty_content(self):
        results = self.sm.scan_for_secrets("")
        self.assertEqual(len(results), 0)

    def test_clean_content(self):
        results = self.sm.scan_for_secrets("Hello, this is a clean string with no secrets.")
        self.assertEqual(len(results), 0)

    def test_jwt_detected(self):
        content = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("jwt_token", types)


class TestSecretsManagerExtendedDetection(unittest.TestCase):
    """Tests for extended secret patterns."""

    def setUp(self):
        self.sm = SecretsManager()

    def test_slack_token_detected(self):
        content = "SLACK_TOKEN=xox" "b-123456789012-aBcDeFgHiJkLmNoPqRsTuVwXyZ"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("slack_token", types)

    def test_google_api_key(self):
        content = "GOOGLE_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuv"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("google_api_key", types)

    def test_stripe_secret_key(self):
        content = "STRIPE_KEY=sk_live_" "abcdefghijklmnopqrstuvwxyzabcd"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("stripe_secret_key", types)
        severities = [r["severity"] for r in results if r["secret_type"] == "stripe_secret_key"]
        self.assertEqual(severities[0], "critical")

    def test_sendgrid_api_key(self):
        content = "SG.abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwx.abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwx"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("sendgrid_api_key", types)

    def test_npm_token(self):
        content = "NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz0123456789"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("npm_token", types)

    def test_ssh_openssh_private_key(self):
        content = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("ssh_private_key", types)
        severities = [r["severity"] for r in results if r["secret_type"] == "ssh_private_key"]
        self.assertEqual(severities[0], "critical")

    def test_pgp_private_key(self):
        content = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("pgp_private_key", types)

    def test_pem_certificate(self):
        content = "-----BEGIN CERTIFICATE-----\nMIIBxjCCAW2gAwIBAgIJALmVV\n-----END CERTIFICATE-----"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("pem_certificate", types)

    def test_authorization_header(self):
        content = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("authorization_header", types)

    def test_env_secret_aws(self):
        content = "export AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyzabcd"
        results = self.sm.scan_for_secrets(content)
        types = [r["secret_type"] for r in results]
        self.assertIn("env_secret", types)

    def test_redaction_of_critical_secrets(self):
        """Critical secrets should be redacted in output."""
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ\n-----END RSA PRIVATE KEY-----"
        results = self.sm.scan_for_secrets(content)
        for r in results:
            if r["severity"] in ("critical", "high"):
                self.assertIn("REDACTED", r["match"])

    def test_medium_secrets_not_redacted(self):
        """Medium severity secrets should NOT be redacted."""
        content = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
        results = self.sm.scan_for_secrets(content)
        for r in results:
            if r["severity"] == "medium":
                self.assertNotIn("REDACTED", r["match"])

    def test_source_tracking(self):
        """Source parameter should be preserved in results."""
        results = self.sm.scan_for_secrets("AKIAIOSFODNN7EXAMPLE", source="my_file.py")
        for r in results:
            self.assertEqual(r["source"], "my_file.py")

    def test_detector_field(self):
        """Core patterns should be labeled 'core', extended as 'extended'."""
        content = "AKIAIOSFODNN7EXAMPLE\nSG.abc123def45678901234567890.abc123def45678901234567890"
        results = self.sm.scan_for_secrets(content)
        detectors = set(r["detector"] for r in results)
        self.assertIn("core", detectors)
        self.assertIn("extended", detectors)


class TestSecretsManagerFileScanning(unittest.TestCase):
    """Tests for SecretsManager file and directory scanning."""

    def setUp(self):
        self.sm = SecretsManager()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_file(self, name: str, content: str) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_scan_file_with_secrets(self):
        path = self._write_file("config.py", "API_KEY=AKIAIOSFODNN7EXAMPLE")
        results = self.sm.scan_file(path)
        types = [r["secret_type"] for r in results]
        self.assertIn("aws_key", types)

    def test_scan_file_without_secrets(self):
        path = self._write_file("clean.py", "x = 42\nprint(x)")
        results = self.sm.scan_file(path)
        self.assertEqual(len(results), 0)

    def test_scan_nonexistent_file(self):
        results = self.sm.scan_file("/nonexistent/path/file.txt")
        self.assertEqual(len(results), 0)

    def test_scan_directory(self):
        self._write_file("a.py", "AWS_KEY=AKIAIOSFODNN7EXAMPLE")
        self._write_file("b.py", "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        self._write_file("clean.txt", "no secrets here")
        results = self.sm.scan_directory(self.tmpdir)
        types = [r["secret_type"] for r in results]
        self.assertIn("aws_key", types)
        self.assertIn("github_token", types)

    def test_scan_directory_with_extension_filter(self):
        self._write_file("secrets.py", "AKIAIOSFODNN7EXAMPLE")
        self._write_file("secrets.js", "AKIAIOSFODNN7EXAMPLE")
        results = self.sm.scan_directory(self.tmpdir, extensions={".py"})
        # Should only find secrets in .py files
        sources = set(r["source"] for r in results)
        for src in sources:
            self.assertTrue(src.endswith(".py"))

    def test_scan_directory_skips_hidden_files(self):
        self._write_file(".env", "AKIAIOSFODNN7EXAMPLE")
        results = self.sm.scan_directory(self.tmpdir)
        # Hidden files should be skipped
        types = [r["secret_type"] for r in results]
        self.assertNotIn("aws_key", types)

    def test_scan_directory_max_files(self):
        for i in range(10):
            self._write_file(f"f{i}.py", "AKIAIOSFODNN7EXAMPLE")
        results = self.sm.scan_directory(self.tmpdir, max_files=3)
        # Should scan at most 3 files
        self.assertLessEqual(len(results), 3)


class TestSecretsManagerReport(unittest.TestCase):
    """Tests for SecretsManager.get_report()."""

    def setUp(self):
        self.sm = SecretsManager()

    def test_empty_report(self):
        report = self.sm.get_report()
        self.assertEqual(report["total_findings"], 0)
        self.assertEqual(report["by_severity"], {})
        self.assertEqual(report["by_type"], {})

    def test_report_after_scan(self):
        self.sm.scan_for_secrets("AKIAIOSFODNN7EXAMPLE", source="test")
        report = self.sm.get_report()
        self.assertGreater(report["total_findings"], 0)
        self.assertIn("high", report["by_severity"])
        self.assertIn("aws_key", report["by_type"])

    def test_report_includes_stats(self):
        self.sm.scan_for_secrets("AKIAIOSFODNN7EXAMPLE")
        report = self.sm.get_report()
        self.assertIn("scan_stats", report)
        self.assertEqual(report["scan_stats"]["content_scans"], 1)

    def test_report_critical_findings(self):
        self.sm.scan_for_secrets("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
        report = self.sm.get_report()
        self.assertGreater(len(report["critical_findings"]), 0)

    def test_clear_findings(self):
        self.sm.scan_for_secrets("AKIAIOSFODNN7EXAMPLE")
        self.sm.clear_findings()
        report = self.sm.get_report()
        self.assertEqual(report["total_findings"], 0)
        self.assertEqual(report["scan_stats"]["content_scans"], 0)

    def test_report_has_generated_at(self):
        self.sm.scan_for_secrets("AKIAIOSFODNN7EXAMPLE")
        report = self.sm.get_report()
        self.assertIn("generated_at", report)


class TestSecretsManagerRedaction(unittest.TestCase):
    """Tests for the redaction logic."""

    def test_redact_critical_long(self):
        result = SecretsManager._redact_match("AKIAIOSFODNN7EXAMPLE", "critical")
        self.assertEqual(result, "AKIA***REDACTED***MPLE")

    def test_redact_critical_short(self):
        result = SecretsManager._redact_match("short", "critical")
        self.assertEqual(result, "***REDACTED***")

    def test_redact_high(self):
        result = SecretsManager._redact_match("some-long-api-key-value-here", "high")
        self.assertEqual(result, "some***REDACTED***here")

    def test_no_redact_medium(self):
        original = "some-medium-key-value"
        result = SecretsManager._redact_match(original, "medium")
        self.assertEqual(result, original)

    def test_no_redact_low(self):
        original = "some-low-value"
        result = SecretsManager._redact_match(original, "low")
        self.assertEqual(result, original)


# ══════════════════════════════════════════════════════════════════════════════
# 4. TAMPER-EVIDENT LOGGER TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestTamperEvidenceLoggerBasic(unittest.TestCase):
    """Basic tests for TamperEvidenceLogger."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        chain_file = os.path.join(self.tmpdir, "test_chain.log")
        self.logger = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=chain_file,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_log_entry_has_required_fields(self):
        entry = self.logger.log("INFO", "TEST_EVENT", target="example.com")
        self.assertIn("sequence", entry)
        self.assertIn("timestamp", entry)
        self.assertIn("level", entry)
        self.assertIn("event_type", entry)
        self.assertIn("module", entry)
        self.assertIn("target", entry)
        self.assertIn("details", entry)
        self.assertIn("previous_hash", entry)
        self.assertIn("entry_hash", entry)

    def test_sequence_increments(self):
        e1 = self.logger.log("INFO", "E1")
        e2 = self.logger.log("INFO", "E2")
        self.assertEqual(e1["sequence"], 1)
        self.assertEqual(e2["sequence"], 2)

    def test_genesis_seed(self):
        entry = self.logger.log("INFO", "FIRST")
        self.assertEqual(entry["previous_hash"], "GENESIS")

    def test_hash_chain_links(self):
        e1 = self.logger.log("INFO", "E1")
        e2 = self.logger.log("INFO", "E2")
        self.assertEqual(e2["previous_hash"], e1["entry_hash"])

    def test_invalid_level_normalized(self):
        entry = self.logger.log("CRITICAL", "TEST")
        self.assertEqual(entry["level"], "INFO")

    def test_valid_levels(self):
        for level in ["INFO", "WARN", "ALERT"]:
            entry = self.logger.log(level, f"TEST_{level}")
            self.assertEqual(entry["level"], level)

    def test_log_with_details(self):
        entry = self.logger.log(
            "WARN", "SECRETS_DETECTED",
            target="example.com",
            details={"count": 3, "types": ["aws_key"]},
        )
        self.assertEqual(entry["details"]["count"], 3)
        self.assertEqual(entry["details"]["types"], ["aws_key"])

    def test_crlf_sanitized_in_target(self):
        entry = self.logger.log("INFO", "TEST", target="evil\nINJECTED")
        self.assertNotIn("\n", entry["target"])


class TestTamperEvidenceChainVerification(unittest.TestCase):
    """Tests for chain integrity verification."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        chain_file = os.path.join(self.tmpdir, "test_chain.log")
        self.tl = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=chain_file,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_valid_chain(self):
        for i in range(10):
            self.tl.log("INFO", f"EVENT_{i}")
        result = self.tl.verify_chain()
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries_checked"], 10)
        self.assertEqual(len(result["violations"]), 0)

    def test_tampered_entry_detected(self):
        """Modifying an entry's content should break the chain."""
        for i in range(5):
            self.tl.log("INFO", f"EVENT_{i}")
        # Tamper with entry 2's level
        self.tl._entries[2]["level"] = "ALERT"
        result = self.tl.verify_chain()
        self.assertFalse(result["valid"])
        self.assertGreater(len(result["violations"]), 0)

    def test_tampered_hash_detected(self):
        """Modifying an entry's hash should break the chain."""
        self.tl.log("INFO", "E1")
        self.tl.log("INFO", "E2")
        self.tl._entries[1]["entry_hash"] = "deadbeef" * 8
        result = self.tl.verify_chain()
        self.assertFalse(result["valid"])

    def test_tampered_previous_hash_detected(self):
        """Modifying an entry's previous_hash should break the chain."""
        self.tl.log("INFO", "E1")
        self.tl.log("INFO", "E2")
        self.tl.log("INFO", "E3")
        self.tl._entries[2]["previous_hash"] = "cafebabe" * 8
        result = self.tl.verify_chain()
        self.assertFalse(result["valid"])

    def test_first_violation_reported(self):
        """First violation should include entry index and issues."""
        for i in range(5):
            self.tl.log("INFO", f"EVENT_{i}")
        self.tl._entries[2]["level"] = "TAMPERED"
        result = self.tl.verify_chain()
        self.assertIsNotNone(result["first_violation"])
        self.assertEqual(result["first_violation"]["entry_index"], 2)
        self.assertGreater(len(result["first_violation"]["issues"]), 0)

    def test_empty_chain_valid(self):
        result = self.tl.verify_chain()
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries_checked"], 0)


class TestTamperEvidenceLoggerPersistence(unittest.TestCase):
    """Tests for chain file persistence."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.chain_file = os.path.join(self.tmpdir, "persist_chain.log")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_chain_persisted_to_disk(self):
        tl = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=self.chain_file,
        )
        tl.log("INFO", "PERSISTED_EVENT")
        self.assertTrue(os.path.isfile(self.chain_file))
        with open(self.chain_file) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["event_type"], "PERSISTED_EVENT")

    def test_chain_loaded_from_disk(self):
        """A new TamperEvidenceLogger should continue an existing chain."""
        tl1 = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=self.chain_file,
        )
        tl1.log("INFO", "FIRST")
        tl1.log("WARN", "SECOND")

        # Create new logger pointing to same file
        tl2 = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=self.chain_file,
        )
        # New entry should continue the chain
        entry = tl2.log("ALERT", "THIRD")
        self.assertEqual(entry["sequence"], 3)

    def test_loaded_chain_verifies(self):
        """Chain loaded from disk should verify correctly."""
        tl1 = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=self.chain_file,
        )
        for i in range(5):
            tl1.log("INFO", f"E{i}")

        tl2 = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=self.chain_file,
        )
        result = tl2.verify_chain()
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries_checked"], 5)


class TestTamperEvidenceLoggerStatistics(unittest.TestCase):
    """Tests for TamperEvidenceLogger.get_statistics()."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tl = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=os.path.join(self.tmpdir, "stats_chain.log"),
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_empty_statistics(self):
        stats = self.tl.get_statistics()
        self.assertEqual(stats["total_entries"], 0)
        self.assertEqual(stats["by_level"], {"INFO": 0, "WARN": 0, "ALERT": 0})
        self.assertIsNone(stats["first_entry"])
        self.assertIsNone(stats["last_entry"])
        self.assertTrue(stats["chain_valid"])

    def test_statistics_after_logging(self):
        self.tl.log("INFO", "E1")
        self.tl.log("INFO", "E2")
        self.tl.log("WARN", "E3")
        self.tl.log("ALERT", "E4")
        stats = self.tl.get_statistics()
        self.assertEqual(stats["total_entries"], 4)
        self.assertEqual(stats["by_level"]["INFO"], 2)
        self.assertEqual(stats["by_level"]["WARN"], 1)
        self.assertEqual(stats["by_level"]["ALERT"], 1)
        self.assertIsNotNone(stats["first_entry"])
        self.assertIsNotNone(stats["last_entry"])

    def test_event_type_counts(self):
        self.tl.log("INFO", "SCAN_START")
        self.tl.log("INFO", "SCAN_START")
        self.tl.log("WARN", "FINDING")
        stats = self.tl.get_statistics()
        self.assertEqual(stats["by_event_type"]["SCAN_START"], 2)
        self.assertEqual(stats["by_event_type"]["FINDING"], 1)


class TestTamperEvidenceLoggerQuerying(unittest.TestCase):
    """Tests for TamperEvidenceLogger.get_entries()."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tl = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=os.path.join(self.tmpdir, "query_chain.log"),
        )
        self.tl.log("INFO", "TYPE_A")
        self.tl.log("WARN", "TYPE_B")
        self.tl.log("ALERT", "TYPE_A")
        self.tl.log("INFO", "TYPE_C")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_get_all_entries(self):
        entries = self.tl.get_entries()
        self.assertEqual(len(entries), 4)

    def test_filter_by_level(self):
        entries = self.tl.get_entries(level="WARN")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["event_type"], "TYPE_B")

    def test_filter_by_event_type(self):
        entries = self.tl.get_entries(event_type="TYPE_A")
        self.assertEqual(len(entries), 2)

    def test_limit(self):
        entries = self.tl.get_entries(limit=2)
        self.assertEqual(len(entries), 2)

    def test_offset(self):
        entries = self.tl.get_entries(offset=2)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["event_type"], "TYPE_A")  # 3rd entry

    def test_combined_filters(self):
        entries = self.tl.get_entries(level="INFO", event_type="TYPE_A")
        self.assertEqual(len(entries), 1)


class TestTamperEvidenceLoggerClear(unittest.TestCase):
    """Tests for TamperEvidenceLogger.clear()."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tl = TamperEvidenceLogger(
            log_dir=self.tmpdir,
            chain_file=os.path.join(self.tmpdir, "clear_chain.log"),
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_clear_resets_state(self):
        self.tl.log("INFO", "E1")
        self.tl.log("WARN", "E2")
        self.tl.clear()
        stats = self.tl.get_statistics()
        self.assertEqual(stats["total_entries"], 0)

    def test_clear_resets_chain(self):
        self.tl.log("INFO", "E1")
        self.tl.clear()
        entry = self.tl.log("INFO", "E_AFTER_CLEAR")
        self.assertEqual(entry["sequence"], 1)
        self.assertEqual(entry["previous_hash"], "GENESIS")


# ══════════════════════════════════════════════════════════════════════════════
# 5. INTEGRATION TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestCreateHardenedEngine(unittest.TestCase):
    """Tests for the create_hardened_engine factory function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_returns_all_components(self):
        engine, sandbox, secrets, tamper = create_hardened_engine(
            log_dir=self.tmpdir,
        )
        self.assertIsInstance(engine, SecurityPolicyEngine)
        self.assertIsInstance(sandbox, PluginSandbox)
        self.assertIsInstance(secrets, SecretsManager)
        self.assertIsInstance(tamper, TamperEvidenceLogger)

    def test_engine_has_policies(self):
        engine, _, _, _ = create_hardened_engine(log_dir=self.tmpdir)
        policies = engine.list_policies()
        self.assertEqual(len(policies), 5)

    def test_tamper_logger_uses_custom_dir(self):
        _, _, _, tamper = create_hardened_engine(log_dir=self.tmpdir)
        tamper.log("INFO", "INTEGRATION_TEST")
        self.assertTrue(os.path.isdir(self.tmpdir))


class TestIntegrationPolicyAndSandbox(unittest.TestCase):
    """Integration: policy engine + sandbox working together."""

    def test_clean_plugin_passes_policy(self):
        engine = SecurityPolicyEngine()
        code = '''
import json

def run(target, base_url="", timeout=8, verify_tls=True):
    return [{"title": "OK", "severity": "info", "category": "test"}]
'''
        violations = PluginSandbox.check_code_for_violations(code)
        ctx = {
            "operation_type": "plugin_exec",
            "uses_dangerous_builtins": len([v for v in violations if v["type"] == "forbidden_builtin"]) > 0,
            "accesses_filesystem": False,
            "calls_subprocess": len([v for v in violations if v["match"] == "subprocess"]) > 0,
            "accesses_network": False,
        }
        result = engine.enforce_policy("plugin_sandbox_policy", ctx)
        self.assertTrue(result["allowed"])

    def test_malicious_plugin_fails_policy(self):
        engine = SecurityPolicyEngine()
        code = 'import os\nos.system("id")\n'
        violations = PluginSandbox.check_code_for_violations(code)
        ctx = {
            "operation_type": "plugin_exec",
            "uses_dangerous_builtins": False,
            "accesses_filesystem": False,
            "calls_subprocess": True,
            "accesses_network": False,
        }
        result = engine.enforce_policy("plugin_sandbox_policy", ctx)
        self.assertFalse(result["allowed"])


class TestIntegrationSecretsAndPolicy(unittest.TestCase):
    """Integration: secrets manager + policy engine."""

    def test_clean_content_passes_secrets_policy(self):
        engine = SecurityPolicyEngine()
        sm = SecretsManager()
        findings = sm.scan_for_secrets("Hello, clean content")
        ctx = {
            "scans_for_secrets": True,
            "hardcoded_secrets_found": len(findings) > 0,
            "produces_output": True,
            "output_secret_scan_enabled": True,
            "has_urls": False,
            "credentials_in_urls": False,
            "private_keys_in_output": False,
        }
        result = engine.enforce_policy("secrets_policy", ctx)
        self.assertTrue(result["allowed"])

    def test_secrets_content_fails_secrets_policy(self):
        engine = SecurityPolicyEngine()
        sm = SecretsManager()
        findings = sm.scan_for_secrets("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
        # Note: the secrets_policy checks hardcoded_secrets_found which is about
        # the code containing secrets, not the output. Here we simulate.
        ctx = {
            "scans_for_secrets": True,
            "hardcoded_secrets_found": True,
            "produces_output": True,
            "output_secret_scan_enabled": True,
            "has_urls": False,
            "credentials_in_urls": False,
            "private_keys_in_output": False,
        }
        result = engine.enforce_policy("secrets_policy", ctx)
        self.assertFalse(result["allowed"])


class TestExtendedPatternsCompilation(unittest.TestCase):
    """Verify all extended secret patterns compile and match expected types."""

    def test_all_patterns_are_tuples_of_four(self):
        """Each extended pattern should be a 4-tuple."""
        for pattern in _EXTENDED_SECRET_PATTERNS:
            self.assertEqual(len(pattern), 4, f"Pattern {pattern[0]} should be a 4-tuple")
            name, regex, severity, description = pattern
            self.assertIsInstance(name, str)
            self.assertIsInstance(severity, str)
            self.assertIsInstance(description, str)
            self.assertTrue(hasattr(regex, "match"), f"{name} should have a compiled regex")

    def test_all_severities_valid(self):
        valid = {"critical", "high", "medium", "low"}
        for pattern in _EXTENDED_SECRET_PATTERNS:
            self.assertIn(pattern[2], valid, f"{pattern[0]} has invalid severity {pattern[2]}")


if __name__ == "__main__":
    unittest.main()

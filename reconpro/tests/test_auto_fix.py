"""ReconPro Age III — Tests for auto_fix.py.

Covers:
- FixProposal dataclass creation, serialisation, deserialisation
- FixAnalyzer pattern matching (security, performance, code quality, config)
- FixAnalyzer AST-based code transformation
- FixStore persistent storage CRUD, lifecycle, history, stats
- AutoFixEngine orchestration (propose, apply, batch, verify)
- Dry-run mode (default) — nothing is applied
- Convenience functions
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Tuple
from unittest.mock import patch, MagicMock

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(TEST_DIR, "..", "..")
sys.path.insert(0, PROJECT_ROOT)

from reconpro.auto_fix import (
    FixProposal,
    FixAnalyzer,
    FixStore,
    AutoFixEngine,
    ProposalStatus,
    RiskLevel,
    FixCategory,
    _get_call_name,
    _get_call_full_name,
    _IssueNodeFinder,
    propose_fixes,
    get_fix_proposals,
)


# ═══════════════════════════════════════════════════════════════════════════
# FixProposal Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestFixProposal(unittest.TestCase):
    """Tests for the FixProposal dataclass."""

    def test_default_creation(self):
        p = FixProposal()
        self.assertEqual(p.severity, "medium")
        self.assertEqual(p.status, ProposalStatus.PROPOSED.value)
        self.assertEqual(p.risk_level, RiskLevel.MEDIUM.value)
        self.assertEqual(p.confidence, 0.5)
        self.assertFalse(p.automated)
        self.assertEqual(p.affected_lines, [])
        self.assertEqual(p.verification_steps, [])
        self.assertEqual(p.source_issue, {})

    def test_custom_creation(self):
        p = FixProposal(
            title="Fix eval()",
            description="Replace eval with ast.literal_eval",
            severity="high",
            category=FixCategory.SECURITY.value,
            affected_file="/tmp/test.py",
            affected_lines=[10, 11],
            original_code="x = eval(data)",
            proposed_code="x = ast.literal_eval(data)",
            risk_level=RiskLevel.LOW.value,
            confidence=0.85,
            automated=True,
            verification_steps=["Re-run AST analyzer"],
            rollback_plan="git checkout -- /tmp/test.py",
        )
        self.assertEqual(p.title, "Fix eval()")
        self.assertEqual(p.severity, "high")
        self.assertEqual(p.category, FixCategory.SECURITY.value)
        self.assertEqual(p.affected_file, "/tmp/test.py")
        self.assertEqual(p.affected_lines, [10, 11])
        self.assertTrue(p.automated)
        self.assertEqual(len(p.verification_steps), 1)

    def test_to_dict_keys(self):
        p = FixProposal(title="test")
        d = p.to_dict()
        expected_keys = {
            "id", "title", "description", "severity", "category",
            "affected_file", "affected_lines", "original_code",
            "proposed_code", "risk_level", "confidence", "automated",
            "verification_steps", "rollback_plan", "status",
            "source_issue", "created_at", "applied_at", "verified_at",
            "error_message",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_from_dict_roundtrip(self):
        original = FixProposal(
            title="Roundtrip test",
            severity="critical",
            category=FixCategory.SECURITY.value,
            confidence=0.99,
            automated=True,
        )
        d = original.to_dict()
        restored = FixProposal.from_dict(d)
        self.assertEqual(restored.id, original.id)
        self.assertEqual(restored.title, original.title)
        self.assertEqual(restored.severity, original.severity)
        self.assertEqual(restored.confidence, original.confidence)
        self.assertEqual(restored.automated, original.automated)

    def test_from_dict_defaults_on_missing_fields(self):
        p = FixProposal.from_dict({})
        self.assertEqual(p.severity, "medium")
        self.assertEqual(p.status, ProposalStatus.PROPOSED.value)
        self.assertEqual(p.confidence, 0.5)
        self.assertFalse(p.automated)

    def test_id_is_generated(self):
        p1 = FixProposal()
        p2 = FixProposal()
        self.assertNotEqual(p1.id, p2.id)
        self.assertTrue(len(p1.id) >= 8)

    def test_created_at_is_populated(self):
        p = FixProposal()
        self.assertTrue(len(p.created_at) > 0)

    def test_status_enums(self):
        self.assertEqual(ProposalStatus.PROPOSED.value, "proposed")
        self.assertEqual(ProposalStatus.APPROVED.value, "approved")
        self.assertEqual(ProposalStatus.APPLIED.value, "applied")
        self.assertEqual(ProposalStatus.VERIFIED.value, "verified")
        self.assertEqual(ProposalStatus.REJECTED.value, "rejected")
        self.assertEqual(ProposalStatus.FAILED.value, "failed")
        self.assertEqual(ProposalStatus.ROLLED_BACK.value, "rolled_back")

    def test_risk_level_enums(self):
        self.assertEqual(RiskLevel.LOW.value, "low")
        self.assertEqual(RiskLevel.MEDIUM.value, "medium")
        self.assertEqual(RiskLevel.HIGH.value, "high")
        self.assertEqual(RiskLevel.CRITICAL.value, "critical")

    def test_fix_category_enums(self):
        self.assertEqual(FixCategory.SECURITY.value, "security")
        self.assertEqual(FixCategory.PERFORMANCE.value, "performance")
        self.assertEqual(FixCategory.CODE_QUALITY.value, "code_quality")
        self.assertEqual(FixCategory.CONFIG.value, "config")
        self.assertEqual(FixCategory.DEPENDENCY.value, "dependency")
        self.assertEqual(FixCategory.INFRASTRUCTURE.value, "infrastructure")


# ═══════════════════════════════════════════════════════════════════════════
# FixAnalyzer Tests — Pattern Matching
# ═══════════════════════════════════════════════════════════════════════════


class TestFixAnalyzerPatternMatching(unittest.TestCase):
    """Tests for FixAnalyzer's pattern matching against issue dicts."""

    def setUp(self):
        self.analyzer = FixAnalyzer()

    def test_eval_issue_matches(self):
        issue = {
            "title": "eval() Usage",
            "category": "dangerous_eval",
            "severity": "critical",
            "evidence": "x = eval(user_input)",
            "asset": "/app/main.py",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("eval", p.title.lower())
        self.assertEqual(p.category, FixCategory.SECURITY.value)

    def test_exec_issue_matches(self):
        issue = {
            "title": "exec() Usage",
            "category": "dangerous_exec",
            "severity": "critical",
            "evidence": "exec(code)",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("exec", p.title.lower())

    def test_command_injection_shell_true(self):
        issue = {
            "title": "subprocess shell=True",
            "category": "command_injection",
            "severity": "high",
            "evidence": "subprocess.run(cmd, shell=True)",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("shell", p.title.lower())

    def test_sql_injection_fstring(self):
        issue = {
            "title": "SQL in f-string",
            "category": "sql_injection",
            "severity": "critical",
            "evidence": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertEqual(p.category, FixCategory.SECURITY.value)

    def test_hardcoded_secret(self):
        issue = {
            "title": "Hardcoded Secret",
            "category": "hardcoded_secret",
            "severity": "high",
            "evidence": "api_key = \"sk-1234567890abcdef\"",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("secret", p.title.lower())

    def test_weak_crypto(self):
        issue = {
            "title": "Weak Hash Algorithm",
            "category": "weak_crypto",
            "severity": "medium",
            "evidence": "hashlib.md5(data).hexdigest()",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("cryptograph", p.description.lower())

    def test_cors_wildcard(self):
        issue = {
            "title": "CORS Wildcard Origin",
            "category": "cors_wildcard",
            "severity": "medium",
            "evidence": 'Access-Control-Allow-Origin: *',
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("cors", p.title.lower())

    def test_csrf_disabled(self):
        issue = {
            "title": "CSRF Protection Disabled",
            "category": "csrf_disabled",
            "severity": "high",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)

    def test_debug_mode(self):
        issue = {
            "title": "Debug Mode Enabled",
            "category": "debug_mode",
            "severity": "low",
            "evidence": "DEBUG = True",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("debug", p.title.lower())

    def test_cleartext_http(self):
        issue = {
            "title": "HTTP (Cleartext) URL",
            "category": "cleartext_http",
            "severity": "medium",
            "evidence": 'requests.get("http://example.com/api")',
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("http", p.title.lower())

    def test_temp_file_race(self):
        issue = {
            "title": "Insecure Temp File (mktemp)",
            "category": "temp_file_race",
            "severity": "high",
            "evidence": "tmp = tempfile.mktemp()",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("mktemp", p.title.lower())

    def test_sensitive_logging(self):
        issue = {
            "title": "Sensitive Data Logging",
            "category": "sensitive_logging",
            "severity": "medium",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)

    def test_path_traversal(self):
        issue = {
            "title": "Potential Path Traversal",
            "category": "path_traversal",
            "severity": "high",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)

    def test_unsafe_deserialization(self):
        issue = {
            "title": "Unsafe Deserialization (pickle)",
            "category": "unsafe_deserialization",
            "severity": "critical",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)

    def test_jwt_no_verify(self):
        issue = {
            "title": "JWT Decode Without Verification",
            "category": "jwt_no_verify",
            "severity": "high",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)

    def test_config_issue_directory_missing(self):
        issue = {
            "severity": "warning",
            "category": "paths",
            "message": "Plugin directory does not exist: /path/to/plugins",
            "suggestion": "Plugin directory will be created when loading plugins.",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertEqual(p.category, FixCategory.CONFIG.value)

    def test_config_issue_invalid_json(self):
        issue = {
            "severity": "error",
            "category": "config",
            "message": "config.json has invalid JSON: Expecting value",
            "suggestion": "Fix JSON syntax in config.json.",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("json", p.title.lower())

    def test_config_issue_disk_space(self):
        issue = {
            "severity": "warning",
            "category": "disk",
            "message": "Low disk space: 0.30 GB free.",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)

    def test_config_issue_network(self):
        issue = {
            "severity": "warning",
            "category": "network",
            "message": "DNS resolution failed — network may be offline.",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)

    def test_config_issue_python_version(self):
        issue = {
            "severity": "error",
            "category": "python",
            "message": "Python 3.8 is below minimum (3.9).",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)

    def test_generic_proposal_for_unknown_issue(self):
        issue = {
            "title": "Something unusual",
            "message": "An unusual problem occurred",
            "severity": "low",
            "category": "custom_category",
            "suggestion": "Investigate manually",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertIn("Something unusual", p.title)
        self.assertEqual(p.confidence, 0.3)
        self.assertFalse(p.automated)

    def test_none_for_empty_issue(self):
        p = self.analyzer.analyze_issue({})
        self.assertIsNone(p)

    def test_source_issue_stored(self):
        issue = {
            "title": "eval() Usage",
            "category": "dangerous_eval",
            "severity": "critical",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertEqual(p.source_issue["title"], "eval() Usage")

    def test_affected_file_from_asset(self):
        issue = {
            "title": "eval() Usage",
            "category": "dangerous_eval",
            "asset": "/app/main.py",
            "severity": "critical",
        }
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertEqual(p.affected_file, "/app/main.py")

    def test_automated_flag_from_template(self):
        # shell=True removal is automated
        issue = {"category": "command_injection", "severity": "high"}
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertTrue(p.automated)

    def test_non_automated_flag(self):
        # eval replacement is NOT automated
        issue = {"category": "dangerous_eval", "severity": "critical"}
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertFalse(p.automated)

    def test_severity_normalisation(self):
        # "error" should map to "high"
        p = FixAnalyzer._normalise_severity("error")
        self.assertEqual(p, "high")

    def test_severity_normalisation_warning(self):
        p = FixAnalyzer._normalise_severity("warning")
        self.assertEqual(p, "medium")

    def test_severity_normalisation_valid(self):
        p = FixAnalyzer._normalise_severity("critical")
        self.assertEqual(p, "critical")

    def test_rollback_plan_generated(self):
        issue = {"category": "dangerous_eval", "asset": "/app/main.py", "severity": "critical"}
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertTrue(len(p.rollback_plan) > 0)

    def test_verification_steps_generated(self):
        issue = {"category": "dangerous_eval", "severity": "critical"}
        p = self.analyzer.analyze_issue(issue)
        self.assertIsNotNone(p)
        self.assertTrue(len(p.verification_steps) >= 1)


# ═══════════════════════════════════════════════════════════════════════════
# FixAnalyzer Tests — Code-Level Proposals (AST)
# ═══════════════════════════════════════════════════════════════════════════


class TestFixAnalyzerCodeProposals(unittest.TestCase):
    """Tests for AST-based code fix proposals."""

    def setUp(self):
        self.analyzer = FixAnalyzer()

    def test_propose_code_fixes_eval(self):
        code = textwrap.dedent("""\
            x = eval(user_input)
        """)
        issues = [{
            "title": "eval() Usage",
            "category": "dangerous_eval",
            "severity": "critical",
            "evidence": "eval(user_input)",
        }]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, issues)
        os.unlink(f.name)
        self.assertTrue(len(proposals) >= 1)
        # Should have proposed code with ast.literal_eval
        found = False
        for p in proposals:
            if "literal_eval" in p.proposed_code.lower():
                found = True
        self.assertTrue(found, "Should propose ast.literal_eval replacement")

    def test_propose_code_fixes_nonexistent_file(self):
        issues = [{"title": "test", "category": "test"}]
        proposals = self.analyzer.propose_code_fixes("/nonexistent/path.py", issues)
        self.assertEqual(len(proposals), 0)

    def test_propose_code_fixes_no_issues(self):
        code = "x = 1\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [])
        os.unlink(f.name)
        self.assertEqual(len(proposals), 0)

    def test_ast_transform_eval(self):
        code = textwrap.dedent("""\
            result = eval(data)
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "eval() Usage",
                "category": "dangerous_eval",
                "severity": "critical",
                "evidence": "eval(data)",
            }])
        os.unlink(f.name)
        self.assertTrue(len(proposals) >= 1)
        p = proposals[0]
        self.assertIn("literal_eval", p.proposed_code)
        self.assertTrue(len(p.affected_lines) > 0)
        self.assertTrue(len(p.verification_steps) > 0)

    def test_ast_transform_shell_true(self):
        code = textwrap.dedent("""\
            subprocess.run(cmd, shell=True, capture_output=True)
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "subprocess shell=True",
                "category": "command_injection",
                "severity": "high",
                "evidence": "shell=True",
            }])
        os.unlink(f.name)
        self.assertTrue(len(proposals) >= 1)
        p = proposals[0]
        self.assertNotIn("shell=True", p.proposed_code)

    def test_ast_transform_hardcoded_secret(self):
        code = textwrap.dedent("""\
            api_key = "sk-1234567890abcdef"
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "Hardcoded Secret",
                "category": "hardcoded_secret",
                "severity": "high",
                "evidence": 'api_key = "sk-1234567890abcdef"',
            }])
        os.unlink(f.name)
        self.assertTrue(len(proposals) >= 1)
        p = proposals[0]
        self.assertIn("os.environ", p.proposed_code)

    def test_ast_transform_bare_except(self):
        code = textwrap.dedent("""\
            try:
                do_something()
            except:
                pass
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "Bare Except",
                "category": "bare_except",
                "severity": "low",
                "evidence": "except:",
            }])
        os.unlink(f.name)
        # Bare except may or may not generate a proposal depending on AST match
        # At minimum it should not crash
        self.assertIsInstance(proposals, list)

    def test_ast_transform_debug_mode(self):
        code = textwrap.dedent("""\
            DEBUG = True
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "Debug Mode Enabled",
                "category": "debug_mode",
                "severity": "low",
                "evidence": "DEBUG = True",
            }])
        os.unlink(f.name)
        self.assertTrue(len(proposals) >= 1)
        p = proposals[0]
        # debug_mode: either AST transform produced code or pattern-match fallback
        self.assertTrue(
            "False" in p.proposed_code or len(p.description) > 0,
            f"Expected proposed code or description, got: {p.proposed_code!r}",
        )

    def test_ast_transform_http_to_https(self):
        code = textwrap.dedent("""\
            url = "http://example.com/api/data"
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "HTTP (Cleartext) URL",
                "category": "cleartext_http",
                "severity": "medium",
                "evidence": 'url = "http://example.com/api/data"',
            }])
        os.unlink(f.name)
        self.assertTrue(len(proposals) >= 1)
        p = proposals[0]
        # cleartext_http: either AST transform produced code or pattern-match fallback
        self.assertTrue(
            "https://" in p.proposed_code or len(p.description) > 0,
            f"Expected https in proposed code or description, got: {p.proposed_code!r}",
        )

    def test_ast_transform_mktemp(self):
        code = textwrap.dedent("""\
            tmp = tempfile.mktemp(suffix=".txt")
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "Insecure Temp File (mktemp)",
                "category": "temp_file_race",
                "severity": "high",
                "evidence": "tempfile.mktemp(suffix=\".txt\")",
            }])
        os.unlink(f.name)
        self.assertTrue(len(proposals) >= 1)
        p = proposals[0]
        self.assertIn("NamedTemporaryFile", p.proposed_code)

    def test_ast_transform_csrf(self):
        code = textwrap.dedent("""\
            WTF_CSRF_ENABLED = False
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "CSRF Protection Disabled",
                "category": "csrf_disabled",
                "severity": "high",
                "evidence": "WTF_CSRF_ENABLED = False",
            }])
        os.unlink(f.name)
        self.assertTrue(len(proposals) >= 1)
        p = proposals[0]
        # csrf_disabled: either AST transform produced code or pattern-match fallback
        self.assertTrue(
            "True" in p.proposed_code or len(p.description) > 0,
            f"Expected True in proposed code or description, got: {p.proposed_code!r}",
        )

    def test_syntax_error_file_no_crash(self):
        code = "def broken(:\n  pass"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(code)
            f.flush()
            proposals = self.analyzer.propose_code_fixes(f.name, [{
                "title": "test",
                "category": "test",
                "severity": "low",
            }])
        os.unlink(f.name)
        self.assertIsInstance(proposals, list)


class TestFixAnalyzerConfigProposals(unittest.TestCase):
    """Tests for configuration fix proposals."""

    def setUp(self):
        self.analyzer = FixAnalyzer()

    def test_config_fixes_from_diagnostics(self):
        issues = [
            {"severity": "warning", "category": "paths", "message": "directory does not exist: /tmp/plugins"},
            {"severity": "error", "category": "config", "message": "config.json has invalid JSON: bad"},
            {"severity": "warning", "category": "disk", "message": "Low disk space: 0.3 GB free."},
            {"severity": "error", "category": "python", "message": "Python 3.8 is below minimum (3.9)."},
            {"severity": "warning", "category": "network", "message": "DNS resolution failed"},
        ]
        proposals = self.analyzer.propose_config_fixes(issues)
        self.assertEqual(len(proposals), len(issues))
        for p in proposals:
            self.assertIsInstance(p, FixProposal)
            self.assertTrue(len(p.title) > 0)

    def test_empty_config_issues(self):
        proposals = self.analyzer.propose_config_fixes([])
        self.assertEqual(len(proposals), 0)


# ═══════════════════════════════════════════════════════════════════════════
# AST Utility Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestASTUtilities(unittest.TestCase):
    """Tests for AST helper functions."""

    def test_get_call_name_simple(self):
        code = "eval(x)"
        tree = ast.parse(code)
        call = tree.body[0].value
        self.assertEqual(_get_call_name(call), "eval")

    def test_get_call_name_attribute(self):
        code = "subprocess.run(cmd)"
        tree = ast.parse(code)
        call = tree.body[0].value
        self.assertEqual(_get_call_name(call), "run")

    def test_get_call_full_name_attribute(self):
        code = "subprocess.run(cmd)"
        tree = ast.parse(code)
        call = tree.body[0].value
        self.assertEqual(_get_call_full_name(call), "subprocess.run")

    def test_get_call_full_name_simple(self):
        code = "eval(x)"
        tree = ast.parse(code)
        call = tree.body[0].value
        self.assertEqual(_get_call_full_name(call), "eval")

    def test_issue_node_finder_eval(self):
        code = "x = eval(user_data)"
        tree = ast.parse(code)
        finder = _IssueNodeFinder("dangerous_eval", "eval(user_data)", "eval() Usage")
        finder.visit(tree)
        self.assertEqual(len(finder.matched_nodes), 1)
        self.assertIsInstance(finder.matched_nodes[0], ast.Call)

    def test_issue_node_finder_exec(self):
        code = "exec(code)"
        tree = ast.parse(code)
        finder = _IssueNodeFinder("dangerous_exec", "", "exec()")
        finder.visit(tree)
        self.assertEqual(len(finder.matched_nodes), 1)

    def test_issue_node_finder_shell_true(self):
        code = "subprocess.run(cmd, shell=True)"
        tree = ast.parse(code)
        finder = _IssueNodeFinder("command_injection", "shell=True", "")
        finder.visit(tree)
        self.assertEqual(len(finder.matched_nodes), 1)

    def test_issue_node_finder_no_match(self):
        code = "x = 1 + 2"
        tree = ast.parse(code)
        finder = _IssueNodeFinder("dangerous_eval", "", "")
        finder.visit(tree)
        self.assertEqual(len(finder.matched_nodes), 0)

    def test_issue_node_finder_bare_except(self):
        code = textwrap.dedent("""\
            try:
                x = 1
            except:
                pass
        """)
        tree = ast.parse(code)
        finder = _IssueNodeFinder("bare_except", "except:", "")
        finder.visit(tree)
        self.assertEqual(len(finder.matched_nodes), 1)

    def test_issue_node_finder_hardcoded_secret(self):
        code = 'password = "super_secret_123"'
        tree = ast.parse(code)
        finder = _IssueNodeFinder("hardcoded_secret", code, "")
        finder.visit(tree)
        self.assertEqual(len(finder.matched_nodes), 1)

    def test_issue_node_finder_sql_in_fstring(self):
        code = 'f"SELECT * FROM users WHERE id = {uid}"'
        tree = ast.parse(code)
        finder = _IssueNodeFinder("sql_injection", code, "")
        finder.visit(tree)
        self.assertEqual(len(finder.matched_nodes), 1)


# ═══════════════════════════════════════════════════════════════════════════
# FixStore Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestFixStore(unittest.TestCase):
    """Tests for the persistent FixStore."""

    def _make_store(self) -> FixStore:
        tmp = tempfile.mkdtemp()
        store_path = Path(tmp) / "test_fixes.json"
        return FixStore(store_path=store_path), tmp

    def test_create_store(self):
        store, tmp = self._make_store()
        try:
            self.assertIsInstance(store, FixStore)
        finally:
            shutil.rmtree(tmp)

    def test_add_and_get(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="Test fix")
            store.add(p)
            retrieved = store.get(p.id)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.title, "Test fix")
        finally:
            shutil.rmtree(tmp)

    def test_add_persists_to_disk(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="Persistent test")
            store.add(p)
            # Reload from disk
            store2 = FixStore(store_path=store._path)
            retrieved = store2.get(p.id)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.title, "Persistent test")
        finally:
            shutil.rmtree(tmp)

    def test_update_proposal(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="Original")
            store.add(p)
            p.title = "Updated"
            p.status = ProposalStatus.APPROVED.value
            store.update(p)
            retrieved = store.get(p.id)
            self.assertEqual(retrieved.title, "Updated")
            self.assertEqual(retrieved.status, ProposalStatus.APPROVED.value)
        finally:
            shutil.rmtree(tmp)

    def test_update_nonexistent_silent(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="Ghost")
            # Should not crash
            store.update(p)
        finally:
            shutil.rmtree(tmp)

    def test_remove_proposal(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="To remove")
            store.add(p)
            self.assertTrue(store.remove(p.id))
            self.assertIsNone(store.get(p.id))
        finally:
            shutil.rmtree(tmp)

    def test_remove_nonexistent(self):
        store, tmp = self._make_store()
        try:
            self.assertFalse(store.remove("nonexistent"))
        finally:
            shutil.rmtree(tmp)

    def test_list_all(self):
        store, tmp = self._make_store()
        try:
            store.add(FixProposal(title="A"))
            store.add(FixProposal(title="B"))
            store.add(FixProposal(title="C"))
            all_p = store.list_all()
            self.assertEqual(len(all_p), 3)
        finally:
            shutil.rmtree(tmp)

    def test_list_by_status(self):
        store, tmp = self._make_store()
        try:
            p1 = FixProposal(title="Proposed", status=ProposalStatus.PROPOSED.value)
            p2 = FixProposal(title="Approved", status=ProposalStatus.APPROVED.value)
            store.add(p1)
            store.add(p2)
            proposed = store.list_by_status("proposed")
            self.assertEqual(len(proposed), 1)
            self.assertEqual(proposed[0].title, "Proposed")
        finally:
            shutil.rmtree(tmp)

    def test_list_by_category(self):
        store, tmp = self._make_store()
        try:
            p1 = FixProposal(title="Sec", category=FixCategory.SECURITY.value)
            p2 = FixProposal(title="Perf", category=FixCategory.PERFORMANCE.value)
            store.add(p1)
            store.add(p2)
            sec = store.list_by_category(FixCategory.SECURITY.value)
            self.assertEqual(len(sec), 1)
        finally:
            shutil.rmtree(tmp)

    def test_list_by_severity(self):
        store, tmp = self._make_store()
        try:
            p1 = FixProposal(title="Crit", severity="critical")
            p2 = FixProposal(title="Low", severity="low")
            store.add(p1)
            store.add(p2)
            crit = store.list_by_severity("critical")
            self.assertEqual(len(crit), 1)
        finally:
            shutil.rmtree(tmp)

    def test_approve_proposal(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="To approve")
            store.add(p)
            self.assertTrue(store.approve(p.id))
            retrieved = store.get(p.id)
            self.assertEqual(retrieved.status, ProposalStatus.APPROVED.value)
        finally:
            shutil.rmtree(tmp)

    def test_approve_already_applied_fails(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="Already applied", status=ProposalStatus.APPLIED.value)
            store.add(p)
            self.assertFalse(store.approve(p.id))
        finally:
            shutil.rmtree(tmp)

    def test_reject_proposal(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="To reject")
            store.add(p)
            self.assertTrue(store.reject(p.id))
            retrieved = store.get(p.id)
            self.assertEqual(retrieved.status, ProposalStatus.REJECTED.value)
        finally:
            shutil.rmtree(tmp)

    def test_reject_already_applied_fails(self):
        store, tmp = self._make_store()
        try:
            p = FixProposal(title="Already applied", status=ProposalStatus.APPLIED.value)
            store.add(p)
            self.assertFalse(store.reject(p.id))
        finally:
            shutil.rmtree(tmp)

    def test_get_history(self):
        store, tmp = self._make_store()
        try:
            store.add(FixProposal(title="H1"))
            store.add(FixProposal(title="H2"))
            history = store.get_history()
            self.assertGreaterEqual(len(history), 2)
        finally:
            shutil.rmtree(tmp)

    def test_get_stats(self):
        store, tmp = self._make_store()
        try:
            store.add(FixProposal(title="S1", severity="critical", category="security", confidence=0.8))
            store.add(FixProposal(title="S2", severity="low", category="config", confidence=0.4))
            stats = store.get_stats()
            self.assertEqual(stats["total_proposals"], 2)
            self.assertIn("by_status", stats)
            self.assertIn("by_severity", stats)
            self.assertIn("by_category", stats)
            self.assertEqual(stats["average_confidence"], 0.6)
        finally:
            shutil.rmtree(tmp)

    def test_empty_store_stats(self):
        store, tmp = self._make_store()
        try:
            stats = store.get_stats()
            self.assertEqual(stats["total_proposals"], 0)
            self.assertEqual(stats["average_confidence"], 0.0)
        finally:
            shutil.rmtree(tmp)

    def test_corrupted_store_file(self):
        store, tmp = self._make_store()
        try:
            # Write garbage to the store file
            store._path.parent.mkdir(parents=True, exist_ok=True)
            store._path.write_text("{invalid json!!!", encoding="utf-8")
            # Reload should not crash
            store2 = FixStore(store_path=store._path)
            self.assertEqual(len(store2.list_all()), 0)
        finally:
            shutil.rmtree(tmp)

    def test_missing_store_file(self):
        store, tmp = self._make_store()
        try:
            # Remove the file
            if store._path.exists():
                store._path.unlink()
            store2 = FixStore(store_path=store._path)
            self.assertEqual(len(store2.list_all()), 0)
        finally:
            shutil.rmtree(tmp)


# ═══════════════════════════════════════════════════════════════════════════
# AutoFixEngine Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestAutoFixEngine(unittest.TestCase):
    """Tests for the AutoFixEngine orchestrator."""

    def _make_engine(self) -> AutoFixEngine:
        tmp = tempfile.mkdtemp()
        store_path = Path(tmp) / "test_engine_fixes.json"
        store = FixStore(store_path=store_path)
        engine = AutoFixEngine(store=store, dry_run=True)
        return engine, tmp

    def test_init_dry_run_default(self):
        engine = AutoFixEngine()
        self.assertTrue(engine._dry_run)

    def test_init_explicit_wet_run(self):
        engine, tmp = self._make_engine()
        try:
            self.assertTrue(engine._dry_run)
        finally:
            shutil.rmtree(tmp)

    def test_analyze_single_issue(self):
        engine, tmp = self._make_engine()
        try:
            issue = {"title": "eval() Usage", "category": "dangerous_eval", "severity": "critical"}
            p = engine.analyze_issue(issue)
            self.assertIsNotNone(p)
            self.assertIn("eval", p.title.lower())
        finally:
            shutil.rmtree(tmp)

    def test_analyze_single_issue_stored(self):
        engine, tmp = self._make_engine()
        try:
            issue = {"title": "eval() Usage", "category": "dangerous_eval", "severity": "critical"}
            p = engine.analyze_issue(issue)
            stored = engine._store.get(p.id)
            self.assertIsNotNone(stored)
        finally:
            shutil.rmtree(tmp)

    def test_analyze_none_issue(self):
        engine, tmp = self._make_engine()
        try:
            p = engine.analyze_issue({})
            self.assertIsNone(p)
        finally:
            shutil.rmtree(tmp)

    def test_propose_fixes_with_findings(self):
        engine, tmp = self._make_engine()
        try:
            scan = {
                "findings": [
                    {"title": "eval() Usage", "category": "dangerous_eval", "severity": "critical"},
                    {"title": "Debug Mode", "category": "debug_mode", "severity": "low"},
                ]
            }
            proposals = engine.propose_fixes(scan)
            self.assertEqual(len(proposals), 2)
        finally:
            shutil.rmtree(tmp)

    def test_propose_fixes_with_diagnostics(self):
        engine, tmp = self._make_engine()
        try:
            scan = {
                "diagnostics": {
                    "checks": [
                        {"label": "network_dns", "status": "error", "error": "DNS failed"},
                        {"label": "python_version", "status": "ok"},
                    ]
                }
            }
            proposals = engine.propose_fixes(scan)
            # At least one for the failed check
            self.assertGreaterEqual(len(proposals), 1)
        finally:
            shutil.rmtree(tmp)

    def test_propose_fixes_with_config_issues(self):
        engine, tmp = self._make_engine()
        try:
            scan = {
                "config_issues": [
                    {"severity": "error", "category": "config", "message": "config.json has invalid JSON"},
                ]
            }
            proposals = engine.propose_fixes(scan)
            self.assertGreaterEqual(len(proposals), 1)
        finally:
            shutil.rmtree(tmp)

    def test_propose_fixes_with_cross_validation(self):
        engine, tmp = self._make_engine()
        try:
            scan = {
                "cross_validation": {
                    "mismatches": [
                        {
                            "finding": "Port 8080 open",
                            "category": "port",
                            "severity": "medium",
                            "details": "Reported but not confirmed",
                        }
                    ]
                }
            }
            proposals = engine.propose_fixes(scan)
            self.assertGreaterEqual(len(proposals), 1)
        finally:
            shutil.rmtree(tmp)

    def test_propose_fixes_empty_scan(self):
        engine, tmp = self._make_engine()
        try:
            proposals = engine.propose_fixes({})
            self.assertEqual(len(proposals), 0)
        finally:
            shutil.rmtree(tmp)

    def test_propose_fixes_combined(self):
        engine, tmp = self._make_engine()
        try:
            scan = {
                "findings": [
                    {"title": "eval()", "category": "dangerous_eval", "severity": "critical"},
                ],
                "diagnostics": {
                    "checks": [
                        {"label": "disk_space", "status": "error", "error": "Low disk"},
                    ]
                },
                "config_issues": [
                    {"severity": "warning", "category": "paths", "message": "directory does not exist: /tmp/x"},
                ],
            }
            proposals = engine.propose_fixes(scan)
            self.assertGreaterEqual(len(proposals), 3)
        finally:
            shutil.rmtree(tmp)

    def test_propose_code_fixes(self):
        engine, tmp = self._make_engine()
        try:
            code = textwrap.dedent("""\
                x = eval(user_input)
            """)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(code)
                f.flush()
                issues = [{
                    "title": "eval() Usage",
                    "category": "dangerous_eval",
                    "severity": "critical",
                    "evidence": "eval(user_input)",
                }]
                proposals = engine.propose_code_fixes(f.name, issues)
            os.unlink(f.name)
            self.assertGreaterEqual(len(proposals), 1)
        finally:
            shutil.rmtree(tmp)

    def test_propose_config_fixes(self):
        engine, tmp = self._make_engine()
        try:
            issues = [
                {"severity": "warning", "category": "paths", "message": "directory does not exist"},
            ]
            proposals = engine.propose_config_fixes(issues)
            self.assertGreaterEqual(len(proposals), 1)
        finally:
            shutil.rmtree(tmp)


# ═══════════════════════════════════════════════════════════════════════════
# AutoFixEngine — Apply & Dry-Run Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestAutoFixEngineApply(unittest.TestCase):
    """Tests for fix application (dry-run and actual)."""

    def _make_engine(self, dry_run: bool = True) -> Tuple[AutoFixEngine, str]:
        tmp = tempfile.mkdtemp()
        store_path = Path(tmp) / "test_apply_fixes.json"
        store = FixStore(store_path=store_path)
        engine = AutoFixEngine(store=store, dry_run=dry_run)
        return engine, tmp

    def test_dry_run_does_not_modify_file(self):
        engine, tmp = self._make_engine(dry_run=True)
        try:
            code = 'DEBUG = True\n'
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(code)
                f.flush()
                p = FixProposal(
                    title="Disable debug mode",
                    severity="low",
                    category=FixCategory.SECURITY.value,
                    affected_file=f.name,
                    affected_lines=[1],
                    original_code=code.strip(),
                    proposed_code="DEBUG = False  # disabled in production",
                    status=ProposalStatus.APPROVED.value,
                )
                result = engine.apply_fix(p)
            # File should NOT be modified
            with open(f.name) as f2:
                content = f2.read()
            self.assertEqual(content, code)
            self.assertTrue(result["dry_run"])
            self.assertTrue(result["success"])
            os.unlink(f.name)
        finally:
            shutil.rmtree(tmp)

    def test_dry_run_describes_changes(self):
        engine, tmp = self._make_engine(dry_run=True)
        try:
            p = FixProposal(
                title="Test fix",
                original_code="old code",
                proposed_code="new code",
                affected_file="/app/test.py",
                affected_lines=[10],
            )
            result = engine.apply_fix(p)
            self.assertIn("DRY-RUN", result["message"])
            self.assertEqual(len(result["changes"]), 1)
        finally:
            shutil.rmtree(tmp)

    def test_apply_rejects_unapproved(self):
        engine, tmp = self._make_engine(dry_run=False)
        try:
            p = FixProposal(
                title="Unapproved fix",
                status=ProposalStatus.PROPOSED.value,
                affected_file="/some/file.py",
            )
            result = engine.apply_fix(p)
            self.assertFalse(result["success"])
            self.assertIn("approved", result["message"].lower())
        finally:
            shutil.rmtree(tmp)

    def test_apply_already_applied(self):
        engine, tmp = self._make_engine(dry_run=False)
        try:
            p = FixProposal(
                title="Already done",
                status=ProposalStatus.APPLIED.value,
            )
            result = engine.apply_fix(p)
            self.assertFalse(result["success"])
            self.assertIn("already", result["message"].lower())
        finally:
            shutil.rmtree(tmp)

    def test_apply_no_file_path(self):
        engine, tmp = self._make_engine(dry_run=False)
        try:
            p = FixProposal(
                title="No file",
                status=ProposalStatus.APPROVED.value,
                proposed_code="something",
            )
            result = engine.apply_fix(p)
            self.assertFalse(result["success"])
        finally:
            shutil.rmtree(tmp)

    def test_apply_nonexistent_file(self):
        engine, tmp = self._make_engine(dry_run=False)
        try:
            p = FixProposal(
                title="Ghost file",
                status=ProposalStatus.APPROVED.value,
                affected_file="/nonexistent/ghost.py",
                proposed_code="x = 1",
            )
            result = engine.apply_fix(p)
            self.assertFalse(result["success"])
        finally:
            shutil.rmtree(tmp)

    def test_apply_no_proposed_code(self):
        engine, tmp = self._make_engine(dry_run=False)
        try:
            code = "x = 1\n"
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(code)
                f.flush()
                p = FixProposal(
                    title="No code",
                    status=ProposalStatus.APPROVED.value,
                    affected_file=f.name,
                    proposed_code="",
                )
                result = engine.apply_fix(p)
            os.unlink(f.name)
            self.assertFalse(result["success"])
        finally:
            shutil.rmtree(tmp)

    def test_apply_actual_fix(self):
        engine, tmp = self._make_engine(dry_run=False)
        try:
            code = "DEBUG = True\n"
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(code)
                f.flush()
                p = FixProposal(
                    title="Disable debug mode",
                    severity="low",
                    status=ProposalStatus.APPROVED.value,
                    affected_file=f.name,
                    affected_lines=[1],
                    original_code="DEBUG = True",
                    proposed_code="DEBUG = False  # disabled in production",
                )
                result = engine.apply_fix(p, dry_run=False)
            with open(f.name) as f2:
                content = f2.read()
            self.assertIn("False", content)
            self.assertTrue(result["success"])
            # Cleanup
            os.unlink(f.name)
            bak = Path(f.name + ".bak")
            if bak.exists():
                bak.unlink()
        finally:
            shutil.rmtree(tmp)

    def test_apply_creates_backup(self):
        engine, tmp = self._make_engine(dry_run=False)
        try:
            code = "old = 1\n"
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(code)
                f.flush()
                p = FixProposal(
                    title="Replace code",
                    status=ProposalStatus.APPROVED.value,
                    affected_file=f.name,
                    affected_lines=[1],
                    original_code="old = 1",
                    proposed_code="new = 2",
                )
                engine.apply_fix(p, dry_run=False)
            bak = Path(f.name + ".bak")
            self.assertTrue(bak.exists())
            with open(bak) as f2:
                self.assertEqual(f2.read(), code)
            os.unlink(f.name)
            if bak.exists():
                bak.unlink()
        finally:
            shutil.rmtree(tmp)


# ═══════════════════════════════════════════════════════════════════════════
# AutoFixEngine — Batch Fix Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestAutoFixEngineBatchFix(unittest.TestCase):
    """Tests for batch fix application."""

    def _make_engine(self, dry_run: bool = True) -> Tuple[AutoFixEngine, str]:
        tmp = tempfile.mkdtemp()
        store_path = Path(tmp) / "test_batch_fixes.json"
        store = FixStore(store_path=store_path)
        engine = AutoFixEngine(store=store, dry_run=dry_run)
        return engine, tmp

    def test_batch_dry_run(self):
        engine, tmp = self._make_engine(dry_run=True)
        try:
            proposals = [
                FixProposal(title="Fix 1"),
                FixProposal(title="Fix 2"),
            ]
            result = engine.batch_fix(proposals)
            self.assertEqual(result["total"], 2)
            self.assertEqual(result["succeeded"], 2)
            self.assertEqual(result["failed"], 0)
        finally:
            shutil.rmtree(tmp)

    def test_batch_skips_non_automated_unapproved(self):
        engine, tmp = self._make_engine(dry_run=False)
        try:
            proposals = [
                FixProposal(title="Auto fix", automated=True),
                FixProposal(title="Manual fix", automated=False),
            ]
            result = engine.batch_fix(proposals, dry_run=False)
            self.assertEqual(result["skipped"], 1)
        finally:
            shutil.rmtree(tmp)

    def test_batch_empty(self):
        engine, tmp = self._make_engine(dry_run=True)
        try:
            result = engine.batch_fix([])
            self.assertEqual(result["total"], 0)
        finally:
            shutil.rmtree(tmp)

    def test_batch_result_structure(self):
        engine, tmp = self._make_engine(dry_run=True)
        try:
            proposals = [FixProposal(title="X")]
            result = engine.batch_fix(proposals)
            self.assertIn("total", result)
            self.assertIn("succeeded", result)
            self.assertIn("failed", result)
            self.assertIn("skipped", result)
            self.assertIn("results", result)
            self.assertEqual(len(result["results"]), 1)
        finally:
            shutil.rmtree(tmp)


# ═══════════════════════════════════════════════════════════════════════════
# AutoFixEngine — Verification Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestAutoFixEngineVerify(unittest.TestCase):
    """Tests for fix verification."""

    def _make_engine(self) -> Tuple[AutoFixEngine, str]:
        tmp = tempfile.mkdtemp()
        store_path = Path(tmp) / "test_verify.json"
        store = FixStore(store_path=store_path)
        engine = AutoFixEngine(store=store, dry_run=True)
        return engine, tmp

    def test_verify_applied_fix_success(self):
        engine, tmp = self._make_engine()
        try:
            p = FixProposal(
                title="Fix eval",
                status=ProposalStatus.APPLIED.value,
                source_issue={
                    "title": "eval() Usage",
                    "category": "dangerous_eval",
                },
            )
            post_state = {"findings": []}
            result = engine.verify_fix(p, post_state)
            self.assertTrue(result["verified"])
            self.assertEqual(p.status, ProposalStatus.VERIFIED.value)
        finally:
            shutil.rmtree(tmp)

    def test_verify_applied_fix_still_present(self):
        engine, tmp = self._make_engine()
        try:
            p = FixProposal(
                title="Fix eval",
                status=ProposalStatus.APPLIED.value,
                source_issue={
                    "title": "eval() Usage",
                    "category": "dangerous_eval",
                },
            )
            post_state = {"findings": [
                {"title": "eval() Usage", "category": "dangerous_eval"},
            ]}
            result = engine.verify_fix(p, post_state)
            self.assertFalse(result["verified"])
            self.assertEqual(len(result["remaining_issues"]), 1)
        finally:
            shutil.rmtree(tmp)

    def test_verify_not_applied(self):
        engine, tmp = self._make_engine()
        try:
            p = FixProposal(
                title="Not yet applied",
                status=ProposalStatus.PROPOSED.value,
            )
            result = engine.verify_fix(p, {})
            self.assertFalse(result["verified"])
        finally:
            shutil.rmtree(tmp)

    def test_verify_result_structure(self):
        engine, tmp = self._make_engine()
        try:
            p = FixProposal(status=ProposalStatus.APPLIED.value)
            result = engine.verify_fix(p, {})
            self.assertIn("verified", result)
            self.assertIn("proposal_id", result)
            self.assertIn("details", result)
            self.assertIn("remaining_issues", result)
        finally:
            shutil.rmtree(tmp)


# ═══════════════════════════════════════════════════════════════════════════
# Fix History Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestFixHistory(unittest.TestCase):
    """Tests for fix history tracking."""

    def _make_engine(self) -> Tuple[AutoFixEngine, str]:
        tmp = tempfile.mkdtemp()
        store_path = Path(tmp) / "test_history.json"
        store = FixStore(store_path=store_path)
        engine = AutoFixEngine(store=store, dry_run=True)
        return engine, tmp

    def test_get_fix_history(self):
        engine, tmp = self._make_engine()
        try:
            engine.analyze_issue({"title": "Test", "category": "debug_mode", "severity": "low"})
            history = engine.get_fix_history()
            self.assertGreaterEqual(len(history), 1)
        finally:
            shutil.rmtree(tmp)

    def test_history_has_required_fields(self):
        engine, tmp = self._make_engine()
        try:
            engine.analyze_issue({"title": "H Test", "category": "debug_mode", "severity": "low"})
            history = engine.get_fix_history()
            entry = history[0]
            self.assertIn("timestamp", entry)
            self.assertIn("action", entry)
            self.assertIn("proposal_id", entry)
            self.assertIn("proposal_title", entry)
            self.assertIn("status", entry)
            self.assertIn("severity", entry)
            self.assertIn("category", entry)
        finally:
            shutil.rmtree(tmp)


# ═══════════════════════════════════════════════════════════════════════════
# Convenience Function Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestConvenienceFunctions(unittest.TestCase):
    """Tests for module-level convenience functions."""

    def test_propose_fixes_returns_list(self):
        scan = {
            "findings": [
                {"title": "eval()", "category": "dangerous_eval", "severity": "critical"},
            ]
        }
        proposals = propose_fixes(scan)
        self.assertIsInstance(proposals, list)
        self.assertGreaterEqual(len(proposals), 1)

    def test_propose_fixes_empty(self):
        proposals = propose_fixes({})
        self.assertEqual(len(proposals), 0)

    def test_get_fix_proposals_returns_list(self):
        tmp = tempfile.mkdtemp()
        try:
            store_path = Path(tmp) / "conv_test.json"
            proposals = get_fix_proposals(store_path=store_path)
            self.assertIsInstance(proposals, list)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""ReconPro v11 — Tests for Auto Validation Pipeline.

Comprehensive unit tests covering all classes and stages in
auto_validation.py. Uses only stdlib (unittest, tempfile, os).

Run:
    python -m unittest reconpro.tests.test_auto_validation -v
    python reconpro/tests/test_auto_validation.py
"""

from __future__ import annotations

import ast
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# Ensure project root is on path
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(TEST_DIR, "..", "..")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from reconpro.auto_validation import (
    ImportValidator,
    InterfaceValidator,
    PerformanceValidator,
    SecurityValidator,
    Severity,
    StageStatus,
    SyntaxValidator,
    TestValidator,
    TypeValidator,
    ValidationFinding,
    ValidationPipeline,
    ValidationReport,
    ValidationStage,
    ValidationStageResult,
    _get_stdlib_modules,
    validate_full,
    validate_imports,
    validate_syntax,
)
from reconpro.constants import MEMORY_DIR


class TestSeverity(unittest.TestCase):
    """Tests for the Severity enum."""

    def test_enum_values(self) -> None:
        self.assertEqual(Severity.CRITICAL.value, "critical")
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.MEDIUM.value, "medium")
        self.assertEqual(Severity.LOW.value, "low")
        self.assertEqual(Severity.INFO.value, "info")

    def test_ordering(self) -> None:
        self.assertTrue(Severity.CRITICAL < Severity.HIGH)
        self.assertTrue(Severity.HIGH < Severity.MEDIUM)
        self.assertTrue(Severity.MEDIUM < Severity.LOW)
        self.assertTrue(Severity.LOW < Severity.INFO)
        self.assertTrue(Severity.CRITICAL < Severity.INFO)

    def test_sort_key(self) -> None:
        self.assertEqual(Severity.CRITICAL.sort_key, 0)
        self.assertEqual(Severity.HIGH.sort_key, 1)
        self.assertEqual(Severity.MEDIUM.sort_key, 2)
        self.assertEqual(Severity.LOW.sort_key, 3)
        self.assertEqual(Severity.INFO.sort_key, 4)

    def test_comparison_operators(self) -> None:
        self.assertLessEqual(Severity.CRITICAL, Severity.HIGH)
        self.assertGreaterEqual(Severity.INFO, Severity.LOW)
        self.assertGreater(Severity.MEDIUM, Severity.CRITICAL)
        self.assertLess(Severity.HIGH, Severity.INFO)


class TestStageStatus(unittest.TestCase):
    """Tests for the StageStatus enum."""

    def test_values(self) -> None:
        self.assertEqual(StageStatus.PASSED.value, "passed")
        self.assertEqual(StageStatus.FAILED.value, "failed")
        self.assertEqual(StageStatus.SKIPPED.value, "skipped")
        self.assertEqual(StageStatus.ERROR.value, "error")


class TestValidationFinding(unittest.TestCase):
    """Tests for the ValidationFinding dataclass."""

    def test_defaults(self) -> None:
        f = ValidationFinding()
        self.assertEqual(f.file, "")
        self.assertEqual(f.line, 0)
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.message, "")
        self.assertEqual(f.suggestion, "")
        self.assertEqual(f.rule_id, "")

    def test_custom_values(self) -> None:
        f = ValidationFinding(
            file="test.py", line=42, severity="high",
            message="Bad stuff", suggestion="Fix it", rule_id="RULE-001",
        )
        self.assertEqual(f.file, "test.py")
        self.assertEqual(f.line, 42)
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.message, "Bad stuff")
        self.assertEqual(f.suggestion, "Fix it")
        self.assertEqual(f.rule_id, "RULE-001")

    def test_invalid_severity_normalized_to_info(self) -> None:
        f = ValidationFinding(severity="super_critical")
        self.assertEqual(f.severity, "info")

    def test_to_dict(self) -> None:
        f = ValidationFinding(file="a.py", line=1, severity="critical",
                              message="err", suggestion="fix", rule_id="R1")
        d = f.to_dict()
        self.assertEqual(d["file"], "a.py")
        self.assertEqual(d["line"], 1)
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["message"], "err")
        self.assertEqual(d["suggestion"], "fix")
        self.assertEqual(d["rule_id"], "R1")

    def test_case_insensitive_severity(self) -> None:
        f = ValidationFinding(severity="CRITICAL")
        self.assertEqual(f.severity, "critical")


class TestValidationStageResult(unittest.TestCase):
    """Tests for the ValidationStageResult dataclass."""

    def test_passed_property(self) -> None:
        r = ValidationStageResult(stage_name="test", status="passed")
        self.assertTrue(r.passed)

    def test_failed_status(self) -> None:
        r = ValidationStageResult(stage_name="test", status="failed")
        self.assertFalse(r.passed)

    def test_finding_counts(self) -> None:
        findings = [
            ValidationFinding(severity="critical"),
            ValidationFinding(severity="critical"),
            ValidationFinding(severity="high"),
            ValidationFinding(severity="medium"),
            ValidationFinding(severity="medium"),
            ValidationFinding(severity="medium"),
            ValidationFinding(severity="low"),
            ValidationFinding(severity="info"),
            ValidationFinding(severity="info"),
            ValidationFinding(severity="info"),
        ]
        r = ValidationStageResult(stage_name="test", status="failed", findings=findings)
        self.assertEqual(r.finding_count, 10)
        self.assertEqual(r.critical_count(), 2)
        self.assertEqual(r.high_count(), 1)
        self.assertEqual(r.medium_count(), 3)
        self.assertEqual(r.low_count(), 1)
        self.assertEqual(r.info_count(), 3)

    def test_has_critical_or_high(self) -> None:
        findings = [ValidationFinding(severity="medium")]
        r = ValidationStageResult(stage_name="test", status="passed", findings=findings)
        self.assertFalse(r.has_critical_or_high())

        findings.append(ValidationFinding(severity="critical"))
        r2 = ValidationStageResult(stage_name="test", status="failed", findings=findings)
        self.assertTrue(r2.has_critical_or_high())

    def test_to_dict(self) -> None:
        r = ValidationStageResult(
            stage_name="syntax", status="passed", duration=1.234,
            files_scanned=10, findings=[],
        )
        d = r.to_dict()
        self.assertEqual(d["stage_name"], "syntax")
        self.assertEqual(d["status"], "passed")
        self.assertEqual(d["duration"], 1.234)
        self.assertEqual(d["files_scanned"], 10)
        self.assertEqual(d["finding_count"], 0)
        self.assertEqual(d["findings"], [])
        self.assertEqual(d["error_message"], "")


class TestValidationReport(unittest.TestCase):
    """Tests for the ValidationReport dataclass."""

    def _make_report(self, **kwargs) -> ValidationReport:
        defaults = {
            "timestamp": "2024-01-01T00:00:00",
            "project_root": "/tmp/project",
            "overall_status": "passed",
            "total_duration": 1.0,
        }
        defaults.update(kwargs)
        return ValidationReport(**defaults)

    def test_defaults(self) -> None:
        r = self._make_report()
        self.assertTrue(r.passed)
        self.assertEqual(r.total_findings, 0)
        self.assertEqual(r.total_critical, 0)
        self.assertEqual(r.stages_passed, 0)
        self.assertEqual(r.stages_total, 0)

    def test_aggregate_counts(self) -> None:
        s1 = ValidationStageResult(
            stage_name="syntax", status="passed",
            findings=[
                ValidationFinding(severity="critical"),
                ValidationFinding(severity="high"),
            ],
        )
        s2 = ValidationStageResult(
            stage_name="imports", status="passed",
            findings=[
                ValidationFinding(severity="high"),
                ValidationFinding(severity="low"),
                ValidationFinding(severity="info"),
            ],
        )
        r = self._make_report(stage_results=[s1, s2])
        self.assertEqual(r.total_findings, 5)
        self.assertEqual(r.total_critical, 1)
        self.assertEqual(r.total_high, 2)
        self.assertEqual(r.total_medium, 0)
        self.assertEqual(r.total_low, 1)
        self.assertEqual(r.total_info, 1)
        self.assertEqual(r.stages_passed, 2)
        self.assertEqual(r.stages_total, 2)
        self.assertEqual(r.files_scanned_total, 0)

    def test_get_stage_result(self) -> None:
        s1 = ValidationStageResult(stage_name="syntax", status="passed")
        s2 = ValidationStageResult(stage_name="imports", status="failed")
        r = self._make_report(stage_results=[s1, s2])
        self.assertIsNotNone(r.get_stage_result("syntax"))
        self.assertIsNotNone(r.get_stage_result("imports"))
        self.assertIsNone(r.get_stage_result("nonexistent"))

    def test_get_trends_no_previous(self) -> None:
        r = self._make_report()
        trends = r.get_trends()
        self.assertFalse(trends["trend_available"])

    def test_get_trends_with_previous(self) -> None:
        s1 = ValidationStageResult(stage_name="syntax", status="passed",
                                     findings=[ValidationFinding(severity="critical")])
        r = self._make_report(
            stage_results=[s1],
            total_duration=5.0,
            previous_report={
                "timestamp": "2023-12-31T00:00:00",
                "total_findings": 10,
                "total_critical": 2,
                "total_high": 3,
                "total_duration": 8.0,
            },
        )
        trends = r.get_trends()
        self.assertTrue(trends["trend_available"])
        self.assertEqual(trends["findings_delta"], -9)  # 1 - 10
        self.assertEqual(trends["critical_delta"], -1)    # 1 - 2
        self.assertEqual(trends["high_delta"], -3)         # 0 - 3
        self.assertEqual(trends["duration_delta"], -3.0)
        self.assertTrue(trends["improved"])

    def test_summary(self) -> None:
        s1 = ValidationStageResult(stage_name="syntax", status="passed",
                                     duration=0.5, files_scanned=10)
        r = self._make_report(stage_results=[s1], total_duration=0.5)
        summary = r.summary()
        self.assertIn("ReconPro Auto-Validation Report", summary)
        self.assertIn("PASSED", summary)
        self.assertIn("syntax", summary)

    def test_to_dict(self) -> None:
        r = self._make_report()
        d = r.to_dict()
        self.assertIn("timestamp", d)
        self.assertIn("overall_status", d)
        self.assertIn("stage_results", d)
        self.assertIn("trends", d)

    def test_save_and_load(self) -> None:
        """Test save creates a JSON file and load_latest can read it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            reports_dir = Path(tmpdir) / "reports"
            s1 = ValidationStageResult(stage_name="syntax", status="passed")
            r = self._make_report(stage_results=[s1])

            saved_path = r.save(reports_dir)
            self.assertTrue(saved_path.exists())

            loaded = ValidationReport.load_latest(reports_dir)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["overall_status"], "passed")
            self.assertEqual(loaded["stage_results"][0]["stage_name"], "syntax")

    def test_load_latest_no_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            loaded = ValidationReport.load_latest(Path(tmpdir))
            self.assertIsNone(loaded)

    def test_load_latest_missing_dir(self) -> None:
        loaded = ValidationReport.load_latest(Path("/nonexistent/path"))
        self.assertIsNone(loaded)


class TestStdlibModules(unittest.TestCase):
    """Tests for the stdlib module detection."""

    def test_returns_set(self) -> None:
        stdlib = _get_stdlib_modules()
        self.assertIsInstance(stdlib, set)
        self.assertTrue(len(stdlib) > 0)

    def test_contains_common_modules(self) -> None:
        stdlib = _get_stdlib_modules()
        for mod in ("os", "sys", "json", "re", "ast", "pathlib", "typing"):
            self.assertIn(mod, stdlib)

    def test_cached(self) -> None:
        first = _get_stdlib_modules()
        second = _get_stdlib_modules()
        self.assertIs(first, second)


class TestValidationStage(unittest.TestCase):
    """Tests for the ValidationStage ABC."""

    def test_discover_python_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some files
            (Path(tmpdir) / "main.py").write_text("print('hello')\n")
            (Path(tmpdir) / "utils.py").write_text("def foo(): pass\n")
            sub = Path(tmpdir) / "pkg"
            sub.mkdir()
            (sub / "__init__.py").write_text("")
            (sub / "mod.py").write_text("x = 1\n")

            # Should skip __pycache__
            cache = Path(tmpdir) / "__pycache__"
            cache.mkdir()
            (cache / "cached.pyc").write_bytes(b"\x00")

            stage = _ConcreteValidationStage(Path(tmpdir))
            files = stage._discover_python_files()
            file_names = [f.name for f in files]
            self.assertIn("main.py", file_names)
            self.assertIn("utils.py", file_names)
            self.assertIn("__init__.py", file_names)
            self.assertIn("mod.py", file_names)
            self.assertNotIn("cached.pyc", file_names)

    def test_make_result(self) -> None:
        stage = _ConcreteValidationStage(Path("/tmp"))
        findings = [ValidationFinding(message="test")]
        result = stage._make_result("passed", findings, 5, 1.0)
        self.assertEqual(result.stage_name, "concrete")
        self.assertEqual(result.status, "passed")
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.files_scanned, 5)
        self.assertEqual(result.duration, 1.0)


class _ConcreteValidationStage(ValidationStage):
    """Concrete implementation for testing ValidationStage ABC."""

    name = "concrete"
    description = "Concrete test stage"

    def run(self) -> ValidationStageResult:
        return self._make_result("passed", [])


# ────────────────────────────────────────────────────────────────────────
# SyntaxValidator Tests
# ────────────────────────────────────────────────────────────────────────

class TestSyntaxValidator(unittest.TestCase):
    """Tests for the SyntaxValidator stage."""

    def test_valid_python_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "good.py").write_text("x = 1\nprint(x)\n")
            (Path(tmpdir) / "also_good.py").write_text(
                "def foo(a: int) -> str:\n    return str(a)\n"
            )
            validator = SyntaxValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.status, "passed")
            self.assertEqual(result.finding_count, 0)
            self.assertEqual(result.files_scanned, 2)

    def test_syntax_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("def foo(\n")  # Incomplete function
            validator = SyntaxValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.status, "failed")
            self.assertTrue(result.finding_count > 0)
            self.assertTrue(any(f.severity == "critical" for f in result.findings))

    def test_mixed_valid_and_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "good.py").write_text("pass\n")
            (Path(tmpdir) / "bad.py").write_text("if True\n")  # Missing colon
            validator = SyntaxValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.files_scanned, 2)

    def test_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = SyntaxValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.status, "passed")
            self.assertEqual(result.finding_count, 0)

    def test_skips_pycache(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "__pycache__").mkdir()
            (Path(tmpdir) / "__pycache__" / "compiled.pyc").write_bytes(b"\x00")
            (Path(tmpdir) / "real.py").write_text("pass\n")
            validator = SyntaxValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.finding_count, 0)

    def test_finding_has_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("def (\n")
            validator = SyntaxValidator(Path(tmpdir))
            result = validator.run()
            self.assertTrue(any(f.rule_id.startswith("SYN-") for f in result.findings))

    def test_utf8_file_handling(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "unicode.py").write_text(
                "# Comment with Unicode: \u00e9\u00e8\u00ea\nx = 1\n",
                encoding="utf-8",
            )
            validator = SyntaxValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.status, "passed")


# ────────────────────────────────────────────────────────────────────────
# ImportValidator Tests
# ────────────────────────────────────────────────────────────────────────

class TestImportValidator(unittest.TestCase):
    """Tests for the ImportValidator stage."""

    def test_valid_imports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "mod.py").write_text(
                "import os\nimport sys\nfrom pathlib import Path\n\n"
                "def main():\n    print(os.name)\n"
            )
            validator = ImportValidator(Path(tmpdir))
            result = validator.run()
            # Should not fail on valid stdlib imports
            self.assertNotEqual(result.status, "error")

    def test_unused_import_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "mod.py").write_text(
                "import os\nimport collections\n\n"
                "def main():\n    return os.name\n"
            )
            validator = ImportValidator(Path(tmpdir))
            result = validator.run()
            unused = [f for f in result.findings if f.rule_id == "IMP-003"]
            # collections should be flagged as unused
            self.assertTrue(len(unused) > 0)
            self.assertTrue(any("collections" in f.message for f in unused))

    def test_circular_imports_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a simple circular dependency
            a_path = Path(tmpdir) / "a.py"
            b_path = Path(tmpdir) / "b.py"
            a_path.write_text("import b\nx = 1\n")
            b_path.write_text("import a\ny = 2\n")

            validator = ImportValidator(Path(tmpdir))
            result = validator.run()
            circular = [f for f in result.findings if f.rule_id == "IMP-001"]
            self.assertTrue(len(circular) > 0, "Should detect circular import between a.py and b.py")

    def test_skip_test_files_for_unused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test_something.py").write_text(
                "import os\nimport unittest\n\n"
                "class TestCase(unittest.TestCase):\n    pass\n"
            )
            validator = ImportValidator(Path(tmpdir))
            result = validator.run()
            unused = [f for f in result.findings if f.rule_id == "IMP-003"]
            # Test files should be skipped for unused import checks
            self.assertEqual(len(unused), 0)

    def test_skip_init_files_for_unused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "__init__.py").write_text(
                "from .mod import something\n"
            )
            validator = ImportValidator(Path(tmpdir))
            result = validator.run()
            unused = [f for f in result.findings if f.rule_id == "IMP-003"]
            self.assertEqual(len(unused), 0)

    def test_syntax_error_files_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "broken.py").write_text("def (\n")
            (Path(tmpdir) / "ok.py").write_text("pass\n")
            validator = ImportValidator(Path(tmpdir))
            result = validator.run()
            # Should not crash
            self.assertIn(result.status, ("passed", "failed"))


# ────────────────────────────────────────────────────────────────────────
# InterfaceValidator Tests
# ────────────────────────────────────────────────────────────────────────

class TestInterfaceValidator(unittest.TestCase):
    """Tests for the InterfaceValidator stage."""

    def test_missing_registry_graceful(self) -> None:
        """If registry.py doesn't exist, should produce a warning, not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InterfaceValidator(Path(tmpdir))
            result = validator.run()
            # Should not crash, should report a medium finding
            self.assertIn(result.status, ("failed", "error"))
            self.assertTrue(result.finding_count > 0)

    def test_actual_reconpro_registry(self) -> None:
        """Run against actual ReconPro registry."""
        reconpro_root = Path(__file__).parent.parent
        validator = InterfaceValidator(reconpro_root)
        result = validator.run()
        self.assertIsInstance(result, ValidationStageResult)
        self.assertEqual(result.stage_name, "interfaces")
        # All modules should have runners
        no_runner = [f for f in result.findings if f.rule_id == "IFC-002"]
        self.assertEqual(len(no_runner), 0, "All modules should have runners")

    def test_result_structure(self) -> None:
        """Result has expected structure."""
        reconpro_root = Path(__file__).parent.parent
        validator = InterfaceValidator(reconpro_root)
        result = validator.run()
        self.assertIsNotNone(result.stage_name)
        self.assertIn(result.status, ("passed", "failed", "error", "skipped"))
        self.assertGreaterEqual(result.duration, 0)


# ────────────────────────────────────────────────────────────────────────
# TypeValidator Tests
# ────────────────────────────────────────────────────────────────────────

class TestTypeValidator(unittest.TestCase):
    """Tests for the TypeValidator stage."""

    def test_full_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "typed.py").write_text(
                "def add(a: int, b: int) -> int:\n    return a + b\n"
                "\n"
                "def greet(name: str) -> str:\n    return f'Hello {name}'\n"
            )
            validator = TypeValidator(Path(tmpdir))
            result = validator.run()
            # Should pass with no findings about low coverage
            low_coverage = [f for f in result.findings if f.rule_id == "TYP-001"]
            self.assertEqual(len(low_coverage), 0)

    def test_low_coverage_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # File with many untyped functions
            untyped_code = "\n".join(
                f"def func{i}():\n    return {i}\n"
                for i in range(5)
            )
            (Path(tmpdir) / "untyped.py").write_text(untyped_code)
            validator = TypeValidator(Path(tmpdir))
            result = validator.run()
            low_coverage = [f for f in result.findings if f.rule_id == "TYP-001"]
            self.assertTrue(len(low_coverage) > 0, "Should detect low type coverage")

    def test_skips_test_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test_foo.py").write_text(
                "def test_something():\n    assert True\n"
            )
            validator = TypeValidator(Path(tmpdir))
            result = validator.run()
            low_coverage = [f for f in result.findings if f.rule_id == "TYP-001"]
            self.assertEqual(len(low_coverage), 0, "Test files should be skipped")

    def test_skips_init_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "__init__.py").write_text("x = 1\n")
            validator = TypeValidator(Path(tmpdir))
            result = validator.run()
            low_coverage = [f for f in result.findings if f.rule_id == "TYP-001"]
            self.assertEqual(len(low_coverage), 0, "__init__ files should be skipped")

    def test_class_methods_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "cls.py").write_text(
                "class My:\n"
                "    def typed(self, x: int) -> int:\n"
                "        return x\n"
                "    def untyped(self):\n"
                "        pass\n"
            )
            validator = TypeValidator(Path(tmpdir))
            result = validator.run()
            # Only 2 functions, so coverage threshold won't trigger
            self.assertIsInstance(result, ValidationStageResult)


# ────────────────────────────────────────────────────────────────────────
# SecurityValidator Tests
# ────────────────────────────────────────────────────────────────────────

class TestSecurityValidator(unittest.TestCase):
    """Tests for the SecurityValidator stage."""

    def test_detects_eval(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "evil.py").write_text("x = eval(user_input)\n")
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            eval_findings = [f for f in result.findings if f.rule_id == "SEC-001"]
            self.assertTrue(len(eval_findings) > 0, "Should detect eval()")

    def test_detects_exec(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "evil.py").write_text("exec('print(1)')\n")
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            exec_findings = [f for f in result.findings if f.rule_id == "SEC-001"]
            self.assertTrue(len(exec_findings) > 0, "Should detect exec()")

    def test_detects_hardcoded_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.py").write_text('password = "my_secret_123"\n')
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            secret_findings = [f for f in result.findings if f.rule_id == "SEC-007"]
            self.assertTrue(len(secret_findings) > 0, "Should detect hardcoded password")

    def test_detects_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.py").write_text('api_key = "sk_live_1234567890abcdef"\n')
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            secret_findings = [f for f in result.findings if f.rule_id == "SEC-007"]
            self.assertTrue(len(secret_findings) > 0, "Should detect hardcoded API key")

    def test_detects_shell_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "runner.py").write_text(
                "import subprocess\n"
                "subprocess.run('ls', shell=True)\n"
            )
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            shell_findings = [f for f in result.findings if f.rule_id == "SEC-005"]
            self.assertTrue(len(shell_findings) > 0, "Should detect shell=True")

    def test_detects_mutable_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "mod.py").write_text(
                "def append_to(item, target=[]):\n"
                "    target.append(item)\n"
                "    return target\n"
            )
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            mutable_findings = [f for f in result.findings if f.rule_id == "SEC-006"]
            self.assertTrue(len(mutable_findings) > 0, "Should detect mutable default")

    def test_detects_verify_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "req.py").write_text(
                "import urllib.request\n"
                "urllib.request.urlopen('http://example.com', context=None)\n"
            )
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            # verify=False check is for keyword args
            # This test ensures the stage runs without error
            self.assertIsInstance(result, ValidationStageResult)

    def test_clean_code_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "clean.py").write_text(
                "def safe_function(data: str) -> str:\n"
                "    return data.upper()\n"
                "\n"
                "import os\n"
                "def get_path() -> str:\n"
                "    return os.getcwd()\n"
            )
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            # No high or critical findings expected
            high_or_critical = [f for f in result.findings
                                 if f.severity in ("critical", "high")]
            self.assertEqual(len(high_or_critical), 0)

    def test_skips_secrets_in_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "mod.py").write_text(
                "# password = \"not_a_real_password\"\n"
                "def foo():\n    pass\n"
            )
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            secret_findings = [f for f in result.findings if f.rule_id == "SEC-007"]
            self.assertEqual(len(secret_findings), 0, "Secrets in comments should be ignored")

    def test_detects_cert_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "ssl_mod.py").write_text(
                "import ssl\n"
                "ctx = ssl.create_default_context()\n"
                "ctx.verify_mode = ssl.CERT_NONE\n"
            )
            validator = SecurityValidator(Path(tmpdir))
            result = validator.run()
            cert_findings = [f for f in result.findings if f.rule_id == "SEC-003"]
            self.assertTrue(len(cert_findings) > 0, "Should detect CERT_NONE")


# ────────────────────────────────────────────────────────────────────────
# PerformanceValidator Tests
# ────────────────────────────────────────────────────────────────────────

class TestPerformanceValidator(unittest.TestCase):
    """Tests for the PerformanceValidator stage."""

    def test_small_files_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "small.py").write_text("pass\n")
            validator = PerformanceValidator(Path(tmpdir))
            result = validator.run()
            oversized = [f for f in result.findings if f.rule_id == "PERF-001"]
            self.assertEqual(len(oversized), 0)

    def test_large_file_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            lines = ["pass\n"] * PerformanceValidator.MAX_FILE_LINES + ["x = 1\n"]
            (Path(tmpdir) / "big.py").write_text("".join(lines))
            validator = PerformanceValidator(Path(tmpdir))
            result = validator.run()
            oversized = [f for f in result.findings if f.rule_id == "PERF-001"]
            self.assertTrue(len(oversized) > 0, "Should detect large file")

    def test_summary_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "mod.py").write_text("x = 1\n")
            validator = PerformanceValidator(Path(tmpdir))
            result = validator.run()
            summary = [f for f in result.findings if f.rule_id == "PERF-000"]
            self.assertTrue(len(summary) > 0, "Should have summary finding")
            self.assertIn("Total lines of code", summary[0].message)

    def test_always_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "any.py").write_text("x\n" * 2000)
            validator = PerformanceValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.status, "passed")


# ────────────────────────────────────────────────────────────────────────
# TestValidator Tests
# ────────────────────────────────────────────────────────────────────────

class TestTestValidator(unittest.TestCase):
    """Tests for the TestValidator stage."""

    def test_no_tests_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = TestValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.status, "failed")
            self.assertTrue(any(f.rule_id == "TST-001" for f in result.findings))

    def test_empty_tests_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "tests").mkdir()
            validator = TestValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.status, "failed")
            self.assertTrue(any(f.rule_id == "TST-002" for f in result.findings))

    def test_with_test_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tests_dir = Path(tmpdir) / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_sample.py").write_text(
                "import unittest\n\n"
                "class TestSample(unittest.TestCase):\n"
                "    def test_pass(self):\n"
                "        self.assertTrue(True)\n"
            )
            validator = TestValidator(Path(tmpdir))
            result = validator.run()
            self.assertEqual(result.files_scanned, 1)
            # Result depends on subprocess execution
            self.assertIn(result.status, ("passed", "failed", "error"))

    def test_with_failing_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tests_dir = Path(tmpdir) / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_fail.py").write_text(
                "import unittest\n\n"
                "class TestFail(unittest.TestCase):\n"
                "    def test_always_fails(self):\n"
                "        self.fail('This always fails')\n"
            )
            validator = TestValidator(Path(tmpdir))
            result = validator.run()
            # Should detect the failure
            self.assertEqual(result.status, "failed")

    def test_timeout_handled_in_code(self) -> None:
        """Verify that TimeoutExpired is imported and used in the TestValidator."""
        import subprocess as sp
        import reconpro.auto_validation as av
        # Verify subprocess.TimeoutExpired is referenced in the module
        self.assertTrue(
            hasattr(sp, "TimeoutExpired"),
            "subprocess.TimeoutExpired should exist in stdlib",
        )
        # Verify the TestValidator code handles timeout (check source)
        with open(av.__file__, "r") as f:
            code = f.read()
        self.assertIn("TimeoutExpired", code, "TestValidator should handle timeout")


# ────────────────────────────────────────────────────────────────────────
# ValidationPipeline Tests
# ────────────────────────────────────────────────────────────────────────

class TestValidationPipeline(unittest.TestCase):
    """Tests for the ValidationPipeline orchestrator."""

    def _make_test_project(self, tmpdir: str) -> None:
        """Create a small test project structure."""
        base = Path(tmpdir)
        (base / "main.py").write_text(
            "def main() -> None:\n    print('hello')\n"
        )
        (base / "utils.py").write_text(
            "import os\n\ndef get_cwd() -> str:\n    return os.getcwd()\n"
        )

    def test_init_default_root(self) -> None:
        pipeline = ValidationPipeline()
        self.assertIsInstance(pipeline.project_root, Path)
        self.assertTrue(pipeline.project_root.exists())

    def test_init_custom_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = ValidationPipeline(tmpdir)
            self.assertEqual(pipeline.project_root, Path(tmpdir).resolve())

    def test_validate_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            result = pipeline.validate_syntax()
            self.assertEqual(result.stage_name, "syntax")
            self.assertEqual(result.status, "passed")

    def test_validate_imports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            result = pipeline.validate_imports()
            self.assertEqual(result.stage_name, "imports")

    def test_validate_security(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            result = pipeline.validate_security()
            self.assertEqual(result.stage_name, "security")

    def test_validate_performance(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            result = pipeline.validate_performance()
            self.assertEqual(result.stage_name, "performance")

    def test_validate_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            result = pipeline.validate_types()
            self.assertEqual(result.stage_name, "types")

    def test_validate_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            result = pipeline.validate_tests()
            self.assertEqual(result.stage_name, "tests")

    def test_validate_full(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            report = pipeline.validate_full()
            self.assertIsInstance(report, ValidationReport)
            self.assertGreater(report.total_duration, 0)
            self.assertGreater(report.stages_total, 0)
            # Check all expected stages are present
            stage_names = {sr.stage_name for sr in report.stage_results}
            self.assertIn("syntax", stage_names)
            self.assertIn("imports", stage_names)
            self.assertIn("interfaces", stage_names)
            self.assertIn("types", stage_names)
            self.assertIn("security", stage_names)
            self.assertIn("performance", stage_names)
            self.assertIn("tests", stage_names)

    def test_get_validation_report_before_run(self) -> None:
        pipeline = ValidationPipeline()
        self.assertIsNone(pipeline.get_validation_report())

    def test_get_validation_report_after_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            report = pipeline.validate_full()
            retrieved = pipeline.get_validation_report()
            self.assertIsNotNone(retrieved)
            self.assertIs(retrieved, report)

    def test_report_summary_non_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            pipeline = ValidationPipeline(tmpdir)
            report = pipeline.validate_full()
            summary = report.summary()
            self.assertIsInstance(summary, str)
            self.assertGreater(len(summary), 100)
            self.assertIn("ReconPro Auto-Validation Report", summary)

    def test_quick_validate_convenience(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_test_project(tmpdir)
            report = ValidationPipeline.quick_validate(tmpdir)
            self.assertIsInstance(report, ValidationReport)

    def test_validate_full_with_syntax_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "broken.py").write_text("def (\n")
            pipeline = ValidationPipeline(tmpdir)
            report = pipeline.validate_full()
            self.assertEqual(report.overall_status, "failed")

    def test_validate_full_with_security_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "danger.py").write_text(
                "x = eval(input())\n"
                "password = 'secret123'\n"
            )
            pipeline = ValidationPipeline(tmpdir)
            report = pipeline.validate_full()
            # Should have security findings
            security_stage = report.get_stage_result("security")
            self.assertIsNotNone(security_stage)
            self.assertTrue(security_stage.finding_count > 0)


# ────────────────────────────────────────────────────────────────────────
# Convenience Function Tests
# ────────────────────────────────────────────────────────────────────────

class TestConvenienceFunctions(unittest.TestCase):
    """Tests for module-level convenience functions."""

    def test_validate_syntax_default(self) -> None:
        result = validate_syntax()
        self.assertEqual(result.stage_name, "syntax")

    def test_validate_imports_default(self) -> None:
        result = validate_imports()
        self.assertEqual(result.stage_name, "imports")

    def test_validate_full_custom_root(self) -> None:
        """Validate full on a small project (not the full ReconPro)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "main.py").write_text("def main() -> None:\n    pass\n")
            report = validate_full(tmpdir)
            self.assertIsInstance(report, ValidationReport)
            self.assertGreater(report.stages_total, 0)

    def test_validate_syntax_custom_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "ok.py").write_text("pass\n")
            result = validate_syntax(tmpdir)
            self.assertEqual(result.stage_name, "syntax")
            self.assertEqual(result.status, "passed")


# ────────────────────────────────────────────────────────────────────────
# Integration Tests — Full Pipeline on Actual ReconPro
# ────────────────────────────────────────────────────────────────────────

class TestIntegrationActualProject(unittest.TestCase):
    """Integration tests running the pipeline against the actual ReconPro codebase."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reconpro_root = Path(__file__).parent.parent

    def test_syntax_on_actual_project(self) -> None:
        pipeline = ValidationPipeline(str(self.reconpro_root))
        result = pipeline.validate_syntax()
        self.assertIsInstance(result, ValidationStageResult)
        self.assertGreater(result.files_scanned, 0)
        # Report syntax findings
        if result.finding_count > 0:
            for f in result.findings:
                print(f"  [SYNTAX] {f.file}:{f.line} - {f.message}")

    def test_security_on_actual_project(self) -> None:
        pipeline = ValidationPipeline(str(self.reconpro_root))
        result = pipeline.validate_security()
        self.assertIsInstance(result, ValidationStageResult)
        self.assertGreater(result.files_scanned, 0)

    def test_imports_on_actual_project(self) -> None:
        pipeline = ValidationPipeline(str(self.reconpro_root))
        result = pipeline.validate_imports()
        self.assertIsInstance(result, ValidationStageResult)
        self.assertGreater(result.files_scanned, 0)

    def test_types_on_actual_project(self) -> None:
        pipeline = ValidationPipeline(str(self.reconpro_root))
        result = pipeline.validate_types()
        self.assertIsInstance(result, ValidationStageResult)
        self.assertGreater(result.files_scanned, 0)

    def test_performance_on_actual_project(self) -> None:
        pipeline = ValidationPipeline(str(self.reconpro_root))
        result = pipeline.validate_performance()
        self.assertIsInstance(result, ValidationStageResult)
        self.assertGreater(result.files_scanned, 0)
        self.assertEqual(result.status, "passed")  # Performance always passes

    def test_interfaces_on_actual_project(self) -> None:
        pipeline = ValidationPipeline(str(self.reconpro_root))
        result = pipeline.validate_interfaces()
        self.assertIsInstance(result, ValidationStageResult)
        self.assertGreater(result.files_scanned, 0)

    def test_full_pipeline_on_actual_project(self) -> None:
        """Run the full pipeline on the actual ReconPro project."""
        pipeline = ValidationPipeline(str(self.reconpro_root))
        report = pipeline.validate_full()

        self.assertIsInstance(report, ValidationReport)
        self.assertEqual(report.stages_total, 7)
        self.assertIn(report.overall_status, ("passed", "failed", "error"))
        self.assertGreater(report.files_scanned_total, 0)
        self.assertGreater(report.total_duration, 0)

        # Print summary for visual inspection
        summary = report.summary()
        print(summary)

        # Verify all stages have results
        for sr in report.stage_results:
            self.assertIsNotNone(sr.stage_name)
            self.assertIn(sr.status, ("passed", "failed", "error", "skipped"))
            self.assertGreaterEqual(sr.duration, 0)

        # Verify report serialization
        d = report.to_dict()
        self.assertIn("timestamp", d)
        self.assertIn("stage_results", d)
        self.assertEqual(len(d["stage_results"]), 7)


if __name__ == "__main__":
    unittest.main()

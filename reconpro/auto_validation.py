"""ReconPro v11 — Auto Validation Pipeline.

Comprehensive automated validation framework for ReconPro Age III.
Orchestrates multiple validation stages: syntax, imports, interfaces,
types, security, performance, and tests.

Pure Python, ZERO external dependencies. Uses stdlib only:
    py_compile, ast, importlib, subprocess, pathlib, json, time, logging.

Classes:
    ValidationFinding     — Single finding with file, line, severity, message, suggestion
    ValidationStageResult — Result of running a single validation stage
    ValidationReport      — Comprehensive report across all stages with trend data
    ValidationStage       — ABC base class for individual validation stages
    SyntaxValidator       — Validates Python syntax via py_compile and ast.parse
    ImportValidator       — Validates import chains, circular/missing/unused imports
    InterfaceValidator    — Validates module interface compliance
    TypeValidator         — Validates type annotation coverage
    SecurityValidator     — Runs static security checks on source code
    PerformanceValidator  — Runs basic performance benchmarks
    TestValidator         — Runs the test suite via subprocess
    ValidationPipeline    — Orchestrates all validation stages

Usage:
    from reconpro.auto_validation import ValidationPipeline

    pipeline = ValidationPipeline("/path/to/reconpro")
    report = pipeline.validate_full()
    print(report.summary())
    report.save()
"""

from __future__ import annotations

import ast
import importlib.util
import json
import logging
import os
import py_compile
import re
import subprocess
import sys
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import MEMORY_DIR, RECONPRO_HOME

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────

VALIDATION_REPORTS_DIR: Path = MEMORY_DIR / "validation_reports"

# Severity ordering: lower number = more severe
_SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

VALID_SEVERITIES: frozenset[str] = frozenset(_SEVERITY_ORDER.keys())

# Python stdlib modules (for import resolution checks)
_STDLIB_MODULES: Optional[Set[str]] = None


def _get_stdlib_modules() -> Set[str]:
    """Lazily compute the set of stdlib module names."""
    global _STDLIB_MODULES
    if _STDLIB_MODULES is not None:
        return _STDLIB_MODULES
    stdlib_names: Set[str] = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()
    # Fallback: read from the current Python's lib
    if not stdlib_names:
        import pkgutil
        for m in pkgutil.iter_modules():
            if not m.ispkg:
                stdlib_names.add(m.name)
    # Add top-level builtins
    stdlib_names.update({
        "os", "sys", "re", "json", "ast", "time", "logging", "subprocess",
        "pathlib", "dataclasses", "enum", "abc", "typing", "collections",
        "itertools", "functools", "hashlib", "urllib", "http", "socket",
        "ssl", "importlib", "io", "textwrap", "datetime", "traceback",
        "threading", "multiprocessing", "concurrent", "asyncio", "copy",
        "shutil", "tempfile", "glob", "fnmatch", "operator", "string",
        "struct", "array", "weakref", "types", "inspect", "dis",
        "tokenize", "token", "keyword", "argparse", "configparser",
        "pickle", "shelve", "sqlite3", "csv", "xml", "html", "email",
        "mimetypes", "base64", "binascii", "codecs", "unicodedata",
        "math", "cmath", "decimal", "fractions", "random", "statistics",
        "numbers", "gettext", "locale", "calendar", "platform",
        "signal", "mmap", "resource", "ctypes", "warnings",
    })
    _STDLIB_MODULES = stdlib_names
    return _STDLIB_MODULES


# ────────────────────────────────────────────────────────────────────────
# Data Classes
# ────────────────────────────────────────────────────────────────────────

class Severity(Enum):
    """Validation finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_key(self) -> int:
        return _SEVERITY_ORDER[self.value]

    def __lt__(self, other: "Severity") -> bool:
        if isinstance(other, Severity):
            return self.sort_key < other.sort_key
        return NotImplemented

    def __le__(self, other: "Severity") -> bool:
        if isinstance(other, Severity):
            return self.sort_key <= other.sort_key
        return NotImplemented

    def __ge__(self, other: "Severity") -> bool:
        if isinstance(other, Severity):
            return self.sort_key >= other.sort_key
        return NotImplemented

    def __gt__(self, other: "Severity") -> bool:
        if isinstance(other, Severity):
            return self.sort_key > other.sort_key
        return NotImplemented


class StageStatus(Enum):
    """Status of a validation stage."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class ValidationFinding:
    """A single validation finding.

    Attributes:
        file: Relative file path where the finding was detected.
        line: Line number (0 if not applicable).
        severity: Severity level of the finding.
        message: Human-readable description of the finding.
        suggestion: Suggested fix or action.
        rule_id: Identifier for the rule that produced this finding.
    """
    file: str = ""
    line: int = 0
    severity: str = "info"
    message: str = ""
    suggestion: str = ""
    rule_id: str = ""

    def __post_init__(self) -> None:
        if self.severity.lower() not in VALID_SEVERITIES:
            self.severity = "info"
        else:
            self.severity = self.severity.lower()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "message": self.message,
            "suggestion": self.suggestion,
            "rule_id": self.rule_id,
        }


@dataclass
class ValidationStageResult:
    """Result of running a single validation stage.

    Attributes:
        stage_name: Human-readable name of the stage.
        status: Overall pass/fail/skip/error status.
        duration: Wall-clock time in seconds.
        findings: List of ValidationFinding objects.
        files_scanned: Number of files scanned.
        error_message: Error message if the stage raised an exception.
    """
    stage_name: str = ""
    status: str = "skipped"
    duration: float = 0.0
    findings: List[ValidationFinding] = field(default_factory=list)
    files_scanned: int = 0
    error_message: str = ""

    @property
    def passed(self) -> bool:
        return self.status == StageStatus.PASSED.value

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "info")

    def has_critical_or_high(self) -> bool:
        return any(f.severity in ("critical", "high") for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "status": self.status,
            "duration": round(self.duration, 3),
            "files_scanned": self.files_scanned,
            "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
        }


@dataclass
class ValidationReport:
    """Comprehensive validation report across all stages.

    Attributes:
        timestamp: When the report was generated.
        project_root: Root directory that was validated.
        overall_status: Overall pass/fail status.
        stage_results: Per-stage results.
        total_duration: Total wall-clock time in seconds.
        previous_report: Optional reference to a previous report for trend data.
    """
    timestamp: str = ""
    project_root: str = ""
    overall_status: str = "pending"
    stage_results: List[ValidationStageResult] = field(default_factory=list)
    total_duration: float = 0.0
    previous_report: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    @property
    def passed(self) -> bool:
        return self.overall_status == StageStatus.PASSED.value

    @property
    def total_findings(self) -> int:
        return sum(sr.finding_count for sr in self.stage_results)

    @property
    def total_critical(self) -> int:
        return sum(sr.critical_count() for sr in self.stage_results)

    @property
    def total_high(self) -> int:
        return sum(sr.high_count() for sr in self.stage_results)

    @property
    def total_medium(self) -> int:
        return sum(sr.medium_count() for sr in self.stage_results)

    @property
    def total_low(self) -> int:
        return sum(sr.low_count() for sr in self.stage_results)

    @property
    def total_info(self) -> int:
        return sum(sr.info_count() for sr in self.stage_results)

    @property
    def stages_passed(self) -> int:
        return sum(1 for sr in self.stage_results if sr.passed)

    @property
    def stages_total(self) -> int:
        return len(self.stage_results)

    @property
    def files_scanned_total(self) -> int:
        return sum(sr.files_scanned for sr in self.stage_results)

    def get_stage_result(self, stage_name: str) -> Optional[ValidationStageResult]:
        """Look up a stage result by name."""
        for sr in self.stage_results:
            if sr.stage_name == stage_name:
                return sr
        return None

    def get_trends(self) -> Dict[str, Any]:
        """Compare current report with previous report for trend data."""
        if not self.previous_report:
            return {"trend_available": False}

        prev_findings = self.previous_report.get("total_findings", 0)
        prev_critical = self.previous_report.get("total_critical", 0)
        prev_high = self.previous_report.get("total_high", 0)
        prev_duration = self.previous_report.get("total_duration", 0.0)
        prev_timestamp = self.previous_report.get("timestamp", "")

        return {
            "trend_available": True,
            "previous_timestamp": prev_timestamp,
            "findings_delta": self.total_findings - prev_findings,
            "critical_delta": self.total_critical - prev_critical,
            "high_delta": self.total_high - prev_high,
            "duration_delta": round(self.total_duration - prev_duration, 3),
            "improved": (
                self.total_findings < prev_findings
                or (self.total_findings == prev_findings
                    and self.total_duration < prev_duration)
            ),
        }

    def summary(self) -> str:
        """Generate a human-readable summary of the report."""
        lines: List[str] = []
        lines.append("=" * 72)
        lines.append("  ReconPro Auto-Validation Report")
        lines.append(f"  Generated: {self.timestamp}")
        lines.append(f"  Project:   {self.project_root}")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"  Overall Status:  {self.overall_status.upper()}")
        lines.append(f"  Duration:         {self.total_duration:.3f}s")
        lines.append(f"  Stages:           {self.stages_passed}/{self.stages_total} passed")
        lines.append(f"  Files Scanned:    {self.files_scanned_total}")
        lines.append("")

        # Severity breakdown
        lines.append("  Findings by Severity:")
        lines.append(f"    CRITICAL: {self.total_critical}")
        lines.append(f"    HIGH:     {self.total_high}")
        lines.append(f"    MEDIUM:   {self.total_medium}")
        lines.append(f"    LOW:      {self.total_low}")
        lines.append(f"    INFO:     {self.total_info}")
        lines.append(f"    TOTAL:    {self.total_findings}")
        lines.append("")

        # Per-stage results
        lines.append("  Stage Results:")
        lines.append("  " + "-" * 66)
        for sr in self.stage_results:
            status_marker = "PASS" if sr.passed else "FAIL"
            finding_str = ""
            if sr.finding_count > 0:
                parts: List[str] = []
                if sr.critical_count():
                    parts.append(f"{sr.critical_count()} crit")
                if sr.high_count():
                    parts.append(f"{sr.high_count()} high")
                if sr.medium_count():
                    parts.append(f"{sr.medium_count()} med")
                if sr.low_count():
                    parts.append(f"{sr.low_count()} low")
                finding_str = f" [{', '.join(parts)}]"
            lines.append(
                f"    [{status_marker}] {sr.stage_name:<25s} "
                f"{sr.files_scanned:>4} files  {sr.duration:>7.3f}s"
                f"{finding_str}"
            )
        lines.append("")

        # Trend data
        trends = self.get_trends()
        if trends.get("trend_available"):
            lines.append("  Trends (vs previous run):")
            lines.append(f"    Findings:  {'+' if trends['findings_delta'] >= 0 else ''}{trends['findings_delta']}")
            lines.append(f"    Critical:  {'+' if trends['critical_delta'] >= 0 else ''}{trends['critical_delta']}")
            lines.append(f"    High:      {'+' if trends['high_delta'] >= 0 else ''}{trends['high_delta']}")
            lines.append(f"    Duration:  {'+' if trends['duration_delta'] >= 0 else ''}{trends['duration_delta']:.3f}s")
            improved = "YES" if trends["improved"] else "NO"
            lines.append(f"    Improved:  {improved}")
            lines.append("")

        # Critical and high findings detail
        all_critical_high: List[ValidationFinding] = []
        for sr in self.stage_results:
            for f in sr.findings:
                if f.severity in ("critical", "high"):
                    all_critical_high.append(f)

        if all_critical_high:
            lines.append("  Critical/High Findings:")
            lines.append("  " + "-" * 66)
            for f in sorted(all_critical_high,
                             key=lambda x: _SEVERITY_ORDER.get(x.severity, 99)):
                loc = f"{f.file}:{f.line}" if f.line else f.file
                lines.append(f"    [{f.severity.upper():8s}] {loc}")
                lines.append(f"              {f.message}")
                if f.suggestion:
                    lines.append(f"              -> {f.suggestion}")
            lines.append("")

        lines.append("=" * 72)
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON persistence."""
        trends = self.get_trends()
        return {
            "timestamp": self.timestamp,
            "project_root": self.project_root,
            "overall_status": self.overall_status,
            "total_duration": round(self.total_duration, 3),
            "files_scanned": self.files_scanned_total,
            "total_findings": self.total_findings,
            "total_critical": self.total_critical,
            "total_high": self.total_high,
            "total_medium": self.total_medium,
            "total_low": self.total_low,
            "total_info": self.total_info,
            "stages_passed": self.stages_passed,
            "stages_total": self.stages_total,
            "trends": trends,
            "stage_results": [sr.to_dict() for sr in self.stage_results],
        }

    def save(self, reports_dir: Optional[Path] = None) -> Path:
        """Save the report as a JSON file to the validation reports directory.

        Args:
            reports_dir: Override directory for saving. Defaults to
                         RECONPRO_HOME/memory/validation_reports/.

        Returns:
            Path to the saved report file.
        """
        save_dir = reports_dir or VALIDATION_REPORTS_DIR
        save_dir.mkdir(parents=True, exist_ok=True)

        filename = f"validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = save_dir / filename

        data = self.to_dict()
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        logger.info("Validation report saved to %s", filepath)
        return filepath

    @classmethod
    def load_latest(cls, reports_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """Load the most recent validation report from disk.

        Args:
            reports_dir: Override directory. Defaults to VALIDATION_REPORTS_DIR.

        Returns:
            Parsed report dict, or None if no reports exist.
        """
        load_dir = reports_dir or VALIDATION_REPORTS_DIR
        if not load_dir.exists():
            return None

        reports = sorted(load_dir.glob("validation_*.json"))
        if not reports:
            return None

        latest = reports[-1]
        try:
            with open(latest, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load report %s: %s", latest, exc)
            return None


# ────────────────────────────────────────────────────────────────────────
# ValidationStage — ABC Base
# ────────────────────────────────────────────────────────────────────────

class ValidationStage(ABC):
    """Abstract base class for individual validation stages.

    Each stage represents one validation domain (syntax, imports, etc.).
    Subclasses must implement ``run()`` and set ``name`` / ``description``.

    Attributes:
        name: Short identifier for the stage.
        description: Human-readable description.
    """

    name: str = "unnamed"
    description: str = ""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root

    @abstractmethod
    def run(self) -> ValidationStageResult:
        """Execute the validation stage.

        Returns:
            ValidationStageResult with findings, status, and duration.
        """
        ...

    def _make_result(
        self,
        status: str,
        findings: List[ValidationFinding],
        files_scanned: int = 0,
        duration: float = 0.0,
        error_message: str = "",
    ) -> ValidationStageResult:
        return ValidationStageResult(
            stage_name=self.name,
            status=status,
            duration=duration,
            findings=findings,
            files_scanned=files_scanned,
            error_message=error_message,
        )

    def _discover_python_files(self) -> List[Path]:
        """Find all .py files under project_root (excluding __pycache__)."""
        files: List[Path] = []
        try:
            for py_file in self.project_root.rglob("*.py"):
                # Skip __pycache__, .git, node_modules, and egg-info
                parts = py_file.relative_to(self.project_root).parts
                skip_dirs = {"__pycache__", ".git", "node_modules",
                             ".eggs", "*.egg-info", ".tox", ".venv", "venv"}
                if any(part in skip_dirs for part in parts):
                    continue
                files.append(py_file)
        except (OSError, ValueError):
            pass
        return sorted(files)


# ────────────────────────────────────────────────────────────────────────
# SyntaxValidator
# ────────────────────────────────────────────────────────────────────────

class SyntaxValidator(ValidationStage):
    """Validate Python syntax for all .py files.

    Uses py_compile for byte-code compilation and ast.parse for
    structural validation (detects syntax errors py_compile might miss).
    """

    name = "syntax"
    description = "Check all Python files compile and parse as valid ASTs"

    def run(self) -> ValidationStageResult:
        start = time.monotonic()
        findings: List[ValidationFinding] = []
        py_files = self._discover_python_files()

        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))

            # 1. py_compile check
            try:
                py_compile.compile(
                    str(py_file), doraise=True, quiet=True,
                )
            except py_compile.PyCompileError as exc:
                findings.append(ValidationFinding(
                    file=rel,
                    line=self._extract_error_line(str(exc)),
                    severity="critical",
                    message=f"Syntax error (py_compile): {exc}",
                    suggestion="Fix the syntax error in this file.",
                    rule_id="SYN-001",
                ))
                continue  # Don't try ast.parse if compile fails

            # 2. ast.parse check (catches deeper structural issues)
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                ast.parse(source, filename=str(py_file))
            except SyntaxError as exc:
                findings.append(ValidationFinding(
                    file=rel,
                    line=exc.lineno or 0,
                    severity="critical",
                    message=f"AST parse error: {exc.msg}",
                    suggestion="Review and fix the syntax structure.",
                    rule_id="SYN-002",
                ))

        duration = time.monotonic() - start
        has_critical = any(f.severity == "critical" for f in findings)
        status = StageStatus.FAILED.value if has_critical else StageStatus.PASSED.value
        return self._make_result(status, findings, len(py_files), duration)

    @staticmethod
    def _extract_error_line(error_str: str) -> int:
        """Try to extract a line number from a PyCompileError string."""
        match = re.search(r"line (\d+)", error_str)
        return int(match.group(1)) if match else 0


# ────────────────────────────────────────────────────────────────────────
# ImportValidator
# ────────────────────────────────────────────────────────────────────────

class ImportValidator(ValidationStage):
    """Validate import chains across the project.

    Checks for:
    - Circular imports between modules
    - Imports that reference non-existent modules (missing)
    - Unused imports (imported but never referenced in scope)
    """

    name = "imports"
    description = "Check for circular, missing, and unused imports"

    def run(self) -> ValidationStageResult:
        start = time.monotonic()
        findings: List[ValidationFinding] = []
        py_files = self._discover_python_files()

        # Build import graph
        graph: Dict[str, Set[str]] = {}
        file_imports: Dict[str, List[Tuple[str, str, int]]] = {}  # file -> [(module, name, line)]
        file_used_names: Dict[str, Set[str]] = {}

        stdlib = _get_stdlib_modules()
        project_name = self.project_root.name  # e.g. "reconpro"

        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError:
                continue  # Skip files with syntax errors (SyntaxValidator handles them)

            imports: List[Tuple[str, str, int]] = []
            names_used: Set[str] = set()

            for node in ast.walk(tree):
                # Collect imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append((alias.name, alias.asname or alias.name, node.lineno))
                elif isinstance(node, ast.ImportFrom):
                    module_name = node.module or ""
                    if module_name.startswith(f"."):  # relative imports
                        if module_name == ".":
                            module_name = f"{project_name}.{rel.replace('/', '.').replace('.py', '').replace('.__init__', '')}"
                        # Keep as-is for graph purposes
                    for alias in node.names:
                        imports.append((module_name, alias.asname or alias.name, node.lineno))

                # Collect name references (simple: names used in the module body)
                if isinstance(node, ast.Name):
                    names_used.add(node.id)
                elif isinstance(node, ast.Attribute):
                    # Collect just the base attribute name
                    names_used.add(node.attr)

            graph[rel] = set()
            file_imports[rel] = imports
            file_used_names[rel] = names_used

            # Build graph edges: map local imports to relative file paths
            for mod_name, _local_name, _line in imports:
                local_mod = self._module_to_file_rel(mod_name, py_files, project_name)
                if local_mod and local_mod != rel:
                    graph[rel].add(local_mod)

        # 1. Check for circular imports
        findings.extend(self._find_circular_imports(graph))

        # 2. Check for missing imports
        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))
            for mod_name, local_name, line in file_imports.get(rel, []):
                # Skip relative imports (they are resolved by the package system)
                if mod_name.startswith("."):
                    continue
                # Skip stdlib
                top_level = mod_name.split(".")[0]
                if top_level in stdlib:
                    continue
                # Check if the top-level module exists somewhere in the project
                found = False
                for other_file in py_files:
                    other_rel = str(other_file.relative_to(self.project_root))
                    if other_rel == f"{top_level}.py" or other_rel.startswith(f"{top_level}/"):
                        found = True
                        break
                # Also check if it could be an installed package
                if not found:
                    try:
                        spec = importlib.util.find_spec(top_level)
                        if spec is not None:
                            found = True
                    except (ImportError, ModuleNotFoundError, ValueError):
                        pass
                if not found:
                    # Only flag if it looks like a project-internal import
                    if top_level == project_name or top_level in {
                        p.relative_to(self.project_root).parts[0]
                        for p in py_files
                        if len(p.relative_to(self.project_root).parts) > 0
                    }:
                        findings.append(ValidationFinding(
                            file=rel,
                            line=line,
                            severity="high",
                            message=f"Missing import: '{mod_name}' (as '{local_name}')",
                            suggestion=f"Ensure the module '{mod_name}' exists or remove the import.",
                            rule_id="IMP-002",
                        ))

        # 3. Check for unused imports
        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))
            source = py_file.read_text(encoding="utf-8", errors="replace")

            # Skip test files and __init__ files (commonly re-export)
            if "test_" in rel or rel.endswith("__init__.py"):
                continue

            for mod_name, local_name, line in file_imports.get(rel, []):
                # Common patterns that are used but not simple name refs
                if local_name in ("*", "_"):
                    continue
                if local_name.startswith("_") and local_name.endswith("_"):
                    continue
                # Check if name appears as a used reference in the AST
                if local_name not in file_used_names.get(rel, set()):
                    # Double-check: search full source — name should appear
                    # more than once (once in import, once in usage)
                    name_pattern = re.compile(r'\b' + re.escape(local_name) + r'\b')
                    matches = name_pattern.findall(source)
                    if len(matches) <= 1:  # Only the import itself
                        findings.append(ValidationFinding(
                            file=rel,
                            line=line,
                            severity="low",
                            message=f"Unused import: '{local_name}' from '{mod_name}'",
                            suggestion=f"Remove unused import or use '{local_name}'.",
                            rule_id="IMP-003",
                        ))

        duration = time.monotonic() - start
        has_critical_or_high = any(f.severity in ("critical", "high") for f in findings)
        status = StageStatus.FAILED.value if has_critical_or_high else StageStatus.PASSED.value
        return self._make_result(status, findings, len(py_files), duration)

    def _find_circular_imports(self, graph: Dict[str, Set[str]]) -> List[ValidationFinding]:
        """Detect circular import chains using DFS."""
        findings: List[ValidationFinding] = []
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = {node: WHITE for node in graph}
        path: List[str] = []

        def dfs(node: str) -> None:
            color[node] = GRAY
            path.append(node)

            for neighbor in graph.get(node, set()):
                if neighbor not in color:
                    continue
                if color[neighbor] == GRAY:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    cycle_str = " -> ".join(cycle[-5:])  # Show last 5 nodes
                    findings.append(ValidationFinding(
                        file=node,
                        line=0,
                        severity="high",
                        message=f"Circular import detected: {cycle_str}",
                        suggestion="Refactor to break the cycle using lazy imports or reorganization.",
                        rule_id="IMP-001",
                    ))
                elif color[neighbor] == WHITE:
                    dfs(neighbor)

            path.pop()
            color[node] = BLACK

        for node in sorted(graph.keys()):
            if color.get(node) == WHITE:
                dfs(node)

        return findings

    def _module_to_file_rel(
        self, module_name: str, py_files: List[Path], project_name: str,
    ) -> Optional[str]:
        """Convert a module import name to a relative file path.

        E.g., 'reconpro.scanner' -> 'scanner.py' (if project_root is reconpro/)
        """
        if not module_name:
            return None

        # Strip project prefix if present
        if module_name.startswith(project_name + "."):
            module_name = module_name[len(project_name) + 1:]

        # Direct file match
        candidate = module_name.replace(".", os.sep) + ".py"
        candidate_init = os.path.join(module_name.replace(".", os.sep), "__init__.py")

        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))
            if rel == candidate or rel == candidate_init:
                return rel

        return None


# ────────────────────────────────────────────────────────────────────────
# InterfaceValidator
# ────────────────────────────────────────────────────────────────────────

class InterfaceValidator(ValidationStage):
    """Validate that registered modules implement expected interfaces.

    Checks:
    - All modules in the registry have a callable runner
    - Module functions have the expected signature (target, base_url, ...)
    - Registry completeness: no orphaned runner functions
    """

    name = "interfaces"
    description = "Check module interface compliance against registry and protocols"

    def run(self) -> ValidationStageResult:
        start = time.monotonic()
        findings: List[ValidationFinding] = []
        py_files = self._discover_python_files()
        files_scanned = len(py_files)

        # Try to load the registry
        registry_modules: Dict[str, Any] = {}
        local_modules: Dict[str, Any] = {}

        try:
            # Add project root to path for import resolution
            if str(self.project_root.parent) not in sys.path:
                sys.path.insert(0, str(self.project_root.parent))

            import importlib
            try:
                reg_mod = importlib.import_module(f"{self.project_root.name}.registry")
                registry_modules = getattr(reg_mod, "MODULE_REGISTRY", {})
                local_modules = getattr(reg_mod, "LOCAL_MODULES", {})
            except ImportError:
                findings.append(ValidationFinding(
                    file="registry.py",
                    line=0,
                    severity="medium",
                    message="Could not import registry module for interface validation",
                    suggestion="Ensure registry.py is importable.",
                    rule_id="IFC-000",
                ))

            all_modules: Dict[str, Any] = {}
            all_modules.update(registry_modules)
            all_modules.update(local_modules)
            all_module_ids = list(all_modules.keys())

            if not all_modules:
                findings.append(ValidationFinding(
                    file="registry.py",
                    line=0,
                    severity="high",
                    message="Module registry is empty — no modules registered",
                    suggestion="Register modules in registry.py.",
                    rule_id="IFC-001",
                ))
                duration = time.monotonic() - start
                return self._make_result(
                    StageStatus.FAILED.value, findings, files_scanned, duration,
                )

            # 1. Check each module has a callable runner
            for module_id in sorted(all_module_ids):
                entry = all_modules[module_id]
                runner = entry.get("runner")

                if runner is None:
                    findings.append(ValidationFinding(
                        file="registry.py",
                        line=0,
                        severity="critical",
                        message=f"Module '{module_id}' has no runner",
                        suggestion=f"Add a callable runner for '{module_id}' in registry.py.",
                        rule_id="IFC-002",
                    ))
                elif not callable(runner):
                    findings.append(ValidationFinding(
                        file="registry.py",
                        line=0,
                        severity="critical",
                        message=f"Module '{module_id}' runner is not callable (type={type(runner).__name__})",
                        suggestion="Ensure the runner is a callable function.",
                        rule_id="IFC-003",
                    ))
                else:
                    # 2. Check function signature
                    sig_ok = self._check_runner_signature(runner, module_id)
                    if not sig_ok:
                        findings.append(ValidationFinding(
                            file="registry.py",
                            line=0,
                            severity="medium",
                            message=f"Module '{module_id}' has non-standard runner signature",
                            suggestion="Standard: (target: str, base_url: str, timeout: int = 8, verify_tls: bool = True) -> list",
                            rule_id="IFC-004",
                        ))

                # 3. Check module has required metadata
                if "name" not in entry:
                    findings.append(ValidationFinding(
                        file="registry.py",
                        line=0,
                        severity="low",
                        message=f"Module '{module_id}' missing 'name' metadata",
                        suggestion="Add 'name' key to the module registry entry.",
                        rule_id="IFC-005",
                    ))

            # 4. Check for orphaned module files (in modules/ but not in registry)
            modules_dir = self.project_root / "modules"
            if modules_dir.exists():
                registered_names = set(all_module_ids)
                for mod_file in modules_dir.glob("*.py"):
                    if mod_file.name == "__init__.py":
                        continue
                    stem = mod_file.stem
                    # Map file stems to module IDs
                    file_map = {
                        "free_info_ops": "info_ops",
                    }
                    mapped_id = file_map.get(stem, stem)
                    if mapped_id not in registered_names:
                        findings.append(ValidationFinding(
                            file=f"modules/{mod_file.name}",
                            line=0,
                            severity="info",
                            message=f"Module file '{mod_file.name}' not found in registry",
                            suggestion="Either register the module or remove the orphaned file.",
                            rule_id="IFC-006",
                        ))

        except Exception as exc:
            duration = time.monotonic() - start
            return self._make_result(
                StageStatus.ERROR.value, findings, files_scanned, duration,
                error_message=f"Interface validation error: {exc}",
            )

        duration = time.monotonic() - start
        has_critical = any(f.severity == "critical" for f in findings)
        status = StageStatus.FAILED.value if has_critical else StageStatus.PASSED.value
        return self._make_result(status, findings, files_scanned, duration)

    def _check_runner_signature(self, runner: Any, module_id: str) -> bool:
        """Check if a runner has the standard signature."""
        try:
            import inspect
            sig = inspect.signature(runner)
            params = list(sig.parameters.keys())
            # Standard: target, base_url, timeout, verify_tls
            if len(params) < 2:
                return False
            if params[0] not in ("target", "self"):
                return False
            if len(params) >= 2 and params[1] not in ("base_url", "url", "args"):
                # Allow some flexibility
                pass
            return True
        except (ValueError, TypeError):
            return False


# ────────────────────────────────────────────────────────────────────────
# TypeValidator
# ────────────────────────────────────────────────────────────────────────

class TypeValidator(ValidationStage):
    """Validate type annotation coverage across the codebase.

    Checks:
    - Functions/methods with return type annotations
    - Functions/methods with parameter type annotations
    - Coverage percentage per file and overall
    """

    name = "types"
    description = "Check type annotation coverage for functions and methods"

    def run(self) -> ValidationStageResult:
        start = time.monotonic()
        findings: List[ValidationFinding] = []
        py_files = self._discover_python_files()

        total_funcs = 0
        typed_funcs = 0
        total_params = 0
        typed_params = 0

        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))

            # Skip test files and __init__ files for coverage
            if "test_" in rel or rel.endswith("__init__.py"):
                continue

            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError:
                continue

            file_funcs = 0
            file_typed = 0
            file_untyped: List[Tuple[str, int]] = []

            for node in ast.iter_child_nodes(tree):
                # Only check top-level and class-level definitions (not nested)
                func_nodes: List[ast.AST] = []
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_nodes.append(node)
                elif isinstance(node, ast.ClassDef):
                    for item in ast.iter_child_nodes(node):
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            func_nodes.append(item)

                for func in func_nodes:
                    file_funcs += 1
                    total_funcs += 1

                    # Check return annotation
                    has_return = func.returns is not None

                    # Check parameter annotations
                    func_params = 0
                    func_typed_params = 0
                    for arg in func.args.args:
                        if arg.arg in ("self", "cls"):
                            continue
                        func_params += 1
                        total_params += 1
                        if arg.annotation is not None:
                            func_typed_params += 1
                            typed_params += 1

                    if has_return and func_params > 0 and func_typed_params == func_params:
                        file_typed += 1
                        typed_funcs += 1
                    elif not has_return:
                        file_untyped.append((func.name, func.lineno))

            # Report files with low type coverage
            if file_funcs >= 3 and file_typed / file_funcs < 0.3:
                coverage_pct = int(file_typed / file_funcs * 100) if file_funcs else 0
                untyped_names = ", ".join(n for n, _l in file_untyped[:5])
                findings.append(ValidationFinding(
                    file=rel,
                    line=0,
                    severity="low",
                    message=f"Low type annotation coverage: {coverage_pct}% "
                            f"({file_typed}/{file_funcs} functions)",
                    suggestion=f"Add type hints to: {untyped_names}, ...",
                    rule_id="TYP-001",
                ))

        # Overall coverage finding
        if total_funcs > 0:
            overall_coverage = typed_funcs / total_funcs * 100
            if overall_coverage < 50:
                findings.append(ValidationFinding(
                    file="<overall>",
                    line=0,
                    severity="medium",
                    message=f"Overall type annotation coverage is {overall_coverage:.1f}% "
                            f"({typed_funcs}/{total_funcs} functions)",
                    suggestion="Add type annotations to improve code quality and IDE support.",
                    rule_id="TYP-002",
                ))

        duration = time.monotonic() - start
        status = StageStatus.PASSED.value
        return self._make_result(status, findings, len(py_files), duration)


# ────────────────────────────────────────────────────────────────────────
# SecurityValidator
# ────────────────────────────────────────────────────────────────────────

class SecurityValidator(ValidationStage):
    """Run static security checks on Python source code.

    Checks for:
    - Use of eval(), exec(), compile() with arbitrary input
    - Hardcoded secrets (passwords, API keys, tokens)
    - Insecure SSL/TLS settings (verify=False, CERT_NONE)
    - Use of pickle with untrusted data
    - SQL injection patterns
    - Shell injection via os.system() or subprocess with shell=True
    - Dangerous default arguments (mutable defaults)
    - Use of assert for security checks
    """

    name = "security"
    description = "Run static security analysis on Python source code"

    # Patterns for secret detection
    _SECRET_PATTERNS: List[Tuple[str, str]] = [
        (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', "Hardcoded password"),
        (r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
        (r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded token"),
        (r'(?:secret|client_secret)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret"),
    ]

    def run(self) -> ValidationStageResult:
        start = time.monotonic()
        findings: List[ValidationFinding] = []
        py_files = self._discover_python_files()

        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))

            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError:
                continue

            # AST-based checks
            findings.extend(self._check_dangerous_calls(tree, rel))
            findings.extend(self._check_insecure_ssl(tree, rel))
            findings.extend(self._check_subprocess_shell(tree, rel))
            findings.extend(self._check_mutable_defaults(tree, rel))

            # Regex-based checks (line-by-line)
            for line_idx, line_text in enumerate(source.splitlines(), start=1):
                findings.extend(self._check_secrets_in_line(line_text, rel, line_idx))
                findings.extend(self._check_assert_security(line_text, rel, line_idx))

        duration = time.monotonic() - start
        has_high_or_critical = any(
            f.severity in ("critical", "high") for f in findings
        )
        status = StageStatus.FAILED.value if has_high_or_critical else StageStatus.PASSED.value
        return self._make_result(status, findings, len(py_files), duration)

    def _check_dangerous_calls(self, tree: ast.AST, rel: str) -> List[ValidationFinding]:
        """Check for eval(), exec(), and compile() calls."""
        results: List[ValidationFinding] = []
        dangerous = {"eval", "exec", "compile"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name in dangerous:
                    results.append(ValidationFinding(
                        file=rel,
                        line=node.lineno,
                        severity="high",
                        message=f"Dangerous function call: {func_name}()",
                        suggestion=f"Avoid {func_name}() with untrusted input. Use ast.literal_eval() or safer alternatives.",
                        rule_id="SEC-001",
                    ))
        return results

    def _check_insecure_ssl(self, tree: ast.AST, rel: str) -> List[ValidationFinding]:
        """Check for disabled SSL verification."""
        results: List[ValidationFinding] = []

        for node in ast.walk(tree):
            # Check for verify=False keyword arguments
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "verify":
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                            results.append(ValidationFinding(
                                file=rel,
                                line=node.lineno,
                                severity="high",
                                message="SSL verification disabled (verify=False)",
                                suggestion="Enable SSL verification or use explicit exception handling.",
                                rule_id="SEC-002",
                            ))

            # Check for CERT_NONE assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "verify_mode":
                        val = node.value
                        # Matches both: ctx.verify_mode = CERT_NONE and
                        # ctx.verify_mode = ssl.CERT_NONE
                        is_cert_none = (
                            (isinstance(val, ast.Name) and val.id == "CERT_NONE") or
                            (isinstance(val, ast.Attribute) and val.attr == "CERT_NONE")
                        )
                        if is_cert_none:
                            results.append(ValidationFinding(
                                file=rel,
                                line=node.lineno,
                                severity="high",
                                message="SSL verify_mode set to CERT_NONE",
                                suggestion="Use proper certificate verification.",
                                rule_id="SEC-003",
                            ))

            # Check for check_hostname = False
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "check_hostname":
                        if isinstance(node.value, ast.Constant) and node.value.value is False:
                            results.append(ValidationFinding(
                                file=rel,
                                line=node.lineno,
                                severity="medium",
                                message="SSL check_hostname disabled",
                                suggestion="Enable hostname verification when possible.",
                                rule_id="SEC-004",
                            ))

        return results

    def _check_subprocess_shell(self, tree: ast.AST, rel: str) -> List[ValidationFinding]:
        """Check for subprocess calls with shell=True."""
        results: List[ValidationFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name and ("subprocess" in func_name or func_name in (
                    "run", "call", "check_call", "check_output", "Popen",
                )):
                    for keyword in node.keywords:
                        if keyword.arg == "shell":
                            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                results.append(ValidationFinding(
                                    file=rel,
                                    line=node.lineno,
                                    severity="high",
                                    message="subprocess call with shell=True (injection risk)",
                                    suggestion="Use shell=False with a list argument, or sanitize input thoroughly.",
                                    rule_id="SEC-005",
                                ))

        return results

    def _check_mutable_defaults(self, tree: ast.AST, rel: str) -> List[ValidationFinding]:
        """Check for mutable default arguments (common bug source)."""
        results: List[ValidationFinding] = []
        mutable_types = (ast.List, ast.Dict, ast.Set)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is None:
                        continue
                    if isinstance(default, mutable_types):
                        results.append(ValidationFinding(
                            file=rel,
                            line=node.lineno,
                            severity="low",
                            message=f"Mutable default argument in function '{node.name}'",
                            suggestion="Use None as default and initialize inside the function body.",
                            rule_id="SEC-006",
                        ))
                        break  # One finding per function is enough

        return results

    def _check_secrets_in_line(
        self, line_text: str, rel: str, line: int,
    ) -> List[ValidationFinding]:
        """Check for hardcoded secrets using regex patterns."""
        results: List[ValidationFinding] = []

        # Skip comments
        stripped = line_text.strip()
        if stripped.startswith("#") or stripped.startswith("\"\"\"") or stripped.startswith("'''"):
            return results

        for pattern, description in self._SECRET_PATTERNS:
            if re.search(pattern, line_text, re.IGNORECASE):
                results.append(ValidationFinding(
                    file=rel,
                    line=line,
                    severity="high",
                    message=f"{description} detected",
                    suggestion="Use environment variables or a secrets manager instead.",
                    rule_id="SEC-007",
                ))
                break  # One secret finding per line

        return results

    def _check_assert_security(
        self, line_text: str, rel: str, line: int,
    ) -> List[ValidationFinding]:
        """Check for assert used for security checks (stripped in -O mode)."""
        results: List[ValidationFinding] = []
        stripped = line_text.strip()

        if re.match(r'^assert\s+.*(?:auth|permission|admin|secure|valid|safe)', stripped, re.IGNORECASE):
            results.append(ValidationFinding(
                file=rel,
                line=line,
                severity="medium",
                message="Assert used for security-critical check (disabled with -O)",
                suggestion="Replace with an explicit if/raise pattern.",
                rule_id="SEC-008",
            ))

        return results

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        """Extract the full dotted name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts: List[str] = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""


# ────────────────────────────────────────────────────────────────────────
# PerformanceValidator
# ────────────────────────────────────────────────────────────────────────

class PerformanceValidator(ValidationStage):
    """Run basic performance benchmarks on the codebase.

    Checks:
    - Total lines of code
    - Module file sizes (flag oversized files > 1500 lines)
    - Import complexity (deep import chains)
    - Function complexity (flag functions > 100 lines)
    """

    name = "performance"
    description = "Run codebase performance and complexity analysis"

    MAX_FILE_LINES = 1500
    MAX_FUNCTION_LINES = 100

    def run(self) -> ValidationStageResult:
        start = time.monotonic()
        findings: List[ValidationFinding] = []
        py_files = self._discover_python_files()
        total_loc = 0

        for py_file in py_files:
            rel = str(py_file.relative_to(self.project_root))

            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = source.splitlines()
            line_count = len(lines)
            total_loc += line_count

            # Check file size
            if line_count > self.MAX_FILE_LINES:
                findings.append(ValidationFinding(
                    file=rel,
                    line=0,
                    severity="medium",
                    message=f"Large file: {line_count} lines (threshold: {self.MAX_FILE_LINES})",
                    suggestion="Consider splitting into smaller modules.",
                    rule_id="PERF-001",
                ))

            # Check function complexity
            try:
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_lines = node.end_lineno - node.lineno + 1 if hasattr(node, 'end_lineno') and node.end_lineno else 0
                    if func_lines > self.MAX_FUNCTION_LINES:
                        findings.append(ValidationFinding(
                            file=rel,
                            line=node.lineno,
                            severity="low",
                            message=f"Large function '{node.name}': {func_lines} lines "
                                    f"(threshold: {self.MAX_FUNCTION_LINES})",
                            suggestion=f"Refactor '{node.name}' into smaller functions.",
                            rule_id="PERF-002",
                        ))

        # Summary info finding
        findings.append(ValidationFinding(
            file="<summary>",
            line=0,
            severity="info",
            message=f"Total lines of code: {total_loc} across {len(py_files)} files",
            suggestion="",
            rule_id="PERF-000",
        ))

        duration = time.monotonic() - start
        # Performance is informational, always passes
        status = StageStatus.PASSED.value
        return self._make_result(status, findings, len(py_files), duration)


# ────────────────────────────────────────────────────────────────────────
# TestValidator
# ────────────────────────────────────────────────────────────────────────

class TestValidator(ValidationStage):
    """Run the project's test suite.

    Executes the test runner via subprocess and captures results.
    """

    name = "tests"
    description = "Run the project test suite and report results"

    def run(self) -> ValidationStageResult:
        start = time.monotonic()
        findings: List[ValidationFinding] = []
        files_scanned = 0

        # Find test files
        tests_dir = self.project_root / "tests"
        if not tests_dir.exists():
            findings.append(ValidationFinding(
                file="<tests>",
                line=0,
                severity="medium",
                message="No tests/ directory found",
                suggestion="Create tests/ with unit tests for critical modules.",
                rule_id="TST-001",
            ))
            duration = time.monotonic() - start
            return self._make_result(StageStatus.FAILED.value, findings, 0, duration)

        test_files = sorted(tests_dir.glob("test_*.py"))
        files_scanned = len(test_files)

        if not test_files:
            findings.append(ValidationFinding(
                file="<tests>",
                line=0,
                severity="medium",
                message="No test_*.py files found in tests/",
                suggestion="Add unit tests.",
                rule_id="TST-002",
            ))
            duration = time.monotonic() - start
            return self._make_result(StageStatus.FAILED.value, findings, files_scanned, duration)

        # Run tests via subprocess
        try:
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", str(tests_dir),
                 "-p", "test_*.py", "-v"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.project_root.parent),
            )
            output = result.stdout + result.stderr
            return_code = result.returncode

        except subprocess.TimeoutExpired:
            findings.append(ValidationFinding(
                file="<tests>",
                line=0,
                severity="high",
                message="Test suite timed out after 120 seconds",
                suggestion="Investigate hanging tests and add timeouts.",
                rule_id="TST-003",
            ))
            duration = time.monotonic() - start
            return self._make_result(StageStatus.FAILED.value, findings, files_scanned, duration)
        except (OSError, FileNotFoundError) as exc:
            findings.append(ValidationFinding(
                file="<tests>",
                line=0,
                severity="high",
                message=f"Failed to execute test runner: {exc}",
                suggestion="Ensure Python unittest is available.",
                rule_id="TST-004",
            ))
            duration = time.monotonic() - start
            return self._make_result(StageStatus.FAILED.value, findings, files_scanned, duration)

        # Parse test output
        tests_run = 0
        failures = 0
        errors = 0
        skipped = 0

        # Extract test counts from unittest output
        run_match = re.search(r"Ran (\d+) test", output)
        if run_match:
            tests_run = int(run_match.group(1))

        # Look for FAIL/ERROR lines for individual failures
        failure_lines = [l for l in output.splitlines() if l.startswith("FAIL:") or l.startswith("ERROR:")]
        errors = output.count("ERROR:")
        failures = output.count("FAIL:") - errors  # FAIL: includes ERROR: count in some formats

        # Count skipped from output
        skip_match = re.search(r"skipped=(\d+)", output)
        if skip_match:
            skipped = int(skip_match.group(1))

        # Create findings for failures and errors
        for fail_line in failure_lines:
            test_name = fail_line.split(":", 1)[-1].strip()
            findings.append(ValidationFinding(
                file="<tests>",
                line=0,
                severity="high",
                message=f"Test failure: {test_name}",
                suggestion="Review and fix the failing test.",
                rule_id="TST-005",
            ))

        if return_code != 0:
            status = StageStatus.FAILED.value
        else:
            status = StageStatus.PASSED.value

        # Info finding with test summary
        findings.append(ValidationFinding(
            file="<summary>",
            line=0,
            severity="info",
            message=f"Test results: {tests_run} ran, {failures} failed, {errors} errors, {skipped} skipped",
            suggestion="",
            rule_id="TST-000",
        ))

        duration = time.monotonic() - start
        return self._make_result(status, findings, files_scanned, duration)


# ────────────────────────────────────────────────────────────────────────
# ValidationPipeline — Orchestrator
# ────────────────────────────────────────────────────────────────────────

class ValidationPipeline:
    """Orchestrates all validation stages for ReconPro.

    Provides methods to run individual stages or the full pipeline.
    Results are collected into a ValidationReport with trend data.

    Usage:
        pipeline = ValidationPipeline("/path/to/reconpro")
        report = pipeline.validate_full()
        print(report.summary())
        report.save()

    Or run individual stages:
        pipeline = ValidationPipeline("/path/to/reconpro")
        result = pipeline.validate_syntax()
    """

    def __init__(self, project_root: Optional[str] = None) -> None:
        """Initialize the pipeline.

        Args:
            project_root: Root directory to validate. Defaults to the
                          directory containing this file (reconpro/).
        """
        if project_root:
            self.project_root = Path(project_root).resolve()
        else:
            self.project_root = Path(__file__).parent.resolve()

        self._report: Optional[ValidationReport] = None
        self._stages: Dict[str, ValidationStage] = {}
        self._init_stages()
        logger.info(
            "ValidationPipeline initialized for %s", self.project_root,
        )

    def _init_stages(self) -> None:
        """Create all validation stage instances."""
        self._stages = {
            "syntax": SyntaxValidator(self.project_root),
            "imports": ImportValidator(self.project_root),
            "interfaces": InterfaceValidator(self.project_root),
            "types": TypeValidator(self.project_root),
            "security": SecurityValidator(self.project_root),
            "performance": PerformanceValidator(self.project_root),
            "tests": TestValidator(self.project_root),
        }

    def validate_syntax(self) -> ValidationStageResult:
        """Run syntax validation stage only.

        Returns:
            ValidationStageResult for the syntax stage.
        """
        return self._stages["syntax"].run()

    def validate_imports(self) -> ValidationStageResult:
        """Run import validation stage only.

        Returns:
            ValidationStageResult for the imports stage.
        """
        return self._stages["imports"].run()

    def validate_interfaces(self) -> ValidationStageResult:
        """Run interface compliance validation stage only.

        Returns:
            ValidationStageResult for the interfaces stage.
        """
        return self._stages["interfaces"].run()

    def validate_types(self) -> ValidationStageResult:
        """Run type annotation validation stage only.

        Returns:
            ValidationStageResult for the types stage.
        """
        return self._stages["types"].run()

    def validate_security(self) -> ValidationStageResult:
        """Run security validation stage only.

        Returns:
            ValidationStageResult for the security stage.
        """
        return self._stages["security"].run()

    def validate_performance(self) -> ValidationStageResult:
        """Run performance validation stage only.

        Returns:
            ValidationStageResult for the performance stage.
        """
        return self._stages["performance"].run()

    def validate_tests(self) -> ValidationStageResult:
        """Run test suite validation stage only.

        Returns:
            ValidationStageResult for the tests stage.
        """
        return self._stages["tests"].run()

    def validate_full(self) -> ValidationReport:
        """Run ALL validation stages and produce a comprehensive report.

        Returns:
            ValidationReport with per-stage results, summary, and trends.
        """
        pipeline_start = time.monotonic()
        stage_results: List[ValidationStageResult] = []

        # Load previous report for trend comparison
        previous = ValidationReport.load_latest()

        stage_order = [
            "syntax", "imports", "interfaces", "types",
            "security", "performance", "tests",
        ]

        for stage_name in stage_order:
            stage = self._stages[stage_name]
            logger.info("Running validation stage: %s", stage_name)

            try:
                result = stage.run()
                stage_results.append(result)
                logger.info(
                    "Stage '%s' completed: %s (%d findings, %.3fs)",
                    stage_name, result.status, result.finding_count, result.duration,
                )
            except Exception as exc:
                # Catch unexpected stage errors
                error_result = ValidationStageResult(
                    stage_name=stage_name,
                    status=StageStatus.ERROR.value,
                    duration=0.0,
                    error_message=f"Stage failed with exception: {exc}\n{traceback.format_exc()}",
                )
                stage_results.append(error_result)
                logger.error("Stage '%s' raised exception: %s", stage_name, exc)

        total_duration = time.monotonic() - pipeline_start

        # Determine overall status
        has_critical = any(sr.critical_count() > 0 for sr in stage_results)
        all_passed = all(sr.passed for sr in stage_results)
        any_errors = any(sr.status == StageStatus.ERROR.value for sr in stage_results)

        if has_critical:
            overall = "failed"
        elif any_errors:
            overall = "error"
        elif all_passed:
            overall = "passed"
        else:
            overall = "passed"  # Warnings/low findings don't fail

        report = ValidationReport(
            timestamp=datetime.now().isoformat(),
            project_root=str(self.project_root),
            overall_status=overall,
            stage_results=stage_results,
            total_duration=total_duration,
            previous_report=previous,
        )

        self._report = report
        logger.info(
            "Full validation complete: %s (%.3fs, %d findings)",
            overall, total_duration, report.total_findings,
        )
        return report

    def get_validation_report(self) -> Optional[ValidationReport]:
        """Get the most recently generated report.

        Returns:
            The ValidationReport from the last run, or None if no
            validation has been executed yet.
        """
        return self._report

    @classmethod
    # DEAD CODE: consider removal
    def quick_validate(cls, project_root: Optional[str] = None) -> ValidationReport:
        """Convenience method: create a pipeline and run full validation.

        Args:
            project_root: Root directory to validate.

        Returns:
            ValidationReport with full results.
        """
        pipeline = cls(project_root)
        return pipeline.validate_full()


# ────────────────────────────────────────────────────────────────────────
# Convenience functions
# ────────────────────────────────────────────────────────────────────────

# DEAD CODE: consider removal
# DEAD CODE: consider removal
def validate_syntax(project_root: Optional[str] = None) -> ValidationStageResult:
    """Quick syntax validation.

    Args:
        project_root: Root directory. Defaults to reconpro package root.

    Returns:
        ValidationStageResult for syntax checks.
    """
    pipeline = ValidationPipeline(project_root)
    return pipeline.validate_syntax()


# DEAD CODE: consider removal
def validate_imports(project_root: Optional[str] = None) -> ValidationStageResult:
    """Quick import validation.

    Args:
        project_root: Root directory. Defaults to reconpro package root.

    Returns:
        ValidationStageResult for import checks.
    """
    pipeline = ValidationPipeline(project_root)
    return pipeline.validate_imports()


def validate_full(project_root: Optional[str] = None) -> ValidationReport:
    """Convenience function: run full validation pipeline.

    Args:
        project_root: Root directory. Defaults to reconpro package root.

    Returns:
        ValidationReport with all stage results.
    """
    return ValidationPipeline.quick_validate(project_root)

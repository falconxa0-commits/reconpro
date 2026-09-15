# type: ignore
"""Tests for reconpro.quality_intelligence - Quality Intelligence System.

Covers:
  - QualityDimension dataclass
  - _ASTAnalyzer metrics collection
  - Security pattern scanning
  - All 8 quality dimension computations
  - QualityIntelligence single-file analysis
  - QualityIntelligence repository analysis
  - QualityTrend: snapshots, comparison, regression, trajectory
  - QualityGate: define, evaluate, history
  - Edge cases and error handling
  - JSON persistence
  - Grade / severity mapping from constants.py
"""
from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path
from typing import Any, Dict, List

import pytest

from reconpro.quality_intelligence import (
    DEFAULT_DIMENSION_WEIGHTS,
    QualityDimension,
    QualityGate,
    QualityIntelligence,
    QualitySnapshot,
    QualityTrend,
    _ASTAnalyzer,
    _assign_grade,
    _assign_severity,
    _assign_dimension_grade,
    _compute_maintainability_index,
    _estimate_test_coverage,
    _parse_file_safe,
    _scan_security_patterns,
    analyze_file,
    analyze_repository,
    get_quality_trend,
)
from reconpro.constants import VALID_GRADES, VALID_SEVERITIES


# Source code templates used by fixtures (avoid triple-quote nesting)
CLEAN_CODE = (
    '    """Module docstring."""\n'
    '\n'
    '    from __future__ import annotations\n'
    '    from typing import List, Optional, Dict, Any\n'
    '\n\n'
    '    def add_numbers(a: int, b: int) -> int:\n'
    '        """Add two numbers."""\n'
    '        return a + b\n'
    '\n\n'
    '    class DataProcessor:\n'
    '        """Processes data items."""\n'
    '\n'
    '        def __init__(self, name: str, max_items: int = 100) -> None:\n'
    '            self.name = name\n'
    '            self.max_items = max_items\n'
    '\n'
    '        def process(self, items: List[str]) -> Dict[str, Any]:\n'
    '            """Process a list of items."""\n'
    '            result: Dict[str, Any] = {}\n'
    '            for item in items:\n'
    '                if len(item) > 0:\n'
    '                    try:\n'
    '                        result[item] = len(item)\n'
    '                    except (ValueError, TypeError):\n'
    '                        result[item] = -1\n'
    '            return result\n'
    '\n'
    '        def get_summary(self) -> str:\n'
    '            """Return a summary string."""\n'
    '            return f"DataProcessor({self.name})"\n'
)

PROBLEMATIC_CODE = (
    '    import pickle\n'
    '    import os\n'
    '    import subprocess\n'
    '    import ssl\n'
    '\n'
    '    def BadFunc(x,y,z,a,b,c,d):\n'
    '        eval(x)\n'
    '        exec(y)\n'
    '        os.system(z)\n'
    '        pickle.loads(a)\n'
    '        subprocess.call(b, shell=True)\n'
    '        ssl._create_unverified_context()\n'
    '\n'
    '        for i in range(100):\n'
    '            for j in range(100):\n'
    '                for k in range(100):\n'
    '                    for l in range(10):\n'
    '                        if i > 0:\n'
    '                            if j > 0:\n'
    '                                if k > 0:\n'
    '                                    pass\n'
    '\n'
    '    class my_class:\n'
    '        def DoSomething(self):\n'
    '            try:\n'
    '                pass\n'
    '            except:\n'
    '                pass\n'
)

TEST_CODE = (
    '    """Tests for something."""\n'
    '    from unittest.mock import patch, MagicMock\n'
    '\n'
    "    def test_addition():\n"
    "        assert 1 + 1 == 2\n"
    "        assert 2 + 2 == 4\n"
    '\n'
    "    def test_subtraction():\n"
    "        assert 5 - 3 == 2\n"
    '\n'
    "    def test_with_mock():\n"
    "        with patch('some.module') as mock:\n"
    "            mock.return_value = 42\n"
    "            assert mock() == 42\n"
)

REPO_CLEAN = (
    '    """Clean module."""\n'
    '    from typing import Optional\n'
    '\n'
    '    def greet(name: str) -> str:\n'
    '        """Greet someone."""\n'
    '        return f"Hello, {name}"\n'
)

REPO_TEST = (
    "    def test_greet():\n"
    '        assert greet("World") == "Hello, World"\n'
    '        assert greet("") == "Hello, "\n'
)

BAD_REPO = (
    '    import pickle, os, subprocess, ssl\n'
    '\n'
    '    def dangerous(x):\n'
    '        eval(x)\n'
    '        exec(x)\n'
    '        os.system(x)\n'
    '        pickle.loads(x)\n'
    '        subprocess.call(x, shell=True)\n'
    '        ssl._create_unverified_context()\n'
    '        return True\n'
)

DECORATOR_CODE = (
    '    from functools import lru_cache\n'
    '\n'
    '    @lru_cache(maxsize=128)\n'
    '    def compute(x: int) -> int:\n'
    '        """Cached computation."""\n'
    '        return x * x\n'
)

ASYNC_CODE = (
    '    async def fetch_data(url: str) -> str:\n'
    '        """Fetch data asynchronously."""\n'
    '        return url\n'
)

NESTED_CLASS_CODE = (
    '    class Outer:\n'
    '        """Outer class."""\n'
    '        class Inner:\n'
    '            """Inner class."""\n'
    '            def method(self) -> None:\n'
    '                pass\n'
)

LONG_FUNC_CODE = 'def long_function():\n' + ''.join(f'    x_{i} = {i}\n' for i in range(200)) + '    return 0\n'


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════


@pytest.fixture
def clean_code(tmp_path: Path) -> str:
    """Write a clean, well-typed Python file and return its path."""
    source = textwrap.dedent(CLEAN_CODE)
    path = tmp_path / "clean_code.py"
    path.write_text(source, encoding="utf-8")
    return str(path)


@pytest.fixture
def problematic_code(tmp_path: Path) -> str:
    """Write a problematic Python file and return its path."""
    source = textwrap.dedent(PROBLEMATIC_CODE)
    path = tmp_path / "problematic_code.py"
    path.write_text(source, encoding="utf-8")
    return str(path)


@pytest.fixture
def test_file(tmp_path: Path) -> str:
    """Write a test file and return its path."""
    source = textwrap.dedent(TEST_CODE)
    path = tmp_path / "test_something.py"
    path.write_text(source, encoding="utf-8")
    return str(path)


@pytest.fixture
def multi_file_repo(tmp_path: Path) -> str:
    """Create a small repo with several Python files."""
    (tmp_path / "clean.py").write_text(textwrap.dedent(REPO_CLEAN), encoding="utf-8")
    (tmp_path / "test_clean.py").write_text(textwrap.dedent(REPO_TEST), encoding="utf-8")
    return str(tmp_path)


@pytest.fixture
def empty_file(tmp_path: Path) -> str:
    path = tmp_path / "empty.py"
    path.write_text("", encoding="utf-8")
    return str(path)


@pytest.fixture
def syntax_error_file(tmp_path: Path) -> str:
    path = tmp_path / "broken.py"
    path.write_text("def (\n", encoding="utf-8")
    return str(path)


# ════════════════════════════════════════════════════════════════════════
# Tests: Helper functions
# ════════════════════════════════════════════════════════════════════════


class TestAssignSeverity:
    """Tests for _assign_severity."""

    def test_high_score(self) -> None:
        assert _assign_severity(90) == "low"
        assert _assign_severity(80) == "low"

    def test_medium_score(self) -> None:
        assert _assign_severity(70) == "medium"
        assert _assign_severity(60) == "medium"

    def test_low_score(self) -> None:
        assert _assign_severity(45) == "high"
        assert _assign_severity(40) == "high"

    def test_critical_score(self) -> None:
        assert _assign_severity(20) == "critical"
        assert _assign_severity(0) == "critical"

    def test_boundary_values(self) -> None:
        assert _assign_severity(80) == "low"
        assert _assign_severity(60) == "medium"
        assert _assign_severity(40) == "high"


class TestAssignGrade:
    """Tests for _assign_grade (uses GRADE_THRESHOLDS from constants)."""

    def test_a_plus(self) -> None:
        assert _assign_grade(95) == "A+"
        assert _assign_grade(90) == "A+"

    def test_a(self) -> None:
        assert _assign_grade(85) == "A"
        assert _assign_grade(80) == "A"

    def test_b(self) -> None:
        assert _assign_grade(75) == "B"
        assert _assign_grade(65) == "B"

    def test_c(self) -> None:
        assert _assign_grade(55) == "C"
        assert _assign_grade(50) == "C"

    def test_d(self) -> None:
        assert _assign_grade(40) == "D"
        assert _assign_grade(35) == "D"

    def test_f(self) -> None:
        assert _assign_grade(20) == "F"
        assert _assign_grade(0) == "F"

    def test_grades_match_constants(self) -> None:
        for score, expected in [(92, "A+"), (82, "A"), (70, "B"), (45, "C"), (37, "D"), (10, "F")]:
            result = _assign_grade(score)
            assert result in VALID_GRADES, f"Grade {result} not in VALID_GRADES"


class TestAssignDimensionGrade:
    """Tests for _assign_dimension_grade (stricter thresholds)."""

    def test_strict_grades(self) -> None:
        assert _assign_dimension_grade(95) == "A+"
        assert _assign_dimension_grade(85) == "A"
        assert _assign_dimension_grade(75) == "B"
        assert _assign_dimension_grade(60) == "C"
        assert _assign_dimension_grade(45) == "D"
        assert _assign_dimension_grade(20) == "F"


class TestComputeMaintainabilityIndex:
    """Tests for _compute_maintainability_index."""

    def test_perfect_small_file(self) -> None:
        idx = _compute_maintainability_index(
            total_loc=100, comment_lines=30, blank_lines=20,
            max_nesting=2, avg_func_loc=10,
        )
        assert 0 <= idx <= 100

    def test_large_functions_penalised(self) -> None:
        small = _compute_maintainability_index(200, 20, 20, 2, 10)
        large = _compute_maintainability_index(200, 20, 20, 2, 80)
        assert small > large

    def test_deep_nesting_penalised(self) -> None:
        shallow = _compute_maintainability_index(200, 20, 20, 2, 20)
        deep = _compute_maintainability_index(200, 20, 20, 8, 20)
        assert shallow > deep

    def test_comments_help(self) -> None:
        # Use larger avg_func_loc to avoid capping at 100
        no_comments = _compute_maintainability_index(200, 0, 20, 3, 30)
        with_comments = _compute_maintainability_index(200, 60, 20, 3, 30)
        assert with_comments >= no_comments  # comments should not reduce maintainability

    def test_zero_loc(self) -> None:
        assert _compute_maintainability_index(0, 0, 0, 0, 0) == 100.0


class TestEstimateTestCoverage:
    """Tests for _estimate_test_coverage."""

    def test_good_test_file(self) -> None:
        lines = [
            "def test_something():",
            "    assert 1 == 1",
            "    assert 2 == 2",
            "    assert 3 == 3",
            "",
            "def test_another():",
            "    assert 'a' == 'a'",
            "    assert 'b' == 'b'",
        ]
        result = _estimate_test_coverage(lines)
        assert result["test_function_count"] == 2
        assert result["assert_count"] == 5
        assert result["quality_estimate"] > 0

    def test_empty_lines(self) -> None:
        result = _estimate_test_coverage([])
        assert result["quality_estimate"] == 0.0

    def test_no_tests(self) -> None:
        lines = ["x = 1", "y = 2"]
        result = _estimate_test_coverage(lines)
        assert result["test_function_count"] == 0

    def test_with_mocks(self) -> None:
        lines = [
            "from unittest.mock import patch, MagicMock",
            "def test_mock():",
            "    with patch('x') as mock:",
            "        assert mock.called",
            "        assert MagicMock() is not None",
        ]
        result = _estimate_test_coverage(lines)
        assert result["mock_count"] > 0
        assert result["quality_estimate"] > 0


class TestScanSecurityPatterns:
    """Tests for _scan_security_patterns."""

    def test_detects_eval(self) -> None:
        source = "result = eval(user_input)"
        issues = _scan_security_patterns(source)
        assert len(issues) >= 1
        assert any("eval" in i["pattern"] for i in issues)

    def test_detects_pickle(self) -> None:
        source = "data = pickle.loads(raw)"
        issues = _scan_security_patterns(source)
        assert any("pickle" in i["pattern"] for i in issues)

    def test_detects_shell_true(self) -> None:
        source = "subprocess.call(cmd, shell=True)"
        issues = _scan_security_patterns(source)
        assert any("shell=True" in i["pattern"] for i in issues)

    def test_detects_ssl_bypass(self) -> None:
        source = "ctx = ssl._create_unverified_context()"
        issues = _scan_security_patterns(source)
        assert any("SSL" in i["pattern"] for i in issues)

    def test_clean_code_no_issues(self) -> None:
        source = "x = 1\ny = 2\nprint(x + y)"
        issues = _scan_security_patterns(source)
        real_issues = [i for i in issues if "noqa" not in i["pattern"] and "pass" not in i["pattern"]]
        assert len(real_issues) == 0

    def test_multiple_issues(self) -> None:
        source = "eval(x)\nexec(y)\nos.system(cmd)\npickle.loads(data)\nsubprocess.call(x, shell=True)\n"
        issues = _scan_security_patterns(source)
        assert len(issues) >= 5

    def test_line_numbers(self) -> None:
        source = "safe_line = 1\neval(x)\nanother_safe = 3"
        issues = _scan_security_patterns(source)
        eval_issues = [i for i in issues if "eval" in i["pattern"]]
        assert len(eval_issues) == 1
        assert eval_issues[0]["line"] == 2


class TestParseFileSafe:
    """Tests for _parse_file_safe."""

    def test_valid_python(self, clean_code: str) -> None:
        tree = _parse_file_safe(clean_code)
        assert tree is not None

    def test_invalid_python(self, syntax_error_file: str) -> None:
        tree = _parse_file_safe(syntax_error_file)
        assert tree is None

    def test_missing_file(self) -> None:
        tree = _parse_file_safe("/nonexistent/path/file.py")
        assert tree is None


# ════════════════════════════════════════════════════════════════════════
# Tests: _ASTAnalyzer
# ════════════════════════════════════════════════════════════════════════


class TestASTAnalyzer:
    """Tests for the _ASTAnalyzer metrics collection."""

    def test_counts_functions(self, clean_code: str) -> None:
        tree = _parse_file_safe(clean_code)
        assert tree is not None
        source = Path(clean_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        assert len(analyzer.functions) >= 2

    def test_counts_classes(self, clean_code: str) -> None:
        tree = _parse_file_safe(clean_code)
        source = Path(clean_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        assert len(analyzer.classes) == 1
        assert analyzer.classes[0]["name"] == "DataProcessor"

    def test_docstring_detection(self, clean_code: str) -> None:
        tree = _parse_file_safe(clean_code)
        source = Path(clean_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        assert analyzer.docstring_count > 0
        assert analyzer.docstring_targets > 0

    def test_nesting_depth(self, problematic_code: str) -> None:
        tree = _parse_file_safe(problematic_code)
        source = Path(problematic_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        assert analyzer.max_nesting_depth >= 4

    def test_type_hint_detection(self, clean_code: str) -> None:
        tree = _parse_file_safe(clean_code)
        source = Path(clean_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        assert analyzer.has_type_hints > 0
        assert analyzer.total_params > 0

    def test_except_handler_tracking(self, problematic_code: str) -> None:
        tree = _parse_file_safe(problematic_code)
        source = Path(problematic_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        assert analyzer.except_handlers >= 1
        assert analyzer.bare_except_handlers >= 1

    def test_import_tracking(self, clean_code: str) -> None:
        tree = _parse_file_safe(clean_code)
        source = Path(clean_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        assert len(analyzer.imports) > 0

    def test_naming_violations(self, problematic_code: str) -> None:
        tree = _parse_file_safe(problematic_code)
        source = Path(problematic_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        names = [v["name"] for v in analyzer.naming_violations]
        assert "BadFunc" in names
        assert "my_class" in names
        assert "DoSomething" in names

    def test_no_naming_violations_clean(self, clean_code: str) -> None:
        tree = _parse_file_safe(clean_code)
        source = Path(clean_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        analyzer.visit(tree)
        assert len(analyzer.naming_violations) == 0

    def test_blank_and_comment_lines(self, clean_code: str) -> None:
        source = Path(clean_code).read_text(encoding="utf-8")
        analyzer = _ASTAnalyzer(source.splitlines())
        tree = _parse_file_safe(clean_code)
        assert tree is not None
        analyzer.visit(tree)
        assert analyzer.blank_lines >= 0
        assert analyzer.comment_lines >= 0


# ════════════════════════════════════════════════════════════════════════
# Tests: QualityDimension
# ════════════════════════════════════════════════════════════════════════


class TestQualityDimension:
    """Tests for QualityDimension dataclass."""

    def test_defaults(self) -> None:
        dim = QualityDimension(name="test")
        assert dim.score == 0.0
        assert dim.weight == 0.0
        assert dim.severity == "info"
        assert dim.grade == "F"

    def test_to_dict(self) -> None:
        dim = QualityDimension(
            name="complexity", score=75.5, weight=0.12,
            severity="medium", grade="C", details="test detail",
            metrics={"avg_loc": 25},
        )
        d = dim.to_dict()
        assert d["name"] == "complexity"
        assert d["score"] == 75.5
        assert d["weight"] == 0.12
        assert d["severity"] == "medium"
        assert d["grade"] == "C"
        assert d["details"] == "test detail"
        assert d["metrics"]["avg_loc"] == 25

    def test_severity_in_valid_severities(self) -> None:
        for score in [90, 70, 50, 30, 10]:
            sev = _assign_severity(score)
            assert sev in VALID_SEVERITIES


# ════════════════════════════════════════════════════════════════════════
# Tests: QualityIntelligence - single file analysis
# ════════════════════════════════════════════════════════════════════════


class TestQualityIntelligenceSingleFile:
    """Tests for single-file quality analysis."""

    def test_clean_file_analysis(self, clean_code: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(clean_code)
        assert "error" not in result
        assert result["loc"] > 0
        assert result["overall_score"] > 0
        assert len(result["dimensions"]) == 8
        assert "complexity" in result["dimensions"]
        assert "security" in result["dimensions"]
        assert result["functions"] > 0
        assert result["classes"] == 1

    def test_problematic_file_low_score(self, problematic_code: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(problematic_code)
        assert result["overall_score"] > 0
        sec = result["dimensions"]["security"]
        assert sec["score"] < 50
        assert len(result["security_issues"]) >= 5

    def test_test_file_coverage(self, test_file: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(test_file)
        assert "coverage" in result["dimensions"]
        cov = result["dimensions"]["coverage"]
        assert cov["metrics"].get("test_function_count", 0) > 0
        assert cov["metrics"].get("assert_count", 0) > 0

    def test_empty_file(self, empty_file: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(empty_file)
        assert result["loc"] == 0
        assert result["overall_score"] == 0.0

    def test_syntax_error_file(self, syntax_error_file: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(syntax_error_file)
        assert "error" in result

    def test_missing_file(self) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality("/nonexistent/file.py")
        assert "error" in result

    def test_all_dimensions_have_required_fields(self, clean_code: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(clean_code)
        for dim_name, dim_data in result["dimensions"].items():
            assert "score" in dim_data
            assert "weight" in dim_data
            assert "severity" in dim_data
            assert "grade" in dim_data
            assert "details" in dim_data
            assert 0 <= dim_data["score"] <= 100
            assert 0 < dim_data["weight"] <= 1
            assert dim_data["severity"] in VALID_SEVERITIES

    def test_dimension_scores_bounded(self, problematic_code: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(problematic_code)
        for dim_data in result["dimensions"].values():
            assert 0 <= dim_data["score"] <= 100

    def test_type_safety_high_on_clean(self, clean_code: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(clean_code)
        ts = result["dimensions"]["type_safety"]
        assert ts["score"] > 60

    def test_type_safety_low_on_untyped(self, problematic_code: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(problematic_code)
        ts = result["dimensions"]["type_safety"]
        assert ts["score"] < 50

    def test_documentation_high_on_clean(self, clean_code: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(clean_code)
        doc = result["dimensions"]["documentation"]
        assert doc["score"] > 70

    def test_documentation_low_on_problematic(self, problematic_code: str) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(problematic_code)
        doc = result["dimensions"]["documentation"]
        assert doc["score"] < 20


# ════════════════════════════════════════════════════════════════════════
# Tests: QualityIntelligence - repository analysis
# ════════════════════════════════════════════════════════════════════════


class TestQualityIntelligenceRepository:
    """Tests for repository-level quality analysis."""

    def test_repo_analysis(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        result = qi.analyze_repository_quality()
        assert "error" not in result
        assert result["file_count"] >= 2
        assert result["total_loc"] > 0
        assert 0 <= result["composite_score"] <= 100
        assert result["grade"] in VALID_GRADES
        assert len(result["dimensions"]) == 8

    def test_repo_composite_score(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.analyze_repository_quality()
        score = qi.get_quality_score()
        assert 0 <= score <= 100

    def test_repo_quality_dimensions(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.analyze_repository_quality()
        dims = qi.get_quality_dimensions()
        assert len(dims) == 8
        for dim_name, dim_data in dims.items():
            assert "score" in dim_data
            assert 0 <= dim_data["score"] <= 100

    def test_repo_no_path(self) -> None:
        qi = QualityIntelligence()
        result = qi.analyze_repository_quality()
        assert "error" in result

    def test_repo_empty_dir(self, tmp_path: Path) -> None:
        qi = QualityIntelligence(repository_path=str(tmp_path))
        result = qi.analyze_repository_quality()
        assert "error" in result

    def test_repo_skips_pycache(self, tmp_path: Path) -> None:
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "cached.pyc").write_bytes(b"\x00" * 100)
        (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
        qi = QualityIntelligence(repository_path=str(tmp_path))
        result = qi.analyze_repository_quality()
        assert result["file_count"] == 1

    def test_repo_includes_gate_result(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        result = qi.analyze_repository_quality()
        assert "gate_result" in result
        assert "passed" in result["gate_result"]

    def test_repo_includes_trend(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        result = qi.analyze_repository_quality()
        assert "trend" in result


# ════════════════════════════════════════════════════════════════════════
# Tests: QualityTrend
# ════════════════════════════════════════════════════════════════════════


class TestQualityTrend:
    """Tests for QualityTrend.

    These tests use isolated QualityTrend instances that do NOT share
    the on-disk persistence file to avoid cross-test pollution.
    """

    @pytest.fixture(autouse=True)
    def _isolate_trend(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Redirect snapshot storage to a temp dir."""
        from reconpro import quality_intelligence as qi_mod
        iso_file = tmp_path / "snapshots.json"
        monkeypatch.setattr(qi_mod, "SNAPSHOTS_FILE", iso_file)
        self._tmp_path = tmp_path

    def _make_trend(self) -> QualityTrend:
        return QualityTrend()

    def test_record_and_retrieve_snapshot(self) -> None:
        trend = self._make_trend()
        snapshot = trend.record_snapshot(
            composite_score=75.0,
            dimensions={"complexity": 80, "security": 70},
            file_count=10,
            total_loc=1000,
        )
        assert snapshot.composite_score == 75.0
        assert snapshot.dimensions["complexity"] == 80
        snapshots = trend.get_snapshots()
        assert len(snapshots) >= 1
        assert snapshots[-1].composite_score == 75.0

    def test_get_latest(self) -> None:
        trend = QualityTrend()
        assert trend.get_latest() is None
        trend.record_snapshot(50.0, {})
        assert trend.get_latest() is not None
        assert trend.get_latest().composite_score == 50.0

    def test_compare_with_previous_insufficient(self) -> None:
        trend = QualityTrend()
        assert trend.compare_with_previous() is None
        trend.record_snapshot(50.0, {})
        assert trend.compare_with_previous() is None

    def test_compare_with_previous(self) -> None:
        trend = QualityTrend()
        trend.record_snapshot(60.0, {"complexity": 70, "security": 50})
        trend.record_snapshot(75.0, {"complexity": 80, "security": 65})
        comp = trend.compare_with_previous()
        assert comp is not None
        assert comp["score_delta"] == 15.0
        assert comp["direction"] == "improving"
        assert comp["dimension_deltas"]["complexity"] == 10.0
        assert comp["dimension_deltas"]["security"] == 15.0

    def test_regression_detection(self) -> None:
        trend = QualityTrend()
        trend.record_snapshot(80.0, {"complexity": 85})
        trend.record_snapshot(60.0, {"complexity": 50})
        regressions = trend.detect_regressions(5.0)
        assert len(regressions) >= 1
        assert regressions[0]["score_delta"] == -20.0

    def test_no_false_regressions(self) -> None:
        trend = QualityTrend()
        trend.record_snapshot(60.0, {"complexity": 65})
        trend.record_snapshot(62.0, {"complexity": 67})
        regressions = trend.detect_regressions(5.0)
        assert len(regressions) == 0

    def test_trajectory_projection(self) -> None:
        trend = QualityTrend()
        for score in [50, 55, 60, 65, 70]:
            trend.record_snapshot(float(score), {})
        proj = trend.project_trajectory(3)
        assert proj is not None
        assert proj["trend"] == "improving"
        assert len(proj["projected_scores"]) == 3
        assert proj["slope"] > 0

    def test_trajectory_insufficient_data(self) -> None:
        trend = QualityTrend()
        trend.record_snapshot(50.0, {})
        trend.record_snapshot(55.0, {})
        assert trend.project_trajectory() is None

    def test_snapshot_persistence(self) -> None:
        trend1 = QualityTrend()
        trend1.record_snapshot(42.0, {"complexity": 50})
        trend2 = QualityTrend()
        snapshots = trend2.get_snapshots()
        assert any(s.composite_score == 42.0 for s in snapshots)

    def test_max_snapshots_limit(self) -> None:
        trend = QualityTrend()
        for i in range(QualityTrend.MAX_SNAPSHOTS + 50):
            trend.record_snapshot(float(i % 100), {})
        assert len(trend.get_snapshots()) <= QualityTrend.MAX_SNAPSHOTS

    def test_snapshot_to_dict(self) -> None:
        trend = QualityTrend()
        snap = trend.record_snapshot(77.5, {"a": 80.0}, 5, 500, "/test")
        d = snap.to_dict()
        assert d["composite_score"] == 77.5
        assert d["dimensions"] == {"a": 80.0}
        assert d["file_count"] == 5
        assert d["total_loc"] == 500
        assert d["repository_path"] == "/test"
        assert "timestamp" in d


class TestQualityTrendDirection:
    """Test direction classification in compare_with_previous."""

    def test_stable_direction(self) -> None:
        trend = QualityTrend()
        trend.record_snapshot(60.0, {})
        trend.record_snapshot(61.0, {})
        comp = trend.compare_with_previous()
        assert comp is not None
        assert comp["direction"] == "stable"

    def test_declining_direction(self) -> None:
        trend = QualityTrend()
        trend.record_snapshot(70.0, {})
        trend.record_snapshot(55.0, {})
        comp = trend.compare_with_previous()
        assert comp is not None
        assert comp["direction"] == "regressing"

    def test_improvements_and_regressions_lists(self) -> None:
        trend = QualityTrend()
        trend.record_snapshot(70.0, {"a": 60, "b": 80, "c": 70})
        trend.record_snapshot(70.0, {"a": 80, "b": 50, "c": 70})
        comp = trend.compare_with_previous()
        assert comp is not None
        assert "a" in comp["improvements"]
        assert "b" in comp["regressions"]
        assert "c" not in comp["improvements"]
        assert "c" not in comp["regressions"]


# ════════════════════════════════════════════════════════════════════════
# Tests: QualityGate
# ════════════════════════════════════════════════════════════════════════


class TestQualityGate:
    """Tests for QualityGate."""

    def test_define_and_evaluate_pass(self) -> None:
        gate = QualityGate()
        gate.define_gate("test_gate", {"_composite": 50.0, "security": 40.0})
        result = gate.evaluate("test_gate", {
            "composite_score": 80.0,
            "dimensions": {"security": 70.0},
        })
        assert result.passed is True
        assert len(result.failures) == 0

    def test_define_and_evaluate_fail_composite(self) -> None:
        gate = QualityGate()
        gate.define_gate("test_gate", {"_composite": 90.0})
        result = gate.evaluate("test_gate", {
            "composite_score": 50.0,
            "dimensions": {},
        })
        assert result.passed is False
        assert len(result.failures) == 1
        assert "_composite" in result.failures[0]["dimension"]

    def test_define_and_evaluate_fail_dimension(self) -> None:
        gate = QualityGate()
        gate.define_gate("test_gate", {"security": 80.0})
        result = gate.evaluate("test_gate", {
            "composite_score": 90.0,
            "dimensions": {"security": 30.0},
        })
        assert result.passed is False
        assert any(f["dimension"] == "security" for f in result.failures)

    def test_undefined_gate(self) -> None:
        gate = QualityGate()
        result = gate.evaluate("nonexistent", {
            "composite_score": 50.0,
            "dimensions": {},
        })
        assert "_gate_not_found" in str(result.failures)

    def test_gate_history(self) -> None:
        gate = QualityGate()
        gate.define_gate("test_gate", {"_composite": 50.0})
        gate.evaluate("test_gate", {"composite_score": 60.0, "dimensions": {}})
        gate.evaluate("test_gate", {"composite_score": 40.0, "dimensions": {}})
        history = gate.get_gate_history("test_gate")
        assert len(history) == 2

    def test_gate_history_all(self) -> None:
        gate = QualityGate()
        gate.define_gate("gate_a", {"_composite": 50.0})
        gate.define_gate("gate_b", {"_composite": 50.0})
        gate.evaluate("gate_a", {"composite_score": 60.0, "dimensions": {}})
        gate.evaluate("gate_b", {"composite_score": 70.0, "dimensions": {}})
        history = gate.get_gate_history()
        assert len(history) == 2

    def test_gate_pass_rate(self) -> None:
        gate = QualityGate()
        gate.define_gate("test_gate", {"_composite": 50.0})
        gate.evaluate("test_gate", {"composite_score": 60.0, "dimensions": {}})
        gate.evaluate("test_gate", {"composite_score": 40.0, "dimensions": {}})
        gate.evaluate("test_gate", {"composite_score": 55.0, "dimensions": {}})
        rate = gate.get_gate_pass_rate("test_gate")
        assert rate == pytest.approx(2 / 3, abs=0.01)

    def test_gate_pass_rate_no_history(self) -> None:
        gate = QualityGate()
        assert gate.get_gate_pass_rate("nonexistent") == 0.0

    def test_gate_actions_on_failure(self) -> None:
        actions_called: List[str] = []

        def fail_action() -> None:
            actions_called.append("called")

        gate = QualityGate()
        gate.define_gate("test_gate", {"_composite": 99.0}, actions=[fail_action])
        gate.evaluate("test_gate", {"composite_score": 50.0, "dimensions": {}})
        assert "called" in actions_called

    def test_gate_actions_not_called_on_pass(self) -> None:
        actions_called: List[str] = []

        def fail_action() -> None:
            actions_called.append("called")

        gate = QualityGate()
        gate.define_gate("test_gate", {"_composite": 50.0}, actions=[fail_action])
        gate.evaluate("test_gate", {"composite_score": 80.0, "dimensions": {}})
        assert len(actions_called) == 0

    def test_gate_action_exception_handling(self) -> None:
        def bad_action() -> None:
            raise RuntimeError("action failed")

        gate = QualityGate()
        gate.define_gate("test_gate", {"_composite": 99.0}, actions=[bad_action])
        result = gate.evaluate("test_gate", {"composite_score": 50.0, "dimensions": {}})
        assert result.passed is False
        assert len(result.actions_taken) == 1
        assert "failed" in result.actions_taken[0]

    def test_gate_result_to_dict(self) -> None:
        gate = QualityGate()
        gate.define_gate("g", {"_composite": 50.0})
        result = gate.evaluate("g", {"composite_score": 60.0, "dimensions": {}})
        d = result.to_dict()
        assert d["gate_name"] == "g"
        assert d["passed"] is True
        assert "timestamp" in d

    def test_gate_persistence(self) -> None:
        gate1 = QualityGate()
        gate1.define_gate("persist_gate", {"_composite": 50.0})
        gate1.evaluate("persist_gate", {"composite_score": 60.0, "dimensions": {}})
        # hermetic default: cross-session loading is an explicit opt-in
        gate2 = QualityGate(load_history=True)
        history = gate2.get_gate_history("persist_gate")
        assert len(history) >= 1


# ════════════════════════════════════════════════════════════════════════
# Tests: QualityIntelligence - report and thresholds
# ════════════════════════════════════════════════════════════════════════


class TestQualityReport:
    """Tests for quality report generation."""

    def test_report_contains_composite(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.analyze_repository_quality()
        report = qi.get_quality_report()
        assert "COMPOSITE SCORE" in report
        assert str(qi.get_quality_score()) in report

    def test_report_contains_dimensions(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.analyze_repository_quality()
        report = qi.get_quality_report()
        for dim in DEFAULT_DIMENSION_WEIGHTS:
            assert dim in report

    def test_report_contains_trend(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.analyze_repository_quality()
        report = qi.get_quality_report()
        assert "TREND" in report

    def test_report_contains_gate(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.analyze_repository_quality()
        report = qi.get_quality_report()
        assert "release_ready" in report

    def test_report_before_analysis(self) -> None:
        qi = QualityIntelligence()
        report = qi.get_quality_report()
        assert "COMPOSITE SCORE" in report


class TestSetQualityThreshold:
    """Tests for set_quality_threshold."""

    def test_set_threshold(self) -> None:
        qi = QualityIntelligence()
        qi.set_quality_threshold({"_composite": 70.0, "security": 60.0})
        assert qi._thresholds["_composite"] == 70.0
        assert qi._thresholds["security"] == 60.0

    def test_replace_threshold(self) -> None:
        qi = QualityIntelligence()
        qi.set_quality_threshold({"_composite": 90.0})
        qi.set_quality_threshold({"_composite": 40.0})
        assert qi._thresholds["_composite"] == 40.0


class TestTrackQualityOverTime:
    """Tests for track_quality_over_time."""

    def test_track_before_analysis(self) -> None:
        qi = QualityIntelligence()
        data = qi.track_quality_over_time()
        assert "snapshot_count" in data
        assert "regressions" in data
        assert "trajectory" in data

    def test_track_after_repo_analysis(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.analyze_repository_quality()
        data = qi.track_quality_over_time()
        assert data["snapshot_count"] >= 1
        assert data["latest_snapshot"] is not None


class TestTrendAndGateProperties:
    """Tests for trend and gate property accessors."""

    def test_trend_property(self) -> None:
        qi = QualityIntelligence()
        assert isinstance(qi.trend, QualityTrend)

    def test_gate_property(self) -> None:
        qi = QualityIntelligence()
        assert isinstance(qi.gate, QualityGate)

    def test_default_gate_defined(self) -> None:
        qi = QualityIntelligence()
        result = qi.gate.evaluate("release_ready", {
            "composite_score": 100.0,
            "dimensions": {"security": 100.0, "reliability": 100.0},
        })
        assert result.passed is True


# ════════════════════════════════════════════════════════════════════════
# Tests: Convenience functions
# ════════════════════════════════════════════════════════════════════════


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_analyze_file(self, clean_code: str) -> None:
        result = analyze_file(clean_code)
        assert "dimensions" in result
        assert result["loc"] > 0

    def test_analyze_repository(self, multi_file_repo: str) -> None:
        result = analyze_repository(multi_file_repo)
        assert "composite_score" in result
        assert result["file_count"] >= 1

    def test_get_quality_trend(self) -> None:
        result = get_quality_trend()
        assert "snapshot_count" in result


# ════════════════════════════════════════════════════════════════════════
# Tests: Custom weights
# ════════════════════════════════════════════════════════════════════════


class TestCustomWeights:
    """Tests for custom dimension weights."""

    def test_custom_weights_affect_score(self, clean_code: str) -> None:
        weights = dict(DEFAULT_DIMENSION_WEIGHTS)
        weights["security"] = 0.80
        qi = QualityIntelligence(weights=weights)
        result = qi.analyze_code_quality(clean_code)
        assert 0 <= result["overall_score"] <= 100

    def test_default_weights_sum_near_one(self) -> None:
        total = sum(DEFAULT_DIMENSION_WEIGHTS.values())
        assert abs(total - 1.0) < 0.01


# ════════════════════════════════════════════════════════════════════════
# Tests: Integration - full pipeline
# ════════════════════════════════════════════════════════════════════════


class TestFullPipeline:
    """Integration tests running the full quality intelligence pipeline."""

    def test_full_pipeline(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.gate.define_gate("ci_check", {"_composite": 30.0, "security": 20.0})
        result = qi.analyze_repository_quality()
        assert result["composite_score"] >= 0
        assert result["grade"] in VALID_GRADES
        assert result["file_count"] >= 2
        score = qi.get_quality_score()
        assert score == result["composite_score"]
        dims = qi.get_quality_dimensions()
        assert len(dims) == 8
        trend = qi.track_quality_over_time()
        assert trend["snapshot_count"] >= 1
        gate_result = qi.gate.evaluate("ci_check", {
            "composite_score": result["composite_score"],
            "dimensions": {k: v["score"] for k, v in result["dimensions"].items()},
        })
        assert gate_result.gate_name == "ci_check"
        report = qi.get_quality_report()
        assert len(report) > 100
        assert "ReconPro" in report

    def test_multiple_repo_analyses_create_trend(self, multi_file_repo: str) -> None:
        qi = QualityIntelligence(repository_path=multi_file_repo)
        qi.analyze_repository_quality()
        qi.analyze_repository_quality()
        trend = qi.track_quality_over_time()
        assert trend["snapshot_count"] >= 2
        assert trend["comparison"] is not None

    def test_problematic_repo_triggers_gate_failure(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text(textwrap.dedent(BAD_REPO), encoding="utf-8")
        qi = QualityIntelligence(repository_path=str(tmp_path))
        result = qi.analyze_repository_quality()
        sec_dim = result["dimensions"]["security"]
        assert sec_dim["score"] < 20
        assert result["gate_result"]["passed"] is False


class TestEdgeCases:
    """Edge case tests."""

    def test_file_with_only_comments(self, tmp_path: Path) -> None:
        path = tmp_path / "comments_only.py"
        path.write_text("# just a comment\n# another comment\n", encoding="utf-8")
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(str(path))
        assert result["loc"] == 2

    def test_file_with_only_imports(self, tmp_path: Path) -> None:
        path = tmp_path / "imports_only.py"
        path.write_text(
            "import os\nimport sys\nfrom pathlib import Path\n",
            encoding="utf-8",
        )
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(str(path))
        assert result["loc"] == 3

    def test_file_with_decorator(self, tmp_path: Path) -> None:
        path = tmp_path / "decorators.py"
        path.write_text(textwrap.dedent(DECORATOR_CODE), encoding="utf-8")
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(str(path))
        assert result["functions"] >= 1

    def test_async_function(self, tmp_path: Path) -> None:
        path = tmp_path / "async_code.py"
        path.write_text(textwrap.dedent(ASYNC_CODE), encoding="utf-8")
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(str(path))
        assert result["functions"] >= 1

    def test_nested_class(self, tmp_path: Path) -> None:
        path = tmp_path / "nested.py"
        path.write_text(textwrap.dedent(NESTED_CLASS_CODE), encoding="utf-8")
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(str(path))
        assert result["classes"] >= 2

    def test_unicode_source(self, tmp_path: Path) -> None:
        path = tmp_path / "unicode.py"
        path.write_text("# -*- coding: utf-8 -*-\n# Comment with unicode: \u00e9\ndef f(): pass\n", encoding="utf-8")
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(str(path))
        assert result["loc"] >= 3

    def test_very_long_function(self, tmp_path: Path) -> None:
        path = tmp_path / "long_func.py"
        path.write_text(LONG_FUNC_CODE, encoding="utf-8")
        qi = QualityIntelligence()
        result = qi.analyze_code_quality(str(path))
        complexity = result["dimensions"]["complexity"]
        assert complexity["metrics"]["long_functions"] >= 1

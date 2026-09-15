"""Tests for reconpro.cli — CLI rendering functions."""

import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock, call
from io import StringIO

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.cli import (
    _render_summary,
    _render_findings_table,
    _render_module_breakdown,
    _render_badge,
    _render_remediations,
    _output_result,
    _banner,
    SEV_COLORS,
    GRADE_COLORS,
)
from reconpro.scanner import ReconProResult


def _make_result(
    score=85,
    grade="A",
    findings=None,
    modules_run=None,
    target="example.com",
    badge_markdown="![ReconPro A](url)",
    vibesec_score=None,
    vibesec_grade=None,
    module_results=None,
):
    """Build a ReconProResult with sensible defaults."""
    if findings is None:
        findings = []
    if modules_run is None:
        modules_run = ["recon"]
    if module_results is None:
        module_results = {}
    sc = {}
    for f in findings:
        sev = f.get("severity", "info")
        sc[sev] = sc.get(sev, 0) + 1
    return ReconProResult(
        target=target,
        modules_run=modules_run,
        findings=findings,
        severity_counts=sc,
        total_score=score,
        grade=grade,
        badge_markdown=badge_markdown,
        vibesec_score=vibesec_score,
        vibesec_grade=vibesec_grade,
        module_results=module_results,
    )


# ── SEV_COLORS and GRADE_COLORS completeness ──────────────────────────────


class TestSevColors(unittest.TestCase):
    """Test SEV_COLORS dictionary in cli module."""

    def test_has_five_entries(self):
        self.assertEqual(len(SEV_COLORS), 5)

    def test_covers_all_severities(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            self.assertIn(sev, SEV_COLORS)

    def test_critical_is_bright_red(self):
        self.assertEqual(SEV_COLORS["critical"], "bright_red")

    def test_info_is_dim(self):
        self.assertEqual(SEV_COLORS["info"], "dim")

    def test_values_are_strings(self):
        for v in SEV_COLORS.values():
            self.assertIsInstance(v, str)


class TestGradeColors(unittest.TestCase):
    """Test GRADE_COLORS dictionary in cli module."""

    def test_has_six_entries(self):
        self.assertEqual(len(GRADE_COLORS), 6)

    def test_covers_all_grades(self):
        for grade in ("A+", "A", "B", "C", "D", "F"):
            self.assertIn(grade, GRADE_COLORS)

    def test_values_are_strings(self):
        for v in GRADE_COLORS.values():
            self.assertIsInstance(v, str)


# ── _render_summary ────────────────────────────────────────────────────────


class TestRenderSummary(unittest.TestCase):
    """Test _render_summary with various score/grade combinations."""

    @patch("reconpro.cli.console")
    def test_perfect_score(self, mock_console):
        result = _make_result(score=100, grade="A+")
        _render_summary(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_zero_score(self, mock_console):
        result = _make_result(score=0, grade="F")
        _render_summary(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_mid_score(self, mock_console):
        result = _make_result(score=55, grade="C")
        _render_summary(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_custom_title(self, mock_console):
        result = _make_result(score=70, grade="B")
        _render_summary(result, title="CUSTOM")
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_with_vibesec(self, mock_console):
        result = _make_result(score=80, grade="A", vibesec_score=90, vibesec_grade="A+")
        _render_summary(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_unknown_grade_gets_color(self, mock_console):
        result = _make_result(score=50, grade="Z")
        _render_summary(result)
        self.assertTrue(mock_console.print.called)


# ── _render_findings_table ────────────────────────────────────────────────


class TestRenderFindingsTable(unittest.TestCase):
    """Test _render_findings_table with various finding sets."""

    @patch("reconpro.cli.console")
    def test_empty_findings(self, mock_console):
        result = _make_result(findings=[])
        _render_findings_table(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_single_finding(self, mock_console):
        findings = [
            {"title": "Test", "severity": "high", "category": "test",
             "module": "recon", "points_deducted": 10},
        ]
        result = _make_result(findings=findings)
        _render_findings_table(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_many_findings(self, mock_console):
        findings = [
            {"title": f"Finding {i}", "severity": s, "category": "c",
             "module": "m", "points_deducted": 5}
            for i, s in enumerate(["critical", "high", "medium", "low", "info"] * 20)
        ]
        result = _make_result(findings=findings)
        _render_findings_table(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_with_remediation_column(self, mock_console):
        findings = [
            {"title": "T", "severity": "high", "category": "c",
             "module": "m", "points_deducted": 10, "remediation": "Fix it"},
        ]
        result = _make_result(findings=findings)
        _render_findings_table(result, show_remediation=True)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_finding_with_no_severity_defaults_info(self, mock_console):
        findings = [{"title": "NoSev", "category": "c", "module": "m"}]
        result = _make_result(findings=findings)
        _render_findings_table(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_finding_title_truncated(self, mock_console):
        long_title = "A" * 200
        findings = [{"title": long_title, "severity": "info", "category": "c", "module": "m"}]
        result = _make_result(findings=findings)
        _render_findings_table(result)
        self.assertTrue(mock_console.print.called)


# ── _render_module_breakdown ──────────────────────────────────────────────


class TestRenderModuleBreakdown(unittest.TestCase):
    """Test _render_module_breakdown with various module results."""

    @patch("reconpro.cli.console")
    def test_no_module_results(self, mock_console):
        result = _make_result(module_results={})
        _render_module_breakdown(result)
        # Should return early, no print
        self.assertFalse(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_single_module_no_findings(self, mock_console):
        mr = {"recon": {"findings": []}}
        result = _make_result(module_results=mr)
        _render_module_breakdown(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_multiple_modules_with_findings(self, mock_console):
        mr = {
            "recon": {"findings": [
                {"severity": "critical"},
                {"severity": "high"},
            ]},
            "auth": {"findings": [{"severity": "medium"}]},
        }
        result = _make_result(module_results=mr)
        _render_module_breakdown(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_module_with_mixed_severities(self, mock_console):
        mr = {"recon": {"findings": [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]}}
        result = _make_result(module_results=mr)
        _render_module_breakdown(result)
        self.assertTrue(mock_console.print.called)


# ── _render_badge ───────────────────────────────────────────────────────────


class TestRenderBadge(unittest.TestCase):
    """Test _render_badge."""

    @patch("reconpro.cli.console")
    def test_with_badge(self, mock_console):
        result = _make_result(badge_markdown="![ReconPro A](url)")
        _render_badge(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_no_badge(self, mock_console):
        result = _make_result(badge_markdown="")
        _render_badge(result)
        self.assertFalse(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_none_badge(self, mock_console):
        result = _make_result(badge_markdown=None)
        _render_badge(result)
        self.assertFalse(mock_console.print.called)


# ── _render_remediations ───────────────────────────────────────────────────


class TestRenderRemediations(unittest.TestCase):
    """Test _render_remediations with/without actionable items."""

    @patch("reconpro.cli.console")
    def test_no_remediations(self, mock_console):
        result = _make_result(findings=[])
        _render_remediations(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_info_only_remediations_skipped(self, mock_console):
        findings = [
            {"severity": "info", "remediation": "Check docs", "points_deducted": 0},
        ]
        result = _make_result(findings=findings)
        _render_remediations(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_low_with_zero_points_skipped(self, mock_console):
        findings = [
            {"severity": "low", "remediation": "Low fix", "points_deducted": 0},
        ]
        result = _make_result(findings=findings)
        _render_remediations(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_critical_remediation(self, mock_console):
        findings = [
            {"severity": "critical", "remediation": "Patch immediately", "points_deducted": 30},
        ]
        result = _make_result(findings=findings)
        _render_remediations(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_duplicate_remediations_deduplicated(self, mock_console):
        findings = [
            {"severity": "critical", "remediation": "Same fix", "points_deducted": 30},
            {"severity": "high", "remediation": "Same fix", "points_deducted": 20},
        ]
        result = _make_result(findings=findings)
        _render_remediations(result)
        # Should print the deduplicated fix only once
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_empty_remediation_string(self, mock_console):
        findings = [
            {"severity": "critical", "remediation": "", "points_deducted": 30},
        ]
        result = _make_result(findings=findings)
        _render_remediations(result)
        # No actionable items since remediation is empty
        self.assertTrue(mock_console.print.called)


# ── _output_result ─────────────────────────────────────────────────────────


class TestOutputResult(unittest.TestCase):
    """Test _output_result with json_output=True/False and output_file."""

    @patch("reconpro.cli.save_scan")
    @patch("reconpro.cli.console")
    def test_json_output_no_file(self, mock_console, mock_save):
        result = _make_result()
        args = MagicMock()
        args.json_output = True
        args.output_file = None
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            _output_result(result, args)
            output = mock_stdout.getvalue()
            self.assertIn("example.com", output)
            self.assertIn("total_score", output)

    @patch("reconpro.cli.save_scan")
    @patch("reconpro.cli.console")
    def test_json_output_with_file(self, mock_console, mock_save, tmp_path=None):
        result = _make_result()
        import tempfile
        fd, tmpfile = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            args = MagicMock()
            args.json_output = True
            args.output_file = tmpfile
            _output_result(result, args)
            with open(tmpfile) as f:
                data = json.load(f)
            self.assertEqual(data["total_score"], 85)
        finally:
            os.unlink(tmpfile)

    @patch("reconpro.cli.save_scan")
    @patch("reconpro.cli.console")
    def test_rich_output_no_file(self, mock_console, mock_save):
        result = _make_result()
        args = MagicMock()
        args.json_output = False
        args.output_file = None
        _output_result(result, args)
        self.assertTrue(mock_console.print.called)
        mock_save.assert_called_once()

    @patch("reconpro.cli.save_scan")
    @patch("reconpro.cli.console")
    def test_rich_output_with_file(self, mock_console, mock_save):
        result = _make_result()
        import tempfile
        fd, tmpfile = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            args = MagicMock()
            args.json_output = False
            args.output_file = tmpfile
            _output_result(result, args)
            with open(tmpfile) as f:
                data = json.load(f)
            self.assertEqual(data["target"], "example.com")
        finally:
            os.unlink(tmpfile)

    @patch("reconpro.cli.save_scan")
    @patch("reconpro.cli.console")
    def test_show_remediation_flag(self, mock_console, mock_save):
        findings = [
            {"severity": "high", "remediation": "Fix now", "points_deducted": 20},
        ]
        result = _make_result(findings=findings)
        args = MagicMock()
        args.json_output = False
        args.output_file = None
        _output_result(result, args, show_remediation=True)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.save_scan")
    @patch("reconpro.cli.console")
    def test_custom_title(self, mock_console, mock_save):
        result = _make_result()
        args = MagicMock()
        args.json_output = False
        args.output_file = None
        _output_result(result, args, title="BLITZ")
        self.assertTrue(mock_console.print.called)


# ── _banner ────────────────────────────────────────────────────────────────


class TestBanner(unittest.TestCase):
    """Test _banner with json mode (should not print)."""

    @patch("reconpro.cli.console")
    def test_banner_prints_in_normal_mode(self, mock_console):
        args = MagicMock()
        args.json_output = False
        _banner(args)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_banner_suppressed_in_json_mode(self, mock_console):
        args = MagicMock()
        args.json_output = True
        _banner(args)
        self.assertFalse(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_banner_with_none_args(self, mock_console):
        with patch("reconpro.cli._cli_args", None):
            _banner(None)
            # _cli_args is None, so getattr returns None, then json_output is False
            self.assertTrue(mock_console.print.called)


# ── Edge cases ─────────────────────────────────────────────────────────────


class TestCliEdgeCases(unittest.TestCase):
    """Edge cases for CLI rendering functions."""

    @patch("reconpro.cli.console")
    def test_score_zero_bar_empty(self, mock_console):
        result = _make_result(score=0, grade="F")
        _render_summary(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_score_100_bar_full(self, mock_console):
        result = _make_result(score=100, grade="A+")
        _render_summary(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_no_modules_run(self, mock_console):
        result = _make_result(modules_run=[])
        _render_summary(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.console")
    def test_large_finding_list_truncated(self, mock_console):
        findings = [{"title": f"F{i}", "severity": "info", "category": "c",
                      "module": "m"} for i in range(100)]
        result = _make_result(findings=findings)
        _render_findings_table(result)
        self.assertTrue(mock_console.print.called)

    @patch("reconpro.cli.save_scan")
    @patch("reconpro.cli.console")
    def test_output_result_missing_args_attributes(self, mock_console, mock_save):
        """Verify getattr defaults work when args lacks attributes."""
        result = _make_result()
        args = MagicMock(spec=[])  # No attributes
        # This should not raise due to getattr with defaults
        _output_result(result, args)
        self.assertTrue(mock_console.print.called)


class TestRichMarkupEscaping(unittest.TestCase):
    """Dynamic text interpolated into console.print must never be parsed
    as Rich markup (terminal content-spoofing vector).

    Regression for the fix where a plugin-create error message containing
    the manifest id regex ``[a-z0-9][a-z0-9_-]`` was silently stripped by
    the Rich tag parser, and hostile input like ``[red]FAKE[/]`` could
    inject fake colored output.
    """

    def test_escape_neutralizes_markup_tags(self):
        from reconpro.lazy_rich import escape
        hostile = "[red]FAKE-PASS[/green] [bold]pwned"
        out = escape(hostile)
        # After escaping, Rich renders the literal brackets, never tags:
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        c = Console(file=buf, force_terminal=False, no_color=True)
        c.print(out)
        rendered = buf.getvalue()
        self.assertIn("[red]", rendered)      # tag text survives literally
        self.assertIn("FAKE-PASS", rendered)  # content intact
        # Rich only strips *unescaped* tags; the escaped form keeps them:
        c2 = Console(file=StringIO(), force_terminal=False, no_color=True)
        escaped_buf = c2.file
        c2.print(escape("[bold]x"))
        self.assertIn("[bold]", escaped_buf.getvalue())

    def test_escape_preserves_plain_text(self):
        from reconpro.lazy_rich import escape
        self.assertEqual(escape("plain text 123"), "plain text 123")

    def test_escape_is_idempotent_for_safe_text(self):
        from reconpro.lazy_rich import escape
        safe = "no tags here"
        self.assertEqual(escape(escape(safe)), escape(safe))

    def test_plugin_error_messages_escape_exceptions(self):
        """The plugin command error paths must route through escape()."""
        import reconpro.cli as cli_mod
        src = open(cli_mod.__file__, encoding="utf-8").read()
        # every "X failed: {exc}" print must wrap exc in escape()
        import re as _re
        bad = [m for m in _re.finditer(
            r'console\.print\(f"[^"]*failed: \{exc\}"', src)]
        self.assertEqual(
            bad, [],
            "unescaped {exc} interpolation found in console.print — "
            "wrap with escape(str(exc))")


if __name__ == "__main__":
    unittest.main()

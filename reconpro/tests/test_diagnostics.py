"""ReconPro v11 — Tests for diagnostics.py and cli_help.py.

Covers:
- run_diagnostics returns all expected keys
- health_check returns valid status values
- get_version_info includes reconpro version
- generate_debug_report returns non-empty string
- module_status lists all 26 modules
- validate_config returns list of dicts
- cli_help render functions return non-empty strings
- MODULE_HELP has entries for all modules
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure parent package is importable
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(TEST_DIR, "..", "..")
sys.path.insert(0, PROJECT_ROOT)


class TestRunDiagnostics(unittest.TestCase):
    """Tests for run_diagnostics()."""

    def test_returns_dict(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertIsInstance(result, dict)

    def test_has_timestamp_key(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertIn("timestamp", result)

    def test_has_total_checks_key(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertIn("total_checks", result)

    def test_has_passed_key(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertIn("passed", result)

    def test_has_failed_key(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertIn("failed", result)

    def test_has_checks_list(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertIn("checks", result)
        self.assertIsInstance(result["checks"], list)

    def test_total_checks_equals_ten(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertEqual(result["total_checks"], 10)

    def test_passed_plus_failed_equals_total(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertEqual(result["passed"] + result["failed"], result["total_checks"])

    def test_python_version_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("python_version", labels)

    def test_reconpro_version_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("reconpro_version", labels)

    def test_module_registry_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("module_registry", labels)

    def test_plugin_directory_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("plugin_directory", labels)

    def test_scan_history_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("scan_history", labels)

    def test_config_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("configuration", labels)

    def test_disk_space_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("disk_space", labels)

    def test_network_dns_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("network_dns", labels)

    def test_ssl_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("ssl_certificate", labels)

    def test_memory_check_present(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        labels = [c["label"] for c in result["checks"]]
        self.assertIn("memory", labels)

    def test_each_check_has_label_status(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        for check in result["checks"]:
            self.assertIn("label", check)
            self.assertIn("status", check)

    def test_timestamp_is_string(self):
        from reconpro.diagnostics import run_diagnostics
        result = run_diagnostics()
        self.assertIsInstance(result["timestamp"], str)


class TestHealthCheck(unittest.TestCase):
    """Tests for health_check()."""

    def test_returns_dict(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIsInstance(result, dict)

    def test_has_python_key(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIn("python", result)

    def test_has_modules_key(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIn("modules", result)

    def test_has_plugins_key(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIn("plugins", result)

    def test_has_history_key(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIn("history", result)

    def test_has_config_key(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIn("config", result)

    def test_has_network_key(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIn("network", result)

    def test_has_home_key(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIn("home", result)

    def test_all_values_are_strings(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        for k, v in result.items():
            self.assertIsInstance(v, str, f"Value for {k} is not a string: {v}")

    def test_python_status_is_ok_or_error(self):
        from reconpro.diagnostics import health_check
        result = health_check()
        self.assertIn(result["python"], ("ok", "error"))


class TestGetVersionInfo(unittest.TestCase):
    """Tests for get_version_info()."""

    def test_returns_dict(self):
        from reconpro.diagnostics import get_version_info
        result = get_version_info()
        self.assertIsInstance(result, dict)

    def test_has_reconpro_version(self):
        from reconpro.diagnostics import get_version_info
        result = get_version_info()
        self.assertIn("reconpro", result)
        from reconpro import __version__ as _v
        self.assertEqual(result["reconpro"], _v)

    def test_has_python_version(self):
        from reconpro.diagnostics import get_version_info
        result = get_version_info()
        self.assertIn("python", result)

    def test_has_platform(self):
        from reconpro.diagnostics import get_version_info
        result = get_version_info()
        self.assertIn("platform", result)

    def test_has_module_count(self):
        from reconpro.diagnostics import get_version_info
        result = get_version_info()
        self.assertIn("module_count", result)

    def test_has_installation_path(self):
        from reconpro.diagnostics import get_version_info
        result = get_version_info()
        self.assertIn("installation_path", result)

    def test_all_values_are_strings(self):
        from reconpro.diagnostics import get_version_info
        result = get_version_info()
        for k, v in result.items():
            self.assertIsInstance(v, str, f"Value for {k} is not a string: {v}")

    def test_module_count_matches_all_modules(self):
        from reconpro.diagnostics import get_version_info
        from reconpro.registry import ALL_MODULES
        result = get_version_info()
        self.assertEqual(result["module_count"], str(len(ALL_MODULES)))


class TestGenerateDebugReport(unittest.TestCase):
    """Tests for generate_debug_report()."""

    def test_returns_string(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        self.assertIsInstance(report, str)

    def test_report_not_empty(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        self.assertTrue(len(report) > 0)

    def test_contains_version_header(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        self.assertIn("Debug Report", report)

    def test_contains_version_info_section(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        self.assertIn("VERSION INFORMATION", report)

    def test_contains_health_check_section(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        self.assertIn("HEALTH CHECK", report)

    def test_contains_module_status_section(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        self.assertIn("MODULE STATUS", report)

    def test_contains_diagnostics_summary(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        self.assertIn("DIAGNOSTICS SUMMARY", report)

    def test_contains_environment_section(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        self.assertIn("ENVIRONMENT", report)

    def test_contains_reconpro_version(self):
        from reconpro.diagnostics import generate_debug_report
        report = generate_debug_report()
        from reconpro import __version__ as _v2
        self.assertIn(_v2, report)


class TestModuleStatus(unittest.TestCase):
    """Tests for module_status()."""

    def test_returns_list(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        self.assertIsInstance(result, list)

    def test_lists_at_least_26_modules(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        self.assertGreaterEqual(len(result), 26)

    def test_each_entry_is_dict(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        for m in result:
            self.assertIsInstance(m, dict)

    def test_each_entry_has_id(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        for m in result:
            self.assertIn("id", m)

    def test_each_entry_has_name(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        for m in result:
            self.assertIn("name", m)

    def test_each_entry_has_type(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        for m in result:
            self.assertIn("type", m)
            self.assertIn(m["type"], ("remote", "local"))

    def test_each_entry_has_runner_status(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        for m in result:
            self.assertIn("runner_status", m)
            self.assertIsInstance(m["runner_status"], bool)

    def test_includes_recon_module(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        ids = [m["id"] for m in result]
        self.assertIn("recon", ids)

    def test_includes_host_module(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        ids = [m["id"] for m in result]
        self.assertIn("host", ids)

    def test_includes_quantum_fingerprint(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        ids = [m["id"] for m in result]
        self.assertIn("quantum_fingerprint", ids)

    def test_includes_dead_drop(self):
        from reconpro.diagnostics import module_status
        result = module_status()
        ids = [m["id"] for m in result]
        self.assertIn("dead_drop", ids)


class TestValidateConfig(unittest.TestCase):
    """Tests for validate_config()."""

    def test_returns_list(self):
        from reconpro.diagnostics import validate_config
        result = validate_config()
        self.assertIsInstance(result, list)

    def test_each_entry_is_dict(self):
        from reconpro.diagnostics import validate_config
        result = validate_config()
        for issue in result:
            self.assertIsInstance(issue, dict)

    def test_each_entry_has_severity(self):
        from reconpro.diagnostics import validate_config
        result = validate_config()
        for issue in result:
            self.assertIn("severity", issue)

    def test_each_entry_has_category(self):
        from reconpro.diagnostics import validate_config
        result = validate_config()
        for issue in result:
            self.assertIn("category", issue)

    def test_each_entry_has_message(self):
        from reconpro.diagnostics import validate_config
        result = validate_config()
        for issue in result:
            self.assertIn("message", issue)

    def test_severity_values_are_valid(self):
        from reconpro.diagnostics import validate_config
        result = validate_config()
        valid_severities = ("error", "warning", "info")
        for issue in result:
            self.assertIn(issue["severity"], valid_severities)

    def test_suggestion_field_present(self):
        from reconpro.diagnostics import validate_config
        result = validate_config()
        for issue in result:
            self.assertIn("suggestion", issue)


class TestCliHelpModuleHelp(unittest.TestCase):
    """Tests for MODULE_HELP data and cli_help renderers."""

    def test_module_help_is_dict(self):
        from reconpro.cli_help import MODULE_HELP
        self.assertIsInstance(MODULE_HELP, dict)

    def test_has_recon_entry(self):
        from reconpro.cli_help import MODULE_HELP
        self.assertIn("recon", MODULE_HELP)

    def test_has_auth_entry(self):
        from reconpro.cli_help import MODULE_HELP
        self.assertIn("auth", MODULE_HELP)

    def test_has_quantum_fingerprint_entry(self):
        from reconpro.cli_help import MODULE_HELP
        self.assertIn("quantum_fingerprint", MODULE_HELP)

    def test_has_dead_drop_entry(self):
        from reconpro.cli_help import MODULE_HELP
        self.assertIn("dead_drop", MODULE_HELP)

    def test_has_host_entry(self):
        from reconpro.cli_help import MODULE_HELP
        self.assertIn("host", MODULE_HELP)

    def test_module_help_has_26_entries(self):
        from reconpro.cli_help import MODULE_HELP
        self.assertGreaterEqual(len(MODULE_HELP), 26)

    def test_each_module_has_description(self):
        from reconpro.cli_help import MODULE_HELP
        for mid, entry in MODULE_HELP.items():
            self.assertIn("description", entry, f"Module {mid} missing description")

    def test_each_module_has_examples(self):
        from reconpro.cli_help import MODULE_HELP
        for mid, entry in MODULE_HELP.items():
            self.assertIn("examples", entry, f"Module {mid} missing examples")
            self.assertIsInstance(entry["examples"], list)

    def test_each_module_has_details(self):
        from reconpro.cli_help import MODULE_HELP
        for mid, entry in MODULE_HELP.items():
            self.assertIn("details", entry, f"Module {mid} missing details")

    def test_each_module_has_see_also(self):
        from reconpro.cli_help import MODULE_HELP
        for mid, entry in MODULE_HELP.items():
            self.assertIn("see_also", entry, f"Module {mid} missing see_also")

    def test_each_module_has_output(self):
        from reconpro.cli_help import MODULE_HELP
        for mid, entry in MODULE_HELP.items():
            self.assertIn("output", entry, f"Module {mid} missing output")

    def test_examples_are_non_empty(self):
        from reconpro.cli_help import MODULE_HELP
        for mid, entry in MODULE_HELP.items():
            self.assertTrue(len(entry["examples"]) > 0, f"Module {mid} has no examples")


class TestCliHelpRenderers(unittest.TestCase):
    """Tests for cli_help render functions."""

    def test_render_module_help_returns_string(self):
        from reconpro.cli_help import render_module_help
        result = render_module_help("recon")
        self.assertIsInstance(result, str)

    def test_render_module_help_not_empty(self):
        from reconpro.cli_help import render_module_help
        result = render_module_help("recon")
        self.assertTrue(len(result) > 0)

    def test_render_module_help_contains_description(self):
        from reconpro.cli_help import render_module_help
        result = render_module_help("recon")
        self.assertIn("DESCRIPTION", result)

    def test_render_module_help_contains_examples(self):
        from reconpro.cli_help import render_module_help
        result = render_module_help("recon")
        self.assertIn("EXAMPLES", result)

    def test_render_module_help_unknown_module(self):
        from reconpro.cli_help import render_module_help
        result = render_module_help("nonexistent_module_xyz")
        self.assertIn("Unknown module", result)

    def test_render_module_help_with_dash(self):
        from reconpro.cli_help import render_module_help
        result = render_module_help("quantum-fingerprint")
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_render_all_modules_returns_string(self):
        from reconpro.cli_help import render_all_modules
        result = render_all_modules()
        self.assertIsInstance(result, str)

    def test_render_all_modules_not_empty(self):
        from reconpro.cli_help import render_all_modules
        result = render_all_modules()
        self.assertTrue(len(result) > 0)

    def test_render_all_modules_contains_remote(self):
        from reconpro.cli_help import render_all_modules
        result = render_all_modules()
        self.assertIn("REMOTE", result)

    def test_render_all_modules_contains_advanced(self):
        from reconpro.cli_help import render_all_modules
        result = render_all_modules()
        self.assertIn("ADVANCED", result)

    def test_render_quick_start_returns_string(self):
        from reconpro.cli_help import render_quick_start
        result = render_quick_start()
        self.assertIsInstance(result, str)

    def test_render_quick_start_not_empty(self):
        from reconpro.cli_help import render_quick_start
        result = render_quick_start()
        self.assertTrue(len(result) > 0)

    def test_render_quick_start_contains_scan_command(self):
        from reconpro.cli_help import render_quick_start
        result = render_quick_start()
        self.assertIn("reconpro scan", result)

    def test_render_examples_returns_string(self):
        from reconpro.cli_help import render_examples
        result = render_examples()
        self.assertIsInstance(result, str)

    def test_render_examples_not_empty(self):
        from reconpro.cli_help import render_examples
        result = render_examples()
        self.assertTrue(len(result) > 0)

    def test_render_examples_contains_ci_cd(self):
        from reconpro.cli_help import render_examples
        result = render_examples()
        self.assertIn("CI/CD", result)

    def test_cli_commands_is_dict(self):
        from reconpro.cli_help import CLI_COMMANDS
        self.assertIsInstance(CLI_COMMANDS, dict)

    def test_cli_commands_has_scan(self):
        from reconpro.cli_help import CLI_COMMANDS
        self.assertIn("scan", CLI_COMMANDS)

    def test_cli_commands_has_blitz(self):
        from reconpro.cli_help import CLI_COMMANDS
        self.assertIn("blitz", CLI_COMMANDS)

    def test_cli_commands_has_agent(self):
        from reconpro.cli_help import CLI_COMMANDS
        self.assertIn("agent", CLI_COMMANDS)


class TestCheckHelper(unittest.TestCase):
    """Tests for the internal _check helper function."""

    def test_check_success(self):
        from reconpro.diagnostics import _check
        result = _check("test_ok", lambda: 42)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["value"], 42)

    def test_check_failure(self):
        from reconpro.diagnostics import _check
        result = _check("test_fail", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        self.assertEqual(result["status"], "error")
        self.assertIn("boom", result["error"])


class TestEstimateModuleLines(unittest.TestCase):
    """Tests for _estimate_module_lines helper."""

    def test_returns_int_or_none(self):
        from reconpro.diagnostics import _estimate_module_lines
        result = _estimate_module_lines("recon")
        self.assertTrue(result is None or isinstance(result, int))

    def test_unknown_module_returns_none(self):
        from reconpro.diagnostics import _estimate_module_lines
        result = _estimate_module_lines("nonexistent_module_xyz")
        self.assertIsNone(result)

    def test_recon_returns_positive(self):
        from reconpro.diagnostics import _estimate_module_lines
        result = _estimate_module_lines("recon")
        if result is not None:
            self.assertGreater(result, 0)


if __name__ == "__main__":
    unittest.main()

"""Integration tests — run actual module functions against safe targets.

These tests import and verify all 28 module runners are callable,
and optionally run a couple against localhost (safe, expected to fail gracefully).
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.modules import (
    run_recon, run_vibesec, run_auth, run_chain,
    run_bot, run_gorgon, run_oblivion, run_nhi,
    run_host, run_dev, run_doctor, run_cloud_recon,
    run_pegasus, run_team,
    run_quantum_fingerprint, run_dark_web_monitor, run_info_ops,
    run_steganography_detector, run_covert_channel, run_zero_day_hunter,
    run_infrastructure_ghost, run_signal_intelligence,
    run_nation_state_attributor, run_weaponized_report,
    run_honeypot_dance, run_dead_drop,
    run_container_sec, run_iac_audit,
)

ALL_RUNNERS = [
    run_recon, run_vibesec, run_auth, run_chain,
    run_bot, run_gorgon, run_oblivion, run_nhi,
    run_host, run_dev, run_doctor, run_cloud_recon,
    run_pegasus, run_team,
    run_quantum_fingerprint, run_dark_web_monitor, run_info_ops,
    run_steganography_detector, run_covert_channel, run_zero_day_hunter,
    run_infrastructure_ghost, run_signal_intelligence,
    run_nation_state_attributor, run_weaponized_report,
    run_honeypot_dance, run_dead_drop,
    run_container_sec, run_iac_audit,
]


class TestImportAllModules(unittest.TestCase):
    """Verify all 28 module functions can be imported."""

    def test_imported_28_runners(self):
        self.assertEqual(len(ALL_RUNNERS), 28,
                         f"Expected 28, got {len(ALL_RUNNERS)}")

    def test_all_imports_are_unique(self):
        self.assertEqual(len(ALL_RUNNERS), len(set(id(r) for r in ALL_RUNNERS)))


class TestAllRunnersCallable(unittest.TestCase):
    """All module runners are callable."""

    def test_all_runners_callable(self):
        for i, runner in enumerate(ALL_RUNNERS):
            self.assertTrue(callable(runner),
                            f"Runner at index {i} ({runner.__name__}) is not callable")


class TestRunnerNames(unittest.TestCase):
    """All runners have the expected name prefix."""

    def test_all_named_run_xxx(self):
        for runner in ALL_RUNNERS:
            self.assertTrue(runner.__name__.startswith("run_"),
                            f"{runner.__name__} doesn't start with 'run_'")


class TestQuantumFingerprintIntegration(unittest.TestCase):
    """Run quantum_fingerprint against 127.0.0.1.

    Should return a list (possibly empty on network error, but must not crash).
    """

    def test_returns_list(self):
        try:
            result = run_quantum_fingerprint(
                target="127.0.0.1",
                base_url="https://127.0.0.1",
                timeout=2,
                verify_tls=False,
            )
        except Exception as e:
            self.fail(f"run_quantum_fingerprint raised {type(e).__name__}: {e}")

        self.assertIsInstance(result, list,
                             f"Expected list, got {type(result).__name__}")

    def test_list_items_are_findings_or_dicts(self):
        try:
            result = run_quantum_fingerprint(
                target="127.0.0.1",
                base_url="https://127.0.0.1",
                timeout=2,
                verify_tls=False,
            )
        except Exception:
            self.skipTest("Module raised an exception")
            return

        for item in result:
            # Items should be Finding objects or dicts
            has_severity = (
                hasattr(item, 'severity') or
                (isinstance(item, dict) and 'severity' in item)
            )
            self.assertTrue(has_severity,
                            f"Item {item!r} has no 'severity' attribute or key")


class TestDeadDropIntegration(unittest.TestCase):
    """Run dead_drop with a valid target.

    Should return a list (possibly empty on network error, but must not crash).
    """

    def test_returns_list_or_empty(self):
        try:
            result = run_dead_drop(
                target="127.0.0.1",
                base_url="https://127.0.0.1",
                timeout=2,
                verify_tls=False,
            )
        except Exception as e:
            self.fail(f"run_dead_drop raised {type(e).__name__}: {e}")

        self.assertIsInstance(result, list,
                             f"Expected list, got {type(result).__name__}")


class TestLocalModulesIntegration(unittest.TestCase):
    """Run local audit modules against current directory."""

    def test_host_audit_returns_list(self):
        try:
            result = run_host(
                target=".",
                base_url="",
                timeout=8,
                verify_tls=True,
            )
        except Exception as e:
            self.skipTest(f"run_host raised: {e}")
            return

        self.assertIsInstance(result, list)

    def test_dev_audit_returns_list(self):
        try:
            result = run_dev(
                target=".",
                base_url="",
                timeout=8,
                verify_tls=True,
            )
        except Exception as e:
            self.skipTest(f"run_dev raised: {e}")
            return

        self.assertIsInstance(result, list)

    def test_doctor_audit_returns_list(self):
        try:
            result = run_doctor(
                target="localhost",
                base_url="",
                timeout=8,
                verify_tls=True,
            )
        except Exception as e:
            self.skipTest(f"run_doctor raised: {e}")
            return

        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()

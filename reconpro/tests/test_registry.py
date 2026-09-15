"""Tests for reconpro.registry — module registry."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.registry import (
    MODULE_REGISTRY,
    LOCAL_MODULES,
    ALL_MODULES,
    DEFAULT_MODULES,
    DEFAULT_LOCAL_MODULES,
    get_module_runner,
    is_local_module,
    is_remote_module,
)


class TestModuleRegistryCount(unittest.TestCase):
    """Test MODULE_REGISTRY entry count (11 core + 12 advanced + 2 orphaned = 25)."""

    def test_module_registry_has_correct_count(self):
        # 11 core + 12 advanced + 2 orphaned = 25 remote modules
        self.assertEqual(len(MODULE_REGISTRY), 25,
                         f"Expected 25, got {len(MODULE_REGISTRY)}: {list(MODULE_REGISTRY.keys())}")


class TestLocalModulesCount(unittest.TestCase):
    """Test that LOCAL_MODULES has exactly 3 entries."""

    def test_local_modules_has_3_entries(self):
        self.assertEqual(len(LOCAL_MODULES), 3)

    def test_local_modules_are_host_dev_doctor(self):
        expected = {"host", "dev", "doctor"}
        self.assertEqual(set(LOCAL_MODULES.keys()), expected)


class TestAllModulesCount(unittest.TestCase):
    """Test ALL_MODULES count (25 remote + 3 local = 28)."""

    def test_all_modules_count(self):
        # 25 remote + 3 local = 28 total
        self.assertEqual(len(ALL_MODULES), 28)


class TestDefaultModulesCount(unittest.TestCase):
    """Test that DEFAULT_MODULES has 20 entries."""

    def test_default_modules_has_20_entries(self):
        self.assertEqual(len(DEFAULT_MODULES), 20)

    def test_default_local_modules_has_3_entries(self):
        self.assertEqual(len(DEFAULT_LOCAL_MODULES), 3)


class TestRegistryEntryStructure(unittest.TestCase):
    """Test that every entry in MODULE_REGISTRY has required keys."""

    def test_all_entries_have_name(self):
        for mod_id, entry in MODULE_REGISTRY.items():
            self.assertIn("name", entry, f"{mod_id} missing 'name'")

    def test_all_entries_have_runner(self):
        for mod_id, entry in MODULE_REGISTRY.items():
            self.assertIn("runner", entry, f"{mod_id} missing 'runner'")

    def test_all_entries_have_color(self):
        for mod_id, entry in MODULE_REGISTRY.items():
            self.assertIn("color", entry, f"{mod_id} missing 'color'")


class TestRunnersAreCallable(unittest.TestCase):
    """Test that every runner in MODULE_REGISTRY is callable."""

    def test_all_registry_runners_callable(self):
        for mod_id, entry in MODULE_REGISTRY.items():
            runner = entry["runner"]
            self.assertIsNotNone(runner, f"{mod_id} has runner=None")
            self.assertTrue(callable(runner), f"{mod_id} runner is not callable")

    def test_all_local_runners_callable(self):
        for mod_id, entry in LOCAL_MODULES.items():
            runner = entry["runner"]
            self.assertIsNotNone(runner, f"{mod_id} has runner=None")
            self.assertTrue(callable(runner), f"{mod_id} runner is not callable")


class TestGetModuleRunner(unittest.TestCase):
    """Test get_module_runner function."""

    def test_returns_runner_for_known_module(self):
        runner = get_module_runner("recon")
        self.assertIsNotNone(runner)
        self.assertTrue(callable(runner))

    def test_returns_runner_for_local_module(self):
        runner = get_module_runner("host")
        self.assertIsNotNone(runner)
        self.assertTrue(callable(runner))

    def test_returns_none_for_unknown_module(self):
        runner = get_module_runner("nonexistent_module_xyz")
        self.assertIsNone(runner)

    def test_returns_none_for_empty_string(self):
        runner = get_module_runner("")
        self.assertIsNone(runner)


class TestIsLocalIsRemote(unittest.TestCase):
    """Test is_local_module and is_remote_module."""

    def test_host_is_local(self):
        self.assertTrue(is_local_module("host"))

    def test_dev_is_local(self):
        self.assertTrue(is_local_module("dev"))

    def test_doctor_is_local(self):
        self.assertTrue(is_local_module("doctor"))

    def test_recon_is_remote(self):
        self.assertTrue(is_remote_module("recon"))

    def test_recon_is_not_local(self):
        self.assertFalse(is_local_module("recon"))

    def test_host_is_not_remote(self):
        self.assertFalse(is_remote_module("host"))

    def test_unknown_is_neither(self):
        self.assertFalse(is_local_module("unknown"))
        self.assertFalse(is_remote_module("unknown"))


class TestNoRunnerNone(unittest.TestCase):
    """Ensure no module has runner=None (vibesec is now a real runner)."""

    def test_no_none_runners_in_registry(self):
        for mod_id, entry in MODULE_REGISTRY.items():
            self.assertIsNotNone(entry["runner"],
                                 f"{mod_id} has runner=None")

    def test_no_none_runners_in_local(self):
        for mod_id, entry in LOCAL_MODULES.items():
            self.assertIsNotNone(entry["runner"],
                                 f"{mod_id} has runner=None")


class TestDefaultModulesAreInRegistry(unittest.TestCase):
    """Ensure all DEFAULT_MODULES entries exist in MODULE_REGISTRY."""

    def test_default_modules_in_registry(self):
        for mod_id in DEFAULT_MODULES:
            self.assertIn(mod_id, MODULE_REGISTRY,
                          f"{mod_id} in DEFAULT_MODULES but not in MODULE_REGISTRY")

    def test_default_local_modules_in_local(self):
        for mod_id in DEFAULT_LOCAL_MODULES:
            self.assertIn(mod_id, LOCAL_MODULES,
                          f"{mod_id} in DEFAULT_LOCAL_MODULES but not in LOCAL_MODULES")


if __name__ == "__main__":
    unittest.main()

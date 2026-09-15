"""Tests for reconpro.plugins — plugin and hook system."""

from pathlib import Path
import sys
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.plugins import HookManager, create_plugin_template, PLUGIN_DIR


class TestHookManagerRegister(unittest.TestCase):
    """Test HookManager.register."""

    def setUp(self):
        HookManager.clear()

    def tearDown(self):
        HookManager.clear()

    def test_valid_hook_returns_true(self):
        result = HookManager.register("pre_scan", lambda t, u, m: None)
        self.assertTrue(result)

    def test_invalid_hook_returns_false(self):
        result = HookManager.register("nonexistent_hook", lambda: None)
        self.assertFalse(result)

    def test_all_valid_hook_names_accepted(self):
        for hook_name in HookManager.HOOK_NAMES:
            result = HookManager.register(hook_name, lambda: None)
            self.assertTrue(result, f"Failed to register {hook_name}")

    def test_register_multiple_callbacks(self):
        HookManager.register("pre_scan", lambda: None, priority=10)
        HookManager.register("pre_scan", lambda: None, priority=5)
        hooks = HookManager.list_hooks()
        self.assertEqual(hooks["pre_scan"], 2)


class TestHookManagerFire(unittest.TestCase):
    """Test HookManager.fire."""

    def setUp(self):
        HookManager.clear()

    def tearDown(self):
        HookManager.clear()

    def test_fire_calls_callbacks_in_priority_order(self):
        call_order = []
        HookManager.register("post_scan", lambda *a, **k: call_order.append(2), priority=20)
        HookManager.register("post_scan", lambda *a, **k: call_order.append(1), priority=10)
        HookManager.register("post_scan", lambda *a, **k: call_order.append(3), priority=30)

        HookManager.fire("post_scan", "target", [], 100)
        self.assertEqual(call_order, [1, 2, 3])

    def test_fire_short_circuits_on_non_none(self):
        called_second = []
        HookManager.register("pre_finding", lambda f: "modified_finding", priority=10)
        HookManager.register("pre_finding", lambda f: called_second.append(True), priority=20)

        result = HookManager.fire("pre_finding", {"title": "test"})
        self.assertEqual(result, "modified_finding")
        self.assertEqual(called_second, [])  # second callback not called

    def test_fire_returns_none_when_all_none(self):
        HookManager.register("post_scan", lambda *a, **k: None)
        result = HookManager.fire("post_scan")
        self.assertIsNone(result)

    def test_fire_no_callbacks_returns_none(self):
        result = HookManager.fire("pre_scan")
        self.assertIsNone(result)

    def test_fire_exception_ignored(self):
        def bad_callback(*args, **kwargs):
            raise RuntimeError("boom")
        HookManager.register("post_scan", bad_callback)
        # Should not raise
        result = HookManager.fire("post_scan")
        self.assertIsNone(result)


class TestHookManagerClear(unittest.TestCase):
    """Test HookManager.clear."""

    def setUp(self):
        HookManager.clear()

    def tearDown(self):
        HookManager.clear()

    def test_clear_specific_hook(self):
        HookManager.register("pre_scan", lambda: None)
        HookManager.register("post_scan", lambda: None)
        HookManager.clear("pre_scan")
        hooks = HookManager.list_hooks()
        self.assertNotIn("pre_scan", hooks)
        self.assertIn("post_scan", hooks)

    def test_clear_all_hooks(self):
        HookManager.register("pre_scan", lambda: None)
        HookManager.register("post_scan", lambda: None)
        HookManager.clear()
        hooks = HookManager.list_hooks()
        self.assertEqual(hooks, {})

    def test_clear_nonexistent_hook_no_error(self):
        HookManager.clear("nonexistent")  # Should not raise


class TestHookManagerUnregister(unittest.TestCase):
    """Test HookManager.unregister."""

    def setUp(self):
        HookManager.clear()

    def tearDown(self):
        HookManager.clear()

    def test_unregister_removes_specific_callback(self):
        cb = lambda: None  # noqa: E731
        HookManager.register("pre_scan", cb)
        HookManager.unregister("pre_scan", cb)
        hooks = HookManager.list_hooks()
        self.assertEqual(hooks.get("pre_scan", 0), 0)

    def test_unregister_nonexistent_hook_returns_false(self):
        result = HookManager.unregister("nonexistent", lambda: None)
        self.assertFalse(result)


class TestCreatePluginTemplate(unittest.TestCase):
    """Test create_plugin_template creates a valid Python file."""

    def _make_tmp_dir(self):
        d = tempfile.mkdtemp()
        return Path(d)

    def test_creates_valid_python_file(self):
        tmp = self._make_tmp_dir()
        try:
            with patch('reconpro.plugins.PLUGIN_DIR', tmp):
                with patch('reconpro.plugins._ensure_plugin_dir'):
                    path = create_plugin_template("test_plugin")

            self.assertTrue(os.path.exists(str(path)))
            self.assertTrue(str(path).endswith("test_plugin.py"))

            with open(path, "r") as f:
                content = f.read()
            self.assertIn("def run(", content)
            self.assertIn("Finding", content)
            compile(content, str(path), "exec")
        finally:
            import shutil
            shutil.rmtree(str(tmp), ignore_errors=True)

    def test_template_has_correct_name(self):
        tmp = self._make_tmp_dir()
        try:
            with patch('reconpro.plugins.PLUGIN_DIR', tmp):
                with patch('reconpro.plugins._ensure_plugin_dir'):
                    path = create_plugin_template("my_scanner")

            with open(path, "r") as f:
                content = f.read()
            self.assertIn("MY_SCANNER", content)
            self.assertIn("my_scanner", content)
        finally:
            import shutil
            shutil.rmtree(str(tmp), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

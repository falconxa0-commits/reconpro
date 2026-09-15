"""Tests for reconpro.interfaces, reconpro.context, and registry enhancements."""

import sys
import os
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.interfaces import (
    ScanModule,
    FindingProcessor,
    ReportGenerator,
    PluginInterface,
    EventEmitter,
    ConfigurationProvider,
    Findings,
    ScanResult,
    Severity,
    Grade,
    Target,
    ModuleID,
)
from reconpro.context import ScanContext, create_context
from reconpro.registry import (
    get_module_info,
    list_remote_modules,
    list_local_modules,
    get_module_color,
    MODULE_REGISTRY,
    LOCAL_MODULES,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _fake_scan_module(target: str, base_url: str, timeout: int = 8,
                       verify_tls: bool = True) -> list:
    """A simple function matching the ScanModule signature."""
    return [{"target": target, "base_url": base_url}]


def _fake_processor(findings: list) -> list:
    """A simple finding processor."""
    return [f for f in findings if f.get("severity") != "info"]


def _fake_report_generator(data: dict, output_path: str) -> str:
    """A simple report generator."""
    return output_path


class _FakeEventEmitter:
    """A concrete class implementing EventEmitter protocol."""
    def __init__(self):
        self._handlers = {}

    def emit(self, event_type: str, **kwargs):
        results = []
        for cb in self._handlers.get(event_type, []):
            results.append(cb(**kwargs))
        return results

    def on(self, event_type: str, callback):
        self._handlers.setdefault(event_type, []).append(callback)

    def off(self, event_type: str, callback):
        if event_type in self._handlers:
            self._handlers[event_type] = [
                cb for cb in self._handlers[event_type] if cb != callback
            ]


class _FakeConfigProvider:
    """A concrete class implementing ConfigurationProvider protocol."""
    def __init__(self):
        self._store = {}

    def get(self, key: str, default=None):
        return self._store.get(key, default)

    def set(self, key: str, value):
        self._store[key] = value

    def has(self, key: str) -> bool:
        return key in self._store


class _ConcretePlugin(PluginInterface):
    """A concrete implementation of PluginInterface ABC."""
    def __init__(self, name: str = "test-plugin", description: str = "A test plugin"):
        self._name = name
        self._description = description

    def run(self, target: str, base_url: str = "", timeout: int = 8,
            verify_tls: bool = True) -> list:
        return [{"target": target, "plugin": self._name}]

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description


# ══════════════════════════════════════════════════════════════════════════
# ScanModule Protocol Tests
# ══════════════════════════════════════════════════════════════════════════

class TestScanModuleProtocol(unittest.TestCase):
    """Test ScanModule protocol with real module functions."""

    def test_plain_function_satisfies_protocol(self):
        """A plain function with matching signature should satisfy ScanModule."""
        self.assertTrue(isinstance(_fake_scan_module, ScanModule))

    def test_plain_function_callable(self):
        """The function should be callable and return results."""
        result = _fake_scan_module("example.com", "https://example.com")
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["target"], "example.com")

    def test_function_with_defaults(self):
        """Calling with default timeout/verify_tls should work."""
        result = _fake_scan_module("example.com", "https://example.com")
        self.assertIsInstance(result, list)

    def test_function_with_explicit_args(self):
        """Calling with all explicit args should work."""
        result = _fake_scan_module("example.com", "https://example.com",
                                   timeout=15, verify_tls=False)
        self.assertIsInstance(result, list)

    def test_lambda_satisfies_at_runtime(self):
        """runtime_checkable protocols with __call__ match ALL callables.

        This is a known limitation of @runtime_checkable — it cannot check
        parameter signatures at runtime. Static type checkers (mypy, pyright)
        will still catch signature mismatches.
        """
        lam = lambda: []  # noqa: E731
        self.assertTrue(isinstance(lam, ScanModule),
                        "runtime_checkable cannot inspect __call__ param signatures")

    def test_class_instance_with_call_satisfies(self):
        """A class with __call__ matching the signature should satisfy ScanModule."""
        class CallableModule:
            def __call__(self, target: str, base_url: str, timeout: int = 8,
                         verify_tls: bool = True) -> list:
                return []
        self.assertTrue(isinstance(CallableModule(), ScanModule))


# ══════════════════════════════════════════════════════════════════════════
# FindingProcessor Protocol Tests
# ══════════════════════════════════════════════════════════════════════════

class TestFindingProcessorProtocol(unittest.TestCase):
    """Test FindingProcessor protocol."""

    def test_processor_satisfies_protocol(self):
        """A class with process() should satisfy FindingProcessor."""
        class MyProcessor:
            def process(self, findings: list) -> list:
                return findings
        self.assertTrue(isinstance(MyProcessor(), FindingProcessor))

    def test_processor_filters_findings(self):
        """The processor should actually filter findings."""
        findings = [
            {"severity": "critical"},
            {"severity": "info"},
            {"severity": "high"},
        ]
        result = _fake_processor(findings)
        self.assertEqual(len(result), 2)

    def test_processor_with_empty_list(self):
        """Processor should handle empty list."""
        result = _fake_processor([])
        self.assertEqual(result, [])

    def test_plain_function_does_not_satisfy_processor(self):
        """A plain function without a process attribute won't satisfy."""
        self.assertFalse(isinstance(lambda x: x, FindingProcessor))


# ══════════════════════════════════════════════════════════════════════════
# PluginInterface ABC Tests
# ══════════════════════════════════════════════════════════════════════════

class TestPluginInterfaceABC(unittest.TestCase):
    """Test PluginInterface abstract base class."""

    def test_concrete_plugin_instantiates(self):
        """A concrete plugin should instantiate without error."""
        plugin = _ConcretePlugin()
        self.assertIsNotNone(plugin)

    def test_plugin_is_instance_of_abc(self):
        """Concrete plugin should be instance of PluginInterface."""
        plugin = _ConcretePlugin()
        self.assertIsInstance(plugin, PluginInterface)

    def test_plugin_name_property(self):
        """Plugin name property should return correct value."""
        plugin = _ConcretePlugin(name="my-plugin")
        self.assertEqual(plugin.name, "my-plugin")

    def test_plugin_description_property(self):
        """Plugin description property should return correct value."""
        plugin = _ConcretePlugin(description="A cool plugin")
        self.assertEqual(plugin.description, "A cool plugin")

    def test_plugin_run_returns_list(self):
        """Plugin run() should return a list."""
        plugin = _ConcretePlugin()
        result = plugin.run("example.com")
        self.assertIsInstance(result, list)

    def test_plugin_run_with_all_args(self):
        """Plugin run() should accept all 4 args."""
        plugin = _ConcretePlugin()
        result = plugin.run("example.com", "https://example.com",
                            timeout=15, verify_tls=False)
        self.assertIsInstance(result, list)

    def test_abc_cannot_be_instantiated_directly(self):
        """PluginInterface itself should not be instantiable."""
        with self.assertRaises(TypeError):
            PluginInterface()

    def test_incomplete_plugin_cannot_instantiate(self):
        """A plugin missing abstract methods should fail to instantiate."""
        class IncompletePlugin(PluginInterface):
            def run(self, target, base_url="", timeout=8, verify_tls=True):
                return []
            # Missing name and description properties
        with self.assertRaises(TypeError):
            IncompletePlugin()


# ══════════════════════════════════════════════════════════════════════════
# EventEmitter Protocol Tests
# ══════════════════════════════════════════════════════════════════════════

class TestEventEmitterProtocol(unittest.TestCase):
    """Test EventEmitter protocol."""

    def test_concrete_emitter_satisfies_protocol(self):
        """_FakeEventEmitter should satisfy EventEmitter protocol."""
        emitter = _FakeEventEmitter()
        self.assertTrue(isinstance(emitter, EventEmitter))

    def test_emit_with_no_listeners(self):
        """Emitting with no listeners should return empty list."""
        emitter = _FakeEventEmitter()
        result = emitter.emit("scan_complete")
        self.assertEqual(result, [])

    def test_on_and_emit(self):
        """Registering a listener and emitting should call it."""
        emitter = _FakeEventEmitter()
        received = []
        emitter.on("test_event", lambda **kw: received.append(kw))
        emitter.emit("test_event", key="value")
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["key"], "value")

    def test_off_removes_listener(self):
        """Off should remove a specific listener."""
        emitter = _FakeEventEmitter()
        received = []
        cb = lambda **kw: received.append(kw)  # noqa: E731
        emitter.on("test", cb)
        emitter.off("test", cb)
        emitter.emit("test", data=1)
        self.assertEqual(len(received), 0)

    def test_multiple_listeners(self):
        """Multiple listeners should all be called."""
        emitter = _FakeEventEmitter()
        count = [0]
        cb1 = lambda **kw: count.__setitem__(0, count[0] + 1)  # noqa: E731
        cb2 = lambda **kw: count.__setitem__(0, count[0] + 1)  # noqa: E731
        emitter.on("evt", cb1)
        emitter.on("evt", cb2)
        emitter.emit("evt")
        self.assertEqual(count[0], 2)

    def test_plain_object_does_not_satisfy(self):
        """A plain object should not satisfy EventEmitter."""
        self.assertFalse(isinstance(object(), EventEmitter))


# ══════════════════════════════════════════════════════════════════════════
# ConfigurationProvider Protocol Tests
# ══════════════════════════════════════════════════════════════════════════

class TestConfigurationProviderProtocol(unittest.TestCase):
    """Test ConfigurationProvider protocol."""

    def test_concrete_provider_satisfies_protocol(self):
        """_FakeConfigProvider should satisfy ConfigurationProvider protocol."""
        provider = _FakeConfigProvider()
        self.assertTrue(isinstance(provider, ConfigurationProvider))

    def test_get_returns_default_when_empty(self):
        """Get should return default when key doesn't exist."""
        provider = _FakeConfigProvider()
        self.assertIsNone(provider.get("missing_key"))
        self.assertEqual(provider.get("missing_key", 42), 42)

    def test_set_and_get(self):
        """Set should store, get should retrieve."""
        provider = _FakeConfigProvider()
        provider.set("timeout", 15)
        self.assertEqual(provider.get("timeout"), 15)

    def test_has_returns_true_for_existing_key(self):
        """Has should return True for keys that exist."""
        provider = _FakeConfigProvider()
        provider.set("key", "val")
        self.assertTrue(provider.has("key"))

    def test_has_returns_false_for_missing_key(self):
        """Has should return False for missing keys."""
        provider = _FakeConfigProvider()
        self.assertFalse(provider.has("nonexistent"))


# ══════════════════════════════════════════════════════════════════════════
# ReportGenerator Protocol Tests
# ══════════════════════════════════════════════════════════════════════════

class TestReportGeneratorProtocol(unittest.TestCase):
    """Test ReportGenerator protocol."""

    def test_concrete_generator_satisfies_protocol(self):
        """A class with generate() should satisfy ReportGenerator."""
        class MyGenerator:
            def generate(self, data: dict, output_path: str) -> str:
                return output_path
        self.assertTrue(isinstance(MyGenerator(), ReportGenerator))

    def test_generator_returns_output_path(self):
        """Generator should return the output path."""
        result = _fake_report_generator({}, "/tmp/report.html")
        self.assertEqual(result, "/tmp/report.html")


# ══════════════════════════════════════════════════════════════════════════
# Type Alias Tests
# ══════════════════════════════════════════════════════════════════════════

class TestTypeAliases(unittest.TestCase):
    """Test that type aliases are properly defined."""

    def test_findings_alias_is_list(self):
        """Findings should be a list type alias."""
        self.assertEqual(Findings, list)

    def test_scan_result_alias_is_dict(self):
        """ScanResult should be a dict type alias."""
        self.assertEqual(ScanResult, dict)

    def test_severity_alias_is_str(self):
        """Severity should be a str type alias."""
        self.assertEqual(Severity, str)

    def test_grade_alias_is_str(self):
        """Grade should be a str type alias."""
        self.assertEqual(Grade, str)

    def test_target_alias_is_str(self):
        """Target should be a str type alias."""
        self.assertEqual(Target, str)

    def test_module_id_alias_is_str(self):
        """ModuleID should be a str type alias."""
        self.assertEqual(ModuleID, str)

    def test_can_use_severity_alias(self):
        """Severity alias should be usable for assignment."""
        sev: Severity = "critical"  # type: ignore[misc]
        self.assertEqual(sev, "critical")

    def test_can_use_grade_alias(self):
        """Grade alias should be usable for assignment."""
        g: Grade = "A+"  # type: ignore[misc]
        self.assertEqual(g, "A+")


# ══════════════════════════════════════════════════════════════════════════
# ScanContext Tests
# ══════════════════════════════════════════════════════════════════════════

class TestScanContext(unittest.TestCase):
    """Test ScanContext dataclass."""

    def test_create_with_target_only(self):
        """ScanContext should auto-derive base_url and host."""
        ctx = ScanContext(target="example.com", base_url="")
        self.assertEqual(ctx.target, "example.com")
        self.assertEqual(ctx.base_url, "https://example.com")
        self.assertEqual(ctx.host, "example.com")

    def test_create_with_full_url(self):
        """ScanContext with a full URL should extract host correctly."""
        ctx = ScanContext(
            target="https://example.com:8080/path",
            base_url="https://example.com:8080/path",
        )
        self.assertEqual(ctx.host, "example.com:8080")

    def test_create_with_http_scheme(self):
        """ScanContext with http:// should preserve scheme."""
        ctx = ScanContext(
            target="http://example.com",
            base_url="http://example.com",
        )
        self.assertEqual(ctx.scheme, "http")

    def test_create_with_https_scheme(self):
        """ScanContext with https:// should set scheme to https."""
        ctx = ScanContext(
            target="https://example.com",
            base_url="https://example.com",
        )
        self.assertEqual(ctx.scheme, "https")

    def test_default_timeout(self):
        """Default timeout should be 8."""
        ctx = ScanContext(target="example.com", base_url="https://example.com")
        self.assertEqual(ctx.timeout, 8)

    def test_custom_timeout(self):
        """Custom timeout should be stored."""
        ctx = ScanContext(target="example.com", base_url="https://example.com",
                          timeout=30)
        self.assertEqual(ctx.timeout, 30)

    def test_default_verify_tls(self):
        """Default verify_tls should be True."""
        ctx = ScanContext(target="example.com", base_url="https://example.com")
        self.assertTrue(ctx.verify_tls)

    def test_default_rate_limit(self):
        """Default rate_limit should be 10.0."""
        ctx = ScanContext(target="example.com", base_url="https://example.com")
        self.assertEqual(ctx.rate_limit, 10.0)

    def test_trace_id_is_non_empty_string(self):
        """Trace ID should be a 12-char hex string."""
        ctx = ScanContext(target="example.com", base_url="https://example.com")
        self.assertEqual(len(ctx.trace_id), 12)
        self.assertTrue(all(c in "0123456789abcdef" for c in ctx.trace_id))

    def test_trace_id_is_unique(self):
        """Each ScanContext should get a unique trace_id."""
        ctx1 = ScanContext(target="a.com", base_url="https://a.com")
        ctx2 = ScanContext(target="b.com", base_url="https://b.com")
        self.assertNotEqual(ctx1.trace_id, ctx2.trace_id)

    def test_started_at_is_recent(self):
        """started_at should be close to current time."""
        before = time.time()
        ctx = ScanContext(target="example.com", base_url="https://example.com")
        after = time.time()
        self.assertGreaterEqual(ctx.started_at, before)
        self.assertLessEqual(ctx.started_at, after)

    def test_to_args_returns_tuple(self):
        """to_args() should return a 4-element tuple."""
        ctx = ScanContext(target="example.com", base_url="https://example.com",
                          timeout=15, verify_tls=False)
        args = ctx.to_args()
        self.assertIsInstance(args, tuple)
        self.assertEqual(len(args), 4)

    def test_to_args_preserves_values(self):
        """to_args() should preserve target, base_url, timeout, verify_tls."""
        ctx = ScanContext(target="example.com", base_url="https://example.com",
                          timeout=15, verify_tls=False)
        target, base_url, timeout, verify_tls = ctx.to_args()
        self.assertEqual(target, "example.com")
        self.assertEqual(base_url, "https://example.com")
        self.assertEqual(timeout, 15)
        self.assertFalse(verify_tls)

    def test_elapsed_ms_returns_positive(self):
        """elapsed_ms() should return a positive number."""
        ctx = ScanContext(target="example.com", base_url="https://example.com")
        time.sleep(0.01)
        elapsed = ctx.elapsed_ms()
        self.assertGreater(elapsed, 0)

    def test_elapsed_ms_increases(self):
        """elapsed_ms() should increase over time."""
        ctx = ScanContext(target="example.com", base_url="https://example.com")
        e1 = ctx.elapsed_ms()
        time.sleep(0.02)
        e2 = ctx.elapsed_ms()
        self.assertGreater(e2, e1)

    def test_post_init_derives_host_from_target(self):
        """__post_init__ should derive host when not provided."""
        ctx = ScanContext(target="https://example.com/path", base_url="https://example.com/path")
        # host is not empty so it won't re-derive; set empty to test
        ctx2 = ScanContext(target="https://example.com/path", base_url="https://example.com/path", host="")
        self.assertEqual(ctx2.host, "example.com")

    def test_post_init_derives_base_url_from_target(self):
        """__post_init__ should derive base_url when empty string provided."""
        ctx = ScanContext(target="example.com", base_url="")
        self.assertEqual(ctx.base_url, "https://example.com")

    def test_explicit_host_not_overridden(self):
        """Explicit host value should not be overridden by __post_init__."""
        ctx = ScanContext(target="example.com", base_url="https://example.com",
                          host="custom.host")
        self.assertEqual(ctx.host, "custom.host")


# ══════════════════════════════════════════════════════════════════════════
# create_context Factory Tests
# ══════════════════════════════════════════════════════════════════════════

class TestCreateContextFactory(unittest.TestCase):
    """Test the create_context factory function."""

    def test_basic_creation(self):
        """create_context should return a ScanContext."""
        ctx = create_context("example.com")
        self.assertIsInstance(ctx, ScanContext)
        self.assertEqual(ctx.target, "example.com")

    def test_with_kwargs(self):
        """create_context should pass kwargs to ScanContext."""
        ctx = create_context("example.com", timeout=20, verify_tls=False,
                             rate_limit=5.0)
        self.assertEqual(ctx.timeout, 20)
        self.assertFalse(ctx.verify_tls)
        self.assertEqual(ctx.rate_limit, 5.0)

    def test_with_explicit_base_url(self):
        """create_context should accept base_url kwarg."""
        ctx = create_context("example.com", base_url="http://example.com")
        self.assertEqual(ctx.base_url, "http://example.com")


# ══════════════════════════════════════════════════════════════════════════
# Registry Enhancement Tests
# ══════════════════════════════════════════════════════════════════════════

class TestGetModuleInfo(unittest.TestCase):
    """Test get_module_info registry function."""

    def test_returns_info_for_remote_module(self):
        """Should return dict for known remote module."""
        info = get_module_info("recon")
        self.assertIsNotNone(info)
        self.assertIn("name", info)
        self.assertIn("runner", info)
        self.assertIn("color", info)

    def test_returns_info_for_local_module(self):
        """Should return dict for known local module."""
        info = get_module_info("host")
        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "HOST AUDIT")

    def test_returns_none_for_unknown_module(self):
        """Should return None for unknown module ID."""
        self.assertIsNone(get_module_info("nonexistent_xyz"))

    def test_returns_none_for_empty_string(self):
        """Should return None for empty string."""
        self.assertIsNone(get_module_info(""))

    def test_info_has_callable_runner(self):
        """Module info should have a callable runner."""
        info = get_module_info("auth")
        self.assertIsNotNone(info)
        self.assertTrue(callable(info["runner"]))


class TestListRemoteModules(unittest.TestCase):
    """Test list_remote_modules registry function."""

    def test_returns_list(self):
        """Should return a list."""
        result = list_remote_modules()
        self.assertIsInstance(result, list)

    def test_is_sorted(self):
        """Should return alphabetically sorted list."""
        result = list_remote_modules()
        self.assertEqual(result, sorted(result))

    def test_has_expected_count(self):
        """Should have same count as MODULE_REGISTRY."""
        result = list_remote_modules()
        self.assertEqual(len(result), len(MODULE_REGISTRY))

    def test_contains_known_module(self):
        """Should contain known modules."""
        result = list_remote_modules()
        self.assertIn("recon", result)
        self.assertIn("auth", result)
        self.assertIn("chain", result)

    def test_does_not_contain_local(self):
        """Should not contain local modules."""
        result = list_remote_modules()
        self.assertNotIn("host", result)
        self.assertNotIn("dev", result)
        self.assertNotIn("doctor", result)


class TestListLocalModules(unittest.TestCase):
    """Test list_local_modules registry function."""

    def test_returns_list(self):
        """Should return a list."""
        result = list_local_modules()
        self.assertIsInstance(result, list)

    def test_is_sorted(self):
        """Should return alphabetically sorted list."""
        result = list_local_modules()
        self.assertEqual(result, sorted(result))

    def test_has_expected_count(self):
        """Should have 3 local modules."""
        result = list_local_modules()
        self.assertEqual(len(result), 3)

    def test_contains_host_dev_doctor(self):
        """Should contain host, dev, doctor."""
        result = list_local_modules()
        self.assertIn("dev", result)
        self.assertIn("doctor", result)
        self.assertIn("host", result)


class TestGetModuleColor(unittest.TestCase):
    """Test get_module_color registry function."""

    def test_returns_color_for_remote_module(self):
        """Should return color for remote modules."""
        color = get_module_color("recon")
        self.assertEqual(color, "cyan")

    def test_returns_color_for_local_module(self):
        """Should return color for local modules."""
        color = get_module_color("host")
        self.assertEqual(color, "bright_yellow")

    def test_returns_white_for_unknown_module(self):
        """Should return 'white' for unknown modules."""
        self.assertEqual(get_module_color("nonexistent"), "white")

    def test_returns_white_for_empty_string(self):
        """Should return 'white' for empty string."""
        self.assertEqual(get_module_color(""), "white")

    def test_color_matches_registry_entry(self):
        """Color should match the actual registry entry color."""
        for mod_id in MODULE_REGISTRY:
            self.assertEqual(get_module_color(mod_id), MODULE_REGISTRY[mod_id]["color"],
                             f"Color mismatch for {mod_id}")
        for mod_id in LOCAL_MODULES:
            self.assertEqual(get_module_color(mod_id), LOCAL_MODULES[mod_id]["color"],
                             f"Color mismatch for {mod_id}")


if __name__ == "__main__":
    unittest.main()

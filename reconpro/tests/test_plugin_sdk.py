"""plugin_sdk unit tests — manifest, crypto, permissions, analysis,
scaffold, manager, runner/worker IPC.

Run:  python -m pytest reconpro/tests/test_plugin_sdk.py -q
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from reconpro.plugin_sdk import (
    PermissionSet,
    PluginManager,
    PluginRunner,
    analyze_source,
    check_runnable,
    create_legacy_template,
    create_plugin_skeleton,
    fingerprint,
    generate_keypair,
    sign,
    verify,
)
from reconpro.plugin_sdk.analysis import ViolationType
from reconpro.plugin_sdk.crypto import canonical_payload, source_sha256, verify_manifest
from reconpro.plugin_sdk.manifest import (
    ManifestError,
    load_manifest,
    validate_manifest,
    version_cmp,
)
from reconpro.plugin_sdk.manager import _set_toml_key
from reconpro.plugin_sdk.permissions import PermissionError_


REPO = Path(__file__).resolve().parents[2]


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="psdk-test-"))


GOOD_MAIN = 'def run(target, base_url="", timeout=8, verify_tls=True):\n    return []\n'


def _make_plugin_dir(root: Path, pid: str, version: str = "0.1.0",
                     main: str = GOOD_MAIN, permissions: str = "") -> Path:
    d = root / pid
    d.mkdir(parents=True, exist_ok=True)
    (d / "main.py").write_text(main)
    (d / "plugin.toml").write_text(textwrap.dedent(f"""\
        id = "{pid}"
        name = "{pid.replace('-', ' ').title()}"
        version = "{version}"
        description = "test plugin"
        author = "tester"
        reconpro_min = "11.0.0"

        [permissions]
        network = false
        {permissions}
    """))
    return d


# ═══════════════════════════════════════════════════════════════════
# Manifest
# ═══════════════════════════════════════════════════════════════════

class TestManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_load_valid_manifest(self):
        d = _make_plugin_dir(self.tmp, "alpha")
        m = load_manifest(d)
        self.assertEqual(m.id, "alpha")
        self.assertEqual(m.version, "0.1.0")
        self.assertEqual(m.author, "tester")

    def test_missing_plugin_toml(self):
        d = self.tmp / "beta"
        d.mkdir()
        (d / "main.py").write_text(GOOD_MAIN)
        with self.assertRaises(ManifestError):
            load_manifest(d)

    def test_missing_main_py(self):
        d = self.tmp / "gamma"
        d.mkdir()
        (d / "plugin.toml").write_text('id = "gamma"\nname = "G"\nversion = "1.0.0"\ndescription = "d"\n')
        with self.assertRaises(ManifestError):
            load_manifest(d)

    def test_invalid_toml_syntax(self):
        d = _make_plugin_dir(self.tmp, "delta")
        (d / "plugin.toml").write_text("id = [unclosed\n")
        with self.assertRaises(ManifestError):
            load_manifest(d)

    def test_missing_required_field(self):
        raw = {"id": "x", "name": "X", "version": "1.0.0"}  # no description
        with self.assertRaises(ManifestError):
            validate_manifest(raw)

    def test_invalid_id_rejected(self):
        raw = {"id": "../evil", "name": "E", "version": "1.0.0", "description": "d"}
        with self.assertRaises(ManifestError):
            validate_manifest(raw)

    def test_id_must_match_directory(self):
        d = _make_plugin_dir(self.tmp, "plugin-a")
        # swap the id inside the manifest
        toml = (d / "plugin.toml").read_text().replace('id = "plugin-a"', 'id = "other"')
        (d / "plugin.toml").write_text(toml)
        with self.assertRaises(ManifestError):
            load_manifest(d)

    def test_invalid_version_rejected(self):
        raw = {"id": "x", "name": "X", "version": "not-semver", "description": "d"}
        with self.assertRaises(ManifestError):
            validate_manifest(raw)

    def test_bad_permissions_rejected(self):
        raw = {"id": "x", "name": "X", "version": "1.0.0", "description": "d",
               "permissions": {"network": "yes-please"}}
        with self.assertRaises(ManifestError):
            validate_manifest(raw)

    def test_version_cmp(self):
        self.assertEqual(version_cmp("1.0.0", "1.0.0"), 0)
        self.assertEqual(version_cmp("1.2.0", "1.10.0"), -1)
        self.assertEqual(version_cmp("2.0.0", "1.9.9"), 1)

    def test_manifest_to_dict_roundtrip(self):
        d = _make_plugin_dir(self.tmp, "roundtrip")
        m = load_manifest(d)
        d2 = m.to_dict()
        self.assertEqual(d2["id"], "roundtrip")
        self.assertIn("permissions", d2)

    def test_description_length_capped(self):
        raw = {"id": "x", "name": "X", "version": "1.0.0",
               "description": "d" * 600}
        with self.assertRaises(ManifestError):
            validate_manifest(raw)

    def test_provenance_parsed(self):
        d = _make_plugin_dir(self.tmp, "prov")
        toml = (d / "plugin.toml").read_text() + '\n[provenance]\nsignature = "ab"\nkey_id = "cd"\n'
        (d / "plugin.toml").write_text(toml)
        m = load_manifest(d)
        self.assertEqual(m.signature, "ab")
        self.assertEqual(m.key_id, "cd")


# ═══════════════════════════════════════════════════════════════════
# Crypto
# ═══════════════════════════════════════════════════════════════════

class TestCrypto(unittest.TestCase):
    def test_generate_keypair_distinct(self):
        p1, u1 = generate_keypair()
        p2, u2 = generate_keypair()
        self.assertNotEqual(p1, p2)
        self.assertNotEqual(u1, u2)
        self.assertEqual(len(u1), 64)

    def test_sign_verify_roundtrip(self):
        priv, pub = generate_keypair()
        sig = sign(priv, b"message")
        self.assertTrue(verify(pub, b"message", sig))

    def test_verify_tampered_message(self):
        priv, pub = generate_keypair()
        sig = sign(priv, b"message")
        self.assertFalse(verify(pub, b"messagE", sig))

    def test_verify_tampered_signature(self):
        priv, pub = generate_keypair()
        sig = sign(priv, b"message")
        bad = ("f" * 128) if not sig.startswith("f") else ("0" * 128)
        self.assertFalse(verify(pub, b"message", bad))

    def test_verify_wrong_key(self):
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()
        sig = sign(priv1, b"message")
        self.assertFalse(verify(pub2, b"message", sig))

    def test_verify_malformed_key(self):
        priv, _ = generate_keypair()
        sig = sign(priv, b"m")
        self.assertFalse(verify("zzzz-not-hex", b"m", sig))
        self.assertFalse(verify("abcd", b"m", sig))  # wrong length

    def test_verify_malformed_signature(self):
        _, pub = generate_keypair()
        self.assertFalse(verify(pub, b"m", "short"))
        self.assertFalse(verify(pub, b"m", ""))

    def test_fingerprint_stable(self):
        _, pub = generate_keypair()
        self.assertEqual(fingerprint(pub), fingerprint(pub))
        self.assertEqual(len(fingerprint(pub)), 16)

    def test_canonical_payload_deterministic(self):
        m = {"id": "x", "name": "X", "version": "1.0.0", "permissions": {"network": False}}
        a = canonical_payload(m, "ab" * 32)
        b = canonical_payload(dict(reversed(list(m.items()))), "ab" * 32)
        self.assertEqual(a, b)

    def test_source_sha256(self):
        self.assertEqual(source_sha256(b"abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_verify_manifest_roundtrip(self):
        priv, pub = generate_keypair()
        manifest = {"id": "x", "name": "X", "version": "1.0.0",
                    "permissions": {"network": False, "fs_read": [],
                                    "fs_write": [], "env": [], "subprocess": False}}
        source = b"def run(): pass"
        sig = sign(priv, canonical_payload(manifest, source_sha256(source)))
        self.assertTrue(verify_manifest(pub, manifest, source, sig))

    def test_verify_manifest_source_tamper(self):
        priv, pub = generate_keypair()
        manifest = {"id": "x", "name": "X", "version": "1.0.0", "permissions": {}}
        source = b"def run(): pass"
        sig = sign(priv, canonical_payload(manifest, source_sha256(source)))
        self.assertFalse(verify_manifest(pub, manifest, b"def run(): evil", sig))

    def test_verify_manifest_field_tamper(self):
        priv, pub = generate_keypair()
        manifest = {"id": "x", "name": "X", "version": "1.0.0", "permissions": {}}
        source = b"def run(): pass"
        sig = sign(priv, canonical_payload(manifest, source_sha256(source)))
        manifest["version"] = "9.9.9"
        self.assertFalse(verify_manifest(pub, manifest, source, sig))

    def test_signature_covers_permissions(self):
        priv, pub = generate_keypair()
        manifest = {"id": "x", "permissions": {"network": False}}
        source = b"src"
        sig = sign(priv, canonical_payload(manifest, source_sha256(source)))
        manifest["permissions"] = {"network": True}
        self.assertFalse(verify_manifest(pub, manifest, source, sig))


# ═══════════════════════════════════════════════════════════════════
# Permissions
# ═══════════════════════════════════════════════════════════════════

class TestPermissions(unittest.TestCase):
    def test_defaults_minimal(self):
        p = PermissionSet()
        self.assertFalse(p.network)
        self.assertEqual(p.risk_level(), "minimal")

    def test_subprocess_always_rejected(self):
        with self.assertRaises(PermissionError_):
            PermissionSet.from_manifest({"subprocess": True})

    def test_sensitive_root_rejected(self):
        for root in ("/etc", "/root", "/proc"):
            with self.assertRaises(PermissionError_):
                PermissionSet.from_manifest({"fs_read": [root]})

    def test_unknown_key_rejected(self):
        with self.assertRaises(PermissionError_):
            PermissionSet.from_manifest({"cuda": True})

    def test_non_bool_network_rejected(self):
        with self.assertRaises(PermissionError_):
            PermissionSet.from_manifest({"network": "yes"})

    def test_env_allowlist_valid(self):
        p = PermissionSet.from_manifest({"env": ["HOME", "PATH"]})
        self.assertEqual(p.env_allowlist(), ("HOME", "PATH"))

    def test_env_invalid_name_rejected(self):
        with self.assertRaises(PermissionError_):
            PermissionSet.from_manifest({"env": ["NOT A NAME"]})

    def test_fs_paths_normalised(self):
        p = PermissionSet.from_manifest({"fs_read": ["/tmp/data/"]})
        self.assertEqual(p.read_roots(), ("/tmp/data",))

    def test_as_dict_roundtrip(self):
        p = PermissionSet.from_manifest({"network": True, "env": ["X"]})
        p2 = PermissionSet.from_manifest(p.as_dict())
        self.assertEqual(p, p2)

    def test_risk_levels(self):
        self.assertEqual(PermissionSet().risk_level(), "minimal")
        self.assertEqual(PermissionSet(network=True).risk_level(), "moderate")
        self.assertEqual(PermissionSet(network=True, fs_write=("/tmp/x",)).risk_level(), "elevated")

    def test_summary_mentions_subprocess_never(self):
        self.assertIn("subprocess=never", PermissionSet().summary())

    def test_empty_lists_ok(self):
        p = PermissionSet.from_manifest({})
        self.assertEqual(p.read_roots(), ())
        self.assertEqual(p.write_roots(), ())


# ═══════════════════════════════════════════════════════════════════
# Static analysis
# ═══════════════════════════════════════════════════════════════════

class TestAnalysis(unittest.TestCase):
    def check(self, code, perms=None):
        return check_runnable(code, perms or PermissionSet())

    def test_clean_plugin_passes(self):
        ok, v = self.check(GOOD_MAIN)
        self.assertTrue(ok)

    def test_subprocess_import_blocked(self):
        ok, v = self.check("import subprocess\ndef run(**k):\n    return []\n")
        self.assertFalse(ok)
        self.assertTrue(any(x.kind == ViolationType.BANNED_IMPORT for x in v))

    def test_from_subprocess_import_blocked(self):
        ok, v = self.check("from subprocess import run as sp_run\ndef run(**k):\n    return []\n")
        self.assertFalse(ok)

    def test_ctypes_import_blocked(self):
        ok, v = self.check("import ctypes\ndef run(**k):\n    return []\n")
        self.assertFalse(ok)

    def test_multiprocessing_import_blocked(self):
        ok, v = self.check("import multiprocessing\ndef run(**k):\n    return []\n")
        self.assertFalse(ok)

    def test_os_system_blocked(self):
        ok, v = self.check("import os\ndef run(**k):\n    os.system('ls')\n    return []\n")
        self.assertFalse(ok)
        self.assertTrue(any(x.kind == ViolationType.OS_PROCESS for x in v))

    def test_os_popen_blocked(self):
        ok, v = self.check("import os\ndef run(**k):\n    os.popen('id')\n    return []\n")
        self.assertFalse(ok)

    def test_os_exec_blocked(self):
        ok, v = self.check("import os\ndef run(**k):\n    os.execv('/bin/sh', ['sh'])\n    return []\n")
        self.assertFalse(ok)

    def test_eval_blocked(self):
        ok, v = self.check("def run(**k):\n    eval('1+1')\n    return []\n")
        self.assertFalse(ok)
        self.assertTrue(any(x.kind == ViolationType.EVAL_EXEC for x in v))

    def test_exec_blocked(self):
        ok, v = self.check("def run(**k):\n    exec('x=1')\n    return []\n")
        self.assertFalse(ok)

    def test_compile_blocked(self):
        ok, v = self.check("def run(**k):\n    compile('1', 'f', 'eval')\n    return []\n")
        self.assertFalse(ok)

    def test_dunder_import_blocked(self):
        ok, v = self.check("def run(**k):\n    __import__('subprocess')\n    return []\n")
        self.assertFalse(ok)

    def test_importlib_import_module_blocked(self):
        ok, v = self.check("import importlib\ndef run(**k):\n    importlib.import_module('ctypes')\n    return []\n")
        self.assertFalse(ok)
        self.assertTrue(any(x.kind == ViolationType.DYNAMIC_IMPORT for x in v))

    def test_pickle_loads_blocked(self):
        ok, v = self.check("import pickle\ndef run(**k):\n    pickle.loads(b'')\n    return []\n")
        self.assertFalse(ok)
        self.assertTrue(any(x.kind == ViolationType.UNSAFE_DESERIALIZE for x in v))

    def test_socket_import_blocked_without_network(self):
        ok, v = self.check("import socket\ndef run(**k):\n    return []\n")
        self.assertFalse(ok)

    def test_socket_import_allowed_with_network(self):
        ok, v = self.check("import socket\ndef run(**k):\n    return []\n",
                           PermissionSet(network=True))
        self.assertTrue(ok)

    def test_socket_call_blocked_without_network(self):
        ok, v = self.check("import socket\ndef run(**k):\n    socket.socket()\n    return []\n")
        self.assertFalse(ok)

    def test_syntax_error_blocked(self):
        ok, v = self.check("def broken(:\n")
        self.assertFalse(ok)

    def test_star_import_flagged(self):
        ok, v = self.check("from os import *\ndef run(**k):\n    return []\n")
        self.assertFalse(ok)

    def test_clean_stdlib_ok(self):
        ok, v = self.check("import json, re, math\ndef run(**k):\n    return []\n")
        self.assertTrue(ok)

    def test_advisory_mutation_note(self):
        ok, v = self.check("import os\ndef run(**k):\n    os.chmod('/tmp/x', 0o600)\n    return []\n")
        self.assertTrue(ok)  # advisory only at analysis; runtime blocks outside workdir
        self.assertTrue(any(not x.blocking for x in v))

    def test_assign_run_lambda(self):
        ok, _ = self.check("run = lambda **k: []\n")
        self.assertTrue(ok)


# ═══════════════════════════════════════════════════════════════════
# Scaffold
# ═══════════════════════════════════════════════════════════════════

class TestScaffold(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_skeleton_files_created(self):
        d = create_plugin_skeleton(self.tmp, "my-plugin")
        for name in ("plugin.toml", "main.py", "README.md"):
            self.assertTrue((d / name).is_file(), name)

    def test_skeleton_manifest_valid(self):
        d = create_plugin_skeleton(self.tmp, "valid-skel")
        m = load_manifest(d)
        self.assertEqual(m.id, "valid-skel")

    def test_skeleton_compiles(self):
        d = create_plugin_skeleton(self.tmp, "compile-skel")
        compile((d / "main.py").read_text(), str(d / "main.py"), "exec")

    def test_skeleton_run_returns_empty(self):
        d = create_plugin_skeleton(self.tmp, "empty-skel")
        ok, v = check_runnable((d / "main.py").read_text(), PermissionSet())
        self.assertTrue(ok, v)

    def test_invalid_id_rejected(self):
        from reconpro.plugin_sdk.scaffold import ScaffoldError
        with self.assertRaises(ScaffoldError):
            create_plugin_skeleton(self.tmp, "../evil")

    def test_duplicate_refused_without_force(self):
        create_plugin_skeleton(self.tmp, "dup")
        with self.assertRaises(Exception):
            create_plugin_skeleton(self.tmp, "dup")
        create_plugin_skeleton(self.tmp, "dup", force=True)  # no raise

    def test_legacy_template(self):
        p = create_legacy_template(self.tmp, "legacy_plug")
        self.assertTrue(p.is_file())
        content = p.read_text()
        self.assertIn("def run(", content)
        self.assertIn("Finding", content)

    def test_legacy_template_invalid_name(self):
        from reconpro.plugin_sdk.scaffold import ScaffoldError
        with self.assertRaises(ScaffoldError):
            create_legacy_template(self.tmp, "_bad name")


# ═══════════════════════════════════════════════════════════════════
# Manager lifecycle
# ═══════════════════════════════════════════════════════════════════

class TestManager(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp()
        self.root = self.tmp / "plugins"
        self.mgr = PluginManager(root=self.root,
                                 runner=PluginRunner(wall_timeout_s=8))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _signed_plugin(self, pid="signed-one", version="0.1.0"):
        d = _make_plugin_dir(self.tmp, pid, version=version)
        self.mgr.sign(d)
        return d

    def test_install_signed(self):
        d = self._signed_plugin()
        info = self.mgr.install(d)
        self.assertEqual(info.id, "signed-one")
        self.assertTrue(info.trusted)

    def test_install_unsigned_refused(self):
        d = _make_plugin_dir(self.tmp, "unsigned-one")
        with self.assertRaises(Exception):
            self.mgr.install(d)

    def test_install_unsigned_allowed_flag(self):
        d = _make_plugin_dir(self.tmp, "unsigned-two")
        info = self.mgr.install(d, allow_unsigned=True)
        self.assertFalse(info.trusted)

    def test_install_detects_source_tamper_after_signing(self):
        d = self._signed_plugin("tamper-one")
        (d / "main.py").write_text("def run(**k):\n    return [{'title': 'x', 'severity': 'i', 'category': 'c'}]\n")
        with self.assertRaises(Exception):
            self.mgr.install(d)

    def test_install_refuses_blocking_analysis(self):
        d = _make_plugin_dir(self.tmp, "evil-one",
                             main="import subprocess\ndef run(**k):\n    return []\n")
        self.mgr.sign(d)
        with self.assertRaises(Exception):
            self.mgr.install(d)

    def test_install_refuses_subprocess_permission(self):
        d = _make_plugin_dir(self.tmp, "perm-evil", permissions="subprocess = true")
        with self.assertRaises(Exception):
            self.mgr.install(d, allow_unsigned=True)

    def test_duplicate_install_refused(self):
        d = self._signed_plugin()
        self.mgr.install(d)
        with self.assertRaises(Exception):
            self.mgr.install(d)

    def test_verify_ok(self):
        d = self._signed_plugin()
        self.mgr.install(d)
        report = self.mgr.verify("verify-ok") if False else self.mgr.verify("verify-ok") if False else None
        # (id is signed-one)
        report = self.mgr.verify("signed-one")
        self.assertTrue(report["ok"], report)

    def test_verify_detects_drift(self):
        d = self._signed_plugin()
        self.mgr.install(d)
        installed = self.root / "signed-one" / "main.py"
        installed.write_text(installed.read_text() + "\n# drift\n")
        report = self.mgr.verify("signed-one")
        self.assertFalse(report["ok"])

    def test_upgrade_requires_newer_version(self):
        d = self._signed_plugin("upgrademe", "1.0.0")
        self.mgr.install(d)
        d2 = self._signed_plugin("upgrademe", "1.0.0")
        with self.assertRaises(Exception):
            self.mgr.upgrade(d2)

    def test_upgrade_newer_version(self):
        d = self._signed_plugin("upgood", "1.0.0")
        self.mgr.install(d)
        d2 = self._signed_plugin("upgood", "1.2.0")
        info = self.mgr.upgrade(d2)
        self.assertEqual(info.version, "1.2.0")

    def test_remove(self):
        d = self._signed_plugin("removeme")
        self.mgr.install(d)
        result = self.mgr.remove("removeme")
        self.assertEqual(result["removed"], "removeme")
        self.assertIsNone(self.mgr.info("removeme"))

    def test_remove_unknown_raises(self):
        with self.assertRaises(Exception):
            self.mgr.remove("ghost")

    def test_list_includes_installed(self):
        d = self._signed_plugin("listme")
        self.mgr.install(d)
        ids = [p.id for p in self.mgr.list_plugins()]
        self.assertIn("listme", ids)

    def test_list_skips_underscore_and_broken(self):
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "_hidden.py").write_text("def run(**k):\n    return []\n")
        (self.root / "broken.py").write_text("def not valid !!")
        (self.root / "norun.py").write_text("def other():\n    pass\n")
        ids = [p.id for p in self.mgr.list_plugins()]
        self.assertNotIn("_hidden", ids)
        self.assertNotIn("broken", ids)
        self.assertNotIn("norun", ids)

    def test_legacy_install_and_run(self):
        f = self.tmp / "legacy.py"
        f.write_text('def run(target, **kw):\n    return [{"title": "hi " + target, "severity": "info", "category": "t"}]\n')
        info = self.mgr.install(f)
        self.assertEqual(info.source, "legacy")
        result = self.mgr.run("legacy", "example.com")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.findings[0]["title"], "hi example.com")

    def test_local_key_creation(self):
        priv, pub = self.mgr.ensure_local_key()
        priv2, pub2 = self.mgr.ensure_local_key()
        self.assertEqual(priv, priv2)
        self.assertEqual(pub, pub2)
        self.assertEqual((self.root / "keys" / "local.ed25519").stat().st_mode & 0o777, 0o600)

    def test_trusted_keys_map(self):
        self.mgr.ensure_local_key()
        keys = self.mgr.trusted_keys()
        self.assertTrue(len(keys) >= 2)  # pub->pub + fingerprint->pub

    def test_add_trusted_key(self):
        _, pub = generate_keypair()
        fp = self.mgr.add_trusted_key(pub, "testkey")
        self.assertIn(fp, self.mgr.trusted_keys())

    def test_set_toml_key_appends_header(self):
        text = 'id = "x"\n\n[permissions]\nnetwork = false\n'
        out = _set_toml_key(text, "signature", "AB")
        self.assertIn('[provenance]', out)
        self.assertIn('signature = "AB"', out)
        import tomllib
        parsed = tomllib.loads(out)
        self.assertEqual(parsed["provenance"]["signature"], "AB")

    def test_set_toml_key_replaces_existing(self):
        text = '[provenance]\nsignature = "old"\n'
        out = _set_toml_key(text, "signature", "new")
        self.assertIn('signature = "new"', out)
        self.assertNotIn('signature = "old"', out)

    def test_set_toml_key_ignores_commented_header(self):
        text = '# [provenance]\n# signature = "x"\n'
        out = _set_toml_key(text, "signature", "AA")
        import tomllib
        parsed = tomllib.loads(out)
        self.assertEqual(parsed["provenance"]["signature"], "AA")


# ═══════════════════════════════════════════════════════════════════
# Runner / worker execution
# ═══════════════════════════════════════════════════════════════════

class TestRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _plugin(self, body: str) -> Path:
        f = self.tmp / "plug.py"
        f.write_text(body)
        return f

    def _run(self, body, args=None, **kw):
        runner = PluginRunner(wall_timeout_s=kw.pop("wall_timeout_s", 10), **kw)
        return runner.execute(self._plugin(body), args=args or {"target": "t"})

    def test_happy_path(self):
        r = self._run('def run(target, **kw):\n    return [{"title": "ok " + target, "severity": "info", "category": "c"}]\n')
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.kind, "ok")
        self.assertEqual(r.findings[0]["title"], "ok t")

    def test_pid_separation(self):
        r = self._run('import os\ndef run(**kw):\n    return [{"title": str(os.getpid()), "severity": "info", "category": "c"}]\n')
        self.assertTrue(r.ok)
        self.assertNotEqual(r.pid, os.getpid())
        self.assertNotEqual(int(r.findings[0]["title"]), os.getpid())

    def test_worker_session_pid_group(self):
        r = self._run('import os\ndef run(**kw):\n    return [{"title": str(os.getpgid(0)), "severity": "info", "category": "c"}]\n')
        self.assertTrue(r.ok)
        # start_new_session → worker pgid == worker pid
        self.assertEqual(int(r.findings[0]["title"]), r.pid)

    def test_crash_isolated(self):
        r = self._run('def run(**k):\n    raise RuntimeError("boom")\n')
        self.assertFalse(r.ok)
        self.assertEqual(r.kind, "crash")
        self.assertIn("boom", r.error)

    def test_non_list_rejected(self):
        r = self._run('def run(**k):\n    return "nope"\n')
        self.assertEqual(r.kind, "invalid_output")
        self.assertIn("list", r.error)

    def test_missing_keys_rejected(self):
        r = self._run('def run(**k):\n    return [{"title": "x"}]\n')
        self.assertEqual(r.kind, "invalid_output")

    def test_non_dict_items_rejected(self):
        r = self._run('def run(**k):\n    return ["str"]\n')
        self.assertEqual(r.kind, "invalid_output")

    def test_none_rejected(self):
        r = self._run('def run(**k):\n    return None\n')
        self.assertEqual(r.kind, "invalid_output")

    def test_no_run_function(self):
        r = self._run('def other():\n    pass\n')
        self.assertEqual(r.kind, "invalid_output")
        self.assertIn("run", r.error)

    def test_output_size_capped(self):
        big = "x" * 2000
        r = self._run(f'def run(**k):\n    return [{{"title": "{big}", "severity": "info", "category": "c"}} for _ in range(200)]\n',
                      max_output_bytes=1024)
        self.assertEqual(r.kind, "invalid_output")
        self.assertIn("output_size", r.error)

    def test_too_many_findings_rejected(self):
        r = self._run('def run(**k):\n    return [{"title": "x", "severity": "i", "category": "c"}] * 2000\n')
        self.assertEqual(r.kind, "invalid_output")

    def test_title_truncated(self):
        r = self._run('def run(**k):\n    return [{"title": "A" * 10000, "severity": "i", "category": "c"}]\n')
        self.assertTrue(r.ok)
        self.assertLessEqual(len(r.findings[0]["title"]), 513)

    def test_plugin_stdout_goes_to_stderr_not_result(self):
        r = self._run('def run(**k):\n    print("noise on stdout")\n    return [{"title": "clean", "severity": "i", "category": "c"}]\n')
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.findings[0]["title"], "clean")
        self.assertIn("noise on stdout", r.stderr_tail)

    def test_env_minimal_by_default(self):
        r = self._run('import os\nimport json\ndef run(**k):\n    return [{"title": json.dumps(sorted(os.environ.keys())), "severity": "i", "category": "c"}]\n')
        self.assertTrue(r.ok)
        names = json.loads(r.findings[0]["title"])
        self.assertNotIn("RECONPRO_TEST_SECRET", names)

    def test_env_allowlist_passthrough(self):
        with patch.dict(os.environ, {"RECONPRO_TEST_SECRET": "hunter2"}):
            from reconpro.plugin_sdk.permissions import PermissionSet
            r = PluginRunner(wall_timeout_s=10).execute(
                self._plugin('import os\ndef run(**k):\n    return [{"title": os.environ.get("RECONPRO_TEST_SECRET", "MISSING"), "severity": "i", "category": "c"}]\n'),
                permissions=PermissionSet(env=("RECONPRO_TEST_SECRET",)),
                args={"target": "t"})
        self.assertEqual(r.findings[0]["title"], "hunter2")

    def test_env_secret_key_never_passed(self):
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "leak"}):
            from reconpro.plugin_sdk.permissions import PermissionSet
            r = PluginRunner(wall_timeout_s=10).execute(
                self._plugin('import os\ndef run(**k):\n    return [{"title": os.environ.get("AWS_SECRET_ACCESS_KEY", "MISSING"), "severity": "i", "category": "c"}]\n'),
                permissions=PermissionSet(env=("AWS_SECRET_ACCESS_KEY",)),
                args={"target": "t"})
        self.assertEqual(r.findings[0]["title"], "MISSING")

    def test_timeout_killed(self):
        r = self._run('def run(**k):\n    import time\n    time.sleep(30)\n',
                      wall_timeout_s=3)
        self.assertEqual(r.kind, "timeout")
        self.assertLess(r.duration_ms, 8000)
        self.assertIsNotNone(r.exit_code)

    def test_result_duration_recorded(self):
        r = self._run('def run(**k):\n    return []\n')
        self.assertGreaterEqual(r.duration_ms, 0)

    def test_unicode_findings(self):
        r = self._run('def run(**k):\n    return [{"title": "\\U0001f525 crit \\u4e2d\\u6587", "severity": "i", "category": "c"}]\n')
        self.assertTrue(r.ok)
        self.assertIn("\U0001f525", r.findings[0]["title"])

    def test_missing_plugin_file(self):
        runner = PluginRunner(wall_timeout_s=6)
        r = runner.execute(self.tmp / "ghost.py", args={"target": "t"})
        self.assertFalse(r.ok)
        self.assertEqual(r.kind, "crash")

    def test_to_dict_envelope(self):
        r = self._run('def run(**k):\n    return []\n')
        d = r.to_dict()
        for key in ("ok", "kind", "pid", "findings", "error", "duration_ms"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()

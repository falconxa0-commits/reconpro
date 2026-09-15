"""Security sweep regression tests (Task 7-a — Blocker 4).

Enforces the post-sweep invariants of the reconpro package:

1. NO runtime ``shell=True`` / ``os.system`` / ``os.popen`` call sites
   (detector modules that *scan other code* for such patterns are exempt —
   their hits are string literals, not executed calls; the AST walk below
   parses them out anyway, but they are skipped for policy clarity).
2. NO insecure TLS context construction outside the single audited helper
   (``reconpro/http_layer.py::_unverified_context`` — reachable only via
   explicit user opt-in flags — and ``inspection_context`` for
   certificate-inspection connections).  Verification is the default
   everywhere.
3. NO ``eval``/``exec``/``compile`` calls on dynamic input.
4. NO unsafe deserialization (pickle/marshal/yaml.load without SafeLoader).
5. NO world-writable ``os.chmod`` and NO bulk ``extractall`` outside the
   audited safe_archive module (zip-slip / zip-bomb defence).
6. Behavioural tests for the shell-free command runner, the nexus agent
   shell tool, the external tool SDK handler, and safe archive extraction
   (traversal member, symlink member, zip bomb — all refused).

All behavioural tests run REAL subprocesses and REAL archives — no mocks.
"""

import ast
import inspect
import io
import os
import ssl
import stat as stat_mod
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import reconpro
from reconpro import safe_archive, safe_command
from reconpro.http_layer import _unverified_context, inspection_context

PACKAGE_ROOT = Path(reconpro.__file__).resolve().parent

# Modules that DETECT dangerous patterns in *other people's* code.  Their
# "shell=True" / "eval(" occurrences are detection patterns (string
# literals or scanner logic), never executed calls.
DETECTOR_MODULES = {
    "quality_intelligence.py",
    "supply_chain.py",
    "defense.py",
    "auto_fix.py",
    "ast_analyzer.py",
    "auto_validation.py",  # AST scanner for scanned code (same category)
}

SKIP_DIRS = {"tests", "__pycache__", "scripts"}

SUBPROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
}


# ── AST helpers ──────────────────────────────────────────────────────────

def _iter_package_files():
    """Yield (relative_name, path) for every runtime .py in the package."""
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        rel = path.relative_to(PACKAGE_ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if path.name in DETECTOR_MODULES:
            continue
        yield str(rel), path


def _parse(path: Path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _const_false(value) -> bool:
    return isinstance(value, ast.Constant) and value.value is False


# ═══════════════════════════════════════════════════════════════════════
# 1. AST package sweeps
# ═══════════════════════════════════════════════════════════════════════

class TestNoShellInvocation(unittest.TestCase):
    """The package must never spawn a shell to run a command."""

    def test_no_runtime_shell_true_or_os_system(self):
        """No subprocess call with shell=True, no os.system/os.popen."""
        offenders = []
        for rel, path in _iter_package_files():
            tree = _parse(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _dotted(node.func) if not isinstance(node.func, ast.Lambda) else ""
                if name in SUBPROCESS_FUNCS:
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if (isinstance(kw.value, ast.Constant)
                                    and kw.value.value is True):
                                offenders.append(
                                    f"{rel}:{node.lineno} {name}(shell=True)")
                            elif not isinstance(kw.value, ast.Constant):
                                offenders.append(
                                    f"{rel}:{node.lineno} {name}(shell=<dynamic>)")
                if name in ("os.system", "os.popen",
                            "os.popen2", "os.popen3", "os.popen4"):
                    offenders.append(f"{rel}:{node.lineno} {name}()")
        self.assertEqual(offenders, [],
                         "shell invocation found:\n" + "\n".join(offenders))

    def test_subprocess_first_args_are_not_raw_strings(self):
        """subprocess calls must receive argument lists (no bare strings)."""
        offenders = []
        for rel, path in _iter_package_files():
            tree = _parse(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _dotted(node.func)
                if name in SUBPROCESS_FUNCS and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        offenders.append(
                            f"{rel}:{node.lineno} {name}({first.value[:40]!r})")
        self.assertEqual(offenders, [],
                         "string command passed to subprocess:\n" + "\n".join(offenders))


class TestTLSVerificationDefaults(unittest.TestCase):
    """TLS verification must be the default; insecurity only via the
    audited http_layer helpers."""

    def test_no_unverified_context_outside_http_layer(self):
        """No module may hand-roll an unverified SSL context.

        Forbidden outside http_layer.py: ``ssl._create_unverified_context()``,
        ``ctx.check_hostname = False``, ``ctx.verify_mode = ssl.CERT_NONE``.
        """
        offenders = []
        for rel, path in _iter_package_files():
            if rel == "http_layer.py":
                continue  # the audited choke point lives here
            tree = _parse(path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _dotted(node.func)
                    if name.endswith("_create_unverified_context"):
                        offenders.append(f"{rel}:{node.lineno} {name}()")
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if not isinstance(target, ast.Attribute):
                            continue
                        if target.attr == "check_hostname" and _const_false(node.value):
                            offenders.append(f"{rel}:{node.lineno} check_hostname = False")
                        if (target.attr == "verify_mode"
                                and "CERT_NONE" in _dotted(node.value)):
                            offenders.append(f"{rel}:{node.lineno} verify_mode = CERT_NONE")
        self.assertEqual(offenders, [],
                         "unverified TLS context constructed:\n" + "\n".join(offenders))

    def test_private_ssl_api_absent_from_package_source(self):
        """``ssl._create_unverified_context`` must not appear anywhere in
        runtime module source (tests are excluded; they benchmark it)."""
        hits = [rel for rel, path in _iter_package_files()
                if "_create_unverified_context" in path.read_text(encoding="utf-8")]
        self.assertEqual(hits, [])

    def test_insecure_context_only_via_audited_helper(self):
        """The unverified context is obtainable ONLY through the audited
        http_layer helpers (which live in exactly one module)."""
        ctx = _unverified_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)
        insp = inspection_context()
        self.assertEqual(insp.verify_mode, ssl.CERT_NONE)
        self.assertFalse(insp.check_hostname)
        # the default context (used everywhere else) verifies
        self.assertEqual(ssl.create_default_context().verify_mode, ssl.CERT_REQUIRED)

    def test_verified_defaults_in_signatures(self):
        """Every TLS-taking entry point defaults to verification."""
        from reconpro.http_layer import http_probe
        from reconpro.fuzzer import FuzzSession
        from reconpro.modules.cloud_recon import (
            run_cloud_recon, probe_aws_metadata, probe_azure_metadata,
            probe_gcp_metadata, probe_digitalocean_metadata,
        )

        def default_of(func, param):
            sig = inspect.signature(func)
            self.assertIn(param, sig.parameters, f"{func.__name__} lacks {param}")
            return sig.parameters[param].default

        self.assertIs(default_of(http_probe, "verify_tls"), True)
        self.assertIs(default_of(FuzzSession.__init__, "verify_ssl"), True)
        self.assertIs(default_of(run_cloud_recon, "verify_tls"), True)
        for fn in (probe_aws_metadata, probe_azure_metadata,
                   probe_gcp_metadata, probe_digitalocean_metadata):
            self.assertIs(default_of(fn, "verify_tls"), True,
                          f"{fn.__name__} must default to verified TLS")

    def test_cloud_recon_has_no_hardcoded_insecure_probes(self):
        src = (PACKAGE_ROOT / "modules" / "cloud_recon.py").read_text(encoding="utf-8")
        self.assertNotIn("verify_tls=False", src)
        self.assertNotIn("verify_tls = False", src)


class TestNoDynamicCodeExecution(unittest.TestCase):
    """eval/exec/compile must never run on dynamic input."""

    def test_no_eval_exec_compile_calls(self):
        """No eval/exec/compile call sites exist in runtime modules.

        (``re.compile`` and friends are excluded — only bare names and
        non-``re`` attributes are flagged.  If a legitimate internal
        compile path is ever genuinely required, add it to WHITELIST with
        a documenting comment.)
        """
        WHITELIST = []  # documented exceptions; currently none
        offenders = []
        for rel, path in _iter_package_files():
            tree = _parse(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name) and func.id in ("eval", "exec", "compile"):
                    offenders.append(f"{rel}:{node.lineno} {func.id}()")
                elif isinstance(func, ast.Attribute) and func.attr in ("eval", "exec"):
                    offenders.append(f"{rel}:{node.lineno} {_dotted(func)}()")
                elif (isinstance(func, ast.Attribute) and func.attr == "compile"
                        and _dotted(func.value) not in ("re",)):
                    offenders.append(f"{rel}:{node.lineno} {_dotted(func)}()")
        offenders = [o for o in offenders if o not in WHITELIST]
        self.assertEqual(offenders, [],
                         "dynamic code execution found:\n" + "\n".join(offenders))


class TestNoUnsafeDeserialization(unittest.TestCase):

    def test_no_pickle_marshal_or_unsafe_yaml(self):
        offenders = []
        for rel, path in _iter_package_files():
            tree = _parse(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _dotted(node.func)
                if name in ("pickle.loads", "pickle.load",
                            "marshal.loads", "marshal.load", "dill.loads"):
                    offenders.append(f"{rel}:{node.lineno} {name}")
                if name == "yaml.load":
                    loader = [k for k in node.keywords if k.arg == "Loader"]
                    safe = any("Safe" in _dotted(k.value) or "safe" in _dotted(k.value)
                               for k in loader)
                    if not safe:
                        offenders.append(f"{rel}:{node.lineno} yaml.load() without SafeLoader")
        self.assertEqual(offenders, [],
                         "unsafe deserialization found:\n" + "\n".join(offenders))


class TestNoWorldWritablePermissions(unittest.TestCase):

    def test_no_world_writable_chmod(self):
        offenders = []
        for rel, path in _iter_package_files():
            tree = _parse(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if _dotted(node.func).endswith("chmod") and len(node.args) >= 2:
                    mode = node.args[1]
                    if isinstance(mode, ast.Constant) and isinstance(mode.value, int):
                        if mode.value & 0o022:
                            offenders.append(f"{rel}:{node.lineno} chmod {oct(mode.value)}")
        self.assertEqual(offenders, [],
                         "world/group-writable chmod found:\n" + "\n".join(offenders))


class TestSafeArchiveOnlyExtraction(unittest.TestCase):

    def test_no_bulk_extractall_outside_safe_archive(self):
        """Bulk extraction must go through safe_archive (zip-slip/bomb)."""
        offenders = []
        for rel, path in _iter_package_files():
            if rel == "safe_archive.py":
                continue
            tree = _parse(path)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "extractall"):
                    offenders.append(f"{rel}:{node.lineno} .extractall()")
        self.assertEqual(offenders, [],
                         "raw extractall found:\n" + "\n".join(offenders))


# ═══════════════════════════════════════════════════════════════════════
# 2. Behavioural: shell-free command runner
# ═══════════════════════════════════════════════════════════════════════

class TestSafeCommandRunner(unittest.TestCase):
    """reconpro.safe_command — real subprocesses, no mocks."""

    def test_shell_metacharacters_are_inert(self):
        """;, $(), backticks and && must never reach a shell."""
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pwned")
            for cmd in (
                f"echo hi; touch {marker}",
                f"echo $(touch {marker})",
                f"echo `touch {marker}`",
                f"echo hi && touch {marker}",
            ):
                rc, out = safe_command.run_command(cmd, timeout=10)
                self.assertEqual(rc, 0, msg=cmd)
                self.assertFalse(os.path.exists(marker),
                                 f"command executed via shell: {cmd}")
            self.assertFalse(os.path.exists(marker))

    def test_pipeline_chaining(self):
        rc, out = safe_command.run_command(
            "printf 'c\\na\\nb\\n' | sort | head -1", timeout=10)
        self.assertEqual(rc, 0)
        self.assertEqual(out, "a")

    def test_fallback_operator(self):
        rc, out = safe_command.run_command(
            "ls /definitely_not_here_7a 2>/dev/null || echo fallback", timeout=10)
        self.assertEqual(rc, 0)
        self.assertEqual(out, "fallback")

    def test_stderr_redirect_is_dropped_safely(self):
        # the redirect token must not corrupt argv; stderr is captured and
        # returned to the caller (legacy _run semantics: stdout + stderr)
        rc, out = safe_command.run_command(
            "ls /definitely_not_here_7b 2>/dev/null", timeout=10)
        self.assertNotEqual(rc, 0)
        self.assertIn("definitely_not_here_7b", out)

    def test_list_form_runs_without_shell(self):
        rc, out = safe_command.run_command([sys.executable, "-c", "print('list-ok')"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "list-ok")

    def test_timeout(self):
        rc, _ = safe_command.run_command(
            [sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
        self.assertEqual(rc, -1)

    def test_host_and_doctor_run_use_no_shell(self):
        """modules.host / modules.doctor _run helpers must be shell-free."""
        from reconpro.modules import doctor, host
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pwned")
            for runner in (host._run, doctor._run):
                rc, out = runner(f"echo a; touch {marker}")
                self.assertEqual(rc, 0)
                self.assertFalse(os.path.exists(marker),
                                 f"{runner.__module__}._run executed a shell")
        # sanity: a real command still works through the module helper
        rc, out = host._run("printf 'host-ok' 2>/dev/null")
        self.assertEqual((rc, out), (0, "host-ok"))


class TestNexusShellTool(unittest.TestCase):
    """nexus_agent._tool_shell_command must never spawn a shell."""

    def test_basic_execution(self):
        from reconpro.nexus_agent import _tool_shell_command
        result = _tool_shell_command("echo nexus-safe")
        self.assertTrue(result.success)
        self.assertIn("nexus-safe", result.output)

    def test_injection_inert(self):
        from reconpro.nexus_agent import _tool_shell_command
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pwned")
            _tool_shell_command(f"echo x; touch {marker}")
            self.assertFalse(os.path.exists(marker), "shell injection via nexus tool")

    def test_dangerous_pattern_blocked(self):
        from reconpro.nexus_agent import _tool_shell_command
        result = _tool_shell_command("rm -rf /")
        self.assertFalse(result.success)
        self.assertIn("Blocked", result.output)

    def test_missing_binary(self):
        from reconpro.nexus_agent import _tool_shell_command
        result = _tool_shell_command("definitely_not_a_binary_7a --x")
        self.assertFalse(result.success)


class TestExternalToolHandler(unittest.TestCase):
    """tool_sdk.ExternalToolHandler must execute argv lists, not strings."""

    def test_template_substitution_without_shell(self):
        from reconpro.tool_sdk import ExternalToolHandler
        handler = ExternalToolHandler(
            name="echo_tool",
            command=f"{sys.executable} -c 'print(\"tool-ok\")'",
            parser="raw",
        )
        out = handler()  # _substitute returns a str; __call__ shlex.splits it
        self.assertIn("tool-ok", out)

    def test_injection_through_kwargs_is_inert(self):
        from reconpro.tool_sdk import ExternalToolHandler
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pwned")
            handler = ExternalToolHandler(name="inj", command="echo {target}",
                                          parser="raw")
            out = handler(target=f"x; touch {marker}")
            self.assertFalse(os.path.exists(marker),
                             "tools.yaml injection executed")
            # the payload is echoed literally, never executed
            self.assertIn("touch", out)


# ═══════════════════════════════════════════════════════════════════════
# 3. Behavioural: safe archive extraction
# ═══════════════════════════════════════════════════════════════════════

class TestSafeZipExtraction(unittest.TestCase):
    """safe_archive.safe_extract_zip — real archives, no mocks."""

    @staticmethod
    def _make_zip(path, members):
        """members: list of (filename, data, unix_mode) tuples."""
        with zipfile.ZipFile(path, "w") as zf:
            for name, data, mode in members:
                info = zipfile.ZipInfo(name)
                info.external_attr = (mode if mode is not None else 0o644) << 16
                zf.writestr(info, data)

    def test_normal_zip_extracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            zpath = os.path.join(tmp, "a.zip")
            self._make_zip(zpath, [
                ("good.txt", b"hello", 0o644),
                ("sub/nested.txt", b"nested", 0o644),
            ])
            with zipfile.ZipFile(zpath) as zf:
                extracted = safe_archive.safe_extract_zip(zf, dest)
            self.assertEqual(len(extracted), 2)
            self.assertEqual((Path(dest) / "good.txt").read_bytes(), b"hello")
            self.assertEqual((Path(dest) / "sub" / "nested.txt").read_bytes(), b"nested")
            # restrictive permissions on extracted files
            mode = stat_mod.S_IMODE(os.stat(os.path.join(dest, "good.txt")).st_mode)
            self.assertEqual(mode, 0o600)

    def test_traversal_member_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            zpath = os.path.join(tmp, "a.zip")
            self._make_zip(zpath, [("../evil.txt", b"evil", 0o644)])
            with zipfile.ZipFile(zpath) as zf:
                with self.assertRaises(safe_archive.UnsafeArchiveError):
                    safe_archive.safe_extract_zip(zf, dest)
            self.assertFalse(os.path.exists(os.path.join(tmp, "evil.txt")))
            self.assertFalse(os.path.exists(os.path.join(dest, "evil.txt")))

    def test_absolute_path_member_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            zpath = os.path.join(tmp, "a.zip")
            self._make_zip(zpath, [("/etc/evil-7a.txt", b"evil", 0o644)])
            with zipfile.ZipFile(zpath) as zf:
                with self.assertRaises(safe_archive.UnsafeArchiveError):
                    safe_archive.safe_extract_zip(zf, dest)

    def test_symlink_member_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            zpath = os.path.join(tmp, "a.zip")
            self._make_zip(zpath, [
                ("link.txt", b"/etc/passwd", stat_mod.S_IFLNK | 0o777),
            ])
            with zipfile.ZipFile(zpath) as zf:
                with self.assertRaises(safe_archive.UnsafeArchiveError):
                    safe_archive.safe_extract_zip(zf, dest)
            self.assertFalse(os.path.exists(os.path.join(dest, "link.txt")))

    def test_zip_bomb_refused(self):
        """A >100 MiB (uncompressed) highly-compressible member must be
        rejected by the decompressed-size cap BEFORE extraction."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            zpath = os.path.join(tmp, "bomb.zip")
            payload = b"\x00" * (safe_archive.MAX_TOTAL_BYTES + (5 * 1024 * 1024))
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("bomb.bin", payload)
            del payload
            # sanity: the archive really is tiny (highly compressed)
            self.assertLess(os.path.getsize(zpath), 5 * 1024 * 1024)
            with zipfile.ZipFile(zpath) as zf:
                with self.assertRaises(safe_archive.UnsafeArchiveError):
                    safe_archive.safe_extract_zip(zf, dest)
            self.assertFalse(os.path.exists(os.path.join(dest, "bomb.bin")))

    def test_aggregate_cap_refused(self):
        """Many members totalling > the aggregate cap must be refused."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            zpath = os.path.join(tmp, "many.zip")
            chunk = b"A" * (48 * 1024 * 1024)  # 3 members ≈ 144 MiB total
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
                for i in range(3):
                    zf.writestr(f"m{i}.bin", chunk)
            with zipfile.ZipFile(zpath) as zf:
                with self.assertRaises(safe_archive.UnsafeArchiveError):
                    safe_archive.safe_extract_zip(zf, dest)


class TestSafeTarExtraction(unittest.TestCase):

    def test_normal_tar_extracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            tpath = os.path.join(tmp, "a.tar")
            with tarfile.open(tpath, "w") as tf:
                data = b"hello-tar"
                info = tarfile.TarInfo("good.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            with tarfile.open(tpath) as tf:
                extracted = safe_archive.safe_extract_tar(tf, dest)
            self.assertEqual(len(extracted), 1)
            self.assertEqual((Path(dest) / "good.txt").read_bytes(), b"hello-tar")

    def test_tar_traversal_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out")
            tpath = os.path.join(tmp, "evil.tar")
            with tarfile.open(tpath, "w") as tf:
                data = b"x"
                info = tarfile.TarInfo("../evil.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            with tarfile.open(tpath) as tf:
                with self.assertRaises(safe_archive.UnsafeArchiveError):
                    safe_archive.safe_extract_tar(tf, dest)
            self.assertFalse(os.path.exists(os.path.join(tmp, "evil.txt")))

            tpath2 = os.path.join(tmp, "link.tar")
            with tarfile.open(tpath2, "w") as tf:
                info = tarfile.TarInfo("link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tf.addfile(info)
            with tarfile.open(tpath2) as tf:
                with self.assertRaises(safe_archive.UnsafeArchiveError):
                    safe_archive.safe_extract_tar(tf, dest)
            self.assertFalse(os.path.lexists(os.path.join(dest, "link")))


class TestWorkspaceImportSafety(unittest.TestCase):
    """workspace.import_ws must refuse malicious archives (integration)."""

    def test_import_refuses_traversal_archive(self):
        from reconpro.workspace import WorkspaceManager
        from reconpro.safe_archive import UnsafeArchiveError
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "ws")
            zpath = os.path.join(tmp, "evil.zip")
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("../escaped-7a.txt", b"evil")
            mgr = WorkspaceManager(base_dir=base)
            with self.assertRaises(UnsafeArchiveError):
                mgr.import_ws(zpath, new_name="evil")
            self.assertFalse(os.path.exists(os.path.join(tmp, "escaped-7a.txt")))

    def test_import_accepts_clean_archive(self):
        from reconpro.workspace import WorkspaceManager
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "ws")
            zpath = os.path.join(tmp, "good.zip")
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("workspace.json", '{"name": "good"}')
            mgr = WorkspaceManager(base_dir=base)
            meta = mgr.import_ws(zpath, new_name="good")
            self.assertEqual(meta["name"], "good")


if __name__ == "__main__":
    unittest.main()

"""Regression tests — scanner truth layer + strict command handling.

Covers the three Phase-1 hardening areas:

1. Strict command handling — unknown commands must exit 2 with a helpful
   error BEFORE any network activity (regression: they used to silently
   become scan targets and hang the CLI).
2. Target Validation Pipeline — DNS → Reachability → HTTP/TLS → decision.
   UNREACHABLE targets must never produce HIGH severity findings, scores,
   or grades; every finding carries evidence, confidence and a
   verification state.
3. Shipped-module regressions — honeypot_dance regex crash and
   steganography_detector signature mismatch must never return.
"""

from __future__ import annotations

import io
import logging
import os
import re
import sys
import threading
import http.server
import socketserver
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import Finding
from reconpro.target_validation import (
    VERIFIED_TARGET, PARTIAL_TARGET, UNREACHABLE_TARGET,
    TargetValidation, validate_target_pipeline,
    apply_target_truth, unreachable_finding, state_confidence,
)


# ═══════════════════════════════════════════════════════════════════════
# Test HTTP fixtures
# ═══════════════════════════════════════════════════════════════════════

_HTML = (b"<!DOCTYPE html><html><head><title>Test</title></head>"
         b"<body><h1>Welcome</h1><a href='/admin'>admin</a></body></html>")


class _SilentHandler(http.server.BaseHTTPRequestHandler):
    def _reply(self, status=200, body=_HTML):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(404 if "nonexistent" in self.path else 200)

    do_POST = do_PUT = do_DELETE = do_HEAD = do_GET

    def log_message(self, *a):
        pass


def _start_http_server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _SilentHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def _start_raw_tcp_server():
    """A TCP listener that accepts but never speaks HTTP → PARTIAL target."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(4)
    port = s.getsockname()[1]

    def _accept_loop():
        while True:
            try:
                conn, _ = s.accept()
                conn.close()
            except OSError:
                return

    threading.Thread(target=_accept_loop, daemon=True).start()
    return s, port


def _closed_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ═══════════════════════════════════════════════════════════════════════
# 1. Strict command handling
# ═══════════════════════════════════════════════════════════════════════


class TestScanTargetDetection(unittest.TestCase):
    """looks_like_scan_target keeps the domain shorthand but rejects typos."""

    def test_domains_look_like_targets(self):
        from reconpro.cli import looks_like_scan_target
        for t in ("example.com", "sub.example.co.uk", "example.com:8080",
                  "example.com/path", "https://example.com", "http://x.io",
                  "127.0.0.1", "127.0.0.1:3000", "10.0.0.1",
                  "localhost", "localhost:8080", "my-site.example.org"):
            self.assertTrue(looks_like_scan_target(t), f"{t} should pass")

    def test_words_do_not_look_like_targets(self):
        from reconpro.cli import looks_like_scan_target
        for t in ("unknown-command", "scna", "listt", "help-me", "auditall",
                  "run", "scan-all", "", " ", "--", "-", "/etc/passwd",
                  "not a command", "cmd;rm -rf /", "$(whoami)", "`id`"):
            self.assertFalse(looks_like_scan_target(t), f"{t} should FAIL")


class TestUnknownCommandExits2(unittest.TestCase):
    """`reconpro unknown-command` must exit 2, helpfully, without scanning."""

    def _run_main(self, argv):
        from reconpro import cli
        err = io.StringIO()
        out = io.StringIO()

        def _fail_if_scanning(*a, **k):
            raise AssertionError("heavy engine loaded — scan started!")

        with patch.object(cli, "_load_heavy", side_effect=_fail_if_scanning), \
             patch.object(sys, "stderr", err), patch.object(sys, "stdout", out):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(argv)
        return ctx.exception.code, err.getvalue(), out.getvalue()

    def test_unknown_command_exit_code_is_2(self):
        code, _, _ = self._run_main(["unknown-command-xyz"])
        self.assertEqual(code, 2)

    def test_unknown_command_message_is_helpful(self):
        code, err, _ = self._run_main(["unknown-command-xyz"])
        self.assertIn("unknown command", err)
        self.assertIn("reconpro --help", err)
        self.assertIn("reconpro scan unknown-command-xyz", err)

    def test_unknown_command_never_scans(self):
        # _load_heavy is patched to raise → any scan attempt fails the test
        t0 = time.monotonic()
        self._run_main(["unknown-command-xyz"])
        self.assertLess(time.monotonic() - t0, 5.0, "must fail fast")

    def test_typo_gets_did_you_mean(self):
        _, err, _ = self._run_main(["scna"])
        self.assertIn("Did you mean: scan?", err)
        _, err2, _ = self._run_main(["listt"])
        self.assertIn("Did you mean: list?", err2)

    def test_valid_domain_shorthand_not_rejected_at_parse(self):
        """example.com survives the guard (full scan is not executed here)."""
        from reconpro import cli
        err = io.StringIO()
        out = io.StringIO()
        with patch.object(sys, "stderr", err), patch.object(sys, "stdout", out):
            # Scan against a guaranteed-unreachable reserved domain: the
            # truth layer short-circuits instantly, proving the shorthand
            # was accepted and the parser dispatched `scan`.
            try:
                cli.main(["nonexistent-target-xyz.invalid", "-t", "1"])
            except SystemExit as e:
                # Exit 0 (clean honest no-result), NOT exit 2 (unknown command)
                self.assertEqual(e.code, 0)
        self.assertNotIn("unknown command", err.getvalue())
        # If we get here the guard accepted the domain and dispatched a
        # real (instantly short-circuited) scan instead of exiting 2.


# ═══════════════════════════════════════════════════════════════════════
# 2. Target validation pipeline
# ═══════════════════════════════════════════════════════════════════════


class TestValidationPipelineStates(unittest.TestCase):
    """The pipeline classifies targets into the three truth states."""

    @classmethod
    def setUpClass(cls):
        cls.http_srv, cls.http_port = _start_http_server()
        cls.raw_sock, cls.raw_port = _start_raw_tcp_server()

    @classmethod
    def tearDownClass(cls):
        cls.http_srv.shutdown()
        cls.raw_sock.close()

    def test_verified_target(self):
        v = validate_target_pipeline(f"127.0.0.1:{self.http_port}", timeout=2)
        self.assertEqual(v.state, VERIFIED_TARGET)
        self.assertTrue(v.dns_resolved)
        self.assertTrue(v.reachable)
        self.assertTrue(v.http_ok)
        self.assertEqual(v.details.get("http_status"), 200)

    def test_unreachable_via_reserved_domain(self):
        # .invalid is RFC-2606-reserved → guaranteed NXDOMAIN
        v = validate_target_pipeline("nonexistent-target-xyz.invalid", timeout=2)
        self.assertEqual(v.state, UNREACHABLE_TARGET)
        self.assertFalse(v.dns_resolved)
        self.assertIn("DNS", v.details.get("reason", ""))

    def test_unreachable_via_closed_port(self):
        port = _closed_port()
        v = validate_target_pipeline(f"127.0.0.1:{port}", timeout=2)
        self.assertEqual(v.state, UNREACHABLE_TARGET)
        self.assertTrue(v.dns_resolved)
        self.assertFalse(v.reachable)

    def test_partial_target_non_http_service(self):
        v = validate_target_pipeline(f"http://127.0.0.1:{self.raw_port}", timeout=2)
        self.assertEqual(v.state, PARTIAL_TARGET)
        self.assertTrue(v.dns_resolved)
        self.assertTrue(v.reachable)
        self.assertFalse(v.http_ok)

    def test_checked_at_timestamp_present(self):
        v = validate_target_pipeline(f"127.0.0.1:{self.http_port}", timeout=2)
        self.assertRegex(v.checked_at, r"^\d{4}-\d{2}-\d{2}T")


class TestApplyTargetTruth(unittest.TestCase):
    """Finding tagging + severity capping rules."""

    def _finding(self, severity="high"):
        return Finding(title="t", severity=severity, category="c", module="m",
                       description="d", evidence="e", asset="a")

    def test_verified_keeps_severity(self):
        f = self._finding("critical")
        v = TargetValidation(state=VERIFIED_TARGET, dns_resolved=True,
                             reachable=True, http_ok=True, tls_valid=True)
        apply_target_truth([f], v)
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.verification_state, VERIFIED_TARGET)

    def test_partial_caps_high_to_medium(self):
        f = self._finding("high")
        v = TargetValidation(state=PARTIAL_TARGET, dns_resolved=True,
                             reachable=True, http_ok=False, tls_valid=None)
        apply_target_truth([f], v)
        self.assertEqual(f.severity, "medium")
        self.assertIn("downgraded from high", f.evidence)
        self.assertEqual(f.verification_state, PARTIAL_TARGET)
        self.assertAlmostEqual(f.confidence, state_confidence(PARTIAL_TARGET))

    def test_partial_caps_critical_to_medium(self):
        f = self._finding("critical")
        v = TargetValidation(state=PARTIAL_TARGET, dns_resolved=True,
                             reachable=True, http_ok=False, tls_valid=None)
        apply_target_truth([f], v)
        self.assertEqual(f.severity, "medium")

    def test_partial_keeps_low_and_info(self):
        for sev in ("low", "info", "medium"):
            f = self._finding(sev)
            v = TargetValidation(state=PARTIAL_TARGET, dns_resolved=True,
                                 reachable=True, http_ok=False, tls_valid=None)
            apply_target_truth([f], v)
            self.assertEqual(f.severity, sev, f"{sev} must not be downgraded")

    def test_unreachable_caps_everything(self):
        f = self._finding("high")
        v = TargetValidation(state=UNREACHABLE_TARGET, dns_resolved=False,
                             reachable=False, http_ok=False, tls_valid=None)
        apply_target_truth([f], v)
        self.assertIn(f.severity, ("low", "info"))

    def test_finding_dict_contains_truth_fields(self):
        f = self._finding("high")
        v = TargetValidation(state=VERIFIED_TARGET, dns_resolved=True,
                             reachable=True, http_ok=True, tls_valid=True)
        apply_target_truth([f], v)
        d = f.to_dict()
        self.assertIn("confidence", d)
        self.assertIn("verification_state", d)
        self.assertEqual(d["verification_state"], VERIFIED_TARGET)


class TestUnreachableScanShortCircuit(unittest.TestCase):
    """End-to-end: scanning an unreachable target is honest."""

    def test_engine_scan_unreachable(self):
        import logging
        logging.disable(logging.WARNING)
        try:
            from reconpro.engine import scan
            r = scan("nonexistent-target-xyz.invalid", timeout=2,
                     run_intelligence=False)
        finally:
            logging.disable(logging.NOTSET)
        d = r.to_dict()
        self.assertEqual(d["target_validation"]["state"], UNREACHABLE_TARGET)
        self.assertEqual(d["total_score"], 0)
        self.assertEqual(d["grade"], "U")
        self.assertEqual(d["modules_run"], [])
        # No HIGH/CRITICAL findings — impossible by construction
        for f in d["findings"]:
            self.assertNotIn(f["severity"], ("high", "critical"))
        self.assertEqual(len(d["findings"]), 1)
        self.assertEqual(d["findings"][0]["category"], "target_validation")
        self.assertIn("confidence", d["findings"][0])
        self.assertIn("verification_state", d["findings"][0])
        # Metadata present
        self.assertIn("started_at", d["scan_metadata"])

    def test_sequential_scan_unreachable(self):
        import logging
        logging.disable(logging.WARNING)
        try:
            from reconpro.scanner import scan
            r = scan("nonexistent-target-xyz.invalid", timeout=2)
        finally:
            logging.disable(logging.NOTSET)
        d = r.to_dict()
        self.assertEqual(d["target_validation"]["state"], UNREACHABLE_TARGET)
        self.assertEqual(d["total_score"], 0)
        for f in d["findings"]:
            self.assertNotIn(f["severity"], ("high", "critical"))


class TestVerifiedScanTagging(unittest.TestCase):
    """End-to-end: findings from a live target carry the truth fields."""

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.port = _start_http_server()
        import logging
        logging.disable(logging.WARNING)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        logging.disable(logging.NOTSET)

    def test_findings_tagged_verified(self):
        from reconpro.engine import scan
        r = scan(f"127.0.0.1:{self.port}", modules=["auth"], timeout=2,
                 verify_tls=False, run_intelligence=False)
        d = r.to_dict()
        self.assertEqual(d["target_validation"]["state"], VERIFIED_TARGET)
        self.assertTrue(d["findings"])
        for f in d["findings"]:
            self.assertEqual(f["verification_state"], VERIFIED_TARGET)
            self.assertIsInstance(f["confidence"], float)
            self.assertTrue(0.0 <= f["confidence"] <= 1.0)
            self.assertTrue(f["evidence"], "every finding must carry evidence")


# ═══════════════════════════════════════════════════════════════════════
# 3. Shipped-module regressions (honeypot_dance + steganography_detector)
# ═══════════════════════════════════════════════════════════════════════


class TestHoneypotDanceRegression(unittest.TestCase):
    """Regression: mid-expression (?i) regex flags crashed the module."""

    def test_perfect_response_db_patterns_compile(self):
        from reconpro.modules.honeypot_dance import PERFECT_RESPONSE_DB
        for entry in PERFECT_RESPONSE_DB["error_pages"]:
            re.compile(entry["pattern"], re.DOTALL | re.IGNORECASE)
        for entry in PERFECT_RESPONSE_DB["header_perfection"]:
            for val_pattern, _, _ in entry["suspicious_values"]:
                re.compile(val_pattern, re.IGNORECASE)

    def test_module_runs_without_crash(self):
        from reconpro.modules.honeypot_dance import run_honeypot_dance
        srv, port = _start_http_server()
        try:
            out = run_honeypot_dance(f"127.0.0.1:{port}",
                                    f"http://127.0.0.1:{port}",
                                    timeout=2, verify_tls=False)
            self.assertIsInstance(out, list)
            for f in out:
                self.assertIsInstance(f, Finding)
        finally:
            srv.shutdown()


class TestSteganographyDetectorRegression(unittest.TestCase):
    """Regression: internal check call signatures mismatched definitions."""

    def test_module_runs_without_crash(self):
        from reconpro.modules.steganography_detector import run_steganography_detector
        srv, port = _start_http_server()
        try:
            out = run_steganography_detector(f"127.0.0.1:{port}",
                                            f"http://127.0.0.1:{port}",
                                            timeout=2, verify_tls=False)
            self.assertIsInstance(out, list)
        finally:
            srv.shutdown()

    def test_zero_width_steganography_detected_on_poisoned_body(self):
        """The whitespace check must still actually detect things."""
        from reconpro.modules.steganography_detector import _check_whitespace_steganography
        poisoned = "line one\u200bline two\u200b\nline three\u200b\nline four"
        findings = _check_whitespace_steganography(poisoned, "text/html")
        self.assertTrue(findings, "zero-width chars must be detected")
        self.assertTrue(any("Zero-Width" in f.title for f in findings))


if __name__ == "__main__":
    unittest.main()

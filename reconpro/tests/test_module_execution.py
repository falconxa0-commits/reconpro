"""Full module execution matrix — every shipped module must run safely.

Regression guard for "every module can execute safely":
each of the 28 module runners is executed against a local HTTP server
(and local filesystem for the local modules).  A module may return any
number of findings — but it must NEVER raise, hang, or return garbage.

This is the slow-but-thorough companion of test_integration.py.
"""

from __future__ import annotations

import http.server
import logging
import os
import socketserver
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

logging.disable(logging.WARNING)

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

_HTML = (b"<!DOCTYPE html><html><head><title>Test</title></head>"
         b"<body><h1>Welcome</h1><a href='/admin'>admin</a></body></html>")


class _SilentHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "nonexistent" in self.path:
            self.send_response(404)
        else:
            self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_HTML)

    do_POST = do_PUT = do_DELETE = do_HEAD = do_GET

    def log_message(self, *a):
        pass


REMOTE_RUNNERS = {
    "recon": run_recon, "auth": run_auth, "chain": run_chain,
    "bot": run_bot, "gorgon": run_gorgon, "oblivion": run_oblivion,
    "nhi": run_nhi, "cloud_recon": run_cloud_recon, "pegasus": run_pegasus,
    "team": run_team, "quantum_fingerprint": run_quantum_fingerprint,
    "dark_web_monitor": run_dark_web_monitor, "info_ops": run_info_ops,
    "steganography_detector": run_steganography_detector,
    "covert_channel": run_covert_channel, "zero_day_hunter": run_zero_day_hunter,
    "infrastructure_ghost": run_infrastructure_ghost,
    "signal_intelligence": run_signal_intelligence,
    "nation_state_attributor": run_nation_state_attributor,
    "weaponized_report": run_weaponized_report,
    "honeypot_dance": run_honeypot_dance, "dead_drop": run_dead_drop,
}

LOCAL_RUNNERS = {
    "host": run_host, "dev": run_dev, "doctor": run_doctor,
    "container_sec": run_container_sec, "iac_audit": run_iac_audit,
}

# vibesec returns (findings, score, grade, badge) — documented special case
# handled by the engine; verified separately.


class TestAllRemoteModulesExecute(unittest.TestCase):
    """Every remote module must complete without raising against a live
    local HTTP server. Findings count may be anything (including zero)."""

    @classmethod
    def setUpClass(cls):
        cls.srv = socketserver.TCPServer(("127.0.0.1", 0), _SilentHandler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_all_remote_modules_execute_safely(self):
        failures = []
        for name, fn in sorted(REMOTE_RUNNERS.items()):
            with self.subTest(module=name):
                try:
                    out = fn(
                        target=f"127.0.0.1:{self.port}",
                        base_url=f"http://127.0.0.1:{self.port}",
                        timeout=2, verify_tls=False,
                    )
                    self.assertIsInstance(out, list,
                                          f"{name} must return a list")
                    for f in out:
                        self.assertTrue(hasattr(f, "severity"),
                                       f"{name} returned non-Finding item")
                except Exception as exc:
                    failures.append(f"{name}: {type(exc).__name__}: {exc}")
        self.assertEqual(failures, [], "modules crashed: " + "; ".join(failures))

    def test_module_count_matches_registry(self):
        from reconpro.registry import MODULE_REGISTRY, LOCAL_MODULES
        self.assertEqual(len(REMOTE_RUNNERS) + 1 + len(LOCAL_RUNNERS), 28,
                         "28 modules expected (25 remote + vibesec + 3 local-style)")
        for m in REMOTE_RUNNERS:
            self.assertIn(m, MODULE_REGISTRY, f"{m} missing from registry")


class TestAllLocalModulesExecute(unittest.TestCase):
    """Local modules must complete against a temp directory."""

    def test_all_local_modules_execute_safely(self):
        import tempfile
        failures = []
        with tempfile.TemporaryDirectory() as tmp:
            for name, fn in sorted(LOCAL_RUNNERS.items()):
                with self.subTest(module=name):
                    try:
                        out = fn(target="." if name == "dev" else tmp,
                                 base_url="", timeout=4, verify_tls=True)
                        self.assertIsInstance(out, list, f"{name} must return a list")
                    except Exception as exc:
                        failures.append(f"{name}: {type(exc).__name__}: {exc}")
        self.assertEqual(failures, [], "local modules crashed: " + "; ".join(failures))


class TestVibesecContract(unittest.TestCase):
    """vibesec's documented tuple return must stay engine-compatible."""

    @classmethod
    def setUpClass(cls):
        cls.srv = socketserver.TCPServer(("127.0.0.1", 0), _SilentHandler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_vibesec_returns_documented_tuple(self):
        out = run_vibesec(f"127.0.0.1:{self.port}", f"http://127.0.0.1:{self.port}",
                          timeout=2, verify_tls=False)
        self.assertIsInstance(out, tuple)
        self.assertEqual(len(out), 4)
        findings, score, grade, badge = out
        self.assertIsInstance(findings, list)
        self.assertIsInstance(score, int)
        self.assertIsInstance(grade, str)
        self.assertIsInstance(badge, str)


if __name__ == "__main__":
    unittest.main()

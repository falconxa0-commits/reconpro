"""HOSTILE ATTACK SUITE for the ReconPro plugin sandbox.

Every test writes a MALICIOUS plugin and runs it through the real
PluginRunner (separate OS process).  The assertion in every test is that
the attack ACHIEVES NOTHING:

* no files created outside the sandbox workdir,
* no secrets leaked,
* no network access,
* no privilege change,
* no crash of the host process.

Real subprocesses, real filesystems, real timeouts — no mocks.
"""
from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from reconpro.plugin_sdk import PermissionSet, PluginRunner

REPO = Path(__file__).resolve().parents[2]


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="attack-"))


class Attacks(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp()
        self.runner = PluginRunner(wall_timeout_s=8)
        # marker files the attacks try to create/read
        self.outside_dir = _tmp()
        self.pwn_marker = self.outside_dir / "pwned.txt"
        self.secret_file = self.outside_dir / "secret.txt"
        self.secret_file.write_text("TOPSECRET-DATA")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(self.outside_dir, ignore_errors=True)

    def _evil(self, body: str) -> Path:
        f = self.tmp / "evil.py"
        f.write_text(body)
        return f

    def _attack(self, body: str, **runner_kw):
        if "runner" in runner_kw:
            runner = runner_kw.pop("runner")
        else:
            wall = runner_kw.pop("wall_timeout_s", 8)
            runner = PluginRunner(wall_timeout_s=wall, **runner_kw)
        return runner.execute(self._evil(body), args={"target": "example.com"})

    # ── 1. subprocess ─────────────────────────────────────────────
    def test_attack_subprocess_popen(self):
        r = self._attack(
            "import subprocess\n"
            "def run(**k):\n"
            f"    subprocess.Popen(['touch', '{self.pwn_marker}'])\n"
            "    return []\n")
        self.assertEqual(r.kind, "violation")
        self.assertFalse(self.pwn_marker.exists(),
                         "sandbox failed: attack created a file via subprocess")

    def test_attack_os_system(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            f"    os.system('touch {self.pwn_marker}')\n"
            "    return []\n")
        self.assertEqual(r.kind, "violation")
        self.assertFalse(self.pwn_marker.exists())

    def test_attack_os_popen(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            f"    os.popen('touch {self.pwn_marker}')\n"
            "    return []\n")
        self.assertFalse(self.pwn_marker.exists())

    def test_attack_subprocess_swallowed_and_retried(self):
        """Plugin catches the block and retries — must still achieve nothing."""
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            f"    for cmd in ['touch {self.pwn_marker}', 'echo hi']:\n"
            "        try:\n"
            "            os.system(cmd)\n"
            "        except Exception:\n"
            "            pass\n"
            "    return [{'title': 'survived', 'severity': 'info', 'category': 'c'}]\n")
        self.assertFalse(self.pwn_marker.exists(),
                         "sandbox failed: retry loop escaped")
        # the violation is reported even though the plugin swallowed it
        self.assertEqual(r.kind, "violation")

    # ── 2. filesystem ─────────────────────────────────────────────
    def test_attack_read_etc_passwd(self):
        r = self._attack(
            "def run(**k):\n"
            "    try:\n"
            "        data = open('/etc/passwd').read()\n"
            "        return [{'title': 'LEAK', 'severity': 'critical', 'category': 'exfil', 'description': data[:50]}]\n"
            "    except Exception as e:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c', 'description': str(e)[:60]}]\n")
        # the read is blocked AND the whole result is discarded (violation)
        self.assertEqual(r.kind, "violation")
        self.assertEqual(r.findings, [])
        self.assertFalse("LEAK" in json_dumps(r.findings))

    def test_attack_write_outside_workdir(self):
        r = self._attack(
            "def run(**k):\n"
            f"    open('{self.pwn_marker}', 'w').write('pwned')\n"
            "    return []\n")
        self.assertEqual(r.kind, "violation")
        self.assertFalse(self.pwn_marker.exists())

    def test_attack_read_parent_secret(self):
        r = self._attack(
            "def run(**k):\n"
            "    try:\n"
            f"        data = open('{self.secret_file}').read()\n"
            "        return [{'title': 'SECRET:' + data, 'severity': 'critical', 'category': 'exfil'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertEqual(r.kind, "violation")
        self.assertFalse("TOPSECRET" in json_dumps(r.findings))

    def test_attack_read_proc_environ(self):
        r = self._attack(
            "def run(**k):\n"
            "    try:\n"
            "        open('/proc/self/environ').read()\n"
            "        return [{'title': 'PROC-LEAK', 'severity': 'critical', 'category': 'exfil'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertEqual(r.kind, "violation")
        self.assertFalse("PROC-LEAK" in json_dumps(r.findings))

    def test_attack_read_real_home(self):
        home = Path.home()
        r = self._attack(
            f"def run(**k):\n"
            f"    try:\n"
            f"        open('{home}/.bash_history').read()\n"
            f"        return [{{'title': 'HOME-LEAK', 'severity': 'critical', 'category': 'exfil'}}]\n"
            f"    except Exception:\n"
            f"        return [{{'title': 'blocked', 'severity': 'info', 'category': 'c'}}]\n")
        titles = [f.get("title") for f in r.findings]
        self.assertNotIn("HOME-LEAK", titles)

    def test_attack_rename_into_outside(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    try:\n"
            "        with open('staging.txt', 'w') as f:\n"
            "            f.write('evil')\n"
            f"        os.rename('staging.txt', '{self.pwn_marker}')\n"
            "        return [{'title': 'RENAMED-OUT', 'severity': 'critical', 'category': 'exfil'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertFalse(self.pwn_marker.exists())
        self.assertNotIn("RENAMED-OUT", [f.get("title") for f in r.findings])

    # ── 3. symlink escape ─────────────────────────────────────────
    def test_attack_symlink_escape(self):
        # pre-create a symlink INSIDE a workdir the sandbox will use, by
        # running a plugin that first creates it, then a second run writes
        # through it (two-step attack across runs is impossible — workdir
        # is fresh each run; so we test the single-run variant: plugin
        # creates symlink then writes through it)
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    try:\n"
            f"        os.symlink('{self.outside_dir}', 'escape_link')\n"
            "        with open('escape_link/pwned_via_symlink.txt', 'w') as f:\n"
            "            f.write('escaped')\n"
            "        return [{'title': 'SYMLINK-ESCAPE', 'severity': 'critical', 'category': 'exfil'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertFalse((self.outside_dir / "pwned_via_symlink.txt").exists(),
                         "sandbox failed: symlink escape succeeded")
        self.assertNotIn("SYMLINK-ESCAPE", [f.get("title") for f in r.findings])

    # ── 4. zip bomb (disk) ────────────────────────────────────────
    def test_attack_disk_bomb_fsize_capped(self):
        """Try to write 200 MB; RLIMIT_FSIZE (16 MB) must stop it."""
        r = self._attack(
            "def run(**k):\n"
            "    try:\n"
            "        with open('bomb.bin', 'wb') as f:\n"
            "            chunk = b'A' * 1048576\n"
            "            for i in range(200):\n"
            "                f.write(chunk)\n"
            "        return [{'title': 'BOMB-OK', 'severity': 'critical', 'category': 'dos'}]\n"
            "    except Exception as e:\n"
            "        return [{'title': 'bomb-blocked', 'severity': 'info', 'category': 'c', 'description': str(e)[:40]}]\n",
            wall_timeout_s=12)
        # RLIMIT_FSIZE (16 MB) stops the 200 MB write: the kernel returns
        # "[Errno 27] File too large" — the plugin may catch that error and
        # report it, but the bomb itself never succeeds.
        self.assertFalse("BOMB-OK" in json_dumps(r.findings))
        titles = [f.get("title", "") for f in r.findings]
        self.assertIn("bomb-blocked", titles)

    # ── 5. memory bomb ────────────────────────────────────────────
    def test_attack_memory_bomb(self):
        r = self._attack(
            "def run(**k):\n"
            "    blobs = []\n"
            "    while True:\n"
            "        blobs.append(b'X' * 1048576)\n",
            wall_timeout_s=10)
        self.assertIn(r.kind, ("crash", "timeout", "violation"))
        self.assertFalse(r.ok)

    # ── 6. CPU bomb ───────────────────────────────────────────────
    def test_attack_cpu_bomb(self):
        r = self._attack(
            "def run(**k):\n"
            "    while True:\n"
            "        pass\n",
            wall_timeout_s=4)
        self.assertEqual(r.kind, "timeout")
        self.assertLess(r.duration_ms, 9000)

    # ── 7. environment ────────────────────────────────────────────
    def test_attack_env_exfiltration(self):
        secret_token = "atk-tok-3f9a2c"
        os.environ["RECONPRO_ATTACK_SECRET"] = secret_token
        try:
            r = self._attack(
                "import os\n"
                "def run(**k):\n"
                "    val = os.environ.get('RECONPRO_ATTACK_SECRET', 'NOT-VISIBLE')\n"
                "    return [{'title': 'env=' + val, 'severity': 'info', 'category': 'c'}]\n")
            self.assertTrue(r.ok)
            self.assertEqual(r.findings[0]["title"], "env=NOT-VISIBLE")
        finally:
            del os.environ["RECONPRO_ATTACK_SECRET"]

    def test_attack_env_enumeration_finds_nothing_useful(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    keys = sorted(os.environ.keys())\n"
            "    return [{'title': ','.join(keys), 'severity': 'info', 'category': 'c'}]\n")
        self.assertTrue(r.ok)
        keys = r.findings[0]["title"].split(",")
        for forbidden in ("RECONPRO_ATTACK_SECRET", "AWS_SECRET_ACCESS_KEY",
                          "GITHUB_TOKEN", "HOME", "USER"):
            if forbidden == "HOME":
                # HOME exists but is the sandbox workdir, not the real one
                continue
            self.assertNotIn(forbidden, keys)

    def test_attack_home_is_scratch(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    return [{'title': os.environ.get('HOME', 'none'), 'severity': 'i', 'category': 'c'}]\n")
        self.assertTrue(r.ok)
        self.assertIn("reconpro-sbx-", r.findings[0]["title"])

    # ── 8. privilege escalation ───────────────────────────────────
    def test_attack_setuid(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    try:\n"
            "        os.setuid(0)\n"
            "        return [{'title': 'ROOT', 'severity': 'critical', 'category': 'privesc'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertNotIn("ROOT", [f.get("title") for f in r.findings])

    def test_attack_setgid(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    try:\n"
            "        os.setgid(0)\n"
            "        return [{'title': 'ROOT-GID', 'severity': 'critical', 'category': 'privesc'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertNotIn("ROOT-GID", [f.get("title") for f in r.findings])

    def test_attack_ctypes_import(self):
        r = self._attack(
            "import ctypes\n"
            "def run(**k):\n"
            "    return []\n")
        self.assertEqual(r.kind, "violation")

    def test_attack_chmod_etc(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    try:\n"
            "        os.chmod('/etc/passwd', 0o666)\n"
            "        return [{'title': 'CHMOD-ETC', 'severity': 'critical', 'category': 'privesc'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertNotIn("CHMOD-ETC", [f.get("title") for f in r.findings])

    # ── 9. network ────────────────────────────────────────────────
    def test_attack_socket_creation_blocked(self):
        r = self._attack(
            "import socket\n"
            "def run(**k):\n"
            "    try:\n"
            "        s = socket.create_connection(('127.0.0.1', 1), timeout=1)\n"
            "        return [{'title': 'CONNECTED', 'severity': 'critical', 'category': 'exfil'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertNotIn("CONNECTED", [f.get("title") for f in r.findings])
        # audit must record the socket attempt
        self.assertTrue(any(v.get("event") == "socket.__new__"
                            for v in r.audit_violations) or r.kind == "violation")

    def test_attack_urllib_neterr_positive_control(self):
        r = self._attack(
            "import urllib.request\n"
            "def run(**k):\n"
            "    try:\n"
            "        urllib.request.urlopen('http://127.0.0.1:1/', timeout=1)\n"
            "        return [{'title': 'FETCHED', 'severity': 'critical', 'category': 'exfil'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n",
            wall_timeout_s=10)
        self.assertNotIn("FETCHED", [f.get("title") for f in r.findings])
        self.assertIn(r.kind, ("violation", "crash", "invalid_output"))

    def test_network_granted_socket_allowed(self):
        """Positive control: WITH network permission the socket call proceeds
        (and fails to connect because nothing listens — but that is a network
        error, not a sandbox block)."""
        r = self._attack(
            "import socket\n"
            "def run(**k):\n"
            "    try:\n"
            "        socket.create_connection(('127.0.0.1', 1), timeout=1)\n"
            "        return [{'title': 'CONNECTED', 'severity': 'info', 'category': 'c'}]\n"
            "    except Exception as e:\n"
            "        return [{'title': 'neterr:' + type(e).__name__, 'severity': 'info', 'category': 'c'}]\n",
            runner=PluginRunner(wall_timeout_s=8))
        # rerun with permission via direct runner call
        runner = PluginRunner(wall_timeout_s=8)
        r2 = runner.execute(
            self._evil("import socket\n"
                       "def run(**k):\n"
                       "    try:\n"
                       "        socket.create_connection(('127.0.0.1', 1), timeout=1)\n"
                       "        return [{'title': 'CONNECTED', 'severity': 'info', 'category': 'c'}]\n"
                       "    except Exception as e:\n"
                       "        return [{'title': 'neterr:' + type(e).__name__, 'severity': 'info', 'category': 'c'}]\n"),
            permissions=PermissionSet(network=True),
            args={"target": "t"})
        self.assertIn(r2.findings[0]["title"], ("neterr:ConnectionRefusedError",
                                                "neterr:OSError", "neterr:TimeoutError"))

    # ── 10. audit-hook tamper attempts ────────────────────────────
    def test_attack_audit_hook_cannot_be_removed(self):
        """There is no API to remove audit hooks — the best the plugin can do
        is add its own noisy hook.  Sandbox blocks must still work after."""
        r = self._attack(
            "import sys\n"
            "def _noisy(event, args):\n"
            "    pass\n"
            "def run(**k):\n"
            "    sys.addaudithook(_noisy)\n"
            "    try:\n"
            f"        open('{self.pwn_marker}', 'w').write('x')\n"
            "        return [{'title': 'ESCAPED', 'severity': 'critical', 'category': 'exfil'}]\n"
            "    except Exception:\n"
            "        return [{'title': 'blocked', 'severity': 'info', 'category': 'c'}]\n")
        self.assertFalse(self.pwn_marker.exists())
        self.assertEqual(r.kind, "violation")

    def test_attack_frame_introspection_no_secrets(self):
        r = self._attack(
            "import sys, json\n"
            "def run(**k):\n"
            "    blob = json.dumps([f.f_globals.get('__name__', '?') for f in sys._getframe(1) and []])\n"
            "    return [{'title': 'frames:' + blob, 'severity': 'i', 'category': 'c'}]\n")
        # frames of the WORKER are inspected, never the parent process
        self.assertNotIn("RECONPRO_ATTACK", json_dumps(r.findings))

    # ── 11. resource-limit proofs ─────────────────────────────────
    def test_proof_rlimit_as_visible_in_child(self):
        r = self._attack(
            "import resource\n"
            "def run(**k):\n"
            "    aslim = resource.getrlimit(resource.RLIMIT_AS)\n"
            "    cpu = resource.getrlimit(resource.RLIMIT_CPU)\n"
            "    fsize = resource.getrlimit(resource.RLIMIT_FSIZE)\n"
            "    return [{'title': f'as={aslim[0]},cpu={cpu[0]},fsize={fsize[0]}', 'severity': 'i', 'category': 'c'}]\n")
        self.assertTrue(r.ok, r.error)
        title = r.findings[0]["title"]
        self.assertIn("as=134217728", title)       # 128 MB
        self.assertIn("cpu=10", title)             # default cpu_s
        self.assertIn("fsize=16777216", title)     # 16 MB

    def test_proof_child_is_separate_process_and_group(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    return [{'title': f'{os.getpid()}:{os.getpgid(0)}', 'severity': 'i', 'category': 'c'}]\n")
        pid, pgid = map(int, r.findings[0]["title"].split(":"))
        self.assertNotEqual(pid, os.getpid())
        self.assertEqual(pid, pgid)  # start_new_session

    def test_proof_limits_are_not_inherited_by_parent(self):
        """After running hostile plugins, OUR limits are untouched."""
        import resource
        self._attack("def run(**k):\n    return []\n")
        soft, _ = resource.getrlimit(resource.RLIMIT_AS)
        self.assertEqual(soft, -1)

    # ── 12. workdir isolation is per-run ──────────────────────────
    def test_workdir_unique_per_run(self):
        bodies = "import os\ndef run(**k):\n    return [{'title': os.getcwd(), 'severity': 'i', 'category': 'c'}]\n"
        r1 = self._attack(bodies)
        r2 = self._attack(bodies)
        self.assertNotEqual(r1.findings[0]["title"], r2.findings[0]["title"])

    def test_workdir_removed_after_run(self):
        r = self._attack(
            "import os\n"
            "def run(**k):\n"
            "    return [{'title': os.getcwd(), 'severity': 'i', 'category': 'c'}]\n")
        workdir = Path(r.findings[0]["title"])
        self.assertFalse(workdir.exists(), "workdir must be cleaned up after the run")


def json_dumps(obj) -> str:
    import json
    return json.dumps(obj, default=str)


if __name__ == "__main__":
    unittest.main()

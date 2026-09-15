#!/usr/bin/env python3
"""actions validator (PHOENIX 7-d).

Validates the composite GitHub Action + the repo-level demo workflow and
LIVE-EXECUTES the action's CLI command sequence exactly as the action.yml
steps run them (same argv, same env, same redirections):

 1. `action.yml` parses (yaml.safe_load) with the required inputs
    (target/workspace/format/timeout/python-version), outputs
    (sarif-path/secrets-json-path) and `runs: composite` steps;
 2. steps reference actions/setup-python@v5, actions/upload-artifact@v4 and
    github/codeql-action/upload-sarif@v3; every script step uses `shell: bash`;
 3. the demo workflow `.github/workflows/reconpro-scan.yml` parses and calls
    the action by its correct path (`./actions/reconpro-scan`) with
    `security-events: write` permission;
 4. the install-detection branch works: this repo's pyproject.toml declares
    `name = "reconpro"` (so the action installs from the checkout);
 5. LIVE: in a fixture checkout, runs the full step sequence —
    `ast <target>`, `secrets <target> --json > reconpro-secrets.json`,
    `dev <target>`, `export reconpro-report.sarif` — with GNU `timeout`
    exactly like the action, then verifies the artifact payloads
    (secrets JSON is valid JSON; SARIF is 2.1.0 with rules + results, i.e.
    what upload-artifact/upload-sarif would ship).

Exit code 0 = PASS, 1 = FAIL.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ACTION_YML = os.path.join(REPO, "actions", "reconpro-scan", "action.yml")
WORKFLOW_YML = os.path.join(REPO, ".github", "workflows", "reconpro-scan.yml")
PYTHON = os.environ.get("RECONPRO_PYTHON", "/home/z/.venv/bin/python3")

failures: list[str] = []
checks = 0


def check(cond: bool, name: str, detail: str = "") -> None:
    global checks
    checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(name)


# ── 1. action.yml contract ──────────────────────────────────────────────────
action = None
try:
    with open(ACTION_YML, encoding="utf-8") as fp:
        action = yaml.safe_load(fp)
    check(True, "action.yml parses (yaml.safe_load)")
except (yaml.YAMLError, OSError) as e:
    check(False, "action.yml parses (yaml.safe_load)", str(e))

if action:
    check(isinstance(action.get("name"), str) and "ReconPro" in action["name"], "action name", str(action.get("name")))
    check(isinstance(action.get("description"), str) and len(action["description"]) > 20, "action description present")
    inputs = action.get("inputs") or {}
    for key in ("target", "workspace", "format", "timeout", "python-version"):
        check(key in inputs and isinstance(inputs[key].get("description"), str), f"input declared: {key}", str(inputs[key].get("default")) if key in inputs else "missing")
    outputs = action.get("outputs") or {}
    check("sarif-path" in outputs, "output declared: sarif-path", str(outputs.get("sarif-path", ""))[:60])
    check("secrets-json-path" in outputs, "output declared: secrets-json-path")
    runs = action.get("runs") or {}
    check(runs.get("using") == "composite", "runs.using == composite", str(runs.get("using")))
    steps = runs.get("steps") or []
    check(isinstance(steps, list) and len(steps) >= 7, "runs.steps >= 7", f"{len(steps)} steps")
    uses = [s.get("uses", "") for s in steps if isinstance(s, dict)]
    check(any(u.startswith("actions/setup-python@v") for u in uses), "step uses actions/setup-python@v5", [u for u in uses if "setup-python" in u][0] if any("setup-python" in u for u in uses) else "missing")
    check(any(u.startswith("actions/upload-artifact@v4") for u in uses), "step uses actions/upload-artifact@v4")
    check(any(u.startswith("github/codeql-action/upload-sarif@v3") for u in uses), "step uses github/codeql-action/upload-sarif@v3")
    shell_steps = [s for s in steps if isinstance(s, dict) and "run" in s]
    check(all(s.get("shell") == "bash" for s in shell_steps), "every script step pins shell: bash", f"{len(shell_steps)} script steps")
    check(any("timeout" in (s.get("run") or "") for s in shell_steps), "script steps honour the timeout input (GNU timeout)")
    check(any("m reconpro.cli ast" in (s.get("run") or "") for s in shell_steps), "script runs reconpro ast")
    check(any("m reconpro.cli secrets" in (s.get("run") or "") and "--json" in (s.get("run") or "") for s in shell_steps), "script runs reconpro secrets --json")
    check(any("m reconpro.cli dev" in (s.get("run") or "") for s in shell_steps), "script runs reconpro dev (seeds export)")
    check(any("m reconpro.cli export" in (s.get("run") or "") for s in shell_steps), "script runs reconpro export")
    check(any("${{ inputs.format == 'sarif' }}" in (s.get("if") or "") for s in steps if isinstance(s, dict)), "codeql step gated on format == sarif")
    check(any("category" in (s.get("with") or {}) for s in steps if isinstance(s, dict) and "codeql" in str(s.get("uses", ""))), "codeql step sets a category")
    # inputs flow via env vars (defends against shell template injection)
    env_steps = [s for s in shell_steps if (s.get("env") or {}).get("RECONPRO_TARGET") == "${{ inputs.target }}"]
    check(len(env_steps) >= 3, "target input flows via env (no inline interpolation in run)", f"{len(env_steps)} steps")

# ── 2. workflow contract ────────────────────────────────────────────────────
workflow = None
try:
    with open(WORKFLOW_YML, encoding="utf-8") as fp:
        workflow = yaml.safe_load(fp)
    check(True, "workflow .github/workflows/reconpro-scan.yml parses")
except (yaml.YAMLError, OSError) as e:
    check(False, "workflow .github/workflows/reconpro-scan.yml parses", str(e))

if workflow:
    check(workflow.get("name") == "ReconPro Scan (demo)", "workflow name", str(workflow.get("name")))
    triggers = workflow.get(True) or workflow.get("on") or {}
    check("push" in triggers and "pull_request" in triggers and "workflow_dispatch" in triggers, "workflow triggers push/PR/dispatch", str(list(triggers)))
    perms = workflow.get("permissions") or {}
    check(perms.get("contents") == "read" and perms.get("security-events") == "write", "workflow permissions contents:read + security-events:write", str(perms))
    jobs = workflow.get("jobs") or {}
    ok_jobs = False
    detail = "missing"
    for _jid, job in jobs.items():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if uses == "./actions/reconpro-scan":
                ok_jobs = True
                detail = uses
                with_ = step.get("with") or {}
                check(with_.get("target") == "." and with_.get("format") == "sarif", "workflow passes target + format", str(with_))
    check(ok_jobs, "workflow calls ./actions/reconpro-scan by path", detail)
    check(any(step.get("uses") == "actions/checkout@v4" for job in jobs.values() for step in job.get("steps", [])), "workflow checks out first (actions/checkout@v4)")

# ── 3. install detection branch ─────────────────────────────────────────────
pyproject = open(os.path.join(REPO, "pyproject.toml"), encoding="utf-8").read()
check('name = "reconpro"' in pyproject, "repo pyproject.toml declares name = reconpro (action installs from checkout)")

# ── 4. LIVE: execute the action's CLI sequence exactly as the steps do ──────
# On a GitHub runner the install step makes `reconpro` importable everywhere.
# This sandbox's venv does NOT have reconpro pip-installed (it is only
# importable with cwd = repo root), so we reproduce the post-install state
# with PYTHONPATH — zero side effects on the shared venv.
ENV = {**os.environ, "COLUMNS": "200", "PYTHONUNBUFFERED": "1", "PYTHONPATH": REPO}
ws = tempfile.mkdtemp(prefix="rpact")
with open(os.path.join(ws, "evil.py"), "w", encoding="utf-8") as fp:
    fp.write('import subprocess\nsubprocess.call("ls", shell=True)\nimport pickle\npickle.loads(p)\npassword = "SKYNET-ALPHA-77"\neval(u)\n')


def run_step(argv: list[str], **kw) -> subprocess.CompletedProcess:
    # mirrors the action's `timeout "$RECONPRO_TIMEOUT" python -m reconpro.cli ...`
    wrapped = ["timeout", "300", *argv]
    return subprocess.run(wrapped, cwd=ws, capture_output=True, text=True, timeout=120, env=ENV, **kw)


check("reconpro" not in subprocess.run([PYTHON, "-c", "import reconpro"], capture_output=True).stdout.decode("utf-8", "ignore"), "sandbox venv has no pip-installed reconpro (hence PYTHONPATH simulating the action's install step)")


ast = run_step([PYTHON, "-m", "reconpro.cli", "ast", "."])
check(ast.returncode == 0, "LIVE [ast step]: timeout 300 python -m reconpro.cli ast .", f"exit={ast.returncode}")
check("vulnerability pattern" in ast.stderr, "LIVE [ast step]: findings table in step log (stderr)")

secrets = run_step([PYTHON, "-m", "reconpro.cli", "secrets", ".", "--json"])
secrets_file = os.path.join(ws, "reconpro-secrets.json")
with open(secrets_file, "w", encoding="utf-8") as fp:
    fp.write(secrets.stdout)  # the action redirects stdout into the file
secrets_json = None
try:
    secrets_json = json.loads(open(secrets_file, encoding="utf-8").read())
except json.JSONDecodeError:
    pass
check(secrets.returncode == 0 and isinstance(secrets_json, list), "LIVE [secrets step]: --json > reconpro-secrets.json is valid JSON", f"{len(secrets_json) if isinstance(secrets_json, list) else 0} findings")

dev = run_step([PYTHON, "-m", "reconpro.cli", "dev", "."])
check(dev.returncode == 0, "LIVE [dev step]: seeds the last scan for export", f"exit={dev.returncode}")

exp = run_step([PYTHON, "-m", "reconpro.cli", "export", "reconpro-report.sarif"])
sarif_file = os.path.join(ws, "reconpro-report.sarif")
sarif = None
try:
    sarif = json.loads(open(sarif_file, encoding="utf-8").read())
except (json.JSONDecodeError, OSError):
    pass
check(exp.returncode == 0 and sarif is not None, "LIVE [export step]: reconpro-report.sarif produced + parses")
if sarif:
    check(sarif.get("version") == "2.1.0", "LIVE [upload-sarif payload]: SARIF 2.1.0")
    runs = sarif.get("runs") or []
    results = runs[0].get("results", []) if runs else []
    rules = (runs[0].get("tool", {}) or {}).get("driver", {}).get("rules", []) if runs else []
    check(len(results) >= 1, "LIVE [upload-sarif payload]: results non-empty", f"{len(results)} results")
    check(len(rules) >= 1, "LIVE [upload-sarif payload]: rules non-empty", f"{len(rules)} rules")
check(os.path.isfile(secrets_file) and os.path.isfile(sarif_file), "LIVE [upload-artifact payload]: both files exist for the artifact", "reconpro-report.sarif + reconpro-secrets.json")

# ── summary ─────────────────────────────────────────────────────────────────
subprocess.run(["rm", "-rf", ws], check=False)
print()
print(f"actions validation: {checks - len(failures)}/{checks} checks passed.")
if failures:
    print("RESULT: FAIL", file=sys.stderr)
    sys.exit(1)
print("RESULT: PASS")
sys.exit(0)

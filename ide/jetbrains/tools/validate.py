#!/usr/bin/env python3
"""reconpro-jetbrains validator (PHOENIX 7-d).

Structural validation of the IntelliJ plugin skeleton + LIVE execution of the
exact CLI invocations the plugin performs (ProcessBuilder argv list contract):

 1. plugin.xml parses (xml.etree) and declares: id com.reconpro.intellij,
    since-build 241, toolWindow + projectConfigurable extensions, action group
    with scan/doctor actions;
 2. every class referenced by plugin.xml exists as a .kt source file;
 3. ReconProRunner.kt uses ProcessBuilder with an argv LIST and never
    Runtime.exec with string concatenation (regex contract);
  3b. build.gradle.kts exists and wires the gradle-intellij-plugin;
 4. LIVE: runs `python -m reconpro.cli doctor --json` (ReconProDoctorAction
    contract) and asserts JSON with total_findings/grade;
 5. LIVE: runs the ReconProRunner.buildCommand() argv shape (`-m reconpro.cli
    ast <fixture>`) and asserts exit 0 + findings in output;
 6. LIVE: runs the scanProject() flow (`dev <fixture>` then `export *.sarif`)
    and parses the SARIF exactly like ReconProRunner.parseSarif() would.

Kotlin COMPILATION is not performed (no kotlinc/Gradle in this sandbox) — that
part is honestly labelled compile-blocked. Exit code 0 = PASS, 1 = FAIL.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ide/jetbrains
REPO = os.path.dirname(os.path.dirname(ROOT))  # repo root
PYTHON = os.environ.get("RECONPRO_PYTHON", "/home/z/.venv/bin/python3")

failures: list[str] = []
checks = 0


def check(cond: bool, name: str, detail: str = "") -> None:
    global checks
    checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(name)


# ── 1. plugin.xml contract ──────────────────────────────────────────────────
plugin_xml_path = os.path.join(ROOT, "resources", "META-INF", "plugin.xml")
tree = None
try:
    tree = ET.parse(plugin_xml_path)
    check(True, "plugin.xml parses as XML")
except ET.ParseError as e:
    check(False, "plugin.xml parses as XML", str(e))

if tree is not None:
    root_el = tree.getroot()
    check(root_el.tag == "idea-plugin", "root element is idea-plugin", root_el.tag)
    check(root_el.findtext("id") == "com.reconpro.intellij", "plugin id", str(root_el.findtext("id")))
    iv = root_el.find("idea-version")
    check(iv is not None and iv.get("since-build") == "241", "idea-version since-build=241", iv.get("since-build") if iv is not None else "missing")
    check(root_el.findtext("name") == "ReconPro", "plugin name", str(root_el.findtext("name")))
    check(root_el.findtext("vendor") is not None, "vendor present", str(root_el.findtext("vendor")))

    exts = root_el.find("extensions")
    tool_windows = exts.findall("toolWindow") if exts is not None else []
    check(len(tool_windows) == 1 and tool_windows[0].get("id") == "ReconPro", "toolWindow extension declared", tool_windows[0].get("id") if tool_windows else "missing")
    config = exts.findall("projectConfigurable") if exts is not None else []
    check(len(config) == 1 and (config[0].get("displayName") or "") == "ReconPro", "projectConfigurable declared", config[0].get("id") if config else "missing")

    actions = root_el.find("actions")
    group = actions.find("group") if actions is not None else None
    check(group is not None and group.get("text") == "ReconPro", 'action group "ReconPro"', str(group.get("text")) if group is not None else "missing")
    group_actions = group.findall("action") if group is not None else []
    action_texts = [a.get("text") or "" for a in group_actions]
    check(any("Scan Project" in t for t in action_texts), "scan action present", str(action_texts))
    check(any("Doctor" in t for t in action_texts), "doctor action present", str(action_texts))

    # every referenced class must exist as a Kotlin source file
    for el in tool_windows + config + group_actions:
        cls = el.get("factoryClass") or el.get("instance") or el.get("class")
        rel = os.path.join(ROOT, "src", cls.replace(".", os.sep) + ".kt")
        check(os.path.isfile(rel), f"source exists: {cls}")

# ── 2. Kotlin source contract ───────────────────────────────────────────────
runner_path = os.path.join(ROOT, "src", "com", "reconpro", "sdk", "ReconProRunner.kt")
src = open(runner_path, encoding="utf-8").read()
# Strip comments so the contract checks inspect CODE, not KDoc prose.
src_code = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
src_code = re.sub(r"^\s*//.*$", "", src_code, flags=re.M)
check("ProcessBuilder(argv)" in src_code or ("ProcessBuilder(" in src_code and "argv" in src_code), "ProcessBuilder(argv list) used")
check("listOf(settings.pythonPath, \"-m\", \"reconpro.cli\")" in src_code, "buildCommand argv list literal")
check("Runtime.getRuntime().exec(" not in src_code, "no Runtime.exec string form (in code)")
check(re.search(r'ProcessBuilder\([^)]*"\s*\+', src_code) is None, "no string concatenation into ProcessBuilder")
check("parseSarif" in src_code and "security-severity" in src_code, "SARIF parse + security-severity model")
check('"2.1.0"' in src_code, "SARIF version check present")
check("HONEST BUILD NOTE" in src, "compile-blocked honesty comment present")
check("no shell" in src.lower() or "never a shell" in src.lower(), "no-shell contract documented")

scan_src = open(os.path.join(ROOT, "src", "com", "reconpro", "sdk", "ReconProScanAction.kt"), encoding="utf-8").read()
check("listOf(\"ast\"" in scan_src and "listOf(\"secrets\"" in scan_src, "scan action runs ast + secrets via argv lists")
check("executeOnPooledThread" in scan_src, "scan runs off the EDT")
doc_src = open(os.path.join(ROOT, "src", "com", "reconpro", "sdk", "ReconProDoctorAction.kt"), encoding="utf-8").read()
check('listOf("doctor", "--json")' in doc_src, "doctor action runs doctor --json via argv list")

# ── 3. build wiring ─────────────────────────────────────────────────────────
gradle_path = os.path.join(ROOT, "build.gradle.kts")
check(os.path.isfile(gradle_path), "build.gradle.kts exists (gradle-intellij-plugin)")
if os.path.isfile(gradle_path):
    g = open(gradle_path, encoding="utf-8").read()
    check("org.jetbrains.intellij" in g and "2024.1" in g and '"241"' in g, "gradle wires intellij 2024.1 / sinceBuild 241")
    check("reconproSmoke" in g, "gradle reconproSmoke task mirrors CLI contract")

# ── 4. LIVE: run the exact CLI invocations the plugin performs ─────────────
ENV = {**os.environ, "PYTHONUNBUFFERED": "1", "COLUMNS": "200"}


def run_cli(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    # argv LIST, no shell — mirrors ProcessBuilder(argv) in ReconProRunner.run()
    return subprocess.run([PYTHON, "-m", "reconpro.cli", *args], cwd=cwd, capture_output=True, text=True, timeout=120, env=ENV)


doc = run_cli(["doctor", "--json"], REPO)
doc_json = None
try:
    doc_json = json.loads(doc.stdout)
except json.JSONDecodeError:
    pass
check(doc.returncode == 0 and isinstance(doc_json, dict), "LIVE: doctor --json (ReconProDoctorAction contract)", f"exit={doc.returncode}")
if doc_json:
    check("total_findings" in doc_json and "grade" in doc_json, "doctor JSON has total_findings+grade", f"findings={doc_json.get('total_findings')} grade={doc_json.get('grade')}")

fixture = tempfile.mkdtemp(prefix="rpjfx")
with open(os.path.join(fixture, "evil.py"), "w", encoding="utf-8") as fp:
    fp.write("import subprocess\nsubprocess.call(\"ls\", shell=True)\nimport pickle\npickle.loads(p)\npassword = \"SKYNET-ALPHA-77\"\neval(u)\n")

ast = run_cli(["ast", fixture], REPO)
check(ast.returncode == 0, "LIVE: ast <fixture> (buildCommand argv shape) exit=0", f"exit={ast.returncode}")
check("vulnerability pattern" in ast.stderr, "LIVE: ast reports findings", ast.stderr.strip().splitlines()[-2] if ast.stderr else "")

dev = run_cli(["dev", fixture], REPO)
check(dev.returncode == 0, "LIVE: dev <fixture> (scanProject step 1) exit=0", f"exit={dev.returncode}")
sarif_path = os.path.join(fixture, "reconpro.sarif")
exp = run_cli(["export", sarif_path], REPO)
sarif = None
try:
    sarif = json.loads(open(sarif_path, encoding="utf-8").read())
except (json.JSONDecodeError, OSError):
    pass
check(exp.returncode == 0 and sarif is not None, "LIVE: export *.sarif (scanProject step 2) parses")
if sarif:
    check(sarif.get("version") == "2.1.0", "SARIF version 2.1.0 (parseSarif contract)")
    runs = sarif.get("runs") or []
    results = runs[0].get("results", []) if runs else []
    rules = (runs[0].get("tool", {}).get("driver", {}) or {}).get("rules", []) if runs else []
    check(len(results) >= 1, "SARIF results non-empty", f"{len(results)} results")
    check(len(rules) >= 1 and any("security-severity" in (r.get("properties") or {}) for r in rules), "SARIF rules carry security-severity", f"{len(rules)} rules")

# ── summary ─────────────────────────────────────────────────────────────────
subprocess.run(["rm", "-rf", fixture], check=False)
print()
print(f"reconpro-jetbrains validation: {checks - len(failures)}/{checks} checks passed.")
if failures:
    print("RESULT: FAIL", file=sys.stderr)
    sys.exit(1)
print("RESULT: PASS")
sys.exit(0)

#!/usr/bin/env python3
"""reconpro-nvim validator (PHOENIX 7-d).

No `nvim` binary exists in this sandbox (`which nvim` is empty; only vim 9.1,
which lacks jobstart/vim.api) — so this is STRUCTURAL validation of the Lua
sources plus LIVE execution of the exact argv lists the Lua builds:

 1. all plugin files exist (lua/, plugin/, doc/, syntax/);
 2. init.lua builds the CLI command as an argv LIST (vim.list_extend over
    { python, "-m", "reconpro.cli" }) and runs it via vim.fn.jobstart(cmd, ...)
    — never os.execute / vim.fn.system / io.popen (checked over all .lua);
 3. plugin/reconpro.lua registers >= 3 nvim_create_user_command commands
    (ReconProScan / ReconProSecrets / ReconProDoctor / ReconProVersion);
 4. commands.lua pushes results with vim.fn.setqflist;
 5. Lua structural sanity: block/line comments stripped, then balanced
    ()/[]/{} (catches the classic truncation bug);
 6. vimdoc doc/reconpro.txt contains the required *tags* + modeline;
 7. syntax/reconpro-report.vim defines syn match + hi def link + current_syntax;
 8. LIVE: runs `<python> -m reconpro.cli --version`, `doctor --json`,
    `secrets <fixture> --json` and `ast <fixture>` with argv lists, ports
    parse_table_row()/findings_to_qflist() faithfully into Python, and asserts
    the SAME parsing logic the Lua uses extracts real findings from the real
    CLI output (quickfix entries with filename/type/text).

Exit code 0 = PASS, 1 = FAIL.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ide/neovim
REPO = os.path.dirname(os.path.dirname(ROOT))
PYTHON = os.environ.get("RECONPRO_PYTHON", "/home/z/.venv/bin/python3")

failures: list[str] = []
checks = 0


def check(cond: bool, name: str, detail: str = "") -> None:
    global checks
    checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(name)


# ── 1. files ────────────────────────────────────────────────────────────────
files = {
    "lua/reconpro/init.lua": None,
    "lua/reconpro/commands.lua": None,
    "plugin/reconpro.lua": None,
    "doc/reconpro.txt": None,
    "syntax/reconpro-report.vim": None,
    "README.md": None,
}
for rel in files:
    p = os.path.join(ROOT, *rel.split("/"))
    exists = os.path.isfile(p)
    check(exists, f"file exists: {rel}")
    if exists:
        files[rel] = open(p, encoding="utf-8").read()

init_lua = files["lua/reconpro/init.lua"] or ""
cmd_lua = files["lua/reconpro/commands.lua"] or ""
plugin_lua = files["plugin/reconpro.lua"] or ""
doc = files["doc/reconpro.txt"] or ""
syntax_vim = files["syntax/reconpro-report.vim"] or ""

# ── 2. no-shell jobstart contract ──────────────────────────────────────────


def strip_lua_comments(src: str) -> str:
    """String-aware line-comment stripper: truncates at -- that is NOT inside
    a quoted string (naive regex strippers corrupt lines like `"--json"`)."""
    out = []
    for line in src.split("\n"):
        res = []
        i = 0
        in_str = None
        while i < len(line):
            ch = line[i]
            if in_str:
                if ch == "\\" and i + 1 < len(line):
                    res.append(line[i : i + 2])
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                res.append(ch)
                i += 1
                continue
            if ch in ('"', "'"):
                in_str = ch
                res.append(ch)
                i += 1
                continue
            if ch == "-" and i + 1 < len(line) and line[i + 1] == "-":
                break
            res.append(ch)
            i += 1
        out.append("".join(res))
    return "\n".join(out)


lua_all = init_lua + "\n" + cmd_lua + "\n" + plugin_lua
lua_code = strip_lua_comments(lua_all)  # contract checks inspect CODE, not prose
check("vim.fn.jobstart(cmd" in init_lua, "jobstart(cmd, ...) list-args call")
check('M.config.python, "-m", "reconpro.cli"' in init_lua, "build_cmd argv list literal { python, '-m', 'reconpro.cli' }")
check("vim.list_extend(" in init_lua, "argv built via vim.list_extend (list, not string concat)")
check("os.execute" not in lua_code, "no os.execute in Lua code (comments stripped)")
check("vim.fn.system(" not in lua_code, "no vim.fn.system( in Lua code (comments stripped)")
check("io.popen" not in lua_code, "no io.popen in Lua code (comments stripped)")
check(re.search(r"jobstart\([^,)]*\+", lua_code) is None, "no string concatenation into jobstart")
check('env = {' in init_lua and 'COLUMNS = "200"' in init_lua, "job env pins COLUMNS=200")

# ── 3. user commands ───────────────────────────────────────────────────────
user_cmds = re.findall(r'nvim_create_user_command\("(\w+)"', plugin_lua)
check(len(user_cmds) >= 3, ">= 3 nvim_create_user_command registrations", str(user_cmds))
for c in ("ReconProScan", "ReconProDoctor", "ReconProVersion"):
    check(c in user_cmds, f"user command registered: :{c}")
check("ReconProSecrets" in user_cmds, "bonus user command :ReconProSecrets")

# ── 4. quickfix integration ────────────────────────────────────────────────
check("vim.fn.setqflist(" in cmd_lua, "vim.fn.setqflist used for results")
check("cwindow" in cmd_lua, "quickfix window opened")
check('require("reconpro.init")' in cmd_lua, "commands use the core module")
check("json_decode" in init_lua, "JSON/JSONL decode path present")

# ── 5. Lua structural sanity ───────────────────────────────────────────────
def lua_balance(src: str) -> tuple[bool, str]:
    code = strip_lua_comments(src)
    # drop string literals to avoid counting brackets inside them
    code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', code)
    code = re.sub(r"'(?:[^'\\]|\\.)*'", "''", code)
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for i, ch in enumerate(code):
        if ch in pairs:
            stack.append(ch)
        elif ch in ")]}":
            if not stack or pairs[stack[-1]] != ch:
                return False, f"unbalanced '{ch}' at offset {i}"
            stack.pop()
    return (not stack), (f"unclosed {''.join(stack)}" if stack else "balanced")


for rel, src in (("lua/reconpro/init.lua", init_lua), ("lua/reconpro/commands.lua", cmd_lua), ("plugin/reconpro.lua", plugin_lua)):
    bal, why = lua_balance(src or "")
    check(bal, f"Lua brackets balanced: {rel}", why)

# ── 6. vimdoc tags ─────────────────────────────────────────────────────────
tags = re.findall(r"\*([A-Za-z0-9_:.-]+)\*", doc)
check(len(tags) >= 12, "vimdoc has >= 12 tags", f"{len(tags)} tags")
for t in (":ReconProScan", ":ReconProDoctor", ":ReconProVersion", "reconpro-configuration", "reconpro-quirks", "reconpro-contents"):
    check(t in tags, f"vimdoc tag present: *{t}*")
check("reconpro.txt" in doc, "vimdoc header *reconpro.txt*")
check("ft=help" in doc, "vimdoc modeline ft=help")

# ── 7. syntax file ─────────────────────────────────────────────────────────
check("syn match" in syntax_vim, "syntax file uses syn match")
check("hi def link" in syntax_vim, "syntax file links highlights")
check('b:current_syntax = "reconpro-report"' in syntax_vim, "syntax sets b:current_syntax")

# ── 8. LIVE: run the exact argv lists the Lua builds ──────────────────────
ENV = {**os.environ, "COLUMNS": "200", "PYTHONUNBUFFERED": "1"}


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    # mirrors M.build_cmd + vim.fn.jobstart: LIST argv, no shell
    return subprocess.run([PYTHON, "-m", "reconpro.cli", *args], cwd=REPO, capture_output=True, text=True, timeout=120, env=ENV)


ver = run_cli(["--version"])
check(ver.returncode == 0 and re.search(r"ReconPro\s+\d", ver.stdout), "LIVE: --version (:ReconProVersion)", ver.stdout.strip())

docp = run_cli(["doctor", "--json"])
doc_json = None
try:
    doc_json = json.loads(docp.stdout)
except json.JSONDecodeError:
    pass
check(docp.returncode == 0 and isinstance(doc_json, dict), "LIVE: doctor --json (:ReconProDoctor)", f"findings={doc_json.get('total_findings') if doc_json else '?'}")
check(isinstance(doc_json, dict) and "grade" in doc_json and "total_findings" in doc_json, "doctor JSON contract (findings_to_qflist input)")

fixture = tempfile.mkdtemp(prefix="rpnfx")
with open(os.path.join(fixture, "evil.py"), "w", encoding="utf-8") as fp:
    fp.write('import subprocess\nsubprocess.call("ls", shell=True)\nimport pickle\npickle.loads(p)\npassword = "SKYNET-ALPHA-77"\neval(u)\n')

sec = run_cli(["secrets", fixture, "--json"])
sec_json = None
try:
    sec_json = json.loads(sec.stdout)
except json.JSONDecodeError:
    pass
check(sec.returncode == 0 and isinstance(sec_json, list), "LIVE: secrets --json (:ReconProSecrets)", f"{len(sec_json) if isinstance(sec_json, list) else 0} findings")

# Python port of core.severity_info() — proves the E/W/I mapping logic.
def severity_info(word: str) -> str:
    w = (word or "").upper()
    if w in ("CRITICAL", "HIGH"):
        return "E"
    if w == "MEDIUM":
        return "W"
    return "I"


# Python port of core.findings_to_qflist() (structure only).
qf_from_json = []
for f in sec_json or []:
    qf_from_json.append({
        "filename": f.get("asset") or fixture,
        "lnum": 1,
        "type": severity_info(f.get("severity")),
        "text": f"[{(f.get('severity') or 'INFO').upper()}] {f.get('title')}",
    })
check(len(qf_from_json) >= 1 and all(e["type"] in "EWI" for e in qf_from_json), "LIVE: JSON findings -> quickfix entries (lua logic port)", f"{len(qf_from_json)} entries")

ast = run_cli(["ast", fixture])
check(ast.returncode == 0, "LIVE: ast <dir> (:ReconProScan) exit=0", f"exit={ast.returncode}")


# Python port of core.parse_table_row() — the EXACT algorithm the Lua uses
# (split on literal '│', trimempty, severity word check, >=4 columns).
def parse_table_row(line: str):
    if "│" not in line:
        return None
    cols = [c for c in line.split("│")]
    while cols and cols[0].strip() == "":
        cols.pop(0)
    while cols and cols[-1].strip() == "":
        cols.pop()
    if len(cols) < 4:
        return None
    severity = cols[0].strip()
    if not re.fullmatch(r"[A-Z]+", severity) or severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return None
    file = cols[1].strip()
    code = cols[2].strip()
    message = cols[3].strip()
    if not file or not message:
        return None
    return {"severity": severity, "file": file, "code": code, "message": message}


rows = [r for r in (parse_table_row(line) for line in (ast.stderr + ast.stdout).splitlines()) if r]
check(len(rows) >= 1, "LIVE: lua table-row parser extracts findings from real ast output", f"{len(rows)} rows; e.g. {rows[0]['severity'] if rows else '-'} {rows[0]['message'][:40] if rows else ''}")
qf_rows = [{
    "filename": r["file"],
    "lnum": 1,
    "type": severity_info(r["severity"]),
    "text": f"[{r['severity']}] {r['message']}",
} for r in rows]
check(all(os.path.isfile(e["filename"]) for e in qf_rows), "LIVE: parsed ast file paths exist on disk", f"{len(qf_rows)} entries")
check(any(e["type"] == "E" for e in qf_rows), "LIVE: CRITICAL findings map to quickfix type E")

# ── summary ─────────────────────────────────────────────────────────────────
subprocess.run(["rm", "-rf", fixture], check=False)
print()
print(f"reconpro-nvim validation: {checks - len(failures)}/{checks} checks passed.")
if failures:
    print("RESULT: FAIL", file=sys.stderr)
    sys.exit(1)
print("RESULT: PASS")
sys.exit(0)

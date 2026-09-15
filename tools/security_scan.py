#!/usr/bin/env python3
"""AST-based security scanner for the ReconPro codebase.

Walks every shipped Python file (reconpro/**) and FAILS (exit 1) on:

  subprocess-shell-true      subprocess.* call with shell=True keyword
  os-system                  os.system(...) call (shell injection sink)
  eval-nonliteral            eval() with a non-literal argument
  exec-nonliteral            exec() with a non-literal argument
  pickle-loads               pickle.loads(...) (unsafe deserialization)
  marshal-loads              marshal.loads(...) (unsafe deserialization)
  yaml-load-no-loader        yaml.load(...) without a Loader= argument
  ssl-unverified-context     ssl._create_unverified_context() outside the
                             TLS allowlist (reconpro/http_layer.py,
                             reconpro/tls_policy.py)

Detector modules are WHITELISTED (they implement these checks themselves /
contain fixer code and fixture strings): quality_intelligence.py,
supply_chain.py, defense.py, auto_fix.py, auto_validation.py,
reconpro/modules/ast_analyzer.py, reconpro/scripts/**.

Baseline mode (--baseline-file tools/security_baseline.json):
    Fails only on findings NOT present in the baseline. The baseline is an
    HONEST snapshot of currently-known hits (agent 7-a is fixing them
    concurrently — e.g. reconpro/nexus_agent.py shell=True); as fixes land
    the baseline should SHRINK, never grow. Matching tolerates line drift
    via a (file, rule) count fallback.

Modes:
  --write-baseline FILE   regenerate the baseline from current findings
  --strict                ignore baseline; fail on ANY finding (daily
                          security workflow target state)
  --sarif-out FILE        also write a SARIF 2.1.0 report
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [REPO / "reconpro"]

# modules implementing these very detectors / fixers — whitelisted by design
DETECTOR_WHITELIST = {
    "reconpro/quality_intelligence.py",
    "reconpro/supply_chain.py",
    "reconpro/defense.py",
    "reconpro/auto_fix.py",
    "reconpro/auto_validation.py",
    "reconpro/modules/ast_analyzer.py",
}
SCRIPTS_PREFIX = "reconpro/scripts/"          # report generators, whitelisted
TESTS_PREFIX = "reconpro/tests/"               # scanned, but see baseline note
# TLS rule allowlist — owned by the TLS-fix agent (7-a)
TLS_ALLOWLIST = {
    "reconpro/http_layer.py",
    "reconpro/tls_policy.py",  # does not exist yet; harmless if absent
}

RULES = {
    "subprocess-shell-true": "subprocess call with shell=True (shell injection)",
    "os-system": "os.system() passes commands to the shell unsanitised",
    "eval-nonliteral": "eval() with non-literal argument (arbitrary code execution)",
    "exec-nonliteral": "exec() with non-literal argument (arbitrary code execution)",
    "pickle-loads": "pickle.loads() unsafe deserialization (RCE on untrusted data)",
    "marshal-loads": "marshal.loads() unsafe deserialization",
    "yaml-load-no-loader": "yaml.load() without Loader= (unsafe deserialization)",
    "ssl-unverified-context": "ssl._create_unverified_context() disables TLS verification",
}

SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}


class ImportTracker(ast.NodeVisitor):
    """Collects module aliases so we can resolve dotted call names."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}  # local name -> dotted module path

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{node.module}.{alias.name}"


def dotted_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value, aliases)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


class RuleChecker(ast.NodeVisitor):
    def __init__(self, relpath: str) -> None:
        self.relpath = relpath
        self.aliases: dict[str, str] = {}
        self.findings: list[dict] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def _add(self, rule: str, node: ast.AST, detail: str) -> None:
        self.findings.append({
            "rule": rule,
            "file": self.relpath,
            "line": getattr(node, "lineno", 0),
            "message": f"{RULES[rule]}: {detail}",
        })

    def visit_Call(self, node: ast.Call) -> None:
        full = dotted_name(node.func, self.aliases)
        if full:
            parts = full.split(".")
            # subprocess.run / subprocess.Popen / from subprocess import run ...
            if (parts[0] == "subprocess" and len(parts) == 2
                    and parts[1] in SUBPROCESS_FUNCS) or \
               (len(parts) == 1 and parts[0] in SUBPROCESS_FUNCS
                    and self.aliases.get(parts[0], "").startswith("subprocess.")):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) \
                            and kw.value.value is True:
                        self._add("subprocess-shell-true", node, f"{full}(shell=True)")
            if full == "os.system":
                self._add("os-system", node, "os.system(...)")
            if full in ("pickle.loads", "cPickle.loads"):
                self._add("pickle-loads", node, f"{full}(...)")
            if full == "marshal.loads":
                self._add("marshal-loads", node, "marshal.loads(...)")
            if full == "yaml.load":
                has_loader = any(kw.arg == "Loader" for kw in node.keywords)
                if not has_loader:
                    self._add("yaml-load-no-loader", node, "yaml.load(...) without Loader=")
            if full == "ssl._create_unverified_context" and self.relpath not in TLS_ALLOWLIST:
                self._add("ssl-unverified-context", node, "ssl._create_unverified_context()")
        # builtins eval()/exec() with non-literal first argument
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            shadowed = node.func.id in self.aliases
            if not shadowed and node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant):
                    self._add(f"{node.func.id}-nonliteral", node,
                              f"{node.func.id}(<non-literal>)")
        self.generic_visit(node)


def scan_file(path: Path) -> list[dict]:
    relpath = path.relative_to(REPO).as_posix()
    if relpath in DETECTOR_WHITELIST or relpath.startswith(SCRIPTS_PREFIX):
        return []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError as exc:
        return [{
            "rule": "syntax-error", "file": relpath, "line": getattr(exc, "lineno", 0) or 0,
            "message": f"file does not parse: {exc}",
        }]
    checker = RuleChecker(relpath)
    checker.visit(tree)
    return checker.findings


def iter_scan_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        files.extend(p for p in root.rglob("*.py")
                     if "__pycache__" not in p.parts)
    return sorted(files)


def findings_to_sarif(findings: list[dict]) -> dict:
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "reconpro-security-scan",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/falconxa0-commits/reconpro",
                    "rules": [
                        {"id": rid, "shortDescription": {"text": desc}}
                        for rid, desc in RULES.items()
                    ] + [{"id": "syntax-error", "shortDescription": {"text": "file does not parse"}}],
                }
            },
            "results": [
                {
                    "ruleId": f["rule"],
                    "level": "error",
                    "message": {"text": f["message"]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {"startLine": f["line"]},
                        }
                    }],
                }
                for f in findings
            ],
        }],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="ReconPro AST security scanner")
    ap.add_argument("--baseline-file", type=str, default=None,
                    help="known-findings baseline (fail only on NEW findings)")
    ap.add_argument("--write-baseline", type=str, default=None,
                    help="write current findings to this baseline file and exit 0")
    ap.add_argument("--strict", action="store_true",
                    help="ignore baseline; fail on ANY finding")
    ap.add_argument("--sarif-out", type=str, default=None,
                    help="write SARIF 2.1.0 report of ALL current findings")
    ap.add_argument("--quiet", action="store_true", help="only print summary")
    args = ap.parse_args()

    files = iter_scan_files()
    findings: list[dict] = []
    for path in files:
        findings.extend(scan_file(path))
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))

    if not args.quiet:
        for f in findings:
            print(f"  {f['file']}:{f['line']}: {f['rule']} — {f['message']}")
    print(f"[security-scan] scanned {len(files)} files under reconpro/ — "
          f"{len(findings)} findings "
          f"({len({f['file'] for f in findings})} files affected)")

    if args.sarif_out:
        Path(args.sarif_out).write_text(json.dumps(findings_to_sarif(findings), indent=2) + "\n")
        print(f"[security-scan] SARIF report written to {args.sarif_out}")

    if args.write_baseline:
        baseline = {
            "_comment": (
                "HONEST snapshot of known security-scan findings at release-"
                "engineering time (agent 7-b). Agent 7-a is fixing these "
                "concurrently (e.g. nexus_agent.py shell=True, unverified "
                "TLS contexts). Entries should be REMOVED as fixes land — "
                "never added. Matching: exact 'file:line:rule', with a "
                "(file, rule) count fallback that tolerates line drift."
            ),
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "known_findings": [f"{f['file']}:{f['line']}:{f['rule']}" for f in findings],
        }
        Path(args.write_baseline).write_text(json.dumps(baseline, indent=2) + "\n")
        print(f"[security-scan] baseline written to {args.write_baseline} "
              f"({len(findings)} known findings)")
        return 0

    if args.strict:
        if findings:
            print(f"[security-scan] STRICT MODE: {len(findings)} findings — FAIL")
            return 1
        print("[security-scan] STRICT MODE: clean — PASS")
        return 0

    if args.baseline_file:
        bpath = Path(args.baseline_file)
        if not bpath.exists():
            print(f"[security-scan] FAIL: baseline file not found: {bpath}")
            return 1
        baseline = json.loads(bpath.read_text())
        known = set(baseline.get("known_findings", []))
        # count fallback per (file, rule)
        known_pair_counts: dict[tuple[str, str], int] = {}
        for entry in known:
            try:
                fpath, _line, rule = entry.rsplit(":", 2)
                known_pair_counts[(fpath, rule)] = known_pair_counts.get((fpath, rule), 0) + 1
            except ValueError:
                continue
        cur_pair_counts: dict[tuple[str, str], int] = {}
        for f in findings:
            key = (f["file"], f["rule"])
            cur_pair_counts[key] = cur_pair_counts.get(key, 0) + 1
        new_findings = []
        for f in findings:
            exact = f"{f['file']}:{f['line']}:{f['rule']}" in known
            pair_ok = cur_pair_counts.get((f["file"], f["rule"]), 0) <= \
                known_pair_counts.get((f["file"], f["rule"]), 0)
            if not (exact or pair_ok):
                new_findings.append(f)
        if new_findings:
            print(f"[security-scan] {len(new_findings)} NEW findings not in baseline:")
            for f in new_findings:
                print(f"  NEW  {f['file']}:{f['line']}: {f['rule']} — {f['message']}")
            print("[security-scan] FAIL — fix or explicitly re-baseline them")
            return 1
        print(f"[security-scan] all {len(findings)} findings are known baseline entries "
              f"(zero new) — PASS")
        return 0

    # no baseline, no strict: report and fail on any finding
    if findings:
        print("[security-scan] findings present (run with --baseline-file "
              "tools/security_baseline.json in CI) — FAIL")
        return 1
    print("[security-scan] clean — PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

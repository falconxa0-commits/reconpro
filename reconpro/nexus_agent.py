"""Nexus Agent — Agentic security engine.

The core intelligence brain of ReconPro. Accepts a natural language goal,
reasons about what needs to be done, plans tool usage, executes step by step,
verifies results, and adapts the plan dynamically.

Powered by a built-in rule-based planner — zero external API keys required.
Optionally supports OpenAI/Anthropic LLM backends when API keys are set.

18 built-in tools covering scanning, recon, intel, and export.
Persistent per-target memory stored at ~/.reconpro/memory/agent_context.json.
"""
from __future__ import annotations

import json
import math
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# ── Optional LLM dependency flags ─────────────────────────────────────

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

console = Console()

from .constants import MEMORY_DIR
CONTEXT_FILE = MEMORY_DIR / "agent_context.json"
MAX_ITERATIONS = 10


# ══════════════════════════════════════════════════════════════════════
#  TOOL RESULT & TOOL
# ══════════════════════════════════════════════════════════════════════


class ToolResult:
    """Result of a tool execution."""

    def __init__(self, output: str, success: bool = True, data: Any = None):
        self.output = output
        self.success = success
        self.data = data

    def to_dict(self) -> Dict:
        return {"output": self.output, "success": self.success, "data": self.data}


class Tool:
    """A callable tool the agent can use."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        execute: Callable[..., ToolResult],
        category: str = "scan",
        dangerous: bool = False,
    ):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.execute = execute
        self.category = category
        self.dangerous = dangerous

    def to_openai_tool(self) -> Dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": self.parameters,
                    "required": list(self.parameters.keys()),
                },
            },
        }

    def to_anthropic_tool(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.parameters,
                "required": list(self.parameters.keys()),
            },
        }


class ToolRegistry:
    """Registry of all available tools."""

    def __init__(self):
        self.tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        return self.tools.get(name)

    def execute(self, name: str, **kwargs) -> ToolResult:
        tool = self.tools.get(name)
        if not tool:
            return ToolResult(f"Tool '{name}' not found.", success=False)
        try:
            return tool.execute(**kwargs)
        except Exception as e:
            return ToolResult(f"Tool error: {e}", success=False)

    def list_tools(self) -> List[Dict]:
        return [
            {"name": t.name, "description": t.description, "category": t.category}
            for t in self.tools.values()
        ]

    def to_openai_tools(self) -> List[Dict]:
        return [t.to_openai_tool() for t in self.tools.values()]

    def to_anthropic_tools(self) -> List[Dict]:
        return [t.to_anthropic_tool() for t in self.tools.values()]


# ══════════════════════════════════════════════════════════════════════
#  PERSISTENT MEMORY
# ══════════════════════════════════════════════════════════════════════


class AgentMemory:
    """Persistent memory for the Nexus agent across sessions."""

    def __init__(self):
        MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    def _load(self) -> Dict:
        if CONTEXT_FILE.exists():
            try:
                return json.loads(CONTEXT_FILE.read_text())
            except Exception:
                pass
        return {
            "sessions": [],
            "target_contexts": {},
            "learned_patterns": [],
            "created": datetime.now(timezone.utc).isoformat(),
        }

    def _save(self) -> None:
        # Keep only the last 50 sessions
        if len(self._data.get("sessions", [])) > 50:
            self._data["sessions"] = self._data["sessions"][-50:]
        try:
            CONTEXT_FILE.write_text(json.dumps(self._data, indent=2, default=str))
        except OSError:
            pass

    def save_session(
        self,
        goal: str,
        target: str,
        plan: List[Dict],
        tool_results: List[Dict],
        summary: str,
    ) -> None:
        session = {
            "goal": goal,
            "target": target,
            "plan": plan,
            "tool_results": tool_results,
            "summary": summary,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._data.setdefault("sessions", []).append(session)
        # Update target context
        self._data.setdefault("target_contexts", {})[target] = {
            "last_score": self._extract_score(tool_results),
            "last_grade": self._extract_grade(tool_results),
            "last_run": session["timestamp"],
            "finding_count": self._extract_finding_count(tool_results),
            "known_issues": self._extract_issues(tool_results),
        }
        self._save()

    def get_target_context(self, target: str) -> Optional[Dict]:
        return self._data.get("target_contexts", {}).get(target)

    def get_recent_sessions(self, limit: int = 5) -> List[Dict]:
        return self._data.get("sessions", [])[-limit:]

    @staticmethod
    def _extract_score(results: List[Dict]) -> Optional[int]:
        for r in results:
            d = r.get("data")
            if isinstance(d, dict) and "total_score" in d:
                return d["total_score"]
        return None

    @staticmethod
    def _extract_grade(results: List[Dict]) -> Optional[str]:
        for r in results:
            d = r.get("data")
            if isinstance(d, dict) and "grade" in d:
                return d["grade"]
        return None

    @staticmethod
    def _extract_finding_count(results: List[Dict]) -> int:
        total = 0
        for r in results:
            d = r.get("data")
            if isinstance(d, dict) and "findings" in d:
                total += len(d["findings"])
        return total

    @staticmethod
    def _extract_issues(results: List[Dict]) -> List[str]:
        issues = []
        for r in results:
            d = r.get("data")
            if isinstance(d, dict) and "findings" in d:
                for f in d["findings"]:
                    if isinstance(f, dict) and f.get("severity") in ("critical", "high"):
                        issues.append(f.get("title", ""))
        return issues[:20]


# ══════════════════════════════════════════════════════════════════════
#  TOOL IMPLEMENTATIONS (18 tools)
# ══════════════════════════════════════════════════════════════════════


def _tool_remote_scan(
    target: str = "",
    modules: str = "",
    all_modules: bool = False,
    timeout: int = 10,
) -> ToolResult:
    """Full remote scan of a target domain/URL."""
    from .scanner import scan
    if not target:
        return ToolResult("No target specified.", success=False)
    mod_list = [m.strip().lower() for m in modules.split(",") if m.strip()] if modules else None
    result = scan(target, modules=mod_list, all_modules=all_modules, timeout=timeout)
    return ToolResult(
        f"Scanned {target}. Score: {result.total_score}/100 ({result.grade}). "
        f"{len(result.findings)} findings.",
        success=True,
        data=result.to_dict(),
    )


def _tool_vibesec_benchmark(target: str = "") -> ToolResult:
    """Quick VibeSec score check."""
    from .scanner import scan
    if not target:
        return ToolResult("No target specified.", success=False)
    result = scan(target, modules=["vibesec"])
    score = result.vibesec_score or result.total_score
    grade = result.vibesec_grade or result.grade
    return ToolResult(
        f"VibeSec benchmark for {target}: {score}/100 ({grade}).",
        success=True,
        data={
            "target": target, "vibesec_score": score,
            "vibesec_grade": grade, "findings": result.findings,
        },
    )


def _tool_local_audit(target_path: str = ".") -> ToolResult:
    """Full machine audit."""
    from .scanner import audit_scan
    result = audit_scan(target=target_path, all_modules=True)
    return ToolResult(
        f"Local audit of {target_path}. Score: {result.total_score}/100 ({result.grade}). "
        f"{len(result.findings)} findings.",
        success=True,
        data=result.to_dict(),
    )


def _tool_dev_scan(path: str = ".") -> ToolResult:
    """Developer project scan."""
    from .scanner import audit_scan
    result = audit_scan(target=path, modules=["dev"])
    return ToolResult(
        f"Dev scan of {path}. Score: {result.total_score}/100 ({result.grade}). "
        f"{len(result.findings)} findings.",
        success=True,
        data=result.to_dict(),
    )


def _tool_doctor_check() -> ToolResult:
    """Health check with fix suggestions."""
    from .scanner import audit_scan
    result = audit_scan(target="localhost", modules=["doctor"])
    return ToolResult(
        f"Doctor check complete. Score: {result.total_score}/100 ({result.grade}). "
        f"{len(result.findings)} findings.",
        success=True,
        data=result.to_dict(),
    )


def _tool_port_scan() -> ToolResult:
    """Check for open and risky ports on the local machine."""
    from .modules.host import _check_open_ports
    findings = _check_open_ports()
    if not findings:
        return ToolResult("No risky ports found.", success=True, data=[])
    lines = [f"{f.severity.upper()}: {f.title}" for f in findings]
    return ToolResult(
        f"Found {len(findings)} port issue(s):\n" + "\n".join(lines),
        success=True,
        data=[f.to_dict() for f in findings],
    )


def _tool_secret_hunt(path: str = ".") -> ToolResult:
    """Find secrets and credentials in a directory."""
    from .modules.host import _check_env_secrets
    from .modules.dev import _check_env_files, _check_hardcoded_secrets
    abs_path = os.path.abspath(path)
    all_f = (
        _check_env_secrets()
        + _check_env_files(abs_path)
        + _check_hardcoded_secrets(abs_path)
    )
    if not all_f:
        return ToolResult("No secrets found.", success=True, data=[])
    lines = [f"{f.severity.upper()}: {f.title}" for f in all_f[:20]]
    return ToolResult(
        f"Found {len(all_f)} secret(s):\n" + "\n".join(lines),
        success=True,
        data=[f.to_dict() for f in all_f],
    )


def _tool_subdomain_discover(domain: str = "") -> ToolResult:
    """Discover subdomains via CT logs and DNS."""
    from .subdomains import discover_subdomains
    if not domain:
        return ToolResult("No domain specified.", success=False)
    subs = discover_subdomains(domain)
    return ToolResult(
        f"Found {len(subs)} subdomain(s): {', '.join(subs[:20])}",
        success=True,
        data={"subdomains": subs},
    )


def _tool_blitz_scan(targets_str: str = "") -> ToolResult:
    """Parallel multi-target scan."""
    from .parallel import blitz_scan
    target_list = [t.strip() for t in targets_str.split(",") if t.strip()]
    if len(target_list) < 2:
        return ToolResult("Blitz requires at least 2 comma-separated targets.", success=False)
    result = blitz_scan(target_list, max_workers=min(4, len(target_list)), save=True)
    return ToolResult(
        f"Blitz: {result.get('total_findings', 0)} findings across "
        f"{result.get('targets_scanned', 0)} targets.",
        success=True,
        data=result,
    )


def _tool_ast_analyze(path: str = ".") -> ToolResult:
    """AST code analysis for security anti-patterns."""
    from .modules.ast_analyzer import ASTAnalyzer
    analyzer = ASTAnalyzer()
    findings = analyzer.analyze_directory(path)
    if not findings:
        return ToolResult(f"No code issues found in {path}.", success=True, data=[])
    summary = analyzer.summary()
    lines = [f"{f.severity.upper()}: {f.title} ({f.asset})" for f in findings[:20]]
    return ToolResult(
        f"AST analysis of {path}: {summary['total']} findings.\n" + "\n".join(lines),
        success=True,
        data={
            "findings": [f.to_dict() for f in findings],
            "summary": summary,
        },
    )


def _tool_cve_enrich(findings_json: str = "[]") -> ToolResult:
    """Enrich findings with CVE data from NVD."""
    from .cve_radar import CVERadar
    try:
        findings = json.loads(findings_json)
    except (json.JSONDecodeError, TypeError):
        return ToolResult("Invalid findings JSON.", success=False)
    if not findings or not isinstance(findings, list):
        return ToolResult("Empty or invalid findings list.", success=False)
    radar = CVERadar()
    enriched = radar.bulk_enrich(findings[:30])
    threat = radar.threat_summary(enriched)
    cve_count = threat.get("unique_cves_found", 0)
    return ToolResult(
        f"Enriched {len(enriched)} findings. Found {cve_count} unique CVEs. "
        f"{threat.get('recommendation', '')}",
        success=True,
        data={"enriched_findings": enriched, "threat_summary": threat},
    )


def _tool_knowledge_graph(action: str = "build", target: str = "") -> ToolResult:
    """Build or query the security knowledge graph."""
    from .knowledge_graph import SecurityKnowledgeGraph
    if not target:
        return ToolResult("No target specified.", success=False)
    kg = SecurityKnowledgeGraph()
    if action == "build":
        from .history import get_latest
        latest = get_latest(target=target)
        if not latest:
            latest = get_latest()
        if latest:
            kg.add_scan_result(latest)
        n_count = len(list(kg._g.nodes(data=False)))
        e_count = len(list(kg._g.edges(data=False)))
        return ToolResult(
            f"Knowledge graph built: {n_count} nodes, {e_count} edges for {target}.",
            success=True,
            data={"node_count": n_count, "edge_count": e_count, "target": target},
        )
    elif action == "attack_chains":
        chains = kg.find_attack_chains(max_depth=4)
        return ToolResult(
            f"Found {len(chains)} attack chain(s).", success=True,
            data={"attack_chains": chains},
        )
    else:
        return ToolResult(f"Unknown action: {action}. Use 'build' or 'attack_chains'.", success=False)


def _tool_adversarial_loop(target: str = "", rounds: int = 2) -> ToolResult:
    """Run hacker-coder-guardian adversarial loop."""
    from .adversarial import run_adversarial
    if not target:
        return ToolResult("No target specified.", success=False)
    is_local = target in ("localhost", ".", "local", "my machine")
    result = run_adversarial(target, max_rounds=rounds, is_local=is_local)
    return ToolResult(
        f"Adversarial loop: {result.total_findings_initial} initial findings, "
        f"{result.findings_fixed} fixed, {result.findings_unfixed} remaining. "
        f"Score: {result.initial_grade} ({result.initial_score}) -> "
        f"{result.final_grade} ({result.final_score})",
        success=True,
        data={
            "target": result.target,
            "initial_score": result.initial_score,
            "final_score": result.final_score,
            "initial_grade": result.initial_grade,
            "final_grade": result.final_grade,
            "findings_fixed": result.findings_fixed,
            "findings_unfixed": result.findings_unfixed,
            "converged": result.converged,
        },
    )


def _tool_swarm_run(target: str = "", mode: str = "recon") -> ToolResult:
    """Run the full swarm attack (SCOUT -> HACKER -> CODER -> GUARDIAN)."""
    from .swarm import run_swarm
    if not target:
        return ToolResult("No target specified.", success=False)
    result = run_swarm(target, mode=mode)
    total_findings = sum(len(a.findings) for a in result.agents.values())
    return ToolResult(
        f"Swarm complete ({mode} mode). {total_findings} total findings across "
        f"{len(result.agents)} agents.",
        success=True,
        data={
            "target": target, "mode": mode,
            "agents": {k: {"status": v.status.value, "findings_count": len(v.findings)}
                       for k, v in result.agents.items()},
        },
    )


def _tool_generate_report(format: str = "html") -> ToolResult:
    """Generate a report (HTML, MD, SARIF, JSON) from the last scan."""
    from .history import get_latest
    from .formats import export
    latest = get_latest()
    if not latest:
        return ToolResult("No scan data to export. Run a scan first.", success=False)
    target = latest.get("target", "unknown").replace(",", "").replace("/", "_")[:40]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext_map = {"html": ".html", "md": ".md", "sarif": ".sarif", "json": ".json"}
    ext = ext_map.get(format.lower(), ".html")
    filename = f"reconpro_report_{ts}_{target}{ext}"
    filepath = str(MEMORY_DIR / filename)
    path = export(latest, filepath, format=format.lower())
    return ToolResult(
        f"Report generated: {path}",
        success=True,
        data={"path": path, "format": format},
    )


def _tool_scan_history(limit: int = 10) -> ToolResult:
    """List past scans."""
    from .history import list_scans
    scans = list_scans(limit=limit)
    if not scans:
        return ToolResult("No scan history found.", success=True, data=[])
    lines = [
        f"  {s.get('total_score', '?')}/100 ({s.get('grade', '?')})  "
        f"{s.get('target', '?')[:30]}  {len(s.get('findings', []))} findings"
        for s in scans
    ]
    return ToolResult(
        f"Recent {len(scans)} scan(s):\n" + "\n".join(lines),
        success=True,
        data=scans,
    )


def _tool_diff_scans() -> ToolResult:
    """Compare the two most recent scans."""
    from .history import list_scans, diff_scans
    scans = list_scans(limit=2)
    if len(scans) < 2:
        return ToolResult("Need at least 2 scans to compare.", success=False)
    d = diff_scans(scans[0]["_file"], scans[1]["_file"])
    return ToolResult(
        f"A: {d['scan_a']['target']} {d['scan_a']['score']}/100 ({d['scan_a']['grade']})\n"
        f"B: {d['scan_b']['target']} {d['scan_b']['score']}/100 ({d['scan_b']['grade']})\n"
        f"Score change: {d['score_change']} pts | "
        f"Fixed: {len(d['fixed'])} | New: {len(d['new'])} | Persistent: {len(d['persistent'])}",
        success=True,
        data=d,
    )


def _tool_shell_command(command: str = "") -> ToolResult:
    """Execute a command WITHOUT a shell.

    The command string is tokenised with shlex and executed as an
    argument list (shell=False), so no shell metacharacter interpretation
    takes place.  DANGEROUS — use with caution.
    """
    if not command:
        return ToolResult("No command specified.", success=False)
    dangerous_patterns = ["rm -rf /", "mkfs", "dd if=", ":(){ :|:& };:", "chmod -R 777 /"]
    for dp in dangerous_patterns:
        if dp in command:
            return ToolResult(f"Blocked dangerous command pattern: {dp}", success=False)
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return ToolResult(f"Command parse error: {e}", success=False)
    if not argv:
        return ToolResult("No command specified.", success=False)
    try:
        result = subprocess.run(
            argv, shell=False, capture_output=True, text=True, timeout=30,
        )
        output = (result.stdout + result.stderr)[:2000]
        return ToolResult(
            f"Exit code: {result.returncode}\n{output}",
            success=result.returncode == 0,
        )
    except subprocess.TimeoutExpired:
        return ToolResult("Command timed out (30s).", success=False)
    except FileNotFoundError:
        return ToolResult(f"Command not found: {argv[0]}", success=False)
    except Exception as e:
        return ToolResult(f"Command error: {e}", success=False)


def _tool_geoip_enrich(**kwargs):
    """GeoIP enrichment for IP addresses"""
    from .geoip import GeoIPLookup
    ips = kwargs.get("ips", [])
    geo = GeoIPLookup()
    results = {}
    for ip in ips:
        results[ip] = geo.enrich_ip(ip)
    return ToolResult(output=json.dumps(results, indent=2, default=str))


def _tool_threat_feed_check(**kwargs):
    """Check IPs against threat feeds and DNSBLs"""
    from .threat_feeds import check_ip_reputation
    ip = kwargs.get("ip", "")
    result = check_ip_reputation(ip) if ip else {"error": "No IP provided"}
    return ToolResult(output=json.dumps(result, indent=2, default=str))


def _tool_ai_red_team(**kwargs):
    """AI endpoint discovery, vendor fingerprinting, and CVE matching"""
    from .ai_red_team import AIEndpointDiscovery, AIVendorFingerprinter, SecretExtractor
    from .ai_cve_db import AICVEDatabase
    base_url = kwargs.get("base_url", kwargs.get("url", ""))
    if not base_url:
        return ToolResult(output="Error: No URL provided")
    discovery = AIEndpointDiscovery()
    endpoints = discovery.discover(base_url)
    fingerprinter = AIVendorFingerprinter()
    vendors = fingerprinter.fingerprint(base_url)
    db = AICVEDatabase()
    summary = db.get_threat_summary()
    return ToolResult(output=json.dumps({"endpoints": len(endpoints), "vendors": vendors, "ai_threat_landscape": summary}, indent=2, default=str))


def _tool_ai_model_audit(**kwargs):
    """AI model analysis: watermarks, collapse, trauma imprints"""
    from .ai_red_team import WatermarkAnalyzer, ModelCollapseDetector, TraumaImprintDetector
    url = kwargs.get("url", "")
    if not url:
        return ToolResult(output="Error: No URL provided")
    import urllib.request
    try:
        resp = urllib.request.urlopen(url, timeout=10)
        body = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        body = ""
    wm = WatermarkAnalyzer().analyze(body, dict(resp.headers) if 'resp' in dir() else {})
    mc = ModelCollapseDetector().detect(body)
    ti = TraumaImprintDetector().detect(body)
    return ToolResult(output=json.dumps({"watermark": wm, "collapse": mc, "trauma_imprint": ti}, indent=2, default=str))


def _tool_wishes_ritual(**kwargs):
    """Execute 22-Wish orchestration ritual"""
    from .wishes import WishesOrchestrator
    target = kwargs.get("target", "")
    if not target:
        return ToolResult(output="Error: No target provided")
    orchestrator = WishesOrchestrator()
    manifest = orchestrator.execute(target, f"https://{target}", timeout=8, verify_tls=True)
    return ToolResult(output=json.dumps(manifest, indent=2, default=str))


def _tool_cross_validate(**kwargs):
    """Cross-validate scan findings independently"""
    from .cross_validator import CrossValidator
    target = kwargs.get("target", "")
    findings = kwargs.get("findings", [])
    if not target:
        return ToolResult(output="Error: No target provided")
    cv = CrossValidator()
    result = cv.validate(target, findings)
    return ToolResult(output=json.dumps(result, indent=2, default=str))


# ══════════════════════════════════════════════════════════════════════
#  BUILD DEFAULT REGISTRY
# ══════════════════════════════════════════════════════════════════════


def build_registry() -> ToolRegistry:
    """Build the default tool registry with all 18 tools."""
    reg = ToolRegistry()

    reg.register(Tool(
        "remote_scan",
        "Full remote security scan of a domain or URL. Runs all enabled modules (recon, auth, "
        "chain, oblivion, etc.) and returns score, grade, and detailed findings. "
        "Use all_modules=true for maximum coverage.",
        {
            "target": {"type": "string", "description": "Domain or URL to scan"},
            "modules": {"type": "string", "description": "Comma-separated module list (optional, e.g. 'recon,auth')"},
            "all_modules": {"type": "boolean", "description": "Run all available modules"},
            "timeout": {"type": "integer", "description": "Per-request timeout in seconds (default 10)"},
        },
        _tool_remote_scan, category="scan",
    ))

    reg.register(Tool(
        "vibesec_benchmark",
        "Quick VibeSec security score benchmark. Returns a fast 0-100 score and grade "
        "for a target without running the full scan suite.",
        {
            "target": {"type": "string", "description": "Domain or URL to benchmark"},
        },
        _tool_vibesec_benchmark, category="scan",
    ))

    reg.register(Tool(
        "local_audit",
        "Full local machine security audit. Checks open ports, firewall rules, users, SSH config, "
        "Docker security, environment secrets, file permissions, cron jobs, and network config.",
        {
            "target_path": {"type": "string", "description": "Directory to audit (default: current)"},
        },
        _tool_local_audit, category="local",
    ))

    reg.register(Tool(
        "dev_scan",
        "Scan a developer project for security issues: package.json/requirements.txt vulnerabilities, "
        ".env file exposure, git secrets, Docker config, and hardcoded credentials.",
        {
            "path": {"type": "string", "description": "Project directory path (default: current)"},
        },
        _tool_dev_scan, category="scan",
    ))

    reg.register(Tool(
        "doctor_check",
        "Run security health check on the local machine. Checks password policy, disk encryption, "
        "screen auto-lock, antivirus status, system updates, and browser security settings. "
        "Provides fix suggestions for each issue.",
        {},
        _tool_doctor_check, category="local",
    ))

    reg.register(Tool(
        "port_scan",
        "Check for open and risky ports on the local machine. Identifies services that may be "
        "unnecessarily exposed (e.g., databases on public interfaces).",
        {},
        _tool_port_scan, category="recon",
    ))

    reg.register(Tool(
        "secret_hunt",
        "Hunt for secrets and credentials in a directory tree. Scans .env files, hardcoded passwords, "
        "API keys, tokens, and other sensitive values in source code.",
        {
            "path": {"type": "string", "description": "Directory to scan (default: current)"},
        },
        _tool_secret_hunt, category="recon",
    ))

    reg.register(Tool(
        "subdomain_discover",
        "Discover subdomains using certificate transparency logs (crt.sh) and DNS enumeration. "
        "Returns a list of all discovered subdomains for the given domain.",
        {
            "domain": {"type": "string", "description": "Domain to discover subdomains for"},
        },
        _tool_subdomain_discover, category="recon",
    ))

    reg.register(Tool(
        "blitz_scan",
        "Scan multiple targets in parallel using thread pools. Provide comma-separated targets. "
        "Requires at least 2 targets. Uses up to 4 parallel workers.",
        {
            "targets_str": {"type": "string", "description": "Comma-separated list of domains/URLs"},
        },
        _tool_blitz_scan, category="scan",
    ))

    reg.register(Tool(
        "ast_analyze",
        "Static AST code analysis for security anti-patterns in Python, JavaScript, and TypeScript. "
        "Detects eval/exec usage, SQL injection patterns, hardcoded secrets, weak crypto, "
        "unsafe deserialization, path traversal, command injection, and more.",
        {
            "path": {"type": "string", "description": "Directory or file to analyze (default: current)"},
        },
        _tool_ast_analyze, category="intel",
    ))

    reg.register(Tool(
        "cve_enrich",
        "Enrich a list of findings with real CVE data from the NVD (National Vulnerability Database). "
        "Takes a JSON array of finding dicts and returns enriched findings with CVE references, "
        "CVSS scores, and a threat intelligence summary.",
        {
            "findings_json": {"type": "string", "description": "JSON array of finding dicts to enrich"},
        },
        _tool_cve_enrich, category="intel",
    ))

    reg.register(Tool(
        "knowledge_graph",
        "Build or query the security knowledge graph. 'build' action ingests scan results into a graph. "
        "'attack_chains' action discovers potential attack paths through the graph.",
        {
            "action": {"type": "string", "description": "Action: 'build' or 'attack_chains'"},
            "target": {"type": "string", "description": "Target domain the graph is for"},
        },
        _tool_knowledge_graph, category="intel",
    ))

    reg.register(Tool(
        "adversarial_loop",
        "Run the hacker-coder-guardian adversarial remediation loop. HACKER finds vulnerabilities, "
        "CODER generates fix commands, GUARDIAN verifies fixes. Repeats for multiple rounds.",
        {
            "target": {"type": "string", "description": "Domain/URL or 'localhost' for local audit"},
            "rounds": {"type": "integer", "description": "Number of HACKER->CODER->GUARDIAN rounds (default 2)"},
        },
        _tool_adversarial_loop, category="scan",
    ))

    reg.register(Tool(
        "swarm_run",
        "Run the full multi-agent swarm attack system. Orchestrates SCOUT (recon), HACKER (deep vuln), "
        "CODER (remediation), and GUARDIAN (verification) agents in parallel. "
        "Modes: 'full', 'recon', 'attack', 'fix', 'verify'.",
        {
            "target": {"type": "string", "description": "Domain or URL to attack"},
            "mode": {"type": "string", "description": "Swarm mode: 'full', 'recon', 'attack', 'fix', or 'verify'"},
        },
        _tool_swarm_run, category="scan",
    ))

    reg.register(Tool(
        "generate_report",
        "Generate a security report from the most recent scan data. Supports HTML, Markdown, SARIF, "
        "and JSON formats. SARIF is compatible with GitHub Code Scanning.",
        {
            "format": {"type": "string", "description": "Report format: 'html', 'md', 'sarif', or 'json'"},
        },
        _tool_generate_report, category="export",
    ))

    reg.register(Tool(
        "scan_history",
        "List recent scan results from local history. Shows target, score, grade, and finding count.",
        {
            "limit": {"type": "integer", "description": "Number of scans to show (default 10)"},
        },
        _tool_scan_history, category="export",
    ))

    reg.register(Tool(
        "diff_scans",
        "Compare the two most recent scans to see what changed. Shows score delta, fixed findings, "
        "new findings, and persistent issues.",
        {},
        _tool_diff_scans, category="export",
    ))

    reg.register(Tool(
        "shell_command",
        "[DANGEROUS] Execute an arbitrary shell command. Use only when no other tool can accomplish "
        "the task. Certain destructive patterns are blocked.",
        {
            "command": {"type": "string", "description": "Shell command to execute"},
        },
        _tool_shell_command, category="system", dangerous=True,
    ))

    reg.register(Tool(
        "geoip_enrich",
        "GeoIP enrichment for IP addresses",
        {"ips": {"type": "array", "items": {"type": "string"}}},
        _tool_geoip_enrich, category="recon",
    ))

    reg.register(Tool(
        "threat_feed_check",
        "Check IPs against threat feeds and DNSBLs",
        {"ip": {"type": "string"}},
        _tool_threat_feed_check, category="recon",
    ))

    reg.register(Tool(
        "ai_red_team",
        "AI endpoint discovery, vendor fingerprinting, CVE matching",
        {"base_url": {"type": "string"}},
        _tool_ai_red_team, category="scan",
    ))

    reg.register(Tool(
        "ai_model_audit",
        "AI model analysis: watermarks, collapse, trauma imprints",
        {"url": {"type": "string"}},
        _tool_ai_model_audit, category="intel",
    ))

    reg.register(Tool(
        "wishes_ritual",
        "Execute 22-Wish orchestration ritual",
        {"target": {"type": "string"}},
        _tool_wishes_ritual, category="scan",
    ))

    reg.register(Tool(
        "cross_validate",
        "Cross-validate scan findings",
        {"target": {"type": "string"}},
        _tool_cross_validate, category="intel",
    ))

    return reg


# ══════════════════════════════════════════════════════════════════════
#  CVSS-LIKE RISK SCORER
# ══════════════════════════════════════════════════════════════════════


class CVSSScorer:
    """CVSS-inspired risk scoring for security findings.

    Computes a base score (0.0–10.0) using the CVSS v3.1 formula
    simplified for rule-based use:
      - Attack Vector (AV): Network=0.85, Adjacent=0.62, Local=0.55, Physical=0.20
      - Attack Complexity (AC): Low=0.77, High=0.44
      - Privileges Required (PR): None=0.85, Low=0.62, High=0.27
      - User Interaction (UI): None=0.85, Required=0.62
      - Impact (C/I/A): None=0.00, Low=0.22, High=0.56

    BaseScore = roundup(min(Impact + Exploitability, 10))
    Impact = 1 - [(1-C)*(1-I)*(1-A)]
    Exploitability = 8.22 * AV * AC * PR * UI
    """

    # Attack Vector metrics
    _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    # Attack Complexity metrics
    _AC = {"L": 0.77, "H": 0.44}
    # Privileges Required metrics
    _PR = {"N": 0.85, "L": 0.62, "H": 0.27}
    # User Interaction metrics
    _UI = {"N": 0.85, "R": 0.62}
    # CIA Impact metrics
    _CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

    # Category-to-metric mappings. Keys are lowercase substrings matched
    # against finding titles/descriptions.
    _CATEGORY_PROFILES: List[Dict[str, Any]] = [
        # TLS / transport security
        {"patterns": ["hsts", "strict-transport", "tls", "ssl", "certificate", "https redirect",
                        "mixed content", "tls downgrade"],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "L", "i": "H", "a": "N"},
        # Security headers
        {"patterns": ["x-frame", "csp", "content-security", "x-content-type", "x-xss",
                        "referrer-policy", "permissions-policy", "missing header"],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "L", "i": "L", "a": "N"},
        # Admin panel exposure
        {"patterns": ["admin panel", "admin interface", "dashboard exposed", "wp-admin",
                        "phpmyadmin", "control panel"],
         "av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "H"},
        # Authentication weaknesses
        {"patterns": ["weak password", "brute force", "no rate limit", "default credential",
                        "auth bypass", "login", "session fix", "cookie"],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "L"},
        # SQL injection / code injection
        {"patterns": ["sqli", "sql injection", "xss", "cross-site scripting", "command injection",
                        "code injection", "eval", "exec", "rce", "remote code"],
         "av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "H"},
        # Sensitive data exposure
        {"patterns": ["secret", "api key", "token", "credential", ".env", "hardcoded",
                        "private key", "leaked", "exposed", "password in"],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "L", "a": "N"},
        # Open ports / network
        {"patterns": ["open port", "port ", "service exposed", "database exposed",
                        "redis", "mongodb", "mysql", "ssh exposed"],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        # SSRF / redirect
        {"patterns": ["ssrf", "open redirect", "redirect", "url redirect", "server-side request"],
         "av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "L", "a": "L"},
        # Information disclosure
        {"patterns": ["info leak", "version disclose", "server header", "directory listing",
                        "git exposed", "debug mode", "stack trace", "error message"],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "L", "i": "L", "a": "N"},
        # CSRF
        {"patterns": ["csrf", "cross-site request"],
         "av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "L", "i": "H", "a": "N"},
        # Dependency / supply chain
        {"patterns": ["outdated", "vulnerable dependency", "supply chain", "npm audit",
                        "pip audit", "known cve", "package vulnerability"],
         "av": "N", "ac": "H", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        # Docker / container
        {"patterns": ["docker", "container", "privileged", "kubernetes", "k8s"],
         "av": "N", "ac": "H", "pr": "L", "ui": "N", "c": "H", "i": "H", "a": "H"},
        # File permission / local
        {"patterns": ["file permission", "chmod", "world-readable", "writable",
                        "cron", "sudo", "privilege escalation"],
         "av": "L", "ac": "L", "pr": "L", "ui": "N", "c": "H", "i": "H", "a": "H"},
        # Bot / automation detection
        {"patterns": ["bot", "crawler", "automation", "c2", "command and control"],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "L", "i": "L", "a": "L"},
        # Cloud / identity
        {"patterns": ["cloud", "aws", "azure", "gcp", "s3 bucket", "iam", "oauth",
                        "identity", "federation"],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        # Default fallback
        {"patterns": [],
         "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "L", "i": "L", "a": "N"},
    ]

    @classmethod
    def score_finding(cls, finding: Dict) -> Dict[str, Any]:
        """Compute CVSS-like score for a single finding.

        Returns a dict with: base_score, severity, av, ac, pr, ui, c, i, a, vector_string.
        """
        title = (finding.get("title") or "").lower()
        desc = (finding.get("description") or "").lower()
        combined = f"{title} {desc}"
        original_sev = (finding.get("severity") or "").lower()

        # Find matching profile
        profile = cls._CATEGORY_PROFILES[-1]  # default
        for prof in cls._CATEGORY_PROFILES:
            if prof["patterns"] and any(p in combined for p in prof["patterns"]):
                profile = prof
                break

        # Override metrics based on original severity if it's explicitly critical
        av = cls._AV[profile["av"]]
        ac = cls._AC[profile["ac"]]
        pr = cls._PR[profile["pr"]]
        ui = cls._UI[profile["ui"]]
        c = cls._CIA[profile["c"]]
        i = cls._CIA[profile["i"]]
        a = cls._CIA[profile["a"]]

        # If the original severity is critical, boost impact to High
        if original_sev == "critical":
            c = max(c, cls._CIA["H"])
            i = max(i, cls._CIA["H"])
            a = max(a, cls._CIA["H"])
        elif original_sev == "high":
            c = max(c, cls._CIA["L"])
            i = max(i, cls._CIA["L"])
            a = max(a, cls._CIA["L"])

        # CVSS base score calculation
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        impact = 6.42 * iss
        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base_score = 0.0
        else:
            base_score = min(impact + exploitability, 10.0)

        # Round up to nearest 0.1
        base_score = math.ceil(base_score * 10) / 10

        # Derive severity from score
        if base_score >= 9.0:
            derived_sev = "critical"
        elif base_score >= 7.0:
            derived_sev = "high"
        elif base_score >= 4.0:
            derived_sev = "medium"
        elif base_score > 0.0:
            derived_sev = "low"
        else:
            derived_sev = "info"

        # Use the more severe of original vs derived
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        final_sev = original_sev if severity_order.get(original_sev, 99) <= severity_order.get(derived_sev, 99) else derived_sev

        vector = f"CVSS:3.1/AV:{profile['av']}/AC:{profile['ac']}/PR:{profile['pr']}/UI:{profile['ui']}/C:{cls._cia_label(c)}/I:{cls._cia_label(i)}/A:{cls._cia_label(a)}"

        return {
            "base_score": base_score,
            "severity": final_sev,
            "cvss_vector": vector,
            "metrics": {
                "av": profile["av"], "ac": profile["ac"], "pr": profile["pr"],
                "ui": profile["ui"], "c": cls._cia_label(c), "i": cls._cia_label(i),
                "a": cls._cia_label(a),
            },
        }

    @classmethod
    def score_findings(cls, findings: List[Dict]) -> List[Dict]:
        """Score a list of findings, returning enriched list."""
        enriched = []
        for f in findings:
            scored = dict(f)
            cvss = cls.score_finding(f)
            scored["cvss_score"] = cvss["base_score"]
            scored["cvss_severity"] = cvss["severity"]
            scored["cvss_vector"] = cvss["cvss_vector"]
            scored["cvss_metrics"] = cvss["metrics"]
            enriched.append(scored)
        return enriched

    @staticmethod
    def _cia_label(value: float) -> str:
        if value >= 0.56:
            return "H"
        elif value >= 0.22:
            return "L"
        return "N"


# ══════════════════════════════════════════════════════════════════════
#  FINDING CORRELATION ENGINE
# ══════════════════════════════════════════════════════════════════════


class FindingCorrelationEngine:
    """Cross-references individual findings to identify compound risks.

    Each correlation rule specifies:
      - triggers: list of lowercase pattern lists (OR between outer, AND within inner)
      - compound_title: human-readable title for the compound finding
      - compound_severity: severity to assign
      - compound_description: explanation of the risk
      - cvss_override: optional CVSS metrics for the compound finding

    20+ correlation rules covering TLS, auth, data exposure, injection,
    misconfig, cloud, and network compound risks.
    """

    CORRELATION_RULES: List[Dict[str, Any]] = [
        # ── TLS / Transport compound risks ──
        {
            "id": "CORR-001",
            "triggers": [["missing hsts", "strict-transport"], ["mixed content"]],
            "compound_title": "TLS Downgrade Attack Vector",
            "compound_severity": "high",
            "compound_description": (
                "Combination of missing HSTS and mixed content allows a man-in-the-middle "
                "attacker to downgrade HTTPS connections and inject content over unencrypted channels."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "L"},
        },
        {
            "id": "CORR-002",
            "triggers": [["certificate", "cert"], ["weak cipher", "tls", "ssl"]],
            "compound_title": "Weak TLS Configuration Chain",
            "compound_severity": "high",
            "compound_description": (
                "Certificate issues combined with weak TLS/SSL cipher suites create "
                "multiple interception and decryption attack vectors."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "N"},
        },
        {
            "id": "CORR-003",
            "triggers": [["https redirect"], ["mixed content"]],
            "compound_title": "Partial Encryption with Content Leakage",
            "compound_severity": "medium",
            "compound_description": (
                "HTTPS redirect is present but mixed content loads over HTTP, "
                "leaking user data in transit."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "L", "a": "N"},
        },
        # ── Authentication compound risks ──
        {
            "id": "CORR-004",
            "triggers": [["admin panel", "admin interface", "dashboard", "wp-admin"],
                         ["weak password", "default credential", "no rate limit"]],
            "compound_title": "Brute-Force Attack Path to Admin Access",
            "compound_severity": "critical",
            "compound_description": (
                "Exposed admin panel combined with weak or default credentials and no rate "
                "limiting enables trivial brute-force attacks leading to full admin compromise."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-005",
            "triggers": [["session"], ["no rate limit", "brute force"]],
            "compound_title": "Session-Based Credential Stuffing Risk",
            "compound_severity": "high",
            "compound_description": (
                "Session management issues combined with absent rate limiting enable "
                "automated credential stuffing attacks at scale."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "L"},
        },
        {
            "id": "CORR-006",
            "triggers": [["csrf", "cross-site request"], ["cookie", "session"]],
            "compound_title": "Session Hijacking via CSRF",
            "compound_severity": "high",
            "compound_description": (
                "Missing CSRF protection combined with insecure cookie/session handling "
                "enables cross-site request forgery to hijack user sessions."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "N"},
        },
        {
            "id": "CORR-007",
            "triggers": [["auth bypass"], ["admin panel", "dashboard", "privileged"]],
            "compound_title": "Privilege Escalation to Admin",
            "compound_severity": "critical",
            "compound_description": (
                "Authentication bypass combined with exposed admin interfaces allows "
                "unauthenticated attackers to gain full administrative access."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        # ── Data exposure compound risks ──
        {
            "id": "CORR-008",
            "triggers": [[".env", "env file", "environment"], ["git exposed", "git", ".git"]],
            "compound_title": "Full Credential Exposure via Git + Env Leak",
            "compound_severity": "critical",
            "compound_description": (
                "Exposed .git directory combined with .env file disclosure grants attackers "
                "full source code access and all application secrets/credentials."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-009",
            "triggers": [["directory listing"], ["sensitive data", "backup", "config", ".sql", ".zip"]],
            "compound_title": "Sensitive File Exposure via Directory Listing",
            "compound_severity": "high",
            "compound_description": (
                "Directory listing enabled combined with sensitive file patterns allows "
                "attackers to discover and download backups, configs, or databases."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "L", "a": "N"},
        },
        {
            "id": "CORR-010",
            "triggers": [["debug mode", "stack trace", "error message", "verbose"],
                         ["info leak", "version disclose", "technology"]],
            "compound_title": "Information Disclosure Enabling Targeted Attacks",
            "compound_severity": "medium",
            "compound_description": (
                "Debug/error output combined with technology version disclosure provides "
                "attackers with precise targeting information for exploit development."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "L", "i": "L", "a": "N"},
        },
        {
            "id": "CORR-011",
            "triggers": [["hardcoded", "api key", "token"], ["source code", "github", "repo", ".git"]],
            "compound_title": "Supply Chain Secret Compromise",
            "compound_severity": "critical",
            "compound_description": (
                "Hardcoded secrets in source code accessible via public repos or exposed git "
                "history enables complete infrastructure compromise."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        # ── Injection compound risks ──
        {
            "id": "CORR-012",
            "triggers": [["sqli", "sql injection"], ["admin panel", "database", "login"]],
            "compound_title": "SQL Injection to Database Compromise",
            "compound_severity": "critical",
            "compound_description": (
                "SQL injection vulnerability on an admin or login endpoint allows "
                "direct database exfiltration and potential full system compromise."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-013",
            "triggers": [["xss", "cross-site scripting"], ["cookie", "session", "auth"]],
            "compound_title": "XSS to Session Hijack Chain",
            "compound_severity": "high",
            "compound_description": (
                "Cross-site scripting in the presence of session cookies enables "
                "attackers to steal session tokens and hijack authenticated users."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "N"},
        },
        {
            "id": "CORR-014",
            "triggers": [["ssrf"], ["admin panel", "internal", "metadata", "cloud", "aws"]],
            "compound_title": "SSRF to Cloud Metadata / Internal Network Pivot",
            "compound_severity": "critical",
            "compound_description": (
                "Server-Side Request Forgery combined with cloud/internal infrastructure "
                "access enables metadata endpoint abuse and lateral movement."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-015",
            "triggers": [["command injection", "rce", "remote code", "exec"],
                         ["docker", "container", "privileged", "root"]],
            "compound_title": "RCE to Container Escape / Root Access",
            "compound_severity": "critical",
            "compound_description": (
                "Remote code execution in a privileged container environment may lead "
                "to container escape and full host root access."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "H"},
        },
        # ── Network / Infrastructure compound risks ──
        {
            "id": "CORR-016",
            "triggers": [["open port"], ["no firewall", "firewall disabled", "iptables"]],
            "compound_title": "Unprotected Network Services",
            "compound_severity": "high",
            "compound_description": (
                "Open ports combined with absent or disabled firewall rules expose "
                "services directly to the network without any filtering."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-017",
            "triggers": [["open port", "redis", "mongodb", "mysql", "database exposed"],
                         ["no auth", "no password", "default credential", "empty password"]],
            "compound_title": "Unauthenticated Database Access",
            "compound_severity": "critical",
            "compound_description": (
                "Exposed database port with no or default authentication allows any network "
                "attacker to connect, read, modify, or delete all data."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-018",
            "triggers": [["ssh exposed", "ssh", "port 22"], ["weak password", "default credential", "password auth"]],
            "compound_title": "SSH Brute-Force / Credential Attack Vector",
            "compound_severity": "critical",
            "compound_description": (
                "Exposed SSH service with password-based authentication and weak/default "
                "credentials enables remote brute-force attacks leading to system compromise."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        # ── Misconfiguration compound risks ──
        {
            "id": "CORR-019",
            "triggers": [["cors", "cross-origin"], ["credential", "cookie", "auth"]],
            "compound_title": "CORS Misconfiguration with Credential Leak",
            "compound_severity": "high",
            "compound_description": (
                "Overly permissive CORS policy combined with credential-bearing requests "
                "enables cross-origin data exfiltration."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "L", "a": "N"},
        },
        {
            "id": "CORR-020",
            "triggers": [["x-frame", "clickjacking"], ["cookie", "session", "auth", "login"]],
            "compound_title": "Clickjacking to Credential Harvesting",
            "compound_severity": "medium",
            "compound_description": (
                "Missing X-Frame-Options / CSP frame-ancestors combined with active sessions "
                "enables clickjacking attacks to trick users into performing authenticated actions."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "L", "i": "H", "a": "N"},
        },
        {
            "id": "CORR-021",
            "triggers": [["outdated", "vulnerable dependency", "known cve"],
                         ["rce", "remote code", "sqli", "sql injection", "xss"]],
            "compound_title": "Known Exploitable Vulnerability in Active Attack Path",
            "compound_severity": "critical",
            "compound_description": (
                "Outdated dependency with known CVE combined with an active injection/attack "
                "vector means publicly available exploits may be directly applicable."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-022",
            "triggers": [["docker", "container"], ["privileged", "root", "host network"]],
            "compound_title": "Container Privilege Escalation Risk",
            "compound_severity": "high",
            "compound_description": (
                "Docker containers running in privileged mode or with host networking "
                "create a direct path to host system compromise."
            ),
            "cvss_override": {"av": "N", "ac": "H", "pr": "L", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-023",
            "triggers": [["s3 bucket", "cloud storage", "azure blob"], ["public", "no auth", "open access"]],
            "compound_title": "Cloud Storage Data Breach",
            "compound_severity": "critical",
            "compound_description": (
                "Publicly accessible cloud storage with no authentication allows anyone to "
                "read, download, or potentially modify sensitive data at scale."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-024",
            "triggers": [["subdomain", "wildcard"], ["takeover", "dangling dns", "cname"]],
            "compound_title": "Subdomain Takeover Attack Surface",
            "compound_severity": "high",
            "compound_description": (
                "Discovered subdomains combined with potential dangling DNS/CNAME records "
                "create subdomain takeover opportunities for full domain compromise."
            ),
            "cvss_override": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"},
        },
        {
            "id": "CORR-025",
            "triggers": [["open redirect"], ["phishing", "social engineering", "credential"]],
            "compound_title": "Open Redirect Enabling Phishing Chains",
            "compound_severity": "medium",
            "compound_description": (
                "Open redirect vulnerability enables crafted phishing links on the trusted "
                "domain, increasing likelihood of successful credential theft."
            ),
            "cvss_override": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "L", "i": "H", "a": "N"},
        },
    ]

    @classmethod
    def correlate(cls, findings: List[Dict]) -> List[Dict]:
        """Run all correlation rules against findings and return compound findings.

        Each finding is checked as a lowercase string of title + description.
        A rule fires when ALL trigger groups have at least one pattern matched
        across the full finding set.
        """
        if not findings:
            return []

        # Build a flat list of all finding text for matching
        finding_texts: List[str] = []
        for f in findings:
            title = (f.get("title") or "").lower()
            desc = (f.get("description") or "").lower()
            finding_texts.append(f"{title} {desc}")

        compound_findings: List[Dict] = []

        for rule in cls.CORRELATION_RULES:
            triggers = rule["triggers"]
            rule_fired = True

            for trigger_group in triggers:
                # Each trigger group: at least one pattern must match across all findings
                group_matched = False
                for pattern in trigger_group:
                    for ft in finding_texts:
                        if pattern in ft:
                            group_matched = True
                            break
                    if group_matched:
                        break
                if not group_matched:
                    rule_fired = False
                    break

            if rule_fired:
                compound = {
                    "title": rule["compound_title"],
                    "severity": rule["compound_severity"],
                    "description": rule["compound_description"],
                    "category": "compound",
                    "correlation_id": rule["id"],
                    "is_compound": True,
                }
                # Compute CVSS score for the compound finding
                if "cvss_override" in rule:
                    override = rule["cvss_override"]
                    av = CVSSScorer._AV[override["av"]]
                    ac = CVSSScorer._AC[override["ac"]]
                    pr = CVSSScorer._PR[override["pr"]]
                    ui = CVSSScorer._UI[override["ui"]]
                    c_val = CVSSScorer._CIA[override["c"]]
                    i_val = CVSSScorer._CIA[override["i"]]
                    a_val = CVSSScorer._CIA[override["a"]]
                    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
                    impact = 6.42 * iss
                    exploitability = 8.22 * av * ac * pr * ui
                    base_score = math.ceil(min(impact + exploitability, 10.0) * 10) / 10
                    compound["cvss_score"] = base_score
                    compound["cvss_vector"] = (
                        f"CVSS:3.1/AV:{override['av']}/AC:{override['ac']}/"
                        f"PR:{override['pr']}/UI:{override['ui']}/"
                        f"C:{override['c']}/I:{override['i']}/A:{override['a']}"
                    )

                compound_findings.append(compound)

        return compound_findings


# ══════════════════════════════════════════════════════════════════════
#  ATTACK SURFACE MAPPER
# ══════════════════════════════════════════════════════════════════════


class AttackSurfaceMapper:
    """Computes an attack surface score (0–100, higher = more exposed).

    Factors:
      1. Open ports (0–25 pts): 0 ports=0, 1–2=5, 3–5=10, 6–10=15, 11+=25
      2. Exposed paths/endpoints (0–20 pts): 0=0, 1–3=5, 4–7=10, 8–12=15, 13+=20
      3. Missing security headers (0–20 pts): 0=0, 1=3, 2=6, 3=10, 4=14, 5+=20
      4. Tech stack complexity (0–15 pts): 1–2 techs=2, 3–4=5, 5–6=8, 7–8=11, 9+=15
      5. TLS grade (0–20 pts): A=0, B=5, C=10, D=15, F=20
    """

    @classmethod
    def compute(cls, findings: List[Dict], scan_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Compute attack surface score and return breakdown."""
        findings_lower = []
        for f in findings:
            title = (f.get("title") or "").lower()
            desc = (f.get("description") or "").lower()
            findings_lower.append(f"{title} {desc}")
        all_text = " ".join(findings_lower)

        # 1. Open ports
        port_score = cls._score_ports(findings_lower, scan_data)
        # 2. Exposed paths
        path_score = cls._score_exposed_paths(findings_lower)
        # 3. Missing headers
        header_score = cls._score_missing_headers(findings_lower)
        # 4. Tech stack complexity
        tech_score = cls._score_tech_stack(all_text, scan_data)
        # 5. TLS grade
        tls_score = cls._score_tls_grade(findings_lower, scan_data)

        total = min(port_score + path_score + header_score + tech_score + tls_score, 100)

        # Risk rating
        if total >= 80:
            rating = "CRITICAL"
        elif total >= 60:
            rating = "HIGH"
        elif total >= 40:
            rating = "MODERATE"
        elif total >= 20:
            rating = "LOW"
        else:
            rating = "MINIMAL"

        return {
            "attack_surface_score": total,
            "risk_rating": rating,
            "breakdown": {
                "open_ports": {"score": port_score, "max": 25},
                "exposed_paths": {"score": path_score, "max": 20},
                "missing_headers": {"score": header_score, "max": 20},
                "tech_complexity": {"score": tech_score, "max": 15},
                "tls_grade": {"score": tls_score, "max": 20},
            },
        }

    @classmethod
    def _score_ports(cls, findings_lower: List[str], scan_data: Optional[Dict]) -> int:
        port_count = 0
        for ft in findings_lower:
            # Count port-related findings
            if "open port" in ft or "port " in ft:
                port_count += 1
        # Also check scan data for port info
        if scan_data and isinstance(scan_data, dict):
            for f in scan_data.get("findings", []):
                title = (f.get("title") or "").lower()
                if "port" in title:
                    port_count += 1
        if port_count == 0:
            return 0
        elif port_count <= 2:
            return 5
        elif port_count <= 5:
            return 10
        elif port_count <= 10:
            return 15
        else:
            return 25

    @classmethod
    def _score_exposed_paths(cls, findings_lower: List[str]) -> int:
        path_indicators = [
            "admin", "dashboard", "wp-admin", "phpmyadmin", "api",
            ".env", ".git", "backup", "config", "debug", "console",
            "actuator", "graphql", "swagger", "documentation",
        ]
        exposed_count = 0
        for ft in findings_lower:
            for indicator in path_indicators:
                if indicator in ft:
                    exposed_count += 1
                    break
        if exposed_count == 0:
            return 0
        elif exposed_count <= 3:
            return 5
        elif exposed_count <= 7:
            return 10
        elif exposed_count <= 12:
            return 15
        else:
            return 20

    @classmethod
    def _score_missing_headers(cls, findings_lower: List[str]) -> int:
        header_indicators = [
            "x-frame", "csp", "content-security", "x-content-type",
            "x-xss", "hsts", "strict-transport", "referrer-policy",
            "permissions-policy", "missing header", "security header",
        ]
        missing_count = 0
        for ft in findings_lower:
            for h in header_indicators:
                if h in ft:
                    missing_count += 1
                    break
        if missing_count == 0:
            return 0
        elif missing_count == 1:
            return 3
        elif missing_count == 2:
            return 6
        elif missing_count == 3:
            return 10
        elif missing_count == 4:
            return 14
        else:
            return 20

    @classmethod
    def _score_tech_stack(cls, all_text: str, scan_data: Optional[Dict]) -> int:
        tech_keywords = [
            "nginx", "apache", "iis", "tomcat", "node", "express", "react",
            "vue", "angular", "django", "flask", "rails", "laravel", "spring",
            "wordpress", "drupal", "joomla", "php", "python", "ruby",
            "java", "go", "rust", "docker", "kubernetes", "redis",
            "mongodb", "mysql", "postgresql", "postgres", "elasticsearch",
            "cloudflare", "aws", "azure", "gcp", "firebase",
        ]
        detected = set()
        for tech in tech_keywords:
            if tech in all_text:
                detected.add(tech)
        count = len(detected)
        if count <= 2:
            return 2
        elif count <= 4:
            return 5
        elif count <= 6:
            return 8
        elif count <= 8:
            return 11
        else:
            return 15

    @classmethod
    def _score_tls_grade(cls, findings_lower: List[str], scan_data: Optional[Dict]) -> int:
        # Check for TLS-related findings
        tls_issues = 0
        for ft in findings_lower:
            if any(kw in ft for kw in ["tls", "ssl", "certificate", "cipher", "hsts",
                                         "https", "mixed content"]):
                tls_issues += 1
        # If scan data has explicit grade info
        if scan_data and isinstance(scan_data, dict):
            grade = scan_data.get("grade", "") or scan_data.get("tls_grade", "")
            if isinstance(grade, str):
                grade = grade.upper().strip()
                if grade.startswith("A"):
                    return 0
                elif grade.startswith("B"):
                    return 5
                elif grade.startswith("C"):
                    return 10
                elif grade.startswith("D"):
                    return 15
                elif grade.startswith("F"):
                    return 20
        # Derive from findings count
        if tls_issues == 0:
            return 0
        elif tls_issues <= 1:
            return 5
        elif tls_issues <= 2:
            return 10
        elif tls_issues <= 3:
            return 15
        else:
            return 20


# ══════════════════════════════════════════════════════════════════════
#  RISK MATRIX VISUALIZATION
# ══════════════════════════════════════════════════════════════════════


class RiskMatrixVisualizer:
    """Generates a text-based risk matrix (Likelihood vs Impact) using
    Unicode box-drawing characters.

    Matrix layout (5x5):

        Impact →
        Negligible  Low    Medium   High    Critical
    L   ┌─────────┬───────┬─────────┬────────┬──────────┐
    i   │         │       │         │        │          │
    k   │         │       │         │        │          │
    e   ├─────────┼───────┼─────────┼────────┼──────────┤
    l   │         │       │         │        │          │
    i   │         │       │         │        │          │
    h   ├─────────┼───────┼─────────┼────────┼──────────┤
    o   │         │       │    ●    │   ●    │    ●     │
    o   │         │       │         │        │          │
    d   ├─────────┼───────┼─────────┼────────┼──────────┤
        │         │       │         │  ●     │    ●     │
    ↑   │         │       │         │        │          │
        ├─────────┼───────┼─────────┼────────┼──────────┤
        │         │       │         │        │          │
        │         │       │         │        │          │
        └─────────┴───────┴─────────┴────────┴──────────┘
    """

    # Likelihood and Impact bands from CVSS scores
    _LIKELIHOOD_BANDS = [
        ("Very High", 9.0, 10.1),
        ("High", 7.0, 9.0),
        ("Medium", 4.0, 7.0),
        ("Low", 1.0, 4.0),
        ("Very Low", 0.0, 1.0),
    ]

    _IMPACT_BANDS = [
        ("Critical", 9.0, 10.1),
        ("High", 7.0, 9.0),
        ("Medium", 4.0, 7.0),
        ("Low", 1.0, 4.0),
        ("Negligible", 0.0, 1.0),
    ]

    # Color coding for cell density
    _DENSITY_SYMBOLS = ["  ", " ·", " •", " ●", " ██"]

    @classmethod
    def render(cls, findings: List[Dict], width: int = 70) -> str:
        """Render the risk matrix as a text string with Unicode box-drawing.

        Args:
            findings: List of finding dicts with 'cvss_score' (or 'base_score') keys.
            width: Total width of the matrix output.

        Returns:
            Multi-line string with the matrix.
        """
        # Build a 5x5 grid of finding counts
        # Grid[y][x] where y=0 is top (Very High likelihood), x=0 is left (Negligible impact)
        grid: List[List[int]] = [[0] * 5 for _ in range(5)]
        grid_labels: List[List[List[str]]] = [[[] for _ in range(5)] for _ in range(5)]

        for f in findings:
            score = f.get("cvss_score") or f.get("base_score") or 0.0
            if not isinstance(score, (int, float)) or score <= 0:
                continue
            title = (f.get("title") or "")[:12]

            # Determine likelihood (y-axis) and impact (x-axis) from CVSS score
            # For simplicity, we use the CVSS score to derive both:
            # - Impact uses the CIA-derived portion
            # - Likelihood uses the exploitability portion
            # Since we may not have the full breakdown, we approximate:
            impact_idx = cls._score_to_band_index(score)
            likelihood_idx = cls._score_to_likelihood(score, f)

            if 0 <= likelihood_idx < 5 and 0 <= impact_idx < 5:
                grid[likelihood_idx][impact_idx] += 1
                if len(grid_labels[likelihood_idx][impact_idx]) < 3:
                    grid_labels[likelihood_idx][impact_idx].append(title)

        # Build the matrix string
        col_width = 11
        label_width = 12
        lines: List[str] = []

        # Header row
        header = f"{'Likelihood / Impact':<{label_width + 2}}"
        impact_names = [b[0] for b in cls._IMPACT_BANDS]
        for name in impact_names:
            header += f"{name[:col_width]:>{col_width}}"
        lines.append(header)

        # Top border
        lines.append(f"{'':<{label_width + 2}}┌" + "─" * col_width + ("┬" + "─" * col_width) * 4 + "┐")

        likelihood_names = [b[0] for b in cls._LIKELIHOOD_BANDS]
        for y in range(5):
            # Cell content lines (2 lines per row for readability)
            label = likelihood_names[y]
            # Line 1: density symbol
            row1 = f"{label:>{label_width}}  │"
            row2 = f"{'':>{label_width}}  │"
            for x in range(5):
                count = grid[y][x]
                sym = cls._DENSITY_SYMBOLS[min(count, 4)]
                row1 += f"{sym:^{col_width}}│"
                labels = grid_labels[y][x]
                if labels:
                    row2 += f"{labels[0][:col_width]:^{col_width}}│"
                else:
                    row2 += f"{'':^{col_width}}│"

            lines.append(row1)
            lines.append(row2)

            # Separator or bottom border
            if y < 4:
                lines.append(f"{'':<{label_width + 2}}├" + "─" * col_width + ("┼" + "─" * col_width) * 4 + "┤")
            else:
                lines.append(f"{'':<{label_width + 2}}└" + "─" * col_width + ("┴" + "─" * col_width) * 4 + "┘")

        # Summary line
        total = sum(grid[y][x] for y in range(5) for x in range(5))
        critical_zone = sum(grid[y][x] for y in range(2) for x in range(3, 5))
        lines.append("")
        lines.append(f"  Total findings plotted: {total}")
        lines.append(f"  Critical zone (High/Very High × High/Critical): {critical_zone}")

        return "\n".join(lines)

    @classmethod
    def _score_to_band_index(cls, score: float) -> int:
        """Map score to impact band index (0=Negligible, 4=Critical)."""
        for i, (name, lo, hi) in enumerate(cls._IMPACT_BANDS):
            if lo <= score < hi:
                return 4 - i  # Reverse so Critical is rightmost
        return 0

    @classmethod
    def _score_to_likelihood(cls, score: float, finding: Dict) -> int:
        """Estimate likelihood from score and finding metadata.

        Higher CVSS exploitability metrics → higher likelihood.
        We approximate from score and severity.
        """
        severity = (finding.get("severity") or "").lower()
        is_compound = finding.get("is_compound", False)
        is_remote = True  # Most findings in recon are network-based

        # Base likelihood from score
        base = score / 10.0

        # Boost for compound findings (more likely to be exploitable)
        if is_compound:
            base = min(base + 0.15, 1.0)

        # Adjust for severity
        sev_boost = {"critical": 0.1, "high": 0.05, "medium": 0, "low": -0.1, "info": -0.2}
        base += sev_boost.get(severity, 0)
        base = max(0.0, min(base, 1.0))

        # Map to band index (0=Very Low, 4=Very High)
        if base >= 0.85:
            return 0
        elif base >= 0.65:
            return 1
        elif base >= 0.40:
            return 2
        elif base >= 0.15:
            return 3
        else:
            return 4


# ══════════════════════════════════════════════════════════════════════
#  POST-SCAN ADAPTIVE DEEPENING
# ══════════════════════════════════════════════════════════════════════


class AdaptiveDeepeningEngine:
    """Suggests deeper follow-up scans based on initial findings.

    Maps finding categories to recommended deep-dive modules/tools.
    Each rule has:
      - trigger_patterns: list of patterns to match in findings
      - suggested_tool: tool name to suggest
      - suggested_args: arguments for the suggested tool
      - reason: human-readable explanation
      - severity_threshold: minimum severity to trigger (default: medium)
    """

    DEEPENING_RULES: List[Dict[str, Any]] = [
        {
            "trigger_patterns": ["open port", "port scan", "service"],
            "suggested_tool": "port_scan",
            "suggested_args": {},
            "reason": "Open ports detected — run deeper port scan for service fingerprinting",
            "severity_threshold": "medium",
        },
        {
            "trigger_patterns": [".env", "env file", "environment variable", "secret"],
            "suggested_tool": "secret_hunt",
            "suggested_args": {"path": "."},
            "reason": "Potential secret exposure detected — run deep secrets scan",
            "severity_threshold": "medium",
        },
        {
            "trigger_patterns": ["missing header", "x-frame", "csp", "hsts", "security header",
                                  "content-security", "referrer-policy"],
            "suggested_tool": "remote_scan",
            "suggested_args": {"modules": "recon"},
            "reason": "Missing security headers detected — run deep header analysis with recon module",
            "severity_threshold": "low",
        },
        {
            "trigger_patterns": ["admin panel", "dashboard", "wp-admin", "login", "auth"],
            "suggested_tool": "remote_scan",
            "suggested_args": {"modules": "auth"},
            "reason": "Authentication surfaces detected — run deep auth testing module",
            "severity_threshold": "medium",
        },
        {
            "trigger_patterns": ["sqli", "xss", "injection", "rce", "command injection"],
            "suggested_tool": "remote_scan",
            "suggested_args": {"modules": "gorgon"},
            "reason": "Injection vulnerabilities detected — run deep Gorgon active scan",
            "severity_threshold": "high",
        },
        {
            "trigger_patterns": ["ssrf", "redirect", "open redirect", "chain"],
            "suggested_tool": "remote_scan",
            "suggested_args": {"modules": "chain"},
            "reason": "SSRF/redirect vectors detected — run deep chain analysis",
            "severity_threshold": "high",
        },
        {
            "trigger_patterns": ["outdated", "dependency", "package", "npm", "pip", "vulnerability"],
            "suggested_tool": "cve_enrich",
            "suggested_args": {"findings_json": "__AUTO__"},  # Will be populated dynamically
            "reason": "Vulnerable dependencies detected — enrich with CVE intelligence",
            "severity_threshold": "medium",
        },
        {
            "trigger_patterns": ["eval", "exec", "sql", "injection", "hardcoded", "deserialization",
                                  "path traversal", "ast"],
            "suggested_tool": "ast_analyze",
            "suggested_args": {"path": "."},
            "reason": "Code-level vulnerabilities detected — run deep AST analysis",
            "severity_threshold": "medium",
        },
        {
            "trigger_patterns": ["cloud", "aws", "azure", "gcp", "s3", "iam", "oauth"],
            "suggested_tool": "remote_scan",
            "suggested_args": {"modules": "nhi"},
            "reason": "Cloud/identity surfaces detected — run deep cloud recon module",
            "severity_threshold": "medium",
        },
        {
            "trigger_patterns": ["tls", "ssl", "certificate", "cipher", "mixed content"],
            "suggested_tool": "remote_scan",
            "suggested_args": {"modules": "recon"},
            "reason": "TLS issues detected — run deep TLS/certificate analysis",
            "severity_threshold": "medium",
        },
        {
            "trigger_patterns": ["docker", "container", "kubernetes", "privileged"],
            "suggested_tool": "local_audit",
            "suggested_args": {"target_path": "."},
            "reason": "Container/infrastructure issues detected — run deep infrastructure audit",
            "severity_threshold": "high",
        },
        {
            "trigger_patterns": ["subdomain", "attack surface", "fingerprint"],
            "suggested_tool": "subdomain_discover",
            "suggested_args": {"domain": "__AUTO__"},  # Will be populated dynamically
            "reason": "Attack surface expansion opportunity — run subdomain enumeration",
            "severity_threshold": "medium",
        },
        {
            "trigger_patterns": ["bot", "crawler", "c2", "automation"],
            "suggested_tool": "remote_scan",
            "suggested_args": {"modules": "bot"},
            "reason": "Bot/automation indicators detected — run deep bot analysis module",
            "severity_threshold": "high",
        },
        {
            "trigger_patterns": ["info leak", "version disclose", "debug", "stack trace", "error"],
            "suggested_tool": "remote_scan",
            "suggested_args": {"modules": "oblivion"},
            "reason": "Information disclosure detected — run deep Oblivion stealth scan",
            "severity_threshold": "medium",
        },
    ]

    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    @classmethod
    def suggest(
        cls,
        findings: List[Dict],
        domain: str = "",
        already_planned: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Analyze findings and suggest deepening steps.

        Returns a list of suggestion dicts: {tool, args, reason, trigger_findings}.
        """
        already_planned = already_planned or []
        suggestions: List[Dict[str, Any]] = []

        for rule in cls.DEEPENING_RULES:
            threshold = cls._SEVERITY_ORDER.get(rule["severity_threshold"], 2)
            tool = rule["suggested_tool"]

            # Skip if already planned
            if tool in already_planned:
                continue

            # Check if any finding matches the trigger patterns
            matching_findings: List[str] = []
            for f in findings:
                f_sev = cls._SEVERITY_ORDER.get((f.get("severity") or "").lower(), 99)
                if f_sev > threshold:
                    continue
                f_text = f"{(f.get('title') or '').lower()} {(f.get('description') or '').lower()}"
                for pattern in rule["trigger_patterns"]:
                    if pattern in f_text:
                        matching_findings.append(f.get("title", ""))
                        break

            if matching_findings:
                args = dict(rule["suggested_args"])
                # Populate dynamic args
                if args.get("findings_json") == "__AUTO__":
                    try:
                        args["findings_json"] = json.dumps(findings[:20])
                    except (TypeError, ValueError):
                        args["findings_json"] = "[]"
                if args.get("domain") == "__AUTO__" and domain:
                    args["domain"] = domain

                suggestions.append({
                    "tool": tool,
                    "args": args,
                    "reason": rule["reason"],
                    "trigger_findings": matching_findings[:5],
                    "trigger_count": len(matching_findings),
                })

        return suggestions


# ══════════════════════════════════════════════════════════════════════
#  RULE-BASED PLANNING ENGINE  (ENHANCED)
# ══════════════════════════════════════════════════════════════════════


class RuleBasedPlanner:
    """Smart rule-based planner that classifies intent, generates plans,
    and adapts based on results — no LLM required.

    The planner uses a weighted intent scoring system that considers:
      - Direct keyword matches with configurable weights
      - Modifier words that boost or reduce intent scores
      - Target type classification (domain, IP, local, codebase)
      - Proximity of intent words to target words
      - Prior context from persistent memory
      - 30+ intent categories for granular classification
      - Finding correlation engine for compound risk detection
      - CVSS-inspired risk scoring for every finding
      - Attack surface mapping with 0-100 score
      - Post-scan adaptive deepening suggestions
      - Risk matrix visualization
    """

    # ── Intent keyword weights: expanded to 30+ patterns ─────────────
    _INTENT_KEYWORDS: Dict[str, List[Tuple[str, float]]] = {
        # 1. Full scan
        "full_scan": [
            ("scan", 0.4), ("audit", 0.3), ("assess", 0.3), ("pentest", 0.5),
            ("security", 0.2), ("vuln", 0.4), ("test", 0.2), ("evaluate", 0.3),
            ("examine", 0.2), ("inspect", 0.2),
        ],
        # 2. Subdomain recon
        "subdomain_recon": [
            ("subdomain", 0.8), ("sub-domain", 0.8), ("attack surface", 0.6),
            ("enumerate", 0.5), ("discover", 0.3), ("surface map", 0.7),
            ("asset discovery", 0.7), ("footprint", 0.6), ("scope", 0.3),
        ],
        # 3. Local audit
        "local_audit": [
            ("machine", 0.6), ("laptop", 0.6), ("computer", 0.5), ("local", 0.6),
            ("my system", 0.7), ("this machine", 0.6), ("localhost", 0.7),
            ("my mac", 0.7), ("my pc", 0.7), ("my server", 0.7),
            ("endpoint", 0.5), ("workstation", 0.6),
        ],
        # 4. Dev security
        "dev_security": [
            ("project", 0.5), ("codebase", 0.5), ("repo", 0.4), ("source code", 0.5),
            ("dependencies", 0.4), ("package", 0.3), ("code", 0.3),
            ("application", 0.3), ("app", 0.2),
        ],
        # 5. Secret hunting
        "secret_hunting": [
            ("secrets", 0.7), ("secret", 0.7), ("credential", 0.7), ("api key", 0.6),
            ("token", 0.5), ("password", 0.5), ("leak", 0.5), ("exposed", 0.3),
            ("private key", 0.7), ("sensitive data", 0.6), ("hidden", 0.3),
        ],
        # 6. Compliance
        "compliance": [
            ("compliance", 0.7), ("health", 0.5), ("doctor", 0.5), ("diagnos", 0.5),
            ("checkup", 0.5), ("hardening", 0.5), ("cis", 0.6), ("policy", 0.4),
            ("regulation", 0.6), ("gdpr", 0.6), ("hipaa", 0.6), ("pci", 0.6),
            ("soc2", 0.6), ("iso27001", 0.5), ("standard", 0.3),
        ],
        # 7. Attack simulation
        "attack_simulation": [
            ("attack", 0.6), ("exploit", 0.6), ("hack", 0.5), ("swarm", 0.7),
            ("adversarial", 0.7), ("red team", 0.6), ("offensive", 0.5),
            ("breach", 0.5), ("compromise", 0.4), ("penetration", 0.6),
        ],
        # 8. Code analysis
        "code_analysis": [
            (" ast ", 0.7), ("static analysis", 0.5), ("code review", 0.5), ("sast", 0.7),
            ("analyze code", 0.6), ("code quality", 0.4), ("static code", 0.5),
            ("code audit", 0.6), ("source review", 0.5),
        ],
        # 9. Threat intel
        "threat_intel": [
            ("cve", 0.7), ("threat", 0.6), ("intel", 0.6), ("enrich", 0.5),
            ("knowledge graph", 0.7), ("graph", 0.4), ("chain", 0.3),
            ("threat intelligence", 0.8), ("vulnerability database", 0.6),
            ("nvd", 0.7), ("bulletin", 0.5),
        ],
        # 10. Reporting
        "reporting": [
            ("report", 0.7), ("html", 0.4), ("sarif", 0.6), ("pdf", 0.4),
            ("markdown", 0.4), ("export", 0.5), ("document", 0.4), ("generate report", 0.7),
            ("write-up", 0.6), ("writeup", 0.6), ("artifact", 0.4),
        ],
        # 11. Comparison
        "comparison": [
            ("compare", 0.7), ("diff", 0.7), ("vs", 0.5), ("versus", 0.5),
            ("trend", 0.5), ("progress", 0.3), ("regression", 0.6),
            ("before and after", 0.7), ("improvement", 0.4),
        ],
        # 12. Benchmarking
        "benchmarking": [
            ("benchmark", 0.7), ("score", 0.4), ("grade", 0.4), ("rating", 0.5),
            ("vibesec", 0.6), ("quick", 0.2), ("rating", 0.5), ("grade me", 0.6),
        ],
        # 13. TLS/SSL focused (NEW)
        "tls_audit": [
            ("tls", 0.8), ("ssl", 0.7), ("certificate", 0.7), ("https", 0.4),
            ("encryption", 0.5), ("hsts", 0.8), ("cipher", 0.7),
            ("transport", 0.5), ("certificate pinning", 0.7),
        ],
        # 14. Authentication focused (NEW)
        "auth_audit": [
            ("auth", 0.7), ("authentication", 0.8), ("authorization", 0.7),
            ("login", 0.6), ("session", 0.5), ("oauth", 0.7), ("sso", 0.7),
            ("mfa", 0.7), ("2fa", 0.7), ("identity", 0.5), ("iam", 0.6),
        ],
        # 15. API security (NEW)
        "api_security": [
            ("api", 0.7), ("endpoint", 0.5), ("rest", 0.5), ("graphql", 0.7),
            ("openapi", 0.6), ("swagger", 0.5), ("rate limit", 0.6),
            ("api key", 0.6), ("jwt", 0.7), ("token", 0.4),
        ],
        # 16. Infrastructure / DevOps (NEW)
        "infra_security": [
            ("infrastructure", 0.7), ("devops", 0.7), ("ci/cd", 0.7), ("cicd", 0.7),
            ("pipeline", 0.6), ("docker", 0.6), ("kubernetes", 0.7), ("k8s", 0.7),
            ("terraform", 0.7), ("iac", 0.5), ("cloud formation", 0.6),
        ],
        # 17. Cloud security (NEW)
        "cloud_security": [
            ("cloud", 0.7), ("aws", 0.7), ("azure", 0.7), ("gcp", 0.7),
            ("s3", 0.7), ("bucket", 0.5), ("lambda", 0.5), ("serverless", 0.5),
            ("cloud security", 0.8), ("multi-cloud", 0.7),
        ],
        # 18. Network security (NEW)
        "network_security": [
            ("network", 0.6), ("firewall", 0.7), ("waf", 0.7), ("ids", 0.6),
            ("ips", 0.6), ("dns", 0.5), ("dnssec", 0.7), ("port", 0.5),
            ("network scan", 0.8), ("segmentation", 0.6),
        ],
        # 19. Bug bounty / vulnerability hunting (NEW)
        "bug_hunting": [
            ("bug bounty", 0.8), ("bounty", 0.7), ("hunt bugs", 0.8),
            ("find vulnerabilities", 0.8), ("vulnerability assessment", 0.7),
            ("vuln assessment", 0.7), ("pentest", 0.5), ("bug hunt", 0.8),
        ],
        # 20. Remediation / fixing (NEW)
        "remediation": [
            ("fix", 0.7), ("remediat", 0.8), ("patch", 0.6), ("harden", 0.7),
            ("secure", 0.4), ("mitigate", 0.7), ("resolve", 0.5),
            ("auto-fix", 0.8), ("autofix", 0.8),
        ],
        # 21. Monitoring / continuous (NEW)
        "monitoring": [
            ("monitor", 0.7), ("continuous", 0.6), ("schedule", 0.5),
            ("cron", 0.5), ("watch", 0.5), ("alert", 0.6),
            ("surveillance", 0.6), ("observability", 0.5),
        ],
        # 22. Data protection / privacy (NEW)
        "data_protection": [
            ("privacy", 0.7), ("data protection", 0.8), ("pii", 0.7),
            ("personal data", 0.6), ("encryption", 0.5), ("data loss", 0.6),
            ("dlp", 0.7), ("gdpr", 0.5),
        ],
        # 23. Supply chain (NEW)
        "supply_chain": [
            ("supply chain", 0.8), ("dependency", 0.5), ("package", 0.3),
            ("sbom", 0.7), ("software bill", 0.6), ("vendor", 0.5),
            ("third-party", 0.5), ("npm audit", 0.6), ("pip audit", 0.6),
        ],
        # 24. OSINT / reconnaissance (NEW)
        "osint": [
            ("osint", 0.8), ("reconnaissance", 0.7), ("recon", 0.6),
            ("intelligence gathering", 0.7), ("footprinting", 0.7),
            ("passive", 0.5), ("open source intel", 0.8),
        ],
        # 25. Wireless / physical (NEW)
        "wireless_security": [
            ("wifi", 0.8), ("wireless", 0.7), ("bluetooth", 0.7),
            ("wpa", 0.7), ("wep", 0.7), ("physical", 0.5),
        ],
        # 26. Forensics / incident response (NEW)
        "forensics": [
            ("forensic", 0.8), ("incident response", 0.8), ("ir", 0.5),
            ("breach investigation", 0.8), ("post-mortem", 0.6),
            ("incident", 0.5), ("timeline", 0.4),
        ],
        # 27. Configuration review (NEW)
        "config_review": [
            ("config", 0.5), ("configuration", 0.6), ("misconfiguration", 0.7),
            ("setting", 0.3), ("setup", 0.3), ("hardening", 0.5),
        ],
        # 28. Access control (NEW)
        "access_control": [
            ("access control", 0.8), ("rbac", 0.7), ("abac", 0.7),
            ("permission", 0.6), ("privilege", 0.6), ("authorization", 0.5),
            ("role", 0.4), ("acl", 0.7),
        ],
        # 29. Ransomware / malware assessment (NEW)
        "malware_assessment": [
            ("ransomware", 0.8), ("malware", 0.8), ("backdoor", 0.7),
            ("trojan", 0.7), ("rootkit", 0.7), ("crypto", 0.4),
            ("malicious", 0.6), ("payload", 0.6),
        ],
        # 30. Zero-trust assessment (NEW)
        "zero_trust": [
            ("zero trust", 0.8), ("zero-trust", 0.8), ("trust boundary", 0.7),
            ("micro-segmentation", 0.7), ("least privilege", 0.6),
            ("assume breach", 0.6), ("verify trust", 0.7),
        ],
        # 31. Quick check / fast scan (NEW)
        "quick_check": [
            ("quick", 0.7), ("fast", 0.6), ("brief", 0.5), ("lightweight", 0.6),
            ("surface check", 0.7), ("spot check", 0.7), ("sanity", 0.5),
        ],
        # 32. Deep / thorough scan (NEW)
        "deep_scan": [
            ("deep", 0.7), ("thorough", 0.6), ("exhaustive", 0.7),
            ("comprehensive", 0.6), ("maximum", 0.6), ("full depth", 0.7),
            ("no stone unturned", 0.8), ("everything", 0.5),
        ],
        # 33. History / trend analysis (NEW)
        "history_analysis": [
            ("history", 0.7), ("historical", 0.6), ("past scan", 0.7),
            ("previous", 0.4), ("trend", 0.5), ("over time", 0.6),
            ("baseline", 0.5),
        ],
    }

    # Modifier words that amplify intent
    _AMPLIFIERS = {
        "full": 1.5, "deep": 1.5, "complete": 1.4, "everything": 1.5,
        "all": 1.3, "thorough": 1.4, "comprehensive": 1.4, "maximum": 1.5,
        "aggressive": 1.3, "exhaustive": 1.5, "entire": 1.3, "ultimate": 1.4,
        "nmap-style": 1.3, "military-grade": 1.4, "red-team": 1.3,
    }

    # Modifier words that reduce intent
    _DAMPENERS = {
        "quick": 0.7, "fast": 0.7, "brief": 0.6, "simple": 0.7,
        "just": 0.7, "only": 0.6, "basic": 0.6, "lightweight": 0.6,
        "maybe": 0.5, "possibly": 0.5, "check if": 0.6,
    }

    # Module-specific keywords
    _MODULE_KEYWORDS: Dict[str, List[str]] = {
        "recon": ["recon", "reconnaissance", "probe", "fingerprint"],
        "auth": ["auth", "login", "bypass", "session", "cookie"],
        "chain": ["ssrf", "chain", "redirect", "open redirect"],
        "gorgon": ["sqli", "xss", "injection", "gorgon"],
        "oblivion": ["oblivion", "dread", "deep scan", "ultimate"],
        "bot": ["bot", "crawler", "c2", "automation"],
        "nhi": ["nhi", "cloud", "identity", "oauth"],
        "vibesec": ["vibesec", "vibe", "benchmark", "score"],
    }

    def __init__(self, registry: ToolRegistry, memory: AgentMemory):
        self.registry = registry
        self.memory = memory

    def classify_intent(self, goal: str) -> Dict[str, float]:
        """Score each intent based on the goal text.

        Uses weighted keyword matching, proximity scoring, and modifiers.
        Returns a dict mapping intent names to float scores in [0, 1+].
        Supports 30+ intent categories.
        """
        goal_lower = goal.lower()
        # Pad for whole-word matching
        padded = f' {goal_lower} '
        scores: Dict[str, float] = {}
        words = goal_lower.split()

        # Calculate global modifier
        modifier = 1.0
        for w in words:
            if w in self._AMPLIFIERS:
                modifier = max(modifier, self._AMPLIFIERS[w])
            if w in self._DAMPENERS:
                modifier = min(modifier, self._DAMPENERS[w])

        for intent, keywords in self._INTENT_KEYWORDS.items():
            score = 0.0
            for pattern, weight in keywords:
                # Use whole-word matching to avoid false positives
                # (e.g., "repo" matching inside "report")
                if len(pattern.split()) > 1:
                    # Multi-word pattern: check substring (already specific enough)
                    matched = pattern in goal_lower
                else:
                    # Single-word pattern: check whole word with padding
                    matched = f' {pattern} ' in padded
                if matched:
                    # Boost if near a target-like word
                    proximity_boost = 1.0
                    pattern_idx = goal_lower.find(pattern)
                    for tw in (".com", ".io", ".net", ".org", "http", "localhost"):
                        tw_idx = goal_lower.find(tw)
                        if tw_idx >= 0 and abs(pattern_idx - tw_idx) < 40:
                            proximity_boost = 1.3
                            break
                    score += weight * proximity_boost
            scores[intent] = min(score * modifier, 2.0)

        return scores

    def extract_targets(self, goal: str) -> List[str]:
        """Extract targets (domains, IPs, URLs, paths) from the goal."""
        urls = re.findall(r'https?://[\w\-._~:/?#\[\]@!$&\'()*+,;=%]+', goal)
        domains = re.findall(r'[\w][\w\-]*\.[\w]{2,}(?:\.[\w]{2,})?', goal)
        skip = {
            'the', 'and', 'for', 'with', 'all', 'of', 'to', 'from', 'that', 'this',
            'scan', 'audit', 'check', 'find', 'get', 'show', 'me', 'my',
        }
        targets = list(set(
            urls + [d for d in domains if d.lower() not in skip and len(d) > 4]
        ))
        return targets

    def detect_target_type(self, goal: str, targets: List[str]) -> str:
        """Classify the target type from context."""
        goal_lower = goal.lower()
        local_indicators = [
            'machine', 'laptop', 'computer', 'local', 'my system', 'this machine',
            'localhost', 'my mac', 'my pc', 'my server', 'endpoint', 'workstation',
        ]
        for ind in local_indicators:
            if ind in goal_lower:
                return "local"
        dev_indicators = ['project', 'codebase', 'repo', 'source code', 'code review']
        padded = f' {goal_lower} '
        for ind in dev_indicators:
            if f' {ind} ' in padded and not targets:
                return "codebase"
        if targets:
            for t in targets:
                if t.startswith("http"):
                    return "remote"
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', t):
                    return "remote"
            return "remote"
        return "unknown"

    def detect_modules(self, goal: str) -> Optional[List[str]]:
        """Detect specific module requests from the goal text."""
        goal_lower = goal.lower()
        for mod_name, keywords in self._MODULE_KEYWORDS.items():
            for kw in keywords:
                if kw in goal_lower:
                    return [mod_name]
        return None

    def generate_plan(
        self, goal: str, scores: Dict[str, float],
        targets: List[str], target_type: str,
    ) -> List[Dict[str, Any]]:
        """Generate an ordered execution plan based on classified intents.

        Returns a list of step dicts: {"tool", "args", "reason"}
        Now supports 30+ intent categories with smarter multi-tool chaining.
        """
        plan: List[Dict[str, Any]] = []
        domain = ""
        if targets:
            domain = targets[0].replace("https://", "").replace("http://", "").split("/")[0]

        # Sort intents by score, take significant ones
        sorted_intents = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        significant = [(name, s) for name, s in sorted_intents if s > 0.2]

        # Check prior context for this target
        prior = None
        if domain:
            prior = self.memory.get_target_context(domain)

        # Helper to check if an intent is significant
        def has_intent(name: str, threshold: float = 0.3) -> bool:
            return any(n == name and s > threshold for n, s in significant)

        def max_intent(names: List[str], threshold: float = 0.3) -> float:
            return max((s for n, s in significant if n in names and s > threshold), default=0.0)

        # ── Subdomain recon phase ──
        if has_intent("subdomain_recon") or has_intent("osint"):
            if domain:
                plan.append({
                    "tool": "subdomain_discover",
                    "args": {"domain": domain},
                    "reason": "User requested subdomain reconnaissance",
                })

        # ── Benchmarking ──
        if has_intent("benchmarking"):
            if domain:
                plan.append({
                    "tool": "vibesec_benchmark",
                    "args": {"target": domain},
                    "reason": "User wants a quick security benchmark",
                })

        # ── Local audit ──
        if target_type == "local":
            if has_intent("compliance"):
                plan.append({"tool": "doctor_check", "args": {}, "reason": "Health/compliance check requested"})
            if has_intent("local_audit", 0.2) or has_intent("config_review"):
                plan.append({"tool": "local_audit", "args": {"target_path": "."}, "reason": "Local machine audit requested"})
            if has_intent("network_security") or has_intent("forensics"):
                plan.append({"tool": "port_scan", "args": {}, "reason": "Network security assessment requested"})

        # ── Dev security ──
        if target_type == "codebase" or has_intent("dev_security") or has_intent("supply_chain"):
            plan.append({"tool": "dev_scan", "args": {"path": "."}, "reason": "Developer project scan requested"})

        # ── Secret hunting ──
        if has_intent("secret_hunting") or has_intent("data_protection"):
            plan.append({"tool": "secret_hunt", "args": {"path": "."}, "reason": "Secret hunting requested"})

        # ── Code analysis ──
        if has_intent("code_analysis") or has_intent("access_control"):
            plan.append({"tool": "ast_analyze", "args": {"path": "."}, "reason": "Static code analysis requested"})

        # ── Quick check ──
        if has_intent("quick_check") and not has_intent("deep_scan") and not has_intent("full_scan"):
            if domain:
                plan.append({
                    "tool": "vibesec_benchmark",
                    "args": {"target": domain},
                    "reason": "Quick surface-level security check",
                })
                # Quick check stops after benchmark unless more is needed
                if not plan:
                    pass  # Will fall through to fallback

        # ── Full remote scan ──
        is_full = has_intent("full_scan", 0.2) or has_intent("deep_scan")
        if targets and target_type == "remote":
            modules = self.detect_modules(goal)
            if len(targets) > 1:
                # Multiple targets → blitz (even if full_scan is set)
                plan.append({
                    "tool": "blitz_scan",
                    "args": {"targets_str": ",".join(targets)},
                    "reason": f"Multiple targets detected ({len(targets)}), using parallel blitz scan",
                })
            elif is_full or not plan:
                plan.append({
                    "tool": "remote_scan",
                    "args": {
                        "target": targets[0],
                        "modules": ",".join(modules) if modules else "",
                        "all_modules": is_full and not modules,
                    },
                    "reason": "Full remote security scan" +
                              (" with all modules" if is_full and not modules else ""),
                })

        # ── Check compliance: host + doctor + dev ──
        if has_intent("compliance") and target_type == "local":
            if not any(s["tool"] == "doctor_check" for s in plan):
                plan.insert(0, {"tool": "doctor_check", "args": {}, "reason": "Compliance check — health check first"})
            if not any(s["tool"] == "dev_scan" for s in plan):
                plan.append({"tool": "dev_scan", "args": {"path": "."}, "reason": "Compliance check — developer project audit"})

        # ── Find vulnerabilities: recon + auth + chain ──
        if has_intent("bug_hunting") and domain:
            if not any(s["tool"] == "remote_scan" for s in plan):
                plan.append({
                    "tool": "remote_scan",
                    "args": {"target": domain, "modules": "recon,auth,chain", "all_modules": False},
                    "reason": "Vulnerability hunting — recon + auth + chain modules",
                })

        # ── Hunt bugs: recon + gorgon + oblivion ──
        if has_intent("bug_hunting") and has_intent("deep_scan") and domain:
            if not any(s["tool"] == "remote_scan" for s in plan):
                plan.append({
                    "tool": "remote_scan",
                    "args": {"target": domain, "modules": "recon,gorgon,oblivion", "all_modules": False},
                    "reason": "Deep bug hunting — recon + gorgon + oblivion",
                })

        # ── Assess cloud: cloud_recon + nhi ──
        if has_intent("cloud_security") and domain:
            if not any(s["tool"] == "remote_scan" for s in plan):
                plan.append({
                    "tool": "remote_scan",
                    "args": {"target": domain, "modules": "nhi", "all_modules": False},
                    "reason": "Cloud security assessment — cloud recon + identity module",
                })

        # ── TLS audit ──
        if has_intent("tls_audit") and domain:
            if not any(s["tool"] == "remote_scan" for s in plan):
                plan.append({
                    "tool": "remote_scan",
                    "args": {"target": domain, "modules": "recon", "all_modules": False},
                    "reason": "TLS/SSL focused scan",
                })

        # ── Auth audit ──
        if has_intent("auth_audit") and domain:
            if not any(s["tool"] == "remote_scan" for s in plan):
                plan.append({
                    "tool": "remote_scan",
                    "args": {"target": domain, "modules": "auth", "all_modules": False},
                    "reason": "Authentication security assessment",
                })

        # ── API security ──
        if has_intent("api_security") and domain:
            if not any(s["tool"] == "remote_scan" for s in plan):
                plan.append({
                    "tool": "remote_scan",
                    "args": {"target": domain, "modules": "recon,auth", "all_modules": False},
                    "reason": "API security assessment — recon + auth",
                })

        # ── History / trend analysis ──
        if has_intent("history_analysis") or has_intent("comparison"):
            if has_intent("comparison"):
                plan.append({"tool": "diff_scans", "args": {}, "reason": "Scan comparison/trend analysis requested"})
            else:
                plan.append({"tool": "scan_history", "args": {}, "reason": "Historical scan analysis requested"})

        # ── Attack simulation ──
        if has_intent("attack_simulation") or has_intent("malware_assessment"):
            if domain:
                plan.append({
                    "tool": "adversarial_loop",
                    "args": {"target": domain, "rounds": 2},
                    "reason": "Attack simulation / adversarial remediation requested",
                })
            elif target_type == "local":
                plan.append({
                    "tool": "adversarial_loop",
                    "args": {"target": "localhost", "rounds": 2},
                    "reason": "Local adversarial remediation loop",
                })

        # ── Remediation focus ──
        if has_intent("remediation"):
            if domain:
                plan.append({
                    "tool": "adversarial_loop",
                    "args": {"target": domain, "rounds": 3},
                    "reason": "Remediation-focused adversarial loop with extra rounds",
                })
            elif target_type == "local":
                plan.append({
                    "tool": "adversarial_loop",
                    "args": {"target": "localhost", "rounds": 3},
                    "reason": "Local remediation adversarial loop",
                })

        # ── Swarm ──
        has_swarm_word = "swarm" in goal.lower()
        if has_swarm_word and has_intent("attack_simulation"):
            if domain:
                # Replace adversarial_loop with swarm if swarm is explicitly requested
                plan = [s for s in plan if s["tool"] != "adversarial_loop"]
                plan.append({
                    "tool": "swarm_run",
                    "args": {"target": domain, "mode": "full"},
                    "reason": "Full swarm attack requested",
                })

        # ── Threat intel / CVE enrichment / Knowledge graph ──
        if has_intent("threat_intel"):
            if domain and ("graph" in goal.lower() or "chain" in goal.lower()):
                plan.append({
                    "tool": "knowledge_graph",
                    "args": {"action": "build", "target": domain},
                    "reason": "Knowledge graph analysis requested",
                })
            elif domain:
                # For threat intel, do a scan first then enrich
                if not any(s["tool"] in ("remote_scan", "local_audit") for s in plan):
                    plan.insert(0, {
                        "tool": "remote_scan",
                        "args": {"target": domain},
                        "reason": "Threat intel — running initial scan first",
                    })

        # ── Reporting ──
        wants_report = has_intent("reporting")
        has_scan_step = any(
            s["tool"] in ("remote_scan", "local_audit", "blitz_scan", "dev_scan",
                           "vibesec_benchmark", "adversarial_loop", "swarm_run")
            for s in plan
        )
        if wants_report:
            fmt = "sarif" if "sarif" in goal.lower() else "html"
            if has_scan_step:
                plan.append({
                    "tool": "generate_report",
                    "args": {"format": fmt},
                    "reason": f"Report generation requested ({fmt})",
                })
            else:
                # No scan was run — just generate from latest history
                plan.append({
                    "tool": "generate_report",
                    "args": {"format": fmt},
                    "reason": f"Generating {fmt} report from latest scan history",
                })

        # ── Fallback: if no plan was generated ──
        if not plan:
            if targets:
                plan.append({
                    "tool": "remote_scan",
                    "args": {"target": targets[0]},
                    "reason": "Default: scanning the detected target",
                })
            elif target_type == "local":
                plan.append({"tool": "local_audit", "args": {}, "reason": "Default: auditing local machine"})
            elif target_type == "codebase":
                plan.append({"tool": "dev_scan", "args": {}, "reason": "Default: scanning developer project"})
            else:
                plan.append({"tool": "scan_history", "args": {}, "reason": "No clear target — showing scan history"})

        return plan

    def adapt_plan(
        self,
        plan: List[Dict[str, Any]],
        completed_results: List[Tuple[Dict, ToolResult]],
        current_idx: int,
    ) -> List[Dict[str, Any]]:
        """Adapt the remaining plan based on results seen so far.

        This is the 'intelligence' of the rule engine — it inspects intermediate
        results and inserts new steps or modifies remaining ones.
        Enhanced with: adaptive deepening, correlation-aware suggestions,
        and smarter conditional logic.
        """
        additions: List[Dict[str, Any]] = []
        domain = ""
        last_score = None
        has_critical = False
        total_findings = 0
        all_findings: List[Dict] = []
        subdomains_found = False
        scan_data: Optional[Dict] = None

        for step, result in completed_results:
            d = result.data
            if isinstance(d, dict):
                # Extract score from scan results
                if "total_score" in d:
                    last_score = d["total_score"]
                if "vibesec_score" in d:
                    last_score = d["vibesec_score"]
                # Collect findings
                findings = d.get("findings", [])
                if isinstance(findings, list):
                    all_findings.extend(findings)
                    total_findings += len(findings)
                    for f in findings:
                        if isinstance(f, dict) and f.get("severity") in ("critical", "high"):
                            has_critical = True
                # Check for subdomains
                if "subdomains" in d and len(d["subdomains"]) > 3:
                    subdomains_found = True
                # Get target from data
                if not domain:
                    domain = d.get("target", "")
                # Keep scan data reference for deepening
                if step.get("tool") in ("remote_scan", "vibesec_benchmark", "local_audit"):
                    scan_data = d

        # Extract domain from the current step if not yet known
        if not domain and current_idx < len(plan):
            step = plan[current_idx]
            for k, v in step.get("args", {}).items():
                if k in ("target", "domain") and v:
                    domain = v.replace("https://", "").replace("http://", "").split("/")[0]
                    break

        already_planned_tools = [s["tool"] for s in plan]

        # If any findings found → add CVE enrichment (if not already planned)
        has_any_findings = total_findings > 0
        if has_any_findings and not any(s["tool"] == "cve_enrich" for s in plan[current_idx:]):
            if all_findings:
                try:
                    findings_json = json.dumps(all_findings[:20])
                except (TypeError, ValueError):
                    findings_json = "[]"
                reason = "Enriching findings with CVE data from NVD"
                if has_critical:
                    reason = "Critical/high findings detected — enriching with CVE data"
                additions.append({
                    "tool": "cve_enrich",
                    "args": {"findings_json": findings_json},
                    "reason": reason,
                })

        # If many subdomains found and not already doing blitz → suggest knowledge graph
        if subdomains_found and not any(s["tool"] == "blitz_scan" for s in plan[current_idx:]):
            if domain and not any(s["tool"] == "knowledge_graph" for s in plan[current_idx:]):
                additions.append({
                    "tool": "knowledge_graph",
                    "args": {"action": "build", "target": domain},
                    "reason": "Large attack surface detected — building knowledge graph",
                })

        # If score is very low → add knowledge graph
        if last_score is not None and last_score < 40:
            if domain and not any(s["tool"] == "knowledge_graph" for s in plan[current_idx:]):
                additions.append({
                    "tool": "knowledge_graph",
                    "args": {"action": "build", "target": domain},
                    "reason": f"Critical score ({last_score}/100) — analyzing attack surface via knowledge graph",
                })

        # If score is low and no adversarial loop → add one
        if last_score is not None and last_score < 50:
            if domain and not any(s["tool"] in ("adversarial_loop", "swarm_run") for s in plan + additions):
                additions.append({
                    "tool": "adversarial_loop",
                    "args": {"target": domain, "rounds": 2},
                    "reason": f"Low score ({last_score}/100) — running adversarial loop for remediation guidance",
                })

        # ── Adaptive Deepening: suggest deeper scans based on findings ──
        if all_findings:
            deep_suggestions = AdaptiveDeepeningEngine.suggest(
                all_findings, domain=domain, already_planned=already_planned_tools,
            )
            for sug in deep_suggestions[:3]:  # Cap at 3 adaptive suggestions
                if not any(s["tool"] == sug["tool"] for s in plan[current_idx:] + additions):
                    additions.append({
                        "tool": sug["tool"],
                        "args": sug["args"],
                        "reason": sug["reason"],
                    })

        # Insert additions after current step
        remaining = plan[current_idx + 1:]
        plan = plan[:current_idx + 1] + additions + remaining

        return plan

    # ── Post-scan analysis methods ──

    def run_post_scan_analysis(
        self, all_findings: List[Dict], scan_data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Run all post-scan intelligence: CVSS scoring, correlation, attack surface, risk matrix.

        Returns a dict with: scored_findings, compound_findings, attack_surface, risk_matrix.
        """
        result: Dict[str, Any] = {}

        # 1. CVSS Score all findings
        if all_findings:
            scored = CVSSScorer.score_findings(all_findings)
            result["scored_findings"] = scored

            # 2. Finding Correlation
            compound = FindingCorrelationEngine.correlate(scored)
            result["compound_findings"] = compound
            if compound:
                # Merge compound into scored for full picture
                result["all_enriched_findings"] = scored + compound
            else:
                result["all_enriched_findings"] = scored

            # 3. Attack Surface Mapping
            surface = AttackSurfaceMapper.compute(all_findings, scan_data)
            result["attack_surface"] = surface

            # 4. Risk Matrix
            matrix_findings = result["all_enriched_findings"]
            matrix_text = RiskMatrixVisualizer.render(matrix_findings)
            result["risk_matrix"] = matrix_text
        else:
            result["scored_findings"] = []
            result["compound_findings"] = []
            result["all_enriched_findings"] = []
            result["attack_surface"] = {"attack_surface_score": 0, "risk_rating": "MINIMAL", "breakdown": {}}
            result["risk_matrix"] = ""

        return result


# ══════════════════════════════════════════════════════════════════════
#  SYSTEM PROMPT FOR LLM
# ══════════════════════════════════════════════════════════════════════


def _build_system_prompt(tool_descriptions: str, context_summary: str) -> str:
    return f"""You are RECONPRO NEXUS, an elite autonomous security AI agent. You are a senior
security consultant with 20 years of experience in offensive security, penetration
testing, and threat intelligence.

## YOUR MISSION
Analyze the user's natural language goal, then execute a sequence of security tools
to accomplish it. Think step-by-step: ANALYZE → PLAN → EXECUTE → VERIFY.

## YOUR TOOLS ({len(tool_descriptions.splitlines())} available)
{tool_descriptions}

## THINKING PROTOCOL
1. **ANALYZE**: Identify the target type (domain, IP, local, codebase), the user's
   true intent (recon, vulnerability assessment, compliance, remediation), and any
   modifiers (depth, speed, format).
2. **PLAN**: Build an ordered plan. Chain tools intelligently:
   - For full recon: subdomain_discover → remote_scan → cve_enrich → knowledge_graph → generate_report
   - For local audit: doctor_check → local_audit → secret_hunt → ast_analyze
   - For attack simulation: remote_scan → adversarial_loop or swarm_run
   - For threat intel: remote_scan → cve_enrich → knowledge_graph
3. **EXECUTE**: Call tools one at a time. Wait for results before deciding next steps.
4. **VERIFY**: After each tool result, check:
   - Did it succeed? If not, try an alternative approach.
   - Are there critical/high findings? If yes, enrich with CVEs.
   - Is the score very low (< 40)? If yes, add knowledge graph analysis.
   - Were many subdomains found? If yes, consider a follow-up scan.
5. **ADAPT**: Modify your plan based on intermediate results. Add enrichment steps
   when significant findings are discovered.

## RULES
- Max 10 tool calls unless the user explicitly requests more.
- Prioritize critical and high severity findings.
- Always generate a report (generate_report) as the final step when a scan was run.
- Use shell_command ONLY as a last resort when no other tool can accomplish the task.
- Explain your reasoning before each tool call.
- If a tool fails, try an alternative or explain why you can't proceed.

## PREVIOUS CONTEXT
{context_summary}

## OUTPUT FORMAT
After completing all steps, provide a clear summary of:
- What was analyzed
- What tools were used and what they found
- Key findings (severity + title)
- Recommendations
- Any generated reports or artifacts
"""


# ══════════════════════════════════════════════════════════════════════
#  NEXUS AGENT
# ══════════════════════════════════════════════════════════════════════


class NexusAgent:
    """The Nexus Agent — LLM-powered or rule-based agentic security engine.

    Executes a THINK → PLAN → EXECUTE → VERIFY → ADAPT loop, using either
    an LLM (OpenAI/Anthropic) or a smart rule-based planner as fallback.
    Enhanced with finding correlation, CVSS scoring, attack surface mapping,
    adaptive deepening, and risk matrix visualization.
    """

    def __init__(
        self,
        on_message: Optional[Callable] = None,
        on_finding: Optional[Callable] = None,
        on_status: Optional[Callable] = None,
        verbose: bool = True,
    ):
        self.registry = build_registry()
        self.memory = AgentMemory()
        self.planner = RuleBasedPlanner(self.registry, self.memory)
        self.verbose = verbose
        self.on_message = on_message or (lambda msg, style="": None)
        self.on_finding = on_finding or (lambda f: None)
        self.on_status = on_status or (lambda s: None)
        self._findings: List[Dict] = []
        self._steps: List[str] = []
        self._targets: List[str] = []
        self._tool_results: List[Dict] = []

    def _emit(self, msg: str, style: str = "") -> None:
        self.on_message(msg, style)

    def _emit_status(self, status: str) -> None:
        self.on_status(status)

    def _emit_finding(self, finding: Dict) -> None:
        self.on_finding(finding)
        self._findings.append(finding)

    def _detect_backend(self) -> str:
        """Detect which LLM backend is available."""
        if os.environ.get("OPENAI_API_KEY") and HAS_OPENAI:
            return "openai"
        if os.environ.get("ANTHROPIC_API_KEY") and HAS_ANTHROPIC:
            return "anthropic"
        return "rules"

    def execute(self, goal: str) -> Dict[str, Any]:
        """Main entry point. Execute the agent on a natural language goal."""
        backend = self._detect_backend()

        # Reset state
        self._findings = []
        self._steps = []
        self._targets = []
        self._tool_results = []

        if backend == "openai":
            self._emit("[bold cyan]NEXUS[/] | LLM: [green]OpenAI GPT-4o-mini[/]")
            result = self._execute_llm(goal, backend="openai")
        elif backend == "anthropic":
            self._emit("[bold cyan]NEXUS[/] | LLM: [green]Anthropic Claude[/]")
            result = self._execute_llm(goal, backend="anthropic")
        else:
            self._emit("[bold cyan]NEXUS[/] | Engine: [green]Rule-Based Intelligence[/]")
            result = self._execute_rules(goal)

        # Save session to memory
        if self._targets:
            self.memory.save_session(
                goal=goal,
                target=self._targets[0] if self._targets else "unknown",
                plan=[{"step": s} for s in self._steps],
                tool_results=self._tool_results,
                summary=result.get("summary", ""),
            )

        return result

    # ── LLM EXECUTION ─────────────────────────────────────────────────

    def _execute_llm(self, goal: str, backend: str) -> Dict[str, Any]:
        """Execute using LLM tool-calling loop."""
        tool_descs = "\n".join(
            f"  - {t.name}: {t.description}" for t in self.registry.tools.values()
        )
        prior = ""
        for session in self.memory.get_recent_sessions(limit=3):
            prior += f"  - {session.get('target', '?')}: {session.get('summary', '')[:100]}\n"
        context_summary = f"Recent sessions:\n{prior}" if prior else "No prior sessions."

        system_prompt = _build_system_prompt(tool_descs, context_summary)
        messages = [{"role": "system", "content": system_prompt}]
        messages.append({"role": "user", "content": goal})

        self._print_header(goal, "LLM reasoning")

        for iteration in range(MAX_ITERATIONS):
            self._emit_status(f"LLM reasoning (step {iteration + 1})...")

            try:
                if backend == "openai":
                    response = self._call_openai(messages)
                else:
                    response = self._call_anthropic(messages)
            except Exception as e:
                self._emit(f"[red]LLM error: {e} — falling back to rule engine.[/]")
                return self._execute_rules(goal)

            if not response:
                self._emit("[yellow]LLM returned empty response — falling back to rules.[/]")
                return self._execute_rules(goal)

            content = response.get("content", "")
            tool_calls = response.get("tool_calls", [])

            # If no tool calls, the LLM is done
            if not tool_calls:
                if content:
                    self._emit(f"  [dim]{content[:500]}[/]")
                break

            # Execute each tool call
            for tc in tool_calls:
                fn_name = tc.get("function", {}).get("name", "")
                fn_args_str = tc.get("function", {}).get("arguments", "{}")
                try:
                    fn_args = json.loads(fn_args_str) if isinstance(fn_args_str, str) else fn_args_str
                except json.JSONDecodeError:
                    fn_args = {}

                self._emit(f"  [bold]{fn_name}[/]({json.dumps(fn_args)[:100]})")
                self._emit_status(f"Executing: {fn_name}")

                result = self.registry.execute(fn_name, **fn_args)
                success_mark = "[green]✓[/]" if result.success else "[red]✗[/]"
                self._emit(f"    {success_mark} {result.output[:200]}")

                self._steps.append(fn_name)
                self._collect_result(fn_name, result)

                # Feed result back to LLM
                if backend == "openai":
                    messages.append({"role": "assistant", "content": None, "tool_calls": [tc]})
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id", f"call_{fn_name}"),
                        "content": result.output[:4000],
                    })
                else:
                    messages.append({
                        "role": "user",
                        "content": f"Tool {fn_name} result: {result.output[:3000]}",
                    })

        summary = self._build_summary()
        self._print_footer(summary)
        return {
            "goal": goal,
            "steps": self._steps,
            "targets": self._targets,
            "total_findings": len(self._findings),
            "findings": self._findings,
            "summary": summary,
            "backend": backend,
        }

    def _call_openai(self, messages: List[Dict]) -> Optional[Dict]:
        """Call OpenAI API with tool calling."""
        client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        model = os.environ.get("RECONPRO_MODEL", "gpt-4o-mini")
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=self.registry.to_openai_tools(),
            tool_choice="auto",
            max_tokens=4096,
            temperature=0.1,
        )
        choice = response.choices[0]
        message = choice.message
        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                })
        return {"content": message.content or "", "tool_calls": tool_calls}

    def _call_anthropic(self, messages: List[Dict]) -> Optional[Dict]:
        """Call Anthropic API with tool use."""
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        model = os.environ.get("RECONPRO_MODEL", "claude-sonnet-4-20250514")

        system_msg = ""
        anthropic_messages = []
        for m in messages:
            if m["role"] == "system":
                system_msg = m["content"]
            else:
                anthropic_messages.append(m)

        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=system_msg,
            messages=anthropic_messages,
            tools=self.registry.to_anthropic_tools(),
        )

        text_parts, tool_calls = [], []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "type": "function",
                    "function": {
                        "name": block.name,
                        "arguments": json.dumps(block.input),
                    },
                })

        return {"content": "\n".join(text_parts), "tool_calls": tool_calls}

    # ── RULE-BASED EXECUTION (ENHANCED) ───────────────────────────────

    def _execute_rules(self, goal: str) -> Dict[str, Any]:
        """Execute using the intelligent rule-based planner.

        Enhanced with:
        - CVSS scoring for all findings
        - Finding correlation for compound risk detection
        - Attack surface mapping (0-100)
        - Post-scan adaptive deepening
        - Risk matrix visualization
        """
        # THINK phase
        scores = self.planner.classify_intent(goal)
        targets = self.planner.extract_targets(goal)
        target_type = self.planner.detect_target_type(goal, targets)

        domain = ""
        if targets:
            domain = targets[0].replace("https://", "").replace("http://", "").split("/")[0]

        # Build intent display (show top 6 now)
        top_intents = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:6]
        intent_str = " + ".join(f"{n} ({s:.1f})" for n, s in top_intents if s > 0.1)

        self._print_header(goal, "rule-based planner")
        self._emit(f"  [THINK] Analyzing goal...")
        self._emit(f"    [dim]→ Target: {domain or target_type} ({target_type})[/]")
        if intent_str:
            self._emit(f"    [dim]→ Intent: {intent_str}[/]")
        self._emit(f"    [dim]→ Strategy: plan → execute → adapt → analyze[/]")

        # PLAN phase
        plan = self.planner.generate_plan(goal, scores, targets, target_type)
        self._emit(f"")
        self._emit(f"  [PLAN] {len(plan)} step(s):")
        for i, step in enumerate(plan, 1):
            self._emit(f"    {i}. [bold]{step['tool']}[/] — {step['reason']}")

        # EXECUTE phase with adaptation
        completed: List[Tuple[Dict, ToolResult]] = []
        step_idx = 0
        total_steps = len(plan)
        last_scan_data: Optional[Dict] = None

        while step_idx < total_steps and step_idx < MAX_ITERATIONS:
            step = plan[step_idx]
            tool_name = step["tool"]
            args = step["args"]
            current_display = step_idx + 1

            self._emit(f"")
            self._emit(f"  [EXEC] Step {current_display}/{total_steps}: [bold]{tool_name}[/]...")
            self._emit_status(f"Executing step {current_display}/{total_steps}: {tool_name}")

            result = self.registry.execute(tool_name, **args)
            success_mark = "[green]✓[/]" if result.success else "[red]✗[/]"
            self._emit(f"    {success_mark} {result.output[:300]}")

            self._steps.append(tool_name)
            self._collect_result(tool_name, result)
            completed.append((step, result))

            # Track targets and scan data
            if tool_name in ("remote_scan", "vibesec_benchmark", "subdomain_discover",
                             "adversarial_loop", "swarm_run"):
                if domain:
                    self._targets.append(domain)
            if tool_name == "blitz_scan" and result.data:
                for t in result.data.get("results", {}):
                    self._targets.append(t)
            # Keep last scan data for post-scan analysis
            if tool_name in ("remote_scan", "vibesec_benchmark", "local_audit", "dev_scan"):
                if isinstance(result.data, dict):
                    last_scan_data = result.data

            # VERIFY & ADAPT phase (after each step)
            old_len = len(plan)
            plan = self.planner.adapt_plan(plan, completed, step_idx)
            new_steps = len(plan) - old_len
            if new_steps > 0:
                total_steps = len(plan)
                added = plan[step_idx + 1: step_idx + 1 + new_steps]
                self._emit(f"")
                self._emit(f"  [ADAPT] Added {new_steps} step(s) based on results:")
                for a in added:
                    self._emit(f"    + [bold]{a['tool']}[/] — {a['reason']}")

            step_idx += 1

        # ── POST-SCAN INTELLIGENCE ──
        self._emit(f"")
        self._emit(f"  [bold]INTELLIGENCE[/] Post-scan analysis...")
        self._emit_status("Running post-scan intelligence analysis")

        analysis = self.planner.run_post_scan_analysis(self._findings, last_scan_data)

        # 1. Show CVSS scores for findings
        scored = analysis.get("scored_findings", [])
        if scored:
            self._emit(f"")
            self._emit(f"    [bold cyan]CVSS Risk Scoring:[/] {len(scored)} findings scored")
            # Show top 8 by score
            top_scored = sorted(scored, key=lambda f: f.get("cvss_score", 0), reverse=True)[:8]
            for f in top_scored:
                score = f.get("cvss_score", 0)
                sev = f.get("cvss_severity", f.get("severity", "?"))
                title = f.get("title", "?")[:45]
                vector = f.get("cvss_vector", "")
                sev_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green", "info": "dim"}
                color = sev_colors.get(sev, "white")
                self._emit(f"      [{color}]{score:4.1f}[/] [{color}]{sev.upper():8s}[/] {title}")
                if vector:
                    self._emit(f"            [dim]{vector}[/]")

        # 2. Show compound findings
        compound = analysis.get("compound_findings", [])
        if compound:
            self._emit(f"")
            self._emit(f"    [bold red]Compound Risks Identified:[/] {len(compound)} correlation(s)")
            for c in compound:
                cid = c.get("correlation_id", "")
                sev = c.get("severity", "?")
                title = c.get("title", "?")
                score = c.get("cvss_score", "")
                sev_colors = {"critical": "red", "high": "yellow", "medium": "cyan"}
                color = sev_colors.get(sev, "white")
                score_str = f" [{color}]{score:.1f}[/]" if isinstance(score, (int, float)) else ""
                self._emit(f"      [{color}]⬡ {sev.upper()}{score_str}[/] {cid}: {title}")
                self._emit(f"            [dim]{c.get('description', '')[:100]}[/]")

        # 3. Show attack surface score
        surface = analysis.get("attack_surface", {})
        as_score = surface.get("attack_surface_score", 0)
        as_rating = surface.get("risk_rating", "MINIMAL")
        if as_score > 0 or self._findings:
            rating_colors = {"CRITICAL": "red", "HIGH": "yellow", "MODERATE": "cyan", "LOW": "green", "MINIMAL": "dim"}
            rc = rating_colors.get(as_rating, "white")
            self._emit(f"")
            self._emit(f"    [bold]Attack Surface Score:[/] [{rc}]{as_score}/100 ({as_rating})[/]")
            breakdown = surface.get("breakdown", {})
            for factor, vals in breakdown.items():
                score_val = vals.get("score", 0)
                max_val = vals.get("max", 0)
                if score_val > 0:
                    bar_len = int(score_val / max_val * 10) if max_val > 0 else 0
                    bar = "█" * bar_len + "░" * (10 - bar_len)
                    self._emit(f"      {factor.replace('_', ' ').title():20s} {bar} {score_val}/{max_val}")

        # 4. Show risk matrix
        matrix = analysis.get("risk_matrix", "")
        if matrix and self._findings:
            self._emit(f"")
            self._emit(f"    [bold]Risk Matrix (Likelihood × Impact):[/]")
            for line in matrix.split("\n"):
                self._emit(f"    {line}")

        # 5. Show adaptive deepening suggestions
        if self._findings:
            already_run = [s["tool"] for s in completed] if completed else []
            deep_suggestions = AdaptiveDeepeningEngine.suggest(
                self._findings, domain=domain, already_planned=already_run,
            )
            if deep_suggestions:
                self._emit(f"")
                self._emit(f"    [bold yellow]Adaptive Deepening Suggestions:[/]")
                for i, sug in enumerate(deep_suggestions[:4], 1):
                    self._emit(f"      {i}. [bold]{sug['tool']}[/] — {sug['reason']}")
                    if sug.get("trigger_findings"):
                        self._emit(f"         [dim]Triggered by: {', '.join(sug['trigger_findings'][:3])}[/]")

        summary = self._build_enhanced_summary(analysis)
        self._print_footer(summary)
        return {
            "goal": goal,
            "steps": self._steps,
            "targets": self._targets,
            "total_findings": len(self._findings),
            "findings": self._findings,
            "summary": summary,
            "backend": "rules",
            "post_scan_analysis": analysis,
        }

    # ── RESULT COLLECTION ─────────────────────────────────────────────

    def _collect_result(self, tool_name: str, result: ToolResult) -> None:
        """Extract findings from a tool result and store them."""
        entry = {"tool": tool_name, "output": result.output[:500], "success": result.success}
        if result.data:
            entry["data"] = result.data
            if isinstance(result.data, dict):
                # Direct findings
                for f in result.data.get("findings", []):
                    if isinstance(f, dict):
                        self._emit_finding(f)
                # Blitz results
                for t, td in result.data.get("results", {}).items():
                    self._targets.append(t)
                    if isinstance(td, dict):
                        for f in td.get("findings", []):
                            if isinstance(f, dict):
                                self._emit_finding(f)
        self._tool_results.append(entry)

    # ── SUMMARY ───────────────────────────────────────────────────────

    def _build_summary(self) -> str:
        parts = [f"{len(self._findings)} findings"]
        if self._targets:
            parts.append(f"{len(set(self._targets))} target(s)")
        if self._steps:
            parts.append(f"{len(self._steps)} tool call(s)")
        return ", ".join(parts)

    def _build_enhanced_summary(self, analysis: Dict[str, Any]) -> str:
        """Build enhanced summary with post-scan intelligence data."""
        parts = [f"{len(self._findings)} findings"]
        compound_count = len(analysis.get("compound_findings", []))
        if compound_count:
            parts.append(f"{compound_count} compound risk(s)")
        as_score = analysis.get("attack_surface", {}).get("attack_surface_score", 0)
        if as_score > 0:
            parts.append(f"attack surface {as_score}/100")
        if self._targets:
            parts.append(f"{len(set(self._targets))} target(s)")
        if self._steps:
            parts.append(f"{len(self._steps)} tool call(s)")
        return ", ".join(parts)

    # ── RICH OUTPUT ───────────────────────────────────────────────────

    def _print_header(self, goal: str, engine: str) -> None:
        """Print the agent header panel."""
        if not self.verbose:
            return
        title = Text()
        title.append(" NEXUS AGENT ", style="bold white on #1a1a2e")
        title.append(f" [{engine}]", style="dim")

        content = Text()
        content.append(f"Goal: ", style="bold")
        content.append(goal[:120], style="cyan")

        console.print(Panel(content, title=title, border_style="bright_blue", padding=(0, 1)))

    def _print_footer(self, summary: str) -> None:
        """Print the completion footer."""
        if not self.verbose:
            return
        content = Text()
        content.append(f"[DONE] ", style="bold green")
        content.append(f"Goal complete. {summary}.", style="white")

        if self._findings:
            critical = sum(1 for f in self._findings if f.get("severity") == "critical")
            high = sum(1 for f in self._findings if f.get("severity") == "high")
            if critical or high:
                content.append("\n", style="")
                if critical:
                    content.append(f"  [red]{critical} CRITICAL[/]", style="")
                if high:
                    content.append(f"  [yellow]{high} HIGH[/]", style="")

        console.print(Panel(content, border_style="green", padding=(0, 1)))


# ══════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════


def run_nexus_agent(goal: str, verbose: bool = True) -> dict:
    """Run the Nexus Agent on a goal.

    This is the main entry point for the agent system. It creates an agent,
    executes the goal, and returns a results dictionary.

    Args:
        goal: Natural language goal (e.g., "Fully recon example.com and find all vulnerabilities").
        verbose: If True, print rich output. If False, run silently.

    Returns:
        Dict with keys: goal, steps, targets, total_findings, findings, summary, backend.
    """
    if not goal or not goal.strip():
        if verbose:
            console.print("[yellow]No goal provided. Try something like:[/]")
            console.print("  [dim]nexus 'scan example.com with all modules'[/]")
            console.print("  [dim]nexus 'audit my local machine'[/]")
            console.print("  [dim]nexus 'find secrets in my project'[/]")
        return {"error": "No goal provided"}

    def _on_message(msg: str, style: str = "") -> None:
        if verbose:
            if style:
                console.print(msg)
            else:
                console.print(msg)

    def _on_finding(finding: Dict) -> None:
        pass  # Findings are collected internally

    def _on_status(status: str) -> None:
        pass  # Status updates handled internally

    agent = NexusAgent(
        on_message=_on_message,
        on_finding=_on_finding,
        on_status=_on_status,
        verbose=verbose,
    )
    return agent.execute(goal)
"""
ReconPro Swarm Architecture
===========================
Multi-agent swarm system that orchestrates four specialized sub-agents
using multiprocessing. Each agent has a defined role in the kill-chain:

    SCOUT   -> Recon, subdomain discovery, port scanning (broad & fast)
    HACKER  -> Deep vulnerability scanning (oblivion, gorgon, auth, chain)
    CODER   -> Remediation code generation from HACKER findings
    GUARDIAN-> Verification / re-scan of applied fixes

Usage:
    from reconpro.swarm import run_swarm
    results = run_swarm("example.com", mode="full")
"""

from __future__ import annotations

import multiprocessing
import multiprocessing.managers
import os
import signal
import sys
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.columns import Columns
from rich.rule import Rule

# ──────────────────────────────────────────────────────────────────────────────
# Constants & Configuration
# ──────────────────────────────────────────────────────────────────────────────

AGENT_COLORS: Dict[str, str] = {
    "SCOUT": "cyan",
    "HACKER": "red",
    "CODER": "green",
    "GUARDIAN": "yellow",
}

AGENT_ICONS: Dict[str, str] = {
    "SCOUT": "[cyan]\U0001F50D[/]",
    "HACKER": "[red]\U0001F5E1\uFE0F[/]",
    "CODER": "[green]\U0001F4BB[/]",
    "GUARDIAN": "[yellow]\U0001F6E1\uFE0F[/]",
}

VALID_MODES = ("full", "recon", "attack", "fix", "verify")

MODE_AGENT_MAP: Dict[str, List[str]] = {
    "full": ["SCOUT", "HACKER", "CODER", "GUARDIAN"],
    "recon": ["SCOUT"],
    "attack": ["SCOUT", "HACKER"],
    "fix": ["SCOUT", "HACKER", "CODER"],
    "verify": ["SCOUT", "HACKER", "CODER", "GUARDIAN"],
}

# Timeout in seconds for each agent
AGENT_TIMEOUTS: Dict[str, int] = {
    "SCOUT": 120,
    "HACKER": 300,
    "CODER": 60,
    "GUARDIAN": 90,
}


# ──────────────────────────────────────────────────────────────────────────────
# Data Structures
# ──────────────────────────────────────────────────────────────────────────────

class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    FINISHED = "finished"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AgentMessage:
    """Message envelope sent between coordinator and agents via queues."""
    agent: str
    status: AgentStatus
    findings: List[Dict[str, Any]] = field(default_factory=list)
    message: str = ""
    error: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "status": self.status.value,
            "findings": self.findings,
            "message": self.message,
            "error": self.error,
            "timestamp": self.timestamp,
        }


@dataclass
class SwarmResult:
    """Aggregated result from a full swarm run."""
    target: str
    mode: str
    agents: Dict[str, AgentMessage] = field(default_factory=dict)
    total_findings: int = 0
    duration: float = 0.0
    success: bool = True

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "total_findings": self.total_findings,
            "duration": round(self.duration, 2),
            "success": self.success,
            "agents": {k: v.to_dict() for k, v in self.agents.items()},
        }


# ──────────────────────────────────────────────────────────────────────────────
# Agent Worker Functions (run in separate processes)
# ──────────────────────────────────────────────────────────────────────────────

def _scout_worker(
    target: str,
    input_queue: multiprocessing.Queue,
    output_queue: multiprocessing.Queue,
    shared_knowledge: Dict[str, Any],
) -> None:
    """SCOUT agent: broad recon, subdomain discovery, port scanning."""
    output_queue.put(AgentMessage(
        agent="SCOUT", status=AgentStatus.RUNNING, message=f"Starting recon on {target}"
    ))
    findings: List[Dict[str, Any]] = []

    try:
        # Phase 1: Subdomain discovery
        output_queue.put(AgentMessage(
            agent="SCOUT", status=AgentStatus.RUNNING,
            message="Phase 1/3: Subdomain discovery..."
        ))
        try:
            from .subdomains import discover_subdomains
            subdomain_results = discover_subdomains(target)
            if subdomain_results:
                sub_list = [] if isinstance(subdomain_results, dict) else list(subdomain_results)
                if isinstance(subdomain_results, dict):
                    sub_list = subdomain_results.get("subdomains", [])
                findings.append({
                    "type": "subdomains",
                    "target": target,
                    "count": len(sub_list),
                    "data": sub_list[:200],  # cap for shared memory
                })
                shared_knowledge["subdomains"] = sub_list
            else:
                findings.append({"type": "subdomains", "target": target, "count": 0, "data": []})
        except Exception as exc:
            findings.append({"type": "subdomains", "target": target, "error": str(exc)})

        # Phase 2: Port scanning
        output_queue.put(AgentMessage(
            agent="SCOUT", status=AgentStatus.RUNNING,
            message="Phase 2/3: Port scanning..."
        ))
        try:
            from .modules.host import _check_open_ports
            port_results = _check_open_ports(target)
            if port_results:
                findings.append({
                    "type": "open_ports",
                    "target": target,
                    "data": port_results if isinstance(port_results, list) else [port_results],
                })
                shared_knowledge["open_ports"] = port_results
        except Exception as exc:
            findings.append({"type": "open_ports", "target": target, "error": str(exc)})

        # Phase 3: Broad scan
        output_queue.put(AgentMessage(
            agent="SCOUT", status=AgentStatus.RUNNING,
            message="Phase 3/3: Broad vulnerability scan..."
        ))
        try:
            from .scanner import scan
            scan_results = scan(target, modules=["recon", "host"])
            if scan_results:
                findings.append({
                    "type": "scan_results",
                    "target": target,
                    "data": scan_results,
                })
                shared_knowledge["scan_results"] = scan_results
        except Exception as exc:
            findings.append({"type": "scan_results", "target": target, "error": str(exc)})

        shared_knowledge["scout_findings"] = findings
        output_queue.put(AgentMessage(
            agent="SCOUT", status=AgentStatus.FINISHED,
            findings=findings,
            message=f"Recon complete. {len(findings)} finding groups collected."
        ))

    except Exception as exc:
        output_queue.put(AgentMessage(
            agent="SCOUT", status=AgentStatus.FAILED,
            error=f"{type(exc).__name__}: {exc}"
        ))


def _hacker_worker(
    target: str,
    input_queue: multiprocessing.Queue,
    output_queue: multiprocessing.Queue,
    shared_knowledge: Dict[str, Any],
) -> None:
    """HACKER agent: deep vulnerability scanning with attack modules."""
    output_queue.put(AgentMessage(
        agent="HACKER", status=AgentStatus.RUNNING, message=f"Waiting for SCOUT intelligence on {target}"
    ))
    findings: List[Dict[str, Any]] = []

    try:
        # Poll shared knowledge for scout data
        waited = 0
        while "scout_findings" not in shared_knowledge and waited < 30:
            time.sleep(1)
            waited += 1

        if "scout_findings" not in shared_knowledge:
            output_queue.put(AgentMessage(
                agent="HACKER", status=AgentStatus.RUNNING,
                message="No SCOUT data received, proceeding with direct target."
            ))
        else:
            scout_count = len(shared_knowledge.get("scout_findings", []))
            output_queue.put(AgentMessage(
                agent="HACKER", status=AgentStatus.RUNNING,
                message=f"SCOUT intel received ({scout_count} groups). Launching deep scan..."
            ))

        # Also scan discovered subdomains
        subdomains = shared_knowledge.get("subdomains", [])
        targets_to_scan = [target] + (subdomains[:10] if subdomains else [])

        # Phase 1: Oblivion scan
        output_queue.put(AgentMessage(
            agent="HACKER", status=AgentStatus.RUNNING,
            message="Phase 1/5: Running oblivion module..."
        ))
        try:
            from .scanner import scan
            for t in targets_to_scan[:3]:
                result = scan(t, modules=["oblivion"])
                if result:
                    findings.append({"type": "oblivion", "target": t, "data": result})
        except Exception as exc:
            findings.append({"type": "oblivion", "target": target, "error": str(exc)})

        # Phase 2: Gorgon scan
        output_queue.put(AgentMessage(
            agent="HACKER", status=AgentStatus.RUNNING,
            message="Phase 2/5: Running gorgon module..."
        ))
        try:
            from .scanner import scan
            for t in targets_to_scan[:3]:
                result = scan(t, modules=["gorgon"])
                if result:
                    findings.append({"type": "gorgon", "target": t, "data": result})
        except Exception as exc:
            findings.append({"type": "gorgon", "target": target, "error": str(exc)})

        # Phase 3: Auth scan
        output_queue.put(AgentMessage(
            agent="HACKER", status=AgentStatus.RUNNING,
            message="Phase 3/5: Running auth module..."
        ))
        try:
            from .scanner import scan
            for t in targets_to_scan[:3]:
                result = scan(t, modules=["auth"])
                if result:
                    findings.append({"type": "auth", "target": t, "data": result})
        except Exception as exc:
            findings.append({"type": "auth", "target": target, "error": str(exc)})

        # Phase 4: Chain scan
        output_queue.put(AgentMessage(
            agent="HACKER", status=AgentStatus.RUNNING,
            message="Phase 4/5: Running chain module..."
        ))
        try:
            from .scanner import scan
            for t in targets_to_scan[:3]:
                result = scan(t, modules=["chain"])
                if result:
                    findings.append({"type": "chain", "target": t, "data": result})
        except Exception as exc:
            findings.append({"type": "chain", "target": target, "error": str(exc)})

        # Phase 5: NHI scan
        output_queue.put(AgentMessage(
            agent="HACKER", status=AgentStatus.RUNNING,
            message="Phase 5/5: Running nhi module..."
        ))
        try:
            from .scanner import scan
            for t in targets_to_scan[:2]:
                result = scan(t, modules=["nhi"])
                if result:
                    findings.append({"type": "nhi", "target": t, "data": result})
        except Exception as exc:
            findings.append({"type": "nhi", "target": target, "error": str(exc)})

        shared_knowledge["hacker_findings"] = findings
        vuln_count = sum(1 for f in findings if "error" not in f)
        output_queue.put(AgentMessage(
            agent="HACKER", status=AgentStatus.FINISHED,
            findings=findings,
            message=f"Deep scan complete. {vuln_count} vulnerability groups found."
        ))

    except Exception as exc:
        output_queue.put(AgentMessage(
            agent="HACKER", status=AgentStatus.FAILED,
            error=f"{type(exc).__name__}: {exc}"
        ))


def _coder_worker(
    target: str,
    input_queue: multiprocessing.Queue,
    output_queue: multiprocessing.Queue,
    shared_knowledge: Dict[str, Any],
) -> None:
    """CODER agent: analyzes HACKER findings, generates remediation code."""
    output_queue.put(AgentMessage(
        agent="CODER", status=AgentStatus.RUNNING,
        message="Waiting for HACKER vulnerability report..."
    ))
    findings: List[Dict[str, Any]] = []

    try:
        # Wait for hacker findings
        waited = 0
        while "hacker_findings" not in shared_knowledge and waited < 60:
            time.sleep(1)
            waited += 1

        hacker_findings = shared_knowledge.get("hacker_findings", [])
        if not hacker_findings:
            output_queue.put(AgentMessage(
                agent="CODER", status=AgentStatus.FINISHED,
                findings=findings,
                message="No HACKER findings to remediate."
            ))
            return

        output_queue.put(AgentMessage(
            agent="CODER", status=AgentStatus.RUNNING,
            message=f"Analyzing {len(hacker_findings)} vulnerability groups..."
        ))

        # Generate remediation for each finding
        for i, finding in enumerate(hacker_findings):
            if "error" in finding:
                continue

            finding_type = finding.get("type", "unknown")
            finding_target = finding.get("target", target)
            finding_data = finding.get("data", {})

            output_queue.put(AgentMessage(
                agent="CODER", status=AgentStatus.RUNNING,
                message=f"Generating fix for {finding_type} on {finding_target} ({i+1}/{len(hacker_findings)})..."
            ))

            remediation = _generate_remediation(finding_type, finding_target, finding_data)
            findings.append({
                "type": f"remediation_{finding_type}",
                "target": finding_target,
                "original_type": finding_type,
                "remediation": remediation,
            })

        shared_knowledge["coder_findings"] = findings
        shared_knowledge["remediations"] = [f["remediation"] for f in findings if "remediation" in f]
        output_queue.put(AgentMessage(
            agent="CODER", status=AgentStatus.FINISHED,
            findings=findings,
            message=f"Remediation complete. {len(findings)} fix scripts generated."
        ))

    except Exception as exc:
        output_queue.put(AgentMessage(
            agent="CODER", status=AgentStatus.FAILED,
            error=f"{type(exc).__name__}: {exc}"
        ))


def _guardian_worker(
    target: str,
    input_queue: multiprocessing.Queue,
    output_queue: multiprocessing.Queue,
    shared_knowledge: Dict[str, Any],
) -> None:
    """GUARDIAN agent: verifies CODER fixes by re-running checks."""
    output_queue.put(AgentMessage(
        agent="GUARDIAN", status=AgentStatus.RUNNING,
        message="Waiting for CODER remediation scripts..."
    ))
    findings: List[Dict[str, Any]] = []

    try:
        # Wait for coder findings
        waited = 0
        while "coder_findings" not in shared_knowledge and waited < 90:
            time.sleep(1)
            waited += 1

        coder_findings = shared_knowledge.get("coder_findings", [])
        hacker_findings = shared_knowledge.get("hacker_findings", [])

        if not coder_findings and not hacker_findings:
            output_queue.put(AgentMessage(
                agent="GUARDIAN", status=AgentStatus.FINISHED,
                findings=findings,
                message="Nothing to verify."
            ))
            return

        output_queue.put(AgentMessage(
            agent="GUARDIAN", status=AgentStatus.RUNNING,
            message=f"Verifying {len(hacker_findings)} original findings..."
        ))

        # Re-scan target to check if issues persist
        verification_modules = []
        for hf in hacker_findings:
            hf_type = hf.get("type", "")
            if hf_type in ("oblivion", "gorgon", "auth", "chain", "nhi") and hf_type not in verification_modules:
                verification_modules.append(hf_type)

        if verification_modules:
            output_queue.put(AgentMessage(
                agent="GUARDIAN", status=AgentStatus.RUNNING,
                message=f"Re-running modules: {', '.join(verification_modules)}..."
            ))
            try:
                from .scanner import audit_scan
                verify_result = audit_scan(target, modules=verification_modules)
                if verify_result:
                    is_clean = _assess_verification(verify_result)
                    findings.append({
                        "type": "verification",
                        "target": target,
                        "passed": is_clean,
                        "data": verify_result,
                        "modules_checked": verification_modules,
                    })
            except Exception:
                # Fallback: use regular scan for verification
                try:
                    from .scanner import scan
                    verify_result = scan(target, modules=verification_modules)
                    is_clean = _assess_verification(verify_result)
                    findings.append({
                        "type": "verification",
                        "target": target,
                        "passed": is_clean,
                        "data": verify_result,
                        "modules_checked": verification_modules,
                    })
                except Exception as exc:
                    findings.append({
                        "type": "verification",
                        "target": target,
                        "passed": False,
                        "error": str(exc),
                    })

        # Verify each remediation individually
        for i, cf in enumerate(coder_findings):
            if "remediation" not in cf:
                continue
            output_queue.put(AgentMessage(
                agent="GUARDIAN", status=AgentStatus.RUNNING,
                message=f"Verifying fix {i+1}/{len(coder_findings)}: {cf.get('original_type', '?')}..."
            ))
            # Check if the original vulnerability type still appears
            original_type = cf.get("original_type", "")
            still_present = False
            for hf in hacker_findings:
                if hf.get("type") == original_type and "error" not in hf:
                    still_present = True
                    break
            findings.append({
                "type": "fix_verification",
                "target": cf.get("target", target),
                "vulnerability_type": original_type,
                "passed": not still_present,
                "status": "PASS" if not still_present else "STILL VULNERABLE",
            })

        shared_knowledge["guardian_findings"] = findings
        passes = sum(1 for f in findings if f.get("passed", False))
        total = len([f for f in findings if "passed" in f])
        output_queue.put(AgentMessage(
            agent="GUARDIAN", status=AgentStatus.FINISHED,
            findings=findings,
            message=f"Verification complete. {passes}/{total} checks passed."
        ))

    except Exception as exc:
        output_queue.put(AgentMessage(
            agent="GUARDIAN", status=AgentStatus.FAILED,
            error=f"{type(exc).__name__}: {exc}"
        ))


# ──────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────────────────────

def _generate_remediation(
    finding_type: str, target: str, data: Any
) -> Dict[str, str]:
    """Generate remediation commands/scripts based on vulnerability type."""
    remediation_db: Dict[str, Dict[str, str]] = {
        "oblivion": {
            "severity": "HIGH",
            "description": f"Oblivion-class vulnerability detected on {target}",
            "fix": (
                f"# Fix for oblivion vulnerability on {target}\n"
                f"# 1. Update all server-side dependencies:\n"
                f"apt update && apt upgrade -y\n"
                f"# 2. Apply security headers:\n"
                f"# Add to server config: X-Content-Type-Options: nosniff\n"
                f"# X-Frame-Options: DENY\n"
                f"# Content-Security-Policy: default-src 'self'\n"
                f"# 3. Review and patch the identified endpoint\n"
                f"# 4. Restart services after patching\n"
            ),
            "references": "OWASP Top 10, CWE-79, CWE-89",
        },
        "gorgon": {
            "severity": "CRITICAL",
            "description": f"Gorgon-class deep vulnerability on {target}",
            "fix": (
                f"# Fix for gorgon vulnerability on {target}\n"
                f"# 1. Isolate affected system immediately\n"
                f"# 2. Apply kernel security patches:\n"
                f"apt install -y linux-image-generic-lts-$(lsb_release -rs)\n"
                f"# 3. Restrict network access to affected ports\n"
                f"iptables -A INPUT -p tcp --dport <affected> -s trusted_ip -j ACCEPT\n"
                f"iptables -A INPUT -p tcp --dport <affected> -j DROP\n"
                f"# 4. Audit all running services\n"
                f"# 5. Rotate all credentials that may be compromised\n"
            ),
            "references": "MITRE ATT&CK T1190, CWE-200",
        },
        "auth": {
            "severity": "HIGH",
            "description": f"Authentication vulnerability on {target}",
            "fix": (
                f"# Fix for auth vulnerability on {target}\n"
                f"# 1. Enforce strong password policy:\n"
                f"# min 12 chars, upper+lower+digit+special\n"
                f"# 2. Enable MFA for all accounts:\n"
                f"# apt install libpam-google-authenticator\n"
                f"# 3. Implement account lockout after 5 failed attempts\n"
                f"# 4. Set session timeout to 15 minutes\n"
                f"# 5. Use HTTPS only - redirect HTTP to HTTPS\n"
                f"# 6. Disable default credentials\n"
            ),
            "references": "OWASP A07:2021, CWE-287, CWE-521",
        },
        "chain": {
            "severity": "CRITICAL",
            "description": f"Exploit chain vulnerability on {target}",
            "fix": (
                f"# Fix for chain exploit on {target}\n"
                f"# 1. Break the exploit chain by patching the entry point\n"
                f"# 2. Apply input validation on all user-controlled parameters\n"
                f"# 3. Implement WAF rules to detect chain patterns\n"
                f"# 4. Enable detailed logging and monitoring\n"
                f"# 5. Network segmentation to limit lateral movement\n"
                f"# 6. Update IDS signatures\n"
            ),
            "references": "OWASP API Security Top 10, MITRE ATT&CK",
        },
        "nhi": {
            "severity": "MEDIUM",
            "description": f"Network host intelligence finding on {target}",
            "fix": (
                f"# Fix for NHI finding on {target}\n"
                f"# 1. Review exposed services and disable unnecessary ones\n"
                f"# 2. Close non-essential ports\n"
                f"# 3. Implement network access controls\n"
                f"# 4. Enable firewall logging\n"
                f"# 5. Review DNS records for sensitive information exposure\n"
            ),
            "references": "CIS Controls, NIST SP 800-53",
        },
        "scan_results": {
            "severity": "INFO",
            "description": f"General scan finding on {target}",
            "fix": (
                f"# General hardening for {target}\n"
                f"# 1. Review all scan findings\n"
                f"# 2. Apply OS-level hardening\n"
                f"# 3. Update TLS certificates\n"
                f"# 4. Remove informational headers\n"
            ),
            "references": "CIS Benchmarks",
        },
        "subdomains": {
            "severity": "LOW",
            "description": f"Subdomain enumeration results for {target}",
            "fix": (
                f"# Subdomain security review for {target}\n"
                f"# 1. Audit all discovered subdomains\n"
                f"# 2. Remove stale/dangling DNS records\n"
                f"# 3. Ensure all subdomains have valid TLS certs\n"
                f"# 4. Implement certificate monitoring\n"
            ),
            "references": "NIST SP 800-53 SC-12",
        },
        "open_ports": {
            "severity": "MEDIUM",
            "description": f"Open ports detected on {target}",
            "fix": (
                f"# Port hardening for {target}\n"
                f"# 1. Review each open port for necessity\n"
                f"# 2. Close non-essential ports via firewall\n"
                f"# 3. Apply service-specific hardening\n"
                f"# 4. Implement port knocking for sensitive services\n"
            ),
            "references": "CIS Control 9, NIST SC-7",
        },
    }
    return remediation_db.get(
        finding_type,
        {
            "severity": "INFO",
            "description": f"Finding ({finding_type}) on {target}",
            "fix": f"# Review and remediate {finding_type} on {target}\n# Consult the finding data for specifics.",
            "references": "General security best practices",
        },
    )


def _assess_verification(scan_result: Any) -> bool:
    """Assess whether a re-scan result indicates the target is clean."""
    if scan_result is None:
        return True
    if isinstance(scan_result, dict):
        # If there are any 'findings' or 'vulnerabilities' keys with non-empty lists, not clean
        for key in ("findings", "vulnerabilities", "issues", "results"):
            val = scan_result.get(key)
            if val and isinstance(val, (list, dict)) and len(val) > 0:
                return False
        # If 'status' is explicitly clean/ok
        status = str(scan_result.get("status", "")).lower()
        if status in ("clean", "ok", "pass", "safe"):
            return True
    if isinstance(scan_result, list):
        return len(scan_result) == 0
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Swarm Coordinator
# ──────────────────────────────────────────────────────────────────────────────

class SwarmCoordinator:
    """Orchestrates the multi-agent swarm for security assessment.

    Spawns agents as separate processes, manages shared state via
    multiprocessing.Manager, and provides real-time Rich console output.
    """

    def __init__(self, target: str, mode: str = "full", console: Optional[Console] = None):
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Must be one of: {VALID_MODES}")

        self.target = target
        self.mode = mode
        self.console = console or Console()
        self.active_agents = MODE_AGENT_MAP[mode]
        self.agent_statuses: Dict[str, AgentStatus] = {
            name: AgentStatus.IDLE for name in self.active_agents
        }
        self.agent_messages: Dict[str, List[str]] = {
            name: [] for name in self.active_agents
        }
        self.agent_findings_count: Dict[str, int] = {
            name: 0 for name in self.active_agents
        }
        self.agent_errors: Dict[str, str] = {}
        self.final_messages: Dict[str, AgentMessage] = {}
        self.processes: List[multiprocessing.Process] = []

    def _build_status_table(self) -> Table:
        """Build the live status table for Rich display."""
        table = Table(
            title="[bold white]\U0001F535 ReconPro Swarm[/]",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            expand=True,
        )
        table.add_column("Agent", style="bold", width=12)
        table.add_column("Status", width=14)
        table.add_column("Findings", justify="right", width=10)
        table.add_column("Message", min_width=40)

        for agent_name in self.active_agents:
            color = AGENT_COLORS.get(agent_name, "white")
            icon = AGENT_ICONS.get(agent_name, "\u2022")
            status = self.agent_statuses.get(agent_name, AgentStatus.IDLE)
            findings = self.agent_findings_count.get(agent_name, 0)

            # Status styling
            status_text = status.value.upper()
            if status == AgentStatus.RUNNING:
                status_style = f"bold {color}"
            elif status == AgentStatus.FINISHED:
                status_style = "bold green"
            elif status == AgentStatus.FAILED:
                status_style = "bold red"
            elif status == AgentStatus.WAITING:
                status_style = f"italic {color}"
            else:
                status_style = "dim"

            # Latest message
            msgs = self.agent_messages.get(agent_name, [])
            latest_msg = msgs[-1] if msgs else "Queued..."
            if len(latest_msg) > 60:
                latest_msg = latest_msg[:57] + "..."

            table.add_row(
                f"{icon} {agent_name}",
                Text(status_text, style=status_style),
                str(findings),
                Text(latest_msg, style=color),
            )

        return table

    def _build_pipeline_visual(self) -> Panel:
        """Build a visual pipeline showing agent flow."""
        pipeline_parts = []
        for agent_name in self.active_agents:
            color = AGENT_COLORS.get(agent_name, "white")
            status = self.agent_statuses.get(agent_name, AgentStatus.IDLE)
            if status == AgentStatus.FINISHED:
                marker = f"\u2714 [{color}]{agent_name}[/]"
            elif status == AgentStatus.FAILED:
                marker = f"\u2718 [red]{agent_name}[/]"
            elif status == AgentStatus.RUNNING:
                marker = f"\u25B6 [{color}]{agent_name}[/]"
            else:
                marker = f"\u25CB [dim]{agent_name}[/]"
            pipeline_parts.append(marker)

        pipeline_str = " [dim]\u2192[/] ".join(pipeline_parts)
        return Panel(
            Text(pipeline_str, justify="center"),
            title="[bold]Pipeline[/]",
            border_style="blue",
            padding=(0, 2),
        )

    def _consume_messages(self, output_queue: multiprocessing.Queue, timeout: float = 0.3) -> None:
        """Drain all available messages from the output queue."""
        while True:
            try:
                msg = output_queue.get(timeout=timeout)
                if not isinstance(msg, AgentMessage):
                    continue
                self.agent_statuses[msg.agent] = msg.status
                if msg.message:
                    self.agent_messages.setdefault(msg.agent, []).append(msg.message)
                if msg.findings:
                    self.agent_findings_count[msg.agent] = len(msg.findings)
                if msg.error:
                    self.agent_errors[msg.agent] = msg.error
                # Store final message for each agent
                if msg.status in (AgentStatus.FINISHED, AgentStatus.FAILED):
                    self.final_messages[msg.agent] = msg
            except Exception:
                break

    def _check_all_done(self) -> bool:
        """Check if all active agents have terminated."""
        for agent_name in self.active_agents:
            status = self.agent_statuses.get(agent_name, AgentStatus.IDLE)
            if status not in (AgentStatus.FINISHED, AgentStatus.FAILED):
                return False
        return True

    def run(self) -> SwarmResult:
        """Execute the swarm and return aggregated results."""
        start_time = time.time()
        manager = multiprocessing.Manager()
        shared_knowledge = manager.dict()
        output_queue = multiprocessing.Queue()
        input_queue = multiprocessing.Queue()

        # Worker function map
        worker_map = {
            "SCOUT": _scout_worker,
            "HACKER": _hacker_worker,
            "CODER": _coder_worker,
            "GUARDIAN": _guardian_worker,
        }

        # Banner
        self.console.print()
        self.console.print(Rule(
            f"[bold magenta]\U0001F680 RECONPRO SWARM[/] | Target: [bold cyan]{self.target}[/] | Mode: [bold]{self.mode.upper()}[/]",
            style="magenta"
        ))
        self.console.print()

        # Spawn agent processes
        for agent_name in self.active_agents:
            worker_fn = worker_map.get(agent_name)
            if not worker_fn:
                continue
            self.agent_statuses[agent_name] = AgentStatus.WAITING
            proc = multiprocessing.Process(
                target=worker_fn,
                args=(self.target, input_queue, output_queue, shared_knowledge),
                name=f"reconpro-{agent_name.lower()}",
                daemon=True,
            )
            self.processes.append(proc)

        # Start all processes
        for proc in self.processes:
            proc.start()
            self.console.print(
                f"  {AGENT_ICONS.get(proc.name.split('-')[-1].upper(), '')} "
                f"Spawned [bold]{proc.name}[/] (PID {proc.pid})"
            )
        self.console.print()

        # Live display loop
        try:
            with Live(
                self._build_status_table(),
                console=self.console,
                refresh_per_second=4,
                transient=False,
            ) as live:
                while not self._check_all_done():
                    self._consume_messages(output_queue)
                    # Update display
                    layout = Table.grid(expand=True)
                    layout.add_row(self._build_status_table())
                    layout.add_row(self._build_pipeline_visual())
                    live.update(layout)
                    time.sleep(0.25)

                # Final drain
                self._consume_messages(output_queue, timeout=2.0)
                layout = Table.grid(expand=True)
                layout.add_row(self._build_status_table())
                layout.add_row(self._build_pipeline_visual())
                live.update(layout)
        except KeyboardInterrupt:
            self.console.print("\n[bold red]\u26A0 Swarm interrupted by user. Terminating...[/]")
            for proc in self.processes:
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=5)

        # Wait for all processes to finish
        for proc in self.processes:
            proc.join(timeout=AGENT_TIMEOUTS.get(proc.name.split("-")[-1].upper(), 120))
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=5)

        duration = time.time() - start_time

        # Build result
        total_findings = sum(self.agent_findings_count.values())
        success = all(
            self.agent_statuses.get(a) != AgentStatus.FAILED
            for a in self.active_agents
        )

        result = SwarmResult(
            target=self.target,
            mode=self.mode,
            agents={
                name: self.final_messages.get(name, AgentMessage(
                    agent=name,
                    status=self.agent_statuses.get(name, AgentStatus.IDLE),
                ))
                for name in self.active_agents
            },
            total_findings=total_findings,
            duration=duration,
            success=success,
        )

        # Print summary
        self._print_summary(result)

        return result

    def _print_summary(self, result: SwarmResult) -> None:
        """Print a formatted summary of the swarm run."""
        self.console.print()
        self.console.print(Rule("[bold]SWARM SUMMARY[/]", style="magenta"))

        # Overall stats
        status_icon = "\u2705" if result.success else "\u274C"
        self.console.print(
            f"  {status_icon} [bold]Target:[/] {result.target}"
        )
        self.console.print(
            f"  \U0001F552 [bold]Duration:[/] {result.duration:.1f}s"
        )
        self.console.print(
            f"  \U0001F4CA [bold]Total Findings:[/] {result.total_findings}"
        )
        self.console.print(
            f"  \U0001F3AE [bold]Mode:[/] {result.mode.upper()}"
        )
        self.console.print()

        # Per-agent summary
        summary_table = Table(
            title="Agent Report",
            show_header=True,
            header_style="bold",
            border_style="dim",
        )
        summary_table.add_column("Agent", width=12)
        summary_table.add_column("Status", width=12)
        summary_table.add_column("Findings", justify="right", width=10)
        summary_table.add_column("Message", min_width=50)

        for agent_name, msg in result.agents.items():
            color = AGENT_COLORS.get(agent_name, "white")
            status_val = msg.status.value.upper()
            if msg.status == AgentStatus.FAILED:
                status_val = f"[red]{status_val}[/]"
                msg_text = msg.error or "Unknown error"
            else:
                status_val = f"[green]{status_val}[/]"
                msg_text = msg.message or "No message"

            summary_table.add_row(
                f"[{color}]{agent_name}[/]",
                status_val,
                str(len(msg.findings)),
                Text(msg_text[:80], style=color),
            )

        self.console.print(summary_table)

        # Print remediations if CODER ran
        coder_msg = result.agents.get("CODER")
        if coder_msg and coder_msg.findings:
            self.console.print()
            self.console.print(Rule("[bold green]\U0001F4BB REMEDIATION SCRIPTS[/]", style="green"))
            for finding in coder_msg.findings:
                rem = finding.get("remediation", {})
                if not rem:
                    continue
                severity = rem.get("severity", "INFO")
                sev_color = {
                    "CRITICAL": "bold red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "cyan",
                    "INFO": "dim",
                }.get(severity, "white")
                self.console.print(
                    Panel(
                        Text(rem.get("fix", "No fix available."), style="green"),
                        title=f"[{sev_color}][{severity}] {finding.get('target', '?')} - {finding.get('original_type', '?')}[/]",
                        border_style="green",
                        subtitle=f"Refs: {rem.get('references', 'N/A')}",
                    )
                )

        # Print verification results if GUARDIAN ran
        guardian_msg = result.agents.get("GUARDIAN")
        if guardian_msg and guardian_msg.findings:
            self.console.print()
            self.console.print(Rule("[bold yellow]\U0001F6E1\uFE0F VERIFICATION RESULTS[/]", style="yellow"))
            for finding in guardian_msg.findings:
                if finding.get("type") == "fix_verification":
                    passed = finding.get("passed", False)
                    icon = "\u2705" if passed else "\u274C"
                    color = "green" if passed else "red"
                    status = finding.get("status", "UNKNOWN")
                    vuln_type = finding.get("vulnerability_type", "?")
                    target_str = finding.get("target", "?")
                    self.console.print(
                        f"  {icon} [{color}]{vuln_type}[/] on {target_str}: [{color}]{status}[/]"
                    )

        self.console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Public Entry Point
# ──────────────────────────────────────────────────────────────────────────────

# DEAD CODE: consider removal
def run_swarm(
    target: str,
    mode: str = "full",
    console: Optional[Console] = None,
) -> SwarmResult:
    """Main entry point for the ReconPro swarm system.

    Args:
        target: The target domain or IP to assess.
        mode: Execution mode. One of:
            - ``'full'``    — All 4 agents (SCOUT → HACKER → CODER → GUARDIAN)
            - ``'recon'``   — SCOUT only
            - ``'attack'``  — SCOUT + HACKER
            - ``'fix'``     — SCOUT + HACKER + CODER
            - ``'verify'``  — All 4 agents (same as 'full')
        console: Optional Rich Console instance. If None, a new one is created.

    Returns:
        SwarmResult with all agent findings, status, and timing info.

    Example:
        >>> from reconpro.swarm import run_swarm
        >>> result = run_swarm("example.com", mode="attack")
        >>> print(result.summary())
    """
    if not target or not isinstance(target, str):
        raise ValueError("target must be a non-empty string")

    target = target.strip()

    if mode not in VALID_MODES:
        raise ValueError(
            f"Invalid mode '{mode}'. Valid modes: {', '.join(VALID_MODES)}"
        )

    coordinator = SwarmCoordinator(
        target=target,
        mode=mode,
        console=console,
    )
    return coordinator.run()


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def list_modes() -> List[Dict[str, Any]]:
    """Return available swarm modes and their agent compositions."""
    return [
        {"mode": mode, "agents": agents}
        for mode, agents in MODE_AGENT_MAP.items()
    ]


def list_agents() -> List[Dict[str, str]]:
    """Return available agent types with descriptions."""
    return [
        {
            "name": "SCOUT",
            "color": AGENT_COLORS["SCOUT"],
            "description": "Recon + subdomain discovery + port scanning",
            "role": "Intelligence gathering (broad & fast)",
        },
        {
            "name": "HACKER",
            "color": AGENT_COLORS["HACKER"],
            "description": "Deep vulnerability scanning (oblivion, gorgon, auth, chain, nhi)",
            "role": "Exploit discovery & vulnerability assessment",
        },
        {
            "name": "CODER",
            "color": AGENT_COLORS["CODER"],
            "description": "Remediation code generation from findings",
            "role": "Fix script & command generation",
        },
        {
            "name": "GUARDIAN",
            "color": AGENT_COLORS["GUARDIAN"],
            "description": "Verification of applied fixes",
            "role": "Re-scan & pass/fail reporting",
        },
    ]


__all__ = [
    "SwarmCoordinator",
    "SwarmResult",
    "AgentMessage",
    "AgentStatus",
    "run_swarm",
    "list_modes",
    "list_agents",
]

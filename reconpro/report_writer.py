"""AI-Powered Report Writer for ReconPro v11.0.

Generates audience-specific markdown reports from scan data.
LLM integration is optional -- templates work standalone.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .constants import SEVERITY_LEVELS

try:
    import openai
    _HAS_OPENAI = True
except ImportError:
    _HAS_OPENAI = False


# ── Audience Modes ──────────────────────────────────────────────────────

AUDIENCE_MODES: Dict[str, Dict[str, Any]] = {
    "executive": {
        "label": "Executive",
        "description": "1-page, business risk, no jargon, focus on dollar impact",
        "max_findings": 5,
    },
    "technical": {
        "label": "Technical",
        "description": "Full findings, code refs, CVE links, PoC",
        "max_findings": 999,
    },
    "compliance": {
        "label": "Compliance",
        "description": "Framework-mapped, control gaps, evidence",
        "max_findings": 999,
    },
    "developer": {
        "label": "Developer",
        "description": "Actionable PRs, exact code changes, fix commands",
        "max_findings": 999,
    },
}


_SEVERITY_EMOJI = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


# ── ExecutiveSummaryGenerator ───────────────────────────────────────────


class ExecutiveSummaryGenerator:
    """Generate executive summaries with optional LLM enhancement."""

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.3) -> None:
        self._model = model
        self._temperature = temperature

    def generate(
        self,
        scan_data: Dict[str, Any],
        audience: str = "technical",
        llm_client: Optional[Any] = None,
    ) -> str:
        """Generate a narrative summary. Uses LLM if available, otherwise templates."""
        if audience not in AUDIENCE_MODES:
            audience = "technical"

        # Try LLM path
        if llm_client is not None and _HAS_OPENAI:
            try:
                return self._generate_with_llm(scan_data, audience, llm_client)
            except Exception:
                pass  # Fall through to templates

        # Also try if openai module exists and env vars are set
        if _HAS_OPENAI and llm_client is None:
            try:
                client = openai.OpenAI()
                return self._generate_with_llm(scan_data, audience, client)
            except Exception:
                pass

        return self._generate_from_templates(scan_data, audience)

    # ── LLM generation ───────────────────────────────────────────────────

    def _generate_with_llm(
        self,
        scan_data: Dict[str, Any],
        audience: str,
        client: Any,
    ) -> str:
        """Send scan summary to LLM and return narrative."""
        findings = scan_data.get("findings", [])
        target = scan_data.get("target", "Unknown")
        score = scan_data.get("total_score", "N/A")
        grade = scan_data.get("grade", "N/A")

        # Build a compact summary for the LLM
        finding_summaries = []
        for f in findings[:20]:
            sev = f.get("severity", "info")
            title = f.get("title", "Unknown")
            finding_summaries.append(f"  [{sev.upper()}] {title}")

        findings_text = "\n".join(finding_summaries) if finding_summaries else "  No findings."

        mode = AUDIENCE_MODES[audience]

        system_prompt = (
            f"You are a senior security consultant writing a {mode['label'].lower()} "
            f"report for a penetration test / security assessment. "
            f"{mode['description']}. "
            f"Be concise, professional, and actionable. "
            f"Do not use markdown headers or bullet lists inside your narrative. "
            f"Write in clear prose paragraphs."
        )

        user_prompt = (
            f"Target: {target}\n"
            f"Security Score: {score}/100 (Grade: {grade})\n"
            f"Total Findings: {len(findings)}\n"
            f"Findings:\n{findings_text}\n\n"
            f"Write a {mode['label'].lower()}-focused executive summary."
        )

        response = client.chat.completions.create(
            model=self._model,
            temperature=self._temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=1024,
        )
        return response.choices[0].message.content.strip()

    # ── Template-based generation ────────────────────────────────────────

    def _generate_from_templates(
        self,
        scan_data: Dict[str, Any],
        audience: str,
    ) -> str:
        """Generate summary using built-in templates."""
        findings = scan_data.get("findings", [])
        target = scan_data.get("target", "Unknown")
        score = scan_data.get("total_score", "N/A")
        grade = scan_data.get("grade", "N/A")
        modules_run = scan_data.get("modules_run", [])
        duration = scan_data.get("duration", 0)

        severity_counts = self._count_severities(findings)
        sorted_findings = self._sort_findings(findings)
        max_findings = AUDIENCE_MODES[audience]["max_findings"]
        top_findings = sorted_findings[:max_findings]

        if audience == "executive":
            return self._template_executive(
                target, score, grade, severity_counts, top_findings
            )
        elif audience == "technical":
            return self._template_technical(
                target, score, grade, modules_run, duration, sorted_findings
            )
        elif audience == "compliance":
            return self._template_compliance(
                target, score, grade, severity_counts, sorted_findings
            )
        elif audience == "developer":
            return self._template_developer(target, score, grade, sorted_findings)
        return self._template_technical(
            target, score, grade, modules_run, duration, sorted_findings
        )

    # ── Audience templates ───────────────────────────────────────────────

    @staticmethod
    def _template_executive(
        target: str,
        score: Any,
        grade: str,
        severity_counts: Dict[str, int],
        top_findings: List[Dict[str, Any]],
    ) -> str:
        lines: List[str] = [
            f"Security Assessment Summary for {target}",
            "",
            f"Overall Grade: {grade} (Score: {score}/100)",
            "",
            f"A security assessment was conducted against {target}. "
            f"The assessment identified {severity_counts.get('critical', 0)} critical, "
            f"{severity_counts.get('high', 0)} high, "
            f"{severity_counts.get('medium', 0)} medium, and "
            f"{severity_counts.get('low', 0)} low-severity findings.",
            "",
            "Key Findings:",
        ]
        for i, f in enumerate(top_findings, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            desc = f.get("description", "").strip()
            lines.append(f"  {i}. [{sev}] {title}")
            if desc:
                lines.append(f"     {desc[:200]}")
        lines.append("")

        # Business impact paragraph
        crit = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        if crit > 0 or high > 0:
            lines.append(
                "Business Impact: The presence of critical and high-severity "
                "vulnerabilities poses significant risk to data confidentiality, "
                "integrity, and availability. Immediate remediation is recommended "
                "to reduce exposure to potential breaches and regulatory penalties."
            )
        else:
            lines.append(
                "Business Impact: No critical or high-severity findings were "
                "identified. The target demonstrates a reasonable security posture. "
                "Addressing medium and low findings will further harden defenses."
            )
        lines.append("")
        lines.append(
            "Recommendations: Prioritize remediation of critical findings within "
            "24-48 hours. High-severity issues should be addressed within one week. "
            "Schedule a follow-up assessment after remediation is complete."
        )
        return "\n".join(lines)

    @staticmethod
    def _template_technical(
        target: str,
        score: Any,
        grade: str,
        modules_run: List[str],
        duration: float,
        findings: List[Dict[str, Any]],
    ) -> str:
        mins = int(duration // 60)
        secs = int(duration % 60)
        lines: List[str] = [
            f"Technical Assessment Report - {target}",
            "",
            f"Grade: {grade} | Score: {score}/100 | Duration: {mins}m {secs}s",
            f"Modules: {', '.join(modules_run) if modules_run else 'N/A'}",
            f"Total Findings: {len(findings)}",
            "",
        ]
        # Group findings by module
        by_module: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            mod = f.get("module", "unknown")
            by_module.setdefault(mod, []).append(f)
        for mod, mod_findings in sorted(by_module.items()):
            lines.append(f"Module: {mod} ({len(mod_findings)} findings)")
            for f in mod_findings:
                sev = f.get("severity", "info").upper()
                title = f.get("title", "Unknown")
                evidence = f.get("evidence", "")
                remediation = f.get("remediation", "")
                lines.append(f"  [{sev}] {title}")
                if evidence:
                    lines.append(f"    Evidence: {evidence[:200]}")
                if remediation:
                    lines.append(f"    Remediation: {remediation[:200]}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _template_compliance(
        target: str,
        score: Any,
        grade: str,
        severity_counts: Dict[str, int],
        findings: List[Dict[str, Any]],
    ) -> str:
        lines: List[str] = [
            f"Compliance Posture Report - {target}",
            "",
            f"Grade: {grade} | Score: {score}/100",
            "",
            "Control Gap Analysis:",
        ]
        # Map findings to compliance categories
        control_mapping = {
            "Missing HSTS": "A.10.1.1 (ISO 27001) - Cryptographic Controls",
            "Missing Content-Security-Policy": "A.8.25 (ISO 27001) - Secure Development",
            "Missing X-Frame-Options": "SC-7 (NIST 800-53) - Boundary Protection",
            "clickjacking": "SC-7 (NIST 800-53) - Boundary Protection",
            "XSS": "A.8.28 (ISO 27001) - Secure Coding",
            "SQL injection": "A.8.28 (ISO 27001) - Secure Coding",
            "CSRF": "A.8.25 (ISO 27001) - Secure Development",
            "information disclosure": "A.8.12 (ISO 27001) - Data Leakage",
        }
        for f in findings:
            title = f.get("title", "")
            sev = f.get("severity", "info").upper()
            evidence = f.get("evidence", "")
            matched_controls = []
            for trigger, control in control_mapping.items():
                if trigger.lower() in title.lower() or trigger.lower() in evidence.lower():
                    matched_controls.append(control)
            lines.append(f"  [{sev}] {title}")
            if matched_controls:
                for ctrl in matched_controls:
                    lines.append(f"    -> {ctrl}")
            else:
                lines.append(f"    -> General security control (no specific mapping)")
            if evidence:
                lines.append(f"    Evidence: {evidence[:150]}")
        lines.append("")
        lines.append("Remediation Plan:")
        lines.append(
            "  1. Address all CRITICAL and HIGH findings within SLA."
        )
        lines.append(
            "  2. Document compensating controls for accepted risks."
        )
        lines.append(
            "  3. Schedule re-assessment within 30 days of remediation."
        )
        return "\n".join(lines)

    @staticmethod
    def _template_developer(
        target: str,
        score: Any,
        grade: str,
        findings: List[Dict[str, Any]],
    ) -> str:
        lines: List[str] = [
            f"Developer Fix Report - {target}",
            "",
            f"Grade: {grade} | Score: {score}/100",
            "",
            "Fix Priority Queue:",
        ]
        priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        sorted_f = sorted(
            findings,
            key=lambda x: (priority_map.get(x.get("severity", "info"), 9), x.get("title", "")),
        )
        for i, f in enumerate(sorted_f, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            remediation = f.get("remediation", "No specific remediation provided.")
            evidence = f.get("evidence", "")
            asset = f.get("asset", "")
            lines.append(f"  #{i} [{sev}] {title}")
            if asset:
                lines.append(f"      Asset: {asset}")
            lines.append(f"      Fix: {remediation[:250]}")
            if evidence:
                lines.append(f"      Evidence: {evidence[:150]}")
            lines.append("")
        lines.append("Quick Wins (can fix in < 5 min each):")
        quick_wins = [f for f in sorted_f if f.get("severity") in ("low", "medium")]
        for f in quick_wins[:5]:
            lines.append(f"  - {f.get('title', '')}: {f.get('remediation', '')[:120]}")
        return "\n".join(lines)

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _count_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sorted(
            findings,
            key=lambda x: (SEVERITY_LEVELS.get(x.get("severity", "info"), 99), x.get("title", "")),
        )


# ── MarkdownReportBuilder ───────────────────────────────────────────────


class MarkdownReportBuilder:
    """Build a complete markdown report from scan data."""

    def __init__(self) -> None:
        self._summary_gen = ExecutiveSummaryGenerator()

    # DEAD CODE: consider removal
    def build_report(
        self,
        scan_data: Dict[str, Any],
        audience: str = "technical",
        summary_text: str = "",
    ) -> str:
        """Build a full markdown report combining summary + findings + remediation."""
        if audience not in AUDIENCE_MODES:
            audience = "technical"

        # Generate summary if not provided
        if not summary_text:
            summary_text = self._summary_gen.generate(scan_data, audience)

        target = scan_data.get("target", "Unknown")
        score = scan_data.get("total_score", "N/A")
        grade = scan_data.get("grade", "N/A")
        findings = scan_data.get("findings", [])
        modules_run = scan_data.get("modules_run", [])
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        sorted_findings = ExecutiveSummaryGenerator._sort_findings(findings)
        severity_counts = ExecutiveSummaryGenerator._count_severities(findings)

        md: List[str] = []
        md.append(f"# ReconPro Security Report")
        md.append("")
        md.append(f"**Target:** {target}  ")
        md.append(f"**Grade:** {grade} ({score}/100)  ")
        md.append(f"**Date:** {ts}  ")
        md.append(f"**Audience:** {AUDIENCE_MODES[audience]['label']}  ")
        if modules_run:
            md.append(f"**Modules:** {', '.join(modules_run)}")
        md.append("")

        # Summary section
        md.append("---")
        md.append("")
        md.append("## Executive Summary")
        md.append("")
        for line in summary_text.split("\n"):
            md.append(line)
        md.append("")

        # Severity overview
        md.append("---")
        md.append("")
        md.append("## Severity Overview")
        md.append("")
        md.append("| Severity | Count |")
        md.append("|----------|-------|")
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = severity_counts.get(sev, 0)
            md.append(f"| {sev.upper()} | {cnt} |")
        md.append("")

        # Findings table
        if sorted_findings:
            md.append("---")
            md.append("")
            md.append("## Detailed Findings")
            md.append("")
            md.append("| # | Severity | Finding | Module | Evidence |")
            md.append("|---|----------|---------|--------|----------|")
            for i, f in enumerate(sorted_findings, 1):
                sev = _SEVERITY_EMOJI.get(f.get("severity", "info"), "INFO")
                title = f.get("title", "Unknown").replace("|", "\\|")[:60]
                mod = f.get("module", "-")[:15]
                evidence = f.get("evidence", "").replace("|", "\\|")[:40]
                md.append(f"| {i} | {sev} | {title} | {mod} | {evidence} |")
            md.append("")

        # Module breakdown
        if modules_run:
            md.append("---")
            md.append("")
            md.append("## Module Breakdown")
            md.append("")
            by_module: Dict[str, List[Dict[str, Any]]] = {}
            for f in findings:
                mod = f.get("module", "unknown")
                by_module.setdefault(mod, []).append(f)
            for mod in modules_run:
                mod_findings = by_module.get(mod, [])
                crit = sum(1 for x in mod_findings if x.get("severity") == "critical")
                high = sum(1 for x in mod_findings if x.get("severity") == "high")
                total = len(mod_findings)
                status = "PASS" if total == 0 else ("FAIL" if crit > 0 or high > 0 else "WARN")
                md.append(f"### {mod}")
                md.append(f"- **Status:** {status}  ")
                md.append(
                    f"- **Findings:** {total} "
                    f"({crit} critical, {high} high, {total - crit - high} other)"
                )
                for f in mod_findings[:10]:
                    sev = f.get("severity", "info").upper()
                    title = f.get("title", "")
                    rem = f.get("remediation", "")
                    md.append(f"  - [{sev}] {title}")
                    if rem:
                        md.append(f"    - Fix: {rem[:200]}")
                md.append("")

        # Remediation section
        critical_high = [f for f in sorted_findings if f.get("severity") in ("critical", "high")]
        if critical_high:
            md.append("---")
            md.append("")
            md.append("## Priority Remediation")
            md.append("")
            for i, f in enumerate(critical_high, 1):
                sev = f.get("severity", "").upper()
                title = f.get("title", "")
                rem = f.get("remediation", "No remediation specified.")
                md.append(f"### {i}. [{sev}] {title}")
                md.append("")
                md.append(f"{rem}")
                md.append("")

        md.append("---")
        md.append("")
        md.append("*Generated by ReconPro v11.0*")
        md.append("")

        return "\n".join(md)


# ── Convenience functions ────────────────────────────────────────────────

_summary_generator = ExecutiveSummaryGenerator()
_report_builder = MarkdownReportBuilder()


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def generate_narrative(scan_data: Dict[str, Any], audience: str = "technical") -> str:
    """Generate a narrative summary for the given audience."""
    return _summary_generator.generate(scan_data, audience)


def generate_report_md(
    scan_data: Dict[str, Any],
    audience: str = "technical",
    summary_text: str = "",
) -> str:
    """Generate a full markdown report."""
    return _report_builder.build_report(scan_data, audience, summary_text)


__all__ = [
    "AUDIENCE_MODES",
    "ExecutiveSummaryGenerator",
    "MarkdownReportBuilder",
    "generate_narrative",
    "generate_report_md",
]

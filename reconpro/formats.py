"""Multi-format export for ReconPro scan results.

Supported formats:
  - SARIF 2.1.0 (Microsoft Static Analysis Results Interchange Format)
  - Markdown (.md)
  - JSON (.json)
  - HTML (.html)
  - Print-ready HTML for PDF export (.pdf)
"""
from __future__ import annotations

import json
import html as _html_module
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .constants import __version__


def _normalize(data: Any) -> Dict[str, Any]:
    """Accept both dict and ReconProResult, always return dict."""
    if hasattr(data, "to_dict"):
        return data.to_dict()
    return data


# SARIF severity → level mapping
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Severity sort order (highest first)
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── SARIF 2.1.0 export ────────────────────────────────────────────────


def export_sarif(data: Dict[str, Any], output_path: str) -> str:
    """Export scan results as a SARIF 2.1.0 JSON file.

    Fully compatible with GitHub Code Scanning, Azure DevOps,
    and any SARIF-consuming CI/CD tool.
    """
    data = _normalize(data)
    findings = data.get("findings", [])
    target = data.get("target", "unknown")
    grade = data.get("grade", "N/A")

    # Build unique rules from findings
    rule_index: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        cat = f.get("category", "general")
        if cat not in rule_index:
            rule_index[cat] = {
                "id": f"RP-{cat.upper()}",
                "name": cat.replace("_", " ").title(),
                "shortDescription": {
                    "text": f.get("title", cat.replace("_", " ").title()),
                },
                "fullDescription": {
                    "text": f.get("description", "Security finding."),
                },
                "helpUri": f"https://github.com/falconxa0-commits/reconpro/wiki/{cat}",
                "properties": {
                    "security-severity": _severity_to_cvss(f.get("severity", "info")),
                },
            }

    rules = list(rule_index.values())

    # Build results
    results: List[Dict[str, Any]] = []
    for f in findings:
        cat = f.get("category", "general")
        rule_id = f"RP-{cat.upper()}"
        sev = f.get("severity", "info").lower()
        asset = f.get("asset", target)

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {
                "text": f.get("title", ""),
                "markdown": f"**{f.get('title', '')}**\n\n{f.get('description', '')}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": asset,
                        },
                    },
                }
            ],
            "properties": {
                "category": cat,
                "module": f.get("module", ""),
                "points_deducted": f.get("points_deducted", 0),
                "evidence": f.get("evidence", "")[:200],
                "remediation": f.get("remediation", ""),
                "confidence": f.get("confidence", 0.8),
                "verification_state": f.get("verification_state", "UNVERIFIED"),
            },
        }

        # Add CVE data if present (from CVERadar enrichment)
        cves = f.get("related_cves", [])
        if cves:
            result["relatedLocations"] = []
            for cve in cves[:5]:
                result["relatedLocations"].append({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": cve.get("url", ""),
                        },
                    },
                    "message": {
                        "text": f"{cve.get('cve_id', '')} (CVSS {cve.get('cvss_score', 'N/A')})",
                    },
                })

        results.append(result)

    # Build run properties with optional intelligence data
    run_properties = {
        "target": target,
        "grade": grade,
        "total_score": data.get("total_score", 0),
    }
    # Truth layer — target validation state + scan metadata
    tv = data.get("target_validation")
    if tv:
        run_properties["target_validation"] = tv
    meta = data.get("scan_metadata")
    if meta:
        run_properties["scan_metadata"] = meta
    intel = data.get("intelligence")
    if intel:
        run_properties["intelligence"] = {
            "executive_risk_score": intel.get("executive_risk_score", 0),
            "exposure_score": intel.get("exposure_score", 0),
            "attack_paths_count": len(intel.get("attack_paths", [])),
            "cve_matches": intel.get("cve_matches", []),
            "cwe_matches": intel.get("cwe_matches", []),
        }

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReconPro",
                        "version": __version__,
                        "informationUri": "https://github.com/falconxa0-commits/reconpro",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": (data.get("scan_metadata") or {}).get(
                            "started_at", datetime.now(timezone.utc).isoformat()
                        ),
                    }
                ],
                "properties": run_properties,
            }
        ],
    }

    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return str(p.resolve())


def _severity_to_cvss(sev: str) -> str:
    """Map ReconPro severity to a CVSS-like string for SARIF properties."""
    return {
        "critical": "9.0",
        "high": "7.5",
        "medium": "5.0",
        "low": "2.5",
        "info": "0.0",
    }.get(sev, "0.0")


# ── Markdown export ──────────────────────────────────────────────────


def export_markdown(data: Dict[str, Any], output_path: str) -> str:
    """Export scan results as a Markdown report."""
    data = _normalize(data)
    findings = data.get("findings", [])
    target = data.get("target", "Unknown")
    score = data.get("total_score", 0)
    grade = data.get("grade", "N/A")
    sc = data.get("severity_counts", {})
    modules = data.get("modules_run", [])
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Grade badge
    badge_colors = {
        "A+": "brightgreen", "A": "green", "B": "yellow",
        "C": "red", "D": "orange", "F": "red",
    }
    bc = badge_colors.get(grade, "lightgrey")
    badge = f"![ReconPro {grade}](https://img.shields.io/badge/ReconPro-{grade}-{bc}?style=for-the-badge&labelColor=000000)"

    lines: List[str] = []
    lines.append(f"# ReconPro Security Report\n")
    lines.append(f"{badge}\n")
    lines.append(f"**Target:** `{target}`  ")
    lines.append(f"**Score:** {score}/100  ")
    lines.append(f"**Grade:** {grade}  ")
    # Truth layer — target validation state + scan metadata
    tv = data.get("target_validation") or {}
    if tv:
        state = tv.get("state", "UNKNOWN")
        lines.append(f"**Target State:** `{state}`  ")
        if state != "VERIFIED_TARGET":
            reason = (tv.get("details") or {}).get("reason", "")
            if reason:
                lines.append(f"**Validation:** {reason}  ")
    meta = data.get("scan_metadata") or {}
    scan_ts = (meta.get("started_at") or "").replace("T", " ").split(".")[0]
    lines.append(f"**Generated:** {ts}  ")
    if scan_ts:
        lines.append(f"**Scan Started:** {scan_ts} UTC  ")
    lines.append(f"---\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        c = sc.get(sev, 0)
        lines.append(f"| {sev.capitalize()} | {c} |")
    lines.append(f"| **Total** | **{len(findings)}** |\n")

    # Modules
    if modules:
        lines.append("## Modules Run\n")
        lines.append(", ".join(f"`{m}`" for m in modules) + "\n")

    # Findings table sorted by severity
    lines.append("## Findings\n")
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEV_ORDER.get(f.get("severity", "info").lower(), 99),
    )

    if sorted_findings:
        lines.append("| # | Severity | Category | Finding | Module | Conf. | Pts |")
        lines.append("|---|----------|----------|---------|--------|-------|-----|")
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "info").lower()
            title = f.get("title", "")
            cat = f.get("category", "")
            mod = f.get("module", "")
            pts = f.get("points_deducted", 0)
            conf = f.get("confidence", None)
            conf_s = f"{round(conf * 100)}%" if isinstance(conf, (int, float)) else "—"
            lines.append(f"| {i} | {sev} | `{cat}` | {title} | {mod} | {conf_s} | -{pts} |")
        lines.append("")
        # Evidence appendix — every finding must be reproducible
        lines.append("### Evidence\n")
        for i, f in enumerate(sorted_findings, 1):
            ev = (f.get("evidence") or "").strip()
            if ev:
                lines.append(f"{i}. `{ev[:300]}`")
        lines.append("")
    else:
        lines.append("> ✅ No findings. Target is clean.\n")

    # Module breakdown
    lines.append("## Module Breakdown\n")
    module_map: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        m = f.get("module", "unknown")
        module_map.setdefault(m, []).append(f)
    for mod, mod_findings in sorted(module_map.items()):
        lines.append(f"### {mod} ({len(mod_findings)} findings)\n")
        for f in mod_findings:
            lines.append(f"- **[{f.get('severity', 'info').upper()}]** {f.get('title', '')}")
        lines.append("")

    # Remediation
    lines.append("## Remediation\n")
    remediation_seen: set = set()
    for f in sorted_findings:
        sev = f.get("severity", "info").lower()
        if sev in ("info", "low"):
            continue
        rem = f.get("remediation", "")
        if rem and rem not in remediation_seen:
            remediation_seen.add(rem)
            lines.append(f"- {rem}")
    if not remediation_seen:
        lines.append("> No critical/high remediation actions needed.\n")
    lines.append("")
    # Intelligence section
    intel = data.get("intelligence")
    if intel and (intel.get("attack_paths") or intel.get("cve_matches") or intel.get("mitre_techniques")):
        lines.append("## Intelligence Analysis\n")
        # Composite scores
        for score_name in ["executive_risk_score", "exposure_score", "mission_impact_score", "infrastructure_health_score", "threat_confidence_index"]:
            val = intel.get(score_name, 0)
            label = score_name.replace("_", " ").title()
            lines.append(f"- **{label}:** {val}/100")
        lines.append("")
        # Attack paths
        if intel.get("attack_paths"):
            lines.append("### Attack Paths Detected\n")
            for i, path in enumerate(intel["attack_paths"][:10], 1):
                lines.append(f"{i}. {path.get('description', path.get('steps', 'Unknown path'))}")
            lines.append("")
        # CVE matches
        if intel.get("cve_matches"):
            lines.append(f"### CVE Matches: {', '.join(intel['cve_matches'][:20])}\n")
        # MITRE techniques
        if intel.get("mitre_techniques"):
            lines.append("### MITRE ATT&CK Techniques\n")
            for t in intel["mitre_techniques"][:15]:
                tid = t.get("technique_id", t.get("id", ""))
                tname = t.get("technique_name", t.get("name", ""))
                lines.append(f"- {tid}: {tname}")
            lines.append("")
    lines.append(f"---\n*Generated by ReconPro v{__version__}*\n")

    md_content = "\n".join(lines)
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(md_content, encoding="utf-8")
    return str(p.resolve())


# ── JSON export ──────────────────────────────────────────────────────


def export_json(data: Dict[str, Any], output_path: str) -> str:
    """Export scan results as pretty-printed JSON."""
    data = _normalize(data)
    # Include intelligence data if present
    intel = data.get("intelligence")
    if intel:
        data["intelligence"] = intel
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return str(p.resolve())


# ── HTML export ──────────────────────────────────────────────────────


def export_html(data: Dict[str, Any], output_path: str) -> str:
    """Export scan results as HTML with Chart.js visualizations.

    Phase F: delegates to the overhauled report generator.
    """
    data = _normalize(data)
    from .reports import generate_html_report
    return generate_html_report(data, output_path)


# ── PDF (print-ready HTML) export ────────────────────────────────────


def export_pdf(data: Dict[str, Any], output_path: str) -> str:
    """Generate a print-ready HTML file suitable for saving as PDF.

    Since we cannot use external PDF libraries, this produces a clean
    HTML file with @media print rules. The user can open it in a browser
    and use Ctrl+P / ⌘P to save as PDF.
    """
    data = _normalize(data)
    # Output print-ready HTML directly to the requested path.
    # Browsers will render it and users can Ctrl+P to save as PDF.

    # Reuse the markdown generator for content, then wrap in print HTML
    findings = data.get("findings", [])
    target = data.get("target", "Unknown")
    score = data.get("total_score", 0)
    grade = data.get("grade", "N/A")
    sc = data.get("severity_counts", {})
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    grade_colors = {
        "A+": "#2ecc71", "A": "#27ae60", "B": "#f1c40f",
        "C": "#e67e22", "D": "#e74c3c", "F": "#c0392b",
    }
    gc = grade_colors.get(grade, "#999")

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEV_ORDER.get(f.get("severity", "info").lower(), 99),
    )

    rows = ""
    for f in sorted_findings:
        sev = f.get("severity", "info").lower()
        sev_colors = {
            "critical": "#e74c3c", "high": "#e67e22",
            "medium": "#f1c40f", "low": "#2ecc71", "info": "#95a5a6",
        }
        color = sev_colors.get(sev, "#999")
        rows += (
            f'<tr><td style="color:{color};font-weight:600">{_html_module.escape(sev.upper())}</td>'
            f'<td>{_html_module.escape(str(f.get("title", "")))}</td>'
            f'<td>{_html_module.escape(str(f.get("category", "")))}</td>'
            f'<td>{_html_module.escape(str(f.get("module", "")))}</td>'
            f'<td>-{f.get("points_deducted", 0)}</td></tr>\n'
        )

    if not rows:
        rows = '<tr><td colspan="5" style="text-align:center;padding:30px;color:#2ecc71">No findings.</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconPro Report — {target}</title>
<style>
  @page {{ size: A4; margin: 20mm; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    font-family: 'Helvetica Neue', Arial, sans-serif;
    color: #1a1a1a; padding: 40px; max-width: 900px; margin: 0 auto;
    line-height: 1.6;
  }}
  h1 {{ font-size: 24px; margin-bottom: 4px; color: #111; }}
  .meta {{ color: #666; font-size: 13px; margin-bottom: 24px; }}
  .header {{ display:flex; align-items:center; gap:30px; padding:24px; background:#f8f9fa; border:1px solid #dee2e6; border-radius:8px; margin-bottom:20px; }}
  .score-circle {{ width:80px; height:80px; border-radius:50%; background:{gc}; color:#fff; display:flex; align-items:center; justify-content:center; font-size:28px; font-weight:800; flex-shrink:0; }}
  .header-info h2 {{ font-size:18px; color:#333; }}
  .header-info p {{ color:#666; font-size:13px; }}
  .stats {{ display:flex; gap:12px; margin-bottom:20px; }}
  .stat {{ flex:1; text-align:center; padding:12px; background:#f8f9fa; border:1px solid #dee2e6; border-radius:6px; }}
  .stat .num {{ font-size:24px; font-weight:700; }}
  .stat .lbl {{ font-size:11px; color:#666; text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:20px; }}
  th {{ text-align:left; padding:10px 12px; font-size:11px; text-transform:uppercase; color:#666; border-bottom:2px solid #dee2e6; background:#f8f9fa; }}
  td {{ padding:8px 12px; font-size:13px; border-bottom:1px solid #eee; }}
  tr:nth-child(even) {{ background:#fafafa; }}
  .footer {{ text-align:center; color:#999; font-size:11px; margin-top:40px; padding-top:20px; border-top:1px solid #eee; }}
  @media print {{ body {{ padding: 0; }} .no-print {{ display: none; }} }}
</style>
</head>
<body>
  <h1>ReconPro Security Report</h1>
  <p class="meta">Generated: {ts}</p>

  <div class="header">
    <div class="score-circle">{score}</div>
    <div class="header-info">
      <h2>{_html_module.escape(str(target))} &mdash; Grade {_html_module.escape(str(grade))}</h2>
      <p>Total findings: {len(findings)} | Critical: {sc.get('critical',0)} | High: {sc.get('high',0)} | Medium: {sc.get('medium',0)}</p>
      {_html_module.escape(str((data.get("target_validation") or {}).get("state", "")))}
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="num" style="color:#e74c3c">{sc.get('critical',0)}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num" style="color:#e67e22">{sc.get('high',0)}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" style="color:#f1c40f">{sc.get('medium',0)}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:#2ecc71">{sc.get('low',0)}</div><div class="lbl">Low</div></div>
    <div class="stat"><div class="num" style="color:#95a5a6">{sc.get('info',0)}</div><div class="lbl">Info</div></div>
  </div>

  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Module</th><th>Pts</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <div class="no-print" style="text-align:center;color:#999;font-size:12px;margin-top:20px">
    Use Ctrl+P / ⌘P to save this page as PDF
  </div>

  <div class="footer">Generated by ReconPro v{__version__} — Eleven Blades. One Target. One Verdict.</div>
</body>
</html>"""

    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html, encoding="utf-8")
    return str(p.resolve())


# ── Auto-detect format from extension ─────────────────────────────────


_FORMAT_MAP = {
    ".sarif": export_sarif,
    ".md": export_markdown,
    ".markdown": export_markdown,
    ".json": export_json,
    ".html": export_html,
    ".htm": export_html,
    ".pdf": export_pdf,
}


def export(data: Dict[str, Any], output_path: str, format: Optional[str] = None) -> str:
    """Export scan data to *output_path*, auto-detecting the format.

    If *format* is explicitly given (e.g. ``"sarif"``), it overrides
    the file extension.  Otherwise the format is inferred from the
    extension of *output_path*.

    Accepts both ``dict`` and :class:`ReconProResult`.

    Returns the absolute path of the written file.
    """
    data = _normalize(data)

    if format:
        ext = f".{format.lstrip('.')}"
    else:
        ext = Path(output_path).suffix.lower()

    exporter = _FORMAT_MAP.get(ext)
    if not exporter:
        # Default to JSON
        exporter = export_json

    return exporter(data, output_path)

"""Report generation — Chart.js-powered HTML reports.

Phase F: Complete overhaul with interactive Chart.js visualizations.
Generates a single self-contained HTML file with CDN-loaded Chart.js.

Charts included:
  - Score gauge (doughnut with animated center text)
  - Severity breakdown (doughnut with legend)
  - DREAD radar chart (aggregated risk dimensions)
  - Findings per module (vertical bar)
  - Points deducted per module (horizontal bar)
  - Category distribution (horizontal bar)
  - Severity stacked per module (stacked bar)
  - DREAD per top finding (grouped bar)

Visual features:
  - Glassmorphism cards with backdrop-blur
  - Gradient accent lines
  - Animated stat counters
  - Smooth scroll navigation
  - Executive summary panel
  - Responsive design

Colors pulled from unified theme system for consistency.
"""
from __future__ import annotations

import json
import math
import os
import html as _html_esc
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .theme import Theme
from .constants import __version__ as _VERSION
from .constants import __version__ as _VERSION


_report_theme = Theme.current()


# ── Chart.js CDN ────────────────────────────────────────────────────────

_CHARTJS_CDN = '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>'
_CHARTJS_DATE_ADAPTER = '<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>'


# ── DREAD Labels ───────────────────────────────────────────────────────

_DREAD_LABELS = ("damage", "reproducibility", "exploitability", "affected_users", "discoverability")
_DREAD_SHORT = ("Dmg", "Repro", "Exploit", "Users", "Disc")


# ── Helpers ─────────────────────────────────────────────────────────────


def _module_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings per module."""
    counts: Dict[str, int] = {}
    for f in findings:
        m = f.get("module", "unknown")
        counts[m] = counts.get(m, 0) + 1
    return counts


def _category_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings per category."""
    counts: Dict[str, int] = {}
    for f in findings:
        c = f.get("category", "general")
        counts[c] = counts.get(c, 0) + 1
    return counts


def _points_per_module(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Sum points deducted per module."""
    pts: Dict[str, int] = {}
    for f in findings:
        m = f.get("module", "unknown")
        pts[m] = pts.get(m, 0) + f.get("points_deducted", 0)
    return pts


def _severity_per_module(
    findings: List[Dict[str, Any]],
) -> Dict[str, Dict[str, int]]:
    """Count findings per module per severity."""
    matrix: Dict[str, Dict[str, int]] = {}
    for f in findings:
        m = f.get("module", "unknown")
        s = f.get("severity", "info").lower()
        matrix.setdefault(m, {})
        matrix[m][s] = matrix[m].get(s, 0) + 1
    return matrix


def _aggregate_dread(findings: List[Dict[str, Any]]) -> List[float]:
    """Aggregate DREAD components across all findings.

    Some modules store dread as a float (average score), others as a dict
    with component breakdowns. We handle both cases.

    Returns list of 5 floats: [damage, reproducibility, exploitability, affected_users, discoverability]
    Averaged across all findings that have dread data.
    """
    sums = [0.0] * 5
    counts = [0] * 5

    for f in findings:
        dread = f.get("dread_score") or f.get("dread")
        if dread is None:
            continue

        if isinstance(dread, dict):
            # Dict form: {"damage": 10, "reproducibility": 9, ...}
            for i, key in enumerate(_DREAD_LABELS):
                v = dread.get(key)
                if v is not None and isinstance(v, (int, float)):
                    sums[i] += float(v)
                    counts[i] += 1
        elif isinstance(dread, (int, float)):
            # Float form: overall DREAD score — distribute evenly
            val = float(dread)
            if val > 0:
                for i in range(5):
                    sums[i] += val
                    counts[i] += 1

    # Average each component
    avg = []
    for i in range(5):
        avg.append(round(sums[i] / counts[i], 1) if counts[i] > 0 else 0.0)
    return avg


def _top_finding_dread(findings: List[Dict[str, Any]], n: int = 8) -> List[Dict[str, Any]]:
    """Get top N findings with their DREAD breakdowns for grouped bar chart."""
    # Sort by severity, then by points deducted
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(
        findings,
        key=lambda f: (sev_order.get(f.get("severity", "info").lower(), 99), -f.get("points_deducted", 0)),
    )

    result = []
    for f in sorted_f[:n]:
        dread = f.get("dread_score") or f.get("dread")
        if isinstance(dread, dict):
            components = [dread.get(key, 0) for key in _DREAD_LABELS]
        elif isinstance(dread, (int, float)) and float(dread) > 0:
            # Distribute evenly
            val = float(dread)
            components = [val] * 5
        else:
            components = None

        if components:
            result.append({
                "title": f.get("title", "")[:30],
                "severity": f.get("severity", "info").lower(),
                "components": components,
            })
    return result


def _chart_colors(n: int, palette: str = "severity") -> List[str]:
    """Generate n distinct colors for charts."""
    if palette == "severity":
        base = [
            _report_theme.sev_hex("critical"),
            _report_theme.sev_hex("high"),
            _report_theme.sev_hex("medium"),
            _report_theme.sev_hex("low"),
            _report_theme.sev_hex("info"),
            "#8b5cf6",
            "#ec4899",
            "#14b8a6",
            "#f97316",
            "#6366f1",
            "#a3e635",
            "#22d3ee",
        ]
    elif palette == "dread":
        base = [
            "#ef4444",  # damage - red
            "#f97316",  # reproducibility - orange
            "#eab308",  # exploitability - yellow
            "#8b5cf6",  # affected users - purple
            "#06b6d4",  # discoverability - cyan
        ]
    else:
        base = [
            "#06b6d4", "#8b5cf6", "#f59e0b", "#10b981",
            "#ef4444", "#ec4899", "#6366f1", "#14b8a6",
            "#f97316", "#a3e635", "#22d3ee", "#e879f9",
        ]
    return [base[i % len(base)] for i in range(n)]


def _escape_js(s: str) -> str:
    """Escape a string for safe embedding in JS/JSON."""
    return json.dumps(s)


def _risk_posture(score: int, grade: str, sc: Dict[str, int]) -> Tuple[str, str]:
    """Determine executive risk posture label and description."""
    crit = sc.get("critical", 0)
    high = sc.get("high", 0)

    if score >= 90 and crit == 0 and high == 0:
        return ("Excellent", "Target demonstrates strong security posture with no critical or high-severity findings. Minor informational items may be addressed opportunistically.")
    elif score >= 75 and crit == 0:
        return ("Good", "Overall security posture is sound. A small number of high-severity findings should be prioritized for remediation to reach best-in-class standing.")
    elif score >= 50 and crit <= 2:
        return ("Moderate", "Target presents a moderate attack surface. Critical and high findings require immediate attention. A structured remediation plan is recommended.")
    elif score >= 25:
        return ("Elevated", "Significant security weaknesses detected across multiple categories. Exploit chain potential exists. Prioritize critical findings and conduct a focused remediation sprint.")
    else:
        return ("Critical", "Severe security posture with widespread vulnerabilities. Immediate containment and remediation is required before any production exposure. Consider a dedicated security engagement.")


# ── Chart Generators (return <script> blocks) ───────────────────────────


def _chart_score_gauge(score: int, grade: str, grade_color: str) -> str:
    """Doughnut chart showing score with animated center label."""
    remain = 100 - score
    return f'''
    <script>
      (function() {{
        const ctx = document.getElementById('chart-score-gauge').getContext('2d');
        new Chart(ctx, {{
          type: 'doughnut',
          data: {{
            labels: ['Score', 'Remaining'],
            datasets: [{{
              data: [{score}, {remain}],
              backgroundColor: ['{grade_color}', 'rgba(255,255,255,0.04)'],
              borderWidth: 0,
              cutout: '82%',
              borderRadius: 6,
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: true,
            animation: {{ animateRotate: true, duration: 1200, easing: 'easeOutQuart' }},
            plugins: {{
              legend: {{ display: false }},
              tooltip: {{ enabled: false }}
            }}
          }},
          plugins: [{{
            id: 'centerText',
            afterDraw(chart) {{
              const {{ ctx, width, height }} = chart;
              ctx.save();
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              const cy = height / 2;
              // Glow effect
              ctx.shadowColor = '{grade_color}';
              ctx.shadowBlur = 20;
              ctx.font = '800 48px "Inter", "SF Mono", system-ui, sans-serif';
              ctx.fillStyle = '#ffffff';
              ctx.fillText('{score}', width / 2, cy - 14);
              ctx.shadowBlur = 0;
              ctx.font = '700 20px "Inter", "SF Mono", system-ui, sans-serif';
              ctx.fillStyle = '{grade_color}';
              ctx.fillText('{grade}', width / 2, cy + 20);
              ctx.restore();
            }}
          }}]
        }});
      }})();
    </script>'''


def _chart_severity_doughnut(sc: Dict[str, int]) -> str:
    """Doughnut chart of severity distribution with custom center text."""
    labels = []
    values = []
    colors = []
    for sev in ("critical", "high", "medium", "low", "info"):
        v = sc.get(sev, 0)
        if v > 0:
            labels.append(sev.capitalize())
            values.append(v)
            colors.append(_report_theme.sev_hex(sev))

    if not values:
        return '<p style="color:{h_muted};text-align:center;padding:40px;font-size:13px">No findings to visualize.</p>'.format(h_muted="#555")

    total = sum(values)
    return f'''
    <script>
      (function() {{
        const ctx = document.getElementById('chart-severity').getContext('2d');
        new Chart(ctx, {{
          type: 'doughnut',
          data: {{
            labels: {json.dumps(labels)},
            datasets: [{{
              data: {json.dumps(values)},
              backgroundColor: {json.dumps(colors)},
              borderWidth: 0,
              cutout: '62%',
              borderRadius: 4,
              hoverOffset: 8,
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: true,
            cutout: '62%',
            animation: {{ animateRotate: true, duration: 1000, easing: 'easeOutQuart' }},
            plugins: {{
              legend: {{
                position: 'bottom',
                labels: {{
                  color: '#888', padding: 14, usePointStyle: true, pointStyleWidth: 8,
                  font: {{ size: 11, family: '"Inter", "SF Mono", system-ui, sans-serif' }}
                }}
              }},
              tooltip: {{
                backgroundColor: 'rgba(0,0,0,0.85)',
                titleFont: {{ family: '"Inter", system-ui', size: 12 }},
                bodyFont: {{ family: '"Inter", system-ui', size: 11 }},
                padding: 12, cornerRadius: 8, displayColors: true,
                callbacks: {{
                  label: function(ctx) {{
                    const pct = ((ctx.parsed / {total}) * 100).toFixed(1);
                    return ' ' + ctx.label + ': ' + ctx.parsed + ' (' + pct + '%)';
                  }}
                }}
              }}
            }}
          }},
          plugins: [{{
            id: 'severityCenter',
            afterDraw(chart) {{
              const {{ ctx, width, height }} = chart;
              ctx.save();
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.font = '800 28px "Inter", system-ui, sans-serif';
              ctx.fillStyle = '#ffffff';
              ctx.fillText('{total}', width / 2, height / 2 - 8);
              ctx.font = '500 11px "Inter", system-ui, sans-serif';
              ctx.fillStyle = '#666';
              ctx.fillText('TOTAL', width / 2, height / 2 + 14);
              ctx.restore();
            }}
          }}]
        }});
      }})();
    </script>'''


def _chart_dread_radar(dread_avg: List[float]) -> str:
    """Radar chart of aggregated DREAD scores."""
    has_data = any(v > 0 for v in dread_avg)
    if not has_data:
        return '<p style="color:#555;text-align:center;padding:40px;font-size:13px">No DREAD data available.</p>'

    return f'''
    <script>
      (function() {{
        const ctx = document.getElementById('chart-dread-radar').getContext('2d');
        new Chart(ctx, {{
          type: 'radar',
          data: {{
            labels: {json.dumps(list(_DREAD_SHORT))},
            datasets: [{{
              label: 'DREAD Average',
              data: {json.dumps(dread_avg)},
              backgroundColor: 'rgba(239, 68, 68, 0.12)',
              borderColor: '#ef4444',
              borderWidth: 2,
              pointBackgroundColor: '#ef4444',
              pointBorderColor: '#fff',
              pointBorderWidth: 1,
              pointRadius: 4,
              pointHoverRadius: 7,
              fill: true,
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: true,
            animation: {{ duration: 1000, easing: 'easeOutQuart' }},
            scales: {{
              r: {{
                beginAtZero: true,
                max: 10,
                ticks: {{
                  stepSize: 2, color: '#444', backdropColor: 'transparent',
                  font: {{ size: 9, family: '"SF Mono", monospace' }}
                }},
                grid: {{ color: 'rgba(255,255,255,0.06)' }},
                angleLines: {{ color: 'rgba(255,255,255,0.06)' }},
                pointLabels: {{
                  color: '#999', font: {{ size: 11, family: '"Inter", system-ui, sans-serif', weight: '500' }}
                }}
              }}
            }},
            plugins: {{
              legend: {{ display: false }},
              tooltip: {{
                backgroundColor: 'rgba(0,0,0,0.85)',
                titleFont: {{ family: '"Inter", system-ui', size: 12 }},
                bodyFont: {{ family: '"Inter", system-ui', size: 11 }},
                padding: 12, cornerRadius: 8,
                callbacks: {{
                  label: function(ctx) {{
                    return ' ' + ctx.label + ': ' + ctx.parsed.r + ' / 10';
                  }}
                }}
              }}
            }}
          }}
        }});
      }})();
    </script>'''


def _chart_module_bar(module_breakdown: Dict[str, int]) -> str:
    """Vertical bar chart of findings per module."""
    if not module_breakdown:
        return '<p style="color:#555;text-align:center;padding:40px;font-size:13px">No module data.</p>'

    sorted_mods = sorted(module_breakdown.items(), key=lambda x: x[1], reverse=True)[:12]
    labels = [m.upper() for m, _ in sorted_mods]
    values = [c for _, c in sorted_mods]
    colors = _chart_colors(len(labels))

    return f'''
    <script>
      (function() {{
        const ctx = document.getElementById('chart-modules').getContext('2d');
        new Chart(ctx, {{
          type: 'bar',
          data: {{
            labels: {json.dumps(labels)},
            datasets: [{{
              label: 'Findings',
              data: {json.dumps(values)},
              backgroundColor: {json.dumps(colors)},
              borderRadius: 6,
              borderSkipped: false,
              maxBarThickness: 40,
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'x',
            animation: {{ duration: 800, easing: 'easeOutQuart' }},
            scales: {{
              x: {{ ticks: {{ color: '#555', font: {{ size: 10, family: '"SF Mono", monospace' }} }}, grid: {{ display: false }} }},
              y: {{ beginAtZero: true, ticks: {{ color: '#555', stepSize: 1, font: {{ size: 10 }} }}, grid: {{ color: 'rgba(255,255,255,0.04)' }} }}
            }},
            plugins: {{
              legend: {{ display: false }},
              tooltip: {{
                backgroundColor: 'rgba(0,0,0,0.85)',
                titleFont: {{ family: '"Inter", system-ui', size: 12 }},
                bodyFont: {{ family: '"Inter", system-ui', size: 11 }},
                padding: 12, cornerRadius: 8,
              }}
            }}
          }}
        }});
      }})();
    </script>'''


def _chart_points_hbar(pts_per_mod: Dict[str, int]) -> str:
    """Horizontal bar chart of points deducted per module."""
    if not pts_per_mod:
        return ''

    sorted_mods = sorted(pts_per_mod.items(), key=lambda x: x[1], reverse=True)[:10]
    labels = [m.upper() for m, _ in sorted_mods]
    values = [p for _, p in sorted_mods]
    colors = [
        _report_theme.sev_hex("critical") if p > 20
        else _report_theme.sev_hex("high") if p > 10
        else _report_theme.sev_hex("medium") if p > 5
        else _report_theme.sev_hex("low")
        for p in values
    ]

    return f'''
    <script>
      (function() {{
        const ctx = document.getElementById('chart-points').getContext('2d');
        new Chart(ctx, {{
          type: 'bar',
          data: {{
            labels: {json.dumps(labels)},
            datasets: [{{
              label: 'Points Deducted',
              data: {json.dumps(values)},
              backgroundColor: {json.dumps(colors)},
              borderRadius: 6,
              borderSkipped: false,
              maxBarThickness: 24,
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            animation: {{ duration: 800, easing: 'easeOutQuart' }},
            scales: {{
              x: {{ beginAtZero: true, ticks: {{ color: '#555', font: {{ size: 10 }} }}, grid: {{ color: 'rgba(255,255,255,0.04)' }} }},
              y: {{ ticks: {{ color: '#888', font: {{ size: 11, family: '"SF Mono", monospace' }} }}, grid: {{ display: false }} }}
            }},
            plugins: {{
              legend: {{ display: false }},
              tooltip: {{
                backgroundColor: 'rgba(0,0,0,0.85)',
                padding: 12, cornerRadius: 8,
                callbacks: {{
                  label: function(ctx) {{ return ' -' + ctx.parsed.x + ' points'; }}
                }}
              }}
            }}
          }}
        }});
      }})();
    </script>'''


def _chart_category_hbar(cat_breakdown: Dict[str, int]) -> str:
    """Horizontal bar chart of findings per category."""
    if not cat_breakdown:
        return ''

    sorted_cats = sorted(cat_breakdown.items(), key=lambda x: x[1], reverse=True)[:10]
    labels = [c.replace("_", " ").title() for c, _ in sorted_cats]
    values = [v for _, v in sorted_cats]
    colors = _chart_colors(len(labels), palette="module")

    return f'''
    <script>
      (function() {{
        const ctx = document.getElementById('chart-categories').getContext('2d');
        new Chart(ctx, {{
          type: 'bar',
          data: {{
            labels: {json.dumps(labels)},
            datasets: [{{
              label: 'Findings',
              data: {json.dumps(values)},
              backgroundColor: {json.dumps(colors)},
              borderRadius: 6,
              borderSkipped: false,
              maxBarThickness: 24,
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            animation: {{ duration: 800, easing: 'easeOutQuart' }},
            scales: {{
              x: {{ beginAtZero: true, ticks: {{ color: '#555', stepSize: 1, font: {{ size: 10 }} }}, grid: {{ color: 'rgba(255,255,255,0.04)' }} }},
              y: {{ ticks: {{ color: '#888', font: {{ size: 11, family: '"Inter", system-ui' }} }}, grid: {{ display: false }} }}
            }},
            plugins: {{
              legend: {{ display: false }},
              tooltip: {{
                backgroundColor: 'rgba(0,0,0,0.85)',
                padding: 12, cornerRadius: 8,
              }}
            }}
          }}
        }});
      }})();
    </script>'''


def _chart_severity_stacked_bar(sev_matrix: Dict[str, Dict[str, int]]) -> str:
    """Stacked bar chart: severity breakdown per module."""
    if not sev_matrix:
        return ''

    all_modules = sorted(sev_matrix.keys(), key=lambda m: sum(sev_matrix[m].values()), reverse=True)[:10]
    severities = ["critical", "high", "medium", "low", "info"]
    sev_colors = {s: _report_theme.sev_hex(s) for s in severities}

    datasets = []
    for sev in severities:
        data = [sev_matrix.get(m, {}).get(sev, 0) for m in all_modules]
        if any(d > 0 for d in data):
            datasets.append({
                "label": sev.capitalize(),
                "data": data,
                "backgroundColor": sev_colors[sev],
                "borderRadius": 3,
                "borderSkipped": False,
            })

    if not datasets:
        return ''

    labels = [m.upper() for m in all_modules]
    return f'''
    <script>
      (function() {{
        const ctx = document.getElementById('chart-stacked').getContext('2d');
        new Chart(ctx, {{
          type: 'bar',
          data: {{
            labels: {json.dumps(labels)},
            datasets: {json.dumps(datasets)}
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: true,
            animation: {{ duration: 800, easing: 'easeOutQuart' }},
            scales: {{
              x: {{ stacked: true, ticks: {{ color: '#555', font: {{ size: 10, family: '"SF Mono", monospace' }} }}, grid: {{ display: false }} }},
              y: {{ stacked: true, beginAtZero: true, ticks: {{ color: '#555', stepSize: 1, font: {{ size: 10 }} }}, grid: {{ color: 'rgba(255,255,255,0.04)' }} }}
            }},
            plugins: {{
              legend: {{
                position: 'bottom',
                labels: {{ color: '#888', padding: 12, usePointStyle: true, pointStyleWidth: 8, font: {{ size: 11, family: '"Inter", system-ui' }} }}
              }},
              tooltip: {{
                backgroundColor: 'rgba(0,0,0,0.85)',
                padding: 12, cornerRadius: 8,
              }}
            }}
          }}
        }});
      }})();
    </script>'''


def _chart_dread_grouped_bar(top_dread: List[Dict[str, Any]]) -> str:
    """Grouped bar chart showing DREAD breakdown per top finding."""
    if not top_dread:
        return ''

    labels = [item["title"] for item in top_dread]
    dread_colors = _chart_colors(5, palette="dread")

    datasets = []
    for i, short_label in enumerate(_DREAD_SHORT):
        data = [item["components"][i] for item in top_dread]
        datasets.append({
            "label": short_label,
            "data": data,
            "backgroundColor": dread_colors[i],
            "borderRadius": 3,
            "borderSkipped": False,
            "maxBarThickness": 12,
        })

    return f'''
    <script>
      (function() {{
        const ctx = document.getElementById('chart-dread-grouped').getContext('2d');
        new Chart(ctx, {{
          type: 'bar',
          data: {{
            labels: {json.dumps(labels)},
            datasets: {json.dumps(datasets)}
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            animation: {{ duration: 800, easing: 'easeOutQuart' }},
            scales: {{
              x: {{
                ticks: {{ color: '#888', font: {{ size: 10, family: '"Inter", system-ui', weight: '500' }}, maxRotation: 45, minRotation: 0 }},
                grid: {{ display: false }}
              }},
              y: {{
                beginAtZero: true, max: 10,
                ticks: {{ color: '#555', stepSize: 2, font: {{ size: 10 }} }},
                grid: {{ color: 'rgba(255,255,255,0.04)' }}
              }}
            }},
            plugins: {{
              legend: {{
                position: 'bottom',
                labels: {{ color: '#888', padding: 12, usePointStyle: true, pointStyleWidth: 8, font: {{ size: 10, family: '"Inter", system-ui' }} }}
              }},
              tooltip: {{
                backgroundColor: 'rgba(0,0,0,0.85)',
                padding: 12, cornerRadius: 8,
                callbacks: {{
                  label: function(ctx) {{ return ' ' + ctx.dataset.label + ': ' + ctx.parsed.y + ' / 10'; }}
                }}
              }}
            }}
          }}
        }});
      }})();
    </script>'''


# ── Main Report Generator ───────────────────────────────────────────────


def generate_html_report(data: Dict[str, Any], output_path: str = "") -> str:
    """Generate a Chart.js-powered HTML report. Returns file path.

    Phase F: Complete overhaul with interactive charts:
    - Score gauge (doughnut with animated center text)
    - Severity breakdown (doughnut with total center)
    - DREAD radar chart (aggregated risk dimensions)
    - Findings per module (vertical bar)
    - Points deducted per module (horizontal bar)
    - Category distribution (horizontal bar)
    - Severity stacked per module (stacked bar)
    - DREAD per top finding (grouped bar)
    - Executive summary panel with risk posture
    - Animated stat counters
    - Glassmorphism card design
    - Smooth scroll navigation
    """
    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = data.get("target", "scan").replace("/", "_").replace(":", "")[:30]
        output_path = f"reconpro_report_{target}_{ts}.html"

    score = data.get("total_score", 0)
    grade = data.get("grade", "N/A")
    target = data.get("target", "Unknown")
    findings = data.get("findings", [])
    sc = data.get("severity_counts", {})
    modules = data.get("modules_run", [])
    badge = data.get("badge_markdown", "")
    scan_time = data.get("scan_time", "")

    # Version
    try:
        from .constants import __version__ as _v
        version_str = _v
    except Exception:
        version_str = "unknown"

    # Theme colors
    grade_color = _report_theme.grade_color(grade)
    html_style = _report_theme.html_style()
    h_body_bg = html_style.get("body_bg", "#0a0a0f")
    h_card_bg = html_style.get("card_bg", "#111118")
    h_border = html_style.get("border", "#1a1a2e")
    h_text = html_style.get("text", "#e0e0e0")
    h_muted = html_style.get("muted", "#666666")
    h_crit_color = _report_theme.sev_hex("critical")
    h_high_color = _report_theme.sev_hex("high")
    h_med_color = _report_theme.sev_hex("medium")
    h_low_color = _report_theme.sev_hex("low")
    h_info_color = _report_theme.sev_hex("info")
    h_accent = _report_theme.CYAN if hasattr(_report_theme, 'CYAN') else "#06b6d4"

    # Data processing
    mod_counts = _module_breakdown(findings)
    cat_counts = _category_breakdown(findings)
    pts_mod = _points_per_module(findings)
    sev_matrix = _severity_per_module(findings)
    dread_avg = _aggregate_dread(findings)
    top_dread = _top_finding_dread(findings, n=8)
    total_findings = len(findings)
    total_pts = sum(f.get("points_deducted", 0) for f in findings)
    risk_label, risk_desc = _risk_posture(score, grade, sc)

    # ── Chart scripts ──
    chart_score = _chart_score_gauge(score, grade, grade_color)
    chart_severity = _chart_severity_doughnut(sc)
    chart_dread_radar = _chart_dread_radar(dread_avg)
    chart_modules = _chart_module_bar(mod_counts)
    chart_points = _chart_points_hbar(pts_mod)
    chart_categories = _chart_category_hbar(cat_counts)
    chart_stacked = _chart_severity_stacked_bar(sev_matrix)
    chart_dread_grouped = _chart_dread_grouped_bar(top_dread)

    # ── Findings table rows ──
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: _sev_order.get(
            f.get("severity", "info").lower(), 99
        ),
    )
    findings_rows = ""
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "info").lower()
        color = _report_theme.sev_hex(sev)
        evidence = f.get("evidence", "")
        evidence_short = (evidence[:80] + "..." if len(evidence) > 80 else evidence) if evidence else ""
        dread_val = f.get("dread_score") or f.get("dread", 0)
        dread_display = f"{dread_val:.1f}" if isinstance(dread_val, (int, float)) and not isinstance(dread_val, bool) else (f"{sum(dread_val.values())/5:.1f}" if isinstance(dread_val, dict) else "-")
        evidence_cell = f'<td style="color:{h_muted};font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{evidence_short}</td>' if evidence_short else '<td></td>'
        findings_rows += f'''
        <tr>
          <td style="color:#555;width:36px;font-size:11px">{i}</td>
          <td style="color:{color};font-weight:700;text-transform:uppercase;font-size:10px;width:65px;letter-spacing:0.5px">{_html_esc.escape(sev)}</td>
          <td style="color:{h_muted};font-size:11px;width:80px">{_html_esc.escape(str(f.get("module", "")))}</td>
          <td style="color:{h_text};font-size:12px">{_html_esc.escape(str(f.get("title", "")))}</td>
          <td style="color:{h_muted};font-size:11px;width:110px">{_html_esc.escape(str(f.get("category", "")))}</td>
          <td style="text-align:center;color:{h_med_color};width:36px;font-size:12px;font-weight:600">-{f.get("points_deducted", 0)}</td>
          <td style="text-align:center;color:{h_accent};width:40px;font-size:11px">{_html_esc.escape(str(dread_display))}</td>
          {_html_esc.escape(evidence_short) if evidence_short else ""}
        </tr>'''

    if not findings_rows:
        findings_rows = f'<tr><td colspan="8" style="text-align:center;color:{h_low_color};padding:60px 20px;font-size:14px">No findings detected. Target appears clean.</td></tr>'

    # ── Module tags ──
    module_tags = "".join(f'<span class="module-tag">{m}</span>' for m in modules)

    # ── Top risk findings (critical + high) ──
    top_risk = [f for f in sorted_findings if f.get("severity", "").lower() in ("critical", "high")]
    risk_items = ""
    for f in top_risk[:6]:
        sev = f.get("severity", "").lower()
        color = _report_theme.sev_hex(sev)
        pts = f.get("points_deducted", 0)
        risk_items += f'''
        <div class="risk-item">
          <span class="risk-sev" style="background:{color}">{_html_esc.escape(sev.upper()[:1])}</span>
          <span class="risk-title">{_html_esc.escape(str(f.get("title", "")))}</span>
          <span class="risk-module">{_html_esc.escape(str(f.get("module", "")))}</span>
          <span class="risk-pts" style="color:{color}">-{pts}</span>
        </div>'''
    if not risk_items:
        risk_items = f'<p style="color:{h_low_color};padding:20px;text-align:center;font-size:13px">No critical or high findings detected.</p>'

    # ── Show/hide chart containers based on data availability ──
    has_modules = bool(mod_counts)
    has_points = bool(pts_mod)
    has_categories = bool(cat_counts) and len(cat_counts) > 1
    has_stacked = bool(sev_matrix)
    has_dread_radar = any(v > 0 for v in dread_avg)
    has_dread_grouped = bool(top_dread)

    # ── DREAD average display ──
    dread_overall = round(sum(dread_avg) / 5, 1) if any(v > 0 for v in dread_avg) else 0.0

    # ── Pre-build conditional chart blocks (nested f-strings don't interpolate in ternaries) ──
    _block_dread_radar = f'<div class="chart-card animate-in delay-1"><div class="chart-title">DREAD Risk Radar</div><div class="chart-wrap medium"><canvas id="chart-dread-radar"></canvas></div>{chart_dread_radar}</div>' if has_dread_radar else ''
    _block_points = f'<div class="chart-card animate-in delay-2"><div class="chart-title">Points Deducted per Module</div><div class="chart-wrap tall"><canvas id="chart-points"></canvas></div>{chart_points}</div>' if has_points else ''
    _block_categories = f'<div class="chart-card animate-in delay-1"><div class="chart-title">Category Breakdown</div><div class="chart-wrap tall"><canvas id="chart-categories"></canvas></div>{chart_categories}</div>' if has_categories else ''
    _block_stacked = f'<div class="chart-card animate-in delay-2"><div class="chart-title">Severity Breakdown by Module</div><div class="chart-wrap"><canvas id="chart-stacked"></canvas></div>{chart_stacked}</div>' if has_stacked else ''
    _block_dread_grouped = f'<div class="chart-card full-width animate-in" style="margin-bottom:24px"><div class="chart-title">DREAD Breakdown by Top Findings</div><div class="chart-wrap tall"><canvas id="chart-dread-grouped"></canvas></div>{chart_dread_grouped}</div>' if has_dread_grouped else ''
    _block_risk = f'<div class="risk-panel animate-in" id="risk"><div class="chart-title">Top Risk Findings</div>{risk_items}</div>' if top_risk else ''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconPro Report \u2014 {target}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
{_CHARTJS_CDN}
{_CHARTJS_DATE_ADAPTER}
<style>
  :root {{
    --bg: {h_body_bg};
    --card: {h_card_bg};
    --border: {h_border};
    --text: {h_text};
    --muted: {h_muted};
    --accent: {h_accent};
    --grade: {grade_color};
    --critical: {h_crit_color};
    --high: {h_high_color};
    --medium: {h_med_color};
    --low: {h_low_color};
    --info: {h_info_color};
    --glass: rgba(255, 255, 255, 0.03);
    --glass-border: rgba(255, 255, 255, 0.06);
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  html {{ scroll-behavior: smooth; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', 'SF Mono', system-ui, -apple-system, sans-serif;
    padding: 0;
    line-height: 1.6;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }}

  .container {{ max-width: 1280px; margin: 0 auto; padding: 24px 32px 60px; }}

  /* ── Navigation ─────────────────────────────────────── */
  .nav {{
    position: sticky; top: 0; z-index: 50;
    background: rgba(10, 10, 15, 0.8);
    backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid var(--glass-border);
    padding: 12px 32px;
    display: flex; align-items: center; gap: 24px;
    font-size: 12px;
  }}
  .nav-brand {{ font-weight: 800; font-size: 13px; color: #fff; letter-spacing: 2px; flex-shrink: 0; }}
  .nav-brand span {{ color: var(--accent); }}
  .nav-links {{ display: flex; gap: 4px; flex-wrap: wrap; }}
  .nav-links a {{
    color: var(--muted); text-decoration: none; padding: 4px 10px;
    border-radius: 6px; font-size: 11px; font-weight: 500;
    transition: all 0.2s;
  }}
  .nav-links a:hover {{ color: #fff; background: var(--glass); }}

  /* ── Header ──────────────────────────────────────────── */
  .report-header {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 36px 40px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 20px;
    margin-top: 24px;
    margin-bottom: 24px;
    gap: 32px;
    position: relative;
    overflow: hidden;
  }}
  .report-header::before {{
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, var(--accent), var(--grade), var(--accent));
    opacity: 0.8;
  }}
  .brand {{ flex-shrink: 0; }}
  .brand h1 {{ font-size: 20px; color: #fff; letter-spacing: 3px; font-weight: 900; }}
  .brand .ver {{ color: var(--muted); font-size: 11px; margin-top: 4px; font-weight: 500; }}
  .header-center {{ flex: 1; text-align: center; min-width: 0; }}
  .target-name {{ font-size: 28px; color: #fff; font-weight: 800; margin-bottom: 6px; word-break: break-all; letter-spacing: -0.5px; }}
  .scan-meta {{ color: var(--muted); font-size: 12px; font-weight: 500; }}
  .header-right {{ flex-shrink: 0; width: 180px; height: 180px; }}

  /* ── Stat cards ─────────────────────────────────────── */
  .stat-grid {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 12px; margin-bottom: 24px; }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px 14px;
    text-align: center;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    position: relative;
    overflow: hidden;
  }}
  .stat-card::after {{
    content: ''; position: absolute; bottom: 0; left: 20%; right: 20%; height: 2px;
    background: currentColor; opacity: 0.3; border-radius: 2px;
    transition: all 0.3s;
  }}
  .stat-card:hover {{ transform: translateY(-3px); border-color: var(--glass-border); }}
  .stat-card:hover::after {{ left: 10%; right: 10%; opacity: 0.6; }}
  .stat-num {{ font-size: 30px; font-weight: 900; font-family: 'JetBrains Mono', 'SF Mono', monospace; line-height: 1; }}
  .stat-label {{ font-size: 10px; color: var(--muted); text-transform: uppercase; margin-top: 8px; letter-spacing: 1.2px; font-weight: 600; }}

  /* ── Executive Summary ───────────────────────────────── */
  .exec-summary {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px 32px;
    margin-bottom: 24px;
    display: flex;
    gap: 24px;
    align-items: flex-start;
    position: relative;
  }}
  .exec-badge {{
    flex-shrink: 0;
    width: 72px; height: 72px;
    border-radius: 16px;
    display: flex; align-items: center; justify-content: center;
    font-size: 13px; font-weight: 800;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 1px;
    line-height: 1.2;
    text-align: center;
    padding: 8px;
  }}
  .exec-content {{ flex: 1; min-width: 0; }}
  .exec-title {{ font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 6px; }}
  .exec-desc {{ font-size: 13px; color: var(--muted); line-height: 1.7; }}
  .exec-desc strong {{ color: var(--text); }}

  /* ── Chart grid ──────────────────────────────────────── */
  .chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }}
  .chart-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    transition: border-color 0.3s;
  }}
  .chart-card:hover {{ border-color: var(--glass-border); }}
  .chart-card.full-width {{ grid-column: 1 / -1; }}
  .chart-title {{
    font-size: 11px; color: var(--muted); text-transform: uppercase;
    letter-spacing: 1.5px; margin-bottom: 20px; padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
    font-weight: 700;
    display: flex; align-items: center; gap: 8px;
  }}
  .chart-title::before {{
    content: ''; width: 8px; height: 8px; border-radius: 2px;
    background: var(--accent); flex-shrink: 0;
  }}
  .chart-wrap {{ position: relative; width: 100%; }}
  .chart-wrap.tall {{ height: 320px; }}
  .chart-wrap.medium {{ height: 280px; }}

  /* ── Risk panel ──────────────────────────────────────── */
  .risk-panel {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px 28px;
    margin-bottom: 24px;
  }}
  .risk-item {{
    display: flex; align-items: center; gap: 14px;
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
    transition: background 0.2s;
  }}
  .risk-item:last-child {{ border-bottom: none; }}
  .risk-item:hover {{ background: var(--glass); margin: 0 -12px; padding-left: 12px; padding-right: 12px; border-radius: 8px; }}
  .risk-sev {{
    width: 30px; height: 30px; border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    color: #fff; font-size: 12px; font-weight: 900; flex-shrink: 0;
  }}
  .risk-title {{ flex: 1; font-size: 13px; color: var(--text); font-weight: 500; }}
  .risk-module {{ color: var(--muted); font-size: 11px; font-weight: 500; flex-shrink: 0; }}
  .risk-pts {{ font-size: 12px; font-weight: 700; flex-shrink: 0; font-family: 'JetBrains Mono', monospace; }}

  /* ── Findings table ──────────────────────────────────── */
  .section-title {{
    font-size: 13px; color: #fff; margin: 28px 0 14px;
    padding-left: 14px;
    border-left: 3px solid var(--grade);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    font-weight: 700;
  }}
  table {{
    width: 100%; border-collapse: collapse;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
  }}
  th {{
    text-align: left; padding: 14px 16px;
    font-size: 10px; text-transform: uppercase;
    color: var(--muted); border-bottom: 1px solid var(--border);
    background: var(--bg);
    letter-spacing: 1.2px;
    font-weight: 700;
    position: sticky; top: 0;
  }}
  td {{ padding: 12px 16px; font-size: 12px; border-bottom: 1px solid var(--border); }}
  tr:last-child td {{ border-bottom: none; }}
  tr {{ transition: background 0.15s; }}
  tr:hover {{ background: rgba(255,255,255,0.02); }}

  /* ── Module tags ─────────────────────────────────────── */
  .modules {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; justify-content: center; }}
  .module-tag {{
    background: var(--glass);
    border: 1px solid var(--glass-border);
    color: var(--muted);
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }}

  /* ── Badge box ───────────────────────────────────────── */
  .badge-box {{
    margin-top: 28px; padding: 20px 24px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
  }}
  .badge-box .label {{ color: var(--muted); font-size: 10px; text-transform: uppercase; margin-bottom: 10px; letter-spacing: 1.5px; font-weight: 700; }}
  .badge-box code {{ color: var(--accent); font-size: 13px; word-break: break-all; font-family: 'JetBrains Mono', monospace; }}

  /* ── Footer ──────────────────────────────────────────── */
  .footer {{
    text-align: center; color: var(--muted);
    font-size: 11px; margin-top: 48px; padding-top: 24px;
    border-top: 1px solid var(--border);
    font-weight: 500;
    letter-spacing: 0.5px;
  }}
  .footer strong {{ color: #fff; font-weight: 700; }}

  /* ── Animations ──────────────────────────────────────── */
  @keyframes fadeInUp {{
    from {{ opacity: 0; transform: translateY(16px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}
  .animate-in {{ animation: fadeInUp 0.5s ease-out forwards; opacity: 0; }}
  .delay-1 {{ animation-delay: 0.05s; }}
  .delay-2 {{ animation-delay: 0.10s; }}
  .delay-3 {{ animation-delay: 0.15s; }}
  .delay-4 {{ animation-delay: 0.20s; }}
  .delay-5 {{ animation-delay: 0.25s; }}
  .delay-6 {{ animation-delay: 0.30s; }}
  .delay-7 {{ animation-delay: 0.35s; }}

  /* ── Responsive ──────────────────────────────────────── */
  @media (max-width: 1024px) {{
    .stat-grid {{ grid-template-columns: repeat(4, 1fr); }}
  }}
  @media (max-width: 768px) {{
    .container {{ padding: 16px; }}
    .report-header {{ flex-direction: column; text-align: center; padding: 28px 20px; }}
    .stat-grid {{ grid-template-columns: repeat(3, 1fr); gap: 8px; }}
    .chart-grid {{ grid-template-columns: 1fr; }}
    .header-right {{ width: 160px; height: 160px; }}
    .nav {{ padding: 10px 16px; gap: 12px; }}
    .nav-links {{ display: none; }}
    .exec-summary {{ flex-direction: column; align-items: center; text-align: center; }}
    .target-name {{ font-size: 22px; }}
    table {{ font-size: 11px; }}
    th, td {{ padding: 8px 10px; }}
    .risk-module {{ display: none; }}
  }}
  @media (max-width: 480px) {{
    .stat-grid {{ grid-template-columns: repeat(2, 1fr); }}
  }}

  /* ── Print styles ────────────────────────────────────── */
  @media print {{
    .nav {{ display: none; }}
    body {{ background: #fff; color: #111; padding: 0; }}
    .container {{ padding: 20px; }}
    .stat-card, .chart-card, .risk-panel, .exec-summary, .report-header, table, .badge-box {{
      background: #fff; border-color: #ddd; break-inside: avoid;
    }}
    .stat-num, .target-name, .brand h1, .exec-title {{ color: #111; }}
    .stat-label, .scan-meta, .ver, .chart-title, .risk-module, .module-tag {{ color: #666; }}
    .report-header::before {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
  }}
</style>
</head>
<body>

<!-- Sticky Navigation -->
<nav class="nav">
  <div class="nav-brand">RECON<span>PRO</span></div>
  <div class="nav-links">
    <a href="#summary">Summary</a>
    <a href="#charts">Charts</a>
    <a href="#dread">DREAD</a>
    <a href="#risk">Risk</a>
    <a href="#findings">Findings</a>
  </div>
</nav>

<div class="container">

  <!-- Header -->
  <div class="report-header animate-in">
    <div class="brand">
      <h1>RECONPRO</h1>
      <div class="ver">v{version_str} \u00b7 Security Assessment</div>
    </div>
    <div class="header-center">
      <div class="target-name">{target}</div>
      <div class="scan-meta">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} \u00b7 {total_findings} findings \u00b7 {len(modules)} modules \u00b7 -{total_pts} points</div>
      <div class="modules">{module_tags}</div>
    </div>
    <div class="header-right">
      <canvas id="chart-score-gauge"></canvas>
    </div>
  </div>
  {chart_score}

  <!-- Stat cards -->
  <div class="stat-grid" id="summary">
    <div class="stat-card animate-in delay-1"><div class="stat-num" style="color:var(--critical)">{sc.get("critical",0)}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card animate-in delay-2"><div class="stat-num" style="color:var(--high)">{sc.get("high",0)}</div><div class="stat-label">High</div></div>
    <div class="stat-card animate-in delay-3"><div class="stat-num" style="color:var(--medium)">{sc.get("medium",0)}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card animate-in delay-4"><div class="stat-num" style="color:var(--low)">{sc.get("low",0)}</div><div class="stat-label">Low</div></div>
    <div class="stat-card animate-in delay-5"><div class="stat-num" style="color:var(--info)">{sc.get("info",0)}</div><div class="stat-label">Info</div></div>
    <div class="stat-card animate-in delay-6"><div class="stat-num" style="color:var(--grade)">{score}</div><div class="stat-label">Score</div></div>
    <div class="stat-card animate-in delay-7"><div class="stat-num" style="color:var(--accent)">{dread_overall}</div><div class="stat-label">DREAD</div></div>
  </div>

  <!-- Executive Summary -->
  <div class="exec-summary animate-in" id="exec">
    <div class="exec-badge" style="background:linear-gradient(135deg, {grade_color}, {grade_color}88)">{risk_label}</div>
    <div class="exec-content">
      <div class="exec-title">Risk Posture: {risk_label}</div>
      <div class="exec-desc">{risk_desc}</div>
    </div>
  </div>

  <!-- Charts row 1: severity doughnut + module bar -->
  <div class="chart-grid" id="charts">
    <div class="chart-card animate-in delay-1">
      <div class="chart-title">Severity Distribution</div>
      <div class="chart-wrap"><canvas id="chart-severity"></canvas></div>
      {chart_severity}
    </div>
    <div class="chart-card animate-in delay-2">
      <div class="chart-title">Findings per Module</div>
      <div class="chart-wrap"><canvas id="chart-modules"></canvas></div>
      {chart_modules}
    </div>
  </div>

  <!-- Charts row 2: DREAD radar + points hbar -->
  <div class="chart-grid" id="dread">
    {_block_dread_radar}
    {_block_points}
  </div>

  <!-- Top Risk -->
  {_block_risk}

  <!-- Charts row 3: categories + stacked -->
  <div class="chart-grid">
    {_block_categories}
    {_block_stacked}
  </div>

  <!-- DREAD per top finding -->
  {_block_dread_grouped}

  <!-- Findings table -->
  <div class="section-title" id="findings">All Findings ({total_findings})</div>
  <table>
    <thead><tr><th>#</th><th>Sev</th><th>Module</th><th>Finding</th><th>Category</th><th>Pts</th><th>DREAD</th><th>Evidence</th></tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>

  <!-- Badge -->
  <div class="badge-box">
    <div class="label">GitHub README Badge</div>
    <code>{badge}</code>
  </div>

  <div class="footer">Generated by <strong>ReconPro</strong> v{version_str} \u2014 Eleven Blades. One Target. One Verdict.</div>
</div>

<script>
  // Animate stat counters on load
  document.addEventListener('DOMContentLoaded', function() {{
    document.querySelectorAll('.stat-num').forEach(function(el) {{
      const target = parseFloat(el.textContent);
      if (isNaN(target)) return;
      const isFloat = el.textContent.includes('.');
      const duration = 1200;
      const start = performance.now();
      el.textContent = '0';

      function update(now) {{
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        // easeOutQuart
        const eased = 1 - Math.pow(1 - progress, 4);
        const current = target * eased;
        el.textContent = isFloat ? current.toFixed(1) : Math.round(current);
        if (progress < 1) requestAnimationFrame(update);
      }}
      requestAnimationFrame(update);
    }});

    // Intersection observer for scroll animations
    const observer = new IntersectionObserver(function(entries) {{
      entries.forEach(function(entry) {{
        if (entry.isIntersecting) {{
          entry.target.style.animationPlayState = 'running';
        }}
      }});
    }}, {{ threshold: 0.1 }});

    document.querySelectorAll('.animate-in').forEach(function(el) {{
      observer.observe(el);
    }});
  }});
</script>
</body>
</html>'''

    with open(output_path, "w") as f:
        f.write(html)

    return os.path.abspath(output_path)


# ═══════════════════════════════════════════════════════════════════════
#  Additional export formats — ReconPro v11.1.0
# ═══════════════════════════════════════════════════════════════════════

import csv
import xml.etree.ElementTree as ET
from io import StringIO


# ── Helpers ─────────────────────────────────────────────────────────────


def _findings_to_dicts(findings: Any) -> List[Dict[str, Any]]:
    """Normalize findings (list of dicts or objects) to list of dicts."""
    result: List[Dict[str, Any]] = []
    for f in findings:
        if isinstance(f, dict):
            result.append(f)
        elif hasattr(f, "to_dict"):
            result.append(f.to_dict())
        elif hasattr(f, "__dict__"):
            result.append(vars(f))
        else:
            result.append({"title": str(f)})
    return result


_SEVERITY_ORDER: Dict[str, int] = {
    "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
}

_CSV_COLUMNS = [
    "severity", "module", "category", "title", "description",
    "evidence", "asset", "points_deducted", "remediation",
    "cvss_score", "cvss_vector",
]


# ── CSV ─────────────────────────────────────────────────────────────────


def generate_csv_report(
    findings: Any,
    output_path: str,
    score: Optional[float] = None,
) -> str:
    """Export findings to CSV (pure stdlib).

    Parameters
    ----------
    findings : list of dict-like
        Raw findings as produced by scanner modules.
    output_path : str
        Destination file path.
    score : float, optional
        Overall score (written as comment in header area — CSV has no
        native comment mechanism, so it is omitted from the CSV itself).

    Returns
    -------
    str
        Absolute path of the written file.
    """
    rows = _findings_to_dicts(findings)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(str(path), "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in _CSV_COLUMNS})

    return str(path.resolve())


# ── SARIF v2.1.0 ────────────────────────────────────────────────────────

_SARIF_SEVERITY_MAP: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def generate_sarif_report(
    findings: Any,
    output_path: str,
    target: str = "",
) -> str:
    """Export findings to SARIF v2.1.0 (GitHub Code Scanning compatible).

    Parameters
    ----------
    findings : list of dict-like
    output_path : str
    target : str
        Target identifier included in run properties.

    Returns
    -------
    str
        Absolute path of the written file.
    """
    rows = _findings_to_dicts(findings)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Build unique rules from findings
    rules: List[Dict[str, Any]] = []
    seen_rules: Dict[str, int] = {}
    for f in rows:
        rule_id = f.get("category", f.get("title", "RP-0000"))
        rule_id = rule_id[:100] if len(rule_id) > 100 else rule_id
        if rule_id not in seen_rules:
            idx = len(rules)
            seen_rules[rule_id] = idx
            rules.append({
                "id": rule_id,
                "shortDescription": {
                    "text": f.get("title", rule_id),
                },
                "helpUri": f.get("remediation", ""),
                "properties": {
                    "security-severity": str(f.get("cvss_score", "")),
                },
            })

    results: List[Dict[str, Any]] = []
    for f in rows:
        severity = _SARIF_SEVERITY_MAP.get(
            str(f.get("severity", "info")).lower(), "note"
        )
        rule_id = f.get("category", f.get("title", "RP-0000"))
        rule_id = rule_id[:100] if len(rule_id) > 100 else rule_id
        rule_index = seen_rules.get(rule_id, 0)

        asset = f.get("asset", target)
        location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": asset,
                },
            },
        }

        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": severity,
            "message": {
                "text": f.get("description", ""),
            },
            "locations": [location],
            "properties": {
                "points_deducted": f.get("points_deducted", 0),
                "module": f.get("module", ""),
                "evidence": f.get("evidence", "")[:500] if f.get("evidence") else "",
            },
        })

    sarif: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReconPro",
                        "version": _VERSION,
                        "rules": rules,
                    },
                },
                "results": results,
                "properties": {
                    "target": target,
                },
            }
        ],
    }

    with open(str(path), "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    return str(path.resolve())


# ── XML (Nessus / Burp compatible) ─────────────────────────────────────


def generate_xml_report(
    findings: Any,
    output_path: str,
    score: Optional[float] = None,
) -> str:
    """Export findings to Nessus/Burp-compatible XML.

    Parameters
    ----------
    findings : list of dict-like
    output_path : str
    score : float, optional
        Included in host properties.

    Returns
    -------
    str
        Absolute path of the written file.
    """
    rows = _findings_to_dicts(findings)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    root = ET.Element("nessusclient")
    report = ET.SubElement(root, "Report", name="ReconPro Scan")
    host = ET.SubElement(report, "ReportHost", name="target")

    # HostProperties
    props = ET.SubElement(host, "HostProperties")
    if score is not None:
        ET.SubElement(props, "tag", name="score").text = str(score)
    ET.SubElement(props, "tag", name="findings-count").text = str(len(rows))
    ET.SubElement(props, "tag", name="scan-date").text = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # ReportItems
    for idx, f in enumerate(rows, start=1):
        severity_num = _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 1)
        item = ET.SubElement(
            host,
            "ReportItem",
            port="0",
            service="reconpro",
            protocol="tcp",
            severity=str(severity_num),
            pluginID=str(idx),
            pluginName=f.get("title", f"Finding #{idx}"),
        )
        ET.SubElement(item, "description").text = f.get("description", "")
        ET.SubElement(item, "remediation").text = f.get("remediation", "")
        ET.SubElement(item, "severity_label").text = str(f.get("severity", "info"))
        ET.SubElement(item, "module").text = str(f.get("module", ""))
        ET.SubElement(item, "category").text = str(f.get("category", ""))
        ET.SubElement(item, "asset").text = str(f.get("asset", ""))
        if f.get("evidence"):
            ET.SubElement(item, "evidence").text = str(f["evidence"])[:2000]
        if f.get("cvss_score") is not None:
            ET.SubElement(item, "cvss_score").text = str(f["cvss_score"])
        if f.get("points_deducted") is not None:
            ET.SubElement(item, "points_deducted").text = str(f["points_deducted"])

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(str(path), encoding="unicode", xml_declaration=True)

    return str(path.resolve())


# ── Markdown ────────────────────────────────────────────────────────────

_MD_SEVERITY_BADGE: Dict[str, str] = {
    "critical": "🔴 CRITICAL",
    "high": "🟠 HIGH",
    "medium": "🟡 MEDIUM",
    "low": "🔵 LOW",
    "info": "⚪ INFO",
}


def generate_markdown_report(
    findings: Any,
    output_path: str,
    score: Optional[float] = None,
    target: str = "",
) -> str:
    """Export findings to a clean Markdown report.

    Parameters
    ----------
    findings : list of dict-like
    output_path : str
    score : float, optional
    target : str, optional

    Returns
    -------
    str
        Absolute path of the written file.
    """
    rows = _findings_to_dicts(findings)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Sort by severity descending
    rows.sort(key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 0), reverse=True)

    # Severity counts
    counts: Dict[str, int] = {}
    for f in rows:
        s = str(f.get("severity", "info")).lower()
        counts[s] = counts.get(s, 0) + 1

    lines: List[str] = []
    lines.append("# ReconPro Security Report")
    lines.append("")
    if target:
        lines.append(f"**Target:** `{target}`  ")
    lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    if score is not None:
        lines.append(f"**Score:** {score:.1f}/100  ")
    lines.append(f"**Total Findings:** {len(rows)}")
    lines.append("")

    # Summary statistics
    lines.append("## Summary")
    lines.append("")
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts.get(sev, 0)
        badge = _MD_SEVERITY_BADGE.get(sev, sev.upper())
        lines.append(f"- {badge}: {c}")
    lines.append("")

    if not rows:
        lines.append("> No findings to report.")
        lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("| # | Severity | Module | Title | Points |")
        lines.append("|---|----------|--------|-------|--------|")
        for idx, f in enumerate(rows, start=1):
            sev = str(f.get("severity", "info")).lower()
            badge = _MD_SEVERITY_BADGE.get(sev, sev.upper())
            title = str(f.get("title", "Untitled"))[:80]
            module = str(f.get("module", ""))[:30]
            pts = f.get("points_deducted", 0)
            lines.append(f"| {idx} | {badge} | {module} | {title} | {pts} |")
        lines.append("")

        # Detail sections
        lines.append("## Detail")
        lines.append("")
        for idx, f in enumerate(rows, start=1):
            sev = str(f.get("severity", "info")).lower()
            badge = _MD_SEVERITY_BADGE.get(sev, sev.upper())
            lines.append(f"### {idx}. {badge} — {f.get('title', 'Untitled')}")
            lines.append("")
            if f.get("description"):
                lines.append(f.get("description"))
                lines.append("")
            if f.get("evidence"):
                lines.append(f"**Evidence:**")
                lines.append("```")
                lines.append(str(f["evidence"])[:1000])
                lines.append("```")
                lines.append("")
            if f.get("remediation"):
                lines.append(f"**Remediation:** {f.get('remediation')}")
                lines.append("")
            lines.append("---")
            lines.append("")

    lines.append("---")
    lines.append(f"*Generated by ReconPro v{_VERSION}*  ")
    lines.append("")

    with open(str(path), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return str(path.resolve())


# ── PDF (printable HTML) ───────────────────────────────────────────────


def generate_pdf_report(
    findings: Any,
    output_path: str,
    score: Optional[float] = None,
    target: str = "",
) -> str:
    """Generate a printable-HTML report styled for PDF output.

    Creates a self-contained HTML file with print-optimized CSS.
    The file uses .html extension internally so browsers can render it,
    but the output_path is respected as given by the caller.

    Parameters
    ----------
    findings : list of dict-like
    output_path : str
    score : float, optional
    target : str, optional

    Returns
    -------
    str
        Absolute path of the written file.
    """
    rows = _findings_to_dicts(findings)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # If caller passed a .pdf extension, use .html instead
    actual_path = path
    if path.suffix.lower() == ".pdf":
        actual_path = path.with_suffix(".html")

    rows.sort(key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 0), reverse=True)

    # Severity counts
    counts: Dict[str, int] = {}
    for f in rows:
        s = str(f.get("severity", "info")).lower()
        counts[s] = counts.get(s, 0) + 1

    # ASCII gauge
    gauge_width = 40
    filled = 0
    if score is not None:
        filled = int(round(score / 100 * gauge_width))
    gauge_bar = "█" * filled + "░" * (gauge_width - filled)
    score_display = f"{score:.1f}" if score is not None else "N/A"

    # Build findings rows
    finding_rows_html = ""
    for idx, f in enumerate(rows, start=1):
        sev = str(f.get("severity", "info")).lower()
        title = f.get("title", "Untitled")
        desc = f.get("description", "")
        rem = f.get("remediation", "")
        pts = f.get("points_deducted", 0)
        mod = f.get("module", "")
        sev_color = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#d97706", "low": "#2563eb", "info": "#6b7280",
        }.get(sev, "#6b7280")
        finding_rows_html += f"""
        <tr>
          <td style="text-align:center">{idx}</td>
          <td style="color:{sev_color};font-weight:bold;text-transform:uppercase">{sev}</td>
          <td>{mod}</td>
          <td>{title}</td>
          <td style="text-align:center">{pts}</td>
        </tr>"""

    # Remediation summary
    rem_html = ""
    for f in rows:
        if f.get("remediation"):
            rem_html += f"<li><strong>{f.get('title', 'Untitled')}</strong>: {f['remediation']}</li>\n"

    rem_section_html = ('<h2>Remediation Summary</h2><ul class="rem-list">' + rem_html + '</ul>') if rem_html else ''

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ReconPro Report — {target or 'Scan'}</title>
<style>
  @page {{ size: A4; margin: 1.5cm; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 11pt; color: #1f2937; line-height: 1.6; padding: 2cm; max-width: 210mm; margin: auto; }}
  h1 {{ font-size: 20pt; margin-bottom: 4px; }}
  h2 {{ font-size: 14pt; margin: 20px 0 8px; border-bottom: 2px solid #e5e7eb; padding-bottom: 4px; }}
  .meta {{ color: #6b7280; font-size: 9pt; margin-bottom: 16px; }}
  .gauge {{ font-family: 'Courier New', monospace; font-size: 12pt; background: #f9fafb; padding: 12px 16px; border-radius: 6px; border: 1px solid #e5e7eb; margin: 12px 0 20px; }}
  .gauge-label {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 9pt; color: #6b7280; margin-bottom: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9pt; }}
  th {{ background: #f3f4f6; text-align: left; padding: 6px 8px; border-bottom: 2px solid #d1d5db; }}
  td {{ padding: 5px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  tr:nth-child(even) {{ background: #f9fafb; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin: 12px 0; }}
  .summary-box {{ text-align: center; padding: 10px; border-radius: 6px; border: 1px solid #e5e7eb; }}
  .summary-box .num {{ font-size: 18pt; font-weight: bold; }}
  .summary-box .label {{ font-size: 8pt; text-transform: uppercase; color: #6b7280; }}
  .rem-list {{ margin: 8px 0; padding-left: 20px; }}
  .rem-list li {{ margin-bottom: 4px; font-size: 9pt; }}
  .footer {{ margin-top: 30px; text-align: center; font-size: 8pt; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 8px; }}
  @media print {{ body {{ padding: 0; }} }}
</style>
</head>
<body>
<h1>ReconPro Security Report</h1>
<div class="meta">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp; Target: {target or 'N/A'}</div>

<h2>Score</h2>
<div class="gauge-label">Security Score (out of 100)</div>
<div class="gauge">[{gauge_bar}] {score_display}/100</div>

<h2>Severity Breakdown</h2>
<div class="summary-grid">
  <div class="summary-box" style="background:#fef2f2"><div class="num" style="color:#dc2626">{counts.get('critical', 0)}</div><div class="label">Critical</div></div>
  <div class="summary-box" style="background:#fff7ed"><div class="num" style="color:#ea580c">{counts.get('high', 0)}</div><div class="label">High</div></div>
  <div class="summary-box" style="background:#fffbeb"><div class="num" style="color:#d97706">{counts.get('medium', 0)}</div><div class="label">Medium</div></div>
  <div class="summary-box" style="background:#eff6ff"><div class="num" style="color:#2563eb">{counts.get('low', 0)}</div><div class="label">Low</div></div>
  <div class="summary-box" style="background:#f9fafb"><div class="num" style="color:#6b7280">{counts.get('info', 0)}</div><div class="label">Info</div></div>
</div>

<h2>Findings ({len(rows)})</h2>
<table>
  <thead><tr><th>#</th><th>Severity</th><th>Module</th><th>Title</th><th style="text-align:center">Pts</th></tr></thead>
  <tbody>{finding_rows_html}</tbody>
</table>

{rem_section_html}

<div class="footer">Generated by <strong>ReconPro</strong> v{_VERSION}</div>
</body>
</html>"""

    with open(str(actual_path), "w", encoding="utf-8") as fh:
        fh.write(html)

    return str(actual_path.resolve())


# ── JSON ────────────────────────────────────────────────────────────────


# DEAD CODE: consider removal
def generate_json_report(
    findings: Any,
    output_path: str,
    score: Optional[float] = None,
    target: str = "",
) -> str:
    """Export findings to clean, indented JSON.

    Parameters
    ----------
    findings : list of dict-like
    output_path : str
    score : float, optional
    target : str, optional

    Returns
    -------
    str
        Absolute path of the written file.
    """
    rows = _findings_to_dicts(findings)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        "generator": "ReconPro",
        "version": _VERSION,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "score": score,
        "total_findings": len(rows),
        "findings": rows,
    }

    with open(str(path), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
        fh.write("\n")

    return str(path.resolve())


# ── Auto-detect format ──────────────────────────────────────────────────

_FORMAT_MAP: Dict[str, Any] = {
    "html": generate_html_report,
    "csv": generate_csv_report,
    "json": generate_json_report,
    "sarif": generate_sarif_report,
    "xml": generate_xml_report,
    "md": generate_markdown_report,
    "markdown": generate_markdown_report,
    "pdf": generate_pdf_report,
}

_EXT_MAP: Dict[str, str] = {
    ".html": "html",
    ".htm": "html",
    ".csv": "csv",
    ".json": "json",
    ".sarif": "sarif",
    ".xml": "xml",
    ".md": "md",
    ".markdown": "md",
    ".pdf": "pdf",
}


# DEAD CODE: consider removal
def generate_report_auto(
    findings: Any,
    output_path: str,
    fmt: str = "html",
    score: Optional[float] = None,
    target: str = "",
) -> str:
    """Auto-detect report format from extension or explicit *fmt* parameter.

    Parameters
    ----------
    findings : list of dict-like
    output_path : str
    fmt : str
        One of: html, csv, json, sarif, xml, md, markdown, pdf.
        If ``"auto"``, the format is inferred from *output_path*
        file extension.
    score : float, optional
    target : str, optional

    Returns
    -------
    str
        Absolute path of the written file.
    """
    if fmt == "auto":
        ext = Path(output_path).suffix.lower()
        fmt = _EXT_MAP.get(ext, "html")

    fmt = fmt.lower().strip()
    generator = _FORMAT_MAP.get(fmt)
    if generator is None:
        raise ValueError(
            f"Unknown report format '{fmt}'. "
            f"Supported: {', '.join(sorted(_FORMAT_MAP))}"
        )

    # Build kwargs based on function signature
    import inspect
    sig = inspect.signature(generator)
    kwargs: Dict[str, Any] = {"findings": findings, "output_path": output_path}
    if "score" in sig.parameters:
        kwargs["score"] = score
    if "target" in sig.parameters:
        kwargs["target"] = target

    return generator(**kwargs)


__all__ = [
    "generate_html_report",
    "generate_csv_report",
    "generate_sarif_report",
    "generate_xml_report",
    "generate_markdown_report",
    "generate_pdf_report",
    "generate_json_report",
    "generate_report_auto",
    "generate_production_report",
    "_findings_to_dicts",
]


# ── Production Report Generation (v11) ─────────────────────────────────


def generate_production_report(
    scan_data: Dict[str, Any],
    format: str = "markdown",
) -> str:
    """Generate a comprehensive production report from scan data.

    Supports ``"markdown"`` and ``"json"`` formats.  The report includes:
      - Executive summary (risk score, grade, top findings)
      - Module breakdown table
      - Intelligence analysis summary
      - Engineering metrics summary
      - Recommendations
      - Trend data (from history if available)

    Parameters
    ----------
    scan_data : dict
        Full scan result dictionary (as returned by ``history.get_latest()``).
    format : str
        ``"markdown"`` or ``"json"``.

    Returns
    -------
    str
        The generated report string.
    """
    if format == "json":
        return _production_report_json(scan_data)
    return _production_report_markdown(scan_data)


def _production_report_json(scan_data: Dict[str, Any]) -> str:
    """Build a machine-readable JSON production report."""
    target = scan_data.get("target", "Unknown")
    score = scan_data.get("total_score", 0)
    grade = scan_data.get("grade", "N/A")
    findings = scan_data.get("findings", [])
    modules_run = scan_data.get("modules_run", [])
    severity_counts = scan_data.get("severity_counts", {})
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Severity breakdown
    sev_breakdown = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_breakdown[sev] = severity_counts.get(sev, 0)

    # Top findings (critical + high first)
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 0),
        reverse=True,
    )
    top_findings = sorted_findings[:10]

    # Module breakdown
    module_breakdown = []
    by_module: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        mod = f.get("module", "unknown")
        by_module.setdefault(mod, []).append(f)
    for mod in modules_run:
        mod_findings = by_module.get(mod, [])
        module_breakdown.append({
            "module": mod,
            "total_findings": len(mod_findings),
            "critical": sum(1 for x in mod_findings if x.get("severity") == "critical"),
            "high": sum(1 for x in mod_findings if x.get("severity") == "high"),
            "medium": sum(1 for x in mod_findings if x.get("severity") == "medium"),
            "low": sum(1 for x in mod_findings if x.get("severity") == "low"),
        })

    # Recommendations (actionable remediations)
    recommendations = []
    seen_fixes: set = set()
    for f in sorted_findings:
        if f.get("severity") in ("critical", "high") and f.get("remediation"):
            fix = f.get("remediation", "").strip()
            if fix and fix not in seen_fixes:
                seen_fixes.add(fix)
                recommendations.append({
                    "severity": f.get("severity"),
                    "title": f.get("title", ""),
                    "remediation": fix[:500],
                })

    # Trend data
    trend_data = []
    try:
        from .history import list_scans
        recent = list_scans(target=target, limit=10)
        for s in recent:
            trend_data.append({
                "date": s.get("_saved_at", "")[:16],
                "score": s.get("total_score", 0),
                "grade": s.get("grade", "?"),
                "findings": len(s.get("findings", [])),
            })
    except Exception:
        pass

    report = {
        "generator": "ReconPro",
        "version": _VERSION,
        "timestamp": ts,
        "report_type": "production",
        "target": target,
        "executive_summary": {
            "risk_score": score,
            "grade": grade,
            "total_findings": len(findings),
            "severity_breakdown": sev_breakdown,
            "top_findings": top_findings,
        },
        "module_breakdown": module_breakdown,
        "engineering_metrics": {
            "modules_run": len(modules_run),
            "modules_total": len(modules_run),
        },
        "recommendations": recommendations,
        "trend": trend_data,
    }

    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def _production_report_markdown(scan_data: Dict[str, Any]) -> str:
    """Build a comprehensive Markdown production report."""
    target = scan_data.get("target", "Unknown")
    score = scan_data.get("total_score", 0)
    grade = scan_data.get("grade", "N/A")
    findings = scan_data.get("findings", [])
    modules_run = scan_data.get("modules_run", [])
    severity_counts = scan_data.get("severity_counts", {})
    module_results = scan_data.get("module_results", {})
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Sort findings by severity
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 0),
        reverse=True,
    )
    top_findings = sorted_findings[:10]

    # Severity counts
    crit = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    med = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)
    info = severity_counts.get("info", 0)

    # Risk posture label
    if score >= 80:
        risk_posture = "Low Risk"
    elif score >= 60:
        risk_posture = "Moderate Risk"
    elif score >= 40:
        risk_posture = "Elevated Risk"
    else:
        risk_posture = "High Risk"

    md: List[str] = []

    # ── Header ─────────────────────────────────────────────────────
    md.append(f"# ReconPro v{_VERSION} Production Security Report")
    md.append("")
    md.append(f"**Target:** {target}  ")
    md.append(f"**Date:** {ts}  ")
    md.append(f"**Grade:** {grade} ({score}/100)  ")
    md.append(f"**Risk Posture:** {risk_posture}  ")
    md.append(f"**Total Findings:** {len(findings)}")
    md.append("")

    # ── Executive Summary ──────────────────────────────────────────
    md.append("---")
    md.append("")
    md.append("## Executive Summary")
    md.append("")
    md.append(
        f"A security assessment was conducted against **{target}**. "
        f"The target received an overall security score of **{score}/100** "
        f"(Grade: **{grade}**), indicating a **{risk_posture}** posture."
    )
    md.append("")
    md.append(
        f"The assessment identified {crit} critical, {high} high, "
        f"{med} medium, {low} low, and {info} informational findings "
        f"across {len(modules_run)} modules."
    )
    md.append("")

    if top_findings:
        md.append("**Top Findings:**")
        md.append("")
        for i, f in enumerate(top_findings, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            md.append(f"{i}. **[{sev}]** {title}")
        md.append("")

    # ── Severity Overview ──────────────────────────────────────────
    md.append("---")
    md.append("")
    md.append("## Severity Overview")
    md.append("")
    md.append("| Severity | Count |")
    md.append("|----------|-------|")
    for sev, label in [("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW"), ("info", "INFO")]:
        c = severity_counts.get(sev, 0)
        md.append(f"| {label} | {c} |")
    md.append("")

    # ── Module Breakdown ───────────────────────────────────────────
    md.append("---")
    md.append("")
    md.append("## Module Breakdown")
    md.append("")
    md.append("| Module | Findings | Critical | High | Medium | Low |")
    md.append("|--------|----------|----------|------|--------|-----|")
    by_module: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        mod = f.get("module", "unknown")
        by_module.setdefault(mod, []).append(f)
    for mod in modules_run:
        mf = by_module.get(mod, [])
        mc = sum(1 for x in mf if x.get("severity") == "critical")
        mh = sum(1 for x in mf if x.get("severity") == "high")
        mm = sum(1 for x in mf if x.get("severity") == "medium")
        ml = sum(1 for x in mf if x.get("severity") == "low")
        status = "PASS" if not mf else ("FAIL" if mc > 0 or mh > 0 else "WARN")
        md.append(f"| {mod} | {len(mf)} ({status}) | {mc} | {mh} | {mm} | {ml} |")
    md.append("")

    # ── Intelligence Analysis Summary ──────────────────────────────
    md.append("---")
    md.append("")
    md.append("## Intelligence Analysis")
    md.append("")

    # Category distribution
    cat_counts: Dict[str, int] = {}
    for f in findings:
        cat = f.get("category", "uncategorized")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    if cat_counts:
        md.append("### Finding Categories")
        md.append("")
        md.append("| Category | Count |")
        md.append("|----------|-------|")
        for cat, cnt in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
            md.append(f"| {cat} | {cnt} |")
        md.append("")
    else:
        md.append("> No category data available.")
        md.append("")

    # DREAD analysis for top findings
    dread_findings = [f for f in top_findings if f.get("dread")]
    if dread_findings:
        md.append("### DREAD Risk Analysis (Top Findings)")
        md.append("")
        md.append("| Finding | D | R | E | A | D | Avg |")
        md.append("|---------|---|---|---|---|---|-----|")
        for f in dread_findings[:8]:
            d = f.get("dread", {})
            vals = [d.get(k, 0) for k in ("damage", "reproducibility", "exploitability", "affected_users", "discoverability")]
            avg = sum(vals) / len(vals) if vals else 0
            md.append(f"| {f.get('title', '')[:40]} | {vals[0]} | {vals[1]} | {vals[2]} | {vals[3]} | {vals[4]} | {avg:.1f} |")
        md.append("")

    # ── Engineering Metrics ────────────────────────────────────────
    md.append("---")
    md.append("")
    md.append("## Engineering Metrics")
    md.append("")
    md.append(f"- **Modules Executed:** {len(modules_run)}")
    md.append(f"- **Total Findings:** {len(findings)}")
    md.append(f"- **Points Deducted:** {100 - score}")
    md.append(f"- **Score:** {score}/100")
    md.append("")

    # Module timing if available
    if module_results:
        md.append("### Module Timing")
        md.append("")
        md.append("| Module | Findings | Duration (s) |")
        md.append("|--------|----------|-------------|")
        for mod_id, mod_data in module_results.items():
            n_findings = len(mod_data.get("findings", []))
            duration = mod_data.get("duration", 0)
            md.append(f"| {mod_id} | {n_findings} | {duration:.2f} |")
        md.append("")

    # ── Recommendations ────────────────────────────────────────────
    critical_high = [f for f in sorted_findings if f.get("severity") in ("critical", "high")]
    md.append("---")
    md.append("")
    if critical_high:
        md.append("## Recommendations")
        md.append("")
        seen_fixes: set = set()
        rec_num = 0
        for f in critical_high:
            fix = (f.get("remediation") or "").strip()
            if fix and fix not in seen_fixes:
                seen_fixes.add(fix)
                rec_num += 1
                sev = f.get("severity", "").upper()
                md.append(f"### {rec_num}. [{sev}] {f.get('title', 'Unknown')}")
                md.append("")
                md.append(f"{fix}")
                md.append("")
    else:
        md.append("## Recommendations")
        md.append("")
        md.append("> No critical or high-severity findings. Target demonstrates a reasonable security posture.")
        md.append("")

    # ── Trend Data ─────────────────────────────────────────────────
    try:
        from .history import list_scans as _list_scans
        recent = _list_scans(target=target, limit=10)
        if len(recent) > 1:
            md.append("---")
            md.append("")
            md.append("## Score Trend")
            md.append("")
            md.append("| Date | Score | Grade | Findings |")
            md.append("|------|-------|-------|----------|")
            for s in recent:
                md.append(
                    f"| {s.get('_saved_at', '')[:16]} | {s.get('total_score', '?')} | "
                    f"{s.get('grade', '?')} | {len(s.get('findings', []))} |"
                )
            md.append("")
    except Exception:
        pass

    # ── Footer ─────────────────────────────────────────────────────
    md.append("---")
    md.append("")
    md.append(f"*Generated by ReconPro v{_VERSION} — {ts}*")
    md.append("")

    return "\n".join(md)

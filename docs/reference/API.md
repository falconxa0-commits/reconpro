# API — the JSON output schema and the Python API

Everything ReconPro produces is designed to be machine-consumable:
`--json` commands print JSON on **stdout** (human output goes to stderr),
and the Python package exposes the same results as dataclasses. This
page documents every field, verified against real v11.2.0 output.

The canonical producer is `ReconProResult.to_dict()`
(`reconpro/scanner.py`) — the same dict backs `--json`, `reconpro export
report.json`, the SDKs, and `reconpro serve`.

## Top-level object

```jsonc
{
  // identity
  "target": "demo-app",                  // host or path that was scanned
  "modules_run": ["dev"],                // modules that actually executed

  // verdict
  "total_findings": 1,
  "severity_counts": {"critical": 1},    // counts per severity
  "total_score": 85,                      // 0–100 (100 = clean)
  "grade": "A",                          // A+ | A | B | C | D | F | U
  "badge_markdown": "![ReconPro A](https://img.shields.io/badge/…)",

  // vibesec benchmark (null unless the vibesec module ran)
  "vibesec_score": null,
  "vibesec_grade": null,

  // per-module raw results
  "module_results": {
    "dev": {"findings": [ /* Finding dicts */ ], "count": 1}
  },

  // flat list of every Finding (see below)
  "findings": [ /* … */ ],

  // intelligence pipeline (null when disabled via --no-intelligence)
  "intelligence": { /* see below */ },
  "engineering": null,                   // present when engineering pipeline ran
  "quality": null,                       // present when --quality was passed
  "engineering_score": 95.5,

  // ── truth layer (v11.2.0) ─────────────────────────────────────
  "target_validation": { /* see below; null for local audits */ },
  "scan_metadata": { /* see below */ }
}
```

### `grade`

`A+ ≥ 90`, `A ≥ 80`, `B ≥ 65`, `C ≥ 50`, `D ≥ 35`, else `F`
(`reconpro/constants.py`). The special grade **`U`** (unreachable) is
assigned only when the target validation pipeline short-circuited the
scan — it means "no claim is made", not "clean".

## The Finding object

Every finding — in every format, on every transport — carries these 12
fields (`Finding` dataclass in `reconpro/http_layer.py`):

| Field | Type | Meaning |
|---|---|---|
| `title` | string | one-line summary |
| `severity` | string | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `category` | string | finding taxonomy id (e.g. `hardcoded_secrets`, `target_validation`, `dns`) |
| `module` | string | module id that produced it (`recon`, `dev`, `engine`, …) |
| `description` | string | human explanation |
| `evidence` | string | **what was actually observed** — the proof behind the claim (e.g. `Match: AKIAIOSF...MPLE`, `DNS resolution failed: [Errno -2] Name or service not known`) |
| `asset` | string | file path / host / URL the finding belongs to |
| `points_deducted` | int | score points subtracted |
| `remediation` | string | how to fix it |
| `dread_score` | float | DREAD-model risk weight (0–1) |
| `confidence` | float | **0.0–1.0 reliability estimate for this finding** (v11.2.0) |
| `verification_state` | string | **target state the finding was produced under** (v11.2.0): `VERIFIED_TARGET` \| `PARTIAL_TARGET` \| `UNREACHABLE_TARGET` \| `UNVERIFIED` (local findings before truth application) |

Real example (from `reconpro dev` on a directory containing
`API_KEY = "AKIAIOSFODNN7EXAMPLE"`):

```json
{
  "title": "Hardcoded API key in app.py",
  "severity": "critical",
  "category": "hardcoded_secrets",
  "module": "dev",
  "description": "Secret detected in source code: Hardcoded API key",
  "evidence": "Match: AKIAIOSF...MPLE",
  "asset": "/tmp/rp-docs-evidence/demo-app",
  "points_deducted": 15,
  "remediation": "Move secrets to environment variables or a secrets manager. Never commit secrets to source code.",
  "dread_score": 0.0,
  "confidence": 0.8,
  "verification_state": "UNVERIFIED"
}
```

`UNVERIFIED` is the pre-truth default for local findings (there is no
remote target to validate); remote findings carry one of the three
target states after `apply_target_truth()` runs.

## `target_validation` (remote scans)

Output of the DNS → TCP → HTTP/TLS pipeline (`reconpro/target_validation.py`),
`null` for local audits:

```jsonc
{
  "state": "UNREACHABLE_TARGET",   // VERIFIED_TARGET | PARTIAL_TARGET | UNREACHABLE_TARGET
  "dns_resolved": false,
  "reachable": false,               // TCP connect succeeded
  "http_ok": false,                 // an HTTP(S) request was answered
  "tls_valid": null,                // true | false | null (not probed)
  "details": {
    "host": "nonexistent-target-xyz.invalid",
    "dns": {"ok": false, "ips": [], "error": "[Errno -2] Name or service not known", "is_ip_literal": false},
    "reason": "DNS resolution failed: [Errno -2] Name or service not known"
  },
  "checked_at": "2026-09-18T00:37:01.499796+00:00"
}
```

### What each state means for the findings

| State | Modules run | Severity cap | Default finding confidence | Typical cause |
|---|---|---|---|---|
| `VERIFIED_TARGET` | all requested | none (critical allowed) | 0.9 | DNS + TCP + HTTP(S) all OK |
| `PARTIAL_TARGET` | yes (passive/DNS checks may still be valid) | **medium** (higher findings are downgraded with a note) | 0.5 | DNS ok but HTTP validation failed: non-HTTP service, TLS failure, probe error |
| `UNREACHABLE_TARGET` | **none** — short-circuit | low (only the honest info finding exists) | 0.2 (the finding itself reports 0.95 as *the pipeline's* confidence that the target is unreachable) | DNS failed or no TCP connection |

Verified live (v11.2.0):

```
$ reconpro scan nonexistent-target-xyz.invalid --json -t 2
  → total_findings: 1, severity: info, total_score: 0, grade: "U",
    modules_run: [], findings[0].verification_state: "UNREACHABLE_TARGET",
    scan_metadata.result: "unreachable_target_short_circuit"
```

## `scan_metadata` (all scans)

```jsonc
{
  "scanner": "reconpro",
  "started_at": "2026-09-18T00:37:08.639904+00:00",  // UTC ISO-8601
  "duration_s": 0.03,                                  // wall-clock seconds
  "result": "modules_executed"                         // or "unreachable_target_short_circuit"
}
```

## `intelligence`

Present when the intelligence pipeline runs (default for remote scans;
disable with `--no-intelligence`). Top-level keys, from real output:
`executive_risk_score`, `exposure_score`, `mission_impact_score`,
`infrastructure_health_score`, `threat_confidence_index`,
`pipeline_duration_ms`, `ai_duration_ms`, `graph_duration_ms`,
`intel_duration_ms`, `enabled_engines`, `errors`, `risk_level`,
`has_intelligence`, `ai_analysis`, `classification_summary`,
`extended_findings`, `attack_paths`, `attack_graph`, `attack_chains`,
`kill_chain_mapping`, `cve_matches`, `cwe_matches`,
`mitre_techniques`, `knowledge_graph`, `entity_count`,
`relationship_count`, `regression_data`, `recommendations`.

## Python API

```python
from reconpro import scan, audit_scan, __version__
```

- `scan(target, modules=None, all_modules=False, timeout=8,
  verify_tls=True, rate_limit=10.0)` → `ReconProResult` (network)
- `audit_scan(path)` → `ReconProResult` (local; no network)
- `ReconProResult` fields mirror the JSON above; `result.to_dict()`
  gives the exact JSON shape. Findings inside a raw `result.findings`
  list are plain dicts with the 12 Finding fields.
- Imports are lazy (PEP 562): `import reconpro` is cheap; the engine
  loads on first attribute access (see
  [PERFORMANCE.md](../PERFORMANCE.md)).
- Report writers are importable directly:
  `from reconpro.reports import generate_csv_report,
  generate_pdf_report, generate_html_report, generate_sarif_report,
  generate_markdown_report` (CSV and printable-PDF are Python-API-only;
  the `reconpro export` CLI supports `.sarif/.md/.markdown/.json/.html/
  .htm/.pdf`).

Errors: `scan()` raises `ValueError` for syntactically invalid targets;
`reconpro.scan` does **not** raise for unreachable targets — it returns
the honest `U`-grade result.

## Where the same schema shows up

| Surface | Notes |
|---|---|
| `reconpro <cmd> --json` | identical schema on stdout |
| `reconpro export report.json` | last saved scan, same schema |
| SARIF export (`report.sarif`) | each result's `properties` carries `category`, `module`, `points_deducted`, `evidence`, `remediation`, `confidence`, `verification_state`; `security-severity` maps severity to CVSS-like 0–10 |
| Markdown / HTML reports | render the same fields (target state + scan metadata included) |
| `reconpro serve` | REST wrapper around the same results |
| SDKs (`sdks/`) | parse this JSON into typed results — [SDKS.md](../SDKS.md) |

# Guide — Reports: JSON, SARIF, Markdown, HTML

Every scan can be exported four ways from the CLI (plus CSV and
printable-HTML-as-PDF from the Python API). Every format carries the
truth-layer fields: `target_validation` (state, DNS/TCP/HTTP results)
and `scan_metadata` (`started_at`, `duration_s`, `result`), and every
finding carries its `evidence`, `confidence` and `verification_state`.

All commands on this page were executed against v11.2.0. The examples
below use a saved scan from `reconpro dev <dir>` on a directory
containing one file with `API_KEY = "AKIA…"` (a deliberately planted
fake AWS key).

## The export command

```bash
reconpro export report.sarif     # SARIF 2.1.0 (GitHub Code Scanning)
reconpro export report.md        # Markdown report
reconpro export report.json      # raw JSON (the canonical schema)
reconpro export report.html      # HTML report
reconpro export report.pdf       # print-ready HTML with @media print CSS
                                # (open in a browser, Ctrl+P → save as PDF)
```

`export` serializes the **most recent saved scan** — run `scan`,
`audit`, `dev` or `doctor` first. The format is auto-detected from the
extension (`.sarif`, `.md`/`.markdown`, `.json`, `.html`/`.htm`, `.pdf`).
Two honest caveats, verified live:

- An **unknown extension silently falls back to JSON** (`formats.py:
  _FORMAT_MAP` has no entry → `export_json`). `reconpro export out.xyzv`
  exits 0 and writes JSON. Check your spelling.
- **CSV is not an `export` format** — `reconpro export out.csv` also
  falls back to JSON (the file will *contain* JSON). Use the Python API's
  `generate_csv_report()` if you need CSV.
- `report.pdf` is HTML with print CSS, not a binary PDF — that is the
  design (`formats.py:export_pdf` docstring: no external PDF libraries).

All four variants verified (exit 0, real files):

```
$ reconpro export report.sarif && reconpro export report.md \
  && reconpro export report.json && reconpro export report.html
  Exported: /tmp/rp-docs-evidence/report.sarif
  ...
```

## JSON — the canonical schema

`report.json` is exactly the `ReconProResult.to_dict()` shape (full
field-by-field documentation: [../reference/API.md](../reference/API.md)).
The truth-layer block for the unreachable-target case:

```jsonc
{
  "total_findings": 1,
  "severity_counts": {"info": 1},
  "total_score": 0,
  "grade": "U",
  "modules_run": [],
  "target_validation": {
    "state": "UNREACHABLE_TARGET",
    "dns_resolved": false,
    "reachable": false,
    "http_ok": false,
    "tls_valid": null,
    "details": {"host": "nonexistent-target-xyz.invalid",
                 "dns": {"ok": false, "ips": [],
                          "error": "[Errno -2] Name or service not known"}},
    "checked_at": "2026-09-18T00:37:01.499796+00:00"
  },
  "scan_metadata": {
    "scanner": "reconpro",
    "started_at": "2026-09-18T00:37:01.499796+00:00",
    "duration_s": 0.03,
    "result": "unreachable_target_short_circuit"
  }
}
```

`scan_metadata.result` is `"modules_executed"` for normal scans and
`"unreachable_target_short_circuit"` when the truth layer stopped the
scan — a pipeline can branch on it directly.

## SARIF 2.1.0

The SARIF export targets **GitHub Code Scanning**. Verified properties
of the emitted file:

```jsonc
{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "ReconPro",
                          "rules": [{
      "id": "RP-HARDCODED_SECRETS",
      "properties": {"security-severity": "9.0"},   // per-rule CVSS-like 0–10
      ...
    }]}},
    "results": [{
      "ruleId": "RP-HARDCODED_SECRETS",
      "level": "error",                             // critical/high → error
      "message": {"text": "Hardcoded API key in app.py"},
      "properties": {
        "category": "hardcoded_secrets",
        "module": "dev",
        "points_deducted": 15,
        "evidence": "Match: AKIAIOSF...MPLE",
        "remediation": "Move secrets to environment variables or a secrets manager...",
        "confidence": 0.8,
        "verification_state": "UNVERIFIED"
      }
    }]
  }]
}
```

Notes, verified against a real export:

- `security-severity` (the number GitHub Code Scanning sorts by) lives
  on the **rule** in `tool.driver.rules[].properties`, derived from the
  finding severity (`_severity_to_cvss`).
- Each **result** carries the truth-layer fields in its `properties`:
  `confidence` and `verification_state` included.
- Severity → `level` mapping: critical/high → `error`, medium → `warning`,
  low/info → `note`.

Wire it into GitHub Actions with the shipped composite action — full
tutorial: [../TUTORIALS.md#t3--sarif-in-ci-github-actions](../TUTORIALS.md#t3--sarif-in-ci-github-actions),
and the pipeline exit-code contract in
[ENTERPRISE.md](ENTERPRISE.md#the-exit-code-contract-for-pipelines).

## Markdown

`report.md` is a self-contained report with the grade badge at the top.
Verified head of a real export:

```markdown
# ReconPro Security Report

![ReconPro A](https://img.shields.io/badge/ReconPro-A-green?style=for-the-badge&labelColor=000000)

**Target:** `demo-app`
**Score:** 85/100
**Grade:** A
**Generated:** 2026-09-18 01:35:21 UTC
**Scan Started:** 2026-09-18 01:35:02 UTC
```

(The badge URL is rendered from `img.shields.io` — the same service as
the repository badges; the grade letter and color are computed locally.)

## HTML

`report.html` is a styled single-file report (no external assets)
suitable for attaching to tickets or emailing. Same fields as Markdown,
plus the severity distribution and per-finding remediation blocks.

## Choosing a format

| Format | Use it for |
|---|---|
| `--json` / `report.json` | pipelines, SDKs, anything programmatic |
| `report.sarif` | GitHub Code Scanning, SARIF-capable tools |
| `report.md` | PR comments, tickets, git-committed evidence |
| `report.html` | humans, email attachments |
| `report.pdf` (print-HTML) | printing; open in a browser → Ctrl+P |
| CSV (Python API) | spreadsheets |

## The `reconpro report` command

`reconpro report` renders a report from an **existing scan file**
(default: the last scan) without re-scanning:

```
reconpro report                          # HTML to stdout (default)
reconpro report --markdown               # Markdown
reconpro report --json                   # JSON
reconpro report -i scan.json -o out.md    # explicit input + output file
```

## Ingesting programmatically (Python)

```python
from reconpro.reports import (
    generate_csv_report, generate_pdf_report, generate_html_report,
    generate_sarif_report, generate_markdown_report,
)
```

Each takes the scan result dict and a path. CSV and printable-PDF are
**Python-API-only** (the CLI `export` does not ship them — see the
caveats above).

## Related

- [SCANNING.md](SCANNING.md) — the truth states behind these fields
- [../reference/API.md](../reference/API.md) — the complete JSON schema
- [ENTERPRISE.md](ENTERPRISE.md) — CI/CD wiring and exit codes

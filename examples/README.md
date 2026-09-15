# ReconPro Examples

Runnable, honest examples — every command here was executed while writing it.
Scripts are safe-by-default: local-only checks run out of the box, and the
steps that touch the network are explicitly marked (and commented out where
noted).

| Example | What it shows | Network? |
|---|---|---|
| [`cli/01-first-scan.sh`](cli/01-first-scan.sh) | The five commands everyone runs first | step 5 only (opt-in) |
| [`cli/02-machine-audit.sh`](cli/02-machine-audit.sh) | Audit the local machine, export MD + SARIF | no |
| [`cli/03-project-to-sarif.sh`](cli/03-project-to-sarif.sh) | Developer workflow: project scan → SARIF summary | no |
| [`python/audit_report.py`](python/audit_report.py) | Programmatic API: `audit_scan()` + result object | no |

More walkthroughs live in [docs/TUTORIALS.md](../docs/TUTORIALS.md); the
language SDK examples (Python / Node / Java / Go / Rust) live under
[`sdks/`](../sdks/) — see [docs/SDKS.md](../docs/SDKS.md).

## Running them

```bash
git clone https://github.com/falconxa0-commits/reconpro.git
cd reconpro
pip install reconpro          # or: pip install -e .

bash examples/cli/01-first-scan.sh
bash examples/cli/02-machine-audit.sh
bash examples/cli/03-project-to-sarif.sh /path/to/your/project

python examples/python/audit_report.py /path/to/your/project
```

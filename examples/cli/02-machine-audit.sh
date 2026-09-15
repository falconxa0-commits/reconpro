#!/usr/bin/env bash
# Local machine audit — ports, risky services, config hygiene — then export.
#
# Everything here runs locally: nothing leaves this machine.
set -euo pipefail

echo "== Open ports + risky services (live local check) =="
reconpro ports

echo
echo "== Full machine audit: firewall, SSH, Docker, env vars, files =="
reconpro audit

echo
echo "== Export the last scan =="
reconpro export audit-report.md     # Markdown for humans
reconpro export audit-report.sarif  # SARIF 2.1.0 for tooling / CI

echo
echo "Wrote: audit-report.md, audit-report.sarif"
echo "Tip:   reconpro history   — see every scan stored on this machine"
echo "       reconpro doctor --repair  — apply safe automatic fixes"

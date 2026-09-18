# Guide — Enterprise deployment

Running ReconPro in pipelines, on locked-down machines, and in
air-gapped environments. Everything here was verified against v11.2.0
(commands executed, exit codes captured); the YAML snippets mirror the
workflows this repository runs on itself.

## The exit-code contract (for pipelines)

ReconPro's exit codes are a **stable contract** (the SDKs depend on them
— `sdks/POLICY.md` §3):

| Exit code | Meaning | What your pipeline should do |
|---|---|---|
| `0` | success — the command ran to completion. **Includes an honest unreachable-target scan** (grade `U`): that is a *result*, not an error | continue; branch on `grade` / `scan_metadata.result` in the JSON, not on the exit code |
| `1` | runtime failure — the command could not do its job (plugin action failure, failed verify, out-of-range tutorial step) | fail the job; inspect stderr |
| `2` | **usage error** — unknown command, unknown flag, bad `--timeout` (valid 1–600), bad `--rate-limit` (valid 0.1–1000) | fail the job; this is always a bug in your script (a typo'd flag can never be silently ignored) |
| `130` | interrupted (SIGINT) — the CLI exits promptly via a signal handler + watchdog, no traceback spam | treat as cancellation |

Verified live:

```bash
$ reconpro unknown-cmd-xyz; echo $?
error: unknown command 'unknown-cmd-xyz' …          # did-you-mean on stderr
2
$ reconpro scan example.com --timeout 0; echo $?    # → 2 (range 1–600)
$ reconpro scan example.com --rate-limit 2000; echo $?  # → 2 (range 0.1–1000)
$ reconpro history --json; echo $?                  # → 2 (history has no --json)
```

**Finding-severity gating** is a JSON decision, not an exit-code
decision:

```bash
reconpro scan "$TARGET" --json -t 60 > scan.json 2>/dev/null
jq -e '.severity_counts.high + .severity_counts.critical > 0' scan.json \
  && echo "policy: block" || echo "policy: pass"
```

A pipeline that fails on any exit code ≥ 1 without reading the JSON
conflates "scanner broke" with "scanner found something".

## CI/CD: SARIF + GitHub Code Scanning

The repository ships a composite action —
[`actions/reconpro-scan`](../../actions/reconpro-scan) — that installs
the CLI, runs **AST analysis + secrets scan + project scan** on a
workspace, exports SARIF 2.1.0, uploads the artifact and ingests it into
**GitHub Code Scanning**:

```yaml
name: ReconPro
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: falconxa0-commits/reconpro/actions/reconpro-scan@v11.2.0
        with:
          target: .
          format: sarif        # sarif | json | md | html
          timeout: '300'
```

- Inputs: `target` (file or dir, default `.`), `workspace`, `format`
  (extension-driven, default `sarif`), `timeout` (seconds per
  invocation), `python-version` (default `3.11`).
- Outputs: `sarif-path`, `secrets-json-path`.
- Pin an exact CLI version with the job env
  `RECONPRO_INSTALL_SPEC: reconpro==11.2.0` (otherwise the action
  installs from PyPI — or from the repo when it *is* reconpro).

The step-by-step beginner tutorial (including what the SARIF contains
and where it lands in the GitHub UI) is
[T3 in TUTORIALS.md](../TUTORIALS.md#t3--sarif-in-ci-github-actions);
this project runs that same pipeline on itself
(`.github/workflows/reconpro-scan.yml`).

### Rolling your own (no composite action)

The contract you need: JSON on stdout, human output on stderr, exit
codes as above, one artifact per scan in `~/.reconpro/history/`.

```bash
reconpro dev . --json > rp.json           # local project scan (no network)
reconpro export rp.sarif                  # SARIF 2.1.0 from the last scan
# upload rp.sarif with your platform's SARIF ingestion step, e.g.
# github/codeql-action/upload-sarif@v3
```

Every SARIF result carries `confidence` and `verification_state` in its
`properties`, and per-rule `security-severity` for Code Scanning
sorting — field reference in [REPORTS.md](REPORTS.md).

## Scheduled / multi-target operations

- `reconpro schedule <target> --every 1h` — recurring scans (network)
  persisted on the host.
- `reconpro blitz <t1> <t2> <t3> --workers 4` — parallel multi-target
  scans; each target passes the truth layer independently, so one dead
  host yields that host's honest `U` result without sinking the batch.
- `reconpro diff last last-2` — regression detection between two saved
  scans (the "scan → deploy → scan → diff" workflow; full example in
  [ADVANCED.md](ADVANCED.md#history-and-diff)).
- `reconpro serve --port 7890` — REST wrapper over the same results, for
  dashboards that poll instead of parsing files.

## Air-gapped verification

ReconPro can be introduced into an air-gapped environment with **zero
network trust in the transfer medium**:

1. **Transfer out-of-band** — wheel, sdist, SBOM, `SHA256SUMS`,
   `SHA256SUMS.ed25519`, `SHA256SUMS.asc` (the release assets), plus
   this repository's `docs/keys/` for the public keys.
2. **Verify hashes** (no network needed):
   `sha256sum -c SHA256SUMS` — every artifact must match.
3. **Verify the Ed25519 signature** (authoritative; pure local crypto):

   ```bash
   python3 - <<'EOF'
   from pathlib import Path
   pub = bytes.fromhex(Path("tools/keys/release_key.pub").read_text().strip())
   sig = bytes.fromhex(Path("SHA256SUMS.ed25519").read_text().strip())
   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
   Ed25519PublicKey.from_public_bytes(pub).verify(sig, Path("SHA256SUMS").read_bytes())
   print("Ed25519 signature: VALID")
   EOF
   ```

4. **Verify the GPG signature** if you use Web-of-Trust tooling:
   `gpg --import docs/keys/reconpro-release-5F3D637E.asc && gpg --verify
   SHA256SUMS.asc SHA256SUMS` (the key is also on
   `keyserver.ubuntu.com` / `keys.openpgp.org` for online environments).
5. **Re-verify the provenance chain** from a repository checkout:
   `python tools/release_manager.py verify` — exit 0 means hashes, both
   signatures, the SBOM, the manifest and the commit→build→signature
   chain are all consistent.
6. **Install offline**: `pip install --no-index --find-links .
   reconpro==11.2.0` (both runtime deps — `rich`, `textual`, `requests`,
   `cryptography` — must be vendored the same way if the environment is
   fully offline; the SBOM lists every component and license).

Because wheel **and** sdist are byte-reproducible (v11.2.0+), an
air-gapped site can independently rebuild from source and compare
hashes with the published `SHA256SUMS` — the ultimate no-trust
transfer: ship only the public key, rebuild everything else.

Step-by-step key material and per-release evidence:
[keys/](../keys/README.md), [RELEASES.md](../RELEASES.md). The full
trust-chain reasoning: [PROVENANCE.md](../PROVENANCE.md).

## Key rotation (what to expect as a consumer)

The rotation process maintainers follow (defined in
[keys/README.md](../keys/README.md)):

1. the new public key is **published before first use** (repo +
   keyservers), with the old key kept for historical artifacts;
2. one release is signed with **both** keys as a transition anchor;
3. the old key is revoked with a signed revocation and the
   [RELEASES.md](../RELEASES.md) key table is updated.

As a consumer: pin the fingerprints you trust, re-pin on rotation
announcements, and treat any release signed by an unknown key as
unverified. The v11.1.0 signing key was never published — that gap is
recorded honestly in [RELEASES.md](../RELEASES.md); v11.2.0+ keys are
all published.

## Operational hygiene for scanning fleets

- **Be a good citizen** — `--rate-limit` (0.1–1000 req/s) is shared
  across all modules of a scan; `--all --rate-limit 2` is the polite
  deep scan. Timeouts: `--timeout` per request (1–600 s, default 8).
- **Store the JSON, not the terminal output** — the JSON schema is the
  SDK contract ([sdks/POLICY.md](../../sdks/POLICY.md),
  [../reference/API.md](../reference/API.md)); human output is a
  rendering.
- **`--insecure` is a recorded exception**, not a habit: it is the
  single audited TLS opt-out, and every result permanently carries
  `tls_valid: false` (see [ADVANCED.md](ADVANCED.md#insecure-mode--partial-targets)).
- **Authorization first**: scan targets you own or are explicitly
  permitted to test — ReconPro is a tool, not a license.

## Related

- [SCANNING.md](SCANNING.md) — truth states, module selection, limits
- [REPORTS.md](REPORTS.md) — every report format and its fields
- [ADVANCED.md](ADVANCED.md) — blitz, diff, plugins, `--insecure`
- [../SECURITY.md](../SECURITY.md), [../security/THREAT_MODEL.md](../security/THREAT_MODEL.md) — the security posture and reasoning

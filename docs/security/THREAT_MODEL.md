# Threat Model — ReconPro

A security tool has **two** threat models, and conflating them is how
tools get owned:

1. **The analyst's model** — what ReconPro helps *you* find on your
   assets (exposed secrets, missing headers, weak auth) — the product.
2. **ReconPro's own model** — what an attacker can do *to* the tool
   (through hostile scan targets, malicious plugins, forged releases) —
   the subject of this page, because ReconPro runs on your machine, in
   your CI, pointed at networks you do not control.

Every claim below points at the enforcing code and the regression test
that locks it in. The general posture is summarized in
[../SECURITY.md](../SECURITY.md); the release-integrity half of this page
continues in [../PROVENANCE.md](../PROVENANCE.md).

## Assets and trust boundaries

```
   YOU (analyst / CI runner)
        │ runs
        ▼
   reconpro CLI ──── ~/.reconpro/ (history, plugins, keys, logs)
        │                    ▲
        │ scans              │ loads (signed, sandboxed)
        ▼                    │
   HOSTILE NETWORK      PLUGIN AUTHOR
   (targets you probe)        ▲ signs
        │                     │
        ▼                     │
   RELEASE CHANNEL ───────────┘
   (PyPI / GitHub artifacts)
```

- The **network** is hostile by definition — every response ReconPro
  parses (banners, headers, bodies, certificates) is attacker-controlled
  input.
- The **plugin author** is semi-trusted — plugins run code, but only
  inside the sandbox and only signed.
- The **release channel** must be verifiable end-to-end (hashes,
  signatures, provenance).

## Attack surface 1: hostile scan targets

| Threat | Defense | Enforced by |
|---|---|---|
| Slowloris / hanging responses stall the scan | per-request `--timeout` (1–600, validated), per-module **adaptive timeouts** (`max(t, avg×2.5)`), wall-clock SIGKILL in the plugin runner | `engine.py` |
| Regex/parsing DoS via crafted banners or bodies | bounded pattern suites; the known mid-expression `(?i)` crash class was fixed and regression-tested (v11.2.0) | `test_regression_v11.py`, module health matrix |
| One flaky module poisoning every scan | **circuit breakers** — 3 failures/60 s opens the breaker; 5 consecutive failures quarantines a module for 600 s with a single auto-recovery probe | `ModuleHealthState` in `engine.py` |
| Terminal-content spoofing via crafted hostnames/errors (Rich markup like `[red]PASS[/]`) | every dynamic string passes through `escape()` before rendering | `test_cli.py::TestRichMarkupEscaping` |
| MITM feeding false scan data | **TLS verified by default**; the only unverified contexts are the two audited helpers in `http_layer.py` (`--insecure` opt-in, and cert *inspection*) | `test_security_sweep.py` (AST) |
| Flooding a fragile target (making *you* the incident) | global `--rate-limit` (0.1–1000 req/s, validated, shared across modules) | `cli.py` validation |
| False "HIGH" claims about hosts never reached | the **truth layer** — UNREACHABLE targets short-circuit (score 0, grade U); PARTIAL caps severity at medium | `target_validation.py`, `test_truth_layer.py` |
| Secrets in *your* evidence leaking through reports | secret matches are masked in evidence (`Match: AKIAIOSF...MPLE` — first 8 + `...` + last 4 characters; shorter values become `***`), verified in live `dev` scan output | `security.py` detectors, `modules/dev.py` masking |

## Attack surface 2: the local machine

| Threat | Defense | Enforced by |
|---|---|---|
| Shell injection through tool output (a banner containing `$(...)` that a host-audit helper might execute) | **no `shell=True` anywhere**; commands execute as argument lists; the emulated shell subset (pipes, `||`, redirects) is implemented in Python over `subprocess.run(argv, shell=False)` | `safe_command.py`, `test_security_sweep.py` (AST + marker-file behavioral tests) |
| Zip-slip / symlink escape / zip-bomb via imported workspaces | `safe_archive.py`: path validation, link rejection, 100 MiB decompression cap checked before *and* during extraction, `0o600` files | `safe_archive.py`, `test_security_sweep.py` |
| Unsafe deserialization of scan/config data | no `pickle`/`marshal`; all JSON via strict parsers, all YAML `safe_load`; corrupted `config.json` produces a finding, never a crash | `diagnostics.py`, `test_truth_layer.py` |
| Prompt injection riding target content into AI features (chat, agent, copilot) | `prompt_defense.py`: 6-category `InjectionDetector`, 5-level `ThreatClassifier`, `PromptSanitizer`, audit logging; 150 dedicated tests | `test_prompt_defense.py` |

## Attack surface 3: plugins

A plugin is arbitrary code you chose to run — the sandbox exists so that
choice is *containable*:

- separate OS process (`start_new_session=True`), own PID/process group;
- `RLIMIT_AS` 128 MiB · `RLIMIT_CPU` 10 s · `RLIMIT_FSIZE` 16 MiB ·
  `RLIMIT_NOFILE` 64 · no core dumps; wall-clock SIGKILL of the whole
  process group at 15 s;
- a CPython **audit hook** blocks subprocess/exec/fork, setuid-family
  calls, sockets (unless granted), and every filesystem mutation outside
  the workdir — with `realpath` resolution so symlinks cannot escape;
  reads are default-deny; `/etc`, `/root`, `/proc`, `/sys`,
  `/var/run/secrets` are hard-denied even when granted;
- the worker environment strips `RECONPRO_RELEASE_KEY`,
  `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY` even if the manifest allowlists them;
- static analysis refuses `subprocess`/`ctypes`/`eval`-style plugins
  **before** they load; `subprocess` permission is never grantable;
- results are validated (list-of-dicts, bounded size/count) — a plugin
  cannot corrupt the result pipe.

Attack/defence transcripts and the permission model:
[../PLUGINS.md](../PLUGINS.md). Platform limits are CPython/Linux
mechanics; elsewhere the worker **refuses to run** rather than degrade
to unenforced execution.

## Attack surface 4: the supply chain (the tool itself)

This is where a scanner becomes the delivery vehicle:

| Transition | Threat | Control |
|---|---|---|
| source → commit | a build that does not match the repo | release gate requires a **clean tree**; `PROVENANCE.json` binds commit SHA + source-tree digest |
| commit → build | non-reproducible artifacts (a build-time implant) | **byte-reproducible wheel and sdist** (double-build byte-identity enforced by `tools/release_gate.sh`) |
| build → artifacts | tampering on the release channel | `SHA256SUMS` + **Ed25519 signature** (authoritative) + GPG detach-sig; CycloneDX 1.5 SBOM with per-component licenses |
| artifacts → you | installing something else entirely | `python tools/release_manager.py verify` re-checks hashes, both signatures, SBOM, manifest and the provenance chain end-to-end; 1-byte tamper → exit 1 |
| dependencies | compromised upstream packages | dependabot (pip + actions, weekly), `pip-audit` in the daily security workflow, pinned requirements |

Full procedure and key-rotation process:
[../RELEASE.md](../RELEASE.md) · keys: [../keys/README.md](../keys/README.md)
· per-release evidence: [../RELEASES.md](../RELEASES.md) · the trust
chain, transition by transition: [../PROVENANCE.md](../PROVENANCE.md).

## Honest limits (what this threat model does not claim)

- **The sandbox is CPython/Linux.** The audit hook and rlimits are
  interpreter/OS mechanics; on other platforms the worker refuses to run
  rather than pretend.
- **Prompt defense is pattern-based.** It raises the cost of injection
  and logs everything, but no filter is a proof.
- **`--insecure` exists** because enterprises deliberately scan
  self-signed hosts; it is loudly opt-out, and the report permanently
  records `tls_valid: false`.
- **A green scan is not an attestation.** Findings are evidence-based
  estimates (`confidence` 0–1); the absence of findings is the absence of
  evidence, not evidence of safety.
- **Compliance mapping is a reporting aid**, not a certification (see
  the README's honest-status notes).
- ReconPro is a scanner, not an IDS: it observes at scan time; it does
  not monitor continuously.

## Reporting a weakness in this model

Follow the reporting policy in
[../../SECURITY.md](../../SECURITY.md) (private advisory, 72 h
acknowledgement). "A claim on this page is false" is explicitly listed
there as a security issue — the enforcement is supposed to be real.

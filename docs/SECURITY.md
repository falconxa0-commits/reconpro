# Security Posture

How ReconPro v11.1.0 defends *itself* — the CLI you are running on your
machine and in your CI. This page documents the posture, points at the
enforcing code, and tells you how to report issues. The regression suite
locks every claim below in with AST and behavioural tests
(`reconpro/tests/test_security_sweep.py`, 34 tests;
`test_security*.py`, 383 tests; `test_plugin_sandbox_attacks.py`).

## Strict CLI — typos exit 2

The CLI is strict: `parser.parse_args()` (never `parse_known_args`),
so unrecognized arguments are a hard error. Verified:

```
$ reconpro --bogus-flag
reconpro: error: unrecognized arguments: --bogus-flag      # exit 2
$ reconpro history --json
usage: reconpro ...                                        # exit 2 (no such flag)
$ reconpro plugin
reconpro plugin: error: the following arguments are required: action   # exit 2
```

This makes it safe to script: a misspelled flag cannot be silently
ignored and turn a scan into something else. Runtime failures (unknown
subcommand, plugin failures, failed verifies) exit 1.

## TLS verified by default

**Every** outbound HTTPS connection verifies certificates. The default
context everywhere is `ssl.create_default_context()`. The only way to
opt out is an explicit user flag:

```
reconpro scan example.com --insecure     # (network) same as -k
reconpro vibesec example.com -k          # (network)
reconpro wishes example.com --insecure   # (network)
reconpro quantum-fingerprint example.com -k   # (network)
reconpro ai-redteam example.com --insecure    # (network)
```

`--insecure`/`-k` sets `verify_tls=False` on those code paths only.
There are exactly **two** audited helpers in `reconpro/http_layer.py`
that can construct an unverified context:

1. `_unverified_context()` — reachable **only** behind explicit user
   opt-in (`--insecure`/`-k`); the policy comment in
   `http_layer.py:46-60` spells this out.
2. `inspection_context()` — for *certificate inspection* only (reading
   issuer/validity/SANs of a peer certificate, where chain verification
   is not the purpose). Never used for data transport.

No other module may construct an unverified context by hand — an AST
regression test (`test_security_sweep.py`) enforces this, and
`tools/security_scan.py` (used by the CI security workflow) fails the
build on any new occurrence.

## Shell-free command execution

No `shell=True` anywhere in the runtime package. Commands run as
**argument lists**:

- `reconpro/safe_command.py` — `run_command()` tokenises with `shlex`
  and executes `subprocess.run(argv, shell=False)`. A small shell subset
  (redirects `2>/dev/null`, `A || B` fallback, `A | B` pipelines) is
  emulated **in Python**, never by spawning a shell. Shell
  metacharacters (`;`, `$()`, backticks, `&&`) are passed through as
  literal arguments — injection attempts become harmless text.
  Used by the `host` and `doctor` audit helpers (~72 call sites).
- `reconpro/nexus_agent.py` `_tool_shell_command` — `shlex.split` +
  argument list.
- `reconpro/tool_sdk.py` `ExternalToolHandler` — `shlex.split` +
  argument list for user-defined tools.
- No `os.system` / `os.popen` / bare `eval`/`exec`/`compile` calls on
  user input; no `pickle`/`marshal` deserialization; all YAML is
  `yaml.safe_load`.

All of the above are enforced by AST regression tests, and were proven
behaviourally: payloads like `echo x; touch /tmp/marker` and
`` touch `id` `` echo literally and the marker file is never created.

## Safe archive extraction

`reconpro/safe_archive.py` backs workspace import (`.ws` archives) and
any future extraction:

- member paths validated — absolute paths, `..` traversal, and
  drive-relative (`C:foo`) names rejected (zip-slip defence);
- symlink and hard-link members rejected;
- decompressed size capped per member **and** in aggregate at 100 MiB,
  checked from metadata **before** extraction and re-checked while
  streaming (zip-bomb defence);
- extracted files `0o600`, directories `0o700` — extracted content can
  never become world-writable.

## Prompt injection defense

AI-facing components (chat, agent, copilot, nexus agent) are wrapped in
`reconpro/prompt_defense.py`: a pattern-based `InjectionDetector` (6
categories: instruction override, delimiter injection, code injection,
data exfiltration, context manipulation, encoding/obfuscation), a
5-level `ThreatClassifier`, a `PromptSanitizer`, and a structured
`DefenseAuditLogger`. Input length, repetition and context-overflow
abuse caps are enforced. 150 dedicated tests
(`test_prompt_defense.py`, all passing in 0.29 s) plus the
`--defense` flag on `scan`/`audit` for validation of AI inputs.

## Terminal markup injection (Rich escaping)

Anything dynamic that is printed — exception text, plugin ids and
paths, scan targets — is escaped with
`reconpro.lazy_rich.escape()` before it reaches `console.print`.
Without this, bracketed attacker-controlled content
(`[red]FAKE-PASS[/]`, or simply a regex character class like
`[a-z0-9_-]` in an error message) would be parsed as Rich markup
tags: silently swallowed or rendered as fake colored output — a
terminal content-spoofing vector. A source-level regression test
(`test_cli.py::TestRichMarkupEscaping`) fails the build if any
`{exc}`-style interpolation in `console.print` bypasses `escape()`.
Verified live: `reconpro plugin create '[red]FAKE[/]'` prints the
hostile name literally, never as markup.

## Plugin sandbox

Plugins run in a **separate OS process** with `RLIMIT_AS` 128 MiB,
`RLIMIT_CPU` 10 s, `RLIMIT_FSIZE` 16 MiB, a wall-clock SIGKILL, a
minimal environment (secrets stripped), and a CPython audit hook that
blocks subprocess/exec/fork, setuid-family calls, sockets (unless
granted), and filesystem writes outside the workdir — with
`realpath`-resolution so symlinks cannot escape. Static analysis gates
every run: `subprocess`/`ctypes`/`eval`-style plugins are refused
before they load. `subprocess` permission can never be granted. Full
details, live attack/defence transcripts and the permission model:
[PLUGINS.md](PLUGINS.md).

## Supply chain / release integrity

- Release artifacts (wheel, sdist, SBOM) are covered by `SHA256SUMS`
  with both an **Ed25519** signature and a GnuPG detach-sig;
  `python tools/release_manager.py verify` recomputes and checks all of
  them (a 1-byte tamper makes it fail with exit 1).
- A **CycloneDX 1.5 SBOM** ships with every release, validated against
  the official schema.
- `tools/security_scan.py` runs an AST security scan in CI (daily
  workflow + PR gate) against a baseline; new findings fail the build.
- Plugin code is Ed25519-signed and hash-pinned at install; see
  [PLUGINS.md](PLUGINS.md) and [RELEASE.md](RELEASE.md).

## Reporting issues

This repository is an internal exercise artifact; there is no public
tracker. If you are working within this program:

1. Do not open public issues for security findings.
2. Record the finding in the worklog with a "SECURITY" prefix, or hand
  it to the current security-sweep owner (task 7-a in the PHOENIX
  program).
3. For upstream-style disclosure if this code is ever published: create
  a private advisory (GitHub "Security advisories" → "Report a
  vulnerability") rather than a public issue; include reproduction
  steps and the enforcing-test reference if you believe a claim on this
  page is false.

## Honest limits

- Certificate-inspection connections intentionally do not verify the
  chain (that is their purpose); they are never used for data transport.
- The `zai` command streams to z.ai when used — it is opt-in and only
  runs when invoked.
- `--insecure` exists because enterprises scan hosts with self-signed
  certs on purpose; it is loudly opt-out, never a default.
- Platform limits (`RLIMIT_*`, audit hook) are CPython/Linux mechanics;
  on other interpreters/OSes the sandbox degrades to "no grant" rather
  than "no enforcement" (the worker refuses to run if limits cannot be
  applied where it matters most).

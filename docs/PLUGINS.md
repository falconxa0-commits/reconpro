# Plugins — the ReconPro Plugin SDK

ReconPro v11.2.0 ships a sandboxed plugin SDK: plugins are **separate OS
processes** behind an audit hook, not in-process code. This document
covers the sandbox guarantees, the permission model, the manifest
format, signing, the install/verify/upgrade lifecycle, and a complete
worked example (every command below was executed against this repo).

Plugin internals live in `reconpro/plugin_sdk/` (runner, worker,
manager, manifest, permissions, crypto, scaffold, analysis).

## Layout

```
~/.reconpro/plugins/
  <plugin-id>/            SDK plugin: plugin.toml + main.py (+ README.md)
  <name>.py               LEGACY loose plugin (unsigned, always sandboxed)
  registry.json           install registry (sha256, version, trust) — 0600
  keys/
    local.ed25519         your dev keypair, private half (0600)
    trusted/*.pub         trusted public keys (hex)
```

## The sandbox — what a plugin can never do

Every plugin execution (`reconpro plugin run`, `reconpro playground`, and
the internal `run_plugin()` API) spawns
`python -m reconpro.plugin_sdk.worker` — a **separate OS process with its
own PID and process group** — and communicates over a JSON pipe.

| Guarantee | Mechanism | Verified in this repo |
|---|---|---|
| Separate process/PID | `subprocess.Popen(..., start_new_session=True)`; the result reports the worker's PID | `reconpro playground` printed `pid=23234` while the CLI had a different PID |
| Memory cap | `RLIMIT_AS = 128 MiB` (default `memory_mb=128`) | `reconpro/plugin_sdk/runner.py` + `worker.py` |
| CPU cap | `RLIMIT_CPU = 10 s` (default `cpu_seconds=10`) | same |
| File-size cap | `RLIMIT_FSIZE = 16 MiB` (default `fsize_mb=16`) | same |
| No file descriptors leak | `RLIMIT_NOFILE = 64`; `RLIMIT_CORE = 0` | same |
| Wall-clock kill | parent `communicate(timeout=15 s)`; on expiry the whole **process group** gets `SIGKILL` (`os.killpg`) | same |
| No subprocess / exec / fork / setuid | CPython **audit hook** (`sys.addaudithook`, cannot be uninstalled) blocks `subprocess.Popen`, `os.system/exec/spawn/posix_spawn/fork/forkpty/vfork`, and `os.setuid/setgid/setgroups/setreuid/setregid/initgroups` | test suite `test_plugin_sandbox_attacks.py` |
| No sockets (unless granted) | audit hook blocks `socket.__new__` when `network=false` | same |
| Writes only inside workdir + granted roots | audit hook intercepts `open`/`os.open` and every mutation event (`rename`, `remove`, `mkdir`, `symlink`, `chmod`, …), resolves paths with `realpath` (symlinks cannot escape), and rejects anything outside the write roots | live test below |
| Reads default-DENY | the hook allows reads only from workdir, the plugin's own dir, Python system dirs, safe `/dev` nodes (`/dev/null`, `/dev/urandom`, `/dev/zero`, `/dev/full`) and explicitly granted `fs_read` roots | `reconpro/plugin_sdk/worker.py` |
| Banned imports | `subprocess`, `ctypes`, `multiprocessing`, `concurrent.futures` cannot be imported at all (import event is audited) | live test below |
| Env isolation | the worker's environment contains only `PATH`, `HOME=workdir`, `TMPDIR=workdir`, `PYTHONPATH`, `PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`, `RECONPRO_SANDBOX=1` plus manifest-allowlisted vars; `RECONPRO_RELEASE_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` are stripped even if allowlisted | `_build_env()` in `reconpro/plugin_sdk/runner.py` |
| Sensitive roots hard-denied | `/etc`, `/root`, `/proc`, `/sys`, `/dev/log`, `/var/log`, `/var/run/secrets`, `/run/secrets` are never readable regardless of manifest grants | `SENSITIVE_READ_ROOTS` in `reconpro/plugin_sdk/permissions.py` |

Live verification (this machine):

```
$ reconpro plugin playground sneaky.py   # plugin tries open("/tmp/sneaky-marker", "w")
  Running sneaky.py against example.com (sandbox: own PID, no net, no
  subprocess, workdir-only writes)
  result: kind=violation ok=False pid=23997 duration=1ms
  error:[] sandbox: write outside sandbox (/tmp/sneaky-marker)
  violation:[] open — write outside sandbox (/tmp/sneaky-marker)
$ ls /tmp/sneaky-marker
  ls: cannot access — marker NOT created
```

and the static gate refusing a `subprocess`-importing plugin **before**
it ever loads:

```
$ reconpro plugin playground evil.py    # plugin imports subprocess
  Static analysis refuses this plugin:
  2 blocking violation(s): banned-import@L1(import of 'subprocess' is forbidden
  in the sandbox); subprocess@L3(subprocess call via subprocess.Popen())
```

### Output validation

The worker also validates plugin results: the plugin must return a
**list of dicts** each with non-empty `title`, `severity`, `category`;
at most 1000 findings; the JSON blob must fit `max_output_bytes`
(1 MiB default). Plugin `print()` output is redirected to stderr so it
can never corrupt the result pipe. Violations are *results*, not
crashes — the worker always delivers a structured JSON status line.

## Permission model

Declared in `plugin.toml` under `[permissions]`:

| Permission | Type | Meaning |
|---|---|---|
| `network` | bool (default `false`) | may open sockets |
| `fs_read` | list of paths | extra readable roots (normalised, not resolved — the worker re-resolves with `realpath` at every access) |
| `fs_write` | list of paths | extra writable roots (workdir is always writable) |
| `env` | list of var names | environment variables copied from the parent into the worker |
| `subprocess` | — | **can never be granted.** Requesting `subprocess = true` is an install-time error: *"permission 'subprocess' can never be granted (sandbox policy: no child processes)"* |

Risk grading (informational, from `PermissionSet.risk_level()`):
minimal → low (`fs_read`/`env`) → moderate (`network` xor `fs_write`) →
elevated (`network` + writes).

## Manifest format (`plugin.toml`)

Generated by `reconpro plugin create-sdk <name>` (stdlib `tomllib`):

```toml
id = "my-check"                     # required; ^[a-z0-9][a-z0-9_-]{0,63}$, must equal the directory name
name = "My Check"                   # required; 1..64 chars
version = "0.1.0"                   # required; semver X.Y.Z
description = "Custom ReconPro plugin"  # required; <= 512 chars
author = "you"                      # optional; <= 128 chars
reconpro_min = "11.1.0"             # optional; semver, default "11.0.0"

[permissions]
network = false
fs_read = []
fs_write = []
env = []

# Added by `reconpro plugin sign <dir>`:
[provenance]
signature = "<hex Ed25519 signature>"
key_id = "<public key hex>"
```

`plugin.toml` + `main.py` are both required; the skeleton also ships a
README. `main.py` must expose `run(...)` returning a list of finding
dicts (`title`, `severity`, `category` required; `description`,
`evidence`, `asset`, `points_deducted`, `remediation` recommended).
The default signature accepts `run(target, base_url="", timeout=8,
verify_tls=True)`; extra kwargs are matched by name.

## Signing (Ed25519)

- `reconpro plugin keys` — shows (or first-creates) your local dev
  keypair: private half at `~/.reconpro/plugins/keys/local.ed25519`
  (0600), public half in `keys/trusted/local.pub`. Share only the public
  hex; other machines trust it by dropping it into their `trusted/` dir.
- `reconpro plugin sign <dir>` — signs the canonical payload
  (manifest fields + SHA-256 of `main.py`) and embeds
  `[provenance] signature` + `key_id` into `plugin.toml`.
- Install verifies the signature against every trusted public key;
  unsigned plugins are refused unless `--allow-unsigned` is passed, in
  which case the registry records `trusted: false`.

Real `reconpro plugin keys` output (id truncated):

```
  local dev key  id: 262e80c3a2f35de8
  public : b4d43771c1c450990dd5fd075c6863c7802182869267c78c1037806ae58559df
  private: ~/.reconpro/plugins/keys/local.ed25519 (0600)
  share the PUBLIC key; other machines add it via `reconpro plugin keys` +
trusted dir
```

## Lifecycle commands

```
usage: reconpro plugin [-h] [--allow-unsigned] [--json]
                       {list,create,create-sdk,run,install,verify,upgrade,remove,sign,keys}
                       [name] [target]
```

| Action | Behavior (verified) |
|---|---|
| `list` | lists installed plugins with trust status; `--json` for machine output. Empty state: `No plugins found. Create one: reconpro plugin create-sdk my-check` |
| `create <name>` | creates a **legacy loose .py** template in `~/.reconpro/plugins/` (name must be `snake_case`; hyphens are rejected with a `ScaffoldError`). Unsigned. |
| `create-sdk <name>` | creates a signed-ready skeleton (`plugin.toml`, `main.py`, `README.md`) in the **current directory**. This is the recommended path. |
| `run <id> <target>` | executes the plugin in the sandbox and prints findings as severity lines; network-free unless the plugin has the `network` permission. Missing plugin → prints an info-level "not found" finding (exit 0). |
| `install <dir-or-file>` | static analysis → signature check → copy into the plugin root + registry entry (sha256, version, trust). Unsigned → refused; `--allow-unsigned` records untrusted. Already installed → refused (use `upgrade`/`remove`). |
| `verify <id>` | re-checks source hash vs registry, signature vs trusted keys, static analysis. `PASS`/`FAIL` + per-check lines; exit 0 only when all checks pass. |
| `upgrade <new-plugin-dir>` | installs a strictly newer version (semver compare; refuses same/older versions). |
| `remove <id>` | deletes the registry entry and the plugin files. |
| `sign <dir>` | embeds an Ed25519 signature (see above). |
| `keys` | shows the local dev keypair. |

Exit codes: plugin action failures exit 1; `plugin` with no action
exits 2 (argparse); `plugin verify` exits 1 on FAIL.

## Legacy loose `.py` plugins

A bare `<name>.py` with a `run()` function in the plugin root is
discovered and runnable, but: unsigned by design (verify() reports
"legacy plugins are unsigned by design"), no manifest, no permissions
(always the default minimal `PermissionSet()`), and still **always
sandboxed** — there is no unsandboxed execution path anywhere
(`run_plugin(use_sandbox=...)` is accepted for API compatibility and
ignored, security policy). Legacy discovery uses an AST gate (valid
syntax + callable `run`) — plugin code is never imported during
discovery.

## Worked example (create → edit → sign → install → verify → run)

All six steps were executed against this repository; outputs below are
real.

```bash
# 1. Scaffold a signed-ready SDK plugin in the current directory
$ reconpro plugin create-sdk my-check
  SDK plugin skeleton created: /path/to/reconpro-github/my-check
  Next: edit main.py, then `reconpro plugin sign <dir>` and `plugin install <dir>`

# 2. Edit my-check/main.py — make run() return findings:
#    findings = [{
#        "title": f"Stub finding for {target}",
#        "severity": "info",
#        "category": "custom",
#        "description": "Scaffold output — edit run() in main.py",
#        "asset": target,
#    }]

# 3. Sign it with your local dev key
$ reconpro plugin sign my-check
  Signed my-check
  signature: 0a684eca65b9de76309636e2cea55200…

# 4. Install (verifies the signature, records sha256 in the registry)
$ reconpro plugin install my-check
  Installed my-check v0.1.0 (trusted)
  permissions: network=no, subprocess=never

# 5. Verify — hash drift + signature + static analysis
$ reconpro plugin verify my-check
  PASS  my-check
    ok   source_hash
    ok   signature
    ok   static_analysis

# 6. Run it in the sandbox
$ reconpro plugin run my-check example.com
  INFO      Stub finding for example.com
```

### Drift detection is real

If the installed `main.py` is edited after install, `plugin verify`
fails (exit 1):

```
$ (edit ~/.reconpro/plugins/my-check/main.py)
$ reconpro plugin verify my-check
  FAIL  my-check
    FAIL   source_hash
    FAIL   signature signature missing or untrusted key
    ok   static_analysis
```

Recovery: `plugin remove <id>`, re-`sign` the source dir, re-`install`.

## Safe experimentation: `reconpro playground`

```
usage: reconpro playground [-h] [--target TARGET] [file]
```

Runs any plugin `.py` (or a built-in template if no file is given) in
the sandbox **without installing it**, against `--target` (default
`example.com`). This is the fastest way to check that your plugin plays
by the rules — e.g. the sandbox-violation and static-refusal outputs in
the table above.

## Writing a good plugin

1. Start from `create-sdk`; keep `[permissions]` minimal — ask for
   nothing unless you need it.
2. `run()` returns findings synchronously; keep it under the CPU
   (10 s) and wall-clock (15 s) limits.
3. Network plugins: set `network = true`, then use verified TLS
   (`verify_tls=True` is passed to you by default — honour it).
4. Severity strings: `info | low | medium | high | critical`.
5. Test with `reconpro playground my-plugin.py` before signing.

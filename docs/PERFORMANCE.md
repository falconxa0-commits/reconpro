# Performance — CLI startup

ReconPro's CLI has a hard cold-start budget of **100 ms**, enforced in
CI. This page documents the numbers, the gate, and the lazy-import
architecture that makes them possible.

## Current numbers (this machine, Python 3.12)

Measured with `tools/bench_startup.py` (cold `import reconpro.cli` +
`--version`, one untimed warmup then timed runs). Two fresh sessions on
the shared documentation sandbox while this page was verified (v11.2.0):

```
$ python tools/bench_startup.py --runs 10          # session 1
[bench] stats_ms: {"min_ms": 47.63, "median_ms": 47.83,
                   "avg_ms": 48.1, "p95_ms": 49.21, "max_ms": 49.21}

$ python tools/bench_startup.py                    # session 2 (default 7 runs)
[bench] warmup (untimed, discarded): 54.31 ms
[bench] run 1/7:    52.79 ms        (… runs 2-7: 52.47-53.10 ms)
[bench] {"min_ms": 52.47, "median_ms": 52.55, "avg_ms": 52.68,
         "p95_ms": 53.1, "max_ms": 53.1}
[bench] threshold (median) = 100.0 ms -> PASS
```

**Median 47.8–52.6 ms** depending on machine load (both sessions well
under the 100 ms CI budget); the developer workstation where the
lazy-import work landed measured **≈ 46 ms**. Before the lazy-import
work, cold start measured **~570 ms** (the release engineer's baseline
runs measured medians of 564–594 ms with p95 up to ~1 s under load) — a
~12× improvement. The remaining cost is dominated by Python interpreter
startup itself.

## The benchmark tool

```
usage: bench_startup.py [-h] [--threshold-ms THRESHOLD_MS] [--runs RUNS]
                        [--json-out JSON_OUT] [--python PYTHON]
```

- spawns the real CLI (`<python> -m reconpro.cli --version`) as a
  subprocess — measures **cold** import cost, not a warm cache;
- one untimed warmup run, then N (default 7) timed runs;
- reports min / median / avg / p95 / max;
- `--threshold-ms` (default 100) — **exit 1 if the median exceeds the
  budget**; `--json-out` writes the full report; `--python` selects the
  interpreter (default: the running one).

## The CI gate

`.github/workflows/ci.yml` runs the benchmark with the default 100 ms
threshold on every push/PR; `tools/ci_local.sh` is the local mirror
(`STARTUP_BUDGET_MS` env, default 800 ms to tolerate loaded dev
machines — CI uses the real 100 ms). Note honestly: the workflows have
not yet executed on GitHub Actions; the gate logic itself is the
locally-verified script above.

## How the lazy-import architecture works

Three cooperating mechanisms keep the heavy stack off the fast paths:

### 1. PEP 562 module `__getattr__` — `reconpro/__init__.py`

`__init__.py` defines an `_LAZY_ATTRS` map (name → (module, attribute))
and a module-level `__getattr__(name)` (PEP 562). Importing `reconpro`
is cheap; touching e.g. `reconpro.scan` triggers the real
`importlib.import_module` on first access and **caches the resolved
value in `globals()`** so subsequent lookups are direct. `__dir__`
exposes the lazy names for discoverability.

### 2. `_load_heavy()` in `reconpro/cli.py`

`cli.py` imports only `lazy_rich` names at module level. The engine
stack — `scanner` (module registry), `engine`, `registry`, `history`,
`reports`, `parallel` — is deferred to `_load_heavy()`, which is called
**only** for scan-class commands. Fast-path subcommands never pay the
~300 ms registry import:

```python
_FAST_SUBCOMMANDS = {None, "tutorial", "suggest", "wizard", "playground", "plugin"}
# (doctor --repair also stays light; plain doctor is a scan-class command)
if cmd not in _FAST_SUBCOMMANDS and not (cmd == "doctor" and getattr(args, "repair", False)):
    _load_heavy()
```

To keep `unittest.mock.patch("reconpro.cli.save_scan")` and friends
working, the heavy names exist at module level as `_LazyHeavy` shims
(callable + `__getattr__` + `__getitem__` + `__contains__` +
`__iter__` + `__len__`) that resolve the real object on first use and
then replace themselves in module globals.

### 3. `lazy_rich` proxies — `reconpro/lazy_rich.py`

Importing `rich` alone costs ~110 ms — more than the entire startup
budget. `cli.py` therefore imports rich *names* from
`reconpro.lazy_rich`:

- `console` is a `_ConsoleProxy` — a `__getattr__`-resolving stand-in
  that instantiates the real `rich.console.Console(file=sys.stderr)` on
  first use (human output goes to stderr — see
  [CLI_REFERENCE.md](reference/CLI_REFERENCE.md));
- `Panel`, `Table`, `Progress`, `SpinnerColumn`, `TextColumn`, … are
  `_LazyClass` constructor shims: constructing one resolves the real
  class via `importlib`, caches it in `lazy_rich.globals()`, and returns
  the real instance.

Result: `reconpro --version`, `--help`, `tutorial`, `suggest`, `wizard`,
`playground` and `plugin` never import rich or the engine at all.

## What is *not* fast-pathed

Any scan-class command (`scan`, `audit`, `dev`, `doctor`, `blitz`, …)
loads the full engine — that is the design: the 28-module registry,
history and reporting stack is needed there anyway, and scan time
dominates startup for those commands.

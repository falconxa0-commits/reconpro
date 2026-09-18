# reconpro-sdk (TypeScript) — Stable

Typed, **zero-dependency** TypeScript SDK around the ReconPro CLI
(>= 11.2.0) for Node.js >= 18. Every call spawns
`reconpro <command> --json` as a subprocess with an **argument list** —
never a shell string — and parses the JSON contract from STDOUT; the CLI's
pretty UI goes to STDERR (docker/kubectl convention) and is captured only
for error reporting.

Stability tier: **Stable** — versioning & compatibility policy:
[`../POLICY.md`](../POLICY.md).

- **Zero runtime dependencies** — only Node built-ins (`child_process`,
  `fs/promises`, `os`, `path`).
- **Ships compiled**: `dist/index.js` (built with
  `bun build src/index.ts --outdir dist --target node`) +
  `dist/index.d.ts` — plain Node can consume the package with no build step.
- Source is plain TypeScript (`src/index.ts`) — `bun` runs it natively.

## Install / import

```ts
// from a checkout (no npm publish yet):
import { ReconProClient, ReconProError } from "./sdks/typescript/dist/index.js";
// or run the TypeScript source directly with bun:
import { ReconProClient, ReconProError } from "./sdks/typescript/src/index.js";
```

## Usage

```ts
import { ReconProClient, ReconProError, UNREACHABLE_TARGET } from "reconpro-sdk";

const client = new ReconProClient();          // binary: RECONPRO_BINARY env → "reconpro" on PATH
                                             // timeout: RECONPRO_TIMEOUT_MS env → 300 s

const version = await client.version();       // "ReconPro 11.2.0" — doubles as a liveness ping

// Offline truth-layer demo: a nonexistent *.invalid target short-circuits
// instantly (no network): grade "U", targetValidation.state UNREACHABLE_TARGET.
const result = await client.scan("example.com");
console.log(result.grade, result.totalScore, result.severityCounts);
if (result.targetValidation?.state === UNREACHABLE_TARGET) {
  // honest no-result: no security claims about an unreachable target
}
for (const f of result.findings) {
  console.log(f.severity, f.title, f.confidence, f.verificationState);
}

await client.audit();                         // local host/dev audit (offline)
await client.dev("src");                      // scan a local directory (offline)
const report = await client.exportReport("sarif"); // CLI export; default path in tmpdir
```

## API

| Method | Returns | Notes |
|---|---|---|
| `new ReconProClient({ binaryPath?, timeoutMs? })` | `ReconProClient` | binary via option → `RECONPRO_BINARY` env → `"reconpro"` on PATH; timeout via option → `RECONPRO_TIMEOUT_MS` env → 300 000 ms |
| `version()` | `Promise<string>` | verification ping (`reconpro --version`) |
| `scan(target, opts?)` | `Promise<ScanResult>` | `opts.modules?`, `opts.insecure?`, `opts.outputFile?` (persists the JSON via CLI `-o`, still returns the typed result) |
| `vibesec(target, opts?)` | `Promise<ScanResult>` | vibesec module scan |
| `audit(opts?)` | `Promise<ScanResult>` | local host/dev audit (offline) |
| `dev(path?)` | `Promise<ScanResult>` | scan a local directory (offline; default `"."`) |
| `doctor()` | `Promise<ScanResult>` | local health check (offline) |
| `exportReport(format?, path?)` | `Promise<string>` | CLI `export`; format `sarif`/`md`/`json`/`html` (extension appended when missing); default path `reconpro-report.<format>` in the OS temp dir; returns the path written |

`ScanResult` is fully typed for the CLI 11.2.0 contract: `target`,
`modulesRun`, `totalFindings`, `severityCounts`, `totalScore`, `grade`,
`findings` (each `Finding` carries the truth-layer `confidence: number |
null` and `verificationState: string | null`), `targetValidation`
(`state` — the `VERIFIED_TARGET`/`PARTIAL_TARGET`/`UNREACHABLE_TARGET`
union, `dnsResolved`, `reachable`, `httpOk`, `tlsValid`, `details`,
`checkedAt`; `null` for local scans), `scanMetadata` (`scanner`,
`startedAt`, `durationS`, `result`), the convenience flag `unreachable`,
and `raw` (the complete parsed JSON document — unknown future keys stay
accessible).

## Errors — structured `ReconProError`

```ts
try {
  await client.scan("example.com");
} catch (err) {
  if (err instanceof ReconProError) {
    err.code;      // 'BIN_NOT_FOUND' | 'TIMEOUT' | 'NON_ZERO_EXIT' | 'INVALID_JSON'
                   // | 'INVALID_TARGET' | 'UNSUPPORTED_FORMAT'
    err.exitCode;  // number | null (CLI exit code for NON_ZERO_EXIT)
    err.stderr;    // captured stderr (stdout head for INVALID_JSON)
    err.command;   // the argument list that was executed
  }
}
```

## Run tests

```
cd sdks/typescript
bun test                 # 22 hermetic tests (stub binary, no CLI needed)
node tests/dist-smoke.mjs # plain-Node proof that compiled dist/ works
```

Tests use the canned stub binary `tests/fixtures/reconpro-stub.mjs`
(emits JSON byte-faithful to `reconpro scan <x>.invalid --json` on CLI
11.2.0, plus an unknown `future_field` key to pin forward-compat). The
truth-layer contract test asserts `grade === "U"`,
`targetValidation.state === "UNREACHABLE_TARGET"`, finding
`confidence ≈ 0.95`, `verificationState === "UNREACHABLE_TARGET"`.

## Run examples

```
bun run examples/basic.ts                                   # real CLI (offline *.invalid demo)
RECONPRO_BINARY=tests/fixtures/reconpro-stub.mjs bun run examples/basic.ts
bun run examples/error-handling.ts                          # every error code, stub-backed
```

## Regenerating dist

```
bun build src/index.ts --outdir dist --target node   # emits dist/index.js
# dist/index.d.ts is maintained by hand (bun does not emit declarations);
# keep it in sync with src/index.ts when the public surface changes.
```

## Files

`src/index.ts` (typed API), `dist/` (`index.js` + `index.d.ts`, compiled),
`tests/` (`client.test.ts` — bun test, `dist-smoke.mjs` — plain-node dist
proof, `fixtures/reconpro-stub.mjs` — canned stub binary),
`examples/basic.ts`, `examples/error-handling.ts`, `package.json`,
`tsconfig.json`, this README.

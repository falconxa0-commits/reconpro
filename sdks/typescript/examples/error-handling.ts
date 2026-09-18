/**
 * Structured error handling with the reconpro SDK: every failure mode maps
 * to a `ReconProError` with a stable machine-readable `code`.
 *
 * Run:  bun run examples/error-handling.ts
 *
 * Fully offline: the NON_ZERO_EXIT / INVALID_JSON / TIMEOUT demos run
 * against the canned stub binary (tests/fixtures/reconpro-stub.mjs), and
 * BIN_NOT_FOUND / INVALID_TARGET need no process at all.
 */

import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ReconProClient, ReconProError } from "../src/index.js";

const STUB = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "tests",
  "fixtures",
  "reconpro-stub.mjs",
);

function report(prefix: string, err: unknown): void {
  if (err instanceof ReconProError) {
    console.log(
      `${prefix.padEnd(16)}: code=${err.code} exit=${err.exitCode} :: ${err.message}`,
    );
    if (err.stderr) {
      console.log(
        `${" ".repeat(18)}stderr: ${err.stderr.trim().slice(0, 120)}`,
      );
    }
  } else {
    console.log(`${prefix.padEnd(16)}: unexpected error`, err);
  }
}

// 1. BIN_NOT_FOUND — bad path / not on PATH.
const missing = new ReconProClient({
  binaryPath: "/nonexistent/reconpro",
  timeoutMs: 5_000,
});
await missing.version().catch((err) => report("bin not found", err));

// 2. Healthy ping — version() doubles as a liveness + version check.
const stub = new ReconProClient({ binaryPath: STUB, timeoutMs: 15_000 });
console.log(
  `CLI healthy     : version ping → ${await stub.version().catch(() => "(unavailable)")}`,
);

// 3. NON_ZERO_EXIT — exit code (0/1/2/130 contract) + captured stderr.
await stub.scan("make-it-fail.invalid").catch((err) => report("non-zero exit", err));

// 4. INVALID_JSON — exit 0 but stdout was not parseable JSON.
await stub.scan("garbage.invalid").catch((err) => report("invalid json", err));

// 5. TIMEOUT — per-call timeout (ms), process killed.
const slow = new ReconProClient({ binaryPath: STUB, timeoutMs: 300 });
await slow.scan("sleepy-target.invalid").catch((err) => report("timeout", err));

// 6. INVALID_TARGET — client-side validation (defence in depth).
// (scan() is async, so the rejection must be awaited to be observed here.)
try {
  await new ReconProClient().scan("example.com; rm -rf /");
} catch (err) {
  report("rejected target", err);
}

#!/usr/bin/env node
/**
 * Dist smoke test — proves the COMPILED `dist/index.js` works under plain
 * Node (>= 18), with no bun and no build step for consumers.
 *
 * Run:  node tests/dist-smoke.mjs   (from sdks/typescript; or via
 *       `npm run test:dist`)
 *
 * Uses the canned stub binary (tests/fixtures/reconpro-stub.mjs) so the run
 * is hermetic; also exercises the truth-layer contract.
 */

import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ReconProClient,
  ReconProError,
  UNREACHABLE_TARGET,
} from "../dist/index.js";

const STUB = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "reconpro-stub.mjs",
);

const client = new ReconProClient({ binaryPath: STUB, timeoutMs: 15_000 });

// 1. version ping (plain node, compiled dist).
const version = await client.version();
assert.equal(version, "ReconPro 11.2.0");

// 2. truth-layer contract through the compiled dist.
const result = await client.scan("dist-smoke-target.invalid");
assert.equal(result.grade, "U");
assert.equal(result.totalFindings, 1);
assert.equal(result.totalScore, 0);
assert.ok(Array.isArray(result.modulesRun) && result.modulesRun.length === 0);
assert.ok(result.unreachable);
assert.equal(result.targetValidation?.state, UNREACHABLE_TARGET);
assert.equal(result.targetValidation?.dnsResolved, false);
assert.equal(result.findings[0]?.severity, "info");
assert.equal(result.findings[0]?.verificationState, UNREACHABLE_TARGET);
assert.ok(Math.abs((result.findings[0]?.confidence ?? 0) - 0.95) < 1e-9);
assert.equal(result.scanMetadata?.scanner, "reconpro");
// unknown future key stays reachable via raw
assert.equal(result.raw.future_field?.anything?.[0], "the");

// 3. structured errors through the compiled dist.
await assert.rejects(
  client.scan("make-it-fail.invalid"),
  (err) =>
    err instanceof ReconProError &&
    err.code === "NON_ZERO_EXIT" &&
    err.exitCode === 2 &&
    err.stderr.includes("boom"),
);
await assert.rejects(
  client.scan("garbage.invalid"),
  (err) => err instanceof ReconProError && err.code === "INVALID_JSON",
);
await assert.rejects(
  new ReconProClient({
    binaryPath: "/nonexistent/reconpro-xyz",
    timeoutMs: 5_000,
  }).version(),
  (err) => err instanceof ReconProError && err.code === "BIN_NOT_FOUND",
);

console.log(
  "dist-smoke OK: compiled dist/index.js works under plain " +
    `node ${process.versions.node} (version, truth-layer contract, structured errors)`,
);

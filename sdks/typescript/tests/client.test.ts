/**
 * Test suite for reconpro-sdk (TypeScript, Stable tier — see sdks/POLICY.md).
 *
 * Hermetic: every CLI-backed case runs against the stub binary
 * `tests/fixtures/reconpro-stub.mjs` (canned JSON byte-faithful to
 * `reconpro scan <x>.invalid --json` on CLI 11.2.0, plus an unknown
 * "future_field" to pin forward-compat). Error paths are exercised through
 * the real public SDK API via the stub's documented magic targets.
 *
 * Run:  bun test          (or: bun test tests/client.test.ts)
 */

import { describe, expect, test } from "bun:test";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ReconProClient,
  ReconProError,
  UNREACHABLE_TARGET,
  TARGET_STATES,
  validateTarget,
  normalizeScanResult,
  EXPORT_FORMATS,
  DEFAULT_BINARY,
  DEFAULT_TIMEOUT_MS,
} from "../src/index.js";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
export const STUB_PATH = join(TEST_DIR, "fixtures", "reconpro-stub.mjs");

const stubClient = (options = {}) =>
  new ReconProClient({ binaryPath: STUB_PATH, timeoutMs: 15_000, ...options });

/** Minimal sh-script stub (for quirks the fixture does not model). */
async function shStub(body: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "reconpro-sdk-ts-"));
  const path = join(dir, "reconpro-stub");
  await writeFile(path, `#!/bin/sh\n${body}`, "utf8");
  await chmod(path, 0o755);
  return path;
}

/** Await a promise that must reject with a ReconProError; return it typed. */
async function expectSdkError(
  fn: () => Promise<unknown>,
): Promise<ReconProError> {
  try {
    await fn();
  } catch (e) {
    expect(e).toBeInstanceOf(ReconProError);
    return e as ReconProError;
  }
  throw new Error("expected the promise to reject with a ReconProError");
}

// ─────────────────────────── construction & config ─────────────────────────

describe("client construction", () => {
  test("constructor options take precedence; env vars are honoured", () => {
    const before = process.env.RECONPRO_BINARY;
    process.env.RECONPRO_BINARY = "/from/env/reconpro";
    try {
      expect(new ReconProClient().binaryPath).toBe("/from/env/reconpro");
      expect(
        new ReconProClient({ binaryPath: "/explicit/reconpro" }).binaryPath,
      ).toBe("/explicit/reconpro");
    } finally {
      if (before === undefined) delete process.env.RECONPRO_BINARY;
      else process.env.RECONPRO_BINARY = before;
    }
  });

  test("defaults: binary name + 300 s timeout", () => {
    const client = new ReconProClient({ binaryPath: "/x/reconpro" });
    expect(client.binaryPath).toBe("/x/reconpro");
    expect(DEFAULT_BINARY).toBe("reconpro");
    expect(DEFAULT_TIMEOUT_MS).toBe(300_000);
  });

  test("buildCommand is an argument list, never a shell string", () => {
    const client = new ReconProClient({ binaryPath: "/x/reconpro" });
    expect(client.buildCommand(["scan", "t", "--json"])).toEqual([
      "/x/reconpro",
      "scan",
      "t",
      "--json",
    ]);
  });
});

// ─────────────────────────── truth-layer contract ─────────────────────────

describe("scan — truth-layer contract (hermetic, stub-backed)", () => {
  test("unreachable *.invalid target returns the honest no-result", async () => {
    const result = await stubClient().scan("nonexistent-target-blah.invalid");

    expect(result.grade).toBe("U");
    expect(result.totalFindings).toBe(1);
    expect(result.totalScore).toBe(0);
    expect(result.modulesRun).toEqual([]);
    expect(result.severityCounts).toEqual({ info: 1 });
    expect(result.unreachable).toBe(true);

    const tv = result.targetValidation;
    expect(tv).not.toBeNull();
    expect(tv!.state).toBe(UNREACHABLE_TARGET);
    expect(tv!.dnsResolved).toBe(false);
    expect(tv!.reachable).toBe(false);
    expect(tv!.httpOk).toBe(false);
    expect(tv!.tlsValid).toBeNull();
    expect(tv!.checkedAt).toBeTypeOf("string");

    expect(result.findings).toHaveLength(1);
    const f = result.findings[0];
    expect(f.severity).toBe("info"); // HIGH impossible by construction
    expect(f.category).toBe("target_validation");
    expect(f.pointsDeducted).toBe(0);
    expect(f.verificationState).toBe(UNREACHABLE_TARGET);
    expect(f.confidence).toBeCloseTo(0.95);
    expect(f.dreadScore).toBe(0);

    const meta = result.scanMetadata;
    expect(meta).not.toBeNull();
    expect(meta!.scanner).toBe("reconpro");
    expect(meta!.result).toBe("unreachable_target_short_circuit");
    expect(meta!.durationS).toBeCloseTo(0.01);
    expect(meta!.startedAt).toBeTypeOf("string");

    // Unknown keys stay reachable via raw (forward compatibility).
    expect(
      (result.raw.future_field as { anything: string[] }).anything[0],
    ).toBe("the");
  });

  test("legacy result without truth-layer fields still parses", async () => {
    const legacy = {
      target: "example.com",
      grade: "B",
      total_findings: 1,
      findings: [{ title: "Old finding", severity: "low" }],
    };
    const result = normalizeScanResult(legacy);
    expect(result.grade).toBe("B");
    expect(result.targetValidation).toBeNull();
    expect(result.scanMetadata).toBeNull();
    expect(result.unreachable).toBe(false);
    expect(result.findings[0].confidence).toBeNull();
    expect(result.findings[0].verificationState).toBeNull();
  });

  test("null target_validation (local scans) is tolerated", () => {
    const result = normalizeScanResult({ target: "x", target_validation: null });
    expect(result.targetValidation).toBeNull();
    expect(result.unreachable).toBe(false);
  });

  test("vibesec() returns the same typed contract", async () => {
    const result = await stubClient().vibesec("nonexistent-target-blah.invalid");
    expect(result.grade).toBe("U");
    expect(result.targetValidation!.state).toBe(UNREACHABLE_TARGET);
  });

  test("audit()/dev()/doctor() return local typed results", async () => {
    const client = stubClient();
    for (const result of [await client.audit(), await client.dev(), await client.doctor()]) {
      expect(result.modulesRun).toEqual(["dev"]);
      expect(result.targetValidation).toBeNull();
      expect(result.grade).toBe("A+");
    }
  });
});

// ─────────────────────────────── error contract ───────────────────────────

describe("structured errors", () => {
  test("BIN_NOT_FOUND when the binary cannot be spawned", async () => {
    const client = new ReconProClient({
      binaryPath: "/nonexistent/reconpro-xyz",
      timeoutMs: 5_000,
    });
    const err = await expectSdkError(() => client.version());
    expect(err.code).toBe("BIN_NOT_FOUND");
  });

  test("TIMEOUT kills the process and rejects", async () => {
    const client = stubClient({ timeoutMs: 300 });
    const err = await expectSdkError(() => client.scan("sleepy-target.invalid"));
    expect(err.code).toBe("TIMEOUT");
  });

  test("NON_ZERO_EXIT carries exit code + captured stderr", async () => {
    const err = await expectSdkError(() =>
      stubClient().scan("make-it-fail.invalid"),
    );
    expect(err.code).toBe("NON_ZERO_EXIT");
    expect(err.exitCode).toBe(2);
    expect(err.stderr).toContain("boom");
  });

  test("INVALID_JSON when stdout is not JSON (exit 0)", async () => {
    const err = await expectSdkError(() =>
      stubClient().scan("garbage.invalid"),
    );
    expect(err.code).toBe("INVALID_JSON");
    expect(err.stderr).toContain("this is not json"); // stdout head for diagnostics
  });

  test("INVALID_JSON when stdout is a JSON array, not an object", async () => {
    const stub = await shStub("echo '[1, 2, 3]'");
    const err = await expectSdkError(() =>
      new ReconProClient({ binaryPath: stub, timeoutMs: 5_000 }).audit(),
    );
    expect(err.code).toBe("INVALID_JSON");
  });

  test("INVALID_TARGET for shell metacharacters (client-side)", () => {
    expect(() => validateTarget("example.com; rm -rf /")).toThrow(ReconProError);
    expect(() => validateTarget("   ")).toThrow(ReconProError);
    const err = (() => {
      try {
        return validateTarget("$(whoami)");
      } catch (e) {
        expect(e).toBeInstanceOf(ReconProError);
        return e as ReconProError;
      }
    })();
    expect(err.code).toBe("INVALID_TARGET");
  });

  test("UNSUPPORTED_FORMAT for bad export formats", async () => {
    await expect(stubClient().exportReport("pdf" as never)).rejects.toMatchObject({
      code: "UNSUPPORTED_FORMAT",
    });
  });
});

// ────────────────────────────── output files ──────────────────────────────

describe("-o output file round-trip", () => {
  test("JSON is read back from the file (CLI writes only there)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "reconpro-sdk-ts-out-"));
    const out = join(dir, "scan.json");
    const result = await stubClient().scan("nonexistent-target-blah.invalid", {
      outputFile: out,
    });
    expect(result.grade).toBe("U");
    expect(result.targetValidation!.state).toBe(UNREACHABLE_TARGET);
    const onDisk = JSON.parse(await readFile(out, "utf8"));
    expect(onDisk.target).toBe("nonexistent-target-blah.invalid");
    expect(onDisk.grade).toBe("U");
  });

  test("missing output file → INVALID_JSON", async () => {
    const stub = await shStub("exit 0"); // claims -o but writes nothing
    const err = await expectSdkError(() =>
      new ReconProClient({ binaryPath: stub, timeoutMs: 5_000 }).scan(
        "example.com",
        { outputFile: "/never-written-by-stub.json" },
      ),
    );
    expect(err.code).toBe("INVALID_JSON");
  });
});

// ──────────────────────────────── export ──────────────────────────────────

describe("exportReport", () => {
  test("writes via the CLI export subcommand and returns the path", async () => {
    const dir = await mkdtemp(join(tmpdir(), "reconpro-sdk-ts-exp-"));
    const out = join(dir, "report.sarif");
    const written = await stubClient().exportReport("sarif", out);
    expect(written).toBe(out);
    const content = await readFile(out, "utf8");
    expect(content).toContain("stub");
  });

  test("appends the format extension when missing", async () => {
    const dir = await mkdtemp(join(tmpdir(), "reconpro-sdk-ts-exp2-"));
    const out = join(dir, "report");
    const written = await stubClient().exportReport("md", out);
    expect(written).toBe(`${out}.md`);
  });

  test("EXPORT_FORMATS covers sarif/md/json/html", () => {
    expect([...EXPORT_FORMATS]).toEqual(["sarif", "md", "json", "html"]);
  });
});

// ───────────────────────────── version ping ───────────────────────────────

describe("version", () => {
  test("returns the CLI version string from stdout", async () => {
    expect(await stubClient().version()).toBe("ReconPro 11.2.0");
  });

  test("usage-error exit 2 surfaces as NON_ZERO_EXIT (sh stub)", async () => {
    const stub = await shStub('echo "usage: boom" >&2\nexit 2\n');
    const err = await expectSdkError(() =>
      new ReconProClient({ binaryPath: stub, timeoutMs: 5_000 }).version(),
    );
    expect(err.code).toBe("NON_ZERO_EXIT");
    expect(err.exitCode).toBe(2);
    expect(err.stderr).toContain("boom");
  });
});

// Re-exported helper contract (kept in sync with the other SDKs' constants).
expect([...TARGET_STATES]).toEqual([
  "VERIFIED_TARGET",
  "PARTIAL_TARGET",
  "UNREACHABLE_TARGET",
]);

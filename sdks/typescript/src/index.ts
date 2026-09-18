/**
 * reconpro-sdk — typed, zero-dependency TypeScript SDK around the ReconPro
 * CLI (>= 11.2.0).
 *
 * Every call spawns `reconpro <command> --json` as a subprocess with an
 * **argument list** — never a shell string — and parses the JSON contract
 * from STDOUT. The CLI's pretty UI is printed to STDERR (docker/kubectl
 * convention) and is captured only for error reporting.
 *
 * Config (constructor options or env): `RECONPRO_BINARY` (default
 * `"reconpro"`, resolved via PATH), `RECONPRO_TIMEOUT_MS` (default 300000).
 *
 * CLI exit-code contract: 0 success · 1 runtime error · 2 usage error ·
 * 130 interrupted. Non-zero exits throw a `ReconProError` with
 * `code: "NON_ZERO_EXIT"`, `exitCode`, and the captured `stderr`.
 *
 * Stability tier: **Stable** — versioning & compatibility policy:
 * `sdks/POLICY.md`. Parsing is additive-tolerant (policy §3): unknown JSON
 * keys are ignored (kept in `raw`), missing optional keys default safely
 * (`confidence` → `null`, `targetValidation` → `null`).
 */

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";

// ───────────────────────────── contract constants ──────────────────────────

/** Default binary name — resolved via PATH by the OS. */
export const DEFAULT_BINARY = "reconpro";
/** Default per-call timeout: 300 s (see sdks/POLICY.md §5). */
export const DEFAULT_TIMEOUT_MS = 300_000;

/** CLI exit codes (the process contract — see sdks/POLICY.md §3). */
export const EXIT_SUCCESS = 0;
export const EXIT_RUNTIME_ERROR = 1;
export const EXIT_USAGE_ERROR = 2;
export const EXIT_INTERRUPTED = 130;

/** `target_validation.state` values (the truth layer). */
export const VERIFIED_TARGET = "VERIFIED_TARGET";
export const PARTIAL_TARGET = "PARTIAL_TARGET";
export const UNREACHABLE_TARGET = "UNREACHABLE_TARGET";
export const TARGET_STATES = [
  VERIFIED_TARGET,
  PARTIAL_TARGET,
  UNREACHABLE_TARGET,
] as const;

/** Export formats the CLI auto-detects from the file extension. */
export const EXPORT_FORMATS = ["sarif", "md", "json", "html"] as const;

/** Shell metacharacters rejected client-side (defence in depth). */
export const INVALID_TARGET_CHARS = /[`;$&|<>(){}[\]!*'"\\\n\r\t ]/;

// ─────────────────────────────── result types ─────────────────────────────

/** The three truth-layer target states (`(string & {})` keeps autocomplete
 * while tolerating future states the CLI may add — see sdks/POLICY.md §3). */
export type TargetState =
  | typeof VERIFIED_TARGET
  | typeof PARTIAL_TARGET
  | typeof UNREACHABLE_TARGET
  | (string & {});

/** Severity name → finding count (severity names are CLI-controlled). */
export type SeverityCounts = Record<string, number>;

/** One vulnerability/observation emitted by a reconpro module.
 * `confidence` (0..1) and `verificationState` are the truth-layer fields
 * added in CLI 11.2.0; both are `null` when the CLI did not measure one. */
export interface Finding {
  readonly title: string;
  readonly severity: string;
  readonly category: string;
  readonly module: string;
  readonly description: string;
  readonly evidence: string;
  readonly asset: string;
  readonly pointsDeducted: number;
  readonly remediation: string;
  readonly dreadScore: number;
  readonly confidence: number | null;
  readonly verificationState: string | null;
}

/** Truth-layer result for the scanned target (`null` for local scans such
 * as audit/dev). */
export interface TargetValidation {
  readonly state: TargetState;
  readonly dnsResolved: boolean | null;
  readonly reachable: boolean | null;
  readonly httpOk: boolean | null;
  readonly tlsValid: boolean | null;
  readonly details: Record<string, unknown> | null;
  readonly checkedAt: string | null;
}

/** When/how the scan ran. */
export interface ScanMetadata {
  readonly scanner: string;
  readonly startedAt: string | null;
  readonly durationS: number | null;
  readonly result: string | null;
}

/** Typed view of one reconpro scan (`scan` / `vibesec` / `audit` / `dev` /
 * `doctor`). `raw` keeps the complete parsed JSON document so fields the CLI
 * adds in the future remain accessible without an SDK release. */
export interface ScanResult {
  readonly target: string;
  readonly modulesRun: readonly string[];
  readonly totalFindings: number;
  readonly severityCounts: SeverityCounts;
  readonly totalScore: number;
  readonly grade: string;
  readonly findings: readonly Finding[];
  readonly targetValidation: TargetValidation | null;
  readonly scanMetadata: ScanMetadata | null;
  /** True when the truth layer short-circuited an unreachable target. */
  readonly unreachable: boolean;
  readonly raw: Record<string, unknown>;
}

// ───────────────────────────────── errors ─────────────────────────────────

/** Machine-readable failure codes (contract — see sdks/POLICY.md §5).
 * Codes are only ever ADDED, never renamed. */
export type ReconProErrorCode =
  | "BIN_NOT_FOUND"
  | "TIMEOUT"
  | "NON_ZERO_EXIT"
  | "INVALID_JSON"
  | "INVALID_TARGET"
  | "UNSUPPORTED_FORMAT";

export const RECONPRO_ERROR_CODES = [
  "BIN_NOT_FOUND",
  "TIMEOUT",
  "NON_ZERO_EXIT",
  "INVALID_JSON",
  "INVALID_TARGET",
  "UNSUPPORTED_FORMAT",
] as const satisfies readonly ReconProErrorCode[];

/** Structured SDK failure — every failure mode maps to one stable `code`.
 *
 * - `BIN_NOT_FOUND` — the reconpro binary could not be spawned.
 * - `TIMEOUT` — per-call timeout exceeded.
 * - `NON_ZERO_EXIT` — CLI exited non-zero; `exitCode` (0/1/2/130 contract)
 *   and `stderr` are attached.
 * - `INVALID_JSON` — CLI exited 0 but stdout was not parseable JSON;
 *   `stderr` carries the stdout head for diagnostics.
 * - `INVALID_TARGET` / `UNSUPPORTED_FORMAT` — client-side validation.
 */
export class ReconProError extends Error {
  readonly code: ReconProErrorCode;
  readonly exitCode: number | null;
  readonly stderr: string;
  /** The argument list that was executed (never a shell string). */
  readonly command: readonly string[];

  constructor(
    message: string,
    options: {
      code: ReconProErrorCode;
      exitCode?: number | null;
      stderr?: string;
      command?: readonly string[];
    },
  ) {
    super(message);
    this.name = "ReconProError";
    this.code = options.code;
    this.exitCode = options.exitCode ?? null;
    this.stderr = options.stderr ?? "";
    this.command = options.command ?? [];
    // Keep `instanceof` working after down-leveling/bundling.
    Object.setPrototypeOf(this, ReconProError.prototype);
  }
}

// ───────────────────────────── client options ─────────────────────────────

export interface ClientOptions {
  /** Path to (or name of) the reconpro binary. Default: `RECONPRO_BINARY`
   * env → `"reconpro"` resolved via PATH. */
  binaryPath?: string;
  /** Per-call timeout in milliseconds. Default: `RECONPRO_TIMEOUT_MS` env →
   * 300000. */
  timeoutMs?: number;
}

export interface ScanOptions {
  /** Restrict the run to these modules (`--modules a,b`). */
  modules?: string[];
  /** Skip TLS verification (`--insecure`) — opt-in, audited escape hatch. */
  insecure?: boolean;
  /** Additionally persist the scan JSON to this file via CLI `-o`. */
  outputFile?: string;
}

export interface VibesecOptions {
  outputFile?: string;
}

export interface AuditOptions {
  outputFile?: string;
}

export type ExportFormat = (typeof EXPORT_FORMATS)[number];

// ─────────────────────────── tolerant normalizers ─────────────────────────

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function asNumberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asStringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asBoolOrNull(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function asRecordOrNull(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function toFinding(data: Record<string, unknown>): Finding {
  return {
    title: asString(data.title),
    severity: asString(data.severity),
    category: asString(data.category),
    module: asString(data.module),
    description: asString(data.description),
    evidence: asString(data.evidence),
    asset: asString(data.asset),
    pointsDeducted: asNumber(data.points_deducted),
    remediation: asString(data.remediation),
    dreadScore: asNumber(data.dread_score),
    confidence: asNumberOrNull(data.confidence),
    verificationState: asStringOrNull(data.verification_state),
  };
}

function toTargetValidation(
  data: Record<string, unknown>,
): TargetValidation {
  return {
    state: asString(data.state),
    dnsResolved: asBoolOrNull(data.dns_resolved),
    reachable: asBoolOrNull(data.reachable),
    httpOk: asBoolOrNull(data.http_ok),
    tlsValid: asBoolOrNull(data.tls_valid),
    details: asRecordOrNull(data.details),
    checkedAt: asStringOrNull(data.checked_at),
  };
}

function toScanMetadata(data: Record<string, unknown>): ScanMetadata {
  return {
    scanner: asString(data.scanner) || "reconpro",
    startedAt: asStringOrNull(data.started_at),
    durationS: asNumberOrNull(data.duration_s),
    result: asStringOrNull(data.result),
  };
}

/** Normalize a parsed scan JSON document into a typed `ScanResult`.
 * Unknown keys are ignored (they stay reachable via `raw`); missing
 * optional keys default safely (additive-tolerant, sdks/POLICY.md §3). */
export function normalizeScanResult(
  payload: unknown,
): ScanResult {
  const raw = asRecordOrNull(payload);
  if (raw === null) {
    throw new ReconProError(
      `reconpro CLI JSON output was ${
        payload === null ? "null" : Array.isArray(payload) ? "an array" : typeof payload
      }, expected an object`,
      { code: "INVALID_JSON" },
    );
  }
  const tv = asRecordOrNull(raw.target_validation);
  const sm = asRecordOrNull(raw.scan_metadata);
  const findings = Array.isArray(raw.findings)
    ? raw.findings
        .map((f) => asRecordOrNull(f))
        .filter((f): f is Record<string, unknown> => f !== null)
        .map(toFinding)
    : [];
  const severityCounts: SeverityCounts = {};
  for (const [severity, count] of Object.entries(
    asRecordOrNull(raw.severity_counts) ?? {},
  )) {
    if (typeof count === "number" && Number.isFinite(count)) {
      severityCounts[severity] = count;
    }
  }
  return {
    target: asString(raw.target),
    modulesRun: Array.isArray(raw.modules_run)
      ? raw.modules_run.filter((m): m is string => typeof m === "string")
      : [],
    totalFindings: asNumber(raw.total_findings),
    severityCounts,
    totalScore: asNumber(raw.total_score),
    grade: asString(raw.grade),
    findings,
    targetValidation: tv === null ? null : toTargetValidation(tv),
    scanMetadata: sm === null ? null : toScanMetadata(sm),
    unreachable: tv !== null && asString(tv.state) === UNREACHABLE_TARGET,
    raw,
  };
}

/** Client-side target validation: reject shell metacharacters before
 * spawning. Defence in depth — arguments are passed as a list, so no shell
 * injection is possible anyway; this catches obvious mistakes early. */
export function validateTarget(target: string): string {
  const text = typeof target === "string" ? target.trim() : "";
  if (!text) {
    throw new ReconProError("target must be a non-empty string", {
      code: "INVALID_TARGET",
    });
  }
  if (INVALID_TARGET_CHARS.test(text)) {
    throw new ReconProError(
      `target contains shell metacharacters: ${JSON.stringify(text)}`,
      { code: "INVALID_TARGET" },
    );
  }
  return text;
}

// ───────────────────────────────── client ─────────────────────────────────

/** SDK client that always spawns the CLI with an ARGUMENT LIST. */
export class ReconProClient {
  readonly binaryPath: string;
  readonly timeoutMs: number;

  constructor(options: ClientOptions = {}) {
    this.binaryPath =
      options.binaryPath ??
      process.env.RECONPRO_BINARY ??
      DEFAULT_BINARY;
    const envTimeout = Number(process.env.RECONPRO_TIMEOUT_MS);
    this.timeoutMs =
      options.timeoutMs ??
      (Number.isFinite(envTimeout) && envTimeout > 0
        ? envTimeout
        : DEFAULT_TIMEOUT_MS);
  }

  /** Argument list used to spawn the CLI (unit-testable, no shell). */
  buildCommand(cliArgs: readonly string[]): string[] {
    return [this.binaryPath, ...cliArgs];
  }

  /** Run the CLI; resolve (stdout, stderr). Throws `ReconProError` on
   * failure (spawn, timeout, non-zero exit). */
  private run(
    cliArgs: readonly string[],
  ): Promise<{ stdout: string; stderr: string }> {
    const command = this.buildCommand(cliArgs);
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawn(command[0], command.slice(1), {
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        });
      } catch (err) {
        reject(
          new ReconProError(
            `failed to start ${command[0]}: ${err instanceof Error ? err.message : String(err)} (set binaryPath or RECONPRO_BINARY)`,
            { code: "BIN_NOT_FOUND", command },
          ),
        );
        return;
      }
      let stdout = "";
      let stderr = "";
      let done = false;
      const timer = setTimeout(() => {
        if (done) return;
        done = true;
        child.kill("SIGKILL");
        reject(
          new ReconProError(
            `reconpro CLI timed out after ${this.timeoutMs}ms`,
            { code: "TIMEOUT", command },
          ),
        );
      }, this.timeoutMs);
      child.stdout!.setEncoding("utf8");
      child.stderr!.setEncoding("utf8");
      child.stdout!.on("data", (chunk: string) => {
        stdout += chunk;
      });
      child.stderr!.on("data", (chunk: string) => {
        stderr += chunk;
      });
      child.on("error", (err: NodeJS.ErrnoException) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(
          new ReconProError(
            `reconpro binary not found or not executable: ${command[0]} (${err.code ?? err.message}) — set binaryPath or RECONPRO_BINARY`,
            { code: "BIN_NOT_FOUND", command },
          ),
        );
      });
      child.on("close", (code: number | null, signal: string | null) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (code === 0) {
          resolve({ stdout, stderr });
          return;
        }
        const described =
          code !== null
            ? `reconpro CLI exited with code ${code}`
            : `reconpro CLI terminated by signal ${signal ?? "unknown"}`;
        reject(
          new ReconProError(described, {
            code: "NON_ZERO_EXIT",
            exitCode: code,
            stderr,
            command,
          }),
        );
      });
    });
  }

  /** Run a `--json` command and normalize the typed result.
   *
   * JSON source: STDOUT normally; when `-o` is used the CLI writes the JSON
   * **only** to the output file and leaves stdout empty, so the file is
   * read back instead. */
  private async runJson(
    cliArgs: readonly string[],
    outputFile?: string,
  ): Promise<ScanResult> {
    let { stdout } = await this.run(cliArgs);
    if (outputFile !== undefined) {
      try {
        stdout = await readFile(outputFile, "utf8");
      } catch (err) {
        throw new ReconProError(
          `reconpro CLI wrote no JSON to ${outputFile}: ${err instanceof Error ? err.message : String(err)}`,
          { code: "INVALID_JSON", stderr: stdout.slice(0, 500) },
        );
      }
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout);
    } catch (err) {
      throw new ReconProError(
        `reconpro CLI produced invalid JSON: ${err instanceof Error ? err.message : String(err)}`,
        { code: "INVALID_JSON", stderr: stdout.slice(0, 500) },
      );
    }
    return normalizeScanResult(parsed);
  }

  /** Verification ping: run `reconpro --version` → e.g. "ReconPro 11.2.0".
   * A successful return doubles as a liveness + version check — spawn,
   * timeout, and non-zero-exit failures all throw `ReconProError`. */
  async version(): Promise<string> {
    const { stdout } = await this.run(["--version"]);
    return stdout.trim();
  }

  /** Full remote scan of a domain/URL → typed `ScanResult`.
   *
   * Offline truth-layer note: scanning a nonexistent `*.invalid` target
   * returns instantly with `grade === "U"` and
   * `targetValidation.state === "UNREACHABLE_TARGET"` (no network). */
  async scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
    const text = validateTarget(target);
    const args = ["scan", text];
    if (options.modules !== undefined && options.modules.length > 0) {
      args.push("--modules", options.modules.join(","));
    }
    if (options.insecure === true) {
      args.push("--insecure");
    }
    args.push("--json");
    if (options.outputFile !== undefined) {
      args.push("-o", options.outputFile);
    }
    return this.runJson(args, options.outputFile);
  }

  /** Run the vibesec module against a target → typed `ScanResult`. */
  async vibesec(
    target: string,
    options: VibesecOptions = {},
  ): Promise<ScanResult> {
    const text = validateTarget(target);
    const args = ["vibesec", text, "--json"];
    if (options.outputFile !== undefined) {
      args.push("-o", options.outputFile);
    }
    return this.runJson(args, options.outputFile);
  }

  /** Local host/dev-environment audit → typed `ScanResult` (offline). */
  async audit(options: AuditOptions = {}): Promise<ScanResult> {
    const args = ["audit", "--json"];
    if (options.outputFile !== undefined) {
      args.push("-o", options.outputFile);
    }
    return this.runJson(args, options.outputFile);
  }

  /** Scan a local directory path → typed `ScanResult` (offline).
   * Defaults to the current working directory. */
  async dev(path: string = "."): Promise<ScanResult> {
    const text = typeof path === "string" ? path.trim() : "";
    if (!text) {
      throw new ReconProError("path must be a non-empty string", {
        code: "INVALID_TARGET",
      });
    }
    return this.runJson(["dev", text, "--json"]);
  }

  /** Local health check → typed `ScanResult` (offline). */
  async doctor(): Promise<ScanResult> {
    return this.runJson(["doctor", "--json"]);
  }

  /** Export the last scan via `reconpro export` (format auto-detected from
   * the file extension by the CLI).
   *
   * @param format one of `sarif` / `md` / `json` / `html` (default `sarif`)
   * @param path output file; default `reconpro-report.<format>` in the OS
   *        temp dir. When `path` has no extension, `.<format>` is appended.
   * @returns the path written (resolved absolute or as given)
   */
  async exportReport(
    format: ExportFormat = "sarif",
    path?: string,
  ): Promise<string> {
    if (!EXPORT_FORMATS.includes(format)) {
      throw new ReconProError(
        `unsupported export format ${JSON.stringify(format)}; expected one of ${EXPORT_FORMATS.join("/")}`,
        { code: "UNSUPPORTED_FORMAT" },
      );
    }
    if (typeof path === "string" && path.trim() === "") {
      throw new ReconProError("export path must be non-empty", {
        code: "INVALID_TARGET",
      });
    }
    let out =
      path ??
      join(tmpdir(), `reconpro-report.${format}`);
    if (extname(out) === "") {
      out += `.${format}`;
    }
    await this.run(["export", out]);
    return out;
  }
}

export default ReconProClient;

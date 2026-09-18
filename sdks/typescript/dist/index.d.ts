/**
 * reconpro-sdk — typed, zero-dependency TypeScript SDK around the ReconPro
 * CLI (>= 11.2.0).
 *
 * Public type surface. NOTE: this file is maintained by hand (`bun build`
 * emits `dist/index.js` but not declarations); it must stay in sync with
 * `src/index.ts` (see README "Regenerating dist").
 *
 * Stability tier: Stable — versioning & compatibility policy: sdks/POLICY.md.
 */

/** Default binary name — resolved via PATH by the OS. */
export const DEFAULT_BINARY: "reconpro";
/** Default per-call timeout: 300 s (see sdks/POLICY.md §5). */
export const DEFAULT_TIMEOUT_MS: 300000;

/** CLI exit codes (the process contract — see sdks/POLICY.md §3). */
export const EXIT_SUCCESS: 0;
export const EXIT_RUNTIME_ERROR: 1;
export const EXIT_USAGE_ERROR: 2;
export const EXIT_INTERRUPTED: 130;

/** `target_validation.state` values (the truth layer). */
export const VERIFIED_TARGET: "VERIFIED_TARGET";
export const PARTIAL_TARGET: "PARTIAL_TARGET";
export const UNREACHABLE_TARGET: "UNREACHABLE_TARGET";
export const TARGET_STATES: readonly [
  "VERIFIED_TARGET",
  "PARTIAL_TARGET",
  "UNREACHABLE_TARGET",
];

/** Export formats the CLI auto-detects from the file extension. */
export const EXPORT_FORMATS: readonly ["sarif", "md", "json", "html"];

/** Shell metacharacters rejected client-side (defence in depth). */
export const INVALID_TARGET_CHARS: RegExp;

/** The three truth-layer target states (`(string & {})` keeps autocomplete
 * while tolerating future states the CLI may add — see sdks/POLICY.md §3). */
export type TargetState =
  | "VERIFIED_TARGET"
  | "PARTIAL_TARGET"
  | "UNREACHABLE_TARGET"
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

/** Machine-readable failure codes (contract — see sdks/POLICY.md §5).
 * Codes are only ever ADDED, never renamed. */
export type ReconProErrorCode =
  | "BIN_NOT_FOUND"
  | "TIMEOUT"
  | "NON_ZERO_EXIT"
  | "INVALID_JSON"
  | "INVALID_TARGET"
  | "UNSUPPORTED_FORMAT";

export const RECONPRO_ERROR_CODES: readonly ReconProErrorCode[];

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
  );
}

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

export type ExportFormat = "sarif" | "md" | "json" | "html";

/** Normalize a parsed scan JSON document into a typed `ScanResult`.
 * Unknown keys are ignored (they stay reachable via `raw`); missing
 * optional keys default safely (additive-tolerant, sdks/POLICY.md §3).
 * Throws `ReconProError` (`INVALID_JSON`) for non-object payloads. */
export function normalizeScanResult(payload: unknown): ScanResult;

/** Client-side target validation: reject shell metacharacters before
 * spawning. Throws `ReconProError` (`INVALID_TARGET`) on bad input. */
export function validateTarget(target: string): string;

/** SDK client that always spawns the CLI with an ARGUMENT LIST. */
export class ReconProClient {
  readonly binaryPath: string;
  readonly timeoutMs: number;

  constructor(options?: ClientOptions);

  /** Argument list used to spawn the CLI (unit-testable, no shell). */
  buildCommand(cliArgs: readonly string[]): string[];

  /** Verification ping: run `reconpro --version` → e.g. "ReconPro 11.2.0".
   * A successful return doubles as a liveness + version check — spawn,
   * timeout, and non-zero-exit failures all throw `ReconProError`. */
  version(): Promise<string>;

  /** Full remote scan of a domain/URL → typed `ScanResult`.
   *
   * Offline truth-layer note: scanning a nonexistent `*.invalid` target
   * returns instantly with `grade === "U"` and
   * `targetValidation.state === "UNREACHABLE_TARGET"` (no network). */
  scan(target: string, options?: ScanOptions): Promise<ScanResult>;

  /** Run the vibesec module against a target → typed `ScanResult`. */
  vibesec(target: string, options?: VibesecOptions): Promise<ScanResult>;

  /** Local host/dev-environment audit → typed `ScanResult` (offline). */
  audit(options?: AuditOptions): Promise<ScanResult>;

  /** Scan a local directory path → typed `ScanResult` (offline).
   * Defaults to the current working directory. */
  dev(path?: string): Promise<ScanResult>;

  /** Local health check → typed `ScanResult` (offline). */
  doctor(): Promise<ScanResult>;

  /** Export the last scan via `reconpro export` (format auto-detected from
   * the file extension by the CLI).
   *
   * @param format one of `sarif` / `md` / `json` / `html` (default `sarif`)
   * @param path output file; default `reconpro-report.<format>` in the OS
   *        temp dir. When `path` has no extension, `.<format>` is appended.
   * @returns the path written
   */
  exportReport(
    format?: ExportFormat,
    path?: string,
  ): Promise<string>;
}

export default ReconProClient;

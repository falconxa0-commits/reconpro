// src/index.ts
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
var DEFAULT_BINARY = "reconpro";
var DEFAULT_TIMEOUT_MS = 300000;
var EXIT_SUCCESS = 0;
var EXIT_RUNTIME_ERROR = 1;
var EXIT_USAGE_ERROR = 2;
var EXIT_INTERRUPTED = 130;
var VERIFIED_TARGET = "VERIFIED_TARGET";
var PARTIAL_TARGET = "PARTIAL_TARGET";
var UNREACHABLE_TARGET = "UNREACHABLE_TARGET";
var TARGET_STATES = [
  VERIFIED_TARGET,
  PARTIAL_TARGET,
  UNREACHABLE_TARGET
];
var EXPORT_FORMATS = ["sarif", "md", "json", "html"];
var INVALID_TARGET_CHARS = /[`;$&|<>(){}[\]!*'"\\\n\r\t ]/;
var RECONPRO_ERROR_CODES = [
  "BIN_NOT_FOUND",
  "TIMEOUT",
  "NON_ZERO_EXIT",
  "INVALID_JSON",
  "INVALID_TARGET",
  "UNSUPPORTED_FORMAT"
];

class ReconProError extends Error {
  code;
  exitCode;
  stderr;
  command;
  constructor(message, options) {
    super(message);
    this.name = "ReconProError";
    this.code = options.code;
    this.exitCode = options.exitCode ?? null;
    this.stderr = options.stderr ?? "";
    this.command = options.command ?? [];
    Object.setPrototypeOf(this, ReconProError.prototype);
  }
}
function asString(value) {
  return typeof value === "string" ? value : "";
}
function asNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}
function asNumberOrNull(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
function asStringOrNull(value) {
  return typeof value === "string" ? value : null;
}
function asBoolOrNull(value) {
  return typeof value === "boolean" ? value : null;
}
function asRecordOrNull(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
}
function toFinding(data) {
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
    verificationState: asStringOrNull(data.verification_state)
  };
}
function toTargetValidation(data) {
  return {
    state: asString(data.state),
    dnsResolved: asBoolOrNull(data.dns_resolved),
    reachable: asBoolOrNull(data.reachable),
    httpOk: asBoolOrNull(data.http_ok),
    tlsValid: asBoolOrNull(data.tls_valid),
    details: asRecordOrNull(data.details),
    checkedAt: asStringOrNull(data.checked_at)
  };
}
function toScanMetadata(data) {
  return {
    scanner: asString(data.scanner) || "reconpro",
    startedAt: asStringOrNull(data.started_at),
    durationS: asNumberOrNull(data.duration_s),
    result: asStringOrNull(data.result)
  };
}
function normalizeScanResult(payload) {
  const raw = asRecordOrNull(payload);
  if (raw === null) {
    throw new ReconProError(`reconpro CLI JSON output was ${payload === null ? "null" : Array.isArray(payload) ? "an array" : typeof payload}, expected an object`, { code: "INVALID_JSON" });
  }
  const tv = asRecordOrNull(raw.target_validation);
  const sm = asRecordOrNull(raw.scan_metadata);
  const findings = Array.isArray(raw.findings) ? raw.findings.map((f) => asRecordOrNull(f)).filter((f) => f !== null).map(toFinding) : [];
  const severityCounts = {};
  for (const [severity, count] of Object.entries(asRecordOrNull(raw.severity_counts) ?? {})) {
    if (typeof count === "number" && Number.isFinite(count)) {
      severityCounts[severity] = count;
    }
  }
  return {
    target: asString(raw.target),
    modulesRun: Array.isArray(raw.modules_run) ? raw.modules_run.filter((m) => typeof m === "string") : [],
    totalFindings: asNumber(raw.total_findings),
    severityCounts,
    totalScore: asNumber(raw.total_score),
    grade: asString(raw.grade),
    findings,
    targetValidation: tv === null ? null : toTargetValidation(tv),
    scanMetadata: sm === null ? null : toScanMetadata(sm),
    unreachable: tv !== null && asString(tv.state) === UNREACHABLE_TARGET,
    raw
  };
}
function validateTarget(target) {
  const text = typeof target === "string" ? target.trim() : "";
  if (!text) {
    throw new ReconProError("target must be a non-empty string", {
      code: "INVALID_TARGET"
    });
  }
  if (INVALID_TARGET_CHARS.test(text)) {
    throw new ReconProError(`target contains shell metacharacters: ${JSON.stringify(text)}`, { code: "INVALID_TARGET" });
  }
  return text;
}

class ReconProClient {
  binaryPath;
  timeoutMs;
  constructor(options = {}) {
    this.binaryPath = options.binaryPath ?? process.env.RECONPRO_BINARY ?? DEFAULT_BINARY;
    const envTimeout = Number(process.env.RECONPRO_TIMEOUT_MS);
    this.timeoutMs = options.timeoutMs ?? (Number.isFinite(envTimeout) && envTimeout > 0 ? envTimeout : DEFAULT_TIMEOUT_MS);
  }
  buildCommand(cliArgs) {
    return [this.binaryPath, ...cliArgs];
  }
  run(cliArgs) {
    const command = this.buildCommand(cliArgs);
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawn(command[0], command.slice(1), {
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true
        });
      } catch (err) {
        reject(new ReconProError(`failed to start ${command[0]}: ${err instanceof Error ? err.message : String(err)} (set binaryPath or RECONPRO_BINARY)`, { code: "BIN_NOT_FOUND", command }));
        return;
      }
      let stdout = "";
      let stderr = "";
      let done = false;
      const timer = setTimeout(() => {
        if (done)
          return;
        done = true;
        child.kill("SIGKILL");
        reject(new ReconProError(`reconpro CLI timed out after ${this.timeoutMs}ms`, { code: "TIMEOUT", command }));
      }, this.timeoutMs);
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.on("error", (err) => {
        if (done)
          return;
        done = true;
        clearTimeout(timer);
        reject(new ReconProError(`reconpro binary not found or not executable: ${command[0]} (${err.code ?? err.message}) — set binaryPath or RECONPRO_BINARY`, { code: "BIN_NOT_FOUND", command }));
      });
      child.on("close", (code, signal) => {
        if (done)
          return;
        done = true;
        clearTimeout(timer);
        if (code === 0) {
          resolve({ stdout, stderr });
          return;
        }
        const described = code !== null ? `reconpro CLI exited with code ${code}` : `reconpro CLI terminated by signal ${signal ?? "unknown"}`;
        reject(new ReconProError(described, {
          code: "NON_ZERO_EXIT",
          exitCode: code,
          stderr,
          command
        }));
      });
    });
  }
  async runJson(cliArgs, outputFile) {
    let { stdout } = await this.run(cliArgs);
    if (outputFile !== undefined) {
      try {
        stdout = await readFile(outputFile, "utf8");
      } catch (err) {
        throw new ReconProError(`reconpro CLI wrote no JSON to ${outputFile}: ${err instanceof Error ? err.message : String(err)}`, { code: "INVALID_JSON", stderr: stdout.slice(0, 500) });
      }
    }
    let parsed;
    try {
      parsed = JSON.parse(stdout);
    } catch (err) {
      throw new ReconProError(`reconpro CLI produced invalid JSON: ${err instanceof Error ? err.message : String(err)}`, { code: "INVALID_JSON", stderr: stdout.slice(0, 500) });
    }
    return normalizeScanResult(parsed);
  }
  async version() {
    const { stdout } = await this.run(["--version"]);
    return stdout.trim();
  }
  async scan(target, options = {}) {
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
  async vibesec(target, options = {}) {
    const text = validateTarget(target);
    const args = ["vibesec", text, "--json"];
    if (options.outputFile !== undefined) {
      args.push("-o", options.outputFile);
    }
    return this.runJson(args, options.outputFile);
  }
  async audit(options = {}) {
    const args = ["audit", "--json"];
    if (options.outputFile !== undefined) {
      args.push("-o", options.outputFile);
    }
    return this.runJson(args, options.outputFile);
  }
  async dev(path = ".") {
    const text = typeof path === "string" ? path.trim() : "";
    if (!text) {
      throw new ReconProError("path must be a non-empty string", {
        code: "INVALID_TARGET"
      });
    }
    return this.runJson(["dev", text, "--json"]);
  }
  async doctor() {
    return this.runJson(["doctor", "--json"]);
  }
  async exportReport(format = "sarif", path) {
    if (!EXPORT_FORMATS.includes(format)) {
      throw new ReconProError(`unsupported export format ${JSON.stringify(format)}; expected one of ${EXPORT_FORMATS.join("/")}`, { code: "UNSUPPORTED_FORMAT" });
    }
    if (typeof path === "string" && path.trim() === "") {
      throw new ReconProError("export path must be non-empty", {
        code: "INVALID_TARGET"
      });
    }
    let out = path ?? join(tmpdir(), `reconpro-report.${format}`);
    if (extname(out) === "") {
      out += `.${format}`;
    }
    await this.run(["export", out]);
    return out;
  }
}
var src_default = ReconProClient;
export {
  validateTarget,
  normalizeScanResult,
  src_default as default,
  VERIFIED_TARGET,
  UNREACHABLE_TARGET,
  TARGET_STATES,
  ReconProError,
  ReconProClient,
  RECONPRO_ERROR_CODES,
  PARTIAL_TARGET,
  INVALID_TARGET_CHARS,
  EXPORT_FORMATS,
  EXIT_USAGE_ERROR,
  EXIT_SUCCESS,
  EXIT_RUNTIME_ERROR,
  EXIT_INTERRUPTED,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_BINARY
};

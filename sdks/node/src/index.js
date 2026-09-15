// Thin, zero-dependency wrapper around the reconpro CLI (`python -m reconpro.cli`).
// Every call shells out with an ARGUMENT LIST (never a shell string).
//
// Config (constructor options or env):
//   RECONPRO_PYTHON   python executable (default /home/z/.venv/bin/python3)
//   RECONPRO_ROOT     dir containing the reconpro package, used as spawn cwd
//   RECONPRO_TIMEOUT_MS  per-call timeout (default 120000)
//
// Verified CLI quirks (reconpro 11.1.0): `--version` and `doctor --json` write to
// STDOUT; `history` has NO --json flag (exit 2) and its human table goes to STDERR,
// so history() returns raw text.

import { spawn } from 'node:child_process';

export const DEFAULT_PYTHON = '/home/z/.venv/bin/python3';
export const DEFAULT_ROOT = '/home/z/my-project/download/reconpro-github';
export const DEFAULT_TIMEOUT_MS = 120_000;
export const EXPORT_FORMATS = ['sarif', 'md', 'json', 'html'];
const INVALID_TARGET_CHARS = /[`;$&|<>(){}[\]!*'"\\\n\r\t ]/;

export class SdkError extends Error {
  constructor(message, { exitCode = null, stderr = '', command = null } = {}) {
    super(message);
    this.name = 'SdkError';
    this.exitCode = exitCode;
    this.stderr = stderr;
    this.command = command;
  }
}

/** Builds the ARGUMENT LIST used to spawn the CLI (no shell string ever). */
export function buildArgs(pythonPath, cliArgs = []) {
  return [pythonPath, '-m', 'reconpro.cli', ...cliArgs];
}

/** Client-side target validation: reject shell metacharacters before spawning. */
export function validateTarget(target) {
  const text = typeof target === 'string' ? target.trim() : '';
  if (!text) throw new TypeError('target must be a non-empty string');
  if (INVALID_TARGET_CHARS.test(text)) {
    throw new Error(`target contains shell metacharacters: ${JSON.stringify(text)}`);
  }
  return text;
}

export class ReconProClient {
  constructor({ pythonPath, root, timeoutMs } = {}) {
    this.pythonPath = pythonPath ?? process.env.RECONPRO_PYTHON ?? DEFAULT_PYTHON;
    this.root = root ?? process.env.RECONPRO_ROOT ?? DEFAULT_ROOT;
    this.timeoutMs = timeoutMs ?? Number(process.env.RECONPRO_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS);
  }

  buildCommand(cliArgs) {
    return buildArgs(this.pythonPath, cliArgs);
  }

  _run(cliArgs) {
    const cmd = this.buildCommand(cliArgs);
    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let done = false;
      let child;
      try {
        child = spawn(cmd[0], cmd.slice(1), {
          cwd: this.root,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch (err) {
        reject(new SdkError(`failed to spawn: ${err.message}`, { command: cmd }));
        return;
      }
      const timer = setTimeout(() => {
        if (done) return;
        done = true;
        child.kill('SIGKILL');
        reject(new SdkError(`reconpro CLI timed out after ${this.timeoutMs}ms`, { command: cmd }));
      }, this.timeoutMs);
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (d) => { stdout += d; });
      child.stderr.on('data', (d) => { stderr += d; });
      child.on('error', (err) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(new SdkError(`failed to start ${cmd[0]}: ${err.message}`, { command: cmd }));
      });
      child.on('close', (code) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (code !== 0) {
          reject(new SdkError(`reconpro CLI exited with code ${code}`, {
            exitCode: code, stderr, command: cmd,
          }));
        } else {
          resolve({ stdout, stderr });
        }
      });
    });
  }

  async _runJson(cliArgs) {
    const { stdout } = await this._run(cliArgs);
    try {
      return JSON.parse(stdout);
    } catch (err) {
      throw new SdkError(`reconpro CLI produced invalid JSON: ${err.message}`, {
        exitCode: null, stderr: stdout.slice(0, 500),
      });
    }
  }

  /** CLI version string, e.g. "ReconPro 11.1.0". */
  async version() {
    const { stdout } = await this._run(['--version']);
    return stdout.trim();
  }

  /** Local health check → parsed JSON report. */
  async doctor() {
    return this._runJson(['doctor', '--json']);
  }

  /** Scan history as raw text (CLI quirk: history has no --json flag). */
  async history(target = null, limit = 10) {
    const args = ['history', '--limit', String(limit)];
    if (target !== null) args.push(validateTarget(target));
    const { stdout, stderr } = await this._run(args);
    return (stderr || stdout).trim();
  }

  /** Full remote scan of a domain/URL → parsed JSON (hits the network). */
  async scan(target) {
    return this._runJson(['scan', validateTarget(target), '--json']);
  }

  /** Export the last scan to `path`; returns the path used. */
  async export(path, format = 'sarif') {
    const fmt = String(format).toLowerCase().trim();
    if (!EXPORT_FORMATS.includes(fmt)) {
      throw new Error(`unsupported export format ${JSON.stringify(format)}; expected one of ${EXPORT_FORMATS}`);
    }
    let out = String(path);
    if (!/\.[a-z]+$/i.test(out)) out += `.${fmt}`;
    await this._run(['export', out]);
    return out;
  }
}

export default ReconProClient;

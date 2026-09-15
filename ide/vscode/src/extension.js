/**
 * ReconPro — VS Code extension (v0.1.0, extension skeleton).
 *
 * Runs the `reconpro` CLI (`python -m reconpro.cli`) as a child process with an
 * ARGV ARRAY (never a shell string — `shell` is explicitly `false`), then turns
 * SARIF output into vscode.Diagnostic entries in the Problems panel.
 * When no SARIF is available (e.g. `ast`, which prints a Rich table), the raw
 * CLI output is streamed to the "ReconPro" output channel instead.
 *
 * IMPORTANT stream routing (verified against reconpro 11.1.0):
 *   - human-readable output (banner, Rich tables) → STDERR
 *   - machine-readable output (--json, --version)  → STDOUT
 *   - `reconpro dev <dir>` saves the last scan to history, which is what
 *     `reconpro export <file>.sarif` serialises. `ast` and `secrets` do NOT
 *     enter the SARIF export (upstream CLI behaviour).
 *   - `reconpro ast <file>` currently reports "No vulnerabilities found" even
 *     for vulnerable single files (upstream routes single files through
 *     analyze_directory, which no-ops on files) — we therefore always scan the
 *     workspace ROOT directory.
 *
 * Status: structurally validated (ide/vscode/tools/validate.js runs
 * `node --check` on this file and executes the exact CLI invocations below).
 * Not loadable in a real VS Code in this sandbox (no VS Code installed).
 */

'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

/** @type {import('vscode').ExtensionContext} */
let context;
/** @type {import('vscode').OutputChannel} */
let outputChannel;
/** @type {import('vscode').DiagnosticCollection} */
let diagnostics;

const SEVERITY_MAP = {
  critical: 0, high: 1, medium: 2, low: 3,
};

function getPythonPath() {
  const cfg = require('vscode').workspace.getConfiguration('reconpro');
  const p = cfg.get('pythonPath', 'python3');
  return p && String(p).trim() ? String(p).trim() : 'python3';
}

function getTimeoutMs() {
  const cfg = require('vscode').workspace.getConfiguration('reconpro');
  const sec = Number(cfg.get('timeoutSec', 120));
  return Number.isFinite(sec) && sec >= 5 ? sec * 1000 : 120000;
}

/**
 * Spawn the reconpro CLI with an args ARRAY — no shell string interpolation.
 * Resolves with { code, stdout, stderr, timedOut }.
 *
 * @param {string[]} args
 * @param {string} cwd
 * @param {(chunk: string, stream: 'out' | 'err') => void} [onChunk]
 */
function runCli(args, cwd, onChunk) {
  return new Promise((resolve) => {
    const pythonPath = getPythonPath();
    const argv = [pythonPath, '-m', 'reconpro.cli'].concat(args);
    outputChannel.appendLine(`$ ${argv.map((a) => (/[ "'\\\n]/.test(a) ? JSON.stringify(a) : a)).join(' ')}`);
    const child = spawn(argv[0], argv.slice(1), {
      cwd,
      shell: false, // NEVER a shell — argv array only.
      env: Object.assign({}, process.env, { PYTHONUNBUFFERED: '1' }),
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch (e) { /* already gone */ }
    }, getTimeoutMs());
    child.stdout.on('data', (buf) => {
      const s = buf.toString();
      stdout += s;
      if (onChunk) onChunk(s, 'out');
    });
    child.stderr.on('data', (buf) => {
      const s = buf.toString();
      stderr += s;
      if (onChunk) onChunk(s, 'err');
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      outputChannel.appendLine(`[reconpro] spawn error: ${err.message}`);
      resolve({ code: -1, stdout, stderr, timedOut });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code === null ? (timedOut ? 124 : 1) : code, stdout, stderr, timedOut });
    });
  });
}

/** Strip ANSI escapes + banner noise so the channel shows readable output. */
function cleanCliText(text) {
  return String(text || '')
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\r\n/g, '\n');
}

// ── SARIF → vscode.Diagnostic ─────────────────────────────────────────────

function sarifLevelToDiagnosticSeverity(level, securitySeverity) {
  const vscode = require('vscode');
  const l = String(level || 'warning').toLowerCase();
  if (l === 'error') return vscode.DiagnosticSeverity.Error;
  if (l === 'note' || l === 'none' || l === 'informational') return vscode.DiagnosticSeverity.Information;
  // warning (and unknown): refine with security-severity (0–10) when present.
  const num = Number(securitySeverity);
  if (Number.isFinite(num)) {
    if (num >= 7.0) return vscode.DiagnosticSeverity.Error;
    if (num >= 4.0) return vscode.DiagnosticSeverity.Warning;
    return vscode.DiagnosticSeverity.Information;
  }
  return vscode.DiagnosticSeverity.Warning;
}

function regionToRange(region) {
  const vscode = require('vscode');
  const startLine = Math.max(0, (Number(region && region.startLine) || 1) - 1);
  const startCol = Math.max(0, (Number(region && region.startColumn) || 1) - 1);
  const endLine = Math.max(startLine, (Number(region && region.endLine) || (startLine + 1)) - 1);
  const endCol = Math.max(startCol, (Number(region && region.endColumn) || (startCol + 1)) - 1);
  return new vscode.Range(startLine, startCol, endLine, endCol);
}

/**
 * Parse a SARIF 2.1.0 document into a Map<fsPath, Diagnostic[]>.
 * Only locations whose artifact URI resolves to an EXISTING file produce
 * diagnostics; everything else is reported to the output channel (honest
 * fallback — reconpro's machine-level scans use pseudo-URIs like target ids).
 *
 * @param {string} sarifPath absolute path to a .sarif file
 * @param {string} workspaceRoot absolute workspace root
 * @returns {Map<string, import('vscode').Diagnostic[]>}
 */
function parseSarifToDiagnostics(sarifPath, workspaceRoot) {
  const vscode = require('vscode');
  const byFile = new Map();
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
  } catch (err) {
    outputChannel.appendLine(`[reconpro] could not parse SARIF (${err.message}) — falling back to console output only.`);
    return byFile;
  }
  if (!doc || doc.version !== '2.1.0' || !Array.isArray(doc.runs) || doc.runs.length === 0) {
    outputChannel.appendLine('[reconpro] SARIF is not a 2.1.0 document with runs — falling back to console output only.');
    return byFile;
  }
  let consoleOnly = 0;
  for (const run of doc.runs) {
    const rules = new Map();
    const driver = run.tool && run.tool.driver;
    if (driver && Array.isArray(driver.rules)) {
      for (const r of driver.rules) rules.set(r.id, r);
    }
    for (const result of (run.results || [])) {
      const level = result.level || 'warning';
      const rule = rules.get(result.ruleId) || {};
      const secSev = rule.properties && rule.properties['security-severity'];
      const severity = sarifLevelToDiagnosticSeverity(level, secSev);
      const text = (result.message && (result.message.text || result.message.markdown)) || rule.id || 'ReconPro finding';
      const props = result.properties || {};
      const detail = [
        props.category ? `category: ${props.category}` : '',
        props.evidence ? `evidence: ${props.evidence}` : '',
        props.remediation ? `fix: ${props.remediation}` : '',
      ].filter(Boolean).join('\n');
      const diag = new vscode.Diagnostic(new vscode.Range(0, 0, 0, 1), text, severity);
      diag.source = 'reconpro';
      if (result.ruleId) diag.code = result.ruleId;
      if (detail) diag.message = text + (detail ? `\n${detail}` : '');
      const locations = ((result.locations || []).map((l) => l && l.physicalLocation)).filter(Boolean);
      if (!locations.length) { consoleOnly += 1; continue; }
      for (const phys of locations) {
        const uri = phys.artifactLocation && phys.artifactLocation.uri;
        if (!uri) { consoleOnly += 1; continue; }
        const abs = path.isAbsolute(uri) ? uri : path.join(workspaceRoot, uri);
        if (!fs.existsSync(abs)) { consoleOnly += 1; continue; }
        diag.range = phys.region ? regionToRange(phys.region) : new vscode.Range(0, 0, 0, 1);
        if (!byFile.has(abs)) byFile.set(abs, []);
        byFile.get(abs).push(diag);
      }
    }
  }
  if (consoleOnly) {
    outputChannel.appendLine(`[reconpro] ${consoleOnly} finding(s) had no file-resolvable location (machine-level scan) — see the raw output above.`);
  }
  return byFile;
}

function applyDiagnostics(byFile) {
  const vscode = require('vscode');
  diagnostics.clear();
  let total = 0;
  for (const [abs, list] of byFile) {
    diagnostics.set(vscode.Uri.file(abs), list);
    total += list.length;
  }
  return total;
}

// ── Commands ───────────────────────────────────────────────────────────────

async function cmdScanWorkspace() {
  const vscode = require('vscode');
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || !folders.length) {
    vscode.window.showWarningMessage('ReconPro: open a folder (workspace) first.');
    return;
  }
  const root = folders[0].uri.fsPath;
  outputChannel.show(true);
  outputChannel.appendLine(`[reconpro] workspace scan → ${root}`);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'ReconPro: scanning workspace', cancellable: false },
    async () => {
      // 1) AST analysis — Rich table output (stderr) → console fallback.
      const ast = await runCli(['ast', root], root);
      outputChannel.appendLine(cleanCliText(ast.stderr).split('\n').filter((l) => l && !l.startsWith(' ')).slice(-14).join('\n'));
      outputChannel.appendLine(`[reconpro] ast exit=${ast.code}`);

      // 2) Secrets scan — JSON array (stdout) → console fallback + count.
      const secrets = await runCli(['secrets', root, '--json'], root);
      let secretCount = null;
      try {
        const arr = JSON.parse(secrets.stdout);
        if (Array.isArray(arr)) {
          secretCount = arr.length;
          for (const f of arr) {
            outputChannel.appendLine(`  ${String(f.severity || '?').toUpperCase().padEnd(8)} ${f.title} [${f.asset}]`);
          }
        }
      } catch (e) { /* not JSON → raw output already shown */ }
      if (secretCount === null) outputChannel.appendLine(cleanCliText(secrets.stderr));
      outputChannel.append(`[reconpro] secrets exit=${secrets.code}`);
      outputChannel.appendLine(secretCount === null ? '' : ` (${secretCount} finding(s))`);

      // 3) `dev` scan — saves the last scan so export has real content.
      const dev = await runCli(['dev', root], root);
      outputChannel.appendLine(`[reconpro] dev exit=${dev.code}`);

      // 4) SARIF export → Problems panel. When this fails, everything above
      //    is still visible in the output channel (console fallback path).
      const sarifPath = path.join(os.tmpdir(), `reconpro-${process.pid}.sarif`);
      const exp = await runCli(['export', sarifPath], root);
      if (exp.code === 0 && fs.existsSync(sarifPath)) {
        const byFile = parseSarifToDiagnostics(sarifPath, root);
        const total = applyDiagnostics(byFile);
        outputChannel.appendLine(`[reconpro] SARIF exported: ${sarifPath}`);
        vscode.window.showInformationMessage(
          `ReconPro scan complete — ${total} diagnostic(s) in Problems panel${secretCount !== null ? `, ${secretCount} secret finding(s) in output` : ''}.`,
        );
      } else {
        outputChannel.appendLine(`[reconpro] SARIF export failed (exit=${exp.code}) — console output above is the result.`);
        vscode.window.showWarningMessage('ReconPro scan complete — no SARIF produced; see ReconPro output channel.');
      }
      try { if (fs.existsSync(sarifPath)) fs.unlinkSync(sarifPath); } catch (e) { /* ignore */ }
    },
  );
}

async function cmdDoctor() {
  const vscode = require('vscode');
  const root = vscode.workspace.workspaceFolders ? vscode.workspace.workspaceFolders[0].uri.fsPath : os.tmpdir();
  outputChannel.show(true);
  const res = await runCli(['doctor', '--json'], root);
  if (res.code !== 0) {
    outputChannel.appendLine(cleanCliText(res.stderr));
    vscode.window.showErrorMessage(`ReconPro doctor failed (exit ${res.code}).`);
    return;
  }
  try {
    const doc = JSON.parse(res.stdout);
    const line = `doctor: target=${doc.target} findings=${doc.total_findings} score=${doc.total_score} grade=${doc.grade}`;
    outputChannel.appendLine(`[reconpro] ${line}`);
    const counts = doc.severity_counts || {};
    outputChannel.appendLine(`[reconpro] severity: critical=${counts.critical || 0} high=${counts.high || 0} medium=${counts.medium || 0} low=${counts.low || 0}`);
    vscode.window.showInformationMessage(`ReconPro ${line}`);
  } catch (err) {
    outputChannel.appendLine(res.stdout);
    vscode.window.showWarningMessage('ReconPro doctor returned non-JSON output — see ReconPro output channel.');
  }
}

async function cmdVersion() {
  const vscode = require('vscode');
  const root = vscode.workspace.workspaceFolders ? vscode.workspace.workspaceFolders[0].uri.fsPath : os.tmpdir();
  const res = await runCli(['--version'], root);
  const v = (res.stdout || cleanCliText(res.stderr) || 'unknown').trim();
  outputChannel.appendLine(`[reconpro] CLI reports: ${v}`);
  vscode.window.showInformationMessage(`ReconPro CLI: ${v}`);
}

function activate(ctx) {
  const vscode = require('vscode');
  context = ctx;
  outputChannel = vscode.window.createOutputChannel('ReconPro');
  diagnostics = vscode.languages.createDiagnosticCollection('reconpro');
  context.subscriptions.push(outputChannel, diagnostics);
  context.subscriptions.push(
    vscode.commands.registerCommand('reconpro.scanWorkspace', cmdScanWorkspace),
    vscode.commands.registerCommand('reconpro.doctor', cmdDoctor),
    vscode.commands.registerCommand('reconpro.version', cmdVersion),
  );
  outputChannel.appendLine(`[reconpro] extension activated (reconpro-vscode 0.1.0)`);
}

function deactivate() {
  if (diagnostics) diagnostics.clear();
}

module.exports = { activate, deactivate };

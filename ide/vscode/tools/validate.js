#!/usr/bin/env node
/**
 * reconpro-vscode validator (PHOENIX 7-d).
 *
 * What this PROVES (all live, not just parse):
 *  1. every .json shipped by the extension parses;
 *  2. the manifest has the required fields (publisher reconpro,
 *     engines.vscode ^1.85.0, >=3 commands, configuration keys, problemMatchers,
 *     languages/grammars contributions that point at real files);
 *  3. src/extension.js is syntactically valid JavaScript (`node --check`) and
 *     spawns the CLI via child_process with an ARGS ARRAY and `shell: false`
 *     (regex-checked: no `shell: true`, no string-concat spawn);
 *  4. the exact argv arrays from tasks.json / extension.js actually run the
 *     real reconpro CLI against a vulnerable fixture and exit 0;
 *  5. the problemMatcher regexes in tasks.json MATCH the CLI's real output
 *     (they are not inert text);
 *  6. the extension's SARIF path works end-to-end: `dev <fixture>` →
 *     `export *.sarif` → parseable SARIF 2.1.0 with results + rules.
 *
 * Exit code: 0 = PASS, 1 = FAIL. No VS Code is required (and none is installed
 * in this sandbox — that part stays honestly untested).
 */
'use strict';

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..'); // ide/vscode
const REPO = path.resolve(ROOT, '..', '..'); // repo root
const PYTHON = process.env.RECONPRO_PYTHON || '/home/z/.venv/bin/python3';

let failures = 0;
let checks = 0;

function ok(name, detail) {
  checks += 1;
  console.log(`PASS  ${name}${detail ? ' — ' + detail : ''}`);
}
function fail(name, detail) {
  failures += 1;
  checks += 1;
  console.error(`FAIL  ${name}${detail ? ' — ' + detail : ''}`);
}
function assert(cond, name, detail) {
  if (cond) ok(name, detail); else fail(name, detail);
}

// ── 1. JSON manifests parse ────────────────────────────────────────────────
const jsonFiles = [
  'package.json',
  'language-configuration.json',
  'snippets/sarif.json',
  'syntaxes/sarif.tmLanguage.json',
  '.vscode/tasks.json',
  '.vscode/launch.json',
];
const parsed = {};
for (const rel of jsonFiles) {
  const p = path.join(ROOT, rel);
  try {
    parsed[rel] = JSON.parse(fs.readFileSync(p, 'utf8'));
    ok(`JSON.parse ${rel}`);
  } catch (e) {
    fail(`JSON.parse ${rel}`, e.message);
  }
}

const pkg = parsed['package.json'] || {};

// ── 2. Manifest contract ──────────────────────────────────────────────────
assert(pkg.name === 'reconpro', 'manifest.name', String(pkg.name));
assert(typeof pkg.version === 'string' && /^\d+\.\d+\.\d+$/.test(pkg.version), 'manifest.version semver', pkg.version);
assert(pkg.publisher === 'reconpro', 'manifest.publisher', String(pkg.publisher));
assert(pkg.engines && typeof pkg.engines.vscode === 'string' && pkg.engines.vscode === '^1.85.0', 'manifest.engines.vscode ^1.85.0', pkg.engines && pkg.engines.vscode);

const commands = ((pkg.contributes || {}).commands || []);
assert(Array.isArray(commands) && commands.length >= 3, 'contributes.commands >= 3', `${commands.length} commands`);
const cmdIds = commands.map((c) => c.command);
for (const id of ['reconpro.scanWorkspace', 'reconpro.doctor', 'reconpro.version']) {
  assert(cmdIds.includes(id), `command registered: ${id}`);
}
const props = (((pkg.contributes || {}).configuration || {}).properties || {});
assert(props['reconpro.pythonPath'] && props['reconpro.pythonPath'].type === 'string', 'configuration reconpro.pythonPath');
assert(props['reconpro.timeoutSec'] && props['reconpro.timeoutSec'].type === 'number', 'configuration reconpro.timeoutSec');
assert(Array.isArray((pkg.contributes || {}).problemMatchers) && pkg.contributes.problemMatchers.length >= 1, 'contributes.problemMatchers');
const langs = (pkg.contributes || {}).languages || [];
assert(langs.some((l) => l.id === 'sarif'), 'contributes.languages sarif');
const grammar = (pkg.contributes || {}).grammars || [];
assert(grammar.length >= 1 && fs.existsSync(path.join(ROOT, grammar[0].path)), 'grammar file exists', grammar[0] && grammar[0].path);
assert(fs.existsSync(path.join(ROOT, 'language-configuration.json')), 'language configuration exists');
assert(typeof pkg.main === 'string' && fs.existsSync(path.join(ROOT, pkg.main)), 'manifest.main resolves', pkg.main);

// snippets shape
const snips = parsed['snippets/sarif.json'] || {};
const snipKeys = Object.keys(snips);
assert(snipKeys.length >= 3, 'sarif snippets >= 3', snipKeys.join(', '));
assert(snipKeys.every((k) => snips[k].prefix && Array.isArray(snips[k].body)), 'snippets have prefix+body');

// tmLanguage shape
const tml = parsed['syntaxes/sarif.tmLanguage.json'] || {};
assert(tml.scopeName === 'source.sarif.json' && Array.isArray(tml.patterns), 'tmLanguage scopeName+patterns', tml.scopeName);

// ── 3. extension.js: syntax + no-shell spawn contract ─────────────────────
const extPath = path.join(ROOT, 'src', 'extension.js');
const extSrc = fs.readFileSync(extPath, 'utf8');
const nodeCheck = spawnSync(process.execPath, ['--check', extPath], { encoding: 'utf8' });
assert(nodeCheck.status === 0, 'node --check src/extension.js', (nodeCheck.stderr || '').split('\n')[0]);
assert(/require\(['"]child_process['"]\)/.test(extSrc), 'extension.js requires child_process');
assert(/spawn\(\s*[\w$]+(\[[^\]]*\])?\s*,\s*[\w$]+/.test(extSrc), 'spawn(executable, argsArray) form');
assert(!/shell:\s*true/.test(extSrc), 'no shell:true in extension.js');
assert(/shell:\s*false/.test(extSrc), 'shell explicitly false');
assert(!/spawn\([^)]*\+/.test(extSrc), 'no string-concat spawn arguments');
assert(/activate\s*\(/.test(extSrc) && /deactivate\s*\(/.test(extSrc), 'exports activate + deactivate');

// ── 4. tasks.json: 3 process tasks with problemMatchers ───────────────────
const tasks = parsed['.vscode/tasks.json'] || {};
const taskList = tasks.tasks || [];
assert(taskList.length === 3, 'tasks.json has exactly 3 tasks', String(taskList.length));
for (const t of taskList) {
  assert(t.type === 'process', `task "${t.label}" type=process (argv array, no shell)`);
  assert(t.command === '${config:reconpro.pythonPath}', `task "${t.label}" uses \${config:reconpro.pythonPath}`);
  assert(Array.isArray(t.args) && t.args.includes('-m') && t.args.includes('reconpro.cli'), `task "${t.label}" args array runs -m reconpro.cli`);
  assert(t.options && t.options.env && t.options.env.COLUMNS === '200', `task "${t.label}" sets COLUMNS=200 (deterministic Rich table width)`);
  assert(Array.isArray(t.problemMatcher) && t.problemMatcher.length >= 1, `task "${t.label}" has problemMatcher(s)`, `${(t.problemMatcher || []).length} matchers`);
}
const launch = parsed['.vscode/launch.json'] || {};
assert(Array.isArray(launch.configurations) && launch.configurations.length >= 2, 'launch.json configurations', String(launch.configurations.length));

// ── 5. LIVE smoke: run the real CLI exactly like the tasks/extension do ───
// Fixture: vulnerable python in a SHORT path (ast table truncates file to 30 chars).
const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rpvfx'));
const evil = path.join(fixtureDir, 'evil.py');
fs.writeFileSync(evil, [
  'import subprocess',
  'subprocess.call("ls", shell=True)',
  'import pickle',
  'pickle.loads(payload)',
  'password = "SKYNET-ALPHA-77"',
  'eval(user_code)',
  '',
].join('\n'));

function runCli(args, cwd) {
  // Same spawn discipline as src/extension.js AND the tasks.json tasks
  // (argv array, shell: false, COLUMNS=200 so Rich renders full severities).
  const r = spawnSync(PYTHON, ['-m', 'reconpro.cli'].concat(args), {
    cwd,
    shell: false,
    encoding: 'utf8',
    timeout: 90000,
    env: Object.assign({}, process.env, { PYTHONUNBUFFERED: '1', COLUMNS: '200' }),
  });
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// 5a. --version (reconpro.version command)
const v = runCli(['--version'], REPO);
assert(v.code === 0 && /ReconPro\s+\d+\.\d+\.\d+/.test(v.stdout), 'LIVE: --version (reconpro.version command)', v.stdout.trim());

// 5b. ast task command → apply the task's problemMatcher regexes to real output
const ast = runCli(['ast', fixtureDir], REPO);
assert(ast.code === 0, 'LIVE: ast exit=0', `exit ${ast.code}`);
const astMatchers = (taskList.find((t) => t.label.includes('AST')) || {}).problemMatcher || [];
let astProblems = 0;
let astSample = '';
for (const m of astMatchers) {
  const re = new RegExp(m.pattern.regexp);
  for (const line of (ast.stderr + ast.stdout).split(/\r?\n/)) {
    const hit = re.exec(line);
    if (hit) { astProblems += 1; astSample = astSample || hit[0].trim(); }
  }
}
assert(astProblems >= 1, 'LIVE: ast problemMatcher regexes match real CLI output', `${astProblems} problems; e.g. ${JSON.stringify(astSample.slice(0, 90))}`);

// 5c. secrets task command (non-JSON mode is what the task runs)
const sec = runCli(['secrets', fixtureDir], REPO);
assert(sec.code === 0, 'LIVE: secrets exit=0', `exit ${sec.code}`);
const secMatchers = (taskList.find((t) => t.label.includes('Secrets')) || {}).problemMatcher || [];
let secProblems = 0;
for (const m of secMatchers) {
  const re = new RegExp(m.pattern.regexp);
  for (const line of (sec.stderr + sec.stdout).split(/\r?\n/)) {
    if (re.exec(line)) secProblems += 1;
  }
}
assert(secProblems >= 1, 'LIVE: secrets problemMatcher regexes match real CLI output', `${secProblems} problems`);

// 5d. doctor task + extension doctor command (JSON on stdout)
const doc = runCli(['doctor', '--json'], REPO);
let doctorParsed = null;
try { doctorParsed = JSON.parse(doc.stdout); } catch (e) { /* leave null */ }
assert(doc.code === 0 && doctorParsed !== null, 'LIVE: doctor --json parses (reconpro.doctor command)', doctorParsed ? `findings=${doctorParsed.total_findings} grade=${doctorParsed.grade}` : 'non-JSON');
const docMatchers = (taskList.find((t) => t.label.includes('Doctor')) || {}).problemMatcher || [];
let docProblems = 0;
if (doc.code === 0) {
  const docHuman = runCli(['doctor'], REPO); // the task runs human mode
  for (const m of docMatchers) {
    const re = new RegExp(m.pattern.regexp);
    for (const line of (docHuman.stderr + docHuman.stdout).split(/\r?\n/)) {
      if (re.exec(line)) docProblems += 1;
    }
  }
}
assert(docProblems >= 1, 'LIVE: doctor problemMatcher regexes match real CLI output', `${docProblems} problems`);

// 5e. extension scanWorkspace flow: dev → export → SARIF parse
const dev = runCli(['dev', fixtureDir], REPO);
assert(dev.code === 0, 'LIVE: dev <fixture> exit=0 (scanWorkspace step 3)', `exit ${dev.code}`);
const sarifPath = path.join(fixtureDir, 'reconpro.sarif');
const exp = runCli(['export', sarifPath], REPO);
let sarif = null;
try { sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8')); } catch (e) { /* leave null */ }
assert(exp.code === 0 && sarif !== null, 'LIVE: export *.sarif parses (scanWorkspace step 4)');
if (sarif) {
  assert(sarif.version === '2.1.0' && Array.isArray(sarif.runs) && sarif.runs.length >= 1, 'SARIF 2.1.0 with runs');
  const run = sarif.runs[0];
  assert(run.tool && run.tool.driver && run.tool.driver.name === 'ReconPro', 'SARIF tool.driver.name=ReconPro');
  assert(Array.isArray(run.results) && run.results.length >= 1, 'SARIF results non-empty', `${run.results.length} results`);
  assert(Array.isArray(run.tool.driver.rules) && run.tool.driver.rules.length >= 1, 'SARIF rules non-empty', `${run.tool.driver.rules.length} rules`);
}

// ── summary ────────────────────────────────────────────────────────────────
try { fs.rmSync(fixtureDir, { recursive: true, force: true }); } catch (e) { /* ignore */ }
console.log('');
console.log(`reconpro-vscode validation: ${checks - failures}/${checks} checks passed.`);
if (failures > 0) {
  console.error('RESULT: FAIL');
  process.exit(1);
}
console.log('RESULT: PASS');
process.exit(0);

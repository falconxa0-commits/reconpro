// Hermetic tests for the plain-JS (maintenance-tier) Node SDK.
// Every CLI-backed case runs against a tiny shell-script stub "python"
// binary — no reconpro installation is required.
//
// Run:  cd sdks/node && npm test
//       (or: node --test "sdks/node/test/*.test.js" from the repo root)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  ReconProClient,
  SdkError,
  buildArgs,
  validateTarget,
} from '../src/index.js';

/** Stub "python": the SDK spawns `<python> -m reconpro.cli <args>`, so the
 * stub shifts off the first two args and then behaves like the CLI. */
async function makeStubPython(body) {
  const dir = await mkdtemp(join(tmpdir(), 'reconpro-node-test-'));
  const path = join(dir, 'python-stub');
  await writeFile(path, `#!/bin/sh\nshift 2\n${body}\n`, 'utf8');
  await chmod(path, 0o755);
  return path;
}

function stubClient(pythonPath, timeoutMs = 10_000) {
  return new ReconProClient({ pythonPath, root: process.cwd(), timeoutMs });
}

test('buildArgs always uses an argument list', () => {
  assert.deepEqual(buildArgs('/x/python', ['scan', 't', '--json']), [
    '/x/python',
    '-m',
    'reconpro.cli',
    'scan',
    't',
    '--json',
  ]);
});

test('validateTarget rejects shell metacharacters and empty input', () => {
  assert.throws(() => validateTarget('example.com; rm -rf /'));
  assert.throws(() => validateTarget('   '));
  assert.equal(validateTarget('  example.com  '), 'example.com');
});

test('version() resolves the CLI version string from stdout', async () => {
  const stub = await makeStubPython('echo "ReconPro 11.2.0"');
  assert.equal(await stubClient(stub).version(), 'ReconPro 11.2.0');
});

test('non-zero exit carries exit code + captured stderr', async () => {
  const stub = await makeStubPython('echo "usage: boom" >&2\nexit 2');
  await assert.rejects(
    stubClient(stub).version(),
    (err) =>
      err instanceof SdkError && err.exitCode === 2 && err.stderr.includes('boom'),
  );
});

test('invalid JSON on stdout rejects with an SdkError', async () => {
  const stub = await makeStubPython("echo 'this is not json'");
  await assert.rejects(
    stubClient(stub).scan('example.com'),
    (err) => err instanceof SdkError && /invalid JSON/.test(err.message),
  );
});

test('timeout rejects with an SdkError mentioning the timeout', async () => {
  const stub = await makeStubPython('sleep 5');
  await assert.rejects(
    stubClient(stub, 300).version(),
    (err) => err instanceof SdkError && /timed out/.test(err.message),
  );
});

test('scan() rejects malformed targets client-side (no process spawned)', async () => {
  await assert.rejects(
    stubClient('/nonexistent/python').scan('example.com; rm -rf /'),
  );
});

test('missing binary rejects (spawn failure surfaces)', async () => {
  await assert.rejects(stubClient('/nonexistent/python-xyz').version());
});

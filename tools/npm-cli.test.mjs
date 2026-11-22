import { sqlProfileSuffix } from './lib/session-profile.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { npmInvocation } from './lib/npm-cli.mjs';
test('Windows launches npm JS directly without shell parsing paths or arguments', () => {
  const args = ['install', 'C:\\private space\\literal-$(name).tgz'];
  assert.deepEqual(npmInvocation(args, { platform: 'win32', execPath: 'C:\\Program Files\\nodejs\\node.exe' }), {
    file: 'C:\\Program Files\\nodejs\\node.exe', args: ['C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js', ...args],
  });
});
test('Unix keeps the existing executable and argument boundaries', () => {
  assert.deepEqual(npmInvocation(['pack', '--json'], { platform: 'linux' }), { file: 'npm', args: ['pack', '--json'] });
});

test('all SQL adapter combinations have distinct versions and preserve the SQL-free default', () => {
  const profiles = new Set();
  for (const native of [false, true]) for (const browser of [false, true]) for (const wasmNode of [false, true]) profiles.add(sqlProfileSuffix({ native, browser, wasmNode }));
  assert.equal(profiles.size, 8); assert.equal(sqlProfileSuffix(), ''); assert.equal(sqlProfileSuffix({ native: true }), '-sql');
});

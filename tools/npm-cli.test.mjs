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

#!/usr/bin/env node
// In Chronolog v2 there are zero native C/C++ builds — all test suites run in pure JS + WASM + built-in node:sqlite!
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import process from 'node:process';

const root = resolve(import.meta.dirname, '..');

function walkTests(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'artifacts' || entry.name === 'vendor') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walkTests(full, out);
    else if (entry.name.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

const fastTests = [...walkTests(join(root, 'packages')), ...walkTests(join(root, 'test'))]
  .map(file => relative(root, file).replaceAll('\\', '/'))
  .sort();

if (process.argv.includes('--list')) {
  process.stdout.write(JSON.stringify({ fast: fastTests, excluded: [] }, null, 2) + '\n');
  process.exit(0);
}

process.stderr.write(`test:fast: running all ${fastTests.length} zero-native-build test files\n`);
const start = Date.now();
execFileSync(process.execPath, [join(root, 'node_modules/vitest/vitest.mjs'), 'run', '--maxWorkers=1', '--no-file-parallelism', ...fastTests], {
  cwd: root,
  stdio: 'inherit',
});
const elapsedSec = ((Date.now() - start) / 1000).toFixed(2);
process.stderr.write(`test:fast completed in ${elapsedSec}s\n`);

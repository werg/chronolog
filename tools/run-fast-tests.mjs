#!/usr/bin/env node
// Compute the exact static import closure of every *.test.ts file and run only tests
// that do NOT directly or transitively import native SQL (@chronolog/materializer-doltlite or @dolthub/doltlite).
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import process from 'node:process';

const root = resolve(import.meta.dirname, '..');
const packagesDir = join(root, 'packages');
const NATIVE_SQL_RE = /(?:^|\/)materializer-doltlite(?:\/|$)|@chronolog\/materializer-doltlite|@dolthub\/doltlite/;
const IMPORT_RE = /(?:from\s+|import\s*\(\s*|import\s+)['"]([^'"]+)['"]/g;

// Map workspace package names -> source entry paths from tsconfig.base.json
const tsconfig = JSON.parse(readFileSync(join(root, 'tsconfig.base.json'), 'utf8'));
const aliasMap = new Map();
for (const [alias, targets] of Object.entries(tsconfig.compilerOptions?.paths ?? {})) {
  if (Array.isArray(targets) && typeof targets[0] === 'string') {
    aliasMap.set(alias, resolve(root, targets[0]));
  }
}

function walkTests(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'artifacts') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walkTests(full, out);
    else if (entry.name.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

function resolveImport(specifier, fromFile) {
  if (NATIVE_SQL_RE.test(specifier)) return 'NATIVE_SQL';
  if (aliasMap.has(specifier)) return aliasMap.get(specifier);
  if (!specifier.startsWith('.')) return null;
  const base = resolve(dirname(fromFile), specifier);
  const candidates = [
    base,
    base.replace(/\.js$/u, '.ts'),
    base + '.ts',
    join(base, 'index.ts'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

const cache = new Map();
function touchesNativeSql(file, stack = new Set()) {
  if (NATIVE_SQL_RE.test(relative(root, file).replaceAll('\\', '/'))) return true;
  if (cache.has(file)) return cache.get(file);
  if (stack.has(file)) return false;
  stack.add(file);
  const content = readFileSync(file, 'utf8');
  let touches = false;
  for (const match of content.matchAll(IMPORT_RE)) {
    const target = resolveImport(match[1], file);
    if (target === 'NATIVE_SQL' || (target && touchesNativeSql(target, stack))) {
      touches = true;
      break;
    }
  }
  stack.delete(file);
  cache.set(file, touches);
  return touches;
}

const allTests = [...walkTests(packagesDir), ...walkTests(join(root, 'test'))].sort();
const fastTests = [];
const excludedTests = [];
for (const file of allTests) {
  const rel = relative(root, file).replaceAll('\\', '/');
  if (touchesNativeSql(file)) excludedTests.push(rel);
  else fastTests.push(rel);
}

if (process.argv.includes('--list')) {
  process.stdout.write(JSON.stringify({ fast: fastTests, excluded: excludedTests }, null, 2) + '\n');
  process.exit(0);
}

process.stderr.write(`test:fast: running ${fastTests.length} pure-JS test files (excluded ${excludedTests.length} native-SQL closure files)\n`);
const start = Date.now();
execFileSync(process.execPath, [join(root, 'node_modules/vitest/vitest.mjs'), 'run', ...fastTests], {
  cwd: root,
  stdio: 'inherit',
});
const elapsedSec = ((Date.now() - start) / 1000).toFixed(2);
process.stderr.write(`test:fast completed in ${elapsedSec}s\n`);

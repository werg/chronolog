import { execNpmSync } from './lib/npm-cli.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';
import process from 'node:process';
import { parseArgs } from 'node:util';

import { build } from 'esbuild';
import ts from 'typescript';

const root = resolve(import.meta.dirname, '..');
const { values } = parseArgs({ options: { output: { type: 'string', default: 'artifacts/signals' },
  'allow-dirty': { type: 'boolean', default: false } } });
const output = resolve(values.output), entry = join(root, 'packages/signals/src/index.ts');
const source = git(['rev-parse', 'HEAD']).trim();
const bundled = await build({ entryPoints: [entry], outfile: join(output, 'index.mjs'), write: false,
  bundle: true, platform: 'browser', format: 'esm', target: 'es2022', metafile: true, absWorkingDir: root });
const runtimeInputs = Object.keys(bundled.metafile.inputs).sort();
assert(runtimeInputs.every(path => /^packages\/(signals|canonical)\/src\//u.test(path) ||
  /(?:^|\/)node_modules\/@noble\/hashes\//u.test(path)), 'Signals artifact must contain only the signal core and canonical codec dependencies');
assert(Object.values(bundled.metafile.outputs).every(value => value.imports.length === 0), 'Signals ESM must have no external imports');

const inputs = [...new Set([...runtimeInputs, 'packages/signals/package.json', 'packages/signals/README.md',
  'packages/canonical/package.json', 'package.json', 'pnpm-lock.yaml', 'tsconfig.base.json',
  'tools/package-signals.mjs', 'tools/lib/npm-cli.mjs', 'tools/test-signals-package.mjs'])].sort();
const changed = git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim();
if (changed && !values['allow-dirty']) throw new Error('SIGNALS_PACKAGE_REQUIRES_CLEAN_INPUTS (commit package inputs before building)');
const declarations = emitDeclarations();
const readme = await readFile(join(root, 'packages/signals/README.md'));
for (const text of declarations.values()) {
  const imports = ts.preProcessFile(text, true).importedFiles.map(value => value.fileName);
  assert(imports.every(name => name === './payload.js') && !/reference\s+(?:types|path)=/u.test(text),
    'Signals declarations must be self-contained and portable');
}
assert.equal(git(['rev-parse', 'HEAD']).trim(), source, 'Signals source commit changed during packaging');
assert.equal(git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim(), changed,
  'Signals package inputs changed during packaging');

const dirty = Boolean(changed), suffix = `${source.slice(0, 8)}${dirty ? '-dirty' : ''}`, version = `0.0.0-g${suffix}`;
await mkdir(output, { recursive: true });
await writeFile(join(output, 'index.mjs'), bundled.outputFiles[0].contents);
for (const [name, text] of declarations) await writeFile(join(output, name), text);
await writeFile(join(output, 'README.md'), readme);
const packageJson = { name: '@chronolog/signals', version, type: 'module',
  description: 'Standalone signed, expiring live messages without a database or finality protocol',
  exports: { '.': { types: './index.d.ts', import: './index.mjs' } },
  files: ['index.mjs', 'index.d.ts', 'payload.d.ts', 'provenance.json', 'README.md'], dependencies: {} };
await writeFile(join(output, 'package.json'), JSON.stringify(packageJson, null, 2) + '\n');
const sha256 = Object.fromEntries(await Promise.all(['index.mjs', 'index.d.ts', 'payload.d.ts', 'README.md', 'package.json']
  .map(async name => [name, hash(await readFile(join(output, name)))])));
await writeFile(join(output, 'provenance.json'), JSON.stringify({ format: 'chronolog-signals-package/v1',
  repository: 'werg/chronolog', source, dirty, inputs, runtimeInputs, sha256 }, null, 2) + '\n');
const packed = JSON.parse(execNpmSync(['pack', '--ignore-scripts', '--json', '--pack-destination', output], {
  cwd: output, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}))[0];
const artifact = join(output, `chronolog-signals-${suffix}.tgz`);
await rename(join(output, packed.filename), artifact);
process.stdout.write(JSON.stringify({ artifact, version, source, dirty, sha256: hash(await readFile(artifact)) }) + '\n');

function emitDeclarations() {
  const config = ts.readConfigFile(join(root, 'tsconfig.base.json'), ts.sys.readFile);
  if (config.error) throw new Error(ts.flattenDiagnosticMessageText(config.error.messageText, '\n'));
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const program = ts.createProgram([entry], { ...parsed.options, types: [], noEmit: false,
    declaration: true, declarationMap: false, sourceMap: false, emitDeclarationOnly: true, noEmitOnError: true });
  const diagnostics = [...parsed.errors, ...ts.getPreEmitDiagnostics(program)];
  if (diagnostics.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCurrentDirectory: () => root, getCanonicalFileName: name => name, getNewLine: () => '\n',
  }));
  const files = new Map();
  for (const name of ['index.ts', 'payload.ts']) {
    const file = program.getSourceFile(join(root, 'packages/signals/src', name));
    assert(file, `Signals declaration source missing: ${name}`);
    const result = program.emit(file, (path, text) => files.set(basename(path), text), undefined, true);
    assert(!result.emitSkipped, `Signals declaration emit failed: ${relative(root, file.fileName)}`);
  }
  assert.deepEqual([...files.keys()].sort(), ['index.d.ts', 'payload.d.ts']);
  return files;
}
function git(args) { return execFileSync('git', args, { cwd: root, encoding: 'utf8' }); }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

import { execNpmSync } from './lib/npm-cli.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import process from 'node:process';
import { parseArgs } from 'node:util';

import { build } from 'esbuild';
import ts from 'typescript';

const root = resolve(import.meta.dirname, '..');
const { values } = parseArgs({
  options: {
    output: { type: 'string', default: 'artifacts/pack' },
    'allow-dirty': { type: 'boolean', default: false },
  },
});
const output = resolve(values.output), packageRoot = join(output, 'package');
const source = git(['rev-parse', 'HEAD']).trim(), sourceTree = git(['rev-parse', 'HEAD^{tree}']).trim();
const entry = join(root, 'packages/pack/src/index.ts');

const bundled = await build({
  entryPoints: { index: entry },
  outdir: packageRoot,
  write: false,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  metafile: true,
  absWorkingDir: root,
  external: ['node:*', 'esbuild', '@chronolog/peer-session', '@chronolog/peer-session/*'],
  outExtension: { '.js': '.mjs' },
});

const runtimeInputs = Object.keys(bundled.metafile.inputs).sort();
const declaration = declarations([entry]);
const inputs = [...new Set([
  ...runtimeInputs, ...declaration.inputs,
  'package.json', 'pnpm-lock.yaml', 'tsconfig.base.json',
  'packages/pack/package.json', 'tools/package-pack.mjs', 'tools/lib/npm-cli.mjs',
])].sort();

const changed = git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim();
if (changed && !values['allow-dirty']) throw new Error('PACK_PACKAGE_REQUIRES_CLEAN_INPUTS');
const dirty = Boolean(changed);
const suffix = `${source.slice(0, 8)}${dirty ? '-dirty' : ''}`;
const version = `0.0.0-g${suffix}`;

await rm(packageRoot, { force: true, recursive: true });
await mkdir(packageRoot, { recursive: true });
const files = new Map();
for (const file of bundled.outputFiles) files.set(relative(packageRoot, file.path).replaceAll('\\', '/'), file.contents);
for (const [path, content] of declaration.files) files.set(path, content);
files.set('index.d.ts', `export * from './types/packages/pack/src/index.js';\n`);

files.set('package.json', JSON.stringify({
  name: '@chronolog/pack',
  version,
  type: 'module',
  description: 'Deterministic Chronolog reducer packer, determinism linter, npm/JSR tarball ingester, and lockfile tool',
  exports: {
    '.': { types: './index.d.ts', import: './index.mjs' },
  },
  files: ['*.mjs', '*.d.ts', 'types', 'provenance.json'],
  dependencies: {
    esbuild: '^0.28.2',
  },
  peerDependencies: {
    '@chronolog/peer-session': '*',
  },
  engines: { node: '>=22.15' },
}, null, 2) + '\n');

for (const [path, content] of files) {
  await mkdir(dirname(join(packageRoot, path)), { recursive: true });
  await writeFile(join(packageRoot, path), content);
}
assert.equal(git(['rev-parse', 'HEAD']).trim(), source, 'Source commit changed during packaging');
const sha256 = Object.fromEntries([...files].map(([path, content]) => [path, hash(content)]));
await writeFile(join(packageRoot, 'provenance.json'), JSON.stringify({
  format: 'chronolog-pack-package/v1',
  repository: 'werg/chronolog',
  source,
  sourceTree,
  dirty,
  inputs,
  runtimeInputs,
  sha256,
}, null, 2) + '\n');

const packed = JSON.parse(execNpmSync(['pack', '--ignore-scripts', '--json', '--pack-destination', output], {
  cwd: packageRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}))[0];
const artifact = join(output, `chronolog-pack-${suffix}.tgz`);
await rename(join(output, packed.filename), artifact);
process.stdout.write(JSON.stringify({ artifact, version, source, sourceTree, dirty, sha256: hash(await readFile(artifact)) }) + '\n');

function declarations(entryPoints) {
  const configuration = ts.readConfigFile(join(root, 'tsconfig.base.json'), ts.sys.readFile);
  if (configuration.error) throw new Error(ts.flattenDiagnosticMessageText(configuration.error.messageText, '\n'));
  const parsed = ts.parseJsonConfigFileContent(configuration.config, ts.sys, root);
  const out = join(packageRoot, 'types');
  const options = {
    ...parsed.options, rootDir: root, outDir: out, types: ['node'], noEmit: false,
    declaration: true, declarationMap: false, sourceMap: false, emitDeclarationOnly: true, noEmitOnError: true,
  };
  const compiler = ts.createProgram([...entryPoints], options);
  const diagnostics = [...parsed.errors, ...ts.getPreEmitDiagnostics(compiler)];
  if (diagnostics.length) {
    throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
      getCurrentDirectory: () => root, getCanonicalFileName: name => name, getNewLine: () => '\n',
    }));
  }
  const files = new Map(), inputs = new Set();
  const result = compiler.emit(undefined, (path, content, _bom, _error, sourceFiles) => {
    if (!path.endsWith('.d.ts')) return;
    for (const file of sourceFiles ?? []) inputs.add(relative(root, file.fileName).replaceAll('\\', '/'));
    const rewritten = content.replace(/(['"])(@chronolog\/[^'"]+|chronolog-db)\1/gu, (_match, quote, name) => {
      const sourcePath = parsed.options.paths?.[name]?.[0];
      assert(sourcePath, `Missing declaration alias: ${name}`);
      const destination = join(out, sourcePath.replace(/\.ts$/u, '.js'));
      let local = relative(dirname(path), destination).replaceAll('\\', '/');
      if (!local.startsWith('.')) local = `./${local}`;
      return `${quote}${local}${quote}`;
    });
    files.set(relative(packageRoot, path).replaceAll('\\', '/'), rewritten);
  });
  if (result.emitSkipped || result.diagnostics.length) {
    throw new Error('Pack declaration emit failed');
  }
  return { files, inputs: [...inputs] };
}
function git(args) { return execFileSync('git', args, { cwd: root, encoding: 'utf8' }); }
function hash(value) { return createHash('sha256').update(value).digest('hex'); }

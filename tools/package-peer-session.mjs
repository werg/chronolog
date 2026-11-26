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
    output: { type: 'string', default: 'artifacts/peer-session' },
    'allow-dirty': { type: 'boolean', default: false },
    'no-native-rtc': { type: 'boolean', default: false },
  },
});
const output = resolve(values.output), packageRoot = join(output, 'package');
const nativeRtc = !values['no-native-rtc'];
const source = git(['rev-parse', 'HEAD']).trim(), sourceTree = git(['rev-parse', 'HEAD^{tree}']).trim();

const entries = Object.fromEntries([
  'index', 'native', 'browser', 'worker', 'webrtc', 'websocket', 'tendriller',
  ...(nativeRtc ? ['webrtc-native'] : []),
].map(name => [name, join(root, 'packages/peer-session/src', `${name}.ts`)]));

const pureExternals = [
  'node:*',
  'module',
  'quickjs-emscripten-core',
  '@jitl/quickjs-ng-wasmfile-release-sync',
  ...(nativeRtc ? ['werift'] : []),
];

const bundled = await build({
  entryPoints: entries,
  outdir: packageRoot,
  write: false,
  bundle: true,
  splitting: true,
  platform: 'neutral',
  conditions: ['import', 'default'],
  mainFields: ['module', 'main'],
  format: 'esm',
  target: 'es2022',
  metafile: true,
  absWorkingDir: root,
  external: pureExternals,
  outExtension: { '.js': '.mjs' },
  chunkNames: 'chunks/[name]-[hash]',
});

const runtimeInputs = Object.keys(bundled.metafile.inputs).sort();
assert(
  Object.values(bundled.metafile.outputs).flatMap(value => value.imports).every(value =>
    !value.external ||
    value.path.startsWith('node:') ||
    value.path === 'module' ||
    value.path === 'quickjs-emscripten-core' ||
    value.path === '@jitl/quickjs-ng-wasmfile-release-sync' ||
    (nativeRtc && value.path === 'werift')),
  'The session artifact may import only declared zero-node-gyp runtime dependencies',
);

// Verify browser/worker entrypoints never statically pull Node APIs or werift.
for (const entry of ['index', 'browser', 'worker', 'webrtc', 'websocket', 'tendriller']) {
  const entryOut = Object.entries(bundled.metafile.outputs).find(([, value]) =>
    value.entryPoint === relative(root, entries[entry]).replaceAll('\\', '/'));
  assert(entryOut, `Missing bundled entry: ${entry}`);
  const visited = new Set();
  const inspect = (path) => {
    if (visited.has(path)) return;
    visited.add(path);
    const metadata = bundled.metafile.outputs[path];
    assert(metadata, `Missing bundled dependency: ${path}`);
    for (const dependency of metadata.imports) {
      if (dependency.kind === 'dynamic-import') continue;
      assert(!dependency.external || (!dependency.path.startsWith('node:') && dependency.path !== 'werift'),
        `Worker-compatible entry ${entry} statically imports Node/native runtime: ${dependency.path}`);
      if (!dependency.external) inspect(dependency.path);
    }
  };
  inspect(entryOut[0]);
}

// Verify passive browser/worker/index entrypoints do not eagerly load durable storage, QuickJS, or SQLite-CAS.
const outputName = path => relative(packageRoot, resolve(root, path)).replaceAll('\\', '/');
const runtimeModules = Object.fromEntries(Object.entries(bundled.metafile.outputs).map(([path, value]) => [outputName(path), {
  inputs: Object.entries(value.inputs).filter(([, input]) => input.bytesInOutput > 0).map(([src]) => src).sort(),
  imports: value.imports.map(input => ({ path: input.external ? input.path : outputName(input.path), kind: input.kind, external: input.external === true })),
}]));

const eagerHeavyImpl = path =>
  /^(?:packages\/peer-session\/src\/(?:browser-storage-selector|browser-capabilities|session|content|network-content)\.ts|packages\/materializer\/src\/(?:kernel|quickjs-sandbox)\.ts|packages\/sqlite-cas\/|packages\/records\/src\/(?:browser|native|record-envelope|indexeddb-bytes-store)\.ts)/u.test(path);

for (const entry of ['index', 'browser', 'worker', 'tendriller']) {
  const entryOut = Object.entries(bundled.metafile.outputs).find(([, value]) =>
    value.entryPoint === relative(root, entries[entry]).replaceAll('\\', '/'));
  assert(entryOut, `Missing protocol entry: ${entry}`);
  const visited = new Set();
  const inspect = path => {
    if (visited.has(path)) return;
    visited.add(path);
    const mod = runtimeModules[path];
    assert(mod, `Missing emitted module: ${path}`);
    for (const input of mod.inputs) {
      assert(!eagerHeavyImpl(input), `Passive ${entry} entry eagerly loads heavy implementation: ${input}`);
      if (entry === 'browser' || entry === 'tendriller') {
        assert(!/^packages\/peer-session\/src\/(?:session|runtime|device|browser-device|network)\.ts$/u.test(input),
          `Page ${entry} entry loads participant ownership: ${input}`);
      }
    }
    for (const dependency of mod.imports) {
      if (!dependency.external && dependency.kind !== 'dynamic-import') inspect(dependency.path);
    }
  };
  inspect(outputName(entryOut[0]));
}

// Include compiled sqlite-cas.wasm + manifest for zero-node-gyp deterministic SQLite-CAS in Node, Browser & Cloudflare Workers!
const sqliteWasmPath = join(root, 'packages/sqlite-cas/wasm/sqlite-cas.wasm');
const sqliteManifestPath = join(root, 'packages/sqlite-cas/wasm/manifest.json');
const sqliteWasmBytes = await readFile(sqliteWasmPath);
const sqliteManifestBytes = await readFile(sqliteManifestPath);
const sqliteManifest = JSON.parse(sqliteManifestBytes.toString('utf8'));
assert.equal(hash(sqliteWasmBytes), sqliteManifest.wasmSha256, 'sqlite-cas.wasm digest mismatch against manifest.json');

const declaration = declarations(Object.values(entries));
const inputs = [...new Set([
  ...runtimeInputs, ...declaration.inputs,
  'package.json', 'pnpm-lock.yaml', 'tsconfig.base.json',
  'packages/peer-session/package.json', 'packages/peer-session/README.md',
  'packages/sqlite-cas/wasm/sqlite-cas.wasm', 'packages/sqlite-cas/wasm/manifest.json',
  'tools/package-peer-session.mjs', 'tools/lib/npm-cli.mjs',
])].sort();

const changed = git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim();
if (changed && !values['allow-dirty']) throw new Error('PEER_SESSION_PACKAGE_REQUIRES_CLEAN_INPUTS');
const dirty = Boolean(changed);
const suffix = `${source.slice(0, 8)}${dirty ? '-dirty' : ''}${nativeRtc ? '' : '-relay'}`;
const version = `0.0.0-g${suffix}`;

await rm(packageRoot, { force: true, recursive: true });
await mkdir(packageRoot, { recursive: true });
const files = new Map();
for (const file of bundled.outputFiles) files.set(relative(packageRoot, file.path).replaceAll('\\', '/'), file.contents);
for (const [path, content] of declaration.files) files.set(path, content);
for (const name of Object.keys(entries)) files.set(`${name}.d.ts`, `export * from './types/packages/peer-session/src/${name}.js';\n`);
files.set('wasm/sqlite-cas.wasm', sqliteWasmBytes);
files.set('wasm/manifest.json', sqliteManifestBytes);
files.set('README.md', await readFile(join(root, 'packages/peer-session/README.md')));

const exportsMap = {
  ...Object.fromEntries(Object.keys(entries).map(name => [
    name === 'index' ? '.' : `./${name}`,
    { types: `./${name}.d.ts`, import: `./${name}.mjs` },
  ])),
  './sqlite-cas.wasm': './wasm/sqlite-cas.wasm',
  './sqlite-cas-manifest.json': './wasm/manifest.json',
};

files.set('package.json', JSON.stringify({
  name: '@chronolog/peer-session',
  version,
  type: 'module',
  description: 'Chronolog v2 Merkle-DAG CRDT peer sessions with QuickJS-NG Import-Map reducers, deterministic SQLite-CAS WASM, and zero native builds',
  exports: exportsMap,
  files: ['*.mjs', '*.d.ts', 'chunks', 'types', 'wasm', 'README.md', 'provenance.json'],
  dependencies: {
    'quickjs-emscripten-core': '0.32.0',
    '@jitl/quickjs-ng-wasmfile-release-sync': '0.32.0',
    ...(nativeRtc ? { werift: '0.27.0' } : {}),
  },
  engines: { node: '>=22.15' },
}, null, 2) + '\n');

for (const [path, content] of files) {
  await mkdir(dirname(join(packageRoot, path)), { recursive: true });
  await writeFile(join(packageRoot, path), content);
}
assert.equal(git(['rev-parse', 'HEAD']).trim(), source, 'Source commit changed during packaging');
assert.equal(git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim(), changed, 'Package inputs changed during packaging');
const sha256 = Object.fromEntries([...files].map(([path, content]) => [path, hash(content)]));
await writeFile(join(packageRoot, 'provenance.json'), JSON.stringify({
  format: 'chronolog-peer-session-package/v2',
  repository: 'werg/chronolog-db',
  source,
  sourceTree,
  dirty,
  profile: 'chronolog-crdt-v2',
  zeroNativeBuild: true,
  inputs,
  runtimeInputs,
  runtimeModules,
  nativeRtc,
  sqliteCas: sqliteManifest,
  sha256,
}, null, 2) + '\n');

const packed = JSON.parse(execNpmSync(['pack', '--ignore-scripts', '--json', '--pack-destination', output], {
  cwd: packageRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}))[0];
const artifact = join(output, `chronolog-peer-session-${suffix}.tgz`);
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
    const rewritten = content.replace(/(['"])(@chronolog\/[^'"]+)\1/gu, (_match, quote, name) => {
      const sourcePath = parsed.options.paths?.[name]?.[0];
      assert(sourcePath, `Missing declaration alias: ${name}`);
      const destination = join(out, sourcePath.replace(/\.ts$/u, '.js'));
      let local = relative(dirname(path), destination).replaceAll('\\', '/');
      if (!local.startsWith('.')) local = `./${local}`;
      return `${quote}${local}${quote}`;
    });
    const imports = ts.preProcessFile(rewritten, true).importedFiles.map(value => value.fileName);
    assert(imports.every(name => name.startsWith('.') || name === 'werift' || name === 'quickjs-emscripten-core'),
      `Declarations must be self-contained: ${relative(root, path)} -> ${imports}`);
    files.set(relative(packageRoot, path).replaceAll('\\', '/'), rewritten);
  });
  if (result.emitSkipped || result.diagnostics.length) {
    throw new Error(ts.formatDiagnosticsWithColorAndContext(result.diagnostics, {
      getCurrentDirectory: () => root, getCanonicalFileName: name => name, getNewLine: () => '\n',
    }) || 'Peer session declaration emit failed');
  }
  return { files, inputs: [...inputs] };
}
function git(args) { return execFileSync('git', args, { cwd: root, encoding: 'utf8' }); }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

import { sqlProfileSuffix } from './lib/session-profile.mjs';
import { execNpmSync } from './lib/npm-cli.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { createRequire } from 'node:module';
import process from 'node:process';
import { parseArgs } from 'node:util';

import { build } from 'esbuild';
import ts from 'typescript';

const root = resolve(import.meta.dirname, '..');
const { values } = parseArgs({ options: { output: { type: 'string', default: 'artifacts/peer-session' },
  'allow-dirty': { type: 'boolean', default: false },
  'no-native-rtc': { type: 'boolean', default: false },
  'sql-native': { type: 'boolean', default: false }, 'sql-browser': { type: 'boolean', default: false },
  'sql-celld': { type: 'boolean', default: false }, 'sql-wasm': { type: 'boolean', default: false }, 'wasm-dir': { type: 'string' } } });
const output = resolve(values.output), packageRoot = join(output, 'package');
const nativeRtc = !values['no-native-rtc'];
const sqlEnabled = values['sql-native'] || values['sql-browser'] || values['sql-wasm'] || values['sql-celld'];
const source = git(['rev-parse', 'HEAD']).trim(), sourceTree = git(['rev-parse', 'HEAD^{tree}']).trim();
const engineImport = '#chronolog-peer-native-engine';
const entries = Object.fromEntries(['index', 'native', 'celld', 'browser', 'worker', 'webrtc', 'websocket', 'tendriller',
  ...(nativeRtc ? ['webrtc-native'] : []),
  ...(sqlEnabled ? ['sql'] : []), ...(values['sql-native'] ? ['sql-native'] : []),
  ...(values['sql-browser'] ? ['sql-browser'] : []), ...(values['sql-wasm'] ? ['sql-wasm'] : []),
  ...(values['sql-celld'] ? ['sql-celld', 'workspace-celld'] : [])]
  .map(name => [name, join(root, 'packages/peer-session/src', `${name}.ts`)]));
const bundled = await build({ entryPoints: entries, outdir: packageRoot, write: false, bundle: true,
  // Shared chunks preserve class identity and session ownership across all entrypoints.
  splitting: true, platform: 'neutral', conditions: ['import', 'default'], mainFields: ['module', 'main'],
  format: 'esm', target: 'es2022', metafile: true, absWorkingDir: root, external: ['node:*', 'werift', 'fs-native-extensions'],
  plugins: values['sql-native'] ? [{ name: 'pinned-native-engine', setup(plugin) {
    plugin.onResolve({ filter: /^@dolthub\/doltlite$/ }, () => ({ path: engineImport, external: true }));
  } }] : [],
  outExtension: { '.js': '.mjs' }, chunkNames: 'chunks/[name]-[hash]' });
const runtimeInputs = Object.keys(bundled.metafile.inputs).sort();
assert(runtimeInputs.every(path => sqlEnabled || !path.includes('materializer-doltlite/')),
  'The default session artifact must not contain SQL engine code');
assert(Object.values(bundled.metafile.outputs).flatMap(value => value.imports).every(value => !value.external || value.path.startsWith('node:') ||
  value.path === 'werift' || values['sql-wasm'] && value.path === 'fs-native-extensions' || values['sql-native'] && value.path === engineImport),
  'The session artifact may import only its declared native runtime dependencies');
// The common SQL path and browser adapter must stay independently browser-loadable,
// even when the same archive also contains the optional native engine.
for (const entry of ['index', 'celld', 'browser', 'worker', 'webrtc', 'websocket', 'tendriller', ...(sqlEnabled ? ['sql'] : []),
  ...(values['sql-browser'] ? ['sql-browser'] : []), ...(values['sql-celld'] ? ['sql-celld', 'workspace-celld'] : [])]) {
  const output = Object.entries(bundled.metafile.outputs).find(([, value]) => value.entryPoint === relative(root, entries[entry]).replaceAll('\\', '/'));
  assert(output, `Missing bundled entry: ${entry}`);
  const visited = new Set();
  const inspect = (path) => {
    if (visited.has(path)) return;
    visited.add(path);
    const metadata = bundled.metafile.outputs[path];
    assert(metadata, `Missing bundled dependency: ${path}`);
    for (const dependency of metadata.imports) {
      assert(!dependency.external || !dependency.path.startsWith('node:') && dependency.path !== engineImport && dependency.path !== 'werift',
        `Worker-compatible entry ${entry} imports a Node runtime: ${dependency.path}`);
      if (!dependency.external) inspect(dependency.path);
    }
  };
  inspect(output[0]);
}
// Actual emitted module closures are the boundary: shared chunks must not make
// passive protocol imports load database implementation or persistent data storage.
const outputName = path => relative(packageRoot, resolve(root, path)).replaceAll('\\', '/');
const runtimeModules = Object.fromEntries(Object.entries(bundled.metafile.outputs).map(([path, value]) => [outputName(path), {
  inputs: Object.entries(value.inputs).filter(([, input]) => input.bytesInOutput > 0).map(([source]) => source).sort(),
  imports: value.imports.map(input => ({ path: input.external ? input.path : outputName(input.path), kind: input.kind, external: input.external === true })),
}]));
const durableImplementation = path => /^(?:packages\/peer-session\/src\/(?:browser-storage-selector|browser-capabilities|session|operation-store|replica|content|keys|provisioning|network-content)\.ts|packages\/materializer\/src\/(?:runtime|events|event-store)\.ts|packages\/materializer-doltlite\/|packages\/records\/src\/(?:browser|native|celld|record-envelope|indexeddb-bytes-store)\.ts)/u.test(path);
for (const entry of ['index', 'browser', 'worker', 'tendriller', ...(sqlEnabled ? ['sql'] : [])]) {
  const output = Object.entries(bundled.metafile.outputs).find(([, value]) => value.entryPoint === relative(root, entries[entry]).replaceAll('\\', '/'));
  assert(output, `Missing protocol entry: ${entry}`);
  const visited = new Set();
  const inspect = path => {
    if (visited.has(path)) return;
    visited.add(path);
    const module = runtimeModules[path];
    assert(module, `Missing emitted module: ${path}`);
    for (const input of module.inputs) {
      assert(!durableImplementation(input), `Passive ${entry} entry loads durable implementation: ${input}`);
      if (entry === 'browser' || entry === 'tendriller') assert(!/^packages\/peer-session\/src\/(?:session|runtime|device|browser-device|network|participation|control-participant|worker-application-server)\.ts$/u.test(input),
        `Page ${entry} entry loads participant ownership: ${input}`);
    }
    for (const dependency of module.imports) if (!dependency.external && dependency.kind !== 'dynamic-import') inspect(dependency.path);
  };
  inspect(outputName(output[0]));
}
const declaration = declarations(Object.values(entries));
const inputs = [...new Set([...runtimeInputs, ...declaration.inputs, 'package.json', 'pnpm-lock.yaml', 'tsconfig.base.json',
  'packages/peer-session/package.json', 'packages/peer-session/README.md', 'tools/package-peer-session.mjs', 'tools/lib/npm-cli.mjs', 'tools/lib/session-profile.mjs',
  ...(values['sql-native'] ? ['patches/@dolthub__doltlite@0.11.29.patch'] : [])])].sort();
const changed = git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim();
if (changed && !values['allow-dirty']) throw new Error('PEER_SESSION_PACKAGE_REQUIRES_CLEAN_INPUTS');
const dirty = Boolean(changed), suffix = `${source.slice(0, 8)}${dirty ? '-dirty' : ''}${nativeRtc ? '' : '-relay'}${sqlProfileSuffix({ native: values['sql-native'], browser: values['sql-browser'], wasmNode: values['sql-wasm'] })}${values['sql-celld'] ? '-celld' : ''}`, version = `0.0.0-g${suffix}`;
await rm(packageRoot, { force: true, recursive: true });
await mkdir(packageRoot, { recursive: true });
const files = new Map();
let nativeEngine;
const libc = values['sql-native'] && process.platform === 'linux' ? (process.report.getReport().header.glibcVersionRuntime ? 'glibc' : 'musl') : undefined;
if (values['sql-native']) {
  const require = createRequire(join(root, 'packages/materializer-doltlite/package.json'));
  const engineRoot = dirname(require.resolve('@dolthub/doltlite'));
  const engine = require('@dolthub/doltlite');
  assert.equal(typeof engine.chronologNativeManifest, 'function', 'Build the exact patched native engine before packaging SQL');
  for (const [from, to] of [['index.js', 'index.cjs'], ['index.d.ts', 'index.d.ts'], ['package.json', 'package.json'],
    ['build/Release/doltlite.node', 'build/Release/doltlite.node']]) files.set(`engine/${to}`, await readFile(join(engineRoot, from)));
  nativeEngine = { implementation: '@dolthub/doltlite@0.11.29', platform: process.platform, architecture: process.arch,
    node: process.version, ...(libc ? { libc } : {}), manifest: engine.chronologNativeManifest(),
    patchSha256: hash(await readFile(join(root, 'patches/@dolthub__doltlite@0.11.29.patch'))) };
}
let wasmEngine;
if (values['wasm-dir']) {
  assert(values['sql-wasm'] || values['sql-browser'], '--wasm-dir requires --sql-wasm or --sql-browser');
  const wasmDir = resolve(values['wasm-dir']);
  const manifestBytes = await readFile(join(wasmDir, 'manifest.json'));
  const wasmBytes = await readFile(join(wasmDir, 'sqlite3.wasm'));
  const loaderBytes = await readFile(join(wasmDir, 'sqlite3.mjs'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  assert.equal(hash(wasmBytes), manifest.wasmSha256, 'WASM binary digest mismatch against manifest.json');
  assert.equal(hash(loaderBytes), manifest.loaderSha256, 'WASM loader digest mismatch against manifest.json');
  assert.equal(wasmBytes.byteLength, manifest.wasmBytes, 'WASM binary size mismatch against manifest.json');
  files.set('wasm/manifest.json', manifestBytes);
  files.set('wasm/sqlite3.wasm', wasmBytes);
  files.set('wasm/sqlite3.mjs', loaderBytes);
  files.set('wasm/sqlite3-opfs-async-proxy.js', await readFile(join(wasmDir, 'sqlite3-opfs-async-proxy.js')));
  wasmEngine = { toolchain: manifest.toolchain, wasmSha256: manifest.wasmSha256, loaderSha256: manifest.loaderSha256, wasmBytes: wasmBytes.byteLength };
}
for (const file of bundled.outputFiles) files.set(relative(packageRoot, file.path).replaceAll('\\', '/'), file.contents);
for (const [path, content] of declaration.files) files.set(path, content);
for (const name of Object.keys(entries)) files.set(`${name}.d.ts`, `export * from './types/packages/peer-session/src/${name}.js';\n`);
files.set('README.md', await readFile(join(root, 'packages/peer-session/README.md')));
files.set('package.json', JSON.stringify({ name: '@chronolog/peer-session', version, type: 'module',
  description: 'Signed authored operation-set CRDT sessions with reactive local materialization and optional finality',
  exports: Object.fromEntries(Object.keys(entries).map(name => [name === 'index' ? '.' : `./${name}`, { types: `./${name}.d.ts`, import: `./${name}.mjs` }])),
  files: ['*.mjs', '*.d.ts', 'chunks', 'types', 'README.md', 'provenance.json',
    ...(values['sql-native'] ? ['engine'] : []), ...(wasmEngine ? ['wasm'] : [])],
  dependencies: { 'better-sqlite3': '13.2.0', ...(nativeRtc ? { werift: '0.27.0' } : {}), ...(values['sql-wasm'] ? { 'fs-native-extensions': '1.5.4' } : {}) }, engines: { node: '>=22.15' },
  ...(values['sql-native'] ? { imports: { [engineImport]: './engine/index.cjs' }, os: [process.platform], cpu: [process.arch], ...(libc ? { libc: [libc] } : {}) } : {}),
}, null, 2) + '\n');
for (const [path, content] of files) { await mkdir(dirname(join(packageRoot, path)), { recursive: true }); await writeFile(join(packageRoot, path), content); }
assert.equal(git(['rev-parse', 'HEAD']).trim(), source, 'Source commit changed during packaging');
assert.equal(git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim(), changed, 'Package inputs changed during packaging');
const sha256 = Object.fromEntries([...files].map(([path, content]) => [path, hash(content)]));
await writeFile(join(packageRoot, 'provenance.json'), JSON.stringify({ format: 'chronolog-peer-session-package/v1',
  repository: 'werg/chronolog-db', source, sourceTree, dirty, profile: 'chronolog-crdt-v1',
  inputs, runtimeInputs, runtimeModules, nativeRtc, sqlEngines: [
    ...(values['sql-native'] ? ['native'] : []), ...(values['sql-browser'] ? ['browser'] : []),
    ...(values['sql-wasm'] ? ['wasm-node'] : []), ...(values['sql-celld'] ? ['celld'] : [])], nativeEngine, wasmEngine, sha256 }, null, 2) + '\n');
const packed = JSON.parse(execNpmSync(['pack', '--ignore-scripts', '--json', '--pack-destination', output], {
  cwd: packageRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}))[0];
const artifact = join(output, `chronolog-peer-session-${suffix}.tgz`);
await rename(join(output, packed.filename), artifact);
process.stdout.write(JSON.stringify({ artifact, version, source, sourceTree, dirty, sha256: hash(await readFile(artifact)) }) + '\n');

function declarations(entryPoints) {
  const ambientInputs = values['sql-wasm'] ? ['packages/materializer-doltlite/src/fs-native-extensions.d.ts'] : [];
  const configuration = ts.readConfigFile(join(root, 'tsconfig.base.json'), ts.sys.readFile);
  if (configuration.error) throw new Error(ts.flattenDiagnosticMessageText(configuration.error.messageText, '\n'));
  const parsed = ts.parseJsonConfigFileContent(configuration.config, ts.sys, root);
  const out = join(packageRoot, 'types');
  const options = { ...parsed.options, rootDir: root, outDir: out, types: ['node'], noEmit: false,
    declaration: true, declarationMap: false, sourceMap: false, emitDeclarationOnly: true, noEmitOnError: true };
  const compiler = ts.createProgram([...entryPoints, ...ambientInputs.map(path => join(root, path))], options);
  const diagnostics = [...parsed.errors, ...ts.getPreEmitDiagnostics(compiler)];
  if (diagnostics.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCurrentDirectory: () => root, getCanonicalFileName: name => name, getNewLine: () => '\n',
  }));
  const files = new Map(), inputs = new Set(ambientInputs);
  const result = compiler.emit(undefined, (path, content, _bom, _error, sourceFiles) => {
    if (!path.endsWith('.d.ts')) return;
    for (const file of sourceFiles ?? []) inputs.add(relative(root, file.fileName).replaceAll('\\', '/'));
    const rewritten = content.replace(/(['"])(@chronolog\/[^'"]+|@dolthub\/doltlite)\1/gu, (_match, quote, name) => {
      const sourcePath = parsed.options.paths?.[name]?.[0];
      assert(sourcePath || values['sql-native'] && name === '@dolthub/doltlite', `Missing declaration alias: ${name}`);
      const destination = sourcePath ? join(out, sourcePath.replace(/\.ts$/u, '.js')) : join(packageRoot, 'engine/index.js');
      let local = relative(dirname(path), destination).replaceAll('\\', '/');
      if (!local.startsWith('.')) local = `./${local}`;
      return `${quote}${local}${quote}`;
    });
    const imports = ts.preProcessFile(rewritten, true).importedFiles.map(value => value.fileName);
    assert(imports.every(name => name.startsWith('.') || name === 'werift'), `Declarations must be self-contained: ${relative(root, path)} -> ${imports}`);
    files.set(relative(packageRoot, path).replaceAll('\\', '/'), rewritten);
  });
  assert(!result.emitSkipped, 'Peer session declaration emit failed');
  return { files, inputs: [...inputs] };
}
function git(args) { return execFileSync('git', args, { cwd: root, encoding: 'utf8' }); }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

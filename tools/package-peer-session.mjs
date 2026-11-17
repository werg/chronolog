import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { createRequire } from 'node:module';
import process from 'node:process';
import { parseArgs } from 'node:util';

import { build } from 'esbuild';
import ts from 'typescript';

const root = resolve(import.meta.dirname, '..');
const { values } = parseArgs({ options: { output: { type: 'string', default: 'artifacts/peer-session' },
  'allow-dirty': { type: 'boolean', default: false }, 'native-rtc': { type: 'boolean', default: false },
  'sql-native': { type: 'boolean', default: false }, 'sql-browser': { type: 'string' } } });
const output = resolve(values.output), packageRoot = join(output, 'package');
const source = git(['rev-parse', 'HEAD']).trim(), sourceTree = git(['rev-parse', 'HEAD^{tree}']).trim();
const guides = (await readdir(join(root, 'packages/peer-session'))).filter(name => name.endsWith('.md')).sort();
const engineImport = '#chronolog-peer-native-engine';
const entries = Object.fromEntries(['index', 'native', 'browser', 'webrtc', 'tendriller', 'releases', ...(values['native-rtc'] ? ['webrtc-native'] : []),
  ...(values['sql-native'] ? ['sql-native'] : []), ...(values['sql-browser'] ? ['sql-browser'] : [])]
  .map(name => [name, join(root, 'packages/peer-session/src', `${name}.ts`)]));
const bundled = await build({ entryPoints: entries, outdir: packageRoot, write: false, bundle: true,
  // Shared chunks preserve class identity and session ownership across all entrypoints.
  splitting: true, platform: 'neutral', conditions: ['import', 'default'], mainFields: ['module', 'main'],
  format: 'esm', target: 'es2022', metafile: true, absWorkingDir: root, external: ['node:*', ...(values['native-rtc'] ? ['werift'] : [])],
  plugins: values['sql-native'] ? [{ name: 'pinned-native-engine', setup(plugin) {
    plugin.onResolve({ filter: /^@dolthub\/doltlite$/ }, () => ({ path: engineImport, external: true }));
  } }] : [],
  outExtension: { '.js': '.mjs' }, chunkNames: 'chunks/[name]-[hash]' });
const runtimeInputs = Object.keys(bundled.metafile.inputs).sort();
assert(runtimeInputs.every(path => !/(?:transport-ssb|agent-service|control-store|runtime-browser|testkit)\//u.test(path) &&
  (values['sql-native'] || values['sql-browser'] || !path.includes('materializer-doltlite/'))),
  'The default session artifact must not contain SQL, legacy native services or fixtures');
assert(Object.values(bundled.metafile.outputs).flatMap(value => value.imports).every(value => !value.external || value.path.startsWith('node:') ||
  values['native-rtc'] && value.path === 'werift' || values['sql-native'] && value.path === engineImport),
  'The session artifact must not fetch external runtime dependencies');
const declaration = declarations(Object.values(entries));
const inputs = [...new Set([...runtimeInputs, ...declaration.inputs, 'package.json', 'pnpm-lock.yaml', 'tsconfig.base.json',
  'packages/peer-session/package.json', ...guides.map(name => `packages/peer-session/${name}`), 'tools/package-peer-session.mjs',
  ...(values['sql-native'] || values['sql-browser'] ? ['patches/@dolthub__doltlite@0.11.29.patch'] : []),
  ...(values['sql-browser'] ? ['tools/build-wasm-engine.mjs'] : [])])].sort();
const changed = git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim();
if (changed && !values['allow-dirty']) throw new Error('PEER_SESSION_PACKAGE_REQUIRES_CLEAN_INPUTS');
const dirty = Boolean(changed), suffix = `${source.slice(0, 8)}${dirty ? '-dirty' : ''}${values['native-rtc'] ? '-rtc' : ''}${values['sql-native'] ? '-sql' : ''}${values['sql-browser'] ? '-wasm' : ''}`, version = `0.0.0-g${suffix}`;
await rm(packageRoot, { force: true, recursive: true });
await mkdir(packageRoot, { recursive: true });
const files = new Map();
let nativeEngine, browserEngine;
if (values['sql-native']) {
  const require = createRequire(join(root, 'packages/materializer-doltlite/package.json'));
  const engineRoot = dirname(require.resolve('@dolthub/doltlite'));
  const engine = require('@dolthub/doltlite');
  assert.equal(typeof engine.chronologNativeManifest, 'function', 'Build the exact patched native engine before packaging SQL');
  for (const [from, to] of [['index.js', 'index.cjs'], ['index.d.ts', 'index.d.ts'], ['package.json', 'package.json'],
    ['build/Release/doltlite.node', 'build/Release/doltlite.node']]) files.set(`engine/${to}`, await readFile(join(engineRoot, from)));
  nativeEngine = { implementation: '@dolthub/doltlite@0.11.29', platform: process.platform, architecture: process.arch,
    node: process.version, manifest: engine.chronologNativeManifest(),
    patchSha256: hash(await readFile(join(root, 'patches/@dolthub__doltlite@0.11.29.patch'))) };
}
if (values['sql-browser']) {
  const directory = resolve(values['sql-browser']);
  for (const name of ['manifest.json', 'sqlite3.mjs', 'sqlite3.wasm', 'sqlite3-opfs-async-proxy.js']) {
    files.set(`browser-engine/${name}`, await readFile(join(directory, name)));
  }
  const manifest = JSON.parse(files.get('browser-engine/manifest.json').toString('utf8'));
  const wasm = files.get('browser-engine/sqlite3.wasm');
  assert.equal(manifest.format, 1);
  assert.equal(manifest.toolchain, 'emscripten-4.0.20');
  assert.equal(manifest.wasmBytes, wasm.length);
  assert.equal(manifest.wasmSha256, hash(wasm), 'Browser engine bytes must match their build manifest');
  assert.deepEqual(manifest.portabilityPatches, ['chunk-store-optional-sector-size-v1', 'chunk-store-optional-has-moved-v1', 'vfs-identity-forwarding-v1']);
  const require = createRequire(join(root, 'packages/materializer-doltlite/package.json'));
  const engine = require('@dolthub/doltlite'), engineRoot = dirname(require.resolve('@dolthub/doltlite'));
  assert.equal(typeof engine.chronologNativeManifest, 'function', 'Build the exact patched engine before packaging browser SQL');
  assert.deepEqual(manifest.nativeManifest, engine.chronologNativeManifest(), 'Native and browser engines must share the pinned source identity');
  const source = await readFile(join(engineRoot, 'src/addon.cpp'), 'utf8');
  const start = source.indexOf('// ── Deterministic engine inputs'), end = source.indexOf('extern "C" int doltliteInstallAutoExt(void);');
  assert(start >= 0 && end > start, 'Deterministic source anchors missing');
  assert.equal(manifest.deterministicSourceSha256, hash(source.slice(start, end)), 'Browser engine must use the same deterministic hooks');
  const probe = new engine.DatabaseSync(':memory:');
  try { assert.deepEqual(manifest.runtimeVersions, probe.prepare('SELECT dolt_version() AS doltlite, sqlite_version() AS sqlite, vec_version() AS vec').get()); }
  finally { probe.close(); }
  browserEngine = { directory: 'browser-engine', manifest };
}
for (const file of bundled.outputFiles) files.set(relative(packageRoot, file.path).replaceAll('\\', '/'), file.contents);
for (const [path, content] of declaration.files) files.set(path, content);
for (const name of Object.keys(entries)) files.set(`${name}.d.ts`, `export * from './types/packages/peer-session/src/${name}.js';\n`);
for (const name of guides) {
  const markdown = await readFile(join(root, 'packages/peer-session', name), 'utf8');
  files.set(name, markdown.replace(/\]\(([^\s)]+)\)/gu, (match, target) => {
    if (target.startsWith('#') || /^[a-z][a-z0-9+.-]*:/iu.test(target)) return match;
    const [path, ...anchor] = target.split('#');
    if (guides.includes(path)) return match;
    const repositoryPath = relative(root, resolve(root, 'packages/peer-session', path)).replaceAll('\\', '/');
    assert(!repositoryPath.startsWith('..'), `Guide link leaves the repository: ${target}`);
    return `](https://github.com/werg/chronolog-db/blob/${source}/${repositoryPath}${anchor.length ? `#${anchor.join('#')}` : ''})`;
  }));
}
files.set('package.json', JSON.stringify({ name: '@chronolog/peer-session', version, type: 'module',
  description: 'Authenticated movable-peer application sessions with explicit recovery and applied outcomes',
  exports: { ...Object.fromEntries(Object.keys(entries).map(name => [name === 'index' ? '.' : `./${name}`, { types: `./${name}.d.ts`, import: `./${name}.mjs` }])),
    ...(values['sql-browser'] ? { './browser-engine/*': './browser-engine/*' } : {}) },
  files: ['*.mjs', '*.d.ts', '*.md', 'chunks', 'types', 'provenance.json', ...(values['sql-native'] ? ['engine'] : []),
    ...(values['sql-browser'] ? ['browser-engine'] : [])], dependencies: {}, engines: { node: '>=22.15' },
  ...(values['sql-native'] ? { imports: { [engineImport]: './engine/index.cjs' }, os: [process.platform], cpu: [process.arch] } : {}),
  ...(values['native-rtc'] ? { peerDependencies: { werift: '0.27.0' }, peerDependenciesMeta: { werift: { optional: true } } } : {}),
}, null, 2) + '\n');
for (const [path, content] of files) { await mkdir(dirname(join(packageRoot, path)), { recursive: true }); await writeFile(join(packageRoot, path), content); }
assert.equal(git(['rev-parse', 'HEAD']).trim(), source, 'Source commit changed during packaging');
assert.equal(git(['status', '--porcelain', '--untracked-files=all', '--', ...inputs]).trim(), changed, 'Package inputs changed during packaging');
const sha256 = Object.fromEntries([...files].map(([path, content]) => [path, hash(content)]));
await writeFile(join(packageRoot, 'provenance.json'), JSON.stringify({ format: 'chronolog-peer-session-package/v1',
  repository: 'werg/chronolog-db', source, sourceTree, dirty, profile: 'peer-generation-v1',
  inputs, runtimeInputs, optionalNativeRtc: values['native-rtc'], nativeEngine, browserEngine, sha256 }, null, 2) + '\n');
const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', output], {
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
  const options = { ...parsed.options, rootDir: root, outDir: out, types: ['node'], noEmit: false,
    declaration: true, declarationMap: false, sourceMap: false, emitDeclarationOnly: true, noEmitOnError: true };
  const compiler = ts.createProgram(entryPoints, options);
  const diagnostics = [...parsed.errors, ...ts.getPreEmitDiagnostics(compiler)];
  if (diagnostics.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCurrentDirectory: () => root, getCanonicalFileName: name => name, getNewLine: () => '\n',
  }));
  const files = new Map(), inputs = new Set();
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
    assert(imports.every(name => name.startsWith('.') || values['native-rtc'] && name === 'werift'), `Declarations must be self-contained: ${relative(root, path)} -> ${imports}`);
    files.set(relative(packageRoot, path).replaceAll('\\', '/'), rewritten);
  });
  assert(!result.emitSkipped, 'Peer session declaration emit failed');
  return { files, inputs: [...inputs] };
}
function git(args) { return execFileSync('git', args, { cwd: root, encoding: 'utf8' }); }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

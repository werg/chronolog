import { execNpmSync } from './lib/npm-cli.mjs';
// Verify the Chronolog v2 zero-native-build archive as a normal npm consumer (including offline reopen + SQLite-CAS + native RTC).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { parseArgs } from 'node:util';
import { build } from 'esbuild';
import { URL } from 'node:url';
import process from 'node:process';
import console from 'node:console';
import { setTimeout, clearTimeout } from 'node:timers';

const { values } = parseArgs({ options: { artifact: { type: 'string' }, output: { type: 'string' } } });
assert(values.artifact && values.output, 'Supply --artifact and a new --output directory');
const artifact = resolve(values.artifact), output = resolve(values.output), consumer = join(output, 'consumer');
await mkdir(output, { recursive: true });
await mkdir(consumer, { recursive: true });
await writeFile(join(consumer, 'package.json'), JSON.stringify({
  name: 'chronolog-v2-package-consumer',
  private: true,
  type: 'module',
  dependencies: { '@chronolog/peer-session': `file:${artifact}` },
}));
// Zero native builds (--ignore-scripts): npm installs only pure JS/WASM deps!
execNpmSync(['install', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: consumer, timeout: 120_000, stdio: ['ignore', 'pipe', 'pipe'] });
const packageRoot = join(consumer, 'node_modules/@chronolog/peer-session');
const metadata = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
assert.equal(metadata.dependencies['better-sqlite3'], undefined, 'v2 package must have zero better-sqlite3 native dependency');
assert.equal(metadata.dependencies['quickjs-emscripten-core'], '0.32.0');
assert.equal(metadata.dependencies['@jitl/quickjs-ng-wasmfile-release-sync'], '0.32.0');
assert.ok(metadata.exports['./sqlite-cas.wasm']);
const proof = JSON.parse(await readFile(join(packageRoot, 'provenance.json'), 'utf8'));
assert.equal(proof.zeroNativeBuild, true);
const hash = value => createHash('sha256').update(value).digest('hex');
for (const [file, digest] of Object.entries(proof.sha256)) {
  assert.equal(hash(await readFile(join(packageRoot, file))), digest, file);
}

// Verify browser bundling of passive browser/worker/index entrypoints
const bundle = await build({
  absWorkingDir: consumer,
  entryPoints: ['browser', 'worker', 'webrtc', 'websocket', 'tendriller'].map(name => join(packageRoot, name + '.mjs')),
  outdir: join(output, 'browser'),
  platform: 'browser',
  bundle: true,
  format: 'esm',
  splitting: true,
  metafile: true,
  write: false,
  external: ['module'],
});
assert.ok(!Object.keys(bundle.metafile.inputs).some(path => /werift|transport-webrtc\/src\/native/u.test(path)));

// Verify clean consumer offline reopen with node:sqlite + SQLite-CAS + chronolog/rls!
const v2Probe = `
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { createChainGenesis, createApplicationSession } from '@chronolog/peer-session';
import { openNativeDevice } from '@chronolog/peer-session/native';

const dbPath = join(process.cwd(), 'offline.sqlite');
const dev = await openNativeDevice({ path: dbPath, create: true });
const reducer = \`
import { openDb } from 'chronolog:sqlite';
export default {
  reduce(state, tx) {
    const db = openDb(state);
    db.exec('CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, val TEXT)', [], { mode: 'admin' });
    db.exec('INSERT INTO items VALUES (?, ?)', [tx.payload.id, tx.payload.val], { mode: 'user' });
    return { ok: true, state: db.commit() };
  },
  query(state) {
    const db = openDb(state);
    return db.query('SELECT id, val FROM items ORDER BY id').rows;
  },
};
\`;
const created = await createChainGenesis({
  creator: { publicKey: dev.identity.publicKey, wrapKey: dev.wrapKey.publicKey, reader: true, writer: true, administrator: true },
  imports: { 'app/items': reducer },
  topics: { items: { module: 'app/items', initialState: null } },
});
const sess = await createApplicationSession({
  device: dev,
  genesis: created.genesisBytes,
  casNodes: created.casNodes,
  epochKeys: new Map([[0, created.epoch0Key]]),
});
await (await sess.submit({ updates: [{ topic: 'items', input: { id: 'a', val: 'packaged-v2' } }] })).materialized();
await sess.close();

// Offline reopen from disk (zero node-gyp, node:sqlite + sqlite-cas.wasm!)
const dev2 = await openNativeDevice({ path: dbPath });
const sess2 = await createApplicationSession({ device: dev2, chainId: created.chainId });
const rows = (await sess2.query('items')).value;
assert.deepEqual(rows, [['a', 'packaged-v2']]);
await sess2.close();
console.log(JSON.stringify({ passed: true, rows }));
`;
await writeFile(join(consumer, 'v2-probe.mjs'), v2Probe);

const runProbe = (file) => new Promise((resolveResult, reject) => {
  const child = spawn(process.execPath, [file], { cwd: consumer, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 30_000);
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.once('error', error => { clearTimeout(timer); reject(error); });
  child.once('close', (code, signal) => { clearTimeout(timer); resolveResult({ code, signal, timedOut, stdout, stderr }); });
});

const v2Result = await runProbe('v2-probe.mjs');
assert.equal(v2Result.timedOut, false, 'v2 offline probe timed out');
assert.equal(v2Result.code, 0, v2Result.stderr);
const v2Out = JSON.parse(v2Result.stdout.trim());
assert.equal(v2Out.passed, true);

let nativeRtcOut = null;
if (proof.nativeRtc) {
  await copyFile(new URL('./lib/native-rtc-package-probe.mjs', import.meta.url), join(consumer, 'probe.mjs'));
  const rtcResult = await runProbe('probe.mjs');
  assert.equal(rtcResult.timedOut, false, 'Native RTC child retained sockets/timers after cleanup');
  assert.equal(rtcResult.code, 0, rtcResult.stderr);
  nativeRtcOut = JSON.parse(rtcResult.stdout.trim());
  assert.equal(nativeRtcOut.passed, true);
}

const report = {
  format: 'chronolog-v2-peer-session-package-check/v1',
  passed: true,
  zeroNativeBuild: true,
  source: proof.source,
  dirty: proof.dirty,
  artifact: { path: artifact, sha256: hash(await readFile(artifact)) },
  v2OfflineSqliteCas: v2Out,
  nativeRtc: nativeRtcOut,
};
await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report));

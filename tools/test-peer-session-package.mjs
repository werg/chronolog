// Verify the default archive as a normal npm consumer, including real native RTC.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
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
await mkdir(output); await mkdir(consumer);
await writeFile(join(consumer, 'package.json'), JSON.stringify({ name: 'default-session-package-consumer', private: true, type: 'module', dependencies: { '@chronolog/peer-session': `file:${artifact}` } }));
// Only the archive is requested. npm must install its exact native dependency;
// there is no optional peer, global install or separately supplied Werift copy.
execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: consumer, timeout: 120_000, stdio: ['ignore', 'pipe', 'pipe'] });
const packageRoot = join(consumer, 'node_modules/@chronolog/peer-session');
const metadata = JSON.parse(await readFile(join(packageRoot, 'package.json')));
assert.deepEqual(metadata.dependencies, { werift: '0.27.0' });
assert.equal(metadata.peerDependencies, undefined); assert.equal(metadata.peerDependenciesMeta, undefined);
assert.ok(metadata.exports['./webrtc-native']); assert.equal(metadata.exports['./sql'], undefined);
const proof = JSON.parse(await readFile(join(packageRoot, 'provenance.json')));
assert.equal(proof.nativeRtc, true); assert.equal(proof.optionalNativeRtc, undefined); assert.deepEqual(proof.sqlEngines, []);
const hash = value => createHash('sha256').update(value).digest('hex');
for (const [file, digest] of Object.entries(proof.sha256)) {
  assert.equal(hash(await readFile(join(packageRoot, file))), digest, file);
}
const werift = JSON.parse(await readFile(join(consumer, 'node_modules/werift/package.json')));
assert.equal(werift.version, '0.27.0');
const bundle = await build({ absWorkingDir: consumer, entryPoints: ['index', 'browser', 'worker', 'webrtc', 'websocket', 'tendriller'].map(name => join(packageRoot, name+'.mjs')),
  outdir: join(output, 'browser'), platform: 'browser', bundle: true, format: 'esm', splitting: true, metafile: true, write: false });
assert.ok(!Object.keys(bundle.metafile.inputs).some(path => /werift|transport-webrtc\/src\/native/u.test(path)));
assert.ok(Object.values(bundle.metafile.outputs).flatMap(value => value.imports).every(value => !value.path.startsWith('node:') && value.path !== 'werift'));
await copyFile(new URL('./lib/native-rtc-package-probe.mjs', import.meta.url), join(consumer, 'probe.mjs'));
const result = await new Promise((resolveResult, reject) => {
  const child = spawn(process.execPath, ['probe.mjs'], { cwd: consumer, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 20_000);
  child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  child.once('error', error => { clearTimeout(timer); reject(error); });
  child.once('close', (code, signal) => { clearTimeout(timer); resolveResult({ code, signal, timedOut, stdout, stderr }); });
});
await writeFile(join(output, 'native-process.json'), JSON.stringify(result, null, 2)+'\n');
assert.equal(result.timedOut, false, 'Native RTC child retained sockets/timers after cleanup');
assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null);
const native = JSON.parse(result.stdout.trim()); assert.equal(native.passed, true);
const report = { format: 'default-peer-session-package-check/v1', passed: true, source: proof.source, dirty: proof.dirty,
 artifact: { path: artifact, sha256: hash(await readFile(artifact)) }, nativeDependency: 'werift@0.27.0',
 browserModules: Object.keys(bundle.metafile.inputs).length, browserNativeImports: false, native, naturalExit: true };
await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2)+'\n');
console.log(JSON.stringify(report));

import { checkedPackagePath } from './lib/package-path.mjs';
import { execNpmSync } from './lib/npm-cli.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const { values } = parseArgs({ options: { artifact: { type: 'string' }, output: { type: 'string', default: 'artifacts/peer-session-wasm-check' } } });
if (!values.artifact) throw new Error('Supply --artifact with a packed --no-native-rtc --sql-wasm --wasm-dir session archive');
const artifact = resolve(values.artifact), output = resolve(values.output);
await mkdir(output, { recursive: true });
const consumer = await mkdtemp(join(output, 'consumer-'));
await writeFile(join(consumer, 'package.json'), JSON.stringify({ name: 'independent-peer-sql-consumer', private: true, type: 'module' }));
execNpmSync(['install', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', join(consumer, 'cache'), artifact], {
  cwd: consumer, stdio: ['ignore', 'pipe', 'pipe'],
});
const packageRoot = join(consumer, 'node_modules/@chronolog/peer-session');
const provenance = JSON.parse(await readFile(join(packageRoot, 'provenance.json'), 'utf8'));
assert(!provenance.nativeEngine, 'Portable archive must not contain the native addon');
assert(provenance.sqlEngines.includes('wasm-node'), 'Artifact must expose Node WASM SQL');
assert(provenance.wasmEngine, 'Artifact must carry verified WASM assets');
assert(provenance.inputs.includes('packages/materializer-doltlite/src/fs-native-extensions.d.ts'),
  'WASM declaration inputs must include the native file-locking declaration');
for (const [name, expected] of Object.entries(provenance.sha256)) {
  const path = checkedPackagePath(packageRoot, name);
  assert.equal(hash(await readFile(path)), expected, `Artifact hash mismatch for ${name}`);
}
await cp(join(dirname(fileURLToPath(import.meta.url)), 'fixtures/peer-session-sql-consumer.mjs'), join(consumer, 'consumer.mjs'));
const data = join(consumer, 'data'); await mkdir(data);
const stdout = execFileSync(process.execPath, ['consumer.mjs', data, join(packageRoot, 'wasm')], { cwd: consumer, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 90_000 });
const result = JSON.parse(stdout.trim().split('\n').at(-1));
assert.equal(result.status, 'passed');
const report = { format: 'chronolog-peer-session-wasm-check/v1', artifact, artifactSha256: hash(await readFile(artifact)),
  source: provenance.source, sourceTree: provenance.sourceTree, dirty: provenance.dirty, node: process.version, wasmEngine: provenance.wasmEngine, platform: process.platform, architecture: process.arch, result };
await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
process.stdout.write(JSON.stringify(report) + '\n');
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

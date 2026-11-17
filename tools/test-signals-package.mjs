import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { build } from 'esbuild';

const root = resolve(import.meta.dirname, '..');
const { values } = parseArgs({ options: { artifact: { type: 'string' }, 'allow-dirty': { type: 'boolean', default: false } } });
const commit = execFileSync('git', ['rev-parse', '--short=8', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
const artifact = resolve(values.artifact ?? join(root, 'artifacts/signals', `chronolog-signals-${commit}.tgz`));
const directory = await mkdtemp(join(tmpdir(), 'chronolog-signals-consumer-'));
const report = { format: 'chronolog-signals-consumer/v1', passed: false, artifact, artifactSha256: '', checks: [], source: null, error: '' };
try {
  report.artifactSha256 = hash(await readFile(artifact));
  await writeFile(join(directory, 'package.json'), JSON.stringify({ name: 'isolated-signals-consumer', private: true, type: 'module' }));
  // Offline installation with a fresh cache proves the tarball has no fetched
  // runtime dependencies. Lifecycle scripts and workspace links cannot help it.
  execFileSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', artifact], {
    cwd: directory, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, npm_config_cache: join(directory, 'npm-cache') },
  });
  const installed = join(directory, 'node_modules/@chronolog/signals');
  const metadata = JSON.parse(await readFile(join(installed, 'package.json'), 'utf8'));
  assert.equal(metadata.name, '@chronolog/signals');
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) assert.deepEqual(metadata[field] ?? {}, {});
  const tree = JSON.parse(execFileSync('npm', ['ls', '--all', '--json'], { cwd: directory, encoding: 'utf8' }));
  assert.deepEqual(Object.keys(tree.dependencies), ['@chronolog/signals']);
  assert.deepEqual(tree.dependencies['@chronolog/signals'].dependencies ?? {}, {});
  assert.deepEqual((await readdir(installed)).sort(), ['README.md', 'channel.d.ts', 'codec.d.ts', 'index.d.ts', 'index.mjs', 'package.json', 'provenance.json', 'types.d.ts']);
  const provenance = JSON.parse(await readFile(join(installed, 'provenance.json'), 'utf8'));
  assert.equal(provenance.format, 'chronolog-signals-package/v1');
  assert.match(provenance.source, /^[0-9a-f]{40}$/u);
  if (!values['allow-dirty']) assert.equal(provenance.dirty, false, 'Use a clean-source artifact for release qualification');
  for (const name of ['index.mjs', 'index.d.ts', 'channel.d.ts', 'codec.d.ts', 'types.d.ts', 'README.md', 'package.json']) {
    assert.equal(hash(await readFile(join(installed, name))), provenance.sha256[name], `Artifact hash mismatch: ${name}`);
  }
  report.source = { commit: provenance.source, dirty: provenance.dirty, version: metadata.version };
  report.checks.push('offline install contains one dependency-free package and every content hash matches its source provenance');

  const runtime = `import assert from 'node:assert/strict';
import { SignalChannel, generateSignalIdentity } from '@chronolog/signals';
const identity = await generateSignalIdentity();
const receiver = new SignalChannel({ scope: 'isolated-artifact', identity: await generateSignalIdentity(), authorize: () => true });
const sender = new SignalChannel({ scope: 'isolated-artifact', identity, authorize: () => true });
await assert.rejects(sender.send('typing', true), /signal_disconnected/);
const route = sender.attachRoute({ send: async frame => { await receivedRoute.receive(frame); } });
const receivedRoute = receiver.attachRoute({ send: async frame => { await route.receive(frame); } });
const iterator = receiver.subscribe({ topics: ['typing'] })[Symbol.asyncIterator]();
const next = iterator.next();
const first = await sender.send('typing', { active: true }, { ttlMs: 5000 });
const second = await sender.send('typing', { active: false }, { ttlMs: 5000 });
assert.deepEqual((await next).value, first);
assert.deepEqual((await iterator.next()).value, second);
assert.match(first.authorId, /^[0-9a-f]{64}$/);
assert.equal(first.scope, 'isolated-artifact');
assert.equal(first.expiresAtMs - first.issuedAtMs, 5000);
const idle = iterator.next();
assert.equal((await iterator.return()).done, true);
assert.equal((await idle).done, true);
route.close();
await assert.rejects(sender.send('typing', false), /signal_disconnected/);
sender.close(); receiver.close();
`;
  await writeFile(join(directory, 'consumer.mjs'), runtime);
  execFileSync(process.execPath, [join(directory, 'consumer.mjs')], { cwd: directory, stdio: 'inherit' });
  report.checks.push('ordinary Node ESM consumer verifies signed live delivery, FIFO, expiry metadata, idle cleanup and disconnected failure');

  await writeFile(join(directory, 'consumer.ts'), `import { SignalChannel, generateSignalIdentity,
  type Signals, type SignalPayload, type EphemeralSignal, type SignalSendOptions, type SignalSubscribeOptions } from '@chronolog/signals';
const signalChannel = new SignalChannel({ scope: 'typed-artifact', identity: await generateSignalIdentity(),
  authorize: ({ scope, authorId, topic }) => scope.length > 0 && authorId.length === 64 && topic.length > 0 });
const route = signalChannel.attachRoute({ send: async (frame, { signal }) => { signal.throwIfAborted(); void frame; } });
const channel: Signals = signalChannel;
const payload: SignalPayload = { values: [null, true, 2, 'preview'] };
const send: SignalSendOptions = { ttlMs: 1000 };
const delivered: EphemeralSignal = await channel.send('preview', payload, send);
const options: SignalSubscribeOptions = { topics: [delivered.topic], mode: 'latest', signal: new AbortController().signal };
const stream: AsyncIterable<EphemeralSignal> = channel.subscribe(options);
void stream;
route.close(); signalChannel.close();
// @ts-expect-error Signal payloads exclude executable values.
void channel.send('preview', () => 'not JSON');
// @ts-expect-error Only the declared FIFO/latest modes are supported.
void channel.subscribe({ mode: 'replay' });
`);
  await writeFile(join(directory, 'tsconfig.json'), JSON.stringify({ compilerOptions: { target: 'ES2023', lib: ['ES2023', 'DOM'],
    module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, exactOptionalPropertyTypes: true,
    noUncheckedIndexedAccess: true, skipLibCheck: false, types: [], noEmit: true }, files: ['consumer.ts'] }));
  execFileSync(process.execPath, [fileURLToPath(import.meta.resolve('typescript/bin/tsc')), '--project', join(directory, 'tsconfig.json')],
    { cwd: directory, stdio: 'inherit' });
  report.checks.push('strict TypeScript consumer checks public declarations without workspace aliases, ambient Node types or skipped library checking');
  const browser = await build({ stdin: { contents: "export { SignalChannel, generateSignalIdentity } from '@chronolog/signals';",
    resolveDir: directory }, bundle: true, platform: 'browser', format: 'esm', write: false, metafile: true });
  const browserInputs = Object.keys(browser.metafile.inputs);
  assert.equal(browserInputs.filter(path => path !== '<stdin>').length, 1);
  assert(browserInputs.some(path => path.endsWith('/node_modules/@chronolog/signals/index.mjs')));
  assert(Object.values(browser.metafile.outputs).every(value => value.imports.length === 0));
  report.checks.push('installed browser entry bundles from the single ESM artifact without database, protocol, SQL, membership or native dependencies');
  report.passed = true;
} catch (error) { report.error = error instanceof Error ? error.stack ?? error.message : String(error); throw error; }
finally {
  await writeFile(artifact.replace(/\.tgz$/u, '') + '.consumer.json', JSON.stringify(report, null, 2) + '\n');
  await rm(directory, { recursive: true, force: true });
}
process.stdout.write(JSON.stringify({ passed: true, artifact, checks: report.checks.length }) + '\n');
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

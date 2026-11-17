import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { basename, join, resolve, sep } from 'node:path'
import { selectDistributionArtifact, type DistributionIdentity } from './lib/distribution-artifact.js'

const directory = resolve(argument('--directory', 'artifacts/distribution'))
const requested = optional('--artifact')
const sourcePin = optional('--expected-source')
const checkout = await realpath(resolve(import.meta.dirname, '..'))
const expectedSourceCommit = requested === undefined
  ? execFileSync('git', ['rev-parse', 'HEAD'], { cwd: checkout, encoding: 'utf8' }).trim() : sourcePin
if (requested === undefined && sourcePin !== undefined && sourcePin !== expectedSourceCommit) {
  throw new Error('DISTRIBUTION_DEFAULT_REQUIRES_CURRENT_SOURCE: use --artifact to qualify a historical archive')
}
const selected = await selectDistributionArtifact({ directory, ...(requested === undefined ? {} : { artifact: requested }),
  ...(expectedSourceCommit === undefined ? {} : { expectedSourceCommit }), platform: process.platform, architecture: process.arch })
const { archive } = selected
const temporary = await mkdtemp(join(tmpdir(), 'chronolog-native-consumer-'))
const report = {
  format: 'chronolog-native-consumer-v1', passed: false, archive, archiveSha256: '',
  sourceCommit: selected.identity.sourceCommit, expectedSourceCommit: expectedSourceCommit ?? null,
  platform: selected.identity.platform, architecture: selected.identity.architecture, checks: [] as string[], error: '',
}
// Neither a caller's Node module search path nor a checkout tsconfig may supply
// dependencies to the relocated consumer.
const environment = { ...process.env }
delete environment.NODE_PATH
delete environment.NODE_OPTIONS
delete environment.TSX_TSCONFIG_PATH
try {
  const relocated = await realpath(temporary)
  assert(relocated !== checkout && !relocated.startsWith(`${checkout}${sep}`), 'Set TMPDIR outside the source checkout for relocation qualification')
  report.archiveSha256 = createHash('sha256').update(await readFile(archive)).digest('hex')
  const name = basename(archive, '.tar.gz')
  const entries = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' }).trim().split('\n')
  assert(entries.every(entry => (entry === name || entry.startsWith(`${name}/`)) && !entry.split('/').includes('..')),
    'Archive entries must stay inside the distribution directory')
  execFileSync('tar', ['-xzf', archive, '-C', temporary], { stdio: 'inherit' })
  const distribution = join(temporary, name)
  const manifest = JSON.parse(await readFile(join(distribution, 'release-manifest.json'), 'utf8')) as DistributionIdentity & {
    readonly files: readonly { readonly path: string }[]
  }
  assert.deepEqual({ sourceCommit: manifest.sourceCommit, platform: manifest.platform, architecture: manifest.architecture }, selected.identity,
    'Extracted archive identity changed after selection')
  report.checks.push('archive manifest identifies the required source, operating system and architecture')
  execFileSync(join(distribution, 'bin', 'chronolog-verify'), [], { cwd: temporary, env: environment, stdio: 'inherit' })
  report.checks.push('extracted archive passes its file hashes and internal-symlink verifier outside the checkout')

  const names = new Set<string>()
  for (const entry of manifest.files.filter(file => /\/node_modules\/(?:@[^/]+\/)?[^/]+\/package\.json$/u.test(file.path))) {
    const metadata = JSON.parse(await readFile(join(distribution, entry.path), 'utf8')) as { readonly name?: string }
    if (metadata.name !== undefined) names.add(metadata.name)
  }
  for (const name of ['chronologd', 'chronolog-cli', '@chronolog/agent-service', '@chronolog/client',
    '@chronolog/rpc', '@chronolog/signals', '@chronolog/materializer-doltlite', '@dolthub/doltlite']) {
    assert(names.has(name), `Missing production package: ${name}`)
  }
  for (const name of ['@tendriller/core', '@chronolog/transport-tendriller', '@chronolog/transport-webrtc', 'werift']) {
    assert(!names.has(name), `Unrequested hosted or RTC adapter in native distribution: ${name}`)
  }
  report.checks.push('native daemon, CLI, RPC, signals and SQL dependencies are present without hosted SDK or optional RTC adapters')

  execFileSync(join(distribution, 'bin', 'chronolog'), ['--help'], { cwd: temporary, env: environment, stdio: 'inherit', timeout: 30_000 })
  report.checks.push('packaged CLI launcher runs from outside the checkout')
  const runtime = join(distribution, 'runtime')
  const packagedRequire = createRequire(await realpath(join(runtime, 'package.json')))
  const loader = await realpath(packagedRequire.resolve('tsx'))
  assert(loader.startsWith(`${await realpath(distribution)}${sep}`), 'TypeScript runtime resolved outside the archive')
  const consumer = join(temporary, 'consumer.mjs')
  await writeFile(consumer, consumerSource())
  execFileSync(process.execPath, ['--import', loader, consumer, runtime], {
    cwd: temporary, env: environment, stdio: 'inherit', timeout: 30_000,
  })
  report.checks.push('packaged daemon runtime and client/RPC import, signed signals exchange, and native SQLite/DoltLite payloads persist across reopen')
  report.passed = true
} catch (error) {
  report.error = error instanceof Error ? error.stack ?? error.message : String(error)
  throw error
} finally {
  try { await writeFile(`${archive.replace(/\.tar\.gz$/u, '')}.consumer.json`, `${JSON.stringify(report, null, 2)}\n`) }
  finally { await rm(temporary, { recursive: true, force: true }) }
}
process.stdout.write(`${JSON.stringify({ passed: true, archive, sourceCommit: report.sourceCommit, checks: report.checks.length })}\n`)

function consumerSource(): string { return `import assert from 'node:assert/strict';
import { realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
const runtime = process.argv[2];
const distribution = await realpath(join(runtime, '..'));
async function withinArchive(path) {
  const resolved = await realpath(path);
  assert(resolved.startsWith(distribution + sep), 'Dependency resolved outside archive: ' + resolved);
  return resolved;
}
const daemonManifest = await withinArchive(join(runtime, 'node_modules/chronologd/package.json'));
const daemonRequire = createRequire(daemonManifest);
const agentEntry = await withinArchive(daemonRequire.resolve('@chronolog/agent-service'));
const { NativeAgentStore } = await import(pathToFileURL(agentEntry).href);
const daemon = await import(pathToFileURL(join(dirname(daemonManifest), 'src/agent-runtime.ts')).href);
assert.equal(typeof daemon.createDaemonAgentRuntime, 'function');
const cliRequire = createRequire(await withinArchive(join(runtime, 'node_modules/chronolog-cli/package.json')));
const { ChronologClient } = await import(pathToFileURL(await withinArchive(cliRequire.resolve('@chronolog/client'))).href);
const { HttpRpcTransport } = await import(pathToFileURL(await withinArchive(cliRequire.resolve('@chronolog/rpc'))).href);
const client = new ChronologClient({ groupId: '00'.repeat(32), transport: new HttpRpcTransport({ baseUrl: 'http://127.0.0.1:1' }) });
assert.equal(typeof client.signals.send, 'function');
assert.equal(typeof client.signals.subscribe, 'function');
await client.close();

const { SignalChannel, generateSignalIdentity } = await import(pathToFileURL(await withinArchive(createRequire(agentEntry).resolve('@chronolog/signals'))).href);
const sender = new SignalChannel({ scope: 'native-artifact', identity: await generateSignalIdentity(), authorize: () => true });
const receiver = new SignalChannel({ scope: 'native-artifact', identity: await generateSignalIdentity(), authorize: () => true });
const route = sender.attachRoute({ send: async frame => { await receiver.receive(frame); } });
const iterator = receiver.subscribe({ topics: ['preview'] })[Symbol.asyncIterator]();
try {
  const next = iterator.next();
  const sent = await sender.send('preview', { value: 'signed packaged signal' }, { ttlMs: 5000 });
  assert.deepEqual((await next).value, sent);
  assert.match(sent.authorId, /^[0-9a-f]{64}$/);
} finally { await iterator.return(); route.close(); sender.close(); receiver.close(); }

const bytes = Uint8Array.of(0, 1, 127, 255);
const operationPath = join(process.cwd(), 'operations.sqlite');
let store = new NativeAgentStore(operationPath);
await store.put('payload', bytes);
store.close();
store = new NativeAgentStore(operationPath);
try { assert.deepEqual(await store.get('payload'), bytes); } finally { store.close(); }

const materializerEntry = await withinArchive(daemonRequire.resolve('@chronolog/materializer-doltlite'));
const { readNativeEngineInfo } = await import(pathToFileURL(materializerEntry).href);
const engine = readNativeEngineInfo();
assert.equal(engine.digest.length, 32);
const materializerRequire = createRequire(materializerEntry);
const { DatabaseSync } = materializerRequire(await withinArchive(materializerRequire.resolve('@dolthub/doltlite')));
const sqlPath = join(process.cwd(), 'payload.db');
let database = new DatabaseSync(sqlPath);
try {
  database.exec('CREATE TABLE payloads (id INTEGER PRIMARY KEY, value BLOB NOT NULL)');
  database.prepare('INSERT INTO payloads VALUES (1, ?)').run(bytes);
} finally { database.close(); }
database = new DatabaseSync(sqlPath);
try { assert.deepEqual(Uint8Array.from(database.prepare('SELECT value FROM payloads WHERE id = 1').get().value), bytes); }
finally { database.close(); }
console.log(JSON.stringify({ nativeEngine: engine.descriptor, signals: 'verified', payloads: 'persisted' }));
` }

function optional(name: string): string | undefined {
  const index = process.argv.indexOf(name)
  if (index < 0) return undefined
  const value = process.argv[index + 1]
  if (value === undefined || value.startsWith('-')) throw new Error(`DISTRIBUTION_ARGUMENT_MISSING:${name}`)
  return value
}
function argument(name: string, fallback: string): string { return optional(name) ?? fallback }

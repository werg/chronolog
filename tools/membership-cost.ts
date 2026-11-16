import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises'
import { arch, platform, release } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

import { NativeAgentStore } from '@chronolog/agent-service'
import { encodeSignedGenesis, isCapabilityActive } from '@chronolog/capabilities'
import {
  MembershipAdministrator, createMembershipLedgerClient, encodeSignedEnrollmentApproval, loadOrCreateEnrollmentIdentity,
  prepareEnrollmentRequest, provisionMembership, verifyEnrollmentApproval, type DurableOperationStore,
} from '@chronolog/node-core/membership'
import { bytesToBase64Url, equalBytes } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'

import { createThinMembershipNative, type ThinMembershipTraffic } from './thin-membership-native.js'

class MeasuredStore implements DurableOperationStore {
  #store: NativeAgentStore
  #putCalls = 0
  #valueBytesWritten = 0
  readonly #categories = new Map<string, { calls: number; bytes: number }>()
  constructor(readonly path: string) { this.#store = new NativeAgentStore(path) }
  get(key: string): Promise<Uint8Array | null> { return this.#store.get(key) }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    await this.#store.put(key, bytes)
    this.#putCalls += 1; this.#valueBytesWritten += bytes.length
    // Only structural prefixes are reported; identity/operation keys and their
    // secret values stay inside the private local measurement directory.
    const prefix = key.startsWith('membership/') ? key.split('/').slice(0, 2).join('/') : key.split('/')[0]!
    const category = this.#categories.get(prefix) ?? { calls: 0, bytes: 0 }
    category.calls += 1; category.bytes += bytes.length; this.#categories.set(prefix, category)
  }
  snapshot() { return { putCalls: this.#putCalls, valueBytesWritten: this.#valueBytesWritten,
    retainedValueBytes: this.#store.usageBytes(), categories: Object.fromEntries([...this.#categories].map(([key, value]) => [key, { ...value }])) } }
  reopen(): void { this.#store.close(); this.#store = new NativeAgentStore(this.path) }
  close(): void { this.#store.close() }
}

// This is a measurement of real native storage and the signed HTTP membership
// boundary. It deliberately does not estimate Cloudflare billed usage.
const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const { values } = parseArgs({ options: { output: { type: 'string' } } })
if (values.output === undefined) throw new Error('Usage: tsx tools/membership-cost.ts --output /new/evidence-directory')
const output = resolve(values.output)
await mkdir(dirname(output), { recursive: true }); await mkdir(output)
const nativeDirectory = join(output, 'private-native-state')
const adminPath = join(output, 'private-administrator.sqlite'), devicePath = join(output, 'private-device.sqlite')
const measured = new MeasuredStore(adminPath)
let native: Awaited<ReturnType<typeof createThinMembershipNative>> | undefined
let administrator: MembershipAdministrator | undefined
let deviceStore: NativeAgentStore | undefined
const source = {
  head: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: workspace, encoding: 'utf8' }).trim(),
  dirtyPaths: execFileSync('git', ['status', '--porcelain'], { cwd: workspace, encoding: 'utf8' }).trim().split('\n').filter(Boolean),
  files: Object.fromEntries(await Promise.all(['tools/membership-cost.ts', 'tools/thin-membership-native.ts'].map(async path =>
    [path, createHash('sha256').update(await readFile(join(workspace, path))).digest('hex')] as const))),
}
const report = {
  format: 'chronolog-membership-cost/v1', passed: false, startedAt: new Date().toISOString(), finishedAt: '',
  command: process.argv.slice(1), source, environment: { node: process.version, platform: platform(), release: release(), arch: arch() },
  topology: { route: 'signed HTTP loopback', administratorStore: 'NativeAgentStore SQLite WAL FULL',
    nativeAuthority: 'separate identity and persistent stores, same process', applicationMaterializer: 'actual native DoltLite',
    provider: null, browser: null, relay: null },
  phases: [] as Array<Record<string, unknown>>, checks: [] as string[], final: {} as Record<string, unknown>, error: '',
  limits: [
    'Native loopback measurement, not deployed Cloudflare, Internet routing, browser storage, or a hosted/peer cost comparison.',
    'CPU and RSS cover the measurement process containing both native authority and administrator; they are not per-role billing.',
    'Store put counts and value bytes are logical durable writes, not provider SQL row billing, block writes, or write amplification.',
    'Live file sizes include SQLite WAL/SHM and materializer files; closed sizes are separate. Neither is time-integrated billed storage.',
    'No backup was taken and no blob was replicated. A committed descriptor does not establish any second durable payload copy.',
    'Inline control envelopes are a subset of inline control descriptor bytes. Traffic includes repeated transfers.',
  ],
}
const save = () => writeFile(join(output, 'report.json'), `${JSON.stringify(report, (_key, value: unknown) => typeof value === 'bigint' ? String(value) : value, 2)}\n`)

try {
  native = await createThinMembershipNative({ directory: nativeDirectory })
  const provision = () => provisionMembership({ store: measured, executionManifestDigest: native!.executionManifestDigest,
    schemaAdministratorPublicKey: native!.identity.signing.publicKeyBytes,
    nativeAuthority: { historyId: native!.historyId, publicKey: native!.identity.signing.publicKeyBytes },
    initialCapabilities: native!.initialCapabilities })
  let provisioned = await provision()
  const genesis = bytesToBase64Url(encodeSignedGenesis(provisioned.descriptor.genesis))
  await native.start({ genesis, groupRoute: bytesToBase64Url(provisioned.descriptor.groupRoute) })
  const open = () => MembershipAdministrator.open({ ...provisioned, store: measured,
    ledger: createMembershipLedgerClient({ url: native!.membershipUrl, ...provisioned }) })
  administrator = await open()
  await phase('baseline', async () => ({ finalThrough: (await native!.snapshot()).finalThrough }))
  // Prime schema creation so the size/count comparisons contain only the named
  // candidate workload and its required ordering/catch-up work.
  await phase('schema-and-prime', () => native!.publishWorkload({ namespace: 'prime', count: 1, payloadBytes: 0 }))
  const small = await phase('four-small', () => native!.publishWorkload({ namespace: 'small', count: 4, payloadBytes: 16 }))
  const large = await phase('four-large', () => native!.publishWorkload({ namespace: 'large', count: 4, payloadBytes: 196_608 }))
  const more = await phase('eight-small', () => native!.publishWorkload({ namespace: 'more', count: 8, payloadBytes: 16 }))
  assert.equal(small.count, large.count)
  assert(large.detachedEnvelopeBytes > small.detachedEnvelopeBytes * 100)
  assert(Math.abs(large.descriptorBytes - small.descriptorBytes) <= 16)
  assert.equal(more.count, small.count * 2)
  assert.equal(more.descriptorBytes, small.descriptorBytes * 2)
  report.checks.push('independent payload-size and candidate-count workloads used real accepted SQL/event candidates')
  await phase('warm-empty-sync', async () => ({ newCandidates: 0 }))

  deviceStore = new NativeAgentStore(devicePath)
  const device = await loadOrCreateEnrollmentIdentity(deviceStore, 'cost-device')
  const request = await prepareEnrollmentRequest({ descriptor: provisioned.descriptor, store: deviceStore,
    requestId: 'cost-device-enrollment', requestedRoles: ['reader', 'writer'],
    writerProgram: { sql: true, topics: ['qualification'], signals: [] }, identity: device.signing,
    readerPublicKey: device.reader.publicKeyBytes, transportAuthor: feedIdFromPublicKey(device.signing.publicKeyBytes) })
  const decision = { operationId: 'cost-approve-device', roles: ['reader', 'writer'] as const,
    grantFullHistory: true, writerProgram: { sql: true, topics: ['qualification'], signals: [] } }
  await phase('approval-lost-reply', async () => {
    native!.loseNextAppendReply()
    await assert.rejects(administrator!.approve(request, decision))
    return { responseLost: true }
  })
  const approval = await phase('administrator-reopen-and-exact-retry', async () => {
    const root = bytesToBase64Url(provisioned.identity.publicKeyBytes)
    await administrator!.close(); measured.reopen()
    provisioned = await provision()
    assert.equal(bytesToBase64Url(provisioned.identity.publicKeyBytes), root)
    assert.equal(bytesToBase64Url(encodeSignedGenesis(provisioned.descriptor.genesis)), genesis)
    administrator = await open()
    const result = await administrator.approve(request, decision)
    await verifyEnrollmentApproval(provisioned.descriptor, request, result)
    return result
  }, result => ({ signedApprovalSha256: createHash('sha256').update(encodeSignedEnrollmentApproval(result)).digest('hex') }))
  await phase('approval-exact-retry', async () => {
    const before = (await native!.snapshot()).head.position
    const retried = await administrator!.approve(request, decision)
    assert.deepEqual(encodeSignedEnrollmentApproval(retried), encodeSignedEnrollmentApproval(approval))
    await assert.rejects(administrator!.approve(request, { ...decision, roles: ['reader'] }))
    assert.equal((await native!.snapshot()).head.position, before)
    return { newOrderedEntries: 0, conflictingRequestRefused: true }
  })
  report.checks.push('lost append reply, administrator reopen and exact/conflicting approval retries preserve original identity and decision')
  const capabilities = [...administrator.snapshot.capabilities.values()].filter(capability =>
    equalBytes(capability.grant.signingPublicKey, device.signing.publicKeyBytes) && isCapabilityActive(capability, administrator!.snapshot.revision))
  assert.deepEqual(capabilities.map(capability => capability.grant.role).sort(), ['reader', 'writer'])
  for (const role of ['writer', 'reader']) {
    const capability = capabilities.find(value => value.grant.role === role)!
    await phase(`revoke-${role}-and-rotate`, async () => {
      const revoked = await administrator!.revoke({ operationId: `cost-revoke-${role}`, capabilityIds: [capability.id] })
      return { epoch: String(revoked.epoch) }
    })
  }
  await phase('future-epoch-payload', () => native!.publishWorkload({ namespace: 'future', count: 1, payloadBytes: 4096 }))
  report.checks.push('enrollment and writer/reader revocation with future epoch payload are included in per-phase costs')
  const final = await native.snapshot()
  assert.equal(final.traffic.applicationEnvelopeBytesToAdministrator, 0)
  assert.equal(final.traffic.unexpectedAdministratorRequests, 0)
  assert.equal(administrator.progress.verifiedThrough, final.head.position)
  assert.equal(final.schemaRoles.membershipRootGroupMembers, 0)
  report.checks.push('instrumented signed native endpoint returns no application envelopes and administrator attempts no body endpoint')
  report.final = { traffic: final.traffic, verifiedThrough: administrator.progress.verifiedThrough,
    nativeFinalThrough: final.finalThrough, administrator: measured.snapshot(),
    nativeLiveFiles: await directoryBytes(nativeDirectory),
    deviceValueBytes: deviceStore.usageBytes(), backup: { measured: false, latestDurableCopy: null, lag: null },
    providerUsage: { measured: false, activeDuration: null, billedRequests: null, billedRowsWritten: null, billedStorage: null, relayEgress: null } }
  native.assertHealthy()
  await administrator.close(); administrator = undefined; measured.close()
  deviceStore.close(); deviceStore = undefined
  await native.close(); native = undefined
  report.final.closedStorage = { administrator: await fileMetric(adminPath), device: await fileMetric(devicePath),
    native: await directoryBytes(nativeDirectory), nativeValues: sqliteValues(join(nativeDirectory, 'native.sqlite')) }
  report.passed = true
} catch (error) {
  report.error = error instanceof Error ? error.stack ?? error.message : String(error)
  throw error
} finally {
  try { await administrator?.close() } finally { measured.close(); deviceStore?.close(); await native?.close() }
  report.finishedAt = new Date().toISOString(); await save()
}
process.stdout.write(`Measured native membership costs: ${join(output, 'report.json')}\n`)

async function phase<T>(name: string, work: () => Promise<T>, summarize: (value: T) => unknown = value => value): Promise<T> {
  const startedAt = new Date().toISOString(), start = performance.now(), cpu = process.cpuUsage()
  const beforeTraffic = native!.traffic(), beforeStore = measured.snapshot()
  const beforeFiles = await directoryBytes(nativeDirectory)
  let peakRssBytes = process.memoryUsage().rss
  const sample = setInterval(() => { peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss) }, 10)
  try {
    const result = await work()
    await administrator!.sync()
    const current = await native!.snapshot()
    peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss)
    const resources = process.cpuUsage(cpu), afterStore = measured.snapshot(), afterFiles = await directoryBytes(nativeDirectory)
    report.phases.push({ name, startedAt, elapsedMs: performance.now() - start, result: summarize(result),
      resources: { processUserCpuMicroseconds: resources.user, processSystemCpuMicroseconds: resources.system,
        sampledProcessPeakRssBytes: peakRssBytes, rssSamplingIntervalMs: 10 },
      traffic: difference(current.traffic, beforeTraffic),
      administrator: { before: beforeStore, after: afterStore,
        durablePutCalls: afterStore.putCalls - beforeStore.putCalls,
        durableValueBytesWritten: afterStore.valueBytesWritten - beforeStore.valueBytesWritten,
        retainedValueBytesDelta: afterStore.retainedValueBytes - beforeStore.retainedValueBytes },
      nativeStorage: { before: beforeFiles, after: afterFiles, fileBytesDelta: afterFiles.bytes - beforeFiles.bytes },
      progress: { verifiedThrough: administrator!.progress.verifiedThrough, finalThrough: current.finalThrough, headPosition: current.head.position } })
    await save()
    process.stdout.write(`Measured ${name}\n`)
    return result
  } finally { clearInterval(sample) }
}

function difference(after: ThinMembershipTraffic, before: ThinMembershipTraffic): ThinMembershipTraffic {
  return Object.fromEntries(Object.entries(after).map(([key, value]) => [key, value - before[key as keyof ThinMembershipTraffic]])) as unknown as ThinMembershipTraffic
}
async function fileMetric(path: string) { const value = await stat(path); return { path: relative(output, path), bytes: value.size } }
async function directoryBytes(path: string): Promise<{ bytes: number; files: Array<{ path: string; bytes: number }> }> {
  const files: Array<{ path: string; bytes: number }> = []
  for (const entry of (await readdir(path, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const target = join(path, entry.name)
    if (entry.isDirectory()) files.push(...(await directoryBytes(target)).files)
    else if (entry.isFile()) files.push(await fileMetric(target))
    else throw new Error(`MEASUREMENT_UNSUPPORTED_FILE: ${relative(output, target)}`)
  }
  return { bytes: files.reduce((sum, file) => sum + file.bytes, 0), files }
}
function sqliteValues(path: string) {
  const database = new DatabaseSync(path, { readOnly: true })
  try {
    return database.prepare(`SELECT CASE
      WHEN key LIKE 'agent/authority/%/payload/%' OR key LIKE 'feed/payload/%' THEN 'detached-payload'
      WHEN key LIKE 'feed/%' THEN 'feed-and-evidence'
      WHEN key LIKE 'agent/authority/%' OR key LIKE 'record-log/%' THEN 'authority-and-deduplication'
      WHEN key LIKE 'transactions/%' THEN 'operation-journal'
      WHEN key LIKE 'history/%' THEN 'verified-history'
      ELSE 'other-native-state' END AS category,
      count(*) AS valuesCount, sum(length(value)) AS valueBytes
      FROM agent_values GROUP BY category ORDER BY category`).all()
  } finally { database.close() }
}

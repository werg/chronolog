import assert from 'node:assert/strict'
import { mkdir, readdir, stat, writeFile } from 'node:fs/promises'
import { arch, platform, release } from 'node:os'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'

import { createDoltLiteExecutionManifest, DeterministicMaterializer, type DatabaseLike, type MaterializerOptions, type ReplayProposal } from '@chronolog/materializer-doltlite'
import type { MaterializedReadHandle, PeerExecutionControls } from '@chronolog/materializer'
import { bytesToHex, encodeTransactionCore, program, sqlStatement, transactionDigest, type TransactionCore } from '@chronolog/protocol'

import { openDatabase } from '../packages/materializer-doltlite/src/driver.js'
import { fileSha256, git } from './lib/common.js'

// Component qualification at the materializer's existing diagnostic factory
// boundary. No native engine changes, GC, network or timing assertions.
const { values } = parseArgs({ options: { output: { type: 'string' }, captures: { type: 'string' } } })
const workspace = resolve(import.meta.dirname, '..')
const output = resolve(values.output ?? join(workspace, `artifacts/reader-resources-${Date.now()}`))
const captures = Number(values.captures ?? 128)
assert(Number.isSafeInteger(captures) && captures >= 1 && captures <= 1024, 'CAPTURES_OUT_OF_BOUNDS')
await mkdir(output, { recursive: false })
const data = join(output, 'database'); await mkdir(data)
const path = join(data, 'application.sqlite')
const root = new Uint8Array(32).fill(0xa0), group = new Uint8Array(32).fill(1), membership = new Uint8Array(32).fill(2)
const controls: PeerExecutionControls = { applicationId: group, currentRevision: 0,
  revisions: [{ revision: 0, digest: membership, members: [{ publicKey: root, role: 'admin' }] }] }
const manifest = createDoltLiteExecutionManifest({ profile: 'chronolog-peer-sql-v1' })
const counts = { databaseOpens: 0, databaseCloses: 0, branchCreates: 0, branchDeletes: 0, branchMoves: 0, checkouts: 0, resets: 0, commits: 0 }
const methods = { doltBranch: 'branchCreates', doltDeleteBranch: 'branchDeletes', doltForceBranch: 'branchMoves',
  doltCheckout: 'checkouts', doltResetHard: 'resets', doltCommit: 'commits' } as const
const connections: Array<{ role: 'writer' | 'reader'; closed: boolean; closeCalls: number }> = []
let nextIsWriter = true, writer: DatabaseLike, maximumActiveReaders = 0
const activeReaders = () => connections.filter(connection => connection.role === 'reader' && !connection.closed).length
const factory: NonNullable<MaterializerOptions['openDatabase']> = options => {
  counts.databaseOpens++
  const opened = openDatabase(options), connection = { role: nextIsWriter ? 'writer' as const : 'reader' as const, closed: false, closeCalls: 0 }
  if (nextIsWriter) writer = opened.database
  nextIsWriter = false; connections.push(connection)
  maximumActiveReaders = Math.max(maximumActiveReaders, activeReaders())
  return { ...opened, database: new Proxy(opened.database, {
    get(target, property) {
      const value = Reflect.get(target, property, target) as unknown
      if (typeof value !== 'function') return value
      return (...args: unknown[]) => {
        if (property in methods) counts[methods[property as keyof typeof methods]]++
        if (property === 'close') connection.closeCalls++
        const result = Reflect.apply(value, target, args) as unknown
        if (property === 'close') { connection.closed = true; counts.databaseCloses++ }
        return result
      }
    },
  }) }
}
const options: MaterializerOptions = { path, historyProfile: 'peer-generation-v1', executionManifest: manifest, rootAdministrator: root,
  bootstrapGroupId: group, bootstrapProgram: program('CREATE TABLE resource_items (id INTEGER PRIMARY KEY, payload TEXT NOT NULL) STRICT'),
  checkpointEvery: 8, retainCheckpoints: 8, openDatabase: factory }
let materializer = await DeterministicMaterializer.open(options)
await materializer.materialize([], controls)
const resourceState = () => ({ counters: { ...counts }, activeReaders: activeReaders(),
  activeConnections: connections.filter(connection => !connection.closed).length,
  readerBranches: writer.doltBranches().filter(branch => branch.name.startsWith('chronolog_read_')).length })
const delta = (before: typeof counts, after: typeof counts) => Object.fromEntries(Object.keys(before).map(key =>
  [key, after[key as keyof typeof counts] - before[key as keyof typeof counts]]))
const zeroChanges = Object.fromEntries(Object.keys(counts).map(key => [key, 0]))
const countRows = (view: MaterializedReadHandle) => {
  const result = view.query('SELECT count(*) AS count FROM resource_items').rows[0]?.[0]
  assert(result?.kind === 'integer'); return Number(result.value)
}
async function files(directory = data, prefix = ''): Promise<Array<{ path: string; bytes: number }>> {
  const result: Array<{ path: string; bytes: number }> = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const name = prefix + entry.name
    if (entry.isDirectory()) result.push(...await files(join(directory, entry.name), `${name}/`))
    else if (entry.isFile()) result.push({ path: name, bytes: (await stat(join(directory, entry.name))).size })
  }
  return result.sort((a, b) => a.path.localeCompare(b.path))
}
async function storage() {
  const observed = await files(), wal = observed.filter(file => /(?:^|[._-])wal(?:$|[._-])/iu.test(file.path))
  return { files: observed, totalBytes: observed.reduce((sum, file) => sum + file.bytes, 0),
    mainDatabaseBytes: observed.find(file => file.path === 'application.sqlite')?.bytes ?? null,
    separateWalBytes: wal.length === 0 ? null : wal.reduce((sum, file) => sum + file.bytes, 0),
    separateWalPaths: wal.map(file => file.path), physicalReadBytes: null, physicalWriteBytes: null }
}
async function observeReads(expectedRows: number, label: string) {
  const before = resourceState(), beforeStorage = await storage()
  for (let i = 0; i < captures; i++) {
    const view = materializer.captureRead({ view: 'local' })
    try { assert.equal(countRows(view), expectedRows) } finally { view.release() }
  }
  const existingLeases = Number(heldEight !== undefined) + Number(heldThirtyTwo !== undefined)
  const held = Array.from({ length: 16 - existingLeases }, () => materializer.captureRead({ view: 'local' }))
  assert.throws(() => materializer.captureRead({ view: 'local' }), /MATERIALIZER_SNAPSHOT_LIMIT/u)
  for (const view of held) { assert.equal(countRows(view), expectedRows); view.release() }
  const after = resourceState(), afterStorage = await storage(), changes = delta(before.counters, after.counters)
  assert.deepEqual(changes, zeroChanges)
  assert.deepEqual(afterStorage, beforeStorage)
  assert.equal(after.activeReaders, before.activeReaders); assert.equal(after.readerBranches, before.readerBranches)
  return { label, selectedCommands: expectedRows, sequentialCaptures: captures, simultaneousCaptures: 16, existingLeases, rejectedCapture: 17,
    before, after, changes, beforeStorage, afterStorage }
}
async function command(index: number): Promise<ReplayProposal> {
  const core: TransactionCore = { operationId: `resource-command-${index}`, groupId: group, membershipRevision: membership,
    validationPolicy: new Uint8Array(32).fill(3), authorId: root, authorTimestampMs: BigInt(index), nonce: new Uint8Array(32).fill(index),
    executionManifestDigest: materializer.executionManifestDigest,
    program: program(sqlStatement('INSERT INTO resource_items (id,payload) VALUES (?,?)', [index, 'x'.repeat(128)])) }
  const canonicalCandidate = encodeTransactionCore(core), candidateDigest = await transactionDigest(canonicalCandidate)
  return { txId: candidateDigest, candidateDigest, canonicalCandidate, core }
}
const report = {
  format: 'chronolog-native-reader-resources/v1', passed: false, startedAt: new Date().toISOString(), completedAt: '',
  source: { commit: git(workspace, ['rev-parse', 'HEAD']).trim(), tree: git(workspace, ['rev-parse', 'HEAD^{tree}']).trim(),
    dirty: git(workspace, ['status', '--porcelain', '--untracked-files=normal']).trim().length > 0,
    toolSha256: await fileSha256(join(workspace, 'tools/measure-materializer-readers.ts')),
    materializerSha256: await fileSha256(join(workspace, 'packages/materializer-doltlite/src/materializer.ts')) },
  environment: { node: process.version, platform: platform(), architecture: arch(), osRelease: release(),
    engine: materializer.backend.version, sqlite: materializer.backend.sqliteVersion, engineDigest: bytesToHex(materializer.backend.engineDigest),
    executionManifestDigest: bytesToHex(materializer.executionManifestDigest) },
  scope: 'Native peer-generation SQL materializer with synthetic canonical replay inputs at the verified-input boundary; no peer transport or complete application session qualification.',
  workload: { historySizes: [0, 8, 32], bytesPerRow: 128, checkpointEvery: 8, retainCheckpoints: 8, capturesPerHistory: captures },
  reads: [] as Array<Awaited<ReturnType<typeof observeReads>>>,
  heldViews: null as null | Record<string, unknown>, finalResources: null as null | Record<string, unknown>,
  limits: [
    'Counters cover native database opens/closes and Dolt branch/publication methods at the maintained diagnostic factory seam.',
    'File sizes describe physical files exposed in this disposable directory, not bytes read from disk or every possible in-place write.',
    'No separate WAL-labelled file means separateWalBytes is unknown (null); it does not establish the absence of an internal append log.',
    'Physical read/write bytes are unobserved (null). There is no filesystem tracing or native VFS instrumentation.',
    'No GC, WAL truncation or retention deletion is performed. This bounded workload establishes neither long-run growth nor deployed-volume behavior.',
  ], error: null as string | null,
}
const history: ReplayProposal[] = []
let heldEight: MaterializedReadHandle | undefined, heldThirtyTwo: MaterializedReadHandle | undefined
try {
  for (const horizon of [0, 8, 32]) {
    while (history.length < horizon) {
      history.push(await command(history.length + 1)); await materializer.materialize(history, controls)
      assert.equal(materializer.outcome(history.at(-1)!.txId)?.outcome, 'accepted')
    }
    report.reads.push(await observeReads(horizon, `history-${horizon}`))
    if (horizon === 8) heldEight = materializer.captureRead({ view: 'local' })
  }
  assert(heldEight !== undefined); assert.equal(countRows(heldEight), 8)
  heldThirtyTwo = materializer.captureRead({ view: 'local' })
  const beforeRecovery = resourceState()
  await materializer.materialize(history.slice(0, 4), controls)
  assert.equal(countRows(heldEight), 8); assert.equal(countRows(heldThirtyTwo), 32)
  const whileHeld = resourceState()
  report.reads.push(await observeReads(4, 'recovered-prefix-with-old-views'))
  heldEight.release(); heldEight = undefined; const afterFirstRelease = resourceState()
  heldThirtyTwo.release(); heldThirtyTwo = undefined; const afterLastRelease = resourceState()
  assert.equal(afterLastRelease.activeReaders, 2); assert.equal(afterLastRelease.readerBranches, 2)
  report.heldViews = { heldRowsAfterRecovery: [8, 32], currentRowsAfterRecovery: 4, beforeRecovery, whileHeld, afterFirstRelease, afterLastRelease }
  materializer.close()
  assert(connections.every(connection => connection.closed && connection.closeCalls === 1))
  nextIsWriter = true; materializer = await DeterministicMaterializer.open(options)
  report.reads.push(await observeReads(4, 'reopened-recovered-prefix'))
  materializer.close()
  assert(connections.every(connection => connection.closed && connection.closeCalls === 1))
  report.finalResources = { counters: counts, activeReaders: activeReaders(), maximumActiveReaders,
    activeConnections: connections.filter(connection => !connection.closed).length,
    allConnectionsClosedExactlyOnce: true, storageAfterClose: await storage() }
  report.passed = true
} catch (error) {
  report.error = error instanceof Error ? error.stack ?? error.message : String(error)
  throw error
} finally {
  heldEight?.release(); heldThirtyTwo?.release(); materializer.close()
  report.completedAt = new Date().toISOString()
  await writeFile(join(output, 'report.json'), `${JSON.stringify(report, null, 2)}\n`)
  process.stdout.write(`${JSON.stringify({ passed: report.passed, report: join(output, 'report.json'), maximumActiveReaders })}\n`)
}

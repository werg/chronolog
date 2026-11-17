import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { copyFile, cp, mkdir, mkdtemp, open, readdir, rm, stat, statfs, writeFile } from 'node:fs/promises'
import { arch, platform, release } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { parseArgs } from 'node:util'

import { NativeAgentStore } from '@chronolog/agent-service'
import { createDoltLiteExecutionManifest, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { SignedInclusionFinalityProvider, decodeLedgerRecord, decodeOrderingEvidence, isFinalityClosureRecord, ReferenceRecordLog,
  type CoordinatedHistoryConfiguration, type OrderedRecordHead } from '@chronolog/node-core'
import { base64UrlToBytes } from '@chronolog/protocol'

import { AUTHORITY_CRASH_POINTS, certifiedRecoveryFloor, inspectStoppedAuthority, recoveryJson, type RecoveryOperation } from './lib/authority-recovery-fixture.js'
import { fileSha256, git } from './lib/common.js'

interface RecoveryState {
  readonly head: OrderedRecordHead
  readonly receipts: readonly { readonly position: number; readonly root: string; readonly recordId: string; readonly kind: string }[]
  readonly proposalCount: number
  readonly closedThroughMs: string
  readonly authorityIdentity: string
  readonly executionManifestDigest: string
  readonly certificate: Readonly<Record<string, unknown>>
  readonly feed: { readonly identity: string; readonly records: readonly { readonly id: string; readonly sequence: string }[] }
  readonly operations: Readonly<Record<string, { readonly proposalId: string; readonly final: boolean;
    readonly outcome: { readonly outcome: string; readonly rejectionCode?: string } | null } | null>>
  readonly rows: readonly unknown[]
  readonly events: readonly unknown[]
  readonly payloads: readonly { readonly position: number; readonly recordId: string; readonly kind: string;
    readonly hash: string; readonly descriptorBytes: number; readonly payloadBytes: number | null; readonly detached: boolean }[]
}
interface ChildResult { readonly status: number | null; readonly signal: NodeJS.Signals | null; readonly stdout: string; readonly stderr: string }
interface HoldingAuthority {
  readonly state: RecoveryState
  readonly configuration: { readonly kind: 'coordinated'; readonly historyId: string; readonly authorityPublicKey: string;
    readonly groupId: string; readonly genesisDigest: string; readonly executionManifestDigest: string;
    readonly providerId?: string; readonly providerParameters?: string }
  readonly evidence: readonly string[]
}

const { values } = parseArgs({ options: { output: { type: 'string' }, 'volume-root': { type: 'string' } } })
const workspace = resolve(import.meta.dirname, '..')
const output = resolve(values.output ?? join(workspace, `artifacts/authority-recovery/run-${Date.now()}`))
const volumeRoot = resolve(values['volume-root'] ?? join(workspace, 'artifacts/authority-recovery-private'))
const insideOutput = relative(output, volumeRoot)
assert(isAbsolute(insideOutput) || insideOutput === '..' || insideOutput.startsWith(`..${sep}`), 'PRIVATE_VOLUMES_MUST_BE_OUTSIDE_REPORT_DIRECTORY')
await mkdir(dirname(output), { recursive: true })
await mkdir(output) // Evidence from distinct runs must never be merged.
await mkdir(volumeRoot, { recursive: true, mode: 0o700 })
const volumes = await mkdtemp(join(volumeRoot, 'run-'))
const transcript: { readonly command: readonly string[]; readonly elapsedMs: number; readonly result: ChildResult }[] = []
const checks: { readonly id: string; readonly details: unknown }[] = []
const report = { format: 'chronolog-authority-recovery/v1', passed: false, startedAt: new Date().toISOString(), completedAt: '',
  source: { commit: git(workspace, ['rev-parse', 'HEAD']).trim(), tree: git(workspace, ['rev-parse', 'HEAD^{tree}']).trim(),
    dirty: git(workspace, ['status', '--porcelain', '--untracked-files=normal']).trim().length > 0 },
  environment: { node: process.version, platform: platform(), arch: arch(), osRelease: release(),
    filesystemTypeHex: `0x${(await statfs(volumes)).type.toString(16)}`,
    storage: 'disposable directory on selected volume root; SQLite WAL, synchronous=FULL, exclusive connection fence', volumeRoot,
    process: 'actual Node child processes and SIGKILL; native governed SQL core with portable durable feed transport',
    clock: 'durable controlled author/finality clock; advances after inclusion so crash cases preserve their admission window',
    network: 'no network service; retained evidence exchanged between independent policy stores' },
  acknowledgementContract: { durableCopiesRequired: 1, automaticFailover: false, immediateDiskLossSurvival: false },
  checks, limits: [
    'These disposable fixture identities are synthetic. No deployed Cloudflare service, administrator root move or production volume is exercised.',
    'The exclusive SQLite fence protects the same database file. It does not fence independent disk copies or prove storage-provider attachment semantics.',
    'SIGKILL tests process death at observed durable-port boundaries, not power-loss behavior inside a storage controller.',
    'The controlled clock qualifies recovery outcomes, not wall-clock admission latency or availability under real network delay.',
    'The backup is a quiesced whole-directory copy. Application snapshot export alone is not an authority backup.',
    'Authority-task outage and retained-evidence relay use in-process portable peers; public-network outage and deployed service recovery remain separate.',
    'No independent second-durable-copy acknowledgement or automatic failover is promised.',
  ], failureContext: null as { readonly point: string; readonly operation: RecoveryOperation; readonly before: RecoveryState;
    readonly afterCrash: Awaited<ReturnType<typeof inspectStoppedAuthority>> } | null, error: '' }
const checked = (id: string, details: unknown) => { checks.push({ id, details }); process.stdout.write(`Passed: ${id}\n`) }
const child = (action: string, directory: string, operation = 'accepted', point = 'none', continuity?: string): ChildResult => {
  const args = ['--import', 'tsx', join(workspace, 'tools/lib/authority-recovery-child.ts'), action, directory, operation, point,
    ...(continuity === undefined ? [] : [continuity])]
  const started = Date.now()
  const result = spawnSync(process.execPath, args, { cwd: workspace, encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024 })
  const value = { status: result.status, signal: result.signal, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
  transcript.push({ command: [process.execPath, ...args], elapsedMs: Date.now() - started, result: value })
  if (result.error !== undefined) throw result.error
  return value
}
const completed = (result: ChildResult): ChildResult => {
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`)
  return result
}
const state = (result: ChildResult): RecoveryState => {
  completed(result)
  const line = result.stdout.trim().split('\n').findLast(value => value.startsWith('{"event":"state",'))
  assert(line !== undefined, 'RECOVERY_CHILD_STATE_MISSING')
  return (JSON.parse(line) as { state: RecoveryState }).state
}
try {
  for (const point of AUTHORITY_CRASH_POINTS) {
    for (const operation of ['accepted', 'rejected'] as const) {
      const directory = join(volumes, `${point}-${operation}`)
      const before = state(child('initialize', directory))
      const crashed = child('crash', directory, operation, point)
      assert(crashed.signal === 'SIGKILL' || crashed.status === 137, `${crashed.stdout}\n${crashed.stderr}`)
      assert(crashed.stdout.includes(`"point":"${point}"`))
      const raw = await inspectStoppedAuthority(directory)
      // Preserve the observed stopped disk if a later invariant fails; private
      // crash volumes are deliberately excluded from the public CI artifact.
      report.failureContext = { point, operation, before, afterCrash: raw }
      const committed = !['before_payload_commit', 'after_payload_commit', 'before_record_commit'].includes(point)
      assert.equal(raw.proposalCount, before.proposalCount + (committed ? 1 : 0))
      assert.deepEqual(raw.entries.slice(0, before.head.position).map(entry => entry.recordId), before.receipts.map(entry => entry.recordId))
      const target = raw.entries.filter(entry => entry.kind === 'candidate')[before.proposalCount]
      const closure = target === undefined ? undefined : raw.closures.find(item => item.includedHead.position >= target.position)
      assert.equal(closure !== undefined,
        ['after_closure_commit', 'before_certificate_commit', 'after_certificate_commit', 'before_acknowledgement'].includes(point))
      if (closure !== undefined) {
        const certified = raw.certificate?.kind === 'prefix-certificate' ? raw.certificate.certificate.position : -1
        assert.equal(certified >= closure.position, ['after_certificate_commit', 'before_acknowledgement'].includes(point))
      }
      let continuity = before.head
      if (point === 'after_certificate_commit' || point === 'before_acknowledgement') {
        assert(closure !== undefined)
        continuity = certifiedRecoveryFloor(raw, closure, point)
      }
      const floor = join(volumes, `${point}-${operation}-continuity.json`)
      await writeFile(floor, recoveryJson(continuity), { flag: 'wx' })
      const recovered = state(child('submit', directory, operation, 'none', floor))
      assertTerminal(recovered, operation)
      assert.equal(recovered.proposalCount, before.proposalCount + 1)
      assert.equal(recovered.payloads.length, before.payloads.length + 1)
      assert.deepEqual(recovered.receipts.slice(0, raw.head.position), raw.entries)
      const retried = state(child('submit', directory, operation, 'none', floor))
      assert.equal(retried.operations[operation]?.proposalId, recovered.operations[operation]?.proposalId)
      assertSameState(retried, recovered)
      assert.deepEqual(retried.rows, recovered.rows)
      assert.deepEqual(retried.events, recovered.events)
      assert(retried.payloads.every(payload => payload.payloadBytes !== null))
      checked(`crash/${point}/${operation}`, { before, afterCrash: raw, continuity, recovered,
        exactRetry: { head: retried.head, proposalCount: retried.proposalCount, closedThroughMs: retried.closedThroughMs } })
      report.failureContext = null
    }
  }

  const original = join(volumes, 'complete-volume')
  state(child('initialize', original))
  state(child('submit', original, 'accepted'))
  const final = state(child('submit', original, 'rejected'))
  const fencing = completed(child('fencing', original))
  assert(fencing.stdout.includes('AGENT_STORE_IN_USE'))
  checked('single-file-process-fence', { owner: 'NativeAgentStore', result: 'AGENT_STORE_IN_USE', sameFile: true,
    independentCopiesFenced: false })

  const floor = join(volumes, 'independent-latest-acknowledged-head.json')
  await writeFile(floor, recoveryJson(final.head), { flag: 'wx' })
  const restarted = state(child('inspect', original, 'accepted', 'none', floor))
  assertSameState(restarted, final)
  checked('ordinary-restart', { head: restarted.head, feedRecords: restarted.feed.records.length,
    operations: restarted.operations, rows: restarted.rows, events: restarted.events })

  const backup = join(volumes, 'consistent-backup'), restored = join(volumes, 'restored-volume')
  const backupManifest = await copyClosedVolume(original, backup)
  assert.deepEqual(await copyClosedVolume(backup, restored), backupManifest)
  // All child processes have exited; no old identity remains active during restore.
  await rm(original, { recursive: true })
  const recovered = state(child('inspect', restored, 'accepted', 'none', floor))
  assertSameState(recovered, final)
  assertSameState(state(child('submit', restored, 'accepted', 'none', floor)), final)
  assertSameState(state(child('submit', restored, 'rejected', 'none', floor)), final)
  checked('consistent-whole-volume-restore', { manifest: backupManifest, trustedContinuity: final.head,
    restoredHead: recovered.head, preserved: ['identity', 'configuration', 'certificates', 'deduplication', 'operation journal', 'feed history', 'SQL projection', 'effective events', 'detached bodies'] })

  // A separate SQL projection and two persistent public-evidence observers are
  // open while the real authority process runs. They receive no signing key.
  const projectionPath = join(volumes, 'independent-application.db')
  await copyFile(join(restored, 'application.db'), projectionPath)
  const held = await holdAuthority(restored)
  let one: NativeAgentStore | undefined, two: NativeAgentStore | undefined
  let projection: DeterministicMaterializer | undefined
  try {
    one = new NativeAgentStore(join(volumes, 'retained-observer-one.sqlite'))
    two = new NativeAgentStore(join(volumes, 'retained-observer-two.sqlite'))
    const publicConfiguration: CoordinatedHistoryConfiguration = { kind: 'coordinated', historyId: held.value.configuration.historyId,
      authorityPublicKey: base64UrlToBytes(held.value.configuration.authorityPublicKey), groupId: base64UrlToBytes(held.value.configuration.groupId),
      genesisDigest: base64UrlToBytes(held.value.configuration.genesisDigest), executionManifestDigest: base64UrlToBytes(held.value.configuration.executionManifestDigest),
      ...(held.value.configuration.providerId === undefined ? {} : { providerId: held.value.configuration.providerId }),
      ...(held.value.configuration.providerParameters === undefined ? {} : { providerParameters: base64UrlToBytes(held.value.configuration.providerParameters) }) }
    const first = await SignedInclusionFinalityProvider.open(publicConfiguration, one)
    const second = await SignedInclusionFinalityProvider.open(publicConfiguration, two)
    projection = await DeterministicMaterializer.open({ path: projectionPath, executionManifest: createDoltLiteExecutionManifest(),
      rootAdministrator: base64UrlToBytes(held.value.state.authorityIdentity) })
    for (const bytes of [...held.value.evidence].reverse()) await first.ingest(decodeOrderingEvidence(base64UrlToBytes(bytes)))
    assert.equal(first.progress.finalThrough, held.value.state.head.position)
    assert.deepEqual(projection.localSql('SELECT id, value FROM recovery_probe ORDER BY id', [], { view: 'final' }).rows, held.value.state.rows)
    const killed = await held.kill()
    assert.equal(killed.signal, 'SIGKILL')
    // The process has exited. Only the first peer's retained public evidence is used.
    for (const evidence of [...first.evidence()].reverse()) await second.ingest(evidence)
    assert.deepEqual(second.progress, first.progress)
    assert.deepEqual(second.snapshot(), first.snapshot())
    assert.equal(second.closedThroughMs, BigInt(held.value.state.closedThroughMs))
    const rows = projection.localSql('SELECT id, value FROM recovery_probe ORDER BY id', [], { view: 'final' }).rows
    assert.deepEqual(rows, held.value.state.rows)
    checked('authority-process-loss-with-independent-retained-readers', { termination: killed.signal, authorityProcessExited: true,
      previouslyAcknowledgedHead: held.value.state.head, independentlyOpenStores: 3, authorityPrivateKeysCopied: 0,
      finalSqlRowsAfterProcessExit: rows, relayedProgress: second.progress, closedThroughMs: second.closedThroughMs,
      evidenceBytes: held.value.evidence.reduce((sum, item) => sum + base64UrlToBytes(item).length, 0),
      applicationBodiesNeededForCertificateRelay: 0, publicNetworkClaim: false })
  } finally {
    await held.kill(); projection?.close(); two?.close(); one?.close()
  }

  const offline = completed(child('offline', restored))
  const offlineLine = offline.stdout.trim().split('\n').findLast(value => value.startsWith('{"event":"offline",'))
  assert(offlineLine !== undefined)
  const observation: unknown = JSON.parse(offlineLine)
  const resumed = state(child('inspect', restored))
  assert.equal(resumed.operations['authority-offline']?.final, true)
  assert.equal(resumed.operations['authority-offline']?.outcome?.outcome, 'accepted')
  checked('authority-task-outage-and-resume', { observation, resumedHead: resumed.head,
    resumedOperation: resumed.operations['authority-offline'] })

  // Keep only small ordering state in a separate observer store. It receives no
  // private identities, feed bodies, operation journal or SQL projection.
  const descriptorStore = new NativeAgentStore(join(volumes, 'descriptor-only.sqlite'))
  const fullStore = new NativeAgentStore(join(restored, 'agent.sqlite'))
  try {
    const historyId = resumed.head.historyId
    for (const key of [`record-log/${historyId}`, `agent/authority/${historyId}/configuration`, `agent/authority/${historyId}/certificate`]) {
      const value = await fullStore.get(key)
      assert(value !== null)
      await descriptorStore.put(key, value)
    }
    const log = await ReferenceRecordLog.open(historyId, descriptorStore)
    const retained = await log.read()
    assert(retained.length >= resumed.head.position)
    assert.equal(retained[resumed.head.position - 1]?.root, resumed.head.root)
    const descriptors = retained.filter(entry => !isFinalityClosureRecord(entry.bytes)).map(entry => decodeLedgerRecord(entry.bytes))
    const missing = descriptors.filter(descriptor => descriptor.inlinePayload === null)
    for (const descriptor of missing) {
      assert.equal(await descriptorStore.get(`agent/authority/${historyId}/payload/${descriptor.payloadHash}`), null)
    }
    assert(missing.length > 0)
    checked('descriptor-survival-is-not-payload-survival', { head: await log.head(),
      descriptorCount: descriptors.length, closureCount: retained.length - descriptors.length, inlineControls: descriptors.length - missing.length,
      missingDetachedBodies: missing.length, missingCommittedEnvelopeBytes: missing.reduce((sum, descriptor) => sum + descriptor.payloadLength, 0),
      retainedValueBytes: descriptorStore.usageBytes(), applicationReplayClaim: false })
  } finally { fullStore.close(); descriptorStore.close() }

  // A separate lineage has exactly one current disk and an older offline backup.
  const doomed = join(volumes, 'only-current-disk'), stale = join(volumes, 'stale-backup')
  const old = state(child('initialize', doomed))
  const backupHead = (await inspectStoppedAuthority(doomed)).head
  await copyClosedVolume(doomed, stale)
  const backupAt = new Date().toISOString()
  const acknowledged = state(child('after-backup', doomed))
  const acknowledgedAt = new Date().toISOString()
  const latest = join(volumes, 'independent-loss-checkpoint.json')
  await writeFile(latest, recoveryJson(acknowledged.head), { flag: 'wx' })
  await rm(doomed, { recursive: true }) // No complete fresh backup exists for this lineage.
  const refusal = child('inspect', stale, 'accepted', 'none', latest)
  assert.notEqual(refusal.status, 0)
  assert.match(refusal.stderr, /AUTHORITY_CONTINUITY_NOT_ESTABLISHED/u)
  assert.deepEqual((await inspectStoppedAuthority(stale)).head, backupHead)
  const replacement = state(child('initialize', join(volumes, 'explicit-new-lineage')))
  assert.notEqual(replacement.head.historyId, acknowledged.head.historyId)
  assert.notEqual(replacement.authorityIdentity, acknowledged.authorityIdentity)
  checked('permanent-latest-disk-loss', { backupAt, acknowledgedAt, backupHead, lastAcknowledgedHead: acknowledged.head,
    knownBackupLagReceipts: acknowledged.head.position - backupHead.position,
    knownBackupLagProposals: acknowledged.proposalCount - old.proposalCount,
    knownBackupLagElapsedMs: Date.parse(acknowledgedAt) - Date.parse(backupAt),
    retainedIndependentEvidence: 'latest acknowledged head outside both volumes',
    staleRestoreResult: 'AUTHORITY_CONTINUITY_NOT_ESTABLISHED', decision: 'new lineage; old history never resumed',
    replacementHead: replacement.head, acknowledgedWorkAutomaticallyRecovered: false })
  report.passed = true
} catch (error) {
  report.error = error instanceof Error ? `${error.message}\n${error.stack ?? ''}` : String(error)
  process.exitCode = 1
} finally {
  report.completedAt = new Date().toISOString()
  try {
    await writeFile(join(output, 'process-traces.json'), `${JSON.stringify(transcript, null, 2)}\n`)
    await writeFile(join(output, 'report.json'), `${JSON.stringify(JSON.parse(recoveryJson(report)), null, 2)}\n`)
    await writeFile(join(output, 'manifest.json'), `${JSON.stringify({ files: await manifest(output) }, null, 2)}\n`)
  } finally {
    // The publishable report never contains the keys or private stores used by the drill.
    await rm(volumes, { recursive: true, force: true })
  }
}
if (!report.passed) throw new Error(`AUTHORITY_RECOVERY_DRILL_FAILED: ${report.error}`)
process.stdout.write(`Authority recovery evidence: ${output}\n`)

function assertTerminal(state: RecoveryState, operation: RecoveryOperation) {
  assert.equal(state.operations[operation]?.final, true)
  assert.equal(state.operations[operation]?.outcome?.outcome, operation)
  if (operation === 'rejected') assert.equal(state.operations[operation]?.outcome?.rejectionCode, 'assert:recovery_probe')
  assert.deepEqual(state.rows, [[{ kind: 'integer', value: '1' }, { kind: 'integer', value: operation === 'accepted' ? '20' : '10' }]])
  assert.equal(state.events.length, operation === 'accepted' ? 1 : 0)
}
function assertSameState(actual: RecoveryState, expected: RecoveryState) {
  for (const key of ['authorityIdentity', 'executionManifestDigest', 'feed', 'operations', 'rows', 'events', 'payloads', 'proposalCount'] as const) {
    assert.deepEqual(actual[key], expected[key], `RESTORE_CHANGED_${key}`)
  }
  assert(actual.head.position >= expected.head.position, 'RESTORE_REGRESSED_RECEIPTS')
  assert.deepEqual(actual.receipts.slice(0, expected.head.position), expected.receipts, 'RESTORE_CHANGED_RECEIPT_PREFIX')
  assert(BigInt(actual.closedThroughMs) >= BigInt(expected.closedThroughMs), 'RESTORE_REGRESSED_CUTOFF')
  assert.equal(actual.certificate.historyId, actual.head.historyId)
  assert.equal(actual.certificate.position, actual.head.position)
  assert.equal(actual.certificate.root, actual.head.root)
  assert.equal(actual.certificate.configuration, expected.certificate.configuration)
}
async function copyClosedVolume(source: string, destination: string) {
  const before = await manifest(source)
  await cp(source, destination, { recursive: true, errorOnExist: true, force: false })
  for (const item of before) {
    const file = await open(join(destination, item.path), 'r')
    try { await file.sync() } finally { await file.close() }
  }
  const copied = await manifest(destination)
  assert.deepEqual(copied, before, 'CLOSED_BACKUP_CONTENT_CHANGED')
  return copied
}
async function manifest(directory: string, prefix = ''): Promise<{ readonly path: string; readonly bytes: number; readonly sha256: string }[]> {
  const entries = await readdir(join(directory, prefix), { withFileTypes: true })
  const rows: { path: string; bytes: number; sha256: string }[] = []
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const path = join(prefix, entry.name)
    if (entry.isDirectory()) rows.push(...await manifest(directory, path))
    else {
      assert(entry.isFile(), 'BACKUP_CONTAINS_NONREGULAR_FILE')
      rows.push({ path, bytes: (await stat(join(directory, path))).size, sha256: await fileSha256(join(directory, path)) })
    }
  }
  return rows
}

async function holdAuthority(directory: string) {
  const args = ['--import', 'tsx', join(workspace, 'tools/lib/authority-recovery-child.ts'), 'hold', directory]
  const started = Date.now()
  const running = spawn(process.execPath, args, { cwd: workspace, stdio: ['pipe', 'pipe', 'pipe'] })
  let stdout = '', stderr = '', recorded = false
  let resolveReady!: (value: HoldingAuthority) => void, rejectReady!: (error: Error) => void
  const ready = new Promise<HoldingAuthority>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  running.stdout.setEncoding('utf8'); running.stderr.setEncoding('utf8')
  running.stdout.on('data', (chunk: string) => {
    stdout += chunk
    if (stdout.length > 4 * 1024 * 1024) { running.kill('SIGKILL'); rejectReady(new Error('RECOVERY_CHILD_OUTPUT_TOO_LARGE')); return }
    const line = stdout.split('\n').find(value => value.startsWith('{"event":"holding",') && value.endsWith('}'))
    if (line !== undefined) {
      try { resolveReady(JSON.parse(line) as HoldingAuthority) }
      catch (error) { rejectReady(error instanceof Error ? error : new Error('RECOVERY_CHILD_READY_INVALID', { cause: error })) }
    }
  })
  running.stderr.on('data', (chunk: string) => { stderr += chunk })
  running.once('error', rejectReady)
  const exited = new Promise<ChildResult>(resolve => { running.once('close', (status, signal) => {
    rejectReady(new Error(`RECOVERY_CHILD_EXITED_BEFORE_READY:${status}:${signal}\n${stderr}`))
    resolve({ status, signal, stdout, stderr })
  }) })
  const kill = async () => {
    if (running.exitCode === null && running.signalCode === null) running.kill('SIGKILL')
    const result = await exited
    if (!recorded) { transcript.push({ command: [process.execPath, ...args], elapsedMs: Date.now() - started, result }); recorded = true }
    return result
  }
  const timeout = setTimeout(() => { rejectReady(new Error('RECOVERY_CHILD_START_TIMEOUT')); running.kill('SIGKILL') }, 15_000)
  try { return { value: await ready, kill } }
  catch (error) { await kill(); throw error }
  finally { clearTimeout(timeout) }
}

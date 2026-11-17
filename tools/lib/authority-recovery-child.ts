import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { writeSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

import { base64UrlToBytes, bytesToBase64Url, emit, program } from '@chronolog/protocol'
import { SignedInclusionFinalityProvider, decodeOrderingEvidence, encodeOrderingEvidence, MemoryOperationStore, type OrderedRecordHead } from '@chronolog/node-core'

import {
  AUTHORITY_CRASH_POINTS, inspectStoppedAuthority, openAuthorityRecoveryFixture, recoveryJson,
  type AuthorityCrashPoint, type RecoveryOperation,
} from './authority-recovery-fixture.js'

const [action, directoryArgument, operationArgument, faultArgument, continuityFile] = process.argv.slice(2)
assert(directoryArgument !== undefined, 'RECOVERY_CHILD_DIRECTORY_REQUIRED')
const directory = resolve(directoryArgument)
if (action === 'raw') {
  process.stdout.write(`${recoveryJson(await inspectStoppedAuthority(directory))}\n`)
} else if (action === 'fence') {
  // Another real process opens the production store while its owner is live.
  const { NativeBytesStore } = await import('@chronolog/records/native')
  const store = new NativeBytesStore(join(directory, 'agent.sqlite'))
  store.close()
  process.stdout.write('{"opened":true}\n')
} else {
  assert(['initialize', 'inspect', 'submit', 'crash', 'offline', 'fencing', 'after-backup', 'hold'].includes(action ?? ''), 'RECOVERY_CHILD_ACTION_INVALID')
  const operation: RecoveryOperation = operationArgument === 'rejected' ? 'rejected' : 'accepted'
  if (action === 'crash') assert(AUTHORITY_CRASH_POINTS.includes(faultArgument as AuthorityCrashPoint), 'RECOVERY_CHILD_CRASH_POINT_INVALID')
  const continuity = continuityFile === undefined ? undefined : JSON.parse(await readFile(continuityFile, 'utf8')) as OrderedRecordHead
  const fixture = await openAuthorityRecoveryFixture(directory, {
    ...(action === 'initialize' ? { create: true } : {}),
    ...(continuity === undefined ? {} : { continuity }),
    fault(point) {
      if (action !== 'crash' || point !== faultArgument) return
      // Synchronous output identifies the reached boundary without adding a
      // storage write or running close/finally hooks before abrupt death.
      writeSync(1, `${recoveryJson({ event: 'fault', point, operation })}\n`)
      process.kill(process.pid, 'SIGKILL')
    },
  })
  const retainedEvidence = async (state: Awaited<ReturnType<typeof fixture.inspect>>) => {
    const range = await fixture.authority.read({ limit: 256 })
    assert(!range.hasMore, 'RECOVERY_FIXTURE_RECEIPT_LIMIT')
    const entries = range.entries.filter(entry => entry.position <= state.head.position)
    assert.equal(entries.at(-1)?.root, state.head.root)
    return [...entries.map(entry => encodeOrderingEvidence({ kind: 'ordered-entry', entry })),
      encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: { ...state.head,
        configuration: base64UrlToBytes(state.certificate.configuration), signature: base64UrlToBytes(state.certificate.signature) } })]
  }
  try {
    if (action === 'initialize') await fixture.initialize()
    if (action === 'submit' || action === 'crash') {
      if (action === 'crash') fixture.arm()
      await fixture.submit(operation)
      if (action === 'crash') throw new Error('RECOVERY_CRASH_POINT_NOT_REACHED')
    }
    if (action === 'after-backup') {
      await fixture.node.publish({ operationId: 'recovery-after-backup', program: program(emit('recovery.changed', { afterBackup: true })) })
      await fixture.terminal('recovery-after-backup')
    }
    if (action === 'fencing') {
      const second = spawnSync(process.execPath, ['--import', 'tsx', resolve(import.meta.dirname, 'authority-recovery-child.ts'), 'fence', directory], {
        encoding: 'utf8', timeout: 20_000,
      })
      assert.notEqual(second.status, 0)
      assert.match(second.stderr, /AGENT_STORE_IN_USE/u)
      process.stdout.write(`${recoveryJson({ event: 'fence', status: second.status, reason: 'AGENT_STORE_IN_USE' })}\n`)
    }
    if (action === 'hold') {
      const configuration = fixture.authority.configuration
      const state = await fixture.inspect(), evidence = await retainedEvidence(state)
      writeSync(1, `${recoveryJson({ event: 'holding', state, configuration: {
        kind: configuration.kind, historyId: configuration.historyId,
        authorityPublicKey: bytesToBase64Url(configuration.authorityPublicKey), groupId: bytesToBase64Url(configuration.groupId),
        genesisDigest: bytesToBase64Url(configuration.genesisDigest), executionManifestDigest: bytesToBase64Url(configuration.executionManifestDigest),
        ...(configuration.providerId === undefined ? {} : { providerId: configuration.providerId }),
        ...(configuration.providerParameters === undefined ? {} : { providerParameters: bytesToBase64Url(configuration.providerParameters) }),
      }, evidence: evidence.map(bytesToBase64Url) })}\n`)
      process.stdin.resume()
      await new Promise<void>(resolve => { process.stdin.once('end', resolve) })
    } else if (action === 'offline') {
      const before = await fixture.inspect()
      const retained = await retainedEvidence(before)
      await fixture.agent.close()
      const stoppedHead = await fixture.authority.head()
      const observer = await SignedInclusionFinalityProvider.open(fixture.authority.configuration, new MemoryOperationStore())
      for (const evidence of [...retained].reverse()) await observer.ingest(decodeOrderingEvidence(evidence))
      const secondObserver = await SignedInclusionFinalityProvider.open(fixture.authority.configuration, new MemoryOperationStore())
      for (const evidence of [...observer.evidence()].reverse()) await secondObserver.ingest(evidence)
      assert.equal(observer.progress.finalThrough, before.head.position)
      assert.deepEqual(secondObserver.progress, observer.progress)
      assert.deepEqual(secondObserver.snapshot(), observer.snapshot())
      const receipt = await fixture.node.publish({ operationId: 'recovery-authority-offline', program: program(emit('recovery.changed', { pending: true })) })
      await fixture.node.waitForIdle()
      const pending = await fixture.node.operation('recovery-authority-offline')
      assert(pending !== null && !pending.final)
      assert.deepEqual(await fixture.authority.head(), stoppedHead)
      assert.deepEqual(fixture.node.localSql('SELECT id, value FROM recovery_probe ORDER BY id', [], { view: 'final' }).rows, before.rows)
      assert.deepEqual((await fixture.node.events.read()).transactions, before.events)
      process.stdout.write(`${recoveryJson({ event: 'offline', previousHead: stoppedHead, proposalId: receipt.txIdText,
        operation: pending, finalRows: before.rows, finalEvents: (await fixture.node.events.read()).transactions,
        relayedEvidence: { bytes: retained.reduce((sum, item) => sum + item.length, 0),
          independentObservers: 2, progress: secondObserver.progress, closedThroughMs: secondObserver.closedThroughMs,
          applicationBodiesSupplied: 0 } })}\n`)
    } else process.stdout.write(`${recoveryJson({ event: 'state', state: await fixture.inspect() })}\n`)
  } finally { await fixture.close() }
}

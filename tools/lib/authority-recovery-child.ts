import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { writeSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

import { emit, program } from '@chronolog/protocol'
import { CoordinatedHistoryPolicy, decodeOrderingEvidence, MemoryOperationStore, type OrderedRecordHead } from '@chronolog/node-core'

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
  const { NativeAgentStore } = await import('@chronolog/agent-service')
  const store = new NativeAgentStore(join(directory, 'agent.sqlite'))
  store.close()
  process.stdout.write('{"opened":true}\n')
} else {
  assert(['initialize', 'inspect', 'submit', 'crash', 'offline', 'fencing', 'after-backup'].includes(action ?? ''), 'RECOVERY_CHILD_ACTION_INVALID')
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
    if (action === 'offline') {
      const before = await fixture.inspect()
      const retained = await fixture.transport.evidenceHistory()
      await fixture.agent.close()
      const observer = await CoordinatedHistoryPolicy.open(fixture.authority.configuration, new MemoryOperationStore())
      for (const evidence of [...retained].reverse()) await observer.ingest(decodeOrderingEvidence(evidence.bytes))
      const secondObserver = await CoordinatedHistoryPolicy.open(fixture.authority.configuration, new MemoryOperationStore())
      for (const evidence of [...observer.evidence()].reverse()) await secondObserver.ingest(evidence)
      assert.equal(observer.progress.finalThrough, before.head.position)
      assert.deepEqual(secondObserver.progress, observer.progress)
      const receipt = await fixture.node.publish({ operationId: 'recovery-authority-offline', program: program(emit('recovery.changed', { pending: true })) })
      await fixture.node.waitForIdle()
      const pending = await fixture.node.operation('recovery-authority-offline')
      assert(pending !== null && !pending.final)
      assert.equal((await fixture.authority.head()).position, before.head.position)
      assert.deepEqual(fixture.node.localSql('SELECT id, value FROM recovery_probe ORDER BY id', [], { view: 'final' }).rows, before.rows)
      assert.deepEqual((await fixture.node.events.read()).transactions, before.events)
      process.stdout.write(`${recoveryJson({ event: 'offline', previousHead: before.head, proposalId: receipt.txIdText,
        operation: pending, finalRows: before.rows, finalEvents: (await fixture.node.events.read()).transactions,
        relayedEvidence: { bytes: retained.reduce((sum, item) => sum + item.bytes.length, 0),
          independentObservers: 2, progress: secondObserver.progress, applicationBodiesSupplied: 0 } })}\n`)
    } else process.stdout.write(`${recoveryJson({ event: 'state', state: await fixture.inspect() })}\n`)
  } finally { await fixture.close() }
}

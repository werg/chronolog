import { spawnSync } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { afterEach, describe, expect, it, vi } from 'vitest'
import { emit, program } from '@chronolog/protocol'

import { AUTHORITY_CRASH_POINTS, certifiedRecoveryFloor, inspectStoppedAuthority, openAuthorityRecoveryFixture } from '../tools/lib/authority-recovery-fixture.js'

const directories: string[] = []
afterEach(async () => { await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true }))) })

describe('native authority process crash recovery', () => {
  it('retains an acknowledged prefix across an interrupted later idle certificate write', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'chronolog-authority-ack-prefix-'))
    directories.push(parent)
    const directory = join(parent, 'volume')
    const fixture = await openAuthorityRecoveryFixture(directory, { create: true })
    let acknowledged: Awaited<ReturnType<typeof fixture.inspect>>
    try {
      await fixture.initialize()
      await fixture.submit('accepted')
      await fixture.agent.close()
      acknowledged = await fixture.inspect()
      const put = fixture.store.put.bind(fixture.store)
      const interrupted = vi.spyOn(fixture.store, 'put').mockImplementation(async (key, bytes) => {
        if (key.endsWith('/certificate')) throw new Error('INTERRUPTED_IDLE_CERTIFICATE_WRITE')
        await put(key, bytes)
      })
      try {
        await fixture.advanceClock()
        await expect(fixture.authority.certify()).rejects.toThrow('INTERRUPTED_IDLE_CERTIFICATE_WRITE')
      } finally { interrupted.mockRestore() }
    } finally { await fixture.close() }
    const raw = await inspectStoppedAuthority(directory)
    expect(raw.head.position).toBe(acknowledged.head.position + 1)
    expect(raw.entries.at(-1)?.kind).toBe('closure')
    const target = raw.closures.find(closure => closure.position === acknowledged.head.position)
    expect(target).toBeDefined()
    const continuity = certifiedRecoveryFloor(raw, target!, 'before_acknowledgement')
    expect(continuity).toEqual(acknowledged.head)
    expect(() => certifiedRecoveryFloor(raw, target!, 'after_certificate_commit')).toThrow()
    const recovered = await openAuthorityRecoveryFixture(directory, { continuity })
    try {
      await recovered.submit('accepted')
      const state = await recovered.inspect()
      expect(state.receipts.slice(0, raw.head.position)).toEqual(raw.entries)
      expect(state.operations.accepted).toEqual(acknowledged.operations.accepted)
      expect(state.proposalCount).toBe(acknowledged.proposalCount)
      expect(state.payloads).toEqual(acknowledged.payloads)
      expect(state.rows).toEqual(acknowledged.rows)
      expect(state.events).toEqual(acknowledged.events)
    } finally { await recovered.close() }
  }, 40_000)

  for (const point of AUTHORITY_CRASH_POINTS) {
    for (const operation of ['accepted', 'rejected'] as const) {
      it(`recovers the original ${operation} operation after SIGKILL at ${point}`, async () => {
        const parent = await mkdtemp(join(tmpdir(), 'chronolog-authority-crash-'))
        directories.push(parent)
        const directory = join(parent, 'volume')
        const initial = await openAuthorityRecoveryFixture(directory, { create: true })
        await initial.initialize()
        const before = await initial.inspect()
        await initial.close()
        const crashed = spawnSync(process.execPath, ['--import', 'tsx', resolve('tools/lib/authority-recovery-child.ts'),
          'crash', directory, operation, point], { encoding: 'utf8', timeout: 25_000 })
        expect(crashed.signal === 'SIGKILL' || crashed.status === 137, `${crashed.stdout}\n${crashed.stderr}`).toBe(true)
        expect(crashed.stdout).toContain(`"point":"${point}"`)
        const raw = await inspectStoppedAuthority(directory)
        const committed = !['before_payload_commit', 'after_payload_commit', 'before_record_commit'].includes(point)
        expect(raw.proposalCount).toBe(before.proposalCount + (committed ? 1 : 0))
        expect(raw.entries.slice(0, before.head.position).map(entry => entry.recordId)).toEqual(before.receipts.map(entry => entry.recordId))
        const target = raw.entries.filter(entry => entry.kind === 'candidate')[before.proposalCount]
        const coveringClosure = target === undefined ? undefined : raw.closures.find(closure => closure.includedHead.position >= target.position)
        const closureCommitted = ['after_closure_commit', 'before_certificate_commit', 'after_certificate_commit', 'before_acknowledgement'].includes(point)
        expect(coveringClosure !== undefined).toBe(closureCommitted)
        if (coveringClosure !== undefined) {
          expect(raw.certificate?.kind).toBe('prefix-certificate')
          const certifiedThrough = raw.certificate?.kind === 'prefix-certificate' ? raw.certificate.certificate.position : -1
          expect(certifiedThrough >= coveringClosure.position).toBe(['after_certificate_commit', 'before_acknowledgement'].includes(point))
        }
        let continuity = before.head
        if (point === 'after_certificate_commit' || point === 'before_acknowledgement') {
          expect(coveringClosure).toBeDefined()
          continuity = certifiedRecoveryFloor(raw, coveringClosure!, point)
        }
        const recovered = await openAuthorityRecoveryFixture(directory, { continuity })
        try {
          const original = await recovered.node.operation(`recovery-${operation}`)
          expect(original).not.toBeNull()
          const outcome = await recovered.submit(operation)
          expect(outcome.proposalId).toBe(original?.proposalId)
          expect(outcome.outcome?.outcome).toBe(operation)
          if (operation === 'rejected') expect(outcome.outcome?.rejectionCode).toBe('assert:recovery_probe')
          const state = await recovered.inspect()
          expect(state.proposalCount).toBe(before.proposalCount + 1)
          expect(state.payloads).toHaveLength(before.payloads.length + 1)
          expect(state.receipts.slice(0, raw.head.position)).toEqual(raw.entries)
          expect(state.rows).toEqual([[{ kind: 'integer', value: '1' }, { kind: 'integer', value: operation === 'accepted' ? '20' : '10' }]])
          expect(state.events.flatMap(transaction => transaction.events)).toHaveLength(operation === 'accepted' ? 1 : 0)
          await recovered.submit(operation)
          const retried = await recovered.inspect()
          expect(retried.payloads).toEqual(state.payloads)
          expect(retried.receipts.slice(0, state.head.position).map(entry => entry.recordId)).toEqual(state.receipts.map(entry => entry.recordId))
          expect(retried.operations[operation]).toEqual(state.operations[operation])
          expect(retried.rows).toEqual(state.rows)
          expect(retried.events).toEqual(state.events)
          await expect(recovered.node.publish({ operationId: `recovery-${operation}`,
            program: program(emit('recovery.changed', { changed: true })) })).rejects.toThrow('OPERATION_ID_CONFLICT')
          expect((await recovered.inspect()).payloads).toEqual(state.payloads)
          expect(state.payloads.every(payload => payload.payloadBytes !== null)).toBe(true)
        } finally { await recovered.close() }
      }, 40_000)
    }
  }
})

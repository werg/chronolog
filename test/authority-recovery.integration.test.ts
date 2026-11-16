import { spawnSync } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'
import { emit, program } from '@chronolog/protocol'

import { AUTHORITY_CRASH_POINTS, inspectStoppedAuthority, openAuthorityRecoveryFixture } from '../tools/lib/authority-recovery-fixture.js'

const directories: string[] = []
afterEach(async () => { await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true }))) })

describe('native authority process crash recovery', () => {
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
        const committed = ['after_record_commit', 'after_certificate_commit', 'before_acknowledgement'].includes(point)
        expect(raw.head.position).toBe(before.head.position + (committed ? 1 : 0))
        expect(raw.entries.slice(0, before.head.position).map(entry => entry.recordId)).toEqual(before.payloads.map(entry => entry.recordId))
        if (point === 'after_certificate_commit' || point === 'before_acknowledgement') {
          expect(raw.certificate).toMatchObject({ kind: 'prefix-certificate', certificate: raw.head })
        }
        const recovered = await openAuthorityRecoveryFixture(directory, { continuity: before.head })
        try {
          const original = await recovered.node.operation(`recovery-${operation}`)
          expect(original).not.toBeNull()
          const outcome = await recovered.submit(operation)
          expect(outcome.proposalId).toBe(original?.proposalId)
          expect(outcome.outcome?.outcome).toBe(operation)
          if (operation === 'rejected') expect(outcome.outcome?.rejectionCode).toBe('assert:recovery_probe')
          const state = await recovered.inspect()
          expect(state.head.position).toBe(before.head.position + 1)
          expect(state.rows).toEqual([[{ kind: 'integer', value: '1' }, { kind: 'integer', value: operation === 'accepted' ? '20' : '10' }]])
          expect(state.events.flatMap(transaction => transaction.events)).toHaveLength(operation === 'accepted' ? 1 : 0)
          await recovered.submit(operation)
          expect((await recovered.inspect()).head).toEqual(state.head)
          await expect(recovered.node.publish({ operationId: `recovery-${operation}`,
            program: program(emit('recovery.changed', { changed: true })) })).rejects.toThrow('OPERATION_ID_CONFLICT')
          expect((await recovered.inspect()).head).toEqual(state.head)
          expect(state.payloads.every(payload => payload.payloadBytes !== null)).toBe(true)
        } finally { await recovered.close() }
      }, 40_000)
    }
  }
})

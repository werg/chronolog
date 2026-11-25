import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

import { NativeBytesStore } from '@chronolog/records/native'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { eventExecutionManifest } from '@chronolog/materializer/manifest'
import { createSigningIdentity, signAppDescriptor, signMembership, epochKeyCommitment, type SigningIdentity } from '@chronolog/authority'
import { defineApplication, defineCommand } from './definition.js'
import type { ApplicationDevice } from './device.js'
import { exitCleanupCount } from './exit-cleanup.js'
import { forwardManySessionEvents, mergeSessionChanges, type MergeableSession, type MergedSessionChange } from './multi-session.js'
import { openDisposableNativeDevice, openNativeDevice } from './native.js'
import { createApplicationSession } from './runtime.js'
import type { ApplicationChange } from './session-types.js'

const definition = defineApplication({
  id: 'multi-session-test',
  version: '1',
  commands: {
    addNote: defineCommand({
      description: 'Add a note',
      input: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] },
      prepare: ({ text }) => program(emit('note', { text })),
    }),
  },
  queries: {},
})

async function openSession(device: ApplicationDevice, applicationId: string) {
  const authoritySigner = await createSigningIdentity(), key = crypto.getRandomValues(new Uint8Array(32))
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signAppDescriptor({ applicationId, rootPrincipal: device.identity.publicKey,
    authorityPublicKey: authoritySigner.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    finalityPolicy: { kind: 'none' } }, authoritySigner)
  const membership = await signMembership({ applicationId, revision: 0, previous: null, authorTimeAfterMs: -1n,
    epoch: 0, epochKeyDigest: await epochKeyCommitment(applicationId, 0, key),
    members: [{ publicKey: device.identity.publicKey, reader: true, writer: true, administrator: true, publisher: false, finalizer: false }] }, authoritySigner)
  return createApplicationSession({ device, definition, authority: { descriptor, memberships: [membership] }, epochKeys: new Map([[0, key]]) })
}

const applicationIdFor = (index: number): string => index.toString(16).padStart(2, '0').repeat(32)

/** Minimal scripted session: a push-driven change feed that ends on abort. */
function scriptedSession(applicationId: string): MergeableSession & { push(change: Partial<ApplicationChange>): void; fail(error: Error): void } {
  const queue: ApplicationChange[] = []
  let wake: () => void = () => undefined, failure: Error | undefined
  return {
    applicationId,
    push(change) { queue.push({ kind: 'materialized', revision: { digest: '00'.repeat(32), view: 'local', executionManifestDigest: '11'.repeat(32), policyDigest: '22'.repeat(32) }, revisedProposalIds: [], ...change }); wake() },
    fail(error) { failure = error; wake() },
    async *changes(options = {}) {
      const signal = options.signal
      signal?.addEventListener('abort', () => wake(), { once: true })
      for (;;) {
        if (failure !== undefined) throw failure
        if (signal?.aborted === true) return
        const next = queue.shift()
        if (next !== undefined) { yield next; continue }
        await new Promise<void>(resolve => { wake = resolve })
      }
    },
  }
}

describe('many sessions in one process', () => {
  it('runs 12+ native sessions that share one agent signer, one store worker and one exit listener', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-multi-session-'))
    const warnings: Error[] = []
    const onWarning = (warning: Error): void => { warnings.push(warning) }
    process.on('warning', onWarning)
    const exitListeners = process.listenerCount('exit')
    const signer: SigningIdentity = await createSigningIdentity()
    const devices: ApplicationDevice[] = []
    const sessions: Awaited<ReturnType<typeof openSession>>[] = []
    try {
      for (let index = 0; index < 12; index++) {
        devices.push(await openNativeDevice({ path: join(directory, `page-${index}.sqlite`), create: true, managedSigner: signer }))
      }
      for (let index = 0; index < 12; index++) devices.push(await openDisposableNativeDevice({ sql: true, managedSigner: signer }))
      expect(new Set(devices.map(device => device.identity.publicKey))).toEqual(new Set([signer.publicKey]))
      expect(new Set(devices.map(device => device.storageId)).size).toBe(24)
      expect(NativeBytesStore.poolStatus().stores).toBe(24)
      expect(exitCleanupCount()).toBe(12)
      expect(process.listenerCount('exit')).toBeLessThanOrEqual(exitListeners + 1)

      for (const [index, device] of devices.entries()) sessions.push(await openSession(device, applicationIdFor(index + 1)))
      const merged = mergeSessionChanges(sessions.slice(0, 20))
      merged.add(sessions[20]!)
      expect(merged.size).toBe(21)
      const seen = new Set<string>()
      const reading = (async () => {
        for await (const change of merged) {
          if (change.kind === 'materialized') seen.add(change.applicationId)
          if (seen.size === 21) return
        }
      })()
      await Promise.all(sessions.map(async (session, index) =>
        (await session.command('addNote', { text: `page ${index}` }, { operationId: `note-${index}` })).materialized()))
      await reading
      expect([...seen].sort()).toEqual(sessions.slice(0, 21).map(session => session.applicationId).sort())
      merged.close()

      const checkpoints = new Map<string, string>()
      const delivered: string[] = []
      const forwarders = forwardManySessionEvents({
        sessions, topics: ['note'],
        checkpoints: { load: scope => checkpoints.get(scope.key), save: (scope, cursor) => { checkpoints.set(scope.key, cursor) } },
        project: event => ({ name: event.topic, payload: event.payload }),
        deliver: projected => { delivered.push((projected.payload as { text: string }).text) },
        onError: error => { throw error },
      })
      expect(forwarders.size).toBe(24)
      await expect.poll(() => checkpoints.size, { timeout: 10_000 }).toBe(24)
      await expect.poll(() => delivered.length, { timeout: 10_000 }).toBe(24)
      await expect.poll(() => [...checkpoints.values()].every(state => Object.values((JSON.parse(state) as { entries: Record<string, { acknowledged: boolean }> }).entries).every(entry => entry.acknowledged))).toBe(true)
      expect(new Set(checkpoints.keys())).toEqual(new Set(sessions.map(session => session.applicationId)))
      expect(delivered.sort()).toEqual(sessions.map((_, index) => `page ${index}`).sort())
      await forwarders.close()
      expect(warnings.filter(warning => warning.name === 'MaxListenersExceededWarning')).toEqual([])
    } finally {
      process.removeListener('warning', onWarning)
      await Promise.all(sessions.map(session => session.close()))
      await Promise.all(devices.map(async device => { await device.close() }))
      await rm(directory, { recursive: true, force: true })
    }
    expect(NativeBytesStore.poolStatus()).toEqual({ threadId: null, stores: 0 })
    expect(exitCleanupCount()).toBe(0)
    expect(process.listenerCount('exit')).toBe(exitListeners)
  }, 60_000)

  it('requires the same managed signer on resume', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-managed-native-'))
    const path = join(directory, 'page.sqlite'), signer = await createSigningIdentity()
    try {
      await (await openNativeDevice({ path, create: true, managedSigner: signer })).close()
      await expect(openNativeDevice({ path })).rejects.toThrow('APPLICATION_DEVICE_MANAGED_SIGNER_REQUIRED')
      await expect(openNativeDevice({ path, managedSigner: await createSigningIdentity() })).rejects.toThrow('APPLICATION_DEVICE_KEY_MISMATCH')
      const resumed = await openNativeDevice({ path, managedSigner: signer })
      try { expect(resumed.identity.publicKey).toBe(signer.publicKey) } finally { await resumed.close() }
    } finally { await rm(directory, { recursive: true, force: true }) }
  })

  it('merges sessions added and removed at runtime, with one pending change per session', async () => {
    const a = scriptedSession('aa'), b = scriptedSession('bb'), c = scriptedSession('cc')
    async function* registry(): AsyncIterable<MergeableSession> { yield a; await Promise.resolve(); yield b }
    const merged = mergeSessionChanges(registry())
    const iterator = merged[Symbol.asyncIterator]()
    const take = async (): Promise<MergedSessionChange> => (await iterator.next()).value as MergedSessionChange
    await expect.poll(() => merged.size).toBe(2)
    a.push({}); a.push({ kind: 'dependency' })
    expect(await take()).toMatchObject({ applicationId: 'aa', kind: 'materialized' })
    expect(await take()).toMatchObject({ applicationId: 'aa', kind: 'dependency' })
    merged.add(c); merged.add(c)
    expect(merged.size).toBe(3)
    c.push({}); b.push({})
    const next = [await take(), await take()].map(change => change.applicationId).sort()
    expect(next).toEqual(['bb', 'cc'])
    b.push({}); merged.remove(b)
    expect(merged.size).toBe(2)
    a.push({})
    expect((await take()).applicationId).toBe('aa')
    c.fail(new Error('page failed'))
    await expect(iterator.next()).rejects.toThrow('page failed')
    expect(await iterator.next()).toEqual({ done: true, value: undefined })
    expect(merged.size).toBe(0)
  })

  it('reports a failed session to onError and keeps following the others', async () => {
    const a = scriptedSession('aa'), b = scriptedSession('bb')
    const errors: string[] = []
    const merged = mergeSessionChanges([a, b], { onError: (error, session) => { errors.push(`${session.applicationId}:${(error as Error).message}`) } })
    a.fail(new Error('gone'))
    await expect.poll(() => merged.size).toBe(1)
    b.push({})
    const iterator = merged[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toMatchObject({ applicationId: 'bb' })
    expect(errors).toEqual(['aa:gone'])
    await iterator.return?.()
    expect(merged.size).toBe(0)
  })
})

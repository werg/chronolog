import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  createGenerationRegistry, createPeerIdentity, MemoryPeerStore, signApplicationDescriptor,
  signControlRevision, signTransitionRequest, bytesDigest, type PeerIdentity, type PrefixProof,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { defineApplication, defineCommand, defineQuery, applicationDefinitionDigest } from './definition.js'
import { connectApplications, AbandonedOperationError, ChangedViewError, type ApplicationReadView, type ApplicationSession } from './session.js'
import { openNativeApplication, openNativeDevice } from './native.js'

const definition = defineApplication({ id: 'messages', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string', minLength: 1 }, prepare: text => program(emit('message', { text })) }),
}, queries: {
  messages: defineQuery({ description: 'Messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }),
} })
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { vi.restoreAllMocks(); for (const close of cleanup.splice(0).reverse()) await close() })
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'peer-session-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const host = await createPeerIdentity()
  const a = await openNativeDevice({ path: join(directory, 'a.sqlite'), create: true }), b = await openNativeDevice({ path: join(directory, 'b.sqlite'), create: true }),
    c = await openNativeDevice({ path: join(directory, 'c.sqlite'), create: true })
  cleanup.push(() => a.close(), () => b.close(), () => c.close())
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const artifacts = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: '77'.repeat(32), historyId: 'session-test', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: a.identity.publicKey,
    executionManifestDigest: bytesToHex(artifacts.executionManifestDigest), definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b, c].map(device => ({ publicKey: device.identity.publicKey, reader: true, writer: true, coordinator: true, recovery: true, administrator: true })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  const select = async (identity: PeerIdentity, base: PrefixProof | null, transitionId: string) => {
    const bundle = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, expectedGeneration: bundle.generations.at(-1)?.id ?? null, coordinator: identity.publicKey,
      requester: identity.publicKey, controlRevision: 0, base, transitionId, reason: base === null ? 'create' : 'takeover' }, identity))
  }
  await select(a.identity, null, 'create')
  const open = async (device: typeof a) => {
    const session = await openNativeApplication({ device, authority: await registry.read(), epochKeys, definition })
    cleanup.push(() => session.close()); return session
  }
  return { a, b, c, directory, registry, select, open }
}

async function applied(session: ApplicationSession<typeof definition>, text: string, id: string) {
  const operation = await session.command('say', text, { operationId: id })
  return operation.applied({ signal: AbortSignal.timeout(5000) })
}

describe('public peer application sessions', () => {
  it('owns a single saved attempt, exposes authenticated current results and isolates cancelled waiters', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const operation = await b.command('say', 'saved offline', { operationId: 'once' })
    expect(await operation.get()).toMatchObject({ status: 'saved' })
    const cancelled = new AbortController(), waiting = operation.applied({ signal: cancelled.signal })
    cancelled.abort(new Error('stop waiting'))
    await expect(waiting).rejects.toThrow('stop waiting')
    expect(await operation.get()).toMatchObject({ status: 'saved' })
    const original = await b.operations.inspect('once')
    const link = await connectApplications(a, b)
    cleanup.push(() => link.close())
    expect(await operation.applied({ signal: AbortSignal.timeout(5000) })).toMatchObject({ status: 'applied', outcome: 'accepted', sequence: 1 })
    await operation.retry(); await link.synchronize()
    expect((await b.operations.inspect('once'))?.attempt).toEqual(original?.attempt)
    const result = await a.query('messages', null)
    expect(result.value.events).toHaveLength(1)
    expect(result.value.events[0]).toMatchObject({ author: b.deviceId, operationId: 'once', payload: { text: 'saved offline' } })
    expect(a.capabilities.finality).toBe(false)
    expect('final' in operation).toBe(false)
    expect(await operation.shared({ signal: AbortSignal.timeout(5000) })).toHaveLength(1)
  })

  it('keeps a cut after durable ordering recoverable as the same exact attempt', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    let link = await connectApplications(a, b)
    const changes = a.changes()[Symbol.asyncIterator]()
    await changes.next()
    const cut = changes.next().then(() => { link.close() })
    const operation = await b.command('say', 'lost response', { operationId: 'lost' })
    await cut
    await b.retry('lost').catch(error => { expect(String(error)).toContain('APPLICATION_PEER_DISCONNECTED') })
    expect((await b.operations.get('lost'))?.status).toBe('saved')
    expect((await a.operations.get('lost', { author: b.deviceId }))?.status).toBe('applied')
    const original = await b.operations.inspect('lost')
    link = await connectApplications(a, b)
    cleanup.push(() => link.close())
    const result = await operation.applied({ signal: AbortSignal.timeout(5000) })
    expect(result.sequence).toBe(1)
    expect((await b.operations.inspect('lost'))?.attempt).toEqual(original?.attempt)
    expect((await a.query('messages', null)).value.events).toHaveLength(1)
    await changes.return?.()
  })

  it('keeps observing an applied attempt as late history changes its revision and preserves the captured event view', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const clock = vi.spyOn(Date, 'now').mockReturnValue(500)
    const later = await a.command('say', 'later', { operationId: 'later' })
    const original = await later.applied(), held = await a.readView(), heldBatch = held.readEvents()
    const observations = a.operations.subscribe({ operationId: 'later' })[Symbol.asyncIterator]()
    expect((await observations.next()).value).toEqual(original)
    const changed = observations.next()
    clock.mockReturnValue(100)
    const earlier = await b.command('say', 'earlier', { operationId: 'earlier' })
    const exact = await b.operations.inspect('earlier')
    const link = await connectApplications(a, b); cleanup.push(() => link.close())
    await earlier.applied({ signal: AbortSignal.timeout(5000) }); await link.synchronize()
    const observed = (await changed).value
    expect(observed).toMatchObject({ status: 'applied', attemptId: original.attemptId, outcome: 'accepted' })
    expect(observed?.status === 'applied' && observed.revision).not.toEqual(original.revision)
    expect(held.readEvents()).toEqual(heldBatch)
    const current = await a.readView()
    try {
      expect(current.readEvents().events.map(value => [value.operationId, value.authorTimestampMs])).toEqual([['earlier', '100'], ['later', '500']])
      expect(() => current.readEvents({ cursor: heldBatch.cursor })).toThrow(ChangedViewError)
      expect('finalRevision' in current).toBe(false)
    } finally { current.release(); held.release() }
    await earlier.retry()
    expect((await b.operations.inspect('earlier'))?.attempt).toEqual(exact?.attempt)
    const waiting = observations.next()
    await observations.return?.()
    expect(await waiting).toMatchObject({ done: true })
  })

  it('seeds a fresh recovered generation before replacing a ready older peer view', async () => {
    const f = await fixture(), a = await f.open(f.a)
    await applied(a, 'retained', 'retained')
    const held = await a.readView(), previous = a.revision
    await f.select(f.b.identity, await a.recoveryPoint(), 'fresh-recovery')
    const b = await f.open(f.b)
    expect(b.status.phase).toBe('waiting')
    await expect(b.readView()).rejects.toThrow('PEER_RECOVERING')
    expect(a.revision).toEqual(previous)
    const link = await connectApplications(a, b); cleanup.push(() => link.close())
    expect(a.revision.generation).toBe(b.revision.generation)
    expect((await b.query('messages', null)).value.events.map(value => value.operationId)).toEqual(['retained'])
    expect(held.readEvents().events.map(value => value.operationId)).toEqual(['retained']); held.release()
    const c = await f.open(f.c)
    expect(c.status.phase).toBe('waiting')
    const freshLink = await connectApplications(b, c); cleanup.push(() => freshLink.close())
    expect((await c.query('messages', null)).value.events.map(value => value.operationId)).toEqual(['retained'])
  })

  it('keeps an incomplete recovery waiting and preserves the older source until a complete prefix is available', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    await applied(a, 'one', 'one')
    const link = await connectApplications(a, b); await link.synchronize(); link.close()
    const older = b.revision
    await applied(a, 'two', 'two')
    await f.select(f.c.identity, await a.recoveryPoint(), 'complete-prefix-required')
    const c = await f.open(f.c)
    await expect(connectApplications(b, c)).rejects.toThrow('PEER_RECOVERY_PREFIX_INCOMPLETE')
    expect(c.status.phase).toBe('waiting')
    expect(b.revision).toEqual(older)
    expect((await b.query('messages', null)).value.events).toHaveLength(1)
    const full = await connectApplications(a, c); cleanup.push(() => full.close())
    expect((await c.query('messages', null)).value.events).toHaveLength(2)
    const retry = await connectApplications(b, c); cleanup.push(() => retry.close())
    expect((await b.query('messages', null)).value.events).toHaveLength(2)
  })

  it('replicates retained history from the more complete follower without coordinator connectivity', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b), c = await f.open(f.c)
    await applied(a, 'retained', 'retained')
    const initial = await connectApplications(a, c); await initial.synchronize(); initial.close()
    const link = await connectApplications(b, c); cleanup.push(() => link.close())
    expect(b.status).toMatchObject({ phase: 'waiting', role: 'follower', connectedPeers: 1 })
    expect((await b.query('messages', null)).value.events.map(value => value.operationId)).toEqual(['retained'])
    expect(b.revision.point).toEqual(c.revision.point)
  })

  it('atomically resets recovery views, preserves abandoned evidence and links a deliberate reapplication', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    await applied(a, 'retained', 'retained'); await link.synchronize(); link.close()
    const base = await b.recoveryPoint()
    const abandoned = await a.command('say', 'tail', { operationId: 'tail' }); await abandoned.applied()
    const old = await a.query('messages', null), captured = await a.readView()
    await f.select(f.b.identity, base, 'recover')
    await b.adopt(await f.registry.read())
    const recoveryLink = await connectApplications(a, b)
    cleanup.push(() => recoveryLink.close())
    await expect(abandoned.applied()).rejects.toBeInstanceOf(AbandonedOperationError)
    expect(captured.readEvents().events).toHaveLength(2); captured.release()
    const current = await a.readView()
    expect(() => current.readEvents({ cursor: old.value.cursor })).toThrow(ChangedViewError); current.release()
    expect((await a.query('messages', null)).value.events).toHaveLength(1)
    const prior = await a.operations.inspect('tail')
    const retried = await a.reapply('tail', 'say', 'tail reviewed', { operationId: 'tail-again', observedRevision: a.revision })
    expect((await retried.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
    expect((await a.operations.inspect('tail-again'))?.attempt.payload.header.reapplyOf).toBe(prior?.attempt.id)
    expect((await a.operations.get('tail'))?.status).toBe('abandoned')
  })

  it('keeps device identity and applied outcomes across close/reopen and rejects another owner', async () => {
    const f = await fixture(), a = await f.open(f.a), publicKey = a.deviceId
    await expect(openNativeDevice({ path: join(f.directory, 'a.sqlite') })).rejects.toThrow('AGENT_STORE_IN_USE')
    await applied(a, 'persistent', 'saved')
    await a.close()
    const reopenedDevice = await openNativeDevice({ path: join(f.directory, 'a.sqlite') })
    const reopened = await f.open(reopenedDevice)
    expect(reopened.deviceId).toBe(publicKey)
    expect((await reopened.operations.get('saved'))?.status).toBe('applied')
    expect((await reopened.query('messages', null)).value.events).toHaveLength(1)
  })
})

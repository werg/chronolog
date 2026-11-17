import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { applicationDefinitionDigest, defineApplication, defineCommand } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication } from './runtime.js'
import { APPLICATION_EVENT_CURSOR_LIMIT, connectApplications, type ApplicationEvent } from './session.js'

const definition = defineApplication({ id: 'projection-example', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
  activity: defineCommand({ description: 'Record other activity', input: { type: 'null' }, prepare: () => program(emit('activity', null)) }),
}, queries: {} })
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

class ProjectionStore extends MemoryBytesStore {
  writes = 0
  loseReply = false
  pause: (() => Promise<void>) | null = null
  override async put(key: string, value: Uint8Array): Promise<void> {
    if (key.startsWith('peer-session/projection/')) {
      this.writes++
      await this.pause?.()
      await super.put(key, value)
      if (this.loseReply) { this.loseReply = false; throw new Error('LOST_CHECKPOINT_REPLY') }
    } else await super.put(key, value)
  }
}

async function fixture() {
  const host = await createPeerIdentity(), stores = [new ProjectionStore(), new ProjectionStore()]
  const devices = await Promise.all(stores.map(store => openApplicationDevice({ store, create: true })))
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const execution = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: 'a7'.repeat(32), historyId: 'projection-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: devices[0]!.identity.publicKey, executionManifestDigest: bytesToHex(execution.executionManifestDigest),
    definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: devices.map(device => participantGrant(device.identity.publicKey, { administrator: true })),
  }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
    profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: 'create', expectedGeneration: null,
    coordinator: devices[0]!.identity.publicKey, requester: devices[0]!.identity.publicKey, controlRevision: 0, reason: 'create', base: null,
  }, devices[0]!.identity))
  const open = async (index: number) => {
    const device = await openApplicationDevice({ store: stores[index]! })
    const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys })
    cleanup.push(() => session.close()); return session
  }
  const a = await open(0), b = await open(1)
  return { a, b, stores, open, registry, async recover() {
    const authority = await registry.read(), identity = devices[1]!.identity
    await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, transitionId: 'takeover', expectedGeneration: authority.generations.at(-1)!.id,
      coordinator: identity.publicKey, requester: identity.publicKey, controlRevision: 0, reason: 'takeover', base: await b.recoveryPoint(),
    }, identity))
    const next = await registry.read(); await b.adopt(next); await a.adopt(next)
  } }
}
const messages = (reduce = (state: string[], event: ApplicationEvent) => [...state, event.operationId]) => ({
  id: 'messages', version: '1', topics: ['message'], initial: [] as string[], reduce,
})

describe('owned durable projections', () => {
  it('advances and reopens a checkpoint with the largest admitted topic filter', async () => {
    const f = await fixture(), reduce = vi.fn((state: string[], event: ApplicationEvent) => [...state, event.operationId])
    const topics = ['message', ...Array.from({ length: 127 }, (_, index) => `t${String(index).padStart(3, '0')}${'x'.repeat(124)}`)]
    const definition = { ...messages(reduce), topics }, projection = f.a.project(definition)
    expect((await projection.read()).state).toEqual([])
    await (await f.a.command('say', 'one', { operationId: 'one' })).applied()
    expect((await projection.read()).state).toEqual(['one'])
    await f.a.close()
    const reopened = await f.open(0), resumed = reopened.project(definition)
    expect((await resumed.read()).state).toEqual(['one']); expect(reduce).toHaveBeenCalledOnce()
    await (await reopened.command('say', 'two', { operationId: 'two' })).applied()
    expect((await resumed.read()).state).toEqual(['one', 'two']); expect(reduce).toHaveBeenCalledTimes(2)
  })

  it('round-trips event cursors for worst-case escaped topic filters within the shared bound', async () => {
    const f = await fixture()
    const topics = Array.from({ length: 128 }, (_, index) => String.fromCharCode(0xd800 + index).repeat(128))
    const view = await f.a.readView()
    let cursor: string
    try {
      cursor = view.readEvents({ topics }).cursor
      expect(cursor.length).toBeLessThanOrEqual(APPLICATION_EVENT_CURSOR_LIMIT)
      expect(view.readEvents({ topics, cursor }).events).toEqual([])
    } finally { view.release() }
    await (await f.a.command('say', 'one', { operationId: 'one' })).applied()
    const advanced = await f.a.readView()
    try {
      const batch = advanced.readEvents({ topics, cursor })
      expect(batch.revision.point.sequence).toBe(1); expect(batch.events).toEqual([])
      expect(advanced.readEvents({ topics, cursor: batch.cursor }).hasMore).toBe(false)
    } finally { advanced.release() }
  })

  it('releases an idle change observer immediately and bounds concurrent pulls', async () => {
    const f = await fixture(), projection = f.a.project(messages())
    const observer = projection.changes()[Symbol.asyncIterator]()
    expect((await observer.next()).value?.state).toEqual([])
    const idle = observer.next()
    await expect(observer.next()).rejects.toThrow('APPLICATION_PROJECTION_CONCURRENT_NEXT')
    expect((await observer.return?.())?.done).toBe(true)
    expect((await idle).done).toBe(true)
    expect((await projection.read()).state).toEqual([])
  })

  it('reduces only new matching events, checkpoints empty ranges, and resumes without replay', async () => {
    const f = await fixture(), reduce = vi.fn((state: string[], event: ApplicationEvent) => [...state, event.operationId])
    const projection = f.a.project(messages(reduce))
    expect((await projection.read()).state).toEqual([])
    await (await f.a.command('say', 'one', { operationId: 'one' })).applied()
    const first = await projection.read()
    expect(first.state).toEqual(['one']); expect(first.reset).toBeNull()
    first.state.push('caller mutation')
    const writes = f.stores[0]!.writes
    expect((await projection.read()).state).toEqual(['one'])
    expect(f.stores[0]!.writes).toBe(writes); expect(reduce).toHaveBeenCalledOnce()
    await (await f.a.command('activity', null, { operationId: 'other' })).applied()
    const filtered = await projection.read()
    expect(filtered.state).toEqual(['one']); expect(filtered.revision.point.sequence).toBe(2)
    expect(reduce).toHaveBeenCalledOnce()
    await f.a.close()
    const reopened = await f.open(0), resumed = reopened.project(messages(reduce))
    expect((await resumed.read()).state).toEqual(['one']); expect(reduce).toHaveBeenCalledOnce()
    await (await reopened.command('say', 'two', { operationId: 'two' })).applied()
    expect((await resumed.read()).state).toEqual(['one', 'two']); expect(reduce).toHaveBeenCalledTimes(2)
  })

  it('rebuilds excluded projection state atomically and keeps abandoned attempts inspectable', async () => {
    const f = await fixture(), link = await connectApplications(f.a, f.b)
    await (await f.a.command('say', 'retained', { operationId: 'retained' })).applied()
    await link.synchronize(); await link.close()
    const projection = f.a.project(messages())
    await (await f.a.command('say', 'excluded', { operationId: 'tail' })).applied()
    const old = await projection.read()
    expect(old.state).toEqual(['retained', 'tail'])
    await f.recover()
    const recovered = await projection.read()
    expect(recovered.state).toEqual(['retained'])
    expect(recovered.reset).toEqual({ reason: 'recovery', previousRevision: old.revision })
    expect(recovered.revision).toEqual(f.a.revision)
    expect((await f.a.operations.get('tail'))?.status).toBe('abandoned')
    expect((await projection.read()).reset).toBeNull()
    expect(old.state).toEqual(['retained', 'tail'])
  })

  it('binds durable progress to the reducer version and normalized topic filter', async () => {
    const f = await fixture()
    await (await f.a.command('say', 'one', { operationId: 'one' })).applied()
    await (await f.a.command('activity', null, { operationId: 'other' })).applied()
    const initial = f.a.project(messages()), old = await initial.read()
    expect(() => f.a.project(messages())).toThrow('APPLICATION_PROJECTION_IN_USE')
    await initial.close()
    const version = f.a.project({ ...messages(), version: '2', initial: ['new reducer'] })
    expect(await version.read()).toMatchObject({ state: ['new reducer', 'one'], reset: { reason: 'definition', previousRevision: old.revision } })
    await version.close()
    const filter = f.a.project({ ...messages(), version: '2', topics: ['activity', 'activity'] })
    expect(await filter.read()).toMatchObject({ state: ['other'], reset: { reason: 'definition' } })
    await filter.close()
    const reduce = vi.fn((state: string[], event: ApplicationEvent) => [...state, event.operationId])
    const normalized = f.a.project({ ...messages(reduce), version: '2', topics: ['activity'] })
    expect(await normalized.read()).toMatchObject({ state: ['other'], reset: null })
    expect(reduce).not.toHaveBeenCalled()
  })

  it('leaves the previous checkpoint intact when a reducer fails and isolates it from application progress', async () => {
    const f = await fixture()
    let refuse = false
    const projection = f.a.project(messages((state, event) => {
      if (refuse) { state.push('uncommitted'); throw new Error('REDUCER_FAILED') }
      return [...state, event.operationId]
    }))
    await (await f.a.command('say', 'one', { operationId: 'one' })).applied(); await projection.read()
    await (await f.a.command('say', 'two', { operationId: 'two' })).applied()
    refuse = true
    await expect(projection.read()).rejects.toThrow('REDUCER_FAILED')
    await (await f.a.command('say', 'three', { operationId: 'three' })).applied()
    refuse = false
    expect((await projection.read()).state).toEqual(['one', 'two', 'three'])
  })

  it('requires reopening after an uncertain checkpoint acknowledgment without fencing ordinary commands', async () => {
    const f = await fixture(), projection = f.a.project(messages())
    await (await f.a.command('say', 'one', { operationId: 'one' })).applied()
    f.stores[0]!.loseReply = true
    await expect(projection.read()).rejects.toThrow('LOST_CHECKPOINT_REPLY')
    await expect(projection.read()).rejects.toThrow('APPLICATION_PROJECTION_REOPEN_REQUIRED')
    await (await f.a.command('say', 'two', { operationId: 'two' })).applied()
    await projection.close()
    const reduce = vi.fn((state: string[], event: ApplicationEvent) => [...state, event.operationId])
    expect((await f.a.project(messages(reduce)).read()).state).toEqual(['one', 'two'])
    expect(reduce).toHaveBeenCalledOnce()
  })

  it('drains admitted checkpoint writes before session ownership closes, even after the reader cancels', async () => {
    const f = await fixture(), projection = f.a.project(messages())
    await (await f.a.command('say', 'one', { operationId: 'one' })).applied()
    let entered!: () => void, release!: () => void
    const started = new Promise<void>(resolve => { entered = resolve }), held = new Promise<void>(resolve => { release = resolve })
    f.stores[0]!.pause = () => { entered(); return held }
    const cancel = new AbortController(), reading = projection.read({ signal: cancel.signal })
    const cancelled = expect(reading).rejects.toThrow('stop reading')
    await started; cancel.abort(new Error('stop reading')); await cancelled
    let closed = false
    const closing = f.a.close().then(() => { closed = true })
    await Promise.resolve(); expect(closed).toBe(false)
    release(); await closing; f.stores[0]!.pause = null
    const resumed = await f.open(0), reduce = vi.fn((state: string[], event: ApplicationEvent) => [...state, event.operationId])
    expect((await resumed.project(messages(reduce)).read()).state).toEqual(['one'])
    expect(reduce).not.toHaveBeenCalled()
  })
})

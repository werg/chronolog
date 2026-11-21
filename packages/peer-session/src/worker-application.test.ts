import { createApplicationBackend } from './tendriller.js'
import { createApplicationOwner } from './session-owner.js'
import { connectApplicationOwner } from './worker-application.js'
import { serveApplicationWorker } from './worker-application-server.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, type RecoveryNotice, type SignedTransitionRequest,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'

import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import { openApplicationDevice, type ApplicationStorage } from './device.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import { AbandonedOperationError, connectApplications, type ApplicationReadView, type ApplicationSession } from './session.js'
import { connectApplicationWorker } from './worker-application.js'
import type { ApplicationControlHost } from './recovery.js'
import type { ApplicationParticipation, ApplicationParticipationStatus } from './participation-types.js'

const definition = defineApplication({ id: 'worker-messages', version: '1', commands: {
  say: defineCommand({ description: 'Write a message', input: { type: 'string', minLength: 1, maxLength: 128 },
    prepare: text => program(emit('message', { text })) }),
}, queries: {
  messages: defineQuery({ description: 'Read messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }),
} })
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture(options: { readonly closeA?: () => Promise<void>; readonly data?: boolean;
  readonly openStorageA?: () => Promise<ApplicationStorage>; readonly createMaterializerA?: OpenPeerApplicationOptions['createMaterializer'] } = {}) {
  const host = await createPeerIdentity()
  const a = await openApplicationDevice({ store: new MemoryBytesStore(), create: true, ...(options.closeA === undefined ? {} : { close: options.closeA }),
    ...(options.openStorageA === undefined ? {} : { openStorage: options.openStorageA }) })
  const b = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const execution = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: '91'.repeat(32), historyId: 'worker-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: a.identity.publicKey, executionManifestDigest: bytesToHex(execution.executionManifestDigest),
    definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId,
    profile: descriptor.payload.profile, policy: descriptor.payload.policy, revision: 0, previous: null,
    epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b].map(device => participantGrant(device.identity.publicKey, { administrator: true })),
  }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
    profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null,
    requester: a.identity.publicKey, coordinator: a.identity.publicKey, controlRevision: 0, reason: 'create', base: null,
  }, a.identity))
  const authority = await registry.read()
  const sessions = await Promise.all([a, b].map((device, index) => openPeerApplication({ device, definition, authority, epochKeys,
    ...(index !== 0 || options.createMaterializerA === undefined ? {} : { createMaterializer: options.createMaterializerA }) })))
  for (const session of sessions) {
    cleanup.push(() => session.close())
    if (options.data !== false) await session.keys.missing()
  }
  return { a: sessions[0]!, b: sessions[1]!, registry }
}

async function facade(session: ApplicationSession, host?: ApplicationControlHost, options: {
  readonly timeoutMs?: number; readonly observePort?: (port: MessagePort) => void
} = {}) {
  const endpoint = new MessageChannel()
  cleanup.push(() => { endpoint.port1.close(); endpoint.port2.close() })
  const server = serveApplicationWorker(session, endpoint.port1, host === undefined ? {} : { host })
  cleanup.push(() => server.close())
  if (options.observePort !== undefined) endpoint.port1.addEventListener('message', event => {
    const port = (event.data as { port?: MessagePort }).port
    if (port !== undefined) options.observePort!(port)
  })
  const client = await connectApplicationWorker<typeof definition>(endpoint.port2, { timeoutMs: options.timeoutMs ?? 5000 })
  cleanup.push(() => client.close())
  return { client, endpoint }
}

describe('owned browser application facade', () => {
  it('keeps an unused facade and live exchange cold, then shares first data initialization across callers', async () => {
    let release!: () => void
    const gate = new Promise<void>(resolve => { release = resolve }), closeStorage = vi.fn()
    const openStorage = vi.fn(async () => { await gate; return { store: new MemoryBytesStore(), close: closeStorage } })
    const f = await fixture({ data: false, openStorageA: openStorage }), link = await connectApplications(f.a, f.b)
    cleanup.push(() => link.close())
    const { client } = await facade(f.a), statuses: string[] = []
    const stopStatus = client.onStatus(status => statuses.push(status.database)), stopRecovery = client.onRecovery(() => {})
    const projection = f.a.project<number>({ id: 'registered-only', version: '1', initial: 0, reduce: state => state + 1 })
    expect(client.describe().id).toBe(definition.id)
    expect(client.revision).toBeNull(); expect(client.status.database).toBe('idle')
    const signals = f.b.signals.subscribe({ topics: ['typing'], signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator]()
    const incoming = signals.next()
    await client.signals.send('typing', { during: 'protocol' })
    expect((await incoming).value?.payload).toEqual({ during: 'protocol' }); await signals.return?.()
    expect(openStorage).not.toHaveBeenCalled(); expect(f.b.status.database).toBe('idle')
    let reentrant: Promise<ApplicationReadView> | undefined
    const stopReentrant = f.a.onStatus(status => { if (status.database === 'opening') reentrant ??= f.a.readView() })
    const pageView = client.readView(), localView = f.a.readView()
    await vi.waitFor(() => expect(openStorage).toHaveBeenCalledOnce())
    expect(f.a.status.database).toBe('opening'); expect(closeStorage).not.toHaveBeenCalled()
    release()
    const [page, local, reentered] = await Promise.all([pageView, localView, reentrant!])
    expect(page.revision).toEqual(local.revision); expect(reentered.revision).toEqual(local.revision)
    await page.release(); local.release(); reentered.release()
    expect(openStorage).toHaveBeenCalledOnce(); expect(client.status.database).toBe('ready')
    expect(f.b.status.database).toBe('idle'); expect(statuses).toContain('opening')
    stopReentrant(); stopRecovery(); stopStatus(); await projection.close(); await client.close()
    expect(closeStorage).toHaveBeenCalledOnce()
  })

  it('releases failed data initialization once while the same live participant remains usable', async () => {
    const failure = new Error('INITIAL_MATERIALIZER_FAILED'), closeStorage = vi.fn()
    const openStorage = vi.fn(async () => ({ store: new MemoryBytesStore(), close: closeStorage }))
    const createMaterializer = vi.fn(async () => { throw failure })
    const f = await fixture({ data: false, openStorageA: openStorage, createMaterializerA: createMaterializer })
    const link = await connectApplications(f.a, f.b); cleanup.push(() => link.close())
    const { client } = await facade(f.a)
    const requests = await Promise.allSettled([f.a.readView(), client.readView()])
    expect(requests.every(value => value.status === 'rejected' && value.reason instanceof Error && value.reason.message === failure.message)).toBe(true)
    expect(f.a.status.database).toBe('failed'); expect(f.a.signal.aborted).toBe(false)
    await expect(f.a.readView()).rejects.toBe(failure)
    expect(createMaterializer).toHaveBeenCalledOnce(); expect(openStorage).toHaveBeenCalledOnce(); expect(closeStorage).toHaveBeenCalledOnce()
    const signals = f.b.signals.subscribe({ topics: ['typing'], signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator]()
    const incoming = signals.next()
    await client.signals.send('typing', { after: 'database-failure' })
    expect((await incoming).value?.payload).toEqual({ after: 'database-failure' }); await signals.return?.()
    await client.close(); expect(closeStorage).toHaveBeenCalledOnce()
  })

  it('cancels a projection pull during first initialization and releases late storage on owner close', async () => {
    let release!: (storage: ApplicationStorage) => void
    const gate = new Promise<ApplicationStorage>(resolve => { release = resolve }), closeStorage = vi.fn()
    const openStorage = vi.fn(() => gate), createMaterializer = vi.fn(async () => { throw new Error('MUST_NOT_OPEN_AFTER_CLOSE') })
    const f = await fixture({ data: false, openStorageA: openStorage, createMaterializerA: createMaterializer })
    const projection = f.a.project<number>({ id: 'cancel-opening', version: '1', initial: 0, reduce: state => state + 1 })
    const iterator = projection.changes()[Symbol.asyncIterator](), pending = iterator.next()
    await vi.waitFor(() => expect(openStorage).toHaveBeenCalledOnce())
    await expect(iterator.next()).rejects.toThrow('APPLICATION_PROJECTION_CONCURRENT_NEXT')
    expect((await iterator.return?.())?.done).toBe(true); expect((await pending).done).toBe(true)
    const closing = f.a.close()
    expect(f.a.status.database).toBe('closed')
    release({ store: new MemoryBytesStore(), close: closeStorage })
    await closing
    expect(createMaterializer).not.toHaveBeenCalled(); expect(closeStorage).toHaveBeenCalledOnce()
    expect(f.a.revision).toBeNull()
  })

  it('waits for the specified author when different peers reuse an operation ID', async () => {
    const f = await fixture(), link = await connectApplications(f.a, f.b)
    cleanup.push(() => link.close())
    const { client } = await facade(f.a)
    const own = await (await client.command('say', 'page author', { operationId: 'same-id' })).applied()
    const other = await (await f.b.command('say', 'other author', { operationId: 'same-id' })).applied()
    await link.synchronize()
    expect(await client.operations.wait('same-id')).toEqual(own)
    expect(await client.operations.wait('same-id', { author: f.b.deviceId })).toEqual(other)
    expect((await client.operations.inspect('same-id', { author: f.b.deviceId }))?.state).toEqual(other)
    expect(own.attemptId).not.toBe(other.attemptId)
  })

  it('reads and observes durable projections without moving reducers or storage to the page', async () => {
    const f = await fixture(), reduce = vi.fn((count: number) => count + 1)
    f.a.project({ id: 'message-count', version: '1', topics: ['message'], initial: 0, reduce })
    const { client } = await facade(f.a), projection = client.projection<number>('message-count')
    expect((await projection.read()).state).toBe(0)
    const updates = projection.changes()[Symbol.asyncIterator]()
    expect((await updates.next()).value?.state).toBe(0)
    const changed = updates.next()
    await (await client.command('say', 'owned reducer', { operationId: 'projected' })).applied()
    expect((await changed).value?.state).toBe(1)
    const result = await projection.read()
    expect(result.revision).toEqual(client.revision)
    expect(result.state).toBe(1); expect(reduce).toHaveBeenCalledOnce()
    await updates.return?.(); await projection.close()
    await expect(projection.read()).rejects.toThrow('APPLICATION_PROJECTION_CLOSED')
    expect((await client.query('messages', null)).value.events).toHaveLength(1)
  })

  it('keeps page projection handles bound to the owner registration across replacement', async () => {
    const f = await fixture(), first = f.a.project<number>({ id: 'replaceable', version: '1', initial: 0, reduce: count => count + 1 })
    const { client } = await facade(f.a), old = client.projection<number>('replaceable')
    expect((await old.read()).state).toBe(0)
    const changes = old.changes()[Symbol.asyncIterator]()
    expect((await changes.next()).value?.state).toBe(0)
    const waiting = changes.next()
    await first.close()
    expect((await waiting).done).toBe(true)
    f.a.project<number>({ id: 'replaceable', version: '2', initial: 42, reduce: count => count + 1 })
    const current = client.projection<number>('replaceable')
    expect((await current.read()).state).toBe(42)
    await expect(old.read()).rejects.toThrow('APPLICATION_PROJECTION_CLOSED')
    expect((await old.changes()[Symbol.asyncIterator]().next()).done).toBe(true)
    await old.close(); await old.close()
    expect((await current.read()).state).toBe(42)
    await current.close()
    f.a.project<number>({ id: 'replaceable', version: '3', initial: 84, reduce: count => count + 1 })
    await current.close()
    expect((await client.projection<number>('replaceable').read()).state).toBe(84)
  })

  it('retires obsolete projection bindings when owners repeatedly replace registrations', async () => {
    const f = await fixture(), { client } = await facade(f.a)
    for (let index = 0; index < 12; index++) {
      const owner = f.a.project({ id: `projection-${index}`, version: '1', initial: index, reduce: count => count + 1 })
      const page = client.projection<number>(owner.id)
      expect((await page.read()).state).toBe(index)
      await owner.close()
      await expect(page.read()).rejects.toThrow('APPLICATION_PROJECTION_CLOSED')
    }
  })

  it('completes a pending projection observation when the page closes its handle', async () => {
    const f = await fixture()
    f.a.project<number>({ id: 'observed', version: '1', initial: 0, reduce: count => count + 1 })
    const { client } = await facade(f.a), projection = client.projection<number>('observed')
    const changes = projection.changes()[Symbol.asyncIterator]()
    expect((await changes.next()).value?.state).toBe(0)
    const pending = changes.next()
    await projection.close()
    expect((await pending).done).toBe(true)
    expect((await projection.changes()[Symbol.asyncIterator]().next()).done).toBe(true)
  })

  it('releases a projection while ordinary RPC capacity is occupied by passive waits', async () => {
    const f = await fixture()
    f.b.project<number>({ id: 'releasable', version: '1', initial: 0, reduce: count => count + 1 })
    const { client } = await facade(f.b), projection = client.projection<number>('releasable')
    expect((await projection.read()).state).toBe(0)
    const operation = await client.command('say', 'offline', { operationId: 'release-full' })
    const pending = Promise.allSettled(Array.from({ length: 80 }, () => operation.applied()))
    await projection.close(); await projection.close()
    expect(() => f.b.projection('releasable')).toThrow('APPLICATION_PROJECTION_NOT_FOUND')
    await client.close()
    expect((await pending).every(value => value.status === 'rejected')).toBe(true)
  })

  it('settles the requesting waiter when its response contains malformed participation metadata', async () => {
    const f = await fixture(), { client } = await facade(f.a)
    const getter = vi.spyOn(f.a, 'participation', 'get').mockReturnValue({ status: { phase: 'unknown' } } as unknown as ApplicationParticipation)
    cleanup.push(() => { getter.mockRestore() })
    let settled = false
    const query = client.query('messages', null).finally(() => { settled = true })
    const rejected = expect(query).rejects.toThrow('APPLICATION_WORKER_METADATA_INVALID')
    await vi.waitFor(() => expect(client.signal.aborted).toBe(true))
    expect(settled).toBe(true)
    await rejected
    await vi.waitFor(() => expect(f.a.status.phase).toBe('closed'))
  })

  it('releases a captured view when its completed response crosses a timed-out page waiter', async () => {
    const f = await fixture(), released = vi.fn(), read = f.a.readView.bind(f.a)
    const capture = vi.spyOn(f.a, 'readView').mockImplementation(async () => {
      const view = await read()
      return { ...view, release() { released(); view.release() } }
    })
    cleanup.push(() => { capture.mockRestore() })
    let dropped = false
    const { client } = await facade(f.a, undefined, { timeoutMs: 500, observePort(port) {
      const send = port.postMessage.bind(port)
      vi.spyOn(port, 'postMessage').mockImplementation(value => {
        const response = value as { value?: { id?: number; revision?: unknown } }
        if (!dropped && response.value?.id !== undefined && response.value.revision !== undefined) { dropped = true; return }
        send(value)
      })
    } })
    await expect(client.readView()).rejects.toThrow('APPLICATION_WORKER_TIMEOUT')
    expect(dropped).toBe(true)
    await vi.waitFor(() => expect(released).toHaveBeenCalledOnce())
    capture.mockRestore()
    const views: ApplicationReadView[] = []
    for (let index = 0; index < 8; index++) views.push(await f.a.readView())
    for (const view of views) view.release()
    expect(client.signal.aborted).toBe(false)
  })

  it('keeps applied and shared waits alive beyond the generic RPC deadline', async () => {
    const f = await fixture(), { client } = await facade(f.b, undefined, { timeoutMs: 500 })
    const operation = await client.command('say', 'waiting for a peer', { operationId: 'long-wait' })
    let appliedSettled = false, sharedSettled = false
    const applied = operation.applied(), shared = operation.shared()
    void applied.then(() => { appliedSettled = true }, () => { appliedSettled = true })
    void shared.then(() => { sharedSettled = true }, () => { sharedSettled = true })
    await new Promise(resolve => setTimeout(resolve, 600))
    expect(appliedSettled).toBe(false); expect(sharedSettled).toBe(false)
    const link = await connectApplications(f.a, f.b); cleanup.push(() => link.close())
    expect(await applied).toMatchObject({ operationId: 'long-wait', outcome: 'accepted' })
    expect(await shared).toHaveLength(1)
  })

  it('cancels a hosted recovery wait while preserving its exact durable transition', async () => {
    const f = await fixture(), requests: SignedTransitionRequest[] = []
    let entered!: () => void, blocked = true
    const started = new Promise<void>(resolve => { entered = resolve })
    const { client } = await facade(f.b, { application: () => f.registry.read(), selectGeneration(request) {
      requests.push(request)
      if (blocked) { entered(); return new Promise(() => {}) }
      return f.registry.select(request)
    } })
    const cancel = new AbortController()
    const waiting = client.recovery.takeover({ transitionId: 'cancelled-control-wait', signal: cancel.signal })
    const rejected = expect(waiting).rejects.toThrow('stop waiting for control')
    await started
    cancel.abort(new Error('stop waiting for control')); await rejected
    const journal = await client.recovery.inspect()
    expect(journal).toHaveLength(1)
    expect(journal[0]?.selected).toBeNull()
    expect(journal[0]?.request).toEqual(requests[0])
    blocked = false
    await client.recovery.takeover({ transitionId: 'cancelled-control-wait' })
    expect(requests).toHaveLength(2)
    expect(requests[1]).toEqual(requests[0])
    expect(client.status.role).toBe('coordinator')
  })

  it('observes the owner participation policy and forwards exact broader-recovery approval', async () => {
    const f = await fixture(), lifetime = new AbortController()
    const listeners = new Set<(status: ApplicationParticipationStatus) => void>()
    let status: ApplicationParticipationStatus = { phase: 'approval-required', connectedPeers: [], error: null,
      recovery: { id: 'one-proposal', coordinator: f.a.deviceId, point: f.a.revision!.point,
        reason: 'freshness-unknown', observedAt: null, ageMs: null } }
    const publish = (): void => { for (const listener of listeners) listener(status) }
    const approveRecovery = vi.fn(async (id: string) => {
      if (id !== status.recovery?.id) throw new Error('APPLICATION_RECOVERY_PROPOSAL_CHANGED')
      status = { ...status, phase: 'coordinating', recovery: null }; publish()
    })
    const participation: ApplicationParticipation = {
      get status() { return status }, signal: lifetime.signal,
      onStatus(listener) { listeners.add(listener); listener(status); return () => { listeners.delete(listener) } },
      approveRecovery, diagnostics: async () => [], reconsiderConnections: vi.fn(async () => {}),
      async close() { lifetime.abort(); status = { ...status, phase: 'closed' }; publish() },
    }
    const getter = vi.spyOn(f.a, 'participation', 'get').mockReturnValue(participation)
    cleanup.push(() => { getter.mockRestore() })
    const { client } = await facade(f.a)
    expect(client.participation?.status).toEqual(status)
    const observations: string[] = []
    client.participation!.onStatus(value => observations.push(value.phase))
    await expect(client.participation!.approveRecovery('stale-proposal')).rejects.toThrow('APPLICATION_RECOVERY_PROPOSAL_CHANGED')
    expect(client.participation?.status.phase).toBe('approval-required')
    await client.participation!.approveRecovery('one-proposal')
    expect(approveRecovery).toHaveBeenLastCalledWith('one-proposal')
    expect(client.participation?.status.phase).toBe('coordinating')
    await client.participation!.close()
    expect(client.participation?.signal.aborted).toBe(true)
    expect(observations.at(-1)).toBe('closed')
    expect(client.signal.aborted).toBe(false)
    expect((await client.query('messages', null)).value.events).toEqual([])
  })

  it('keeps keys in the owner and preserves saved intent when a page cancels its waiter', async () => {
    const f = await fixture(), { client } = await facade(f.b)
    expect(client.deviceId).toBe(f.b.deviceId)
    expect(client.storageId).toBe(f.b.storageId)
    expect(client.applicationId).toBe(f.b.applicationId)
    expect(client.describe().commands.map(value => value.name)).toEqual(['say'])
    expect(client.capabilities.sql).toBe(false)
    expect('privateKey' in client).toBe(false)
    expect(client.status.phase).toBe('waiting')
    const operation = await client.command('say', 'saved once', { operationId: 'once' })
    const original = await client.operations.inspect('once')
    const abort = new AbortController(), waiting = operation.applied({ signal: abort.signal })
    const rejected = expect(waiting).rejects.toThrow('cancel observation')
    abort.abort(new Error('cancel observation')); await rejected
    expect((await operation.get())?.status).toBe('saved')
    const link = await connectApplications(f.a, f.b); cleanup.push(() => link.close())
    const result = await operation.applied({ signal: AbortSignal.timeout(5000) })
    expect(result).toMatchObject({ status: 'applied', outcome: 'accepted', operationId: 'once' })
    await operation.retry()
    expect((await client.operations.inspect('once'))?.attempt).toEqual(original?.attempt)
    expect((await client.query('messages', null)).value.events[0]?.payload).toEqual({ text: 'saved once' })
    expect(await operation.shared({ signal: AbortSignal.timeout(5000) })).toHaveLength(1)
  })

  it('pulls coherent changes and event views, releases ownership, and reports a second facade as busy', async () => {
    const f = await fixture(), { client, endpoint } = await facade(f.a)
    await expect(connectApplicationWorker(endpoint.port2, { timeoutMs: 1000 })).rejects.toThrow('APPLICATION_WORKER_CLIENT_IN_USE')
    const changes = client.changes()[Symbol.asyncIterator]()
    expect((await changes.next()).done).toBe(false)
    const before = await client.readView()
    const operation = await client.command('say', 'new', { operationId: 'new' }); await operation.applied()
    const after = await changes.next()
    expect(after.value?.revision.point.sequence).toBe(1)
    expect((await before.readEvents()).events).toHaveLength(0)
    const current = await client.readView()
    expect((await current.readEvents()).events).toHaveLength(1)
    await before.release(); await current.release()
    await changes.return?.(); expect((await changes.next()).done).toBe(true)
    const statuses: string[] = []
    client.onStatus(status => statuses.push(status.phase))
    await client.close()
    expect(client.signal.aborted).toBe(true)
    expect(f.a.status.phase).toBe('closed')
    expect(statuses.at(-1)).toBe('closed')
    await expect(client.query('messages', null)).rejects.toThrow('APPLICATION_SESSION_CLOSED')
  })

  it('retains typed abandonment and exact hosted transition retries without exporting a signer', async () => {
    const f = await fixture()
    let loseReply = true
    const host: ApplicationControlHost = { application: () => f.registry.read(), async selectGeneration(request) {
      const selected = await f.registry.select(request)
      if (loseReply) { loseReply = false; throw new Error('lost hosted reply') }
      return selected
    } }
    const { client: a } = await facade(f.a), { client: b } = await facade(f.b, host)
    const tail = await a.command('say', 'unshared tail', { operationId: 'tail' }); await tail.applied()
    const notice = new Promise<RecoveryNotice>(resolve => b.onRecovery(resolve))
    await expect(b.recovery.takeover({ transitionId: 'recover' })).rejects.toThrow('lost hosted reply')
    const pending = await b.recovery.inspect()
    expect(pending[0]?.selected).toBeNull()
    await b.recovery.takeover({ transitionId: 'recover' })
    expect((await b.recovery.inspect())[0]?.request).toEqual(pending[0]?.request)
    expect((await notice).generation).toBe((await f.registry.read()).generations.at(-1)?.id)
    await a.adopt(await f.registry.read())
    await expect(tail.applied()).rejects.toBeInstanceOf(AbandonedOperationError)
    expect((await a.inspectRecovery()).at(-1)?.abandoned[0]?.operationId).toBe('tail')
    const link = await connectApplications(f.a, f.b); cleanup.push(() => link.close())
    const again = await a.reapply('tail', 'say', 'reviewed', { operationId: 'again', basedOn: (await a.query('messages', null)).revision })
    expect((await again.applied()).outcome).toBe('accepted')
    expect((await tail.get())?.status).toBe('abandoned')
  })

  it.each(['page', 'owner'] as const)('acknowledges %s close only after the owning device finishes releasing storage', async source => {
    let release!: () => void, started!: () => void
    const released = new Promise<void>(resolve => { release = resolve })
    const closing = new Promise<void>(resolve => { started = resolve })
    const f = await fixture({ closeA: async () => { started(); await released } })
    const { client } = await facade(f.a)
    let complete = false
    const ownerClose = source === 'owner' ? f.a.close() : Promise.resolve()
    const closed = client.close().then(() => { complete = true })
    await closing
    expect(complete).toBe(false)
    release(); await Promise.all([closed, ownerClose])
    expect(complete).toBe(true)
  })

  it('carries disposable signals and chunked content without a second command journal', async () => {
    const f = await fixture(), link = await connectApplications(f.a, f.b)
    cleanup.push(() => link.close())
    const { client: a } = await facade(f.a), { client: b } = await facade(f.b)
    const signal = b.signals.subscribe({ topics: ['typing'], signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator]()
    const next = signal.next()
    // A public stream readiness boundary also waits until the queued subscription is installed.
    await b.query('messages', null)
    await a.signals.send('typing', { typing: true })
    expect((await next).value?.payload).toEqual({ typing: true }); await signal.return?.()
    const bytes = new Uint8Array([3, 1, 4, 1, 5]), upload = await a.content.stage({ bytes: bytes.length })
    await upload.write(0, bytes)
    expect((await upload.progress()).missingChunks).toEqual([])
    const reference = await (await a.content.resume(upload.id)).commit()
    await b.content.retain(reference)
    const chunks: Uint8Array[] = []
    for await (const chunk of b.content.read(reference)) chunks.push(chunk)
    expect(chunks).toEqual([bytes])
    expect((await b.content.retained(reference)).payload.peer).toBe(b.deviceId)
    expect((await a.content.retention(reference)).some(value => value.payload.peer === b.deviceId)).toBe(true)
    expect((await a.query('messages', null)).value.events).toHaveLength(0)
  })

  it('bounds pending waits and page streams while leaving a cancelled command inspectable', async () => {
    const f = await fixture(), { client } = await facade(f.b)
    const operation = await client.command('say', 'offline', { operationId: 'offline' })
    const abort = new AbortController()
    const pending = Promise.allSettled(Array.from({ length: 80 }, () => operation.applied({ signal: abort.signal })))
    abort.abort(new Error('stop all waits'))
    const outcomes = await pending
    expect(outcomes.every(value => value.status === 'rejected')).toBe(true)
    expect(outcomes.some(value => value.status === 'rejected' && String(value.reason).includes('APPLICATION_WORKER_REQUEST_LIMIT'))).toBe(true)
    expect((await operation.get())?.status).toBe('saved')
    const streams = Array.from({ length: 14 }, () => client.changes()[Symbol.asyncIterator]())
    expect(() => client.changes()[Symbol.asyncIterator]()).toThrow('APPLICATION_WORKER_STREAM_LIMIT')
    await Promise.all(streams.map(stream => stream.return!()))
    await expect(client.command('say', '💬'.repeat(300_000), { operationId: 'oversized' })).rejects.toThrow('APPLICATION_WORKER_MESSAGE_LIMIT')
    expect(await client.operations.get('oversized')).toBeNull()
  })

  it('closes the owned session even when every ordinary RPC slot is waiting offline', async () => {
    const f = await fixture(), { client } = await facade(f.b)
    const operation = await client.command('say', 'offline', { operationId: 'close-full' })
    const pending = Promise.allSettled(Array.from({ length: 80 }, () => operation.applied()))
    await client.close()
    expect(client.signal.aborted).toBe(true)
    expect(f.b.status.phase).toBe('closed')
    expect((await pending).every(value => value.status === 'rejected')).toBe(true)
  })

  it('rejects malformed query capabilities in Worker readiness metadata', async () => {
    const f = await fixture(), description = f.a.describe()
    const metadata = vi.spyOn(f.a, 'describe').mockReturnValue({ ...description,
      capabilities: { ...description.capabilities, sql: 'yes' as unknown as boolean } })
    try { await expect(facade(f.a)).rejects.toThrow('APPLICATION_WORKER_METADATA_INVALID') }
    finally { metadata.mockRestore() }
  })
})

describe('many endpoints attached to one owner', () => {
  async function owned(session: ApplicationSession, options: Parameters<typeof createApplicationOwner>[1] = {}) {
    const endpoint = new MessageChannel(), owner = createApplicationOwner(session, options)
    cleanup.push(() => { endpoint.port1.close(); endpoint.port2.close() }); cleanup.push(() => owner.close())
    owner.attach(endpoint.port1)
    const connect = async (context: { viewId?: string; documentPath?: string; runId?: string } = {}) => {
      const client = await connectApplicationOwner<typeof definition>(endpoint.port2, {
        applicationId: session.applicationId, definitionId: definition.id, definitionVersion: definition.version, context, timeoutMs: 5000,
      })
      cleanup.push(() => client.detach()); return client
    }
    return { owner, endpoint, connect }
  }

  it('reads cloned verified authority without storage demand and checks the attachment diagnostics grant', async () => {
    const openStorage = vi.fn(async () => ({ store: new MemoryBytesStore(), close: () => undefined }))
    const f = await fixture({ data: false, openStorageA: openStorage }), first = await owned(f.a)
    const client = await first.connect(), authority = await client.authority()
    expect(authority).toEqual(await f.registry.read())
    Object.assign(authority.controls[0]!.payload, { grants: [] })
    expect((await client.authority()).controls[0]!.payload.grants).toHaveLength(2)
    expect((await f.a.authority()).controls[0]!.payload.grants).toHaveLength(2)
    expect(openStorage).not.toHaveBeenCalled(); expect(f.a.status.database).toBe('idle')
    const restricted = await owned(f.b, { authorize: () => ({ capabilities: ['signals'] }) })
    const endpoint = await restricted.connect()
    await expect(endpoint.authority()).rejects.toThrow('APPLICATION_ATTACHMENT_FORBIDDEN')
    expect(f.b.status.database).toBe('idle')
    await endpoint.detach()
    expect((await client.authority()).descriptor.payload.applicationId).toBe(client.applicationId)
  })

  it('rejects observer-incompatible attachment quotas before ready without harming subsequent clients', async () => {
    const f = await fixture()
    const observers = f.a.participation === undefined ? 2 : 3
    const { owner, connect } = await owned(f.a, { authorize: handshake => {
      if (handshake.context?.documentPath === '/streams') return { maxStreams: observers }
      if (handshake.context?.documentPath === '/requests') return { maxRequests: observers }
      return { capabilities: ['signals'], maxStreams: 1, maxRequests: 1 }
    } })
    await expect(connect({ documentPath: '/streams' })).rejects.toThrow('APPLICATION_ATTACHMENT_OBSERVER_LIMIT')
    await expect(connect({ documentPath: '/requests' })).rejects.toThrow('APPLICATION_ATTACHMENT_OBSERVER_LIMIT')
    expect(owner.endpoints()).toHaveLength(0)
    const lean = await connect({ documentPath: '/signals' })
    expect(lean.signal.aborted).toBe(false)
    expect(owner.endpoints()).toHaveLength(1)
    await lean.suspend()
    expect((await lean.resumeAttachment())?.endpointId).toBe(lean.endpoint?.endpointId)
    await expect(lean.authority()).rejects.toThrow('APPLICATION_ATTACHMENT_FORBIDDEN')
    expect(lean.signal.aborted).toBe(false)
  })

  it('rejects inadequate global observer budgets before accepting an endpoint', async () => {
    const f = await fixture()
    const { owner, connect } = await owned(f.a, { maxStreams: 1, maxRequests: 1 })
    await expect(connect()).rejects.toThrow('APPLICATION_ATTACHMENT_OBSERVER_LIMIT')
    expect(owner.endpoints()).toHaveLength(0)
    expect(f.a.signal.aborted).toBe(false)
  })

  it('binds independent endpoints to one lazy session; detach preserves sibling and signed work', async () => {
    const openStorage = vi.fn(async () => ({ store: new MemoryBytesStore(), close: () => undefined }))
    const f = await fixture({ data: false, openStorageA: openStorage }), { owner, connect } = await owned(f.a)
    const [left, right] = await Promise.all([connect({ viewId: 'draft-a', documentPath: '/board.html' }), connect({ viewId: 'draft-b', documentPath: '/review.html' })])
    expect(left.deviceId).toBe(right.deviceId)
    expect(left.endpoint?.ownerInstanceId).toBe(right.endpoint?.ownerInstanceId)
    expect(left.endpoint?.endpointId).not.toBe(right.endpoint?.endpointId)
    expect(left.endpoint?.endpointIncarnation).not.toBe(right.endpoint?.endpointIncarnation)
    const backend = createApplicationBackend({ id: f.a.applicationId, session: left })
    expect(backend.endpoint).toBe(left.endpoint)
    expect(Object.isFrozen(backend.endpoint?.context)).toBe(true)
    expect(openStorage).not.toHaveBeenCalled(); expect(f.a.status.database).toBe('idle')
    expect(owner.endpoints()).toHaveLength(2)
    const [one, two] = await Promise.all([
      left.command('say', 'left document', { operationId: 'left' }), right.command('say', 'right document', { operationId: 'right' }),
    ])
    await Promise.all([one.applied(), two.applied()]); await left.detach()
    expect(f.a.signal.aborted).toBe(false); expect(owner.endpoints()).toHaveLength(1)
    expect((await right.query('messages', null)).value.events.map(event => event.payload)).toEqual([{ text: 'left document' }, { text: 'right document' }])
    expect((await right.operations.inspect('left'))?.state.status).toBe('applied')
    await right.detach(); expect(f.a.signal.aborted).toBe(false)
    await owner.close(); expect(f.a.signal.aborted).toBe(true)
  })

  it('keeps two signal-only attachments cold and injects endpoint identity over forged options', async () => {
    const openStorage = vi.fn(async () => ({ store: new MemoryBytesStore(), close: () => undefined }))
    const f = await fixture({ data: false, openStorageA: openStorage }), link = await connectApplications(f.a, f.b)
    cleanup.push(() => link.close())
    const { connect } = await owned(f.a), [one, two] = await Promise.all([connect({ runId: 'run-one' }), connect({ runId: 'run-two' })])
    const signals = f.b.signals.subscribe({ topics: ['progress'], mode: 'latest' })[Symbol.asyncIterator](), first = signals.next()
    await one.signals.send('progress', 1, { stream: { streamId: 'run-one', endpointId: 'forged', endpointIncarnation: 'forged' } })
    const observed = (await first).value!
    expect(observed.stream?.endpointId).toBe(one.endpoint?.endpointId)
    expect(observed.stream?.endpointIncarnation).toBe(one.endpoint?.endpointIncarnation)
    await one.signals.send('progress', 2, { stream: { streamId: 'run-one' } })
    await two.signals.send('progress', 3, { stream: { streamId: 'run-two' } })
    expect((await signals.next()).value?.payload).toBe(2); expect((await signals.next()).value?.payload).toBe(3)
    await signals.return?.(); expect(openStorage).not.toHaveBeenCalled(); expect(f.b.status.database).toBe('idle')
  })

  it('isolates malformed clients and never grants owner management from a page field', async () => {
    const f = await fixture(), { endpoint, owner, connect } = await owned(f.a)
    let malicious: MessagePort | undefined
    endpoint.port1.addEventListener('message', event => { malicious ??= (event.data as { port: MessagePort }).port })
    const first = await connect(), sibling = await connect()
    await expect(first.participation?.close() ?? first.adopt(await f.registry.read())).rejects.toThrow('APPLICATION_ATTACHMENT_FORBIDDEN')
    malicious!.dispatchEvent(new MessageEvent('message', { data: { id: -1, method: 'query', args: [] } }))
    await vi.waitFor(() => expect(first.signal.aborted).toBe(true))
    expect(f.a.signal.aborted).toBe(false); expect(owner.endpoints()).toHaveLength(1)
    expect((await sibling.query('messages', null)).value.events).toHaveLength(0)
  })

  it('gives duplicated live views independent drafts and permits explicit restore after detach', async () => {
    const f = await fixture({ data: false }), { connect } = await owned(f.a)
    const first = await connect({ viewId: 'retained-view' }), duplicate = await connect({ viewId: 'retained-view' })
    expect(first.endpoint?.context.viewId).toBe('retained-view')
    expect(duplicate.endpoint?.context.viewId).not.toBe('retained-view')
    await first.suspend(); expect((await duplicate.endpoints()).find(value => value.endpointId === first.endpoint?.endpointId)?.state).toBe('suspended')
    expect((await first.resumeAttachment())?.endpointIncarnation).toBe(first.endpoint?.endpointIncarnation)
    await first.detach()
    const restored = await connect({ viewId: 'retained-view' })
    expect(restored.endpoint?.context.viewId).toBe('retained-view')
    expect(restored.endpoint?.endpointIncarnation).not.toBe(first.endpoint?.endpointIncarnation)
  })

  it('rejects incompatible applications and grants only owner-configured capabilities', async () => {
    const f = await fixture(), { endpoint, owner, connect } = await owned(f.a, { authorize: () => ({ capabilities: ['queries', 'diagnostics'], queries: ['messages'] }) })
    await expect(connectApplicationOwner(endpoint.port2, { applicationId: f.a.applicationId, definitionId: definition.id, definitionVersion: 'incompatible', timeoutMs: 5000 })).rejects.toThrow('CONTRACT_INCOMPATIBLE')
    const client = await connect()
    await expect(client.command('say', 'forbidden', { operationId: 'denied' })).rejects.toThrow('APPLICATION_ATTACHMENT_FORBIDDEN')
    const captured = await client.readView()
    await expect(captured.query('SELECT 1')).rejects.toThrow('APPLICATION_ATTACHMENT_QUERY_FORBIDDEN')
    await expect(captured.readEvents()).rejects.toThrow('APPLICATION_ATTACHMENT_FORBIDDEN')
    await captured.release()
    expect((await client.query('messages', null)).value.events).toHaveLength(0)
    expect(owner.endpoints()).toHaveLength(1)
  })

  it('keeps raw captured SQL, named query scopes, event reads and view cleanup under independent grants', async () => {
    const f = await fixture(), read = f.a.readView.bind(f.a), rawQuery = vi.fn(() => ({ columns: [{ name: 'value' }], rows: [[7]] }))
    vi.spyOn(f.a, 'readView').mockImplementation(async () => ({ ...await read(), query: rawQuery }))
    const { connect } = await owned(f.a, { authorize: handshake => handshake.context?.documentPath === '/named'
      ? { capabilities: ['queries', 'events'], queries: ['messages'] }
      : handshake.context?.documentPath === '/events' ? { capabilities: ['events'] } : { capabilities: ['queries'] } })
    const named = await connect({ documentPath: '/named' }), events = await connect({ documentPath: '/events' }), sql = await connect({ documentPath: '/sql' })
    const namedView = await named.readView(), eventsView = await events.readView(), sqlView = await sql.readView()
    await expect(namedView.query('SELECT private_data FROM secret')).rejects.toThrow('APPLICATION_ATTACHMENT_QUERY_FORBIDDEN')
    await expect(eventsView.query('SELECT private_data FROM secret')).rejects.toThrow('APPLICATION_ATTACHMENT_FORBIDDEN')
    expect(rawQuery).not.toHaveBeenCalled()
    expect((await named.query('messages', null)).value.events).toHaveLength(0)
    expect((await eventsView.readEvents()).events).toHaveLength(0)
    await expect(sqlView.readEvents()).rejects.toThrow('APPLICATION_ATTACHMENT_FORBIDDEN')
    expect((await sqlView.query('SELECT 7 AS value')).rows).toEqual([[7]])
    expect(rawQuery).toHaveBeenCalledOnce()
    await Promise.all([namedView.release(), eventsView.release(), sqlView.release()])
    // A denial leaves the held-view reservation releasable and the owner live.
    const again = await sql.readView(); await again.release(); expect(f.a.signal.aborted).toBe(false)
  })

  it('releases an attachment projection without closing another observer or owner registration', async () => {
    const f = await fixture(), { connect } = await owned(f.a)
    f.a.project<number>({ id: 'shared-counter', version: '1', initial: 0, reduce: value => value + 1 })
    const first = await connect(), second = await connect(), one = first.projection<number>('shared-counter'), two = second.projection<number>('shared-counter')
    await Promise.all([one.read(), two.read()]); await one.close()
    expect((await two.read()).state).toBe(0)
    await first.detach()
    await (await second.command('say', 'still owned', { operationId: 'projection-sibling' })).applied()
    expect((await two.read()).state).toBe(1)
    expect(f.a.projection('shared-counter').id).toBe('shared-counter')
  })

  it('bounds views and attachments without sacrificing sibling progress', async () => {
    const f = await fixture(), { connect } = await owned(f.a, { maxAttachments: 2, authorize: () => ({ maxViews: 1 }) })
    const [one, two] = await Promise.all([connect(), connect()]); await expect(connect()).rejects.toThrow('APPLICATION_OWNER_ATTACHMENT_LIMIT')
    const held = await one.readView(); await expect(one.readView()).rejects.toThrow('APPLICATION_WORKER_VIEW_LIMIT')
    expect((await two.query('messages', null)).value.events).toHaveLength(0)
    await one.detach(); expect((await held.release().catch(() => undefined))).toBeUndefined()
    const third = await connect(); expect((await third.query('messages', null)).value.events).toHaveLength(0)
  })
})


it('exposes only finite facade deadlines and clears them on timeout, response and close', async () => {
  const f = await fixture(), { client } = await facade(f.a, undefined, { timeoutMs: 30000 })
  await vi.waitFor(() => expect(client.boundedRequest).toBeNull())
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  const query = vi.spyOn(f.a, 'query').mockImplementation(async () => { await gate; return { revision: f.a.revision!, value: [] } })
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] })
  try {
    const first = client.query('messages', null), firstRejected = first.catch(error => error as unknown)
    expect(client.boundedRequest).toEqual({ startedAt: 0, deadline: 30000 })
    const copy = client.boundedRequest!
    Reflect.set(copy, 'deadline', Infinity)
    expect(client.boundedRequest!.deadline).toBe(30000)
    await vi.advanceTimersByTimeAsync(1000)
    const second = client.query('messages', null), secondRejected = second.catch(error => error as unknown)
    expect(client.boundedRequest!.startedAt).toBe(0)
    await vi.advanceTimersByTimeAsync(16000)
    expect(client.signal.aborted).toBe(false)
    expect(client.boundedRequest!.deadline).toBe(30000)
    await vi.advanceTimersByTimeAsync(13000)
    expect(await firstRejected).toMatchObject({ message: 'APPLICATION_WORKER_TIMEOUT' })
    expect(client.boundedRequest).toEqual({ startedAt: 1000, deadline: 31000 })
    await vi.advanceTimersByTimeAsync(1000)
    expect(await secondRejected).toMatchObject({ message: 'APPLICATION_WORKER_TIMEOUT' })
    expect(client.boundedRequest).toBeNull()
  } finally { release(); query.mockRestore(); vi.useRealTimers() }
  await client.query('messages', null)
  expect(client.boundedRequest).toBeNull()
  await client.close()
  expect(client.boundedRequest).toBeNull()
})

it('excludes passive applied and change waits from bounded facade activity', async () => {
  const f = await fixture(), { client } = await facade(f.a, undefined, { timeoutMs: 30000 })
  await vi.waitFor(() => expect(client.boundedRequest).toBeNull())
  await f.a.pauseOrdering('bounded-request-test')
  const operation = await client.command('say', 'saved', { operationId: 'passive-deadline' })
  const controller = new AbortController()
  const waiting = operation.applied({ signal: controller.signal }).catch(() => undefined)
  const stream = client.changes({ signal: controller.signal })[Symbol.asyncIterator]()
  await stream.next()
  const next = stream.next()
  await vi.waitFor(() => expect(client.boundedRequest).toBeNull())
  controller.abort(Error('TEST_CANCELLED'))
  await waiting; await next; await stream.return?.()
  expect(client.boundedRequest).toBeNull()
})

it('withdraws finite request metadata immediately on caller cancellation', async () => {
  const f = await fixture(), { client } = await facade(f.a, undefined, { timeoutMs: 30000 })
  await vi.waitFor(() => expect(client.boundedRequest).toBeNull())
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  const send = vi.spyOn(f.a.signals, 'send').mockImplementation(async () => { await gate; throw Error('CANCELLED_TEST_WORK') })
  const controller = new AbortController()
  try {
    const result = client.signals.send('held', { value: true }, { signal: controller.signal }).catch(error => error as unknown)
    expect(client.boundedRequest?.deadline).toBeGreaterThan(performance.now())
    controller.abort(Error('CALLER_CANCELLED'))
    expect(client.boundedRequest).toBeNull()
    expect(await result).toMatchObject({ message: 'CALLER_CANCELLED' })
  } finally { release(); send.mockRestore() }
})

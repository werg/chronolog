import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, type RecoveryNotice,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'

import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication } from './runtime.js'
import { AbandonedOperationError, connectApplications, type ApplicationReadView, type ApplicationSession } from './session.js'
import { connectApplicationWorker, serveApplicationWorker } from './worker-application.js'
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

async function fixture(options: { readonly closeA?: () => Promise<void> } = {}) {
  const host = await createPeerIdentity()
  const a = await openApplicationDevice({ store: new MemoryBytesStore(), create: true, ...(options.closeA === undefined ? {} : { close: options.closeA }) })
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
  const sessions = await Promise.all([a, b].map(device => openPeerApplication({ device, definition, authority, epochKeys })))
  for (const session of sessions) cleanup.push(() => session.close())
  return { a: sessions[0]!, b: sessions[1]!, registry }
}

async function facade(session: ApplicationSession, host?: ApplicationControlHost) {
  const endpoint = new MessageChannel()
  cleanup.push(() => { endpoint.port1.close(); endpoint.port2.close() })
  const server = serveApplicationWorker(session, endpoint.port1, host === undefined ? {} : { host })
  cleanup.push(() => server.close())
  const client = await connectApplicationWorker<typeof definition>(endpoint.port2, { timeoutMs: 5000 })
  cleanup.push(() => client.close())
  return { client, endpoint }
}

describe('owned browser application facade', () => {
  it('observes the owner participation policy and forwards exact broader-recovery approval', async () => {
    const f = await fixture(), lifetime = new AbortController()
    const listeners = new Set<(status: ApplicationParticipationStatus) => void>()
    let status: ApplicationParticipationStatus = { phase: 'approval-required', connectedPeers: [], error: null,
      recovery: { id: 'one-proposal', coordinator: f.a.deviceId, point: f.a.revision.point,
        reason: 'freshness-unknown', observedAt: null, ageMs: null } }
    const publish = (): void => { for (const listener of listeners) listener(status) }
    const approveRecovery = vi.fn(async (id: string) => {
      if (id !== status.recovery?.id) throw new Error('APPLICATION_RECOVERY_PROPOSAL_CHANGED')
      status = { ...status, phase: 'coordinating', recovery: null }; publish()
    })
    const participation: ApplicationParticipation = {
      get status() { return status }, signal: lifetime.signal,
      onStatus(listener) { listeners.add(listener); listener(status); return () => { listeners.delete(listener) } },
      approveRecovery,
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

  it('rejects malformed query capabilities in Worker readiness metadata', async () => {
    const f = await fixture(), description = f.a.describe()
    const metadata = vi.spyOn(f.a, 'describe').mockReturnValue({ ...description,
      capabilities: { ...description.capabilities, sql: 'yes' as unknown as boolean } })
    try { await expect(facade(f.a)).rejects.toThrow('APPLICATION_WORKER_METADATA_INVALID') }
    finally { metadata.mockRestore() }
  })
})

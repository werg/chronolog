import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bytesDigest, createGenerationRegistry, createParticipantResponse, createPeerIdentity, MemoryBytesStore, participantGrant, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type SignedTransitionRequest, type ParticipantRequest, type SignedGeneration,
} from '@chronolog/peer-generation'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { defineApplication, defineCommand, applicationDefinitionDigest } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import { createFramedPeerConnectionPair, type FramedPeerConnection } from './network.js'
import { connectApplications, type ApplicationSession } from './session.js'
import type { ApplicationControlHost } from './recovery.js'
import type {
  ApplicationDiscoveryPort, ApplicationParticipationOptions, ApplicationPeerHint, ApplicationPeerInvitation, ApplicationTransportPort,
} from './participation-types.js'

const definition = defineApplication({ id: 'participation', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
}, queries: {} })
const closing: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of closing.splice(0).reverse()) await close(); vi.restoreAllMocks() })

/** Delivery only: real session handshakes, signed authority and history run on these framed pairs. */
class Introductions {
  readonly directory = new Map<string, ApplicationPeerHint>()
  readonly #listeners = new Map<string, (value: ApplicationPeerInvitation) => void>()
  readonly #connections = new Map<string, FramedPeerConnection>()
  readonly counts = { reads: 0, advertisements: 0, withdrawals: 0, opens: 0 }
  unavailable = false
  ports(identity: string): { discovery: ApplicationDiscoveryPort; transport: ApplicationTransportPort } {
    const hub = this
    return {
      discovery: {
        async read({ signal }) { signal.throwIfAborted(); hub.counts.reads++; if (hub.unavailable) throw new Error('DIRECTORY_OFFLINE'); return [...hub.directory.values()] },
        async advertise(value, { signal }) {
          signal.throwIfAborted(); hub.counts.advertisements++; if (hub.unavailable) throw new Error('DIRECTORY_OFFLINE')
          hub.directory.set(identity, { identity: value.identity, route: value.identity })
        },
        async withdraw({ signal }) { signal.throwIfAborted(); hub.counts.withdrawals++; hub.directory.delete(identity) },
        async *invitations({ signal }) {
          const queue: ApplicationPeerInvitation[] = []
          let notify = (): void => {}
          const accept = (value: ApplicationPeerInvitation): void => { queue.push(value); notify() }
          hub.#listeners.set(identity, accept)
          try {
            while (!signal.aborted) {
              if (queue.length === 0) await new Promise<void>(resolve => {
                const done = (): void => { signal.removeEventListener('abort', done); resolve() }
                notify = done; signal.addEventListener('abort', done, { once: true }); if (signal.aborted) done()
              })
              const value = queue.shift(); if (value !== undefined) yield value
            }
          } finally { if (hub.#listeners.get(identity) === accept) hub.#listeners.delete(identity) }
        },
      },
      transport: {
        async open(input, { signal }) {
          signal.throwIfAborted(); hub.counts.opens++
          if (input.invitation !== undefined) {
            if (typeof input.invitation !== 'string') throw new Error('INVITATION_INVALID')
            const connection = hub.#connections.get(input.invitation)
            if (connection === undefined) throw new Error('INVITATION_EXPIRED')
            hub.#connections.delete(input.invitation); return connection
          }
          const target = hub.#listeners.get(input.peer.identity)
          if (target === undefined) throw new Error('PEER_UNAVAILABLE')
          const [left, right] = createFramedPeerConnectionPair(), token = crypto.randomUUID()
          hub.#connections.set(token, right)
          target({ peer: { identity, route: identity }, token })
          return left
        },
      },
    }
  }
}

async function fixture(options: { omitC?: boolean } = {}) {
  const signer = await createPeerIdentity(), stores = [new MemoryBytesStore(), new MemoryBytesStore(), new MemoryBytesStore()]
  const devices = await Promise.all(stores.map(store => openApplicationDevice({ store, create: true })))
  const [a, b, c] = devices as [typeof devices[number], typeof devices[number], typeof devices[number]]
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: 'df'.repeat(32), historyId: 'participation',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: signer.publicKey,
    schemaAdministrator: a.identity.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, signer)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: devices.filter(device => options.omitC !== true || device !== c).map(device => participantGrant(device.identity.publicKey, { administrator: true, dataRole: 'member' })) }, signer)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
    profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null,
    coordinator: a.identity.publicKey, requester: a.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, a.identity))
  const hub = new Introductions(), requests: SignedTransitionRequest[] = []
  const counts = { reads: 0, selections: 0 }
  let offline = false, loseSelection = false
  const host: ApplicationControlHost = {
    async application() { counts.reads++; if (offline) throw new Error('CONTROL_OFFLINE'); return registry.read() },
    async selectGeneration(request) {
      counts.selections++; requests.push(structuredClone(request)); if (offline) throw new Error('CONTROL_OFFLINE')
      const selected = await registry.select(request)
      if (loseSelection) { loseSelection = false; throw new Error('LOST_SELECTION_REPLY') }
      return selected
    },
  }
  const open = async (device: typeof a, createMaterializer?: OpenPeerApplicationOptions['createMaterializer']) => {
    const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys,
      ...(createMaterializer === undefined ? {} : { createMaterializer }) })
    closing.push(() => session.close()); return session
  }
  const participate = (session: ApplicationSession, overrides: Partial<ApplicationParticipationOptions> = {}) => session.participate({
    control: host, ...hub.ports(session.deviceId), recovery: { graceMs: 25, freshnessMs: 300_000 },
    connections: { maxPeers: 2, retryInitialMs: 5, retryMaxMs: 20, timeoutMs: 2000, advertiseMs: 15_000 }, ...overrides,
  })
  return { a, b, c, stores, registry, hub, host, counts, requests, open, participate, signer, descriptor, control,
    offline(value: boolean) { offline = value }, loseSelection() { loseSelection = true } }
}

async function until(check: () => boolean | Promise<boolean>): Promise<void> {
  await vi.waitFor(async () => { expect(await check()).toBe(true) }, { timeout: 5000, interval: 5 })
}
async function post(session: ApplicationSession<typeof definition>, id: string) {
  const operation = await session.command('say', id, { operationId: id })
  await operation.applied({ signal: AbortSignal.timeout(5000) }); return operation
}

describe('owned application participation', () => {
  it('discovers authenticated peers and saves ordinary commands without command-correlated host traffic', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const first = f.participate(a), second = f.participate(b)
    await until(() => first.status.phase === 'coordinating' && second.status.phase === 'following')
    expect(second.status.connectedPeers).toContain(a.deviceId)
    const before = { ...f.counts, ...f.hub.counts }
    const operation = await post(b, 'once')
    await operation.shared({ signal: AbortSignal.timeout(5000) })
    expect({ ...f.counts, ...f.hub.counts }).toEqual(before)
    expect(() => f.participate(b)).toThrow('APPLICATION_PARTICIPATION_ALREADY_STARTED')
    await second.close()
    expect(b.participation).toBe(second); expect(second.status.phase).toBe('closed')
    expect(() => f.participate(b)).toThrow('APPLICATION_PARTICIPATION_ALREADY_STARTED')
    expect(b.signal.aborted).toBe(false)
  })

  it('automatically selects a verified survivor after grace and exactly retries a lost selection reply', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    f.participate(a); const participation = f.participate(b)
    await until(() => participation.status.phase === 'following')
    await (await post(b, 'retained')).shared({ signal: AbortSignal.timeout(5000) })
    const oldGeneration = b.revision.generation
    f.loseSelection(); await a.close()
    const operation = await b.command('say', 'saved during grace', { operationId: 'during-grace' })
    await until(() => participation.status.phase === 'coordinating')
    expect(b.revision.generation).not.toBe(oldGeneration)
    expect(f.requests.length).toBe(2); expect(f.requests[1]).toEqual(f.requests[0])
    expect(await operation.get()).toMatchObject({ status: 'needsReapply' })
    const reapplied = await b.reapply('during-grace', 'say', 'reviewed after recovery', { operationId: 'after-recovery' })
    expect((await reapplied.applied({ signal: AbortSignal.timeout(5000) })).status).toBe('applied')
    expect((await b.recovery.inspect())[0]?.selected).toBe(b.revision.generation)
  })

  it('reconnects through available delivery routes while the control service is unavailable', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    f.offline(true)
    f.participate(a); const participation = f.participate(b)
    const operation = await b.command('say', 'saved until authenticated reconnection', { operationId: 'rejoin' })
    await until(() => participation.status.phase === 'following')
    expect((await operation.applied({ signal: AbortSignal.timeout(5000) })).status).toBe('applied')
    expect(f.requests).toHaveLength(0)
  })

  it('requires explicit approval for an unknown complete prefix and keeps saved commands during host outage', async () => {
    const f = await fixture(), b = await f.open(f.b), participation = f.participate(b)
    const operation = await b.command('say', 'waiting', { operationId: 'waiting' })
    await until(() => participation.status.phase === 'approval-required')
    const proposal = participation.status.recovery!
    expect(proposal).toMatchObject({ coordinator: b.deviceId, reason: 'freshness-unknown', observedAt: null, ageMs: null })
    expect(f.requests).toHaveLength(0)
    await expect(participation.approveRecovery('stale')).rejects.toThrow('APPLICATION_RECOVERY_APPROVAL_STALE')
    f.offline(true); f.hub.unavailable = true
    await participation.approveRecovery(proposal.id)
    await until(() => participation.status.error === 'CONTROL_OFFLINE')
    expect(await operation.get()).toMatchObject({ status: 'saved' })
    expect(f.requests).toHaveLength(0)
    f.offline(false); f.hub.unavailable = false
    await until(() => participation.status.phase === 'coordinating')
    expect(await operation.get()).toMatchObject({ status: 'needsReapply' })
    await expect((await post(b, 'new-generation')).get()).resolves.toMatchObject({ status: 'applied' })
  })

  it('resumes a saved handover request through the same exact transition journal', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    closing.push(() => link.close())
    await post(a, 'retained'); await link.synchronize()
    f.loseSelection()
    await expect(a.recovery.handover(f.host, { coordinator: b.deviceId, transitionId: 'handover' })).rejects.toThrow('LOST_SELECTION_REPLY')
    const original = (await a.recovery.inspect())[0]!.request
    const participation = f.participate(a)
    await until(async () => (await a.recovery.inspect())[0]?.selected !== null)
    expect(f.requests).toEqual([original, original])
    expect(participation.status.phase).not.toBe('approval-required')
    expect(a.revision.generation).toBe((await f.registry.read()).generations.at(-1)?.id)
  })

  it('requires approval after an idle coordinator observation exceeds the local freshness budget', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    f.participate(a)
    const participation = f.participate(b, { recovery: { graceMs: 100, freshnessMs: 50 } })
    await until(() => participation.status.phase === 'following')
    await a.close()
    await until(() => participation.status.phase === 'approval-required')
    expect(participation.status.recovery).toMatchObject({ reason: 'older-than-budget', point: b.revision.point })
    expect(participation.status.recovery!.ageMs).toBeGreaterThan(50)
    expect(f.requests).toHaveLength(0)
  })

  it('does not reuse an approved proposal after a host refresh selects another generation', async () => {
    const f = await fixture(), b = await f.open(f.b)
    let armed = false, reads = 0
    const control: ApplicationControlHost = { ...f.host, async application(options) {
      if (armed && ++reads === 2) {
        await f.registry.select(await signTransitionRequest({ applicationId: b.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
          expectedGeneration: b.revision.generation, coordinator: f.c.identity.publicKey, requester: f.c.identity.publicKey,
          controlRevision: 0, base: await b.recoveryPoint(), transitionId: 'competing', reason: 'takeover' }, f.c.identity))
      }
      return f.host.application(options)
    } }
    const participation = f.participate(b, { control })
    await until(() => participation.status.phase === 'approval-required')
    const original = participation.status.recovery!
    armed = true; await participation.approveRecovery(original.id)
    await until(() => participation.status.phase === 'approval-required' && participation.status.recovery?.id !== original.id)
    expect(f.requests).toHaveLength(0)
    expect(await b.recovery.inspect()).toEqual([])
    await expect(participation.approveRecovery(original.id)).rejects.toThrow('APPLICATION_RECOVERY_APPROVAL_STALE')
  })

  it('rejects an expected recovery prefix if new authenticated history arrives before signing', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const expected = { generation: b.revision.generation, controlRevision: b.revision.controlRevision, point: b.revision.point }
    const link = await connectApplications(a, b)
    closing.push(() => link.close())
    await post(a, 'new-head'); await link.synchronize()
    await expect(b.recovery.takeover(f.host, { expected })).rejects.toThrow('APPLICATION_RECOVERY_PROPOSAL_CHANGED')
    expect(f.requests).toHaveLength(0)
    expect(await b.recovery.inspect()).toEqual([])
  })

  it('cannot turn an incomplete selected prefix into an approvable recovery candidate', async () => {
    const f = await fixture(), a = await f.open(f.a)
    await post(a, 'missing-from-b')
    await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: a.revision.generation, coordinator: f.c.identity.publicKey, requester: f.c.identity.publicKey, controlRevision: 0,
      base: await a.recoveryPoint(), transitionId: 'inherited', reason: 'takeover' }, f.c.identity))
    const b = await f.open(f.b), participation = f.participate(b)
    await until(() => participation.status.error === 'PEER_RECOVERY_PREFIX_INCOMPLETE')
    expect(participation.status.recovery).toBeNull()
    expect(f.requests).toHaveLength(0)
    await expect(b.readView()).rejects.toThrow('PEER_RECOVERING')
  })

  it('authenticates newly enrolled readers through newer signed hello authority without reopening the healthy owner', async () => {
    const f = await fixture({ omitC: true }), a = await f.open(f.a)
    const first = f.participate(a)
    await until(() => first.status.phase === 'coordinating')
    const old = a.revision.generation
    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control),
      grants: [...f.control.payload.grants, participantGrant(f.c.identity.publicKey)] }, f.signer)
    const selected = await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: old, coordinator: a.deviceId, requester: a.deviceId, controlRevision: 1, base: await a.recoveryPoint(),
      transitionId: 'enroll', reason: 'control-change' }, f.a.identity), { control })
    expect(a.revision.generation).toBe(old)
    const c = await f.open(f.c), joined = f.participate(c)
    await until(() => joined.status.phase === 'following' && first.status.connectedPeers.includes(c.deviceId))
    expect(a.revision.generation).toBe(selected.id)
    expect(c.revision.generation).toBe(selected.id)
    await expect((await post(c, 'new-reader')).get()).resolves.toMatchObject({ status: 'applied' })
  })

  it('bounds uncooperative raw openings, deduplicates peer hints and closes late connections once', async () => {
    const f = await fixture(), b = await f.open(f.b), ports = f.hub.ports(b.deviceId)
    const openings: Array<(value: FramedPeerConnection) => void> = []
    const hints = [f.a, f.a, f.a, f.c].map(device => ({ identity: device.identity.publicKey, route: 'same' }))
    const participation = f.participate(b, { discovery: { ...ports.discovery, read: async () => hints },
      transport: { open: () => new Promise(resolve => { openings.push(resolve) }) },
      connections: { maxPeers: 2, timeoutMs: 15, retryInitialMs: 5, retryMaxMs: 10 },
    })
    await until(() => openings.length === 2)
    await new Promise(resolve => setTimeout(resolve, 60))
    expect(openings).toHaveLength(2)
    let reentrant: Promise<void> | undefined
    participation.onStatus(status => { if (status.phase === 'closed') reentrant = participation.close() })
    const closed = participation.close()
    expect(reentrant).toBe(closed)
    await closed
    expect(f.hub.counts.withdrawals).toBe(1)
    let released = 0
    for (const resolve of openings) {
      const [connection, other] = createFramedPeerConnectionPair()
      closing.push(() => other.close())
      resolve({ ...connection, async close() { released++; await connection.close() } })
    }
    await until(() => released === 2)
    expect(participation.status.phase).toBe('closed')
    expect(b.status.connectedPeers).toBe(0); expect(b.signal.aborted).toBe(false)
  })

  it('closes while a manually started exact transition still owns its noncooperative hosted wait', async () => {
    const f = await fixture(), b = await f.open(f.b)
    let sent = false
    const control: ApplicationControlHost = { application: () => f.registry.read(), selectGeneration: () => {
      sent = true; return new Promise<SignedGeneration>(() => {})
    } }
    const manual = b.recovery.takeover(control, { transitionId: 'manual' })
    const cancelled = expect(manual).rejects.toThrow('APPLICATION_SESSION_CLOSED')
    await until(() => sent)
    const participation = f.participate(b)
    await until(() => f.hub.counts.reads > 0)
    await participation.close()
    expect(participation.status.phase).toBe('closed')
    expect(b.signal.aborted).toBe(false)
    await b.close(); await cancelled
  })

  it('fences a delayed control read when participation closes without closing the session', async () => {
    const f = await fixture(), b = await f.open(f.b)
    let request: ParticipantRequest | undefined, deliver!: (value: unknown) => void
    const late = new Promise<unknown>(resolve => { deliver = resolve })
    const control = b.connectControlParticipant({ exchange: value => {
      if (request === undefined) { request = value; return late }
      return f.registry.read().then(bundle => createParticipantResponse(value, bundle))
    } })
    const before = b.revision, participation = f.participate(b, { control })
    await until(() => request !== undefined)
    await participation.close()
    await f.registry.select(await signTransitionRequest({ applicationId: b.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: before.generation, coordinator: b.deviceId, requester: b.deviceId, controlRevision: 0,
      base: await b.recoveryPoint(), transitionId: 'after-close', reason: 'takeover' }, f.b.identity))
    deliver(createParticipantResponse(request!, await f.registry.read()))
    await late; await new Promise(resolve => setTimeout(resolve, 10))
    expect(b.revision).toEqual(before)
    expect(control.signal.aborted).toBe(false)
    await control.application()
    expect(b.revision.generation).not.toBe(before.generation)
  })

  it('reserves coherent view capacity before concurrent asynchronous captures', async () => {
    const f = await fixture(), runtime = await createEventMaterializationRuntime({ store: f.a.store, namespace: 'participation' })
    const capture = vi.spyOn(runtime.queries, 'captureRead')
    const a = await f.open(f.a, () => runtime)
    const openings = Array.from({ length: 8 }, () => a.readView())
    await expect(a.readView()).rejects.toThrow('APPLICATION_VIEW_LIMIT')
    const views = await Promise.all(openings)
    expect(capture).toHaveBeenCalledTimes(8)
    for (const view of views) view.release()
    const view = await a.readView(); view.release()
  })
})

import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type SignedTransitionRequest,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { defineApplication, defineCommand, applicationDefinitionDigest } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication } from './runtime.js'
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

async function fixture() {
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
    grants: devices.map(device => participantGrant(device.identity.publicKey, { administrator: true, dataRole: 'member' })) }, signer)
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
  const open = async (device: typeof a) => {
    const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys })
    closing.push(() => session.close()); return session
  }
  const participate = (session: ApplicationSession, overrides: Partial<ApplicationParticipationOptions> = {}) => session.participate({
    control: host, ...hub.ports(session.deviceId), recovery: { graceMs: 25, freshnessMs: 300_000 },
    connections: { maxPeers: 2, retryInitialMs: 5, retryMaxMs: 20, timeoutMs: 2000, advertiseMs: 15_000 }, ...overrides,
  })
  return { a, b, c, stores, registry, hub, host, counts, requests, open, participate,
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
})

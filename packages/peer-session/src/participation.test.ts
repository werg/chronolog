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
  ApplicationPeerAdvertisement, ApplicationDiscoveryNotification,
} from './participation-types.js'

const definition = defineApplication({ id: 'participation', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
}, queries: {} })
const closing: Array<() => void | Promise<void>> = []
afterEach(async () => { vi.useRealTimers(); for (const close of closing.splice(0).reverse()) await close(); vi.restoreAllMocks() })

/** Delivery only: real session handshakes, signed authority and history run on these framed pairs. */
class Introductions {
  readonly directory = new Map<string, ApplicationPeerHint>()
  readonly advertised = new Map<string, ApplicationPeerAdvertisement>()
  readonly #listeners = new Map<string, (value: ApplicationPeerInvitation) => void>()
  readonly notices = new Map<string, (value: ApplicationDiscoveryNotification) => void>()
  readonly #connections = new Map<string, FramedPeerConnection>()
  readonly counts = { reads: 0, advertisements: 0, withdrawals: 0, opens: 0, frames: 0 }
  unavailable = false
  counted(connection: FramedPeerConnection): FramedPeerConnection {
    return { signal: connection.signal, ...(connection.live === undefined ? {} : { live: connection.live }),
      send: (frame, options) => { this.counts.frames++; return connection.send(frame, options) },
      frames: signal => connection.frames(signal), close: () => connection.close() }
  }
  ports(identity: string): { discovery: ApplicationDiscoveryPort; transport: ApplicationTransportPort } {
    const hub = this
    return {
      discovery: {
        async read({ signal }) { signal.throwIfAborted(); hub.counts.reads++; if (hub.unavailable) throw new Error('DIRECTORY_OFFLINE'); return [...hub.directory.values()] },
        async advertise(value, { signal }) {
          signal.throwIfAborted(); hub.counts.advertisements++; if (hub.unavailable) throw new Error('DIRECTORY_OFFLINE')
          const changed = JSON.stringify(hub.advertised.get(identity)) !== JSON.stringify(value)
          hub.advertised.set(identity, structuredClone(value))
          hub.directory.set(identity, { identity: value.identity, route: value.identity })
          if (changed) for (const notify of hub.notices.values()) notify({ type: 'changed' })
        },
        async withdraw({ signal }) {
          signal.throwIfAborted(); hub.counts.withdrawals++; hub.advertised.delete(identity)
          if (hub.directory.delete(identity)) for (const notify of hub.notices.values()) notify({ type: 'changed' })
        },
        async *notifications({ signal }) {
          const queue: ApplicationDiscoveryNotification[] = [{ type: 'ready' }]
          let notify = (): void => {}
          const accept = (value: ApplicationDiscoveryNotification): void => { queue.push(value); notify() }
          hub.notices.set(identity, accept)
          try {
            while (!signal.aborted) {
              if (queue.length === 0) await new Promise<void>(resolve => {
                const done = (): void => { signal.removeEventListener('abort', done); resolve() }
                notify = done; signal.addEventListener('abort', done, { once: true }); if (signal.aborted) done()
              })
              const value = queue.shift(); if (value !== undefined) yield value
            }
          } finally { if (hub.notices.get(identity) === accept) hub.notices.delete(identity) }
        },
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
            hub.#connections.delete(input.invitation); return hub.counted(connection)
          }
          const target = hub.#listeners.get(input.peer.identity)
          if (target === undefined) throw new Error('PEER_UNAVAILABLE')
          const [left, right] = createFramedPeerConnectionPair(), token = crypto.randomUUID()
          hub.#connections.set(token, right)
          target({ peer: { identity, route: identity }, token })
          return hub.counted(left)
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
  const openCold = async (device: typeof a, createMaterializer?: OpenPeerApplicationOptions['createMaterializer']) => {
    const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys,
      ...(createMaterializer === undefined ? {} : { createMaterializer }) })
    closing.push(() => session.close()); return session
  }
  const open = async (...args: Parameters<typeof openCold>) => {
    const session = await openCold(...args)
    await session.keys.missing(); return session
  }
  const participate = (session: ApplicationSession, overrides: Partial<ApplicationParticipationOptions> = {}) => session.participate({
    control: host, ...hub.ports(session.deviceId), recovery: { graceMs: 25, freshnessMs: 300_000 },
    connections: { maxPeers: 2, retryInitialMs: 5, retryMaxMs: 20, timeoutMs: 2000 }, ...overrides,
  })
  return { a, b, c, stores, registry, hub, host, counts, requests, open, openCold, participate, signer, descriptor, control,
    offline(value: boolean) { offline = value }, loseSelection() { loseSelection = true } }
}

async function until(check: () => boolean | Promise<boolean>, timeout = 5000): Promise<void> {
  await vi.waitFor(async () => { expect(await check()).toBe(true) }, { timeout, interval: 5 })
}
async function post(session: ApplicationSession<typeof definition>, id: string) {
  const operation = await session.command('say', id, { operationId: id })
  await operation.applied({ signal: AbortSignal.timeout(5000) }); return operation
}

function gate() {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}

/** A real verified coordinator reconnects through an invitation already owned by the follower. */
async function holdIncomingCoordinator({ advertised = true } = {}) {
  const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b), ports = f.hub.ports(b.deviceId)
  const opened = gate(), release = gate(), directory = gate(),
    scanned = gate(), selected = gate()
  let reconnecting = false, incoming = 0, attemptSignal: AbortSignal | undefined
  const first = f.participate(a), participation = f.participate(b, {
    control: { ...f.host, async selectGeneration(request, options) { selected.resolve(); return f.host.selectGeneration(request, options) } },
    discovery: { ...ports.discovery, async read(options) {
      if (!reconnecting) return ports.discovery.read(options)
      await directory.promise; scanned.resolve()
      return advertised ? [{ identity: a.deviceId, route: a.deviceId }] : []
    } },
    transport: { async open(input, options) {
      const connection = await ports.transport.open(input, options)
      if (reconnecting && input.invitation !== undefined) {
        incoming++; attemptSignal = options.signal; opened.resolve(); await release.promise
      }
      return connection
    } },
    connections: { maxPeers: 2, retryInitialMs: 5, retryMaxMs: 20, timeoutMs: 5000 },
  })
  closing.push(() => { directory.resolve(); release.resolve() })
  await until(() => participation.status.phase === 'following')
  await until(async () => await f.b.store.get(`peer-session/coordinator-observation/${b.applicationId}`) !== null)
  const generation = b.revision!.generation
  reconnecting = true; await first.close()
  const connection = await f.hub.ports(a.deviceId).transport.open({ peer: { identity: b.deviceId, route: b.deviceId } }, { signal: a.signal })
  closing.push(() => connection.close())
  await opened.promise; directory.resolve(); await scanned.promise
  return { f, a, b, participation, connection, generation, release, selected, incoming: () => incoming, attemptSignal: () => attemptSignal }
}

describe('owned application participation', () => {
  it('starts notifications before its first advertisement and waits for initial ready', async () => {
    const f = await fixture(), a = await f.open(f.a), ports = f.hub.ports(a.deviceId), ready = gate()
    let subscribed = false, returned = false
    const participation = f.participate(a, { discovery: { ...ports.discovery,
      async *notifications(options) {
        subscribed = true
        try { await ready.promise; yield* ports.discovery.notifications(options) } finally { returned = true }
      },
      async advertise(value, options) { expect(subscribed).toBe(true); await ports.discovery.advertise(value, options) },
    } })
    await until(() => subscribed)
    expect(f.hub.counts.advertisements).toBe(0); expect(f.hub.counts.reads).toBe(0); expect(f.counts.reads).toBe(0)
    ready.resolve(); await until(() => participation.status.phase === 'coordinating')
    await participation.close(); expect(returned).toBe(true); expect(f.hub.notices.size).toBe(0)
  })

  it('leaves a healthy underfilled coordinator completely idle for 48 virtual hours', async () => {
    const f = await fixture(), a = await f.open(f.a)
    vi.useFakeTimers()
    const participation = f.participate(a)
    await until(() => participation.status.phase === 'coordinating')
    await vi.advanceTimersByTimeAsync(100)
    await until(() => vi.getTimerCount() === 0)
    const before = { host: { ...f.counts }, discovery: { ...f.hub.counts } }
    expect(vi.getTimerCount()).toBe(0)
    await vi.advanceTimersByTimeAsync(48 * 60 * 60 * 1000)
    expect({ host: { ...f.counts }, discovery: { ...f.hub.counts } }).toEqual(before)
    expect(vi.getTimerCount()).toBe(0); expect(participation.status.phase).toBe('coordinating')
  })

  it('does not advertise for changed notifications and re-announces exactly once after ready', async () => {
    const f = await fixture(), a = await f.open(f.a), participation = f.participate(a)
    await until(() => participation.status.phase === 'coordinating')
    await new Promise(resolve => setTimeout(resolve, 25))
    const before = { ...f.hub.counts }
    f.hub.notices.get(a.deviceId)!({ type: 'changed' })
    await until(() => f.hub.counts.reads > before.reads)
    expect(f.hub.counts.advertisements).toBe(before.advertisements)
    f.hub.notices.get(a.deviceId)!({ type: 'ready' })
    await until(() => f.hub.counts.advertisements === before.advertisements + 1)
    await new Promise(resolve => setTimeout(resolve, 25))
    expect(f.hub.counts.advertisements).toBe(before.advertisements + 1)
    expect(f.counts.selections).toBe(0)
  })

  it('discovers a late peer after 48 idle hours without a lease renewal', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    vi.useFakeTimers()
    const first = f.participate(a)
    await until(() => first.status.phase === 'coordinating'); await vi.advanceTimersByTimeAsync(100)
    const ads = f.hub.counts.advertisements
    await vi.advanceTimersByTimeAsync(48 * 60 * 60 * 1000)
    expect(f.hub.counts.advertisements).toBe(ads)
    // Real crypto/transport work must finish under real deadlines; virtual time only measures settled idle.
    vi.useRealTimers()
    const second = f.participate(b)
    await until(() => second.status.phase === 'following' && first.status.connectedPeers.includes(b.deviceId))
    await new Promise(resolve => setTimeout(resolve, 100))
    vi.useFakeTimers()
    await vi.advanceTimersByTimeAsync(100)
    await until(() => vi.getTimerCount() === 0)
    const before = { host: { ...f.counts }, discovery: { ...f.hub.counts } }
    expect(vi.getTimerCount()).toBe(0)
    await vi.advanceTimersByTimeAsync(48 * 60 * 60 * 1000)
    expect({ host: { ...f.counts }, discovery: { ...f.hub.counts } }).toEqual(before)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('cancels and returns an uncooperative notification iterator without advertising or waiting for it', async () => {
    const f = await fixture(), a = await f.open(f.a), ports = f.hub.ports(a.deviceId)
    let deliver!: (value: IteratorResult<ApplicationDiscoveryNotification>) => void
    const returned = vi.fn(async () => ({ done: true as const, value: undefined }))
    const next = vi.fn(() => new Promise<IteratorResult<ApplicationDiscoveryNotification>>(resolve => { deliver = resolve }))
    const participation = f.participate(a, { discovery: { ...ports.discovery, notifications: () => ({ [Symbol.asyncIterator]: () => ({ next, return: returned }) }) } })
    await until(() => next.mock.calls.length === 1)
    await participation.close(); expect(returned).toHaveBeenCalledTimes(1)
    deliver({ done: false, value: { type: 'ready' } }); await new Promise(resolve => setTimeout(resolve, 10))
    expect(f.hub.counts.advertisements).toBe(0); expect(f.hub.counts.reads).toBe(0); expect(participation.status.phase).toBe('closed')
  })

  it.each(['ended', 'failed', 'changed-before-ready', 'payload'] as const)('backs off and resubscribes after notification %s without accepting invalid readiness', async failure => {
    const f = await fixture(), a = await f.open(f.a), ports = f.hub.ports(a.deviceId), resume = gate()
    let attempts = 0, cleanup = 0
    closing.push(() => resume.resolve())
    const participation = f.participate(a, { discovery: { ...ports.discovery, async *notifications(options) {
      const attempt = ++attempts
      try {
        if (attempt === 1) {
          if (failure === 'failed') throw new Error('NOTIFICATION_TRANSPORT_OFFLINE')
          if (failure === 'changed-before-ready') yield { type: 'changed' }
          if (failure === 'payload') yield { type: 'ready', data: 'untrusted' } as ApplicationDiscoveryNotification
          return
        }
        await resume.promise; yield* ports.discovery.notifications(options)
      } finally { cleanup++ }
    } } })
    await until(() => attempts === 2)
    expect(cleanup).toBe(1); expect(f.hub.counts.advertisements).toBe(0); expect(f.hub.counts.reads).toBe(0)
    expect(participation.status.error).toMatch(/NOTIFICATION/)
    resume.resolve(); await until(() => participation.status.phase === 'coordinating' && participation.status.error === null && f.hub.counts.advertisements > 0)
    expect(participation.status.error).toBeNull(); await participation.close(); expect(cleanup).toBe(2)
  })

  it('serializes scans and retains notifications delivered during an awaited scan', async () => {
    const f = await fixture(), a = await f.open(f.a), ports = f.hub.ports(a.deviceId), release = gate()
    let reading = 0, maximum = 0, reads = 0
    closing.push(() => release.resolve())
    const participation = f.participate(a, { discovery: { ...ports.discovery, async read(options) {
      reading++; maximum = Math.max(maximum, reading)
      try { if (++reads === 1) await release.promise; return await ports.discovery.read(options) } finally { reading-- }
    }, async advertise(value, options) { expect(reading).toBe(0); return ports.discovery.advertise(value, options) } } })
    await until(() => reads === 1)
    f.hub.notices.get(a.deviceId)!({ type: 'changed' }); f.hub.notices.get(a.deviceId)!({ type: 'ready' })
    release.resolve(); await until(() => reads >= 2 && participation.status.phase === 'coordinating')
    await new Promise(resolve => setTimeout(resolve, 25))
    expect(maximum).toBe(1); expect(f.hub.counts.advertisements).toBe(2)
  })

  it('retries a failed active advertisement with capped backoff and becomes timer-free after repair', async () => {
    const f = await fixture(), a = await f.open(f.a), ports = f.hub.ports(a.deviceId)
    let attempts = 0, repaired = false
    vi.useFakeTimers(); vi.spyOn(Math, 'random').mockReturnValue(0.99)
    const participation = f.participate(a, { discovery: { ...ports.discovery, async advertise(value, options) {
      attempts++; if (!repaired) throw new Error('ADVERTISE_OFFLINE'); return ports.discovery.advertise(value, options)
    } } })
    await until(() => attempts >= 3)
    expect(participation.status.error).toBe('ADVERTISE_OFFLINE')
    const before = attempts; await vi.advanceTimersByTimeAsync(100)
    expect(attempts - before).toBeLessThanOrEqual(6)
    repaired = true; await until(() => participation.status.error === null && f.hub.counts.advertisements === 1)
    await until(() => vi.getTimerCount() === 0)
    const settled = attempts; await vi.advanceTimersByTimeAsync(48 * 60 * 60 * 1000)
    expect(attempts).toBe(settled); expect(vi.getTimerCount()).toBe(0)
  })

  it('rechecks signed recovery revocation before a notification-driven approved selection', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b), participation = f.participate(b)
    await until(() => participation.status.phase === 'approval-required')
    const proposal = participation.status.recovery!
    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control),
      grants: f.control.payload.grants.map(grant => grant.publicKey === b.deviceId ? { ...grant, recovery: false } : grant),
    }, f.signer)
    await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: a.revision!.generation, coordinator: a.deviceId, requester: a.deviceId, controlRevision: 1,
      base: await a.recoveryPoint(), transitionId: 'revoke-recovery', reason: 'control-change',
    }, f.a.identity), { control })
    f.hub.notices.get(b.deviceId)!({ type: 'changed' })
    await participation.approveRecovery(proposal.id)
    await until(() => participation.status.error === 'PEER_RECOVERY_FORBIDDEN')
    expect(f.requests).toHaveLength(0)
    expect(await b.recovery.inspect()).toEqual([])
    await expect(participation.approveRecovery(proposal.id)).rejects.toThrow('APPLICATION_RECOVERY_APPROVAL_STALE')
  })

  it('preserves coordinator-loss grace and recovery while a previously ready notification transport is down', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b), ports = f.hub.ports(b.deviceId)
    const outage = gate(), restore = gate()
    let attempts = 0
    closing.push(() => { outage.resolve(); restore.resolve() })
    const first = f.participate(a), second = f.participate(b, { discovery: { ...ports.discovery, async *notifications(options) {
      if (++attempts === 1) { yield { type: 'ready' }; await outage.promise; throw new Error('WATCH_OFFLINE') }
      await restore.promise; yield* ports.discovery.notifications(options)
    } } })
    await until(() => second.status.phase === 'following')
    await until(async () => await f.b.store.get(`peer-session/coordinator-observation/${b.applicationId}`) !== null)
    outage.resolve(); await until(() => attempts >= 2)
    await first.close()
    await until(() => second.status.phase === 'coordinating')
    expect(f.requests).toHaveLength(1)
    expect(f.requests[0]!.payload.coordinator).toBe(b.deviceId)
    expect(second.status.error).toBe('WATCH_OFFLINE')
  })

  it('keeps discovery, authenticated live traffic and controls active without recovery until local data use', async () => {
    const f = await fixture(), openB = vi.fn(() => f.b.openStorage()), openC = vi.fn(() => f.c.openStorage())
    const b = await f.openCold({ ...f.b, openStorage: openB }), c = await f.openCold({ ...f.c, openStorage: openC })
    const first = f.participate(b), second = f.participate(c)
    await until(() => first.status.phase === 'connected' && second.status.phase === 'connected')
    const stream = c.signals.subscribe({ signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), received = stream.next()
    const sent = await b.signals.send('typing', { active: true })
    expect((await received).value).toEqual(sent); await stream.return?.()
    await new Promise(resolve => setTimeout(resolve, 75))
    expect(f.counts.reads).toBeGreaterThan(0); expect(f.counts.selections).toBe(0)
    expect(first.status.recovery).toBeNull(); expect(second.status.recovery).toBeNull()
    expect(openB).not.toHaveBeenCalled(); expect(openC).not.toHaveBeenCalled()
    expect([b.revision, c.revision]).toEqual([null, null])
    expect(f.hub.advertised.get(b.deviceId)).toMatchObject({ data: false, point: null })
    expect(f.hub.advertised.get(c.deviceId)).toMatchObject({ data: false, point: null })
    const connections = f.hub.counts.opens

    const view = await b.readView(); view.release()
    await until(() => first.status.phase === 'approval-required')
    expect(openB).toHaveBeenCalledTimes(1); expect(openC).not.toHaveBeenCalled()
    expect(first.status.recovery).toMatchObject({ coordinator: b.deviceId, reason: 'freshness-unknown' })
    await first.approveRecovery(first.status.recovery!.id)
    await until(() => first.status.phase === 'coordinating')
    await until(() => c.status.generation === b.status.generation)
    expect(f.counts.selections).toBe(1)
    expect(f.hub.counts.opens).toBe(connections)
    expect(b.participation).toBe(first); expect(c.participation).toBe(second)
    expect(c.status.database).toBe('idle'); expect(openC).not.toHaveBeenCalled()
  })

  it('retains a live coordinator whose database failed without claiming data availability or reopening its transport', async () => {
    const f = await fixture(), openA = vi.fn(async () => { throw new Error('STORAGE_DENIED') })
    const a = await f.openCold({ ...f.a, openStorage: openA }), b = await f.openCold(f.b)
    const first = f.participate(a), second = f.participate(b)
    await until(() => first.status.phase === 'connected' && second.status.phase === 'connected')
    const connections = f.hub.counts.opens
    const view = await b.readView(); view.release()
    await until(() => second.status.error === 'APPLICATION_DATA_UNAVAILABLE')
    expect(second.status.phase).not.toBe('following')
    expect(second.status.connectedPeers).toContain(a.deviceId)
    const stream = a.signals.subscribe({ signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), received = stream.next()
    const sent = await b.signals.send('typing', { active: true })
    expect((await received).value).toEqual(sent); await stream.return?.()
    expect(f.hub.counts.opens).toBe(connections)
    expect(f.counts.selections).toBe(0)
    expect(openA).toHaveBeenCalledTimes(1)
    expect(a.status.database).toBe('failed')
  })

  it('re-advertises real history changes without reopening peers or calling the control service', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const first = f.participate(a), second = f.participate(b)
    await until(() => first.status.phase === 'coordinating' && second.status.phase === 'following')
    expect(second.status.connectedPeers).toContain(a.deviceId)
    const before = { control: { ...f.counts }, delivery: { ...f.hub.counts } }
    const operation = await post(b, 'once')
    await operation.shared({ signal: AbortSignal.timeout(5000) })
    await until(() => [a, b].every(session => JSON.stringify(f.hub.advertised.get(session.deviceId)?.point) === JSON.stringify(session.revision!.point)))
    expect(f.counts).toEqual(before.control)
    expect(f.hub.counts.advertisements).toBeGreaterThan(before.delivery.advertisements)
    expect(f.hub.counts.opens).toBe(before.delivery.opens)
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
    const oldGeneration = b.revision!.generation
    f.loseSelection(); await a.close()
    const operation = await b.command('say', 'saved during grace', { operationId: 'during-grace' })
    await until(() => participation.status.phase === 'coordinating')
    expect(b.revision!.generation).not.toBe(oldGeneration)
    expect(f.requests.length).toBe(2); expect(f.requests[1]).toEqual(f.requests[0])
    expect(await operation.get()).toMatchObject({ status: 'needsReapply' })
    const reapplied = await b.reapply('during-grace', 'say', 'reviewed after recovery', { operationId: 'after-recovery' })
    expect((await reapplied.applied({ signal: AbortSignal.timeout(5000) })).status).toBe('applied')
    expect((await b.recovery.inspect())[0]?.selected).toBe(b.revision!.generation)
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

  it.each([true, false])('finishes an owned incoming coordinator opening before recovery (advertised: %s)', async advertised => {
    const h = await holdIncomingCoordinator({ advertised })
    const connecting = h.a.connectPeer({ connection: h.connection, peerIdentity: h.b.deviceId, handshakeTimeoutMs: 5000 })
    void connecting.catch(() => undefined)
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      // The existing attempt outlives the 25ms recovery grace but remains well
      // within its own 5s budget, as a direct-to-relay transport attempt can.
      await Promise.race([h.selected.promise, new Promise<void>(resolve => { timer = setTimeout(resolve, 1000) })])
      expect(h.f.requests).toHaveLength(0)
      h.release.resolve()
      const link = await connecting
      closing.push(() => link.close()); await link.synchronize()
      await until(() => h.participation.status.phase === 'following')
      expect(h.incoming()).toBe(1); expect(h.f.requests).toHaveLength(0)
      expect(h.b.revision!.generation).toBe(h.generation)
    } finally { clearTimeout(timer); h.release.resolve(); await connecting.catch(() => undefined) }
  })

  it('releases the recovery fence when an incoming coordinator opening exhausts its bounded attempt', async () => {
    const h = await holdIncomingCoordinator()
    await until(() => h.participation.status.phase === 'coordinating', 7500)
    expect(h.attemptSignal()?.aborted).toBe(true)
    expect(h.incoming()).toBe(1); expect(h.f.requests).toHaveLength(1)
    expect(h.b.revision!.generation).not.toBe(h.generation)
    expect(h.f.requests[0]?.payload).toMatchObject({ reason: 'takeover', coordinator: h.b.deviceId, expectedGeneration: h.generation })
    // The noncooperative factory remains physically owned until it returns.
    h.release.resolve()
    await until(() => h.connection.signal.aborted)
  })

  it('closes discovery while its incoming coordinator opening remains pending', async () => {
    const h = await holdIncomingCoordinator()
    await h.participation.close()
    expect(h.participation.status.phase).toBe('closed'); expect(h.f.requests).toHaveLength(0)
    expect(h.b.revision!.generation).toBe(h.generation)
    h.release.resolve()
    await until(() => h.connection.signal.aborted)
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
    const operation = await post(a, 'retained')
    // Each direction synchronizes its own captured head. Handover needs the
    // successor's signed retention of this exact newly applied prefix.
    const coverage = await operation.shared({ signal: AbortSignal.timeout(5000) })
    expect(coverage.map(receipt => ({ peer: receipt.payload.peer, point: receipt.payload.point }))).toEqual([
      { peer: b.deviceId, point: a.revision!.point },
    ])
    f.loseSelection()
    await expect(a.recovery.handover(f.host, { coordinator: b.deviceId, transitionId: 'handover' })).rejects.toThrow('LOST_SELECTION_REPLY')
    const original = (await a.recovery.inspect())[0]!.request
    const participation = f.participate(a)
    await until(async () => (await a.recovery.inspect())[0]?.selected !== null)
    expect(f.requests).toEqual([original, original])
    expect(participation.status.phase).not.toBe('approval-required')
    expect(a.revision!.generation).toBe((await f.registry.read()).generations.at(-1)?.id)
  })

  it('requires approval after an idle coordinator observation exceeds the local freshness budget', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    f.participate(a)
    const participation = f.participate(b, { recovery: { graceMs: 100, freshnessMs: 50 } })
    await until(() => participation.status.phase === 'following')
    // Attachment precedes the fully verified head observation. Establish that
    // evidence before making it idle; otherwise unknown freshness is correct.
    await until(async () => await f.b.store.get(`peer-session/coordinator-observation/${b.applicationId}`) !== null)
    await a.close()
    await until(() => participation.status.phase === 'approval-required')
    expect(participation.status.recovery).toMatchObject({ reason: 'older-than-budget', point: b.revision!.point })
    expect(participation.status.recovery!.ageMs).toBeGreaterThan(50)
    expect(f.requests).toHaveLength(0)
  })

  it('does not reuse an approved proposal after a host refresh selects another generation', async () => {
    const f = await fixture(), b = await f.open(f.b)
    let armed = false, reads = 0
    const control: ApplicationControlHost = { ...f.host, async application(options) {
      if (armed && ++reads === 2) {
        await f.registry.select(await signTransitionRequest({ applicationId: b.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
          expectedGeneration: b.revision!.generation, coordinator: f.c.identity.publicKey, requester: f.c.identity.publicKey,
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
    const expected = { generation: b.revision!.generation, controlRevision: b.revision!.controlRevision, point: b.revision!.point }
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
      expectedGeneration: a.revision!.generation, coordinator: f.c.identity.publicKey, requester: f.c.identity.publicKey, controlRevision: 0,
      base: await a.recoveryPoint(), transitionId: 'inherited', reason: 'takeover' }, f.c.identity))
    const b = await f.open(f.b), participation = f.participate(b)
    await until(() => participation.status.error === 'PEER_RECOVERY_PREFIX_INCOMPLETE')
    expect(participation.status.recovery).toBeNull()
    expect(f.requests).toHaveLength(0)
    await expect(b.readView()).rejects.toThrow('PEER_RECOVERING')
  })

  it.each(['self', 'other'] as const)('approves an inherited complete prefix when the %s selection adopted unavailable newer data', async coordinator => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    await post(a, 'retained-ancestor'); await link.synchronize(); await link.close()
    const ancestor = await b.recoveryPoint()
    const select = async (transitionId: string, coordinator: string) => {
      const authority = await f.registry.read()
      return f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
        expectedGeneration: authority.generations.at(-1)!.id, coordinator, requester: f.a.identity.publicKey, controlRevision: 0,
        base: await a.recoveryPoint(), transitionId, reason: 'takeover' }, f.a.identity))
    }
    await select('second', a.deviceId); await a.adopt(await f.registry.read())
    await post(a, 'unavailable-newer-data')
    const current = await select('third', coordinator === 'self' ? b.deviceId : f.c.identity.publicKey)
    await a.close()
    const participation = f.participate(b)
    await until(() => participation.status.phase === 'approval-required')
    const proposal = participation.status.recovery!
    expect(proposal).toMatchObject({ point: ancestor.point, reason: 'freshness-unknown', coordinator: b.deviceId })
    expect(f.requests).toHaveLength(0)
    await expect(b.readView()).rejects.toThrow('PEER_RECOVERING')
    await expect(b.recovery.handover(f.host, { coordinator: f.c.identity.publicKey })).rejects.toThrow('PEER_RECOVERY_PREFIX_INCOMPLETE')
    expect(f.requests).toHaveLength(0)
    await participation.approveRecovery(proposal.id)
    await until(() => participation.status.phase === 'coordinating')
    expect(f.requests).toHaveLength(1)
    expect(f.requests[0]!.payload).toMatchObject({ expectedGeneration: current.id, base: ancestor })
    const view = await b.readView()
    try { expect(view.readEvents().events.map(event => event.operationId)).toEqual(['retained-ancestor']) } finally { view.release() }
    await expect((await post(b, 'new-work')).get()).resolves.toMatchObject({ status: 'applied' })
  })

  it('authenticates newly enrolled readers through newer signed hello authority without reopening the healthy owner', async () => {
    const f = await fixture({ omitC: true }), a = await f.open(f.a)
    const first = f.participate(a)
    await until(() => first.status.phase === 'coordinating')
    const old = a.revision!.generation
    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control),
      grants: [...f.control.payload.grants, participantGrant(f.c.identity.publicKey)] }, f.signer)
    const selected = await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: old, coordinator: a.deviceId, requester: a.deviceId, controlRevision: 1, base: await a.recoveryPoint(),
      transitionId: 'enroll', reason: 'control-change' }, f.a.identity), { control })
    expect(a.revision!.generation).toBe(old)
    const c = await f.open(f.c), joined = f.participate(c)
    await until(() => joined.status.phase === 'following' && first.status.connectedPeers.includes(c.deviceId))
    expect(a.revision!.generation).toBe(selected.id)
    expect(c.revision!.generation).toBe(selected.id)
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
    const before = b.revision!, participation = f.participate(b, { control })
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
    expect(b.revision!.generation).not.toBe(before.generation)
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

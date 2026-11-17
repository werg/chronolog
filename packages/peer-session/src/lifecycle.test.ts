import { afterEach, describe, expect, it } from 'vitest'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryPeerStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest } from '@chronolog/peer-generation'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import type { PeerDescription } from '@chronolog/transport-webrtc'
import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import { openApplicationDevice } from './device.js'
import type { ApplicationPeerAdvertisement, ApplicationPeerHost, ApplicationPeerLease } from './lifecycle.js'
import { openPeerApplication } from './runtime.js'
import type { ApplicationReadView } from './session.js'
import { maintainNativeApplicationWebRtc } from './webrtc-native.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const definition = defineApplication({ id: 'managed-network', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
}, queries: {
  messages: defineQuery({ description: 'Read messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }),
} })

function mailbox<T>() {
  const values: T[] = []
  let ended = false, wake = () => {}
  return {
    send(value: T) { if (!ended) { values.push(value); wake() } },
    close() { ended = true; wake() },
    async *[Symbol.asyncIterator]() {
      while (!ended || values.length > 0) {
        if (values.length > 0) yield values.shift()!
        else await new Promise<void>(resolve => { wake = resolve })
      }
    },
  }
}
async function until(check: () => boolean, timeout = 15_000) {
  const deadline = Date.now() + timeout
  while (!check()) {
    if (Date.now() >= deadline) throw new Error('TEST_CONDITION_TIMEOUT')
    await new Promise(resolve => setTimeout(resolve, 10))
  }
}

async function fixture() {
  const hostIdentity = await createPeerIdentity(), devices = await Promise.all([0, 1, 2].map(() => openApplicationDevice({ store: new MemoryPeerStore(), create: true })))
  const key = crypto.getRandomValues(new Uint8Array(32)), artifacts = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '92'.repeat(32), historyId: 'managed-network', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: hostIdentity.publicKey, schemaAdministrator: devices[0]!.identity.publicKey,
    executionManifestDigest: bytesToHex(artifacts.executionManifestDigest), definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, hostIdentity)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: devices.map((device, index) => participantGrant(device.identity.publicKey, { administrator: index === 0 })) }, hostIdentity)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: hostIdentity })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    expectedGeneration: null, coordinator: devices[0]!.identity.publicKey, requester: devices[0]!.identity.publicKey,
    controlRevision: 0, base: null, transitionId: 'create', reason: 'create' }, devices[0]!.identity))
  let blocked = false, requests = 0, selections = 0
  const leases = new Map<string, ApplicationPeerLease>()
  const listeners = new Map<string, { queue: ReturnType<typeof mailbox<{ channel: string; requesterPeerId: string }>>; close(): void }>()
  const pairs = new Map<string, { slots: Array<{ peer: string; queue: ReturnType<typeof mailbox<PeerDescription>>; ready(value: { role: 'offerer' | 'answerer' }): void }> }>()
  const accessed = () => { requests++; if (blocked) throw new Error('HOST_BLOCKED') }
  const client = (): ApplicationPeerHost => ({
    async application() { accessed(); return registry.read() },
    async selectGeneration(...args) { accessed(); selections++; return registry.select(...args) },
    async discover() { accessed(); return { applicationId: descriptor.payload.applicationId, peers: [...leases.values()] } },
    async advertise(advertisement: ApplicationPeerAdvertisement, options) {
      accessed(); const ttl = options?.ttlMs ?? 600_000, now = Date.now()
      const lease = { advertisement: structuredClone(advertisement), expiresAt: now + ttl, refreshAfter: now + ttl / 2 }
      leases.set(advertisement.peerId, lease); return lease
    },
    async withdraw(peerId) { accessed(); leases.delete(peerId) },
    listenInvitations(peerId, options) {
      accessed()
      const queue = mailbox<{ channel: string; requesterPeerId: string }>()
      let finish!: () => void, ended = false
      const closed = new Promise<void>(resolve => { finish = resolve })
      const close = () => {
        if (ended) return
        ended = true; queue.close(); finish(); options?.signal?.removeEventListener('abort', close)
        if (listeners.get(peerId)?.queue === queue) listeners.delete(peerId)
      }
      listeners.set(peerId, { queue, close }); options?.signal?.addEventListener('abort', close, { once: true })
      return { ready: Promise.resolve(), invitations: queue, closed, close }
    },
    async invite(peerId, invitation) {
      accessed(); const listener = listeners.get(peerId)
      if (listener === undefined) throw new Error('INVITATION_PEER_UNAVAILABLE')
      listener.queue.send(invitation)
    },
    rendezvous(channel, peerId, options) {
      accessed()
      let pair = pairs.get(channel)
      if (pair === undefined) { pair = { slots: [] }; pairs.set(channel, pair) }
      if (pair.slots.length >= 2) throw new Error('RENDEZVOUS_FULL')
      let resolve!: (value: { role: 'offerer' | 'answerer' }) => void
      const ready = new Promise<{ role: 'offerer' | 'answerer' }>(yes => { resolve = yes })
      const queue = mailbox<PeerDescription>(), slot = { peer: peerId, queue, ready: resolve }
      pair.slots.push(slot)
      if (pair.slots.length === 2) { pair.slots[0]!.ready({ role: 'offerer' }); pair.slots[1]!.ready({ role: 'answerer' }) }
      const close = () => { queue.close(); options?.signal?.removeEventListener('abort', close) }
      options?.signal?.addEventListener('abort', close, { once: true })
      return { ready, messages: queue, async send(value) {
        const remote = pair.slots.find(item => item !== slot)
        if (remote === undefined) throw new Error('RENDEZVOUS_PEER_MISSING')
        remote.queue.send(structuredClone(value))
      }, close }
    },
  })
  cleanup.push(() => { for (const value of listeners.values()) value.close(); for (const pair of pairs.values()) for (const slot of pair.slots) slot.queue.close() })
  const open = async (index: number, seed = true) => {
    const session = await openPeerApplication({ device: devices[index]!, authority: await registry.read(), definition,
      ...(seed ? { epochKeys: new Map([[0, key]]) } : {}) })
    cleanup.push(() => session.close()); return session
  }
  return { open, client, registry, get requests() { return requests }, get selections() { return selections },
    block() { blocked = true; for (const value of [...listeners.values()]) value.close() }, unblock() { blocked = false } }
}

const options = {
  configuration: { iceServers: [] }, timeoutMs: 10_000,
  native: { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceAdditionalHostAddresses: ['127.0.0.1'], iceUseIpv4: false, iceUseIpv6: false, iceUseTcp: false },
  retry: { initialDelayMs: 50, maxDelayMs: 100, maxAttempts: 8, jitter: 0 }, recovery: { graceMs: 250, cooldownMs: 1000 },
} satisfies Omit<Parameters<typeof maintainNativeApplicationWebRtc>[1], 'host'>

describe('managed application peer lifecycle', () => {
  it('releases invitation admission when constructing rendezvous fails', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    let attempts = 0
    const host: ApplicationPeerHost = { ...f.client(), rendezvous() {
      attempts++; throw new Error('INVITATION_NETWORK_DOWN')
    } }
    const network = maintainNativeApplicationWebRtc(a, { ...options, host, recovery: false })
    cleanup.push(() => network.close())
    await until(() => network.status.invitationListener === 'listening')
    for (let attempt = 1; attempt <= 3; attempt++) {
      await host.invite(a.deviceId, { channel: `retry-${attempt}`, requesterPeerId: b.deviceId })
      await until(() => attempts === attempt, 1000)
    }
    expect(network.status.activePeers).toBe(0)
    expect(a.status.phase).toBe('ready')
  })

  it('owns late invitations, host-independent commands, bounded availability retry and an eligible automatic successor', async () => {
    const f = await fixture(), a = await f.open(0)
    const netA = maintainNativeApplicationWebRtc(a, { ...options, host: f.client() })
    cleanup.push(() => netA.close())
    await until(() => netA.status.invitationListener === 'listening')
    const b = await f.open(1, false), netB = maintainNativeApplicationWebRtc(b, { ...options, host: f.client() })
    cleanup.push(() => netB.close())
    await netB.ready
    expect(b.status.phase).toBe('ready')
    expect(b.keys.missing()).toEqual([])
    await until(() => netA.status.activePeers === 1 && netB.status.activePeers === 1)
    const before = f.requests
    for (let index = 0; index < 3; index++) await (await b.command('say', `ordinary-${index}`, { operationId: `ordinary-${index}` })).applied({ signal: AbortSignal.timeout(5000) })
    expect(f.requests).toBe(before)
    f.block()
    await until(() => netA.status.invitationListener === 'stopped' && netB.status.invitationListener === 'stopped')
    const blocked = f.requests
    await (await b.command('say', 'host blocked', { operationId: 'blocked' })).applied({ signal: AbortSignal.timeout(5000) })
    expect(f.requests).toBe(blocked)
    expect(b.status.phase).toBe('ready')
    expect(netB.status.activePeers).toBe(1)
    f.unblock()
    await netB.reconnect()
    await until(() => netB.status.invitationListener === 'listening')
    const lostAt = Date.now()
    await netA.close()
    const tail = await a.command('say', 'isolated old tail', { operationId: 'old-tail' })
    await tail.applied()
    await until(() => b.status.role === 'coordinator' && b.status.phase === 'ready')
    expect(Date.now() - lostAt).toBeGreaterThanOrEqual(options.recovery.graceMs)
    expect(f.selections).toBe(1)
    expect((await b.query('messages', null)).value.events).toHaveLength(4)
    const c = await f.open(2, false), netC = maintainNativeApplicationWebRtc(c, { ...options, host: f.client() })
    cleanup.push(() => netC.close())
    await netC.ready
    expect((await c.query('messages', null)).value.events).toHaveLength(4)
    expect(c.keys.missing()).toEqual([])
    expect((await f.registry.read()).generations).toHaveLength(2)
  }, 60_000)
})

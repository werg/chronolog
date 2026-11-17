import type { CapabilitySnapshot, EffectiveCapability } from '@chronolog/capabilities'
import { MemoryOperationStore } from '@chronolog/node-core'
import { assertCanonicalCbor, bytesToHex, generateEd25519KeyPair, utf8, type Ed25519KeyPair } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, frameLivePeerStream, framePeerStream, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import type { SignalLimits } from '@chronolog/signals'
import { frameRtcPeerChannels, WEBRTC_LIVE_LIMITS, type RtcDataChannel } from '@chronolog/transport-webrtc'
import { afterEach, describe, expect, it } from 'vitest'

import { createGovernedPeerService, type GovernedPeerService } from './governed-peer.js'
import { openAuthenticatedPeerLink } from './peer-link.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number): Uint8Array => new Uint8Array(32).fill(value)
function capability(identity: Ed25519KeyPair, role: 'reader' | 'writer', id: number): EffectiveCapability {
  const common = { signingPublicKey: identity.publicKeyBytes,
    transportAuthor: feedIdFromPublicKey(identity.publicKeyBytes),
    subjectId: identity.publicKeyBytes, validFromRevision: 0n }
  return { id: bytes(id), grantedAtRevision: 0n, grant: role === 'writer'
    ? { ...common, role, program: { sql: false, topics: [], signals: ['typing'] } }
    : { ...common, role } }
}
async function replicas(writer = true, signalLimits?: SignalLimits) {
  const identities = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
  const grants = [capability(identities[0], 'reader', 1), capability(identities[1], 'reader', 2)]
  if (writer) grants.push(capability(identities[0], 'writer', 3))
  const original: CapabilitySnapshot = { encryptionEpoch: 0n, groupId: bytes(5), revision: 0n, revisionDigest: bytes(6), rootAdminPublicKey: identities[0].publicKeyBytes,
    capabilityLogFeed: bytes(7), capabilities: new Map(grants.map(grant => [bytesToHex(grant.id), grant])), policies: new Map() }
  const snapshots = [original, original]
  const transports: PortableFeedTransport[] = [], services: GovernedPeerService[] = []
  for (const [index, identity] of identities.entries()) {
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(new MemoryOperationStore(), webFeedCrypto),
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey), crypto: webFeedCrypto })
    transports.push(transport); cleanup.push(() => transport.close())
    const service = await createGovernedPeerService({ identity, groupId: original.groupId, activeMembership: () => snapshots[index]!,
      local: transport.asLink(), attach: link => transport.connect(link),
      ...(signalLimits === undefined ? {} : { signalLimits }) })
    services.push(service); cleanup.push(() => service.close())
  }
  return { identities, snapshots, transports, services }
}
async function connect(left: GovernedPeerService, right: GovernedPeerService, expected?: Uint8Array, withLive = true,
  dispatch: () => boolean | Promise<boolean> = () => true) {
  const lane = <T,>(frame: (options: Parameters<typeof framePeerStream>[0]) => T) => {
    const forward = new TransformStream<Uint8Array, Uint8Array>(), backward = new TransformStream<Uint8Array, Uint8Array>()
    return [frame({ readable: backward.readable, writable: forward.writable }),
      frame({ readable: forward.readable, writable: backward.writable })]
  }
  const reliable = lane(framePeerStream), live = withLive ? lane(frameLivePeerStream) : undefined
  const connections = reliable.map((connection, index) => ({ ...connection, ...(live === undefined ? {} : {
    live: { ...live[index]!, async trySend(bytes: Uint8Array, options?: { readonly signal?: AbortSignal }) {
      if (!await dispatch()) return false
      return live[index]!.trySend(bytes, options)
    } }, signal: AbortSignal.any([connection.signal, live[index]!.signal]),
  }),
    async close() { await Promise.all([connection.close(), live?.[index]?.close()]) } }))
  return Promise.all([left.connectPeer({ connection: connections[0]!, ...(expected === undefined ? {} : { peerIdentity: expected }) }),
    right.connectPeer({ connection: connections[1]! })])
}

class RtcChannel extends EventTarget implements RtcDataChannel {
  readonly label = 'test-lane'
  readonly maxPacketLifeTime = null
  readyState = 'connecting'
  bufferedAmount = 0
  bufferedAmountLowThreshold = 0
  binaryType = 'arraybuffer'
  other!: RtcChannel
  readonly sent: Uint8Array[] = []
  constructor(readonly ordered: boolean, readonly maxRetransmits: number | null) { super() }
  send(bytes: ArrayBuffer): void {
    if (this.readyState !== 'open') throw new Error('test lane closed')
    const copy = bytes.slice(0)
    this.sent.push(new Uint8Array(copy))
    queueMicrotask(() => { if (this.other.readyState === 'open') this.other.dispatchEvent(new MessageEvent('message', { data: copy })) })
  }
  close(): void {
    if (this.readyState === 'closed') return
    this.readyState = 'closed'; this.dispatchEvent(new Event('close')); this.other.close()
  }
}

function rtcConnections() {
  const lane = (ordered: boolean, retransmits: number | null) => {
    const a = new RtcChannel(ordered, retransmits), b = new RtcChannel(ordered, retransmits)
    a.other = b; b.other = a
    return [a, b] as const
  }
  const reliable = lane(true, null), live = lane(false, 0)
  const connections = reliable.map((channel, index) => frameRtcPeerChannels({ reliable: channel, live: live[index]! }))
  for (const channel of [...reliable, ...live]) channel.readyState = 'open'
  for (const channel of [...reliable, ...live]) channel.dispatchEvent(new Event('open'))
  return { connections, live }
}

describe('owned governed peer composition', () => {
  it('retires a physical peer when cancelled live transport work does not settle', async () => {
    const { services } = await replicas()
    let entered!: () => void, writes = 0
    const started = new Promise<void>(resolve => { entered = resolve })
    const sessions = await connect(services[0]!, services[1]!, undefined, true, async () => {
      writes++; entered(); return new Promise<never>(() => {})
    })
    const controller = new AbortController()
    const sending = services[0]!.signals.send('typing', 'cancelled preview', { signal: controller.signal })
    const cancelled = expect(sending).rejects.toThrow('cancel blocked live dispatch')
    await started
    controller.abort(new Error('cancel blocked live dispatch')); await cancelled
    await expect.poll(() => sessions[0].signal.aborted).toBe(true)
    // Either owner can retire first: the signal channel closes its route, or
    // the peer watchdog reports the cancelled write. Both end this session.
    await sessions[0].completion.catch(() => undefined)
    await expect(services[0]!.signals.send('typing', 'later preview')).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    expect(writes).toBe(1)
  })

  it('keeps durable replication available through live congestion and sends only fresh observations on recovery', async () => {
    const { services, transports } = await replicas()
    let busy = true
    const sessions = await connect(services[0]!, services[1]!, undefined, true, () => !busy)
    await expect(services[0]!.signals.send('typing', 'discarded')).rejects.toMatchObject({ code: 'SIGNAL_BACKPRESSURE' })
    expect(sessions.every(session => !session.signal.aborted)).toBe(true)
    await transports[0]!.publish(new Uint8Array([1, 2, 3]))
    await transports[1]!.catchUp()
    const history = await transports[0]!.history()
    const original = await transports[0]!.asLink().read(transports[0]!.identity, 0n, 1)
    expect(await transports[1]!.asLink().read(transports[0]!.identity, 0n, 1)).toEqual(original)
    expect(history).toHaveLength(1)
    busy = false
    const iterator = services[1]!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    const sent = await services[0]!.signals.send('typing', 'fresh')
    expect((await receiving).value).toEqual(sent)
    expect(sent.payload).toBe('fresh')
    expect(sessions.every(session => !session.signal.aborted)).toBe(true)
    expect(await transports[0]!.history()).toEqual(history)
    await iterator.return?.()
  })

  it('applies deployment signal limits without changing durable membership policy', async () => {
    const { services } = await replicas(true, { maxTtlMs: 500 })
    await connect(services[0]!, services[1]!)
    await expect(services[0]!.signals.send('typing', true, { ttlMs: 501 })).rejects.toThrow('SIGNAL_TTL_INVALID')
    const iterator = services[1]!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    const sent = await services[0]!.signals.send('typing', true, { ttlMs: 400 })
    expect((await receiving).value).toEqual(sent)
    expect(sent.expiresAtMs - sent.issuedAtMs).toBe(400)
    await iterator.return?.()
  })

  it('refuses congested live dispatch while preserving authenticated history and the next healthy signal', async () => {
    const { services, transports } = await replicas(), { connections, live } = rtcConnections()
    const sessions = await Promise.all(services.map((service, index) => service.connectPeer({ connection: connections[index]! })))
    const iterator = services[1]!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    try {
      live[0].bufferedAmount = WEBRTC_LIVE_LIMITS.bufferedBytes
      await expect(services[0]!.signals.send('typing', 'discarded preview')).rejects.toThrow('SIGNAL_BACKPRESSURE')
      expect(live[0].sent).toEqual([])
      expect(sessions.every(session => !session.signal.aborted)).toBe(true)
      const record = await transports[0]!.publish(utf8('durable history during live congestion'))
      await transports[1]!.catchUp()
      expect((await transports[1]!.get(record.id))?.payload).toEqual(record.payload)
      live[0].bufferedAmount = 0
      const sent = await services[0]!.signals.send('typing', 'current preview')
      expect((await receiving).value).toEqual(sent)
      expect(live[0].sent).toHaveLength(1)
      expect(sessions.every(session => !session.signal.aborted)).toBe(true)
    } finally { await iterator.return?.(); await Promise.all(sessions.map(session => session.close())) }
  })

  it('attaches reliable-only peers for replication without claiming a live route', async () => {
    const { services, transports } = await replicas()
    const sessions = await connect(services[0]!, services[1]!, undefined, false)
    expect(sessions.every(session => !session.signal.aborted)).toBe(true)
    expect((await transports[0]!.status()).peers).toContain(transports[1]!.identity)
    await expect(services[0]!.signals.send('typing', true)).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    await transports[0]!.catchUp()
    expect(await transports[0]!.history()).toEqual([])
  })

  it('opens without a publisher grant, receives read-only, and selects a later topic grant dynamically', async () => {
    const { services, identities, snapshots, transports } = await replicas(false)
    const [sender, receiver] = services
    await connect(sender!, receiver!, identities[1].publicKeyBytes)
    await expect(sender!.signals.send('typing', true)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    const writer = capability(identities[0], 'writer', 3)
    const membership: CapabilitySnapshot = { ...snapshots[0]!, revision: 1n,
      capabilities: new Map([...snapshots[0]!.capabilities, [bytesToHex(writer.id), writer]]) }
    snapshots[0] = membership; snapshots[1] = membership
    const iterator = receiver!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    const sent = await sender!.signals.send('typing', { active: true })
    expect((await receiving).value).toEqual(sent)
    await expect(receiver!.signals.send('typing', true)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    await expect(sender!.signals.send('durable-chat', true)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    for (const transport of transports) {
      expect(await transport.history()).toEqual([])
      expect(await transport.evidenceHistory()).toEqual([])
    }
    await iterator.return?.()
  })

  it('keeps a healthy connection after publisher revocation and later regrant', async () => {
    const { services, snapshots, identities } = await replicas()
    const sessions = await connect(services[0]!, services[1]!)
    const revoke = { ...snapshots[0]!.capabilities.get(bytesToHex(bytes(3)))!, revokedAtRevision: 1n }
    snapshots[0] = { ...snapshots[0]!, revision: 1n, capabilities: new Map([...snapshots[0]!.capabilities, [bytesToHex(revoke.id), revoke]]) }
    await expect(services[0]!.signals.send('typing', true)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    expect(sessions.every(session => !session.signal.aborted)).toBe(true)
    const replacement = capability(identities[0], 'writer', 4)
    const snapshot: CapabilitySnapshot = { ...snapshots[0], revision: 2n,
      capabilities: new Map([...snapshots[0].capabilities, [bytesToHex(replacement.id), replacement]]) }
    snapshots[0] = snapshot; snapshots[1] = snapshot
    const iterator = services[1]!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    const sent = await services[0]!.signals.send('typing', false)
    expect((await receiving).value).toEqual(sent)
    expect(sessions.every(session => !session.signal.aborted)).toBe(true)
    await iterator.return?.()
  })

  it('drops an in-flight signal after writer revocation while reader access and durable history remain usable', async () => {
    const { services, snapshots, identities, transports } = await replicas()
    let release!: () => void, entered!: () => void, checked!: () => void, first = true
    const gate = new Promise<void>(resolve => { release = resolve })
    const dispatched = new Promise<void>(resolve => { entered = resolve })
    const denied = new Promise<void>(resolve => { checked = resolve })
    const sessions = await connect(services[0]!, services[1]!, undefined, true, async () => {
      if (first) { first = false; entered(); await gate }
      return true
    })
    const iterator = services[1]!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    try {
      const sending = services[0]!.signals.send('typing', 'signed before revocation')
      await dispatched
      const writerId = bytesToHex(bytes(3))
      const revoked = { ...snapshots[1]!.capabilities.get(writerId)!, revokedAtRevision: 1n }
      const capabilities = new Map([...snapshots[1]!.capabilities, [writerId, revoked]])
      const get = capabilities.get.bind(capabilities)
      capabilities.get = id => { if (id === writerId) checked(); return get(id) }
      const current: CapabilitySnapshot = { ...snapshots[1]!, revision: 1n, capabilities }
      snapshots[1] = current
      release(); await sending; await denied
      const record = await transports[0]!.publish(utf8('history after writer-only revocation'))
      await transports[1]!.catchUp()
      expect((await transports[1]!.get(record.id))?.payload).toEqual(record.payload)
      expect(sessions.every(session => !session.signal.aborted)).toBe(true)
      snapshots[0] = current
      await expect(services[0]!.signals.send('typing', 'new unauthorized intent')).rejects.toThrow('SIGNAL_UNAUTHORIZED')
      const replacement = capability(identities[0], 'writer', 4)
      const renewed: CapabilitySnapshot = { ...current, revision: 2n,
        capabilities: new Map([...current.capabilities, [bytesToHex(replacement.id), replacement]]) }
      snapshots[0] = renewed; snapshots[1] = renewed
      const fresh = await services[0]!.signals.send('typing', 'fresh after regrant')
      expect((await receiving).value).toEqual(fresh)
      expect(sessions.every(session => !session.signal.aborted)).toBe(true)
    } finally { release(); await iterator.return?.() }
  })

  it('rechecks the sender reader grant on an established incoming signal route', async () => {
    const { services, snapshots } = await replicas()
    const sessions = await connect(services[0]!, services[1]!)
    const revoke = { ...snapshots[1]!.capabilities.get(bytesToHex(bytes(1)))!, revokedAtRevision: 1n }
    snapshots[1] = { ...snapshots[1]!, revision: 1n, capabilities: new Map([...snapshots[1]!.capabilities, [bytesToHex(revoke.id), revoke]]) }
    const rejected = expect(sessions[1].completion).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    // Dispatch is not a delivery receipt; remote rejection can close it first.
    const [sending] = await Promise.allSettled([services[0]!.signals.send('typing', 'after reader revocation')])
    await rejected
    if (sending.status === 'rejected') expect(sending.reason).toMatchObject({ message: expect.stringMatching(/^(SIGNAL_ROUTE_CLOSED|PEER_CONNECTION_CLOSED)$/u) })
    expect(sessions[1].signal.aborted).toBe(true)
  })

  it('fences an old session cleanup from its replacement and closes all owned routes', async () => {
    const { services, transports } = await replicas()
    const original = await connect(services[0]!, services[1]!)
    const replacement = await connect(services[0]!, services[1]!)
    await Promise.all(original.map(session => session.close()))
    expect(replacement.every(session => !session.signal.aborted)).toBe(true)
    expect((await transports[0]!.status()).peers).toContain(transports[1]!.identity)
    const iterator = services[1]!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    const sent = await services[0]!.signals.send('typing', 'replacement')
    expect((await receiving).value).toEqual(sent)
    await services[0]!.close()
    expect(replacement[0].signal.aborted).toBe(true)
    await expect(services[0]!.signals.send('typing', true)).rejects.toThrow('SIGNAL_CHANNEL_CLOSED')
    await iterator.return?.()
  })

  it('refuses a valid reader claiming another reader feed without replacing the live session', async () => {
    const { services, snapshots, identities, transports } = await replicas()
    const healthy = await connect(services[0]!, services[1]!)
    const attacker = await generateEd25519KeyPair(), grant = capability(attacker, 'reader', 9)
    snapshots[0] = { ...snapshots[0]!, revision: 1n,
      capabilities: new Map([...snapshots[0]!.capabilities, [bytesToHex(grant.id), grant]]) }
    const forward = new TransformStream<Uint8Array, Uint8Array>(), backward = new TransformStream<Uint8Array, Uint8Array>()
    const accepting = services[0]!.connectPeer({ connection: framePeerStream({ readable: backward.readable, writable: forward.writable }) })
    const forged = openAuthenticatedPeerLink({ connection: framePeerStream({ readable: forward.readable, writable: backward.writable }),
      local: transports[1]!.asLink(), identity: attacker, groupId: snapshots[0].groupId, grantId: grant.id,
      authorizePeer: peer => bytesToHex(peer.authorId) === bytesToHex(identities[0].publicKeyBytes) })
    const results = await Promise.allSettled([accepting, forged])
    expect(results[0]).toMatchObject({ status: 'rejected', reason: new Error('PEER_READ_UNAUTHORIZED') })
    if (results[1].status === 'fulfilled') await results[1].value.close()
    expect(healthy.every(session => !session.signal.aborted)).toBe(true)
    expect((await transports[0]!.status()).peers).toContain(transports[1]!.identity)
  })

  it('does not install an earlier slow handshake after a newer session has attached', async () => {
    const { services, snapshots, identities, transports } = await replicas()
    const forward = new TransformStream<Uint8Array, Uint8Array>(), backward = new TransformStream<Uint8Array, Uint8Array>()
    const left = framePeerStream({ readable: backward.readable, writable: forward.writable })
    let entered!: () => void, release!: () => void
    const waiting = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    const earlier = services[0]!.connectPeer({ connection: { ...left, async send(frame) {
      const decoded = assertCanonicalCbor(frame)
      if (Array.isArray(decoded) && decoded[2] === 'hello') entered()
      // Delay the reliable stream, preserving HELLO before its signed proof.
      await gate
      await left.send(frame)
    } } })
    const outcome = earlier.then(() => null, (error: unknown) => error)
    const counterpart = openAuthenticatedPeerLink({ connection: framePeerStream({ readable: forward.readable, writable: backward.writable }),
      local: transports[1]!.asLink(), identity: identities[1], groupId: snapshots[0]!.groupId, grantId: bytes(2), authorizePeer: () => true })
    void counterpart.catch(() => undefined)
    await waiting
    const current = await connect(services[0]!, services[1]!)
    release()
    const [oldRemote] = await Promise.allSettled([counterpart])
    expect(await outcome).toMatchObject({ message: 'PEER_CONNECTION_SUPERSEDED' })
    // Supersession may close the counterpart before its opening promise settles.
    if (oldRemote.status === 'fulfilled') await oldRemote.value.close()
    else expect(oldRemote.reason).toMatchObject({ message: 'PEER_CONNECTION_CLOSED' })
    expect(current.every(session => !session.signal.aborted)).toBe(true)
    const iterator = services[1]!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    const sent = await services[0]!.signals.send('typing', 'current route')
    expect((await receiving).value).toEqual(sent)
    await iterator.return?.()
  })
})

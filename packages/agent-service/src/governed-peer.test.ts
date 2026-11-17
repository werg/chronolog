import type { CapabilitySnapshot, EffectiveCapability } from '@chronolog/capabilities'
import { MemoryOperationStore } from '@chronolog/node-core'
import { assertCanonicalCbor, bytesToHex, generateEd25519KeyPair, type Ed25519KeyPair } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { framePeerStream } from './framing.js'
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
async function replicas(writer = true) {
  const identities = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
  const grants = [capability(identities[0], 'reader', 1), capability(identities[1], 'reader', 2)]
  if (writer) grants.push(capability(identities[0], 'writer', 3))
  const original: CapabilitySnapshot = { encryptionEpoch: 0n, groupId: bytes(5), revision: 0n, revisionDigest: bytes(6), rootAdminPublicKey: identities[0].publicKeyBytes,
    capabilityLogFeed: bytes(7), capabilities: new Map(grants.map(grant => [bytesToHex(grant.id), grant])), policies: new Map(), validatorFloorMs: 0n }
  const snapshots = [original, original]
  const transports: PortableFeedTransport[] = [], services: GovernedPeerService[] = []
  for (const [index, identity] of identities.entries()) {
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(new MemoryOperationStore(), webFeedCrypto),
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey), crypto: webFeedCrypto })
    transports.push(transport); cleanup.push(() => transport.close())
    const service = await createGovernedPeerService({ identity, groupId: original.groupId, activeMembership: () => snapshots[index]!,
      local: transport.asLink(), attach: link => transport.connect(link) })
    services.push(service); cleanup.push(() => service.close())
  }
  return { identities, snapshots, transports, services }
}
async function connect(left: GovernedPeerService, right: GovernedPeerService, expected?: Uint8Array, withLive = true) {
  const lane = () => {
    const forward = new TransformStream<Uint8Array, Uint8Array>(), backward = new TransformStream<Uint8Array, Uint8Array>()
    return [framePeerStream({ readable: backward.readable, writable: forward.writable }),
      framePeerStream({ readable: forward.readable, writable: backward.writable })]
  }
  const reliable = lane(), live = withLive ? lane() : undefined
  const connections = reliable.map((connection, index) => ({ ...connection, ...(live === undefined ? {} : { live: live[index]! }),
    async close() { await Promise.all([connection.close(), live?.[index]?.close()]) } }))
  return Promise.all([left.connectPeer({ connection: connections[0]!, ...(expected === undefined ? {} : { peerIdentity: expected }) }),
    right.connectPeer({ connection: connections[1]! })])
}

describe('owned governed peer composition', () => {
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

  it('rechecks the sender reader grant on an established incoming signal route', async () => {
    const { services, snapshots } = await replicas()
    const sessions = await connect(services[0]!, services[1]!)
    const revoke = { ...snapshots[1]!.capabilities.get(bytesToHex(bytes(1)))!, revokedAtRevision: 1n }
    snapshots[1] = { ...snapshots[1]!, revision: 1n, capabilities: new Map([...snapshots[1]!.capabilities, [bytesToHex(revoke.id), revoke]]) }
    const rejected = expect(sessions[1].completion).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    await services[0]!.signals.send('typing', 'after reader revocation')
    await rejected
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
    const oldRemote = await counterpart
    expect(await outcome).toMatchObject({ message: 'PEER_CONNECTION_SUPERSEDED' })
    await oldRemote.close()
    expect(current.every(session => !session.signal.aborted)).toBe(true)
    const iterator = services[1]!.signals.subscribe()[Symbol.asyncIterator](), receiving = iterator.next()
    const sent = await services[0]!.signals.send('typing', 'current route')
    expect((await receiving).value).toEqual(sent)
    await iterator.return?.()
  })
})

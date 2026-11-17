import type { CapabilitySnapshot, EffectiveCapability } from '@chronolog/capabilities'
import { createGovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { MemoryOperationStore } from '@chronolog/node-core'
import { bytesToHex, generateEd25519KeyPair } from '@chronolog/protocol'
import { ChangeSignal, DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner, type FeedLink } from '@chronolog/records'
import { SignalBackpressureError } from '@chronolog/signals'
import { frameRtcPeerChannels, WEBRTC_LIVE_LIMITS, type RtcDataChannel } from '@chronolog/transport-webrtc'
import { expect, it } from 'vitest'

/** Real framing and peer authorization over deterministic in-memory SCTP channels. */
class Channel extends EventTarget implements RtcDataChannel {
  readonly maxPacketLifeTime = null
  readonly label: string
  readonly ordered: boolean
  readonly maxRetransmits: number | null
  readyState = 'connecting'
  bufferedAmount = 0
  bufferedAmountLowThreshold = 0
  binaryType = 'arraybuffer'
  other!: Channel
  readonly sent: Uint8Array[] = []
  constructor(live: boolean) {
    super(); this.label = live ? 'chronolog.live' : 'chronolog.reliable'
    this.ordered = !live; this.maxRetransmits = live ? 0 : null
  }
  send(data: ArrayBuffer): void {
    if (this.readyState !== 'open') throw new Error('CHANNEL_CLOSED')
    const copy = data.slice(0); this.sent.push(new Uint8Array(copy))
    queueMicrotask(() => {
      if (this.other.readyState === 'open') this.other.dispatchEvent(new MessageEvent('message', { data: copy }))
    })
  }
  close(): void {
    if (this.readyState === 'closed') return
    this.readyState = 'closed'; this.dispatchEvent(new Event('close')); this.other.close()
  }
}

function channels(live: boolean) {
  const left = new Channel(live), right = new Channel(live)
  left.other = right; right.other = left
  return { left, right, open() {
    left.readyState = right.readyState = 'open'
    left.dispatchEvent(new Event('open')); right.dispatchEvent(new Event('open'))
  } }
}

function emptyLink(identity: string): FeedLink {
  const changes = new ChangeSignal()
  return { identity, async head() { return 0n }, async evidenceHead() { return 0n },
    async read() { return [] }, async readEvidence() { return [] }, async readPayload() { return null },
    watch: signal => changes.watch(signal) }
}

it.each([
  { termination: 'malformed live datagram', target: 1, reason: 'WEBRTC_LIVE_FRAME_INVALID' },
  { termination: 'malformed reliable packet', target: 1, reason: 'WEBRTC_PACKET_INVALID' },
  { termination: 'live channel closure', target: 0, reason: 'WEBRTC_LIVE_ENDED' },
  { termination: 'reliable channel closure', target: 0, reason: 'WEBRTC_CONNECTION_ENDED' },
  { termination: 'explicit owner closure', target: 0, reason: 'WEBRTC_CONNECTION_CLOSED' },
] as const)('preserves $termination through authenticated sibling-lane cleanup', async ({ termination, target, reason }) => {
  const identities = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
  const history = channels(false), live = channels(true)
  const connections = [frameRtcPeerChannels({ reliable: history.left, live: live.left }),
    frameRtcPeerChannels({ reliable: history.right, live: live.right })]
  history.open(); live.open()
  await Promise.all(connections.map(connection => connection.ready))
  const sessions = await Promise.all(identities.map((identity, index) => openAuthenticatedPeerLink({
    connection: connections[index]!, local: emptyLink(`feed-${index}`), identity,
    groupId: new Uint8Array(32).fill(1), grantId: new Uint8Array(32).fill(2), authorizePeer: () => true,
  })))
  try {
    if (termination === 'malformed live datagram') live.left.send(new ArrayBuffer(WEBRTC_LIVE_LIMITS.frameBytes + 1))
    else if (termination === 'malformed reliable packet') history.left.send(new ArrayBuffer(1))
    else if (termination === 'live channel closure') live.left.close()
    else if (termination === 'reliable channel closure') history.left.close()
    else await connections[0]!.close()
    await expect(sessions[target]!.completion).rejects.toThrow(reason)
    expect(connections[target]!.signal.aborted).toBe(true)
    expect(connections[target]!.signal.reason).toMatchObject({ message: reason })
    expect([history.left, history.right, live.left, live.right].map(channel => channel.readyState)).toEqual(Array(4).fill('closed'))
  } finally {
    await Promise.all(sessions.map(session => session.close()))
    await Promise.all(connections.map(connection => connection.close()))
  }
})

it('keeps the authenticated durable session after live congestion and dispatches only a later fresh signal', async () => {
  const identities = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
  const grants: EffectiveCapability[] = identities.map((identity, index) => ({
    id: new Uint8Array(32).fill(index + 1), grantedAtRevision: 0n,
    grant: { role: 'reader', signingPublicKey: identity.publicKeyBytes, subjectId: identity.publicKeyBytes,
      transportAuthor: feedIdFromPublicKey(identity.publicKeyBytes), validFromRevision: 0n },
  }))
  grants.push({ id: new Uint8Array(32).fill(3), grantedAtRevision: 0n,
    grant: { role: 'writer', signingPublicKey: identities[0].publicKeyBytes, subjectId: identities[0].publicKeyBytes,
      transportAuthor: feedIdFromPublicKey(identities[0].publicKeyBytes), validFromRevision: 0n,
      program: { sql: false, topics: [], signals: ['typing'] } } })
  const snapshot: CapabilitySnapshot = { groupId: new Uint8Array(32).fill(5), revision: 0n, revisionDigest: new Uint8Array(32).fill(6),
    rootAdminPublicKey: identities[0].publicKeyBytes, capabilityLogFeed: new Uint8Array(32).fill(7),
    capabilities: new Map(grants.map(grant => [bytesToHex(grant.id), grant])), policies: new Map(), validatorFloorMs: 0n }
  const transports = await Promise.all(identities.map(async identity => new PortableFeedTransport({
    store: await DurableFeedStore.open(new MemoryOperationStore(), webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey),
  })))
  let attachments = 0
  const services = await Promise.all(identities.map((identity, index) => createGovernedPeerService({ identity,
    groupId: snapshot.groupId, activeMembership: () => snapshot, local: transports[index]!.asLink(),
    attach(link) { attachments++; return transports[index]!.connect(link) },
  })))
  const history = channels(false), live = channels(true)
  const connections = [frameRtcPeerChannels({ reliable: history.left, live: live.left }),
    frameRtcPeerChannels({ reliable: history.right, live: live.right })]
  history.open(); live.open()
  const received = services[1]!.signals.subscribe({ topics: ['typing'] })[Symbol.asyncIterator]()
  try {
    await Promise.all(connections.map(connection => connection.ready))
    const sessions = await Promise.all(services.map((service, index) => service.connectPeer({ connection: connections[index]! })))
    expect(attachments).toBe(2)
    live.left.bufferedAmount = WEBRTC_LIVE_LIMITS.bufferedBytes
    await expect(services[0]!.signals.send('typing', { text: 'congested intent' })).rejects.toBeInstanceOf(SignalBackpressureError)
    expect(live.left.sent).toEqual([])
    expect(sessions.every(session => !session.signal.aborted)).toBe(true)

    const durable = await transports[0]!.publish(new Uint8Array([8, 9, 10]))
    const original = { id: durable.id, author: durable.author, sequence: durable.sequence, payload: durable.payload }
    await transports[1]!.catchUp()
    expect(await transports[1]!.history()).toMatchObject([original])
    expect(history.left.readyState).toBe('open')
    expect(history.right.readyState).toBe('open')

    live.left.bufferedAmount = 0
    const next = received.next()
    const fresh = await services[0]!.signals.send('typing', { text: 'fresh intent' })
    expect((await next).value).toEqual(fresh)
    expect(live.left.sent).toHaveLength(1)
    expect(sessions.every(session => !session.signal.aborted)).toBe(true)
    expect(attachments).toBe(2)
    expect(await transports[1]!.history()).toMatchObject([original])
  } finally {
    await received.return?.()
    await Promise.all(services.map(service => service.close()))
    await Promise.all(connections.map(connection => connection.close()))
    await Promise.all(transports.map(transport => transport.close()))
  }
})

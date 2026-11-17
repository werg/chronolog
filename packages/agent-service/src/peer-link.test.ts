import { SignalChannel, generateSignalIdentity, type SignalRoute } from '@chronolog/signals'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import os from 'node:os'
import { join } from 'node:path'

import { bytesToHex, sha256 } from '@chronolog/canonical'
import { MemoryOperationStore } from '@chronolog/node-core'
import { MAX_LEDGER_PAYLOAD_BYTES } from '@chronolog/node-core/ledger'
import { assertCanonicalCbor, encodeCanonicalCbor, equalBytes, generateEd25519KeyPair, utf8, type CborValue } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner, type FeedLink } from '@chronolog/records'
import { FeedTransport } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { framePeerStream } from './framing.js'
import { openAuthenticatedPeerLink, type AuthenticatedPeerLinkOptions } from './peer-link.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => {
  try { for (const close of cleanup.splice(0).reverse()) await close() }
  finally { vi.useRealTimers() }
})

function connections() {
  const lane = () => {
    const leftToRight = new TransformStream<Uint8Array, Uint8Array>(), rightToLeft = new TransformStream<Uint8Array, Uint8Array>()
    return [framePeerStream({ readable: rightToLeft.readable, writable: leftToRight.writable }),
      framePeerStream({ readable: leftToRight.readable, writable: rightToLeft.writable })] as const
  }
  const reliable = lane(), live = lane()
  const compose = (index: 0 | 1) => ({ ...reliable[index], live: live[index],
    signal: AbortSignal.any([reliable[index].signal, live[index].signal]),
    async close() { await Promise.all([reliable[index].close(), live[index].close()]) } })
  return [compose(0), compose(1)] as const
}

async function portable() {
  const identity = await generateEd25519KeyPair()
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(new MemoryOperationStore(), webFeedCrypto),
    crypto: webFeedCrypto, signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
  cleanup.push(() => transport.close())
  return { identity, transport }
}

async function payloadSession(readPayload: (hash: string) => Promise<Uint8Array | null>, corruptReply = false) {
  const server = await portable(), client = await portable()
  const [serverConnection, clientConnection] = connections()
  let active = true
  const outgoing = corruptReply ? { ...serverConnection, async send(bytes: Uint8Array) {
    const decoded = assertCanonicalCbor(bytes)
    if (Array.isArray(decoded) && decoded[2] === 'record' && decoded[4] instanceof Uint8Array) {
      const fields = [...decoded] as CborValue[], corrupted = new Uint8Array(decoded[4])
      corrupted[corrupted.length - 1]! ^= 1
      fields[4] = corrupted
      await serverConnection.send(encodeCanonicalCbor(fields))
    } else await serverConnection.send(bytes)
  } } : serverConnection
  const groupId = new Uint8Array(32).fill(11), grantId = new Uint8Array(32).fill(12)
  const [serverLink, clientLink] = await Promise.all([
    openAuthenticatedPeerLink({ connection: outgoing, local: { ...server.transport.asLink(), readPayload }, groupId, grantId,
      identity: server.identity, authorizePeer: peer => active && equalBytes(peer.authorId, client.identity.publicKeyBytes) }),
    openAuthenticatedPeerLink({ connection: clientConnection, local: client.transport.asLink(), groupId, grantId,
      identity: client.identity, authorizePeer: peer => equalBytes(peer.authorId, server.identity.publicKeyBytes) }),
  ])
  cleanup.push(async () => { await Promise.all([serverLink.close(), clientLink.close()]) })
  return { server: serverLink, client: clientLink, revoke: () => { active = false } }
}

async function rangeSession(range: 'records' | 'evidence', read: () => Promise<readonly Uint8Array[]>,
  afterRecord?: () => Promise<void>, options: {
    readonly beforeRequest?: () => Promise<void>
    readonly afterRequest?: () => Promise<void>
    readonly timeouts?: Pick<AuthenticatedPeerLinkOptions,
      'handshakeTimeoutMs' | 'sendTimeoutMs' | 'responseIdleTimeoutMs' | 'requestTimeoutMs'>
  } = {}) {
  const server = await portable(), client = await portable(), [outgoing, incoming] = connections()
  let active = true
  const sent: Uint8Array[] = []
  const connection = { ...outgoing, async send(bytes: Uint8Array) {
    const frame = assertCanonicalCbor(bytes)
    await outgoing.send(bytes)
    if (Array.isArray(frame) && frame[2] === 'record' && frame[4] instanceof Uint8Array) {
      sent.push(frame[4].slice())
      await afterRecord?.()
    }
  } }
  const clientConnection = { ...incoming, async send(bytes: Uint8Array) {
    const frame = assertCanonicalCbor(bytes)
    const request = Array.isArray(frame) && frame[2] === 'range'
    if (request) await options.beforeRequest?.()
    await incoming.send(bytes)
    if (request) await options.afterRequest?.()
  } }
  const local: FeedLink = { ...server.transport.asLink(), ...(range === 'records' ? { read } : { readEvidence: read }) }
  const groupId = new Uint8Array(32).fill(13), grantId = new Uint8Array(32).fill(14)
  const [serverLink, clientLink] = await Promise.all([
    openAuthenticatedPeerLink({ connection, local, groupId, grantId, identity: server.identity,
      authorizePeer: peer => active && equalBytes(peer.authorId, client.identity.publicKeyBytes) }),
    openAuthenticatedPeerLink({ connection: clientConnection, local: client.transport.asLink(), groupId, grantId, identity: client.identity,
      authorizePeer: peer => equalBytes(peer.authorId, server.identity.publicKeyBytes), ...options.timeouts }),
  ])
  cleanup.push(async () => { await Promise.all([serverLink.close(), clientLink.close()]) })
  return { sent, client: clientLink, hint: () => outgoing.send(encodeCanonicalCbor([1n, 'chronolog/peer/v1', 'changed'])),
    revoke: () => { active = false }, read: (limit = 8) => range === 'records'
    ? clientLink.link.read(server.transport.identity, 0n, limit) : clientLink.link.readEvidence(0n, limit) }
}

async function signalSession(receive?: (frame: Uint8Array) => Promise<void>, options?: {
  readonly dispatch?: () => Promise<void>
  readonly sendTimeoutMs?: number
  readonly onError?: (error: unknown) => void
}) {
  const server = await portable(), client = await portable(), [outgoing, incoming] = connections()
  const sent: Uint8Array[] = []
  let incomingActive = true
  const received: Uint8Array[] = []
  let active = true, guard: (() => Promise<void>) | undefined
  const groupId = new Uint8Array(32).fill(31), grantId = new Uint8Array(32).fill(32)
  const [sender, receiver] = await Promise.all([
    openAuthenticatedPeerLink({ connection: { ...outgoing, live: { ...outgoing.live, async send(bytes, sendOptions) {
      sent.push(bytes.slice()); await options?.dispatch?.()
      await outgoing.live.send(bytes, sendOptions)
    } } }, local: server.transport.asLink(), identity: server.identity, groupId, grantId,
      async authorizePeer() { await guard?.(); return active },
      ...(options?.sendTimeoutMs === undefined ? {} : { sendTimeoutMs: options.sendTimeoutMs }) }),
    openAuthenticatedPeerLink({ connection: incoming, local: client.transport.asLink(), identity: client.identity,
      groupId, grantId, authorizePeer: () => incomingActive,
      receiveSignal: async frame => { received.push(frame); await receive?.(frame) },
      ...(options?.onError === undefined ? {} : { onSignalError: options.onError }) }),
  ])
  cleanup.push(async () => { await Promise.all([sender.close(), receiver.close()]) })
  return { sender, receiver, sent, received, revokeIncoming() { incomingActive = false }, revoke() { active = false }, block() {
    let entered!: () => void, release!: () => void
    const blocked = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    guard = async () => { guard = undefined; entered(); await gate }
    return { blocked, release }
  } }
}

async function headSession(kind: 'records' | 'evidence', read: () => Promise<bigint>, invalidReply?: CborValue) {
  const server = await portable(), client = await portable(), [outgoing, incoming] = connections()
  const groupId = new Uint8Array(32).fill(41), grantId = new Uint8Array(32).fill(42), released: bigint[] = []
  let active = true
  const [serverLink, clientLink] = await Promise.all([
    openAuthenticatedPeerLink({ connection: { ...outgoing, async send(bytes) {
      const frame = assertCanonicalCbor(bytes)
      if (Array.isArray(frame) && frame[2] === 'head-result') {
        released.push(frame[4] as bigint)
        if (invalidReply !== undefined) { const changed = [...frame]; changed[4] = invalidReply; bytes = encodeCanonicalCbor(changed) }
      }
      await outgoing.send(bytes)
    } }, local: { ...server.transport.asLink(), ...(kind === 'records' ? { head: read } : { evidenceHead: read }) },
    groupId, grantId, identity: server.identity, authorizePeer: () => active }),
    openAuthenticatedPeerLink({ connection: incoming, local: client.transport.asLink(), groupId, grantId,
      identity: client.identity, authorizePeer: () => true }),
  ])
  cleanup.push(async () => { await Promise.all([serverLink.close(), clientLink.close()]) })
  return { released, revoke: () => { active = false }, close: () => clientLink.close(),
    read: () => kind === 'records' ? clientLink.link.head(server.transport.identity) : clientLink.link.evidenceHead() }
}

describe('authenticated framed range synchronization', () => {
  it('cancels asynchronous live authorization promptly without later leaking the frame or closing the route', async () => {
    const session = await signalSession(), gate = session.block(), controller = new AbortController()
    const frame = utf8('signal/1\n["expired preview"]')
    const sending = session.sender.sendSignal(frame, { signal: controller.signal })
    const rejected = expect(sending).rejects.toThrow('preview expired')
    await gate.blocked; controller.abort(new Error('preview expired'))
    await rejected
    expect(session.sent).toEqual([])
    gate.release()
    await session.sender.sendSignal(frame)
    expect(session.sent).toEqual([frame])
  })

  it('drops excess live frames before admission without disrupting history or later admitted frames', async () => {
    let entered!: () => void, release!: () => void, admitted = 0
    const full = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    const session = await signalSession(async () => { if (++admitted === 8) entered(); await gate })
    const frame = (value: number) => utf8(`signal/1\n[${value}]`)
    try {
      for (let index = 0; index < 8; index++) await session.sender.sendSignal(frame(index))
      await full
      await session.sender.sendSignal(frame(8))
      expect(await session.receiver.link.read(session.receiver.peer.feedId, 0n, 1)).toEqual([])
      expect(admitted).toBe(8)
      release()
      await new Promise<void>(resolve => { setTimeout(resolve, 0) })
      await session.sender.sendSignal(frame(9))
      await expect.poll(() => admitted).toBe(9)
      expect(session.received).toEqual([...Array.from({ length: 8 }, (_, index) => frame(index)), frame(9)])
      expect(await session.receiver.link.evidenceHead()).toBe(0n)
    } finally { release() }
  })

  it.each(['records', 'evidence'] as const)('returns a bounded %s availability head and requires active reader access', async kind => {
    const read = vi.fn(async () => 73n), session = await headSession(kind, read)
    expect(await session.read()).toBe(73n)
    expect(session.released).toEqual([73n])
    session.revoke()
    await expect(session.read()).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    expect(read).toHaveBeenCalledTimes(1)
  })

  it.each(['records', 'evidence'] as const)('rechecks %s head authorization after the storage lookup', async kind => {
    let entered!: () => void, release!: (head: bigint) => void
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<bigint>(resolve => { release = resolve })
    const session = await headSession(kind, async () => { entered(); return gate })
    const reading = session.read()
    await started; session.revoke(); release(73n)
    await expect(reading).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    expect(session.released).toEqual([])
  })

  it.each([-1n, BigInt(Number.MAX_SAFE_INTEGER) + 1n, '73', null])('rejects malformed head response %s', async value => {
    const session = await headSession('evidence', async () => 0n, value)
    await expect(session.read()).rejects.toThrow('FEED_POSITION_INVALID')
  })

  it('applies the existing request bounds and close cancellation to availability heads', async () => {
    const session = await headSession('evidence', () => new Promise<bigint>(() => {}))
    const pending = Array.from({ length: 4 }, () => session.read().catch((error: unknown) => error))
    await expect(session.read()).rejects.toThrow('PEER_REQUEST_LIMIT_EXCEEDED')
    await session.close()
    expect(await Promise.all(pending)).toEqual(Array.from({ length: 4 }, () => new Error('PEER_CONNECTION_CLOSED')))
  })

  it('uses the existing response-idle deadline for an unavailable advertised head', async () => {
    const session = await headSession('evidence', () => new Promise<bigint>(() => {}))
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const reading = session.read().catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(30_000)
    expect(await reading).toEqual(new Error('PEER_RESPONSE_IDLE_TIMEOUT'))
    expect(vi.getTimerCount()).toBe(0)
  })

  it('rechecks reader access before releasing ephemeral messages after authentication', async () => {
    const session = await payloadSession(async () => null)
    const identity = await generateEd25519KeyPair(), frames: Uint8Array[] = []
    const signals = new SignalChannel({ scope: 'room', identity, authorize: () => true })
    signals.attachRoute({ async send(frame) { frames.push(frame) } })
    try {
      await signals.send('progress', 1)
      await session.server.sendSignal(frames[0]!)
      session.revoke()
      await expect(session.server.sendSignal(frames[0]!)).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    } finally { signals.close() }
  })

  it('drops an expired original signal without interrupting durable range synchronization', async () => {
    const frames: Uint8Array[] = [], identity = await generateSignalIdentity()
    const sender = new SignalChannel({ scope: 'room', identity, authorize: () => true, now: () => 100 })
    const receiver = new SignalChannel({ scope: 'room', identity, authorize: () => true, now: () => 200 })
    sender.attachRoute({ async send(frame) { frames.push(frame) } })
    let received!: (value: Awaited<ReturnType<SignalRoute['receive']>>) => void
    const processed = new Promise<Awaited<ReturnType<SignalRoute['receive']>>>(resolve => { received = resolve })
    const receiveRoute = receiver.attachRoute({ async send() {} })
    const session = await signalSession(async frame => { received(await receiveRoute.receive(frame)) })
    try {
      await sender.send('typing', true, { ttlMs: 50 })
      await session.sender.sendSignal(frames[0]!)
      expect(await processed).toBeNull()
      expect(await session.receiver.link.read(session.receiver.peer.feedId, 0n, 1)).toEqual([])
    } finally { sender.close(); receiver.close() }
  })

  it('reports invalid live traffic without granting it durable-connection lifetime authority', async () => {
    const receiver = new SignalChannel({ scope: 'room', identity: await generateSignalIdentity(), authorize: () => true })
    let rejected!: (error: unknown) => void
    const reported = new Promise<unknown>(resolve => { rejected = resolve })
    const receiveRoute = receiver.attachRoute({ async send() {} })
    const session = await signalSession(async frame => { await receiveRoute.receive(frame) }, { onError: rejected })
    try {
      await session.sender.sendSignal(utf8('signal/1\n["malformed application message"]'))
      expect(await reported).toMatchObject({ code: 'signal_frame_invalid' })
      expect(await session.receiver.link.read(session.receiver.peer.feedId, 0n, 1)).toEqual([])
    } finally { receiver.close() }
  })

  it('retires a raw signal transport write that never completes after handoff', async () => {
    const session = await signalSession(undefined, { dispatch: async () => new Promise<void>(() => undefined), sendTimeoutMs: 25 })
    vi.useFakeTimers()
    const sending = session.sender.sendSignal(utf8('signal/1\n["blocked transport"]'))
    const failed = expect(sending).rejects.toThrow('PEER_SIGNAL_SEND_TIMEOUT')
    const closed = expect(session.sender.completion).rejects.toThrow('PEER_SIGNAL_SEND_TIMEOUT')
    await vi.advanceTimersByTimeAsync(26)
    await failed; await closed
  })

  it('exchanges exact native/browser records and evidence bidirectionally over the same framed link', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-framed-native-'))
    cleanup.push(() => rm(directory, { recursive: true, force: true }))
    // This test exercises native storage and framed ranges, with no SSB listener
    // or NAT discovery. Keep optional interface discovery independent of the
    // host sandbox's permission to enumerate network interfaces.
    const interfaces = vi.spyOn(os, 'networkInterfaces').mockReturnValue({})
    let native: FeedTransport
    try { native = await FeedTransport.open({ path: join(directory, 'ssb'), network: { peers: [], reconnect: false } }) }
    finally { interfaces.mockRestore() }
    cleanup.push(() => native.close())
    // Application author identity deliberately differs from the native endpoint feed.
    const nativeIdentity = await generateEd25519KeyPair(), browser = await portable()
    const groupId = new Uint8Array(32).fill(1), grantId = new Uint8Array(32).fill(2)
    const [nativeConnection, browserConnection] = connections()
    let active = true
    const [nativeSession, browserSession] = await Promise.all([
      openAuthenticatedPeerLink({ connection: nativeConnection, local: native.asLink(), groupId, grantId, identity: nativeIdentity,
        authorizePeer: ({ authorId }) => active && equalBytes(authorId, browser.identity.publicKeyBytes) }),
      openAuthenticatedPeerLink({ connection: browserConnection, local: browser.transport.asLink(), groupId, grantId, identity: browser.identity,
        authorizePeer: ({ authorId }) => equalBytes(authorId, nativeIdentity.publicKeyBytes) }),
    ])
    const nativeRecord = await native.publish(utf8('native record'))
    const browserRecord = await browser.transport.publish(utf8('browser record'))
    await native.putEvidence(utf8('portable certificate bytes'))
    expect(await browserSession.link.head(native.identity)).toBe(1n)
    expect(await browserSession.link.evidenceHead()).toBe(1n)
    expect(await nativeSession.link.head(browser.transport.identity)).toBe(1n)
    const detachNative = native.connectLink(nativeSession.link), detachBrowser = browser.transport.connect(browserSession.link)
    cleanup.push(async () => { detachNative(); detachBrowser()
      await Promise.all([nativeSession.close(), browserSession.close()]) })
    await Promise.all([native.catchUpLinks(), browser.transport.catchUp()])
    expect((await native.get(browserRecord.id))?.payload).toEqual(browserRecord.payload)
    expect((await browser.transport.get(nativeRecord.id))?.payload).toEqual(nativeRecord.payload)
    const retainedProofs: Uint8Array[] = []
    for await (const batch of browser.transport.evidenceHistory()) retainedProofs.push(...batch.map(evidence => evidence.bytes))
    expect(retainedProofs).toContainEqual(utf8('portable certificate bytes'))
    expect((await native.status()).peers).toContain(browser.transport.identity)
    let entered!: () => void, release!: (through: bigint) => void
    const waiting = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<bigint>(resolve => { release = resolve })
    const detachWaiting = native.connectLink({ ...nativeSession.link, evidenceHead: async () => { entered(); return gate } })
    await waiting
    const canceled = expect(native.catchUpLinks()).rejects.toMatchObject({ name: 'AbortError' })
    const detachReplacement = native.connectLink(nativeSession.link)
    await canceled
    release(0n); detachWaiting(); detachNative()
    const afterReplacement = await browser.transport.publish(utf8('after native route replacement'))
    await native.catchUpLinks()
    expect((await native.get(afterReplacement.id))?.payload).toEqual(afterReplacement.payload)
    expect((await native.status()).peers).toContain(browser.transport.identity)
    detachReplacement()
    // Membership is rechecked for range requests after the handshake.
    active = false
    await expect(browserSession.link.read(native.identity, 0n, 1)).rejects.toThrow('PEER_READ_UNAUTHORIZED')
  })

  it('refuses an authenticated key without a group read grant before returning history', async () => {
    const left = await portable(), right = await portable(), [leftConnection, rightConnection] = connections()
    const groupId = new Uint8Array(32).fill(3), grantId = new Uint8Array(32).fill(4)
    const results = await Promise.allSettled([
      openAuthenticatedPeerLink({ connection: leftConnection, local: left.transport.asLink(), groupId, grantId,
        identity: left.identity, authorizePeer: () => false }),
      openAuthenticatedPeerLink({ connection: rightConnection, local: right.transport.asLink(), groupId, grantId,
        identity: right.identity, authorizePeer: () => false }),
    ])
    expect(results.every((result) => result.status === 'rejected')).toBe(true)
    expect((await left.transport.history()).length).toBe(0)
    await Promise.all([leftConnection.close(), rightConnection.close()])
  })

  it('fetches a detached payload only on demand and rechecks reader rights', async () => {
    const body = new Uint8Array(256 * 1024 + 17).fill(53), hash = bytesToHex(await sha256(body))
    const provider = vi.fn(async (requested: string) => requested === hash ? body : null)
    const session = await payloadSession(provider)
    await session.client.link.readEvidence(0n, 2)
    expect(provider).not.toHaveBeenCalled()
    expect(equalBytes((await session.client.link.readPayload(hash))!, body)).toBe(true)
    expect(provider).toHaveBeenCalledExactlyOnceWith(hash)
    expect(await session.client.link.readPayload('00'.repeat(32))).toBeNull()
    await expect(session.client.link.readPayload('../not-a-content-address')).rejects.toThrow('PEER_PAYLOAD_REQUEST_INVALID')
    session.revoke()
    await expect(session.client.link.readPayload(hash)).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    expect(provider).toHaveBeenCalledTimes(2)
  })

  it('does not release a body when a grant is revoked during its provider lookup', async () => {
    const body = utf8('retained ciphertext'), hash = bytesToHex(await sha256(body))
    let started!: () => void, release!: (value: Uint8Array) => void
    const lookedUp = new Promise<void>(resolve => { started = resolve })
    const available = new Promise<Uint8Array>(resolve => { release = resolve })
    const session = await payloadSession(async () => { started(); return available })
    const result = session.client.link.readPayload(hash)
    await lookedUp
    session.revoke(); release(body)
    await expect(result).rejects.toThrow('PEER_READ_UNAUTHORIZED')
  })

  it('stops sending application signals to an established peer after reader revocation', async () => {
    const session = await signalSession(), signal = new TextEncoder().encode('signal/1\n["private presence"]')
    await session.sender.sendSignal(signal)
    expect(session.sent).toEqual([signal])
    session.revoke()
    await expect(session.sender.sendSignal(signal)).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    expect(session.sent).toEqual([signal])
  })

  it.each(['revocation', 'close'] as const)('does not release a signal after %s during asynchronous reader authorization', async ending => {
    const session = await signalSession(), gate = session.block()
    const sending = session.sender.sendSignal(new TextEncoder().encode('signal/1\n["private presence"]'))
    const rejected = expect(sending).rejects.toThrow(ending === 'revocation' ? 'PEER_READ_UNAUTHORIZED' : 'PEER_CONNECTION_CLOSED')
    await gate.blocked
    if (ending === 'revocation') session.revoke()
    else await session.sender.close()
    gate.release(); await rejected
    expect(session.sent).toEqual([])
  })

  it('closes an incoming signal lifetime after the remote reader grant is revoked', async () => {
    const session = await signalSession()
    session.revokeIncoming()
    const failed = expect(session.receiver.completion).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    // Local dispatch can race the peer's immediate rejection and physical close.
    const [sending] = await Promise.allSettled([session.sender.sendSignal(utf8('signal/1\n["not admitted"]'))])
    await failed
    if (sending.status === 'rejected') expect(sending.reason).toMatchObject({ message: 'PEER_CONNECTION_CLOSED' })
    expect(session.received).toEqual([])
  })

  it('reports bounded signal ingress overload while durable ranges remain available', async () => {
    let release!: () => void, report!: (error: unknown) => void
    const blocked = new Promise<void>(resolve => { release = resolve })
    const reported = new Promise<unknown>(resolve => { report = resolve })
    const session = await signalSession(async () => blocked, { onError: report })
    try {
      for (let index = 0; index < 9; index++) await session.sender.sendSignal(utf8(`signal/1\n[${index}]`))
      expect(await reported).toMatchObject({ code: 'signal_backpressure' })
      expect(session.received).toHaveLength(8)
      expect(await session.receiver.link.read(session.receiver.peer.feedId, 0n, 1)).toEqual([])
    } finally { release() }
  })

  it.each(['records', 'evidence'] as const)('does not release %s when a grant is revoked during the storage read', async range => {
    let started!: () => void, release!: (records: readonly Uint8Array[]) => void
    const reading = new Promise<void>(resolve => { started = resolve })
    const available = new Promise<readonly Uint8Array[]>(resolve => { release = resolve })
    const session = await rangeSession(range, async () => { started(); return available })
    const result = session.read()
    await reading
    session.revoke(); release([utf8('private descriptor or control evidence')])
    await expect(result).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    expect(session.sent).toEqual([])
  })

  it.each(['records', 'evidence'] as const)('rechecks %s access after a previous frame waits for the reader', async range => {
    const records = [utf8('authorized first frame'), utf8('must remain private after revocation')]
    let blocked!: () => void, release!: () => void
    const sending = new Promise<void>(resolve => { blocked = resolve })
    const delivered = new Promise<void>(resolve => { release = resolve })
    const session = await rangeSession(range, async () => records, async () => { blocked(); await delivered })
    const result = session.read()
    await sending
    session.revoke(); release()
    await expect(result).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    expect(session.sent).toEqual([records[0]])
  })

  it.each(['records', 'evidence'] as const)('accepts a bounded %s range that keeps progressing beyond ten seconds', async range => {
    const records = Array.from({ length: 64 }, (_, index) => utf8(`retained record ${index}`))
    const session = await rangeSession(range, async () => records,
      () => new Promise(resolve => { setTimeout(resolve, 250) }))
    // Complete the real signature handshake before controlling time. Every
    // validated response arrives within 250 ms, but the full legal range takes
    // 16 seconds. An absolute ten-second range timer rejects healthy progress.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const result = session.read(64).then(value => ({ value }), error => ({ error }))
    await vi.advanceTimersByTimeAsync(16_000)
    expect(await result).toEqual({ value: records })
  })

  it('does not spend the response deadline waiting for local framed-send admission', async () => {
    const records = [utf8('response after the request reaches its peer')]
    const session = await rangeSession('records', async () => records, undefined,
      { beforeRequest: () => new Promise(resolve => { setTimeout(resolve, 20_000) }) })
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const result = session.read().then(value => ({ value }), error => ({ error }))
    await vi.advanceTimersByTimeAsync(20_000)
    expect(await result).toEqual({ value: records })
  })

  it('keeps the identity-proof deadline separate from request deadlines', async () => {
    const client = await portable(), [clientConnection, unused] = connections()
    cleanup.push(async () => { await Promise.all([clientConnection.close(), unused.close()]) })
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const result = openAuthenticatedPeerLink({ connection: clientConnection, local: client.transport.asLink(),
      groupId: new Uint8Array(32).fill(15), grantId: new Uint8Array(32).fill(16), identity: client.identity,
      authorizePeer: () => true }).catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(await result).toEqual(new Error('PEER_HANDSHAKE_TIMEOUT'))
    expect(vi.getTimerCount()).toBe(0)
  })

  it('rejects opening when proof succeeds but local HELLO dispatch misses its deadline', async () => {
    const client = await portable(), server = await portable(), [clientConnection, serverConnection] = connections()
    let release!: () => void, verified!: () => void, outcome = 'pending'
    const heldSend = new Promise<void>(resolve => { release = resolve })
    const proofVerified = new Promise<void>(resolve => { verified = resolve })
    cleanup.push(async () => { release(); await Promise.all([clientConnection.close(), serverConnection.close()]) })
    const delayed = { ...clientConnection, async send(bytes: Uint8Array) {
      await clientConnection.send(bytes)
      const frame = assertCanonicalCbor(bytes)
      if (Array.isArray(frame) && frame[2] === 'hello') await heldSend
    } }
    const groupId = new Uint8Array(32).fill(17), grantId = new Uint8Array(32).fill(18)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const opening = openAuthenticatedPeerLink({ connection: delayed, local: client.transport.asLink(),
      groupId, grantId, identity: client.identity, authorizePeer: () => { verified(); return true } })
      .then(session => { outcome = 'opened'; return session }, (error: unknown) => { outcome = 'failed'; return error })
    const remote = await openAuthenticatedPeerLink({ connection: serverConnection, local: server.transport.asLink(),
      groupId, grantId, identity: server.identity, authorizePeer: () => true })
    cleanup.push(() => remote.close())
    await proofVerified
    await vi.advanceTimersByTimeAsync(10_000)
    expect(outcome).toBe('failed')
    expect(await opening).toEqual(new Error('PEER_HANDSHAKE_TIMEOUT'))
    release()
    await vi.advanceTimersByTimeAsync(0)
    expect(outcome).toBe('failed')
    expect(vi.getTimerCount()).toBe(0)
  })

  it('expires a dispatched request after response silence', async () => {
    const session = await rangeSession('records', () => new Promise(() => undefined))
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    let settled = false
    const result = session.read().catch((error: unknown) => { settled = true; return error })
    await vi.advanceTimersByTimeAsync(29_999)
    expect(settled).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    expect(await result).toEqual(new Error('PEER_RESPONSE_IDLE_TIMEOUT'))
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not let hints or another request refresh a silent request', async () => {
    let reads = 0
    const session = await rangeSession('records', () => ++reads === 1 ? new Promise(() => undefined)
      : Promise.resolve(Array.from({ length: 64 }, () => utf8('unrelated response'))),
    () => new Promise(resolve => { setTimeout(resolve, 250) }), { timeouts: { responseIdleTimeoutMs: 1_000 } })
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const silent = session.read().catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(0)
    const progressing = session.read(64).catch((error: unknown) => error)
    for (let index = 0; index < 3; index += 1) { await vi.advanceTimersByTimeAsync(300); await session.hint() }
    await vi.advanceTimersByTimeAsync(100)
    expect(await silent).toEqual(new Error('PEER_RESPONSE_IDLE_TIMEOUT'))
    expect(await progressing).toEqual(new Error('PEER_RESPONSE_IDLE_TIMEOUT'))
  })

  it('keeps the hard request lifetime fixed despite valid progress', async () => {
    const records = Array.from({ length: 64 }, (_, index) => utf8(`slow record ${index}`))
    const session = await rangeSession('records', async () => records,
      () => new Promise(resolve => { setTimeout(resolve, 2_500) }))
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const result = session.read(64).catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(120_000)
    expect(await result).toEqual(new Error('PEER_REQUEST_LIFETIME_TIMEOUT'))
    expect(session.sent.length).toBeGreaterThan(40)
    expect(session.sent.length).toBeLessThan(64)
  })

  it('bounds a blocked local dispatch and clears its request timers', async () => {
    const session = await rangeSession('records', async () => [], undefined,
      { beforeRequest: () => new Promise(() => undefined) })
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const result = session.read().catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(30_000)
    expect(await result).toEqual(new Error('PEER_REQUEST_SEND_TIMEOUT'))
    expect(vi.getTimerCount()).toBe(0)
  })

  it('clears every deadline on close while a request is still queued', async () => {
    let release!: () => void
    const queued = new Promise<void>(resolve => { release = resolve })
    const session = await rangeSession('records', async () => [], undefined, { beforeRequest: () => queued })
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const result = session.read().catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(0)
    expect(vi.getTimerCount()).toBe(2)
    await session.client.close()
    expect(await result).toEqual(new Error('PEER_CONNECTION_CLOSED'))
    expect(vi.getTimerCount()).toBe(0)
    release()
    await vi.advanceTimersByTimeAsync(120_000)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not revive deadlines when a completed response precedes send resolution', async () => {
    let release!: () => void, sends = 0
    const queued = new Promise<void>(resolve => { release = resolve })
    const records = [utf8('response completed before local send resolved')]
    const session = await rangeSession('records', async () => records, undefined,
      { afterRequest: async () => { if (++sends === 1) await queued } })
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const result = session.read()
    await vi.advanceTimersByTimeAsync(0)
    expect(await result).toEqual(records)
    expect(vi.getTimerCount()).toBe(0)
    release()
    await vi.advanceTimersByTimeAsync(120_000)
    expect(vi.getTimerCount()).toBe(0)
    expect(await session.read()).toEqual(records)
  })

  it('does not extend response silence when local send resolves after the first record', async () => {
    let release!: () => void
    const queued = new Promise<void>(resolve => { release = resolve })
    const session = await rangeSession('records', async () => [utf8('first record; completion stalls')],
      () => new Promise(() => undefined), { afterRequest: () => queued, timeouts: { responseIdleTimeoutMs: 1_000 } })
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const result = session.read().catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(900)
    expect(session.sent).toHaveLength(1)
    release()
    await vi.advanceTimersByTimeAsync(100)
    expect(await result).toEqual(new Error('PEER_RESPONSE_IDLE_TIMEOUT'))
    expect(vi.getTimerCount()).toBe(0)
  })

  it('verifies a received body independently of the authenticated sender', async () => {
    const body = utf8('unchanged in provider'), hash = bytesToHex(await sha256(body))
    const session = await payloadSession(async () => body, true)
    await expect(session.client.link.readPayload(hash)).rejects.toThrow('PEER_PAYLOAD_HASH_MISMATCH')
    await expect(session.client.completion).rejects.toThrow('PEER_PAYLOAD_HASH_MISMATCH')
  })

  it.each(['oversized', 'wrong-hash'] as const)('rejects %s provider data before sending it', async (mode) => {
    const intended = utf8('intended'), hash = bytesToHex(await sha256(intended))
    const body = mode === 'oversized' ? new Uint8Array(MAX_LEDGER_PAYLOAD_BYTES + 1) : utf8('different')
    const session = await payloadSession(async () => body)
    await expect(session.client.link.readPayload(hash)).rejects.toThrow('PEER_PAYLOAD_INVALID')
  })

  it('bounds concurrent payload requests and cancels outstanding reads on close', async () => {
    const body = utf8('later'), hash = bytesToHex(await sha256(body))
    let release!: (value: Uint8Array) => void
    const available = new Promise<Uint8Array>(resolve => { release = resolve })
    const session = await payloadSession(async () => available)
    const pending = Array.from({ length: 4 }, () => session.client.link.readPayload(hash))
    const outcomes = Promise.allSettled(pending)
    await expect(session.client.link.readPayload(hash)).rejects.toThrow('PEER_REQUEST_LIMIT_EXCEEDED')
    await session.client.close()
    expect((await outcomes).every(outcome => outcome.status === 'rejected')).toBe(true)
    release(body)
  })
})

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
  const leftToRight = new TransformStream<Uint8Array, Uint8Array>(), rightToLeft = new TransformStream<Uint8Array, Uint8Array>()
  return [framePeerStream({ readable: rightToLeft.readable, writable: leftToRight.writable }),
    framePeerStream({ readable: leftToRight.readable, writable: rightToLeft.writable })] as const
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

describe('authenticated framed range synchronization', () => {
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
    const detachNative = native.connectLink(nativeSession.link), detachBrowser = browser.transport.connect(browserSession.link)
    cleanup.push(async () => { detachNative(); detachBrowser()
      await Promise.all([nativeSession.close(), browserSession.close()]) })
    await Promise.all([native.catchUpLinks(), browser.transport.catchUp()])
    expect((await native.get(browserRecord.id))?.payload).toEqual(browserRecord.payload)
    expect((await browser.transport.get(nativeRecord.id))?.payload).toEqual(nativeRecord.payload)
    expect((await browser.transport.evidenceHistory()).map((evidence) => evidence.bytes)).toContainEqual(utf8('portable certificate bytes'))
    expect((await native.status()).peers).toContain(browser.transport.identity)
    const detachReplacement = native.connectLink(nativeSession.link)
    detachNative()
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

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import os from 'node:os'
import { join } from 'node:path'

import { bytesToHex, sha256 } from '@chronolog/canonical'
import { MemoryOperationStore } from '@chronolog/node-core'
import { MAX_LEDGER_PAYLOAD_BYTES } from '@chronolog/node-core/ledger'
import { assertCanonicalCbor, encodeCanonicalCbor, equalBytes, generateEd25519KeyPair, utf8, type CborValue } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { FeedTransport } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { framePeerStream } from './framing.js'
import { openAuthenticatedPeerLink } from './peer-link.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

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

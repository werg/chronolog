import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import os from 'node:os'
import { join } from 'node:path'

import { MemoryOperationStore } from '@chronolog/node-core'
import { equalBytes, generateEd25519KeyPair, utf8 } from '@chronolog/protocol'
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
    cleanup.push(async () => { native.disconnectLink(nativeSession.link.identity); browser.transport.disconnect(browserSession.link.identity)
      await Promise.all([nativeSession.close(), browserSession.close()]) })
    const nativeRecord = await native.publish(utf8('native record'))
    const browserRecord = await browser.transport.publish(utf8('browser record'))
    await native.putEvidence(utf8('portable certificate bytes'))
    native.connectLink(nativeSession.link)
    browser.transport.connect(browserSession.link)
    await Promise.all([native.catchUpLinks(), browser.transport.catchUp()])
    expect((await native.get(browserRecord.id))?.payload).toEqual(browserRecord.payload)
    expect((await browser.transport.get(nativeRecord.id))?.payload).toEqual(nativeRecord.payload)
    expect((await browser.transport.evidenceHistory()).map((evidence) => evidence.bytes)).toContainEqual(utf8('portable certificate bytes'))
    expect((await native.status()).peers).toContain(browser.transport.identity)
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
})

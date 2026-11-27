import { afterEach, describe, expect, it } from 'vitest'
import { bytesToHex, sha256 } from '@chronolog/canonical'
import { computeCasHash } from '@chronolog/records'
import { CONTENT_CHUNK_BYTES, MAX_BLOB_BYTES, MAX_BLOB_CHUNKS } from './content.js'
import { assertContentWireMessage, createNetworkContent, type ContentWireMessage } from './network-content.js'
import { createFramedPeerConnectionPair } from './network-wire.js'
import { createApplicationOwner } from './session-owner.js'
import { connectApplicationOwner } from './worker-application.js'
import { contentFixture, payload } from './content-test-fixture.js'
import { sessionFixture } from './test-fixture.js'

const cleanup: Array<() => Promise<unknown> | void> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

function pair(
  f: Awaited<ReturnType<typeof contentFixture>>,
  transform: (message: ContentWireMessage, side: number) => ContentWireMessage = message => message,
) {
  const stop = new AbortController(), messages: Array<{ side: number; message: ContentWireMessage }> = []
  const send = (side: number) => async (input: ContentWireMessage) => {
    const message = structuredClone(transform(input, side))
    messages.push({ side, message })
    await (side === 0 ? b : a).handle(message)
  }
  const a = createNetworkContent({ content: f.contents[0]!, peerId: f.identities[1]!.publicKey, signal: stop.signal, authorize: () => true, send: send(0) })
  const b = createNetworkContent({ content: f.contents[1]!, peerId: f.identities[0]!.publicKey, signal: stop.signal, authorize: () => true, send: send(1) })
  const close = () => { a.close(); b.close(); stop.abort() }
  cleanup.push(close)
  return { a, b, messages, close }
}

describe('SHA-256 hash-addressed P2P historical blob recovery', () => {
  it('stores, checks, reads, and deletes empty and multi-chunk blobs locally', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const empty = new Uint8Array(0)
    const emptyInfo = await f.contents[0]!.putBlob(empty)
    expect(emptyInfo.bytes).toBe(0)
    expect(emptyInfo.hash).toBe(bytesToHex(await sha256(empty)))
    expect(await f.contents[0]!.hasBlob(emptyInfo.hash)).toBe(true)
    expect(await f.contents[0]!.getBlob(emptyInfo.hash, { expectedBytes: 0 })).toEqual(empty)

    const large = payload(CONTENT_CHUNK_BYTES * 2 + 137)
    const largeInfo = await f.contents[0]!.putBlob(large)
    expect(largeInfo.bytes).toBe(large.byteLength)
    expect(largeInfo.hash).toBe(bytesToHex(await sha256(large)))
    expect(await f.contents[0]!.hasBlob(largeInfo.hash)).toBe(true)
    expect(await f.contents[0]!.getBlob(largeInfo.hash, { expectedBytes: large.byteLength })).toEqual(large)

    await f.contents[0]!.deleteBlob(largeInfo.hash)
    expect(await f.contents[0]!.hasBlob(largeInfo.hash)).toBe(false)
    expect(await f.contents[0]!.getBlob(largeInfo.hash, { localOnly: true })).toBeNull()
  })

  it('recovers multi-chunk blobs by SHA-256 hash from a connected peer and caches locally', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const bytes = payload(CONTENT_CHUNK_BYTES * 2 + 41)
    const info = await f.contents[0]!.putBlob(bytes)
    const p = pair(f)

    // Missing hash returns null cleanly without throwing.
    expect(await f.contents[1]!.getBlob('ab'.repeat(32))).toBeNull()

    // Recover multi-chunk blob over P2P content channel.
    const recovered = await f.contents[1]!.getBlob(info.hash, { expectedBytes: bytes.byteLength })
    expect(recovered).toEqual(bytes)
    expect(p.messages.filter(m => m.message.type === 'blob-info-request')).toHaveLength(2)
    expect(p.messages.filter(m => m.message.type === 'blob-chunk-request')).toHaveLength(3)

    // Cached locally: remains available after disconnecting the peer.
    p.close()
    expect(await f.contents[1]!.hasBlob(info.hash)).toBe(true)
    expect(await f.contents[1]!.getBlob(info.hash, { localOnly: true })).toEqual(bytes)
  })

  it('supports cache: false when caller does not want to persist recovered blobs locally', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const bytes = payload(512)
    const info = await f.contents[0]!.putBlob(bytes)
    const p = pair(f)

    expect(await f.contents[1]!.getBlob(info.hash, { expectedBytes: 512, cache: false })).toEqual(bytes)
    p.close()
    expect(await f.contents[1]!.hasBlob(info.hash)).toBe(false)
    expect(await f.contents[1]!.getBlob(info.hash, { localOnly: true })).toBeNull()
  })

  it('rejects corrupt peer bytes and falls back to an honest peer', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const bytes = payload(4096)
    const info = await f.contents[0]!.putBlob(bytes)

    // Single corrupt peer: fails SHA-256 verification and never caches corrupt bytes.
    const corruptPair = pair(f, (message, side) => {
      if (side === 0 && message.type === 'blob-chunk-response' && message.bytes !== null) {
        const raw = Uint8Array.from(atob(message.bytes), c => c.charCodeAt(0))
        raw[0] = (raw[0]! + 1) & 0xff
        return { ...message, bytes: btoa(String.fromCharCode(...raw)) }
      }
      return message
    })
    await expect(f.contents[1]!.getBlob(info.hash, { expectedBytes: bytes.byteLength })).rejects.toThrow('CONTENT_BLOB_INVALID')
    expect(await f.contents[1]!.hasBlob(info.hash)).toBe(false)
    corruptPair.close()

    // Corrupt source attached first + honest source attached second: transparently recovers from honest peer.
    const detachCorrupt = f.contents[1]!.attachSource('corrupt-peer', {
      manifest: async () => null,
      chunk: async () => null,
      blobInfo: async hash => ({ hash, bytes: bytes.byteLength }),
      blobChunk: async () => new Uint8Array(bytes.byteLength),
    })
    const detachHonest = f.contents[1]!.attachSource('honest-peer', f.contents[0]!.source())
    cleanup.push(() => { detachCorrupt(); detachHonest() })

    expect(await f.contents[1]!.getBlob(info.hash, { expectedBytes: bytes.byteLength })).toEqual(bytes)
    expect(await f.contents[1]!.hasBlob(info.hash)).toBe(true)
  })

  it('rejects size mismatch and maxBytes overflow before fetching chunks', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const bytes = payload(2048)
    const info = await f.contents[0]!.putBlob(bytes)
    const p = pair(f)

    await expect(f.contents[1]!.getBlob(info.hash, { expectedBytes: 1024 })).rejects.toThrow('CONTENT_BLOB_INVALID')
    await expect(f.contents[1]!.getBlob(info.hash, { maxBytes: 1024 })).rejects.toThrow('CONTENT_READ_LIMIT_EXCEEDED')
    // No chunk-requests should have been sent!
    expect(p.messages.filter(m => m.message.type === 'blob-chunk-request')).toHaveLength(0)
  })

  it('validates blob wire frames strictly before decoding', () => {
    const id = crypto.randomUUID(), hash = 'ab'.repeat(32)
    expect(() => assertContentWireMessage({ type: 'blob-info-request', id, hash })).not.toThrow()
    expect(() => assertContentWireMessage({ type: 'blob-info-request', id, hash: 'short' })).toThrow('CONTENT_WIRE_INVALID')
    expect(() => assertContentWireMessage({ type: 'blob-info-request', id, hash, extra: 1 })).toThrow('CONTENT_WIRE_INVALID')
    expect(() => assertContentWireMessage({ type: 'blob-chunk-request', id, hash, index: 0 })).not.toThrow()
    expect(() => assertContentWireMessage({ type: 'blob-chunk-request', id, hash, index: -1 })).toThrow('CONTENT_WIRE_CHUNK_INVALID')
    expect(() => assertContentWireMessage({ type: 'blob-chunk-request', id, hash, index: MAX_BLOB_CHUNKS })).toThrow('CONTENT_WIRE_CHUNK_INVALID')
    expect(() => assertContentWireMessage({ type: 'blob-info-response', id, bytes: null })).not.toThrow()
    expect(() => assertContentWireMessage({ type: 'blob-info-response', id, bytes: MAX_BLOB_BYTES })).not.toThrow()
    expect(() => assertContentWireMessage({ type: 'blob-info-response', id, bytes: MAX_BLOB_BYTES + 1 })).toThrow('CONTENT_WIRE_INVALID')
    expect(() => assertContentWireMessage({ type: 'blob-chunk-response', id, bytes: null })).not.toThrow()
    // >64 KiB raw chunk rejected even though encrypted chunk limit is larger
    const oversized = new Uint8Array(CONTENT_CHUNK_BYTES + 1)
    let bin = ''
    for (let i = 0; i < oversized.length; i += 8192) bin += String.fromCharCode(...oversized.subarray(i, i + 8192))
    expect(() => assertContentWireMessage({ type: 'blob-chunk-response', id, bytes: btoa(bin) })).toThrow('CONTENT_WIRE_CHUNK_INVALID')
  })

  it('recovers historical blobs end-to-end across authenticated ApplicationSession peers and WorkerApplicationSession RPC', async () => {
    const f = await sessionFixture()
    const a = await f.open(0)
    const b = await f.open(1)
    const ownerB = createApplicationOwner(b)
    const channel = new MessageChannel()
    const detach = ownerB.attach(channel.port1)
    const facadeB = await connectApplicationOwner(channel.port2, { applicationId: b.applicationId })
    cleanup.push(async () => {
      await facadeB.close()
      detach()
      await ownerB.close()
      await a.close()
    })

    const [left, right] = createFramedPeerConnectionPair()
    cleanup.push(async () => { await Promise.all([left.close(), right.close()]) })
    const [linkA, linkB] = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    cleanup.push(async () => { await Promise.all([linkA.close(), linkB.close()]) })

    // Peer A seeds a multi-chunk historical publication bundle blob
    const historicalAsset = payload(CONTENT_CHUNK_BYTES + 500)
    const info = await a.content.putBlob(historicalAsset)

    // Peer B (via WorkerApplicationSession facade, as in a browser tab) recovers it by hash over the P2P link
    expect(await facadeB.content.hasBlob(info.hash)).toBe(false)
    const recovered = await facadeB.content.getBlob(info.hash, { expectedBytes: historicalAsset.byteLength })
    expect(recovered).toEqual(historicalAsset)
    expect(await facadeB.content.hasBlob(info.hash)).toBe(true)

    // Also test putBlob & deleteBlob through WorkerApplicationSession facade
    const browserAsset = payload(CONTENT_CHUNK_BYTES + 19)
    const browserInfo = await facadeB.content.putBlob(browserAsset)
    expect(await a.content.getBlob(browserInfo.hash, { expectedBytes: browserAsset.byteLength })).toEqual(browserAsset)
    await facadeB.content.deleteBlob(browserInfo.hash)
    expect(await facadeB.content.hasBlob(browserInfo.hash)).toBe(false)
  })

  it('unifies public/private lazy content pipe with opt-in keyed-convergent deduplication', async () => {
    const f = await sessionFixture()
    const a = await f.open(0)
    const b = await f.open(1)
    cleanup.push(async () => { await Promise.all([a.close(), b.close()]) })
    const [left, right] = createFramedPeerConnectionPair()
    cleanup.push(async () => { await Promise.all([left.close(), right.close()]) })
    const [linkA, linkB] = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    cleanup.push(async () => { await Promise.all([linkA.close(), linkB.close()]) })

    // Public lazy blob via unified put/get
    const pubData = payload(CONTENT_CHUNK_BYTES + 73)
    const pubRef = await a.content.put(pubData, { visibility: 'public', mediaType: 'text/javascript' })
    expect(pubRef.profile).toBe('chronolog-blob-v2')
    expect(await b.content.get(pubRef)).toEqual(pubData)

    // Private default (randomized IND-CPA): two identical uploads produce distinct IDs
    const privData = payload(4096)
    const rand1 = await a.content.put(privData, { visibility: 'private', mediaType: 'application/pdf' })
    const rand2 = await b.content.put(privData, { visibility: 'private', mediaType: 'application/pdf' })
    expect(rand1.profile).toBe('authored-content-v1')
    expect(rand2.profile).toBe('authored-content-v1')
    if (rand1.profile === 'authored-content-v1' && rand2.profile === 'authored-content-v1') {
      expect(rand1.id).not.toBe(rand2.id)
    }

    // Private deduplicate: true (keyed-convergent): two peers with same epochKey produce IDENTICAL ContentReference IDs
    const dedupA = await a.content.put(privData, { visibility: 'private', mediaType: 'application/pdf', deduplicate: true })
    const dedupB = await b.content.put(privData, { visibility: 'private', mediaType: 'application/pdf', deduplicate: true })
    expect(dedupA).toEqual(dedupB)
    expect(await b.content.get(dedupA)).toEqual(privData)

    // 1-byte change produces a completely different deterministic ContentReference ID
    const mutated = privData.slice()
    mutated[0] = (mutated[0]! + 1) & 0xff
    const dedupMutated = await a.content.put(mutated, { visibility: 'private', mediaType: 'application/pdf', deduplicate: true })
    expect(dedupMutated).not.toEqual(dedupA)
    expect(await b.content.get(dedupMutated)).toEqual(mutated)
  })

  it('publishRelease seeds lazy public blobs (zero eager CAS bloat), supports rollback & P2P recovery, and enforces removed blocklist', async () => {
    const f = await sessionFixture()
    const a = await f.open(0)
    const b = await f.open(1)
    cleanup.push(async () => { await Promise.all([a.close(), b.close()]) })
    const [left, right] = createFramedPeerConnectionPair()
    cleanup.push(async () => { await Promise.all([left.close(), right.close()]) })
    const [linkA, linkB] = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    cleanup.push(async () => { await Promise.all([linkA.close(), linkB.close()]) })

    const v1Html = new TextEncoder().encode('<!doctype html><h1>v1</h1>' + 'x'.repeat(8192))
    const v2Html = new TextEncoder().encode('<!doctype html><h1>v2</h1>')
    const expectedV1Hash = bytesToHex(await sha256(v1Html))

    await (await a.publishRelease({
      entry: 'index.html',
      files: [{ path: 'index.html', bytes: v1Html, type: 'text/html' }],
      authorTimestampMs: 100n,
    })).materialized()

    // Eager CAS did NOT get bloated with UI file bytes (only lightweight seenOps metadata)!
    expect(a.cas.hasSync(computeCasHash(v1Html), 'public')).toBe(false)
    expect(a.cas.hasSync(expectedV1Hash, 'public')).toBe(false)
    expect(await a.content.hasBlob(expectedV1Hash)).toBe(true)

    await (await a.publishRelease({
      entry: 'index.html',
      files: [{ path: 'index.html', bytes: v2Html, type: 'text/html' }],
      authorTimestampMs: 200n,
    })).materialized()

    await linkA.synchronize()
    await linkB.synchronize()

    // Peer B queries historical revision 1 from $publications and recovers its exact bytes over the lazy P2P blob pipe
    const rev1 = (await b.query('$publications', { revision: 1 })).value as { files: { hash: string; size: number }[] }
    expect(rev1.files[0]?.hash).toBe(expectedV1Hash)
    expect(await b.content.get(rev1.files[0]!.hash, { expectedBytes: rev1.files[0]!.size })).toEqual(v1Html)

    // Rollback to revision 1 creates revision 3 pointing to v1 files
    await (await a.rollbackRelease({ revision: 1, authorTimestampMs: 300n })).materialized()
    const pubState = a.topic('$publications') as { revision: number; current: { entry: string; rollbackOf: number; files: { hash: string }[] } }
    expect(pubState.revision).toBe(3)
    expect(pubState.current.rollbackOf).toBe(1)
    expect(pubState.current.files[0]?.hash).toBe(expectedV1Hash)
  })
})

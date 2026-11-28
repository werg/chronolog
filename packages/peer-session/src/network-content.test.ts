import { afterEach, describe, expect, it, vi } from 'vitest'
import { CONTENT_CHUNK_BYTES, MAX_CONTENT_ENCRYPTED_CHUNK_BYTES } from './content.js'
import { assertContentWireMessage, CONTENT_NETWORK_LIMITS, createNetworkContent, type ContentWireMessage } from './network-content.js'
import { contentFixture, deferred, payload } from './content-test-fixture.js'

const cleanup: Array<() => Promise<unknown> | void> = []
afterEach(async () => { vi.useRealTimers(); for (const close of cleanup.splice(0).reverse()) await close() })
function pair(f: Awaited<ReturnType<typeof contentFixture>>, transform: (message: ContentWireMessage, side: number) => ContentWireMessage = message => message) {
  const stop = new AbortController(), messages: Array<{ side: number; message: ContentWireMessage }> = []
  const send = (side: number) => async (input: ContentWireMessage) => {
    const message = structuredClone(transform(input, side)); messages.push({ side, message })
    await (side === 0 ? b : a).handle(message)
  }
  const a = createNetworkContent({ content: f.contents[0]!, peerId: f.identities[1]!.publicKey, signal: stop.signal, authorize: () => true, send: send(0) })
  const b = createNetworkContent({ content: f.contents[1]!, peerId: f.identities[0]!.publicKey, signal: stop.signal, authorize: () => true, send: send(1) })
  const close = () => { a.close(); b.close(); stop.abort() }
  cleanup.push(close)
  return { a, b, messages, close }
}

describe('bounded content protocol on an authenticated channel', () => {
  it('serves manifests and verified encrypted chunks and handles nested pull-to-retain without blocking the pump', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const bytes = payload(CONTENT_CHUNK_BYTES * 2 + 7), reference = await f.contents[0]!.putBytes(bytes), p = pair(f)
    const receipts = await f.contents[0]!.retention(reference)
    expect(receipts).toHaveLength(1)
    expect(receipts[0]?.signer).toBe(f.identities[1]!.publicKey)
    expect(await f.contents[0]!.retained(reference)).toEqual(receipts)
    expect(await f.contents[1]!.readBytes(reference, { maxBytes: bytes.length })).toEqual(bytes)
    // Retention on peer 1 pulled all three chunks in one streamed range request; peer 1's read was local.
    expect(p.messages.filter(item => item.message.type === 'chunks-request')).toHaveLength(1)
    const streamed = p.messages.filter(item => item.message.type === 'chunk-response')
    expect(streamed).toHaveLength(3)
    // Raw ciphertext on the wire: exactly header + plaintext + AES tag, no hex/base64 inflation.
    expect(streamed.every(item => item.message.type === 'chunk-response' && item.message.bytes instanceof Uint8Array && item.message.bytes.length <= MAX_CONTENT_ENCRYPTED_CHUNK_BYTES)).toBe(true)
    expect(MAX_CONTENT_ENCRYPTED_CHUNK_BYTES).toBe(CONTENT_CHUNK_BYTES + 37)
    p.close()
    expect(await f.contents[1]!.readBytes(reference, { maxBytes: bytes.length })).toEqual(bytes)
  })

  it('verifies content hashes and retention signer binding instead of trusting authenticated transport payloads', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const reference = await f.contents[0]!.putBytes(payload(5))
    let mode: 'chunk' | 'receipt' = 'chunk'
    const p = pair(f, (message, side) => {
      if (side === 0 && mode === 'chunk' && message.type === 'chunk-response' && message.bytes !== null) {
        return { ...message, bytes: new Uint8Array(message.bytes.length) }
      }
      if (side === 1 && mode === 'receipt' && message.type === 'retain-response') return { ...message, receipt: { ...message.receipt, signature: '00'.repeat(64) } }
      return message
    })
    await expect(f.contents[1]!.readBytes(reference, { maxBytes: 5 })).rejects.toThrow('CONTENT_CHUNK_INVALID')
    await expect(f.contents[1]!.source().retained!(reference)).rejects.toThrow('CONTENT_INCOMPLETE')
    mode = 'receipt'
    await expect(f.contents[0]!.retention(reference)).rejects.toThrow('AUTHORITY_SIGNATURE_INVALID')
    expect(await f.contents[0]!.retained(reference)).toEqual([])
    p.close()
  })

  it('bounds pending requests, detaches on close, and rejects all waiting callers promptly', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const reference = await f.contents[0]!.putBytes(payload(1)), messages: ContentWireMessage[] = [], stop = new AbortController()
    const link = createNetworkContent({ content: f.contents[1]!, peerId: f.identities[0]!.publicKey, signal: stop.signal, authorize: () => true, send: async message => { messages.push(message) } })
    cleanup.push(() => link.close())
    const limit = CONTENT_NETWORK_LIMITS.pending
    const reads = Array.from({ length: limit + 1 }, () => f.contents[1]!.readBytes(reference, { maxBytes: 1 }).then(() => 'unexpected', (error: Error) => error.message))
    await vi.waitFor(() => expect(messages.filter(message => message.type === 'manifest-request')).toHaveLength(limit))
    link.close()
    const results = await Promise.all(reads)
    expect(results.filter(result => result === 'CONTENT_REQUEST_LIMIT')).toHaveLength(1)
    expect(results.filter(result => result === 'CONTENT_NETWORK_CLOSED')).toHaveLength(limit)
    await expect(f.contents[1]!.readBytes(reference, { maxBytes: 1 })).rejects.toThrow('CONTENT_MANIFEST_MISSING')
  })

  it('limits active incoming tasks without a secondary queue, handles cancellation and frees their slots', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const reference = await f.contents[0]!.putBytes(payload(1)), messages: ContentWireMessage[] = [], gate = deferred<void>(), store = f.stores[0]!, get = store.get.bind(store)
    store.get = async key => { if (key.endsWith(`/manifest/${reference.id}`)) await gate.promise; return get(key) }
    const stop = new AbortController(), link = createNetworkContent({ content: f.contents[0]!, peerId: f.identities[1]!.publicKey, signal: stop.signal, authorize: () => true, send: async message => { messages.push(message) } }); cleanup.push(() => link.close())
    const limit = CONTENT_NETWORK_LIMITS.active, ids = Array.from({ length: limit + 1 }, () => crypto.randomUUID())
    for (const id of ids) await link.handle({ type: 'manifest-request', id, reference })
    expect(messages).toEqual([{ type: 'error', id: ids[limit], code: 'CONTENT_BUSY' }])
    for (const id of ids.slice(0, limit)) await link.handle({ type: 'cancel', id })
    gate.resolve(); await vi.waitFor(() => expect(messages).toHaveLength(1))
    await link.handle({ type: 'manifest-request', id: crypto.randomUUID(), reference })
    await vi.waitFor(() => expect(messages.filter(message => message.type === 'manifest-response')).toHaveLength(1))
  })

  it('times out and cancels outstanding requests; caller abort also cancels without discarding persisted prefixes', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const reference = await f.contents[0]!.putBytes(payload(1)), messages: ContentWireMessage[] = [], stop = new AbortController()
    const link = createNetworkContent({ content: f.contents[1]!, peerId: f.identities[0]!.publicKey, signal: stop.signal, authorize: () => true, send: async message => { messages.push(message) } }); cleanup.push(() => link.close())
    vi.useFakeTimers()
    const timed = expect(f.contents[1]!.readBytes(reference, { maxBytes: 1 })).rejects.toThrow('CONTENT_REQUEST_TIMEOUT')
    await vi.advanceTimersByTimeAsync(CONTENT_NETWORK_LIMITS.timeoutMs + 1); await timed
    expect(messages.filter(message => message.type === 'cancel')).toHaveLength(1)
    const controller = new AbortController(), aborted = expect(f.contents[1]!.readBytes(reference, { maxBytes: 1, signal: controller.signal })).rejects.toThrow('user-cancel')
    await vi.advanceTimersByTimeAsync(0)
    controller.abort(new Error('user-cancel')); await aborted
    await vi.advanceTimersByTimeAsync(0)
    expect(messages.filter(message => message.type === 'cancel')).toHaveLength(2)
  })

  it('checks current reader authorization and rejects oversized or malformed frames before decoding', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const reference = await f.contents[0]!.putBytes(payload(1)), messages: ContentWireMessage[] = [], stop = new AbortController()
    const link = createNetworkContent({ content: f.contents[1]!, peerId: f.identities[0]!.publicKey, signal: stop.signal, authorize: () => false, send: async message => { messages.push(message) } }); cleanup.push(() => link.close())
    await expect(f.contents[1]!.readBytes(reference, { maxBytes: 1 })).rejects.toThrow('CONTENT_FORBIDDEN')
    await expect(link.handle({ type: 'manifest-request', id: crypto.randomUUID(), reference })).rejects.toThrow('CONTENT_FORBIDDEN')
    expect(messages).toEqual([])
    for (const bytes of [new Uint8Array(CONTENT_NETWORK_LIMITS.chunkBytes + 1), 'AA', [1, 2]]) {
      expect(() => assertContentWireMessage({ type: 'chunk-response', id: crypto.randomUUID(), index: 0, bytes })).toThrow()
    }
    expect(() => assertContentWireMessage({ type: 'chunk-response', id: crypto.randomUUID(), index: -1, bytes: null })).toThrow('CONTENT_WIRE_CHUNK_INVALID')
    expect(() => assertContentWireMessage({ type: 'chunks-request', id: crypto.randomUUID(), reference, start: 0, count: 0 })).toThrow('CONTENT_WIRE_CHUNK_INVALID')
    expect(() => assertContentWireMessage({ type: 'chunks-request', id: crypto.randomUUID(), reference, start: 0, count: CONTENT_NETWORK_LIMITS.rangeChunks + 1 })).toThrow('CONTENT_WIRE_CHUNK_INVALID')
    expect(() => assertContentWireMessage({ type: 'manifest-request', id: crypto.randomUUID(), reference, extra: true })).toThrow('CONTENT_WIRE_INVALID')
    expect(() => assertContentWireMessage({ type: 'chunks-request', id: crypto.randomUUID(), reference, start: 1, count: 1 })).toThrow('CONTENT_WIRE_CHUNK_INVALID')
    expect(() => assertContentWireMessage({ type: 'manifest-response', id: crypto.randomUUID(), manifest: { stageId: crypto.randomUUID(), reference: {}, chunks: new Array(2049) } })).toThrow()
  })
})

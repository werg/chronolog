import { afterEach, describe, expect, it, vi } from 'vitest'
import { CONTENT_CHUNK_BYTES } from './content.js'
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
    expect(p.messages.filter(item => item.message.type === 'chunk-request')).toHaveLength(3)
    expect(p.messages.filter(item => item.message.type === 'chunk-response').every(item => item.message.type === 'chunk-response' && item.message.bytes!.length <= CONTENT_NETWORK_LIMITS.chunkBase64Characters)).toBe(true)
    p.close()
    expect(await f.contents[1]!.readBytes(reference, { maxBytes: bytes.length })).toEqual(bytes)
  })

  it('verifies content hashes and retention signer binding instead of trusting authenticated transport payloads', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const reference = await f.contents[0]!.putBytes(payload(5))
    let mode: 'chunk' | 'receipt' = 'chunk'
    const p = pair(f, (message, side) => {
      if (side === 0 && mode === 'chunk' && message.type === 'chunk-response' && message.bytes !== null) {
        return { ...message, bytes: btoa(String.fromCharCode(...new Uint8Array(atob(message.bytes).length))) }
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
    const reads = Array.from({ length: 5 }, () => f.contents[1]!.readBytes(reference, { maxBytes: 1 }).then(() => 'unexpected', (error: Error) => error.message))
    await vi.waitFor(() => expect(messages.filter(message => message.type === 'manifest-request')).toHaveLength(4))
    link.close()
    const results = await Promise.all(reads)
    expect(results.filter(result => result === 'CONTENT_REQUEST_LIMIT')).toHaveLength(1)
    expect(results.filter(result => result === 'CONTENT_NETWORK_CLOSED')).toHaveLength(4)
    await expect(f.contents[1]!.readBytes(reference, { maxBytes: 1 })).rejects.toThrow('CONTENT_MANIFEST_MISSING')
  })

  it('limits active incoming tasks without a secondary queue, handles cancellation and frees their slots', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const reference = await f.contents[0]!.putBytes(payload(1)), messages: ContentWireMessage[] = [], gate = deferred<void>(), store = f.stores[0]!, get = store.get.bind(store)
    store.get = async key => { if (key.endsWith(`/manifest/${reference.id}`)) await gate.promise; return get(key) }
    const stop = new AbortController(), link = createNetworkContent({ content: f.contents[0]!, peerId: f.identities[1]!.publicKey, signal: stop.signal, authorize: () => true, send: async message => { messages.push(message) } }); cleanup.push(() => link.close())
    const ids = Array.from({ length: 5 }, () => crypto.randomUUID())
    for (const id of ids) await link.handle({ type: 'manifest-request', id, reference })
    expect(messages).toEqual([{ type: 'error', id: ids[4], code: 'CONTENT_BUSY' }])
    for (const id of ids.slice(0, 4)) await link.handle({ type: 'cancel', id })
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
    for (const bytes of ['A'.repeat(CONTENT_NETWORK_LIMITS.chunkBase64Characters + 4), 'AA', 'AR==', '%===']) {
      expect(() => assertContentWireMessage({ type: 'chunk-response', id: crypto.randomUUID(), bytes })).toThrow()
    }
    expect(() => assertContentWireMessage({ type: 'manifest-request', id: crypto.randomUUID(), reference, extra: true })).toThrow('CONTENT_WIRE_INVALID')
    expect(() => assertContentWireMessage({ type: 'chunk-request', id: crypto.randomUUID(), reference, index: 1 })).toThrow('CONTENT_WIRE_CHUNK_INVALID')
    expect(() => assertContentWireMessage({ type: 'manifest-response', id: crypto.randomUUID(), manifest: { stageId: crypto.randomUUID(), reference: {}, chunks: new Array(2049) } })).toThrow()
  })
})

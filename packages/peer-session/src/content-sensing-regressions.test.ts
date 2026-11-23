import { describe, expect, it, vi } from 'vitest'
import { bytesDigest } from '@chronolog/peer-generation'
import { canonicalJson, type EventPayload } from '@chronolog/protocol'
import { CONTENT_CHUNK_BYTES, type ContentReference } from './content.js'
import { deferred, fixture } from './content-test-fixture.js'

describe('sensing review regressions', () => {
  it('frees orphan ciphertext if a staged descriptor write fails', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!
    const kept = await content.putBytes(Uint8Array.of(3))
    const before = (await store.entries()).map(entry => entry.key).sort()
    const put = store.put.bind(store)
    let fail = true
    const writing = vi.spyOn(store, 'put').mockImplementation(async (key, bytes) => {
      if (fail && /\/stage\/[0-9a-f]{32}\/0$/u.test(key)) { fail = false; throw new Error('TEST_DESCRIPTOR_FULL') }
      await put(key, bytes)
    })
    try {
      await expect(content.putBytes(new Uint8Array(CONTENT_CHUNK_BYTES).fill(91))).rejects.toThrow('TEST_DESCRIPTOR_FULL')
      // Retention is serialized after the already-scheduled discard cleanup.
      await content.retained(kept)
      expect((await store.entries()).map(entry => entry.key).sort()).toEqual(before)
    } finally { writing.mockRestore() }
  })

  it('captures a prune reference before the caller can mutate it', async () => {
    const f = await fixture(), content = f.openContent(0)
    const discarded = await content.putBytes(Uint8Array.of(1)), kept = await content.putBytes(Uint8Array.of(2))
    const input = { ...discarded }, pruning = content.prune(input)
    Object.assign(input, kept)
    await pruning
    expect(await content.readBytes(kept, { maxBytes: 1 })).toEqual(Uint8Array.of(2))
    await expect(content.readBytes(discarded, { maxBytes: 1 })).rejects.toThrow('CONTENT_UNAVAILABLE')
  })

  it('does not remove chunks retained under another valid manifest', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1), body = Uint8Array.of(4, 5, 6)
    const original = await a.putBytes(body, { mediaType: 'image/png' })
    const manifest = await a.serveManifest(f.b.publicKey, original)
    const alternate = { ...manifest!, mediaType: 'audio/ogg' }
    const alternateRef = { ...original, mediaType: alternate.mediaType,
      id: await bytesDigest(new TextEncoder().encode(canonicalJson(JSON.parse(JSON.stringify(alternate)) as EventPayload, { maxBytes: 262_144, maxNodes: 32_768, maxDepth: 16 }))) }
    const detach = b.attachSource(f.a.publicKey, {
      manifest: async reference => reference.id === original.id ? manifest : alternate,
      chunk: (_reference, index) => a.serveChunk(f.b.publicKey, original, index),
    })
    await b.retain(original); await b.retain(alternateRef); detach()
    await b.prune(original)
    expect(await b.readBytes(alternateRef, { maxBytes: body.length })).toEqual(body)
  })
})


describe('bounded content helpers and local eviction', () => {
  it('round trips empty and multi-chunk media, with explicit read ceilings', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const body = Uint8Array.from({ length: CONTENT_CHUNK_BYTES * 2 + 11 }, (_, i) => i % 251)
    const ref = await a.putBytes(body, { mediaType: 'audio/webm' })
    const manifest = vi.fn((reference: ContentReference) => a.serveManifest(f.b.publicKey, reference))
    b.attachSource(f.a.publicKey, { manifest, chunk: (reference, index) => a.serveChunk(f.b.publicKey, reference, index) })
    await expect(b.readBytes(ref, { maxBytes: body.length - 1 })).rejects.toThrow('CONTENT_READ_LIMIT_EXCEEDED')
    expect(manifest).not.toHaveBeenCalled()
    await expect(b.readBytes(ref, { maxBytes: -1 })).rejects.toThrow('CONTENT_READ_LIMIT_INVALID')
    expect(await b.readBytes(ref, { maxBytes: body.length })).toEqual(body)
    const empty = await a.putBytes(new Uint8Array())
    expect(await a.readBytes(empty, { maxBytes: 0 })).toEqual(new Uint8Array())
    expect(ref.mediaType).toBe('audio/webm')
    expect(f.peers[0]!.revision.point.sequence).toBe(0)
  })

  it('rejects an already-cancelled upload before staging and cleans a cancelled write', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!
    const kept = await content.putBytes(Uint8Array.of(8)), before = (await store.entries()).map(entry => entry.key).sort()
    const stopped = AbortSignal.abort(new Error('TEST_STOP'))
    await expect(content.putBytes(Uint8Array.of(1), { signal: stopped })).rejects.toThrow('TEST_STOP')
    const stop = new AbortController(), put = store.put.bind(store)
    let cancel = true
    const writing = vi.spyOn(store, 'put').mockImplementation(async (key, bytes) => {
      await put(key, bytes)
      if (cancel && key.includes('/chunk/')) { cancel = false; stop.abort(new Error('TEST_STOP')) }
    })
    try {
      await expect(content.putBytes(new Uint8Array(CONTENT_CHUNK_BYTES + 1), { signal: stop.signal })).rejects.toThrow('TEST_STOP')
      await content.retained(kept)
      expect((await store.entries()).map(entry => entry.key).sort()).toEqual(before)
    } finally { writing.mockRestore() }
  })

  it('repairs ciphertext after an interrupted write without reporting false progress', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!, upload = await content.stage({ bytes: 3 })
    const put = store.put.bind(store)
    let fail = true
    const writing = vi.spyOn(store, 'put').mockImplementation(async (key, bytes) => {
      if (fail && key.includes('/chunk/')) { fail = false; throw new Error('TEST_BODY_FULL') }
      await put(key, bytes)
    })
    try {
      await expect(upload.write(0, Uint8Array.of(1, 2, 3))).rejects.toThrow('TEST_BODY_FULL')
      expect(await upload.progress()).toEqual({ bytes: 3, storedBytes: 0, missingChunks: [0] })
      await expect(upload.commit()).rejects.toThrow('CONTENT_STAGE_INCOMPLETE')
      await expect(upload.write(0, Uint8Array.of(3, 2, 1))).rejects.toThrow('CONTENT_CHUNK_REUSED')
      await upload.write(0, Uint8Array.of(1, 2, 3))
      expect(await content.readBytes(await upload.commit(), { maxBytes: 3 })).toEqual(Uint8Array.of(1, 2, 3))
    } finally { writing.mockRestore() }
  })

  it('fences pending provider responses and permits a later explicit fetch', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1), body = Uint8Array.of(1, 3, 5)
    const ref = await a.putBytes(body), encrypted = await a.serveChunk(f.b.publicKey, ref, 0)
    const started = deferred<void>(), response = deferred<Uint8Array | null>()
    b.attachSource(f.a.publicKey, { manifest: reference => a.serveManifest(f.b.publicKey, reference),
      chunk: () => { started.resolve(); return response.promise } })
    const reading = b.readBytes(ref, { maxBytes: 3 }).catch((error: unknown) => error)
    await started.promise
    const first = b.prune(ref), second = b.prune(ref)
    await Promise.all([first, second])
    expect(await reading).toMatchObject({ message: 'CONTENT_PRUNED' })
    response.resolve(encrypted); await response.promise; await new Promise(setImmediate)
    expect((await f.stores[1]!.entries()).filter(entry => entry.key.startsWith('peer-content/'))).toEqual([])
    expect(await a.readBytes(ref, { maxBytes: 3 })).toEqual(body)
    expect(await b.readBytes(ref, { maxBytes: 3 })).toEqual(body)
    await b.prune(ref); await b.prune(ref)
    expect((await f.stores[1]!.entries()).filter(entry => entry.key.startsWith('peer-content/'))).toEqual([])
  })

  it('preserves chunks owned by a pending stage and discards stages idempotently', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!, body = Uint8Array.of(2, 4, 6)
    const upload = await content.stage({ bytes: 3 }); await upload.write(0, body)
    const entries = await store.entries(), stageKey = entries.find(entry => entry.key.endsWith('/stage/' + upload.id))!.key
    const stage = JSON.parse(new TextDecoder().decode((await store.get(stageKey))!)) as Record<string, unknown>
    const descriptor = JSON.parse(new TextDecoder().decode((await store.get(stageKey + '/0'))!)) as Record<string, unknown>
    const { committed: _committed, chunkLayout: _chunkLayout, ...metadata } = stage
    const { plaintextHash: _plaintextHash, ...chunk } = descriptor
    const manifest = { ...metadata, chunks: [chunk] }
    const encoded = new TextEncoder().encode(canonicalJson(manifest as EventPayload, { maxBytes: 262_144, maxNodes: 32_768, maxDepth: 16 }))
    const reference: ContentReference = { profile: 'peer-content-v1', applicationId: f.peers[0]!.descriptor.applicationId,
      historyId: f.peers[0]!.descriptor.historyId, id: await bytesDigest(encoded), epoch: 0, bytes: 3, mediaType: 'application/octet-stream' }
    await store.put(stageKey.slice(0, stageKey.indexOf('/stage/')) + '/manifest/' + reference.id, encoded)
    await content.prune(reference)
    expect((await upload.progress()).missingChunks).toEqual([])
    expect(await content.readBytes(await upload.commit(), { maxBytes: 3 })).toEqual(body)
    await upload.discard(); await upload.discard(); await content.discard(upload.id)
    expect((await store.entries()).filter(entry => entry.key.startsWith('peer-content/'))).toEqual([])
  })

  it('resumes a failed prune after reopening without deleting another reference', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!
    const ref = await content.putBytes(new Uint8Array(CONTENT_CHUNK_BYTES + 3)), kept = await content.putBytes(Uint8Array.of(9))
    const remove = store.delete.bind(store)
    let fail = true
    const deleting = vi.spyOn(store, 'delete').mockImplementation(async key => {
      if (fail && key.endsWith('/manifest/' + ref.id)) { fail = false; throw new Error('TEST_DELETE_INTERRUPTED') }
      await remove(key)
    })
    await expect(content.prune(ref)).rejects.toThrow('TEST_DELETE_INTERRUPTED')
    deleting.mockRestore(); content.close()
    const reopened = f.openContent(0)
    await expect(reopened.readBytes(ref, { maxBytes: ref.bytes })).rejects.toThrow('CONTENT_PRUNED')
    await reopened.prune(ref)
    expect(await reopened.readBytes(kept, { maxBytes: 1 })).toEqual(Uint8Array.of(9))
    await expect(reopened.readBytes(ref, { maxBytes: ref.bytes })).rejects.toThrow('CONTENT_UNAVAILABLE')
    expect((await store.entries()).some(entry => entry.key.includes('/prune/'))).toBe(false)
  })
})

import { describe, expect, it, vi } from 'vitest'
import { CONTENT_CHUNK_BYTES } from './content.js'
import { bytesDigest } from '@chronolog/peer-generation'
import { canonicalJson, type EventPayload } from '@chronolog/protocol'
import { deferred, fixture } from './content-test-fixture.js'

const contentEntries = async (f: Awaited<ReturnType<typeof fixture>>, index = 0) => (await f.stores[index]!.entries()).filter(entry => entry.key.startsWith('peer-content/'))

describe('bounded content bytes and local eviction', () => {
  it.each([0, 1, CONTENT_CHUNK_BYTES, CONTENT_CHUNK_BYTES * 2 + 17])('round trips %i bytes with one bounded chunk per write', async length => {
    const f = await fixture(), content = f.openContent(0), bytes = new Uint8Array(length)
    for (let index = 0; index < length; index++) bytes[index] = index % 251
    const ref = await content.putBytes(bytes, { mediaType: 'audio/webm' })
    expect(ref).toMatchObject({ bytes: length, mediaType: 'audio/webm' })
    expect(await content.readBytes(ref, { maxBytes: length })).toEqual(bytes)
    const manifest = await content.serveManifest(f.a.publicKey, ref)
    expect(manifest!.chunks).toHaveLength(Math.ceil(length / CONTENT_CHUNK_BYTES))
    await content.prune(ref); await content.prune(ref)
    expect(await contentEntries(f)).toEqual([])
    await expect(content.readBytes(ref, { maxBytes: length })).rejects.toThrow('CONTENT_UNAVAILABLE')
  })

  it('validates a required allocation ceiling and cancellation before contacting any source', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const ref = await a.putBytes(new Uint8Array(9)), manifest = vi.fn(async () => null)
    b.attachSource(f.a.publicKey, { manifest, chunk: async () => null })
    for (const maxBytes of [-1, NaN, Infinity, 128 * 1024 * 1024 + 1]) {
      await expect(b.readBytes(ref, { maxBytes })).rejects.toThrow('CONTENT_READ_LIMIT_INVALID')
    }
    await expect(b.readBytes(ref, { maxBytes: 8 })).rejects.toThrow('CONTENT_READ_LIMIT_EXCEEDED')
    const stop = new AbortController(); stop.abort(new Error('cancelled before acquisition'))
    await expect(b.readBytes(ref, { maxBytes: 9, signal: stop.signal })).rejects.toThrow('cancelled before acquisition')
    await expect(b.putBytes(new Uint8Array(9), { signal: stop.signal })).rejects.toThrow('cancelled before acquisition')
    expect(manifest).not.toHaveBeenCalled()
    expect(await contentEntries(f, 1)).toEqual([])
  })

  it('returns cancellation promptly and discards a late upload after its physical write settles', async () => {
    const f = await fixture(), content = f.openContent(0), entered = deferred<void>(), release = deferred<void>()
    const store = f.stores[0]!, put = store.put.bind(store), stop = new AbortController()
    const writing = vi.spyOn(store, 'put').mockImplementation(async (key, bytes) => {
      if (key.includes('/chunk/')) { entered.resolve(); await release.promise }
      await put(key, bytes)
    })
    const result = content.putBytes(new Uint8Array(CONTENT_CHUNK_BYTES + 1), { signal: stop.signal }).catch((error: unknown) => error)
    await entered.promise; stop.abort(new Error('capture stopped'))
    expect(await result).toMatchObject({ message: 'capture stopped' })
    release.resolve()
    await vi.waitFor(async () => { expect(await contentEntries(f)).toEqual([]) })
    writing.mockRestore()
  })

  it('prunes partial downloads and fences late provider replies without touching another reference or the journal', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const ref = await a.putBytes(Uint8Array.of(1, 2, 3)), keep = await b.putBytes(Uint8Array.of(8, 9))
    const baseline = (await f.stores[1]!.entries()).filter(entry => !entry.key.startsWith('peer-content/'))
    const entered = deferred<void>(), release = deferred<Uint8Array | null>()
    const detach = b.attachSource(f.a.publicKey, {
      manifest: reference => a.serveManifest(f.b.publicKey, reference),
      chunk: () => { entered.resolve(); return release.promise },
    })
    const reading = b.readBytes(ref, { maxBytes: 3 }).catch((error: unknown) => error)
    await entered.promise
    await Promise.all([b.prune(ref), b.prune(ref)])
    expect(await reading).toMatchObject({ message: 'CONTENT_PRUNED' })
    release.resolve(await a.serveChunk(f.b.publicKey, ref, 0)); await release.promise
    detach()
    expect(await b.serveManifest(f.b.publicKey, ref)).toBeNull()
    expect(await b.readBytes(keep, { maxBytes: 2 })).toEqual(Uint8Array.of(8, 9))
    expect((await f.stores[1]!.entries()).filter(entry => !entry.key.startsWith('peer-content/'))).toEqual(baseline)
    expect(await a.readBytes(ref, { maxBytes: 3 })).toEqual(Uint8Array.of(1, 2, 3))
    await b.prune(keep)
    expect(await contentEntries(f, 1)).toEqual([])
  })

  it('allows explicit refetch after eviction and treats retention receipts as historical observations', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const ref = await a.putBytes(Uint8Array.of(6, 7))
    b.attachSource(f.a.publicKey, { manifest: reference => a.serveManifest(f.b.publicKey, reference), chunk: (reference, index) => a.serveChunk(f.b.publicKey, reference, index) })
    const receipt = await b.retain(ref); await a.observeRetention(receipt)
    await b.prune(ref)
    await expect(b.retained(ref)).rejects.toThrow('CONTENT_NOT_RETAINED')
    expect(await a.retention(ref)).toEqual([receipt])
    expect(await b.readBytes(ref, { maxBytes: 2 })).toEqual(Uint8Array.of(6, 7))
  })

  it('keeps an interrupted deletion inventory across reopen and retries without regrowth', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!
    const ref = await content.putBytes(new Uint8Array(CONTENT_CHUNK_BYTES + 7))
    const remove = store.delete.bind(store)
    let failed = false
    const deleting = vi.spyOn(store, 'delete').mockImplementation(async key => {
      if (!failed && key.includes('/stage/')) { failed = true; throw new Error('disk unavailable') }
      await remove(key)
    })
    await expect(content.prune(ref)).rejects.toThrow('disk unavailable')
    content.close(); deleting.mockRestore()
    const reopened = f.openContent(0)
    await expect(reopened.readBytes(ref, { maxBytes: ref.bytes })).rejects.toThrow('CONTENT_PRUNED')
    await reopened.prune(ref)
    expect(await contentEntries(f)).toEqual([])
  })

  it('isolates manifests sharing ciphertext and never removes another local upload with the same stage ID', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1), body = Uint8Array.of(3, 8, 13)
    const ref = await a.putBytes(body, { mediaType: 'audio/webm' }), manifest = (await a.serveManifest(f.b.publicKey, ref))!
    const aliasManifest = { ...manifest, mediaType: 'audio/ogg' }
    const alias = { ...ref, mediaType: aliasManifest.mediaType, id: await bytesDigest(new TextEncoder().encode(canonicalJson(aliasManifest as unknown as EventPayload, { maxBytes: 262_144, maxNodes: 32_768, maxDepth: 16 }))) }
    b.attachSource(f.a.publicKey, {
      manifest: reference => reference.id === alias.id ? Promise.resolve(aliasManifest) : a.serveManifest(f.b.publicKey, reference),
      chunk: (_reference, index) => a.serveChunk(f.b.publicKey, ref, index),
    })
    expect(await b.readBytes(alias, { maxBytes: 3 })).toEqual(body)
    expect(await b.readBytes(ref, { maxBytes: 3 })).toEqual(body)
    a.attachSource(f.b.publicKey, {
      manifest: reference => b.serveManifest(f.a.publicKey, reference), chunk: (reference, index) => b.serveChunk(f.a.publicKey, reference, index),
    })
    expect(await a.readBytes(alias, { maxBytes: 3 })).toEqual(body)
    await a.prune(alias)
    expect(await (await a.resume(manifest.stageId)).commit()).toEqual(ref)
    expect(await a.readBytes(ref, { maxBytes: 3 })).toEqual(body)
    await b.prune(ref)
    expect(await b.readBytes(alias, { maxBytes: 3 })).toEqual(body)
    expect((await b.retained(alias)).payload.reference).toEqual(alias)
  })

  it('resumes a commit interrupted while moving staged chunks into reference ownership', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!, body = new Uint8Array(CONTENT_CHUNK_BYTES + 7).fill(29)
    const upload = await content.stage({ bytes: body.length })
    await upload.write(0, body.slice(0, CONTENT_CHUNK_BYTES)); await upload.write(1, body.slice(CONTENT_CHUNK_BYTES))
    const put = store.put.bind(store)
    let moved = 0
    const writing = vi.spyOn(store, 'put').mockImplementation(async (key, bytes) => {
      if (key.includes('/chunk/') && ++moved === 2) throw new Error('interrupted move')
      await put(key, bytes)
    })
    await expect(upload.commit()).rejects.toThrow('interrupted move')
    content.close(); writing.mockRestore()
    const reopened = f.openContent(0), resumed = await reopened.resume(upload.id), ref = await resumed.commit()
    expect(await reopened.readBytes(ref, { maxBytes: body.length })).toEqual(body)
    await resumed.discard(); await resumed.discard()
    expect(await contentEntries(f)).toEqual([])
  })

  it('recovers or discards a staged chunk whose ciphertext write was interrupted', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!, put = store.put.bind(store)
    const upload = await content.stage({ bytes: 3 }), body = Uint8Array.of(5, 10, 15)
    const writing = vi.spyOn(store, 'put').mockImplementation(async (key, bytes) => {
      if (key.includes('/chunk/')) throw new Error('ciphertext write failed')
      await put(key, bytes)
    })
    await expect(upload.write(0, body)).rejects.toThrow('ciphertext write failed')
    expect(await upload.progress()).toEqual({ bytes: 3, storedBytes: 0, missingChunks: [0] })
    writing.mockRestore(); content.close()
    const reopened = f.openContent(0), resumed = await reopened.resume(upload.id)
    await resumed.write(0, body)
    const ref = await resumed.commit()
    expect(await reopened.readBytes(ref, { maxBytes: 3 })).toEqual(body)
    await resumed.discard()
    const failing = vi.spyOn(store, 'put').mockImplementation(async (key, bytes) => {
      if (key.includes('/chunk/')) throw new Error('quota exhausted')
      await put(key, bytes)
    })
    await expect(reopened.putBytes(body)).rejects.toThrow('quota exhausted')
    await vi.waitFor(async () => { expect(await contentEntries(f)).toEqual([]) })
    failing.mockRestore()
  })

  it('preserves ambiguous legacy ciphertext so pruning one old manifest leaves its alias readable offline', async () => {
    const f = await fixture(), content = f.openContent(0), store = f.stores[0]!, body = Uint8Array.of(2, 4, 8)
    const ref = await content.putBytes(body), manifest = (await content.serveManifest(f.a.publicKey, ref))!
    const prefix = `peer-content/${ref.applicationId}/${ref.historyId}`
    const aliasManifest = { ...manifest, mediaType: 'audio/ogg' }
    const encode = (value: unknown) => new TextEncoder().encode(canonicalJson(value as EventPayload, { maxBytes: 262_144, maxNodes: 32_768, maxDepth: 16 }))
    const alias = { ...ref, mediaType: aliasManifest.mediaType, id: await bytesDigest(encode(aliasManifest)) }
    await store.put(`${prefix}/manifest/${alias.id}`, encode(aliasManifest))
    const stage = JSON.parse(new TextDecoder().decode((await store.get(`${prefix}/stage/${manifest.stageId}`))!)) as Record<string, unknown>
    delete stage.chunkLayout
    await store.put(`${prefix}/stage/${manifest.stageId}`, encode(stage))
    const hash = manifest.chunks[0]!.hash, scoped = `${prefix}/chunk/${ref.id}/${hash}`
    await store.put(`${prefix}/chunk/${hash}`, (await store.get(scoped))!)
    await store.delete(scoped)
    content.close()
    const reopened = f.openContent(0)
    expect(await reopened.readBytes(ref, { maxBytes: 3 })).toEqual(body)
    expect(await reopened.readBytes(alias, { maxBytes: 3 })).toEqual(body)
    await reopened.prune(ref)
    expect(await reopened.readBytes(alias, { maxBytes: 3 })).toEqual(body)
    expect((await reopened.retained(alias)).payload.reference).toEqual(alias)
    expect(await store.get(`${prefix}/chunk/${hash}`)).not.toBeNull()
  })

  it('reports stores without deletion support and keeps their existing read/write API usable', async () => {
    const f = await fixture(), backing = f.stores[0]!
    const content = f.openContent(0, { get: key => backing.get(key), put: (key, bytes) => backing.put(key, bytes) })
    const ref = await content.putBytes(Uint8Array.of(2))
    await expect(content.prune(ref)).rejects.toThrow('CONTENT_PRUNE_UNSUPPORTED')
    expect(await content.readBytes(ref, { maxBytes: 1 })).toEqual(Uint8Array.of(2))
  })
})

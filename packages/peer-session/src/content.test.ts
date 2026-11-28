import { afterEach, describe, expect, it } from 'vitest'
import { decodeRecord, encodeRecord, verifyRecord } from '@chronolog/authority'
import { ApplicationContent, CONTENT_CHUNK_BYTES, CONTENT_CHUNK_HEADER_BYTES, MAX_CONTENT_CHUNKS, assertContentManifest } from './content.js'
import { contentFixture, deferred, payload } from './content-test-fixture.js'

const cleanup: Array<() => Promise<unknown>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('encrypted resumable content', () => {
  it('stages indexed 64 KiB chunks durably, resumes after reopen, preserves exact committed identity and rejects conflicting retries', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const [a] = f.contents, bytes = payload(CONTENT_CHUNK_BYTES + 17)
    const upload = await a!.stage({ bytes: bytes.length, mediaType: 'text/plain' })
    await upload.write(1, bytes.subarray(CONTENT_CHUNK_BYTES))
    expect(await upload.progress()).toEqual({ bytes: bytes.length, storedBytes: 17, missingChunks: [0] })
    await a!.close()
    const reopened = f.reopen(0); cleanup.push(() => reopened.close())
    const resumed = await reopened.resumeUpload(upload.id)
    await resumed.write(1, bytes.subarray(CONTENT_CHUNK_BYTES))
    await expect(resumed.write(1, new Uint8Array(17))).rejects.toThrow('CONTENT_CHUNK_CONFLICT')
    await resumed.write(0, bytes.subarray(0, CONTENT_CHUNK_BYTES))
    const reference = await resumed.commit()
    expect(await (await reopened.resumeUpload(upload.id)).commit()).toEqual(reference)
    expect(await reopened.readBytes(reference, { maxBytes: bytes.length })).toEqual(bytes)
    for (const entry of await f.stores[0]!.entries()) {
      if (!entry.key.includes('/chunk/')) continue
      // Binary chunk: [format][epoch u64][nonce 12][ciphertext + tag], no record encoding.
      const index = Number(entry.key.slice(entry.key.lastIndexOf('/') + 1))
      expect(entry.value[0]).toBe(1)
      expect(entry.value.length).toBe(CONTENT_CHUNK_HEADER_BYTES + (index === 0 ? CONTENT_CHUNK_BYTES : 17) + 16)
    }
    await resumed.discard()
    expect(await reopened.readBytes(reference, { maxBytes: bytes.length })).toEqual(bytes)
    await expect(reopened.resumeUpload(upload.id)).rejects.toThrow('CONTENT_STAGE_DISCARDED')
  })

  it('retains exact encrypted bytes after uncertain writes and uncertain commit acknowledgments', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const content = f.contents[0]!, store = f.stores[0]!, put = store.put.bind(store)
    const upload = await content.stage({ bytes: 5 }), bytes = payload(5)
    let failWrite = true, failCommit = true
    store.put = async (key, value) => {
      await put(key, value)
      if (failWrite && key.endsWith('/chunk/0')) { failWrite = false; throw new Error('LOST_WRITE_REPLY') }
      if (failCommit && key.endsWith(`/stage/${upload.id}`) && decodeRecord<{ committed: unknown }>(value).committed !== null) { failCommit = false; throw new Error('LOST_COMMIT_REPLY') }
    }
    await expect(upload.write(0, bytes)).rejects.toThrow('LOST_WRITE_REPLY')
    const before = await store.get(`content/${f.applicationId}/stage/${upload.id}/chunk/0`)
    const resumed = await content.resumeUpload(upload.id)
    await resumed.write(0, bytes)
    expect(await store.get(`content/${f.applicationId}/stage/${upload.id}/chunk/0`)).toEqual(before)
    await expect(resumed.commit()).rejects.toThrow('LOST_COMMIT_REPLY')
    const reference = await (await content.resumeUpload(upload.id)).commit()
    expect(await upload.commit()).toEqual(reference)
    expect(await content.readBytes(reference, { maxBytes: 5 })).toEqual(bytes)
  })

  it('keeps source serving local-only, resumes interrupted pulls from persisted chunks, and signs retention only for complete verified objects', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const [a, b] = f.contents, bytes = payload(CONTENT_CHUNK_BYTES * 2 + 1), reference = await a!.putBytes(bytes)
    let manifestCalls = 0; const chunks: number[] = [], source = a!.source()
    b!.attachSource('fixture', { manifest: async ref => { manifestCalls++; return source.manifest(ref) }, chunk: async (ref, index) => { chunks.push(index); return source.chunk(ref, index) } })
    expect(await b!.source().manifest(reference)).toBeNull()
    expect(manifestCalls).toBe(0)
    const iterator = b!.read(reference)[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual(bytes.subarray(0, CONTENT_CHUNK_BYTES))
    await iterator.return?.()
    await expect(b!.source().retained!(reference)).rejects.toThrow('CONTENT_INCOMPLETE')
    await b!.close()
    const reopened = f.reopen(1); cleanup.push(() => reopened.close())
    reopened.attachSource('fixture', { manifest: (ref, options) => source.manifest(ref, options), chunk: async (ref, index) => { chunks.push(index); return source.chunk(ref, index) } })
    const receipt = await reopened.retain(reference)
    await verifyRecord('content-retention', receipt, f.identities[1]!.publicKey)
    expect(receipt.payload.storageId).toBe('storage-1')
    expect(chunks).toEqual([0, 1, 2])
    expect(await reopened.readBytes(reference, { maxBytes: bytes.length })).toEqual(bytes)
    expect(chunks).toEqual([0, 1, 2])
    a!.attachSource('retained-peer', reopened.source())
    expect(await a!.retention(reference)).toEqual([receipt])
    expect(await a!.retained(reference)).toEqual([receipt])
    await reopened.discard(reference)
    await expect(reopened.source().retained!(reference)).rejects.toThrow('CONTENT_MANIFEST_MISSING')
  })

  it('validates manifests, ciphertext hashes, signatures and reference/peer scopes before cache or retention acceptance', async () => {
    const f = await contentFixture(3); cleanup.push(f.close)
    const [a, b, c] = f.contents, reference = await a!.putBytes(payload(9)), source = a!.source(), manifest = (await source.manifest(reference))!
    const detach = b!.attachSource('bad-manifest', { manifest: async () => ({ ...manifest, chunks: [] }), chunk: (ref, index, options) => source.chunk(ref, index, options) })
    await expect(b!.readBytes(reference, { maxBytes: 9 })).rejects.toThrow('CONTENT_MANIFEST_INVALID')
    expect(await b!.source().manifest(reference)).toBeNull(); detach()
    b!.attachSource('bad-chunk', { manifest: (ref, options) => source.manifest(ref, options), chunk: async () => new Uint8Array(12) })
    await expect(b!.readBytes(reference, { maxBytes: 9 })).rejects.toThrow('CONTENT_CHUNK_INVALID')
    const receipt = await a!.retain(reference)
    await expect(c!.verifyRetention({ ...reference, bytes: 8 }, receipt)).rejects.toThrow('CONTENT_RETENTION_INVALID')
    await expect(c!.verifyRetention(reference, receipt, f.identities[1]!.publicKey)).rejects.toThrow('CONTENT_RETENTION_INVALID')
    await expect(c!.verifyRetention(reference, { ...receipt, signature: '00'.repeat(64) })).rejects.toThrow('AUTHORITY_SIGNATURE_INVALID')
    expect(() => assertContentManifest({ ...manifest, chunks: new Array(MAX_CONTENT_CHUNKS + 1).fill(manifest.chunks[0]) })).toThrow('CONTENT_MANIFEST_INVALID')
    await expect(c!.readBytes({ ...reference, applicationId: 'cd'.repeat(32) }, { maxBytes: 9 })).rejects.toThrow('CONTENT_SCOPE_INVALID')
  })

  it('fences stale upload handles durably on stores without delete and handles zero-byte objects', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const store = { get: f.stores[0]!.get.bind(f.stores[0]), put: f.stores[0]!.put.bind(f.stores[0]) }
    const content = new ApplicationContent({ store, authority: f.authorities[0]!, identity: f.identities[0]!, storageId: 'no-delete' }); cleanup.push(() => content.close())
    const upload = await content.stage({ bytes: 2 }), stale = await content.resumeUpload(upload.id)
    await upload.write(0, payload(2)); await upload.discard(); await upload.discard()
    await expect(stale.write(0, payload(2))).rejects.toThrow('CONTENT_STAGE_DISCARDED')
    await expect(stale.commit()).rejects.toThrow('CONTENT_STAGE_DISCARDED')
    await expect(content.resumeUpload(upload.id)).rejects.toThrow('CONTENT_STAGE_DISCARDED')
    const empty = await content.putBytes(new Uint8Array())
    expect(await content.readBytes(empty, { maxBytes: 0 })).toEqual(new Uint8Array())
    expect((await content.retain(empty)).payload.reference).toEqual(empty)
    await content.discard(empty)
    expect(await content.source().manifest(empty)).toBeNull()
  })

  it('aborts blocked reads promptly and fences late source replies after discard and close', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const [a, b] = f.contents, reference = await a!.putBytes(payload(7)), source = a!.source(), waiting = deferred<Uint8Array | null>(), entered = deferred<void>()
    b!.attachSource('blocked', { manifest: (ref, options) => source.manifest(ref, options), chunk: async () => { entered.resolve(); return waiting.promise } })
    const read = b!.readBytes(reference, { maxBytes: 7 }); const refused = expect(read).rejects.toThrow('CONTENT_DISCARDED')
    await entered.promise; await b!.discard(reference); await refused
    waiting.resolve(await source.chunk(reference, 0)); await Promise.resolve()
    expect(await b!.source().manifest(reference)).toBeNull()
    await b!.close()
    await expect(b!.stage({ bytes: 1 })).rejects.toThrow('CONTENT_CLOSED')
    await expect(b!.readBytes(reference, { maxBytes: 7 })).rejects.toThrow('CONTENT_CLOSED')
  })

  it('rejects closed or revoked local access and bounds references before fetching', async () => {
    const f = await contentFixture(); cleanup.push(f.close)
    const content = f.contents[0]!, reference = await content.putBytes(payload(5))
    let calls = 0
    f.contents[1]!.attachSource('counted', { manifest: async () => { calls++; return null }, chunk: async () => null })
    await expect(f.contents[1]!.readBytes(reference, { maxBytes: 4 })).rejects.toThrow('CONTENT_READ_LIMIT_EXCEEDED')
    expect(calls).toBe(0)
    const manifest = await content.source().manifest(reference)
    expect(manifest).not.toBeNull()
    await f.stores[0]!.put(`content/${f.applicationId}/manifest/${reference.id}`, encodeRecord({ ...manifest, reference: { ...manifest!.reference, bytes: 6 } }))
    await expect(content.source().retained!(reference)).rejects.toThrow('CONTENT_MANIFEST_INVALID')
  })
})

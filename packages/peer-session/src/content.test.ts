import { describe, expect, it, vi } from 'vitest'
import { bytesDigest, participantGrant, peerDigest, signControlRevision, signTransitionRequest } from '@chronolog/peer-generation'
import { CONTENT_CHUNK_BYTES } from './content.js'
import { collect, deferred, fixture } from './content-test-fixture.js'

describe('peer-held application content', () => {
  it('retains with one decrypt pass and verifies retained ciphertext without decrypting again', async () => {
    const f = await fixture(), content = f.openContent(0)
    const stage = await content.stage({ bytes: 3 })
    await stage.write(0, Uint8Array.of(1, 2, 3))
    const reference = await stage.commit(), decrypt = vi.spyOn(crypto.subtle, 'decrypt')
    try {
      expect((await content.retain(reference)).payload.reference).toEqual(reference)
      expect(decrypt).toHaveBeenCalledTimes(1)
      decrypt.mockClear()
      await content.retained(reference)
      await content.retained(reference)
      expect(decrypt).not.toHaveBeenCalled()
      const chunk = (await f.stores[0]!.entries()).find(entry => entry.key.includes('/chunk/'))!
      chunk.value[0]! ^= 1
      await f.stores[0]!.put(chunk.key, chunk.value)
      await expect(content.retained(reference)).rejects.toThrow('CONTENT_CHUNK_HASH_MISMATCH')
    } finally { decrypt.mockRestore() }
  })

  it('resumes indexed encrypted staging and preserves exact committed identity', async () => {
    const f = await fixture(), content = f.openContent(0)
    const body = new Uint8Array(CONTENT_CHUNK_BYTES + 17).fill(91)
    const stage = await content.stage({ bytes: body.length, mediaType: 'image/png' })
    await stage.write(1, body.slice(CONTENT_CHUNK_BYTES))
    await expect(stage.commit()).rejects.toThrow('CONTENT_STAGE_INCOMPLETE')
    expect(await stage.progress()).toEqual({ bytes: body.length, storedBytes: 17, missingChunks: [0] })
    content.close()
    const reopened = f.openContent(0), resumed = await reopened.resume(stage.id)
    await resumed.write(0, body.slice(0, CONTENT_CHUNK_BYTES))
    await resumed.write(0, body.slice(0, CONTENT_CHUNK_BYTES))
    await expect(resumed.write(0, new Uint8Array(CONTENT_CHUNK_BYTES))).rejects.toThrow('CONTENT_CHUNK_REUSED')
    const reference = await resumed.commit()
    expect(await resumed.commit()).toEqual(reference)
    const encrypted = await reopened.serveChunk(f.b.publicKey, reference, 0)
    expect(encrypted).toHaveLength(CONTENT_CHUNK_BYTES + 16)
    expect(encrypted!.slice(0, 100)).not.toEqual(body.slice(0, 100))
    expect(await collect(reopened, reference)).toEqual(body)
    await expect(reopened.serveManifest(f.outsider.publicKey, reference)).rejects.toThrow('CONTENT_ACCESS_DENIED')
    await expect(reopened.serveManifest(f.b.publicKey, { ...reference, historyId: 'elsewhere' })).rejects.toThrow('CONTENT_REFERENCE_INVALID')
  })

  it('fetches only requested chunks, resumes after loss, and acknowledges only a complete durable copy', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const body = new Uint8Array(CONTENT_CHUNK_BYTES * 2 + 7)
    for (let index = 0; index < body.length; index++) body[index] = index % 251
    const stage = await a.stage({ bytes: body.length })
    for (let index = 0; index < 3; index++) await stage.write(index, body.slice(index * CONTENT_CHUNK_BYTES, (index + 1) * CONTENT_CHUNK_BYTES))
    const ref = await stage.commit(), requests: number[] = []
    let failLast = true
    b.attachSource(f.a.publicKey, {
      manifest: reference => a.serveManifest(f.b.publicKey, reference),
      chunk: async (reference, index) => {
        requests.push(index)
        if (index === 2 && failLast) return null
        return a.serveChunk(f.b.publicKey, reference, index)
      },
    })
    expect(await collect(b, ref, { offset: CONTENT_CHUNK_BYTES + 5, length: 10 })).toEqual(body.slice(CONTENT_CHUNK_BYTES + 5, CONTENT_CHUNK_BYTES + 15))
    expect(requests).toEqual([1])
    await expect(b.retained(ref)).rejects.toThrow('CONTENT_NOT_RETAINED')
    await expect(collect(b, ref)).rejects.toThrow('CONTENT_UNAVAILABLE')
    expect(requests).toEqual([1, 0, 2])
    failLast = false
    expect(await collect(b, ref, { offset: CONTENT_CHUNK_BYTES * 2 })).toEqual(body.slice(CONTENT_CHUNK_BYTES * 2))
    expect(requests).toEqual([1, 0, 2, 2])
    const receipt = await b.retained(ref)
    await a.observeRetention(receipt)
    expect(await a.retention(ref)).toEqual([receipt])
    const forged = structuredClone(receipt); (forged.payload as { retainedAt: number }).retainedAt++
    await expect(a.observeRetention(forged)).rejects.toThrow('CONTENT_RETENTION_INVALID')
    a.close(); b.close()
    const reopenedB = f.openContent(1)
    expect(await collect(reopenedB, ref)).toEqual(body)
    expect((await f.openContent(0).retention(ref))[0]).toEqual(receipt)
    expect(f.peers[1]!.revision.point.sequence).toBe(0)
  })

  it('keeps access and staging epoch checks active after reader revocation', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const complete = await a.stage({ bytes: 3 }); await complete.write(0, new Uint8Array([1, 2, 3]))
    const reference = await complete.commit(), partial = await a.stage({ bytes: 3 })
    const key = crypto.getRandomValues(new Uint8Array(32)); f.keys.set(1, key)
    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control), epoch: 1,
      keyDigest: await bytesDigest(key), grants: [participantGrant(f.a.publicKey, { administrator: true })] }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: f.peers[0]!.descriptor.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      transitionId: 'revoke', expectedGeneration: f.peers[0]!.generation.id, requester: f.a.publicKey, coordinator: f.a.publicKey,
      controlRevision: 1, reason: 'control-change', base: await f.peers[0]!.recoveryPoint() }, f.a), { control })
    const selected = await f.registry.read()
    await f.peers[0]!.adopt(selected); await f.peers[1]!.adopt(selected)
    await expect(a.serveManifest(f.b.publicKey, reference)).rejects.toThrow('CONTENT_ACCESS_DENIED')
    await expect(collect(b, reference)).rejects.toThrow('CONTENT_ACCESS_DENIED')
    await expect(partial.write(0, new Uint8Array([4, 5, 6]))).rejects.toThrow('CONTENT_STAGE_EPOCH_CHANGED')
  })

  it('bounds unanswered provider requests and releases manifest and retention waits on close', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const upload = await a.stage({ bytes: 3 }); await upload.write(0, new Uint8Array([1, 2, 3]))
    const ref = await upload.commit(), started = Array.from({ length: 8 }, () => deferred<void>())
    let requests = 0
    b.attachSource(f.a.publicKey, {
      manifest: () => { started[requests++]!.resolve(); return new Promise(() => undefined) },
      chunk: async () => null,
    })
    // Stopping a caller's wait must not release the still-running provider's
    // physical request slot and permit unbounded abandoned requests.
    for (let index = 0; index < 7; index++) {
      const stop = new AbortController()
      const result = collect(b, ref, { signal: stop.signal }).catch((error: unknown) => error)
      await started[index]!.promise
      stop.abort(new Error('TEST_WAIT_ENDED'))
      expect(await result).toMatchObject({ message: 'TEST_WAIT_ENDED' })
    }
    const reading = collect(b, ref).catch((error: unknown) => error)
    await started[7]!.promise
    await expect(collect(b, ref)).rejects.toThrow('CONTENT_UNAVAILABLE')
    expect(requests).toBe(8)
    b.close()
    expect(await reading).toMatchObject({ message: 'CONTENT_CLOSED' })

    const observing = deferred<void>()
    a.attachSource(f.b.publicKey, {
      manifest: async () => null, chunk: async () => null,
      observeRetention: () => { observing.resolve(); return new Promise(() => undefined) },
    })
    const retaining = a.retain(ref).catch((error: unknown) => error)
    await observing.promise
    a.close()
    expect(await retaining).toMatchObject({ message: 'CONTENT_CLOSED' })
    expect(await collect(f.openContent(0), ref)).toEqual(new Uint8Array([1, 2, 3]))
  })

  it('fences a late encrypted provider response before storage or plaintext publication', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const body = new Uint8Array([11, 22, 33]), upload = await a.stage({ bytes: body.length })
    await upload.write(0, body)
    const ref = await upload.commit(), encrypted = await a.serveChunk(f.b.publicKey, ref, 0)
    const started = deferred<void>(), response = deferred<Uint8Array | null>()
    b.attachSource(f.a.publicKey, {
      manifest: reference => a.serveManifest(f.b.publicKey, reference),
      chunk: () => { started.resolve(); return response.promise },
    })
    const reading = collect(b, ref).catch((error: unknown) => error)
    await started.promise
    b.close()
    expect(await reading).toMatchObject({ message: 'CONTENT_CLOSED' })
    response.resolve(encrypted)
    await response.promise
    const reopened = f.openContent(1)
    expect(await reopened.serveManifest(f.b.publicKey, ref)).not.toBeNull()
    expect(await reopened.serveChunk(f.b.publicKey, ref, 0)).toBeNull()
    await expect(reopened.retained(ref)).rejects.toThrow('CONTENT_NOT_RETAINED')
  })
})

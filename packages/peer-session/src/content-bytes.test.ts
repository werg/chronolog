import { afterEach, describe, expect, it, vi } from 'vitest'
import { CONTENT_CHUNK_BYTES, putContentBytes, readContentBytes } from './content-bytes.js'
import type { ContentReference, ContentUpload } from './content.js'
import { deferred, payload } from './content-test-fixture.js'

const reference: ContentReference = { profile: 'authored-content-v1', applicationId: 'ab'.repeat(32), id: 'cd'.repeat(32), epoch: 0, bytes: 1, mediaType: 'application/octet-stream' }
afterEach(() => vi.restoreAllMocks())
describe('bounded byte conveniences', () => {
  it('checks an explicit read ceiling before invoking a source or allocating its body', async () => {
    let called = false
    const content = { async *read() { called = true; yield payload(1) } }
    await expect(readContentBytes(content, { ...reference, bytes: 128 * 1024 * 1024 }, { maxBytes: 1 })).rejects.toThrow('CONTENT_READ_LIMIT_EXCEEDED')
    await expect(readContentBytes(content, reference, { maxBytes: -1 })).rejects.toThrow('CONTENT_READ_LIMIT_INVALID')
    expect(called).toBe(false)
  })
  it('rejects truncated, overrun, oversized and empty chunk streams', async () => {
    for (const chunks of [[], [new Uint8Array()], [payload(2)], [payload(CONTENT_CHUNK_BYTES + 1)]]) {
      await expect(readContentBytes({ async *read() { yield* chunks } }, reference, { maxBytes: 1 })).rejects.toThrow()
    }
  })
  it('cancels a noncooperative iterator promptly and observes its late rejection', async () => {
    const next = deferred<IteratorResult<Uint8Array>>(), stop = new AbortController()
    let returned = false
    const content = { read() { return { [Symbol.asyncIterator]() { return {
      next: () => next.promise,
      return: () => { returned = true; return Promise.resolve({ done: true as const, value: undefined }) },
    } } } } }
    const reading = readContentBytes(content, reference, { maxBytes: 1, signal: stop.signal })
    const rejected = expect(reading).rejects.toThrow('cancel-read')
    stop.abort(new Error('cancel-read')); await rejected
    expect(returned).toBe(true)
    next.reject(new Error('late-source-failure')); await Promise.resolve()
  })
  it('cleans up staging acquired after cancellation and never writes it', async () => {
    const stage = deferred<ContentUpload>(), stop = new AbortController(), discarded = deferred<void>()
    const write = vi.fn(async () => {})
    const upload: ContentUpload = { id: crypto.randomUUID(), write, commit: async () => reference,
      progress: async () => ({ bytes: 1, storedBytes: 0, missingChunks: [0] }), discard: async () => { discarded.resolve() } }
    const putting = putContentBytes({ stage: () => stage.promise }, payload(1), { signal: stop.signal })
    const rejected = expect(putting).rejects.toThrow('cancel-put')
    stop.abort(new Error('cancel-put')); await rejected
    stage.resolve(upload); await discarded.promise
    expect(write).not.toHaveBeenCalled()
  })
  it('keeps convenience writes one bounded detached chunk at a time', async () => {
    const source = payload(CONTENT_CHUNK_BYTES + 3), chunks: Uint8Array[] = []
    const upload: ContentUpload = { id: crypto.randomUUID(), write: async (_index, bytes) => { chunks.push(bytes); bytes.fill(7) },
      commit: async () => ({ ...reference, bytes: source.length }), progress: async () => ({ bytes: source.length, storedBytes: 0, missingChunks: [] }), discard: async () => {} }
    await putContentBytes({ stage: async () => upload }, source)
    expect(chunks.map(chunk => chunk.length)).toEqual([CONTENT_CHUNK_BYTES, 3])
    expect(source).toEqual(payload(source.length))
  })
})

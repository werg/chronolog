import { expect, it, vi } from 'vitest'
import { MemoryBytesStore, type BytesStore, type BytesStoreEntry } from '@chronolog/records'
import { exportDeviceCheckpointStream, restoreDeviceCheckpointStream, generateCheckpointKey } from './checkpoint.js'

function recordingSink() {
  const chunks: Uint8Array[] = [], commit = vi.fn(), abort = vi.fn()
  return { chunks, commit, abort, write: (bytes: Uint8Array) => { chunks.push(bytes.slice()) },
    async *source() { for (const chunk of chunks) yield chunk } }
}

it.each(['raw', 'passphrase'])('streams binary entries, outbox and SQL through bounded frames using a %s secret', async mode => {
  const source = new MemoryBytesStore(), target = new MemoryBytesStore(), secret = mode === 'raw' ? generateCheckpointKey() : 'a long checkpoint passphrase', sink = recordingSink()
  await source.put('z', Uint8Array.of(255, 0)); await source.put('empty', new Uint8Array())
  await source.put('large', new Uint8Array(131_075).fill(7))
  const outbox = [{ operationId: 'pending', createdAt: new Date().toISOString() }]
  const sql = Uint8Array.of(10, 11, 12)
  const exported = await exportDeviceCheckpointStream(source, { secret, sink, retireSource: false, outbox,
    sqlDatabase: { bytes: sql.length, chunks: (async function* () { yield sql.subarray(0, 1); yield sql.subarray(1) })() } })
  const sqlSink = recordingSink()
  const restored = await restoreDeviceCheckpointStream(target, (async function* () {
    for (const chunk of sink.chunks) for (let offset = 0; offset < chunk.length; offset += 13) yield chunk.subarray(offset, offset + 13)
  })(), { secret, sqlSink })
  expect(restored.metadata).toEqual(exported.metadata)
  expect(restored.outbox).toEqual(outbox); expect(restored.sqlDatabaseBytes).toBeNull()
  expect(await target.entries()).toEqual(await source.entries())
  expect(sqlSink.chunks.flatMap(bytes => [...bytes])).toEqual([...sql])
  expect(sqlSink.commit).toHaveBeenCalledOnce(); expect(sink.commit).toHaveBeenCalledOnce()
})

it('never publishes a partial identity on truncation, corruption, trailing bytes or wrong keys', async () => {
  const source = new MemoryBytesStore(), secret = generateCheckpointKey(), sink = recordingSink()
  await source.put('identity', Uint8Array.of(1, 2))
  await exportDeviceCheckpointStream(source, { secret, sink, retireSource: false })
  for (const mode of ['truncated', 'corrupt', 'trailing', 'wrong-key']) {
    const chunks = sink.chunks.map(chunk => chunk.slice()), target = new MemoryBytesStore()
    if (mode === 'truncated') chunks.pop()
    if (mode === 'corrupt') chunks[2]![9]! ^= 1
    if (mode === 'trailing') chunks.push(Uint8Array.of(99))
    await expect(restoreDeviceCheckpointStream(target, (async function* () { yield* chunks })(), { secret: mode === 'wrong-key' ? generateCheckpointKey() : secret })).rejects.toBeInstanceOf(Error)
    expect(await target.entries()).toEqual([])
  }
})

it('releases an abandoned enumeration and preserves source usability after sink failure', async () => {
  const store = new MemoryBytesStore(), secret = generateCheckpointKey(), original = Error('disk full'), abort = vi.fn()
  await store.put('identity', Uint8Array.of(1))
  await expect(exportDeviceCheckpointStream(store, { secret, sink: { write: () => { throw original }, commit: vi.fn(), abort } })).rejects.toBe(original)
  expect(abort).toHaveBeenCalledWith(original)
  const sink = recordingSink()
  await exportDeviceCheckpointStream(store, { secret, sink, retireSource: false })
  await expect(restoreDeviceCheckpointStream(new MemoryBytesStore(), sink.source(), { secret, limits: { maxBytes: 0 } })).rejects.toMatchObject({ code: 'CHECKPOINT_LIMIT_EXCEEDED' })
})

it('hands off more than 256 MiB with one frame of transport backpressure and one value in memory', async () => {
  const secret = generateCheckpointKey(), value = new Uint8Array(8 * 1024 * 1024).fill(42), count = 33
  const enumerate = async function* (): AsyncGenerator<BytesStoreEntry> {
    for (let index = 0; index < count; index++) yield { key: `record/${index.toString().padStart(3, '0')}`, value }
  }
  const source: BytesStore = { get: async () => null, put: async () => undefined, iterateEntries: enumerate }
  let published = false
  const target: BytesStore = { get: async () => null, put: async () => undefined, iterateEntries: enumerate,
    putStreamIfEmpty: async entries => {
      let received = 0
      for await (const entry of entries) {
        expect(entry.key).toBe(`record/${received.toString().padStart(3, '0')}`)
        expect(entry.value.length).toBe(value.length)
        expect(entry.value.every(byte => byte === 42)).toBe(true)
        received++
      }
      expect(received).toBe(count); published = true; return true
    } }
  const queue: { bytes: Uint8Array; resolve(): void }[] = []
  let wake: () => void = () => undefined, done = false, maxFrame = 0
  const sink = { write: (bytes: Uint8Array) => new Promise<void>(resolve => { maxFrame = Math.max(maxFrame, bytes.length); queue.push({ bytes, resolve }); wake() }),
    commit: () => { done = true; wake() } }
  const transport = (async function* () {
    for (;;) {
      if (queue.length === 0 && !done) await new Promise<void>(resolve => { wake = resolve })
      const next = queue.shift()
      if (next === undefined) return
      yield next.bytes; next.resolve()
    }
  })()
  const exported = exportDeviceCheckpointStream(source, { secret, sink, retireSource: false })
  const restored = restoreDeviceCheckpointStream(target, transport, { secret })
  const [result, imported] = await Promise.all([exported, restored])
  expect(published).toBe(true); expect(imported.metadata).toEqual(result.metadata)
  expect(maxFrame).toBeLessThan(66_000)
}, 60_000)

it('streams a maximum outbox without concentrating it in one oversized footer frame', async () => {
  const source = new MemoryBytesStore(), secret = generateCheckpointKey(), sink = recordingSink()
  const outbox = Array.from({ length: 1024 }, (_, index) => ({ operationId: `${index}/` + 'ü'.repeat(500),
    command: '\0'.repeat(128), status: '\0'.repeat(128), createdAt: '2026-11-23T00:00:00.000Z' }))
  await exportDeviceCheckpointStream(source, { secret, sink, outbox, retireSource: false })
  const restored = await restoreDeviceCheckpointStream(new MemoryBytesStore(), sink.source(), { secret })
  expect(restored.outbox).toHaveLength(1024)
  expect(restored.outbox[1023]).toEqual(outbox[1023])
  expect(sink.chunks.every(chunk => chunk.length < 66_000)).toBe(true)
})

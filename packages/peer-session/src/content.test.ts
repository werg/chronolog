import { afterEach, describe, expect, it } from 'vitest'
import { createAppliedEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, executionManifestArtifacts } from '@chronolog/protocol'
import {
  bytesDigest, controlIntentDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryPeerStore, participantGrant, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, type PeerReplica,
} from '@chronolog/peer-generation'
import { ApplicationContent, CONTENT_CHUNK_BYTES, type ContentManifest, type ContentReference } from './content.js'

const peers: PeerReplica[] = [], contents: ApplicationContent[] = []
afterEach(async () => { for (const content of contents.splice(0)) content.close(); for (const peer of peers.splice(0)) await peer.close() })
async function fixture() {
  const host = await createPeerIdentity(), a = await createPeerIdentity(), b = await createPeerIdentity(), outsider = await createPeerIdentity()
  const key = crypto.getRandomValues(new Uint8Array(32)), keys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: '45'.repeat(32), historyId: 'content-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: a.publicKey,
    executionManifestDigest: bytesToHex(manifest.executionManifestDigest), definitionDigest: '01'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b].map(device => participantGrant(device.publicKey, {
      reader: true, writer: true, coordinator: true, recovery: true, administrator: device === a, dataRole: 'member',
    })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null, coordinator: a.publicKey,
    requester: a.publicKey, controlRevision: 0, controlIntentDigest: await controlIntentDigest(control.payload), contextDigest: null, reason: 'create', base: null }, a))
  const stores = [new MemoryPeerStore(), new MemoryPeerStore()]
  const opened = await Promise.all([a, b].map(async (device, index) => {
    const store = stores[index]!, materializer = await createAppliedEventMaterializationRuntime({ store, namespace: 'content' })
    const peer = await createPeerReplica({ authority: await registry.read(), device, store, storageId: device.publicKey, materializer, epochKeys: keys })
    peers.push(peer); return peer
  }))
  const openContent = (index: number) => {
    const content = new ApplicationContent({ replica: opened[index]!, store: stores[index]!, storageId: [a, b][index]!.publicKey, epochKeys: keys })
    contents.push(content); return content
  }
  return { host, a, b, outsider, keys, control, registry, peers: opened, openContent }
}
async function collect(content: ApplicationContent, ref: ContentReference, options: { offset?: number; length?: number; signal?: AbortSignal } = {}): Promise<Uint8Array> {
  const pieces: Uint8Array[] = []
  for await (const bytes of content.read(ref, options)) pieces.push(bytes)
  const output = new Uint8Array(pieces.reduce((length, bytes) => length + bytes.length, 0))
  let offset = 0
  for (const piece of pieces) { output.set(piece, offset); offset += piece.length }
  return output
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

describe('peer-held application content', () => {
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

  it('uses delivered keys after rotation while refusing revoked readers and old stages', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const complete = await a.stage({ bytes: 3 }); await complete.write(0, new Uint8Array([1, 2, 3]))
    const reference = await complete.commit(), partial = await a.stage({ bytes: 3 })
    const key = crypto.getRandomValues(new Uint8Array(32)); f.keys.set(1, key)
    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control), epoch: 1,
      keyDigest: await bytesDigest(key), grants: [participantGrant(f.a.publicKey, { reader: true, writer: true, coordinator: true, recovery: true, administrator: true, dataRole: 'member' })] }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: f.peers[0]!.descriptor.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      transitionId: 'revoke', expectedGeneration: f.peers[0]!.generation.id, requester: f.a.publicKey, coordinator: f.a.publicKey,
      controlRevision: 1, controlIntentDigest: await controlIntentDigest(control.payload), contextDigest: null, reason: 'control-change', base: await f.peers[0]!.recoveryPoint() }, f.a), { control })
    const selected = await f.registry.read()
    await f.peers[0]!.adopt(selected); await f.peers[1]!.adopt(selected)
    await expect(a.serveManifest(f.b.publicKey, reference)).rejects.toThrow('CONTENT_ACCESS_DENIED')
    await expect(collect(b, reference)).rejects.toThrow('CONTENT_ACCESS_DENIED')
    await expect(partial.write(0, new Uint8Array([4, 5, 6]))).rejects.toThrow('CONTENT_STAGE_EPOCH_CHANGED')
    const next = await a.stage({ bytes: 3 }); await next.write(0, new Uint8Array([7, 8, 9]))
    const current = await next.commit()
    expect(current.epoch).toBe(1)
    expect(await collect(a, current)).toEqual(new Uint8Array([7, 8, 9]))
    const preserved = key.slice()
    a.close()
    expect(f.keys.get(1)).toEqual(preserved)
    expect(await collect(f.openContent(0), current)).toEqual(new Uint8Array([7, 8, 9]))
  })

  it('cancels stalled reads while retaining provider capacity until actual settlement', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const upload = await a.stage({ bytes: 3 }); await upload.write(0, new Uint8Array([1, 2, 3]))
    const reference = await upload.commit(), manifest = await a.serveManifest(f.b.publicKey, reference)
    const pending: ReturnType<typeof deferred<ContentManifest | null>>[] = []
    let started = deferred<void>(), blocking = true
    b.attachSource(f.a.publicKey, {
      manifest: async (_reference, options) => {
        if (!blocking) return manifest
        const item = deferred<ContentManifest | null>(); pending.push(item); started.resolve()
        expect(options?.signal).toBeDefined()
        return item.promise
      },
      chunk: (value, index) => a.serveChunk(f.b.publicKey, value, index),
    })
    try {
      for (let index = 0; index < 16; index++) {
        started = deferred<void>()
        const lifetime = new AbortController()
        const reading = collect(b, reference, { signal: lifetime.signal })
        await started.promise
        lifetime.abort(new Error('READ_CANCELLED'))
        await expect(reading).rejects.toThrow('READ_CANCELLED')
      }
      await expect(collect(b, reference)).rejects.toThrow('CONTENT_SOURCE_BUSY')
      expect(pending).toHaveLength(16)
      blocking = false
      pending[0]!.resolve(manifest)
      // A real asynchronous verification lets the settled provider's accounting
      // finish; the other fifteen noncooperative callbacks remain outstanding.
      await a.serveManifest(f.b.publicKey, reference)
      expect(await collect(b, reference)).toEqual(new Uint8Array([1, 2, 3]))
    } finally { for (const item of pending) item.resolve(null) }
  })

  it('ends a stalled content read when its owner closes without clearing the shared key provider', async () => {
    const f = await fixture(), a = f.openContent(0), b = f.openContent(1)
    const upload = await a.stage({ bytes: 1 }); await upload.write(0, new Uint8Array([9]))
    const reference = await upload.commit(), started = deferred<void>(), pending = deferred<ContentManifest | null>()
    const keys = new Map([...f.keys].map(([epoch, bytes]) => [epoch, bytes.slice()]))
    b.attachSource(f.a.publicKey, {
      manifest: async () => { started.resolve(); return pending.promise },
      chunk: async () => null,
    })
    const reading = collect(b, reference)
    await started.promise
    b.close()
    await expect(reading).rejects.toThrow('CONTENT_CLOSED')
    expect(f.keys).toEqual(keys)
    pending.resolve(null)
  })

  it('cancels optional retention announcements without losing the completed local copy', async () => {
    const f = await fixture(), a = f.openContent(0)
    const upload = await a.stage({ bytes: 2 }); await upload.write(0, new Uint8Array([7, 8]))
    const reference = await upload.commit(), started = deferred<void>(), pending = deferred<void>()
    let announcementSignal: AbortSignal | undefined
    a.attachSource(f.b.publicKey, {
      manifest: async () => null,
      chunk: async () => null,
      observeRetention: async (_receipt, options) => { announcementSignal = options?.signal; started.resolve(); return pending.promise },
    })
    const lifetime = new AbortController(), retaining = a.retain(reference, { signal: lifetime.signal })
    await started.promise
    lifetime.abort(new Error('ANNOUNCEMENT_CANCELLED'))
    await expect(retaining).rejects.toThrow('ANNOUNCEMENT_CANCELLED')
    expect(announcementSignal?.aborted).toBe(true)
    expect((await a.retained(reference)).payload.reference).toEqual(reference)
    expect(await collect(a, reference)).toEqual(new Uint8Array([7, 8]))
    pending.resolve()
  })
})

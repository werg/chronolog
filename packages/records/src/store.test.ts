import { mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { createFeedRecord, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from './feed-codec.js'
import { DurableFeedStore, type AtomicBytesStore } from './store.js'
import { payloadHash } from './payload.js'

const directories: string[] = []
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))) })

async function fixture() {
  const path = await mkdtemp(join(tmpdir(), 'chronolog-records-'))
  directories.push(path)
  let failManifest = false
  const bytes: AtomicBytesStore = {
    async get(key) {
      try { return new Uint8Array(await readFile(join(path, encodeURIComponent(key)))) } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
        throw error
      }
    },
    async put(key, value) {
      if (key === 'feed/manifest' && failManifest) throw new Error('simulated durable publication failure')
      const target = join(path, encodeURIComponent(key))
      await writeFile(`${target}.tmp`, value, { flush: true })
      await rename(`${target}.tmp`, target)
    },
  }
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const id = feedIdFromPublicKey(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)))
  const signer = webFeedSigner(id, keys.privateKey)
  return { bytes, signer, failNextPublication: () => { failManifest = true } }
}

describe('durable portable feed store', () => {
  it('retains detached payloads by hash without adding a feed or ledger entry', async () => {
    const { bytes, signer } = await fixture()
    let store = await DurableFeedStore.open(bytes, webFeedCrypto)
    const payload = Uint8Array.of(7, 8, 9), hash = await store.putPayload(payload)
    payload[0] = 0
    expect(await store.getPayload(hash)).toEqual(Uint8Array.of(7, 8, 9))
    expect(store.count()).toBe(0)
    await store.close()
    store = await DurableFeedStore.open(bytes, webFeedCrypto)
    expect(await store.getPayload(hash)).toEqual(Uint8Array.of(7, 8, 9))
    const record = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(3, 4))
    await store.append(record)
    expect(await store.getPayload(await payloadHash(record.payload))).toEqual(record.payload)
    await bytes.put(`feed/payload/${hash}`, Uint8Array.of(9))
    await expect(store.getPayload(hash)).rejects.toThrow('PAYLOAD_HASH_MISMATCH')
    await expect(store.getPayload('../escape')).rejects.toThrow('PAYLOAD_HASH_INVALID')
  })

  it('retains immutable evidence independently of mutable feed sequence', async () => {
    const { bytes } = await fixture()
    let store = await DurableFeedStore.open(bytes, webFeedCrypto)
    const proof = await store.putEvidence(Uint8Array.of(1, 5, 8))
    expect(proof.kind).toBe('appended')
    await store.close()
    store = await DurableFeedStore.open(bytes, webFeedCrypto)
    expect((await store.putEvidence(proof.evidence.bytes)).kind).toBe('duplicate')
    expect(store.evidenceAfter(0n, 10)).toEqual([{ index: 1n, evidence: proof.evidence }])
    expect(store.heads().size).toBe(0)
    expect(store.count()).toBe(0)
  })

  it('reopens exact bytes, contiguous heads, and idempotent append identity', async () => {
    const { bytes, signer } = await fixture()
    let store = await DurableFeedStore.open(bytes, webFeedCrypto)
    const first = await createFeedRecord(signer, webFeedCrypto, 1n, null, 5n, Uint8Array.of(1, 2))
    expect((await store.append(first, 10)).kind).toBe('appended')
    await store.close()
    store = await DurableFeedStore.open(bytes, webFeedCrypto)
    expect(await store.append(first, 20)).toEqual({ kind: 'duplicate' })
    expect(store.head(signer.identity)).toEqual({ sequence: 1n, id: first.id })
    expect(store.feedAfter(signer.identity, 0n, 10)[0]?.raw).toEqual(first.raw)
    expect(store.get(first.id)?.receivedAtMs).toBe(10)
  })

  it('does not publish an incomplete append after interruption', async () => {
    const { bytes, signer, failNextPublication } = await fixture()
    const store = await DurableFeedStore.open(bytes, webFeedCrypto)
    const first = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(1))
    await store.append(first)
    const second = await createFeedRecord(signer, webFeedCrypto, 2n, first.id, 2n, Uint8Array.of(2))
    failNextPublication()
    await expect(store.append(second)).rejects.toThrow('publication failure')
    expect(store.get(second.id)).toBeUndefined()
    const recovered = await DurableFeedStore.open(bytes, webFeedCrypto)
    expect(recovered.count()).toBe(1)
    expect(recovered.head(signer.identity).id).toBe(first.id)
  })

  it('serializes append decisions and preserves fork evidence across reopen', async () => {
    const { bytes, signer } = await fixture()
    const store = await DurableFeedStore.open(bytes, webFeedCrypto)
    const first = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(1))
    const conflicting = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(2))
    const results = await Promise.all([store.append(first), store.append(first), store.append(conflicting)])
    expect(results.map((result) => result.kind)).toEqual(['appended', 'duplicate', 'fork'])
    const reopened = await DurableFeedStore.open(bytes, webFeedCrypto)
    expect(reopened.count()).toBe(1)
    expect(reopened.forkedAuthors()).toEqual([signer.identity])
  })

  it('blocks missing retained bytes instead of inventing a clean empty history', async () => {
    const { bytes, signer } = await fixture()
    const store = await DurableFeedStore.open(bytes, webFeedCrypto)
    const first = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(1))
    await store.append(first)
    await expect(DurableFeedStore.open({ ...bytes, get: (key) => key.startsWith('feed/object/') ? Promise.resolve(null) : bytes.get(key) }, webFeedCrypto))
      .rejects.toThrow('FEED_STORE_RECORD_MISSING')
  })
})

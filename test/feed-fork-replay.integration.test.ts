import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { FeedForkRegistry, MemoryOperationStore } from '@chronolog/node-core/browser'
import { createFeedRecord, DurableFeedStore, feedIdFromPublicKey, PortableFeedTransport, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import type { ChronologTransport, FeedStorePort, TransportRecord } from '@chronolog/records'
import { FeedStore } from '@chronolog/transport-ssb'
import { describe, expect, it } from 'vitest'

async function take(transport: ChronologTransport, count: number): Promise<TransportRecord[]> {
  const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 1_000)
  const records: TransportRecord[] = []
  try {
    for await (const record of transport.subscribe(controller.signal)) {
      records.push(record)
      if (records.length === count) break
    }
    return records
  } finally { clearTimeout(timeout); controller.abort() }
}

for (const storage of ['portable', 'sqlite'] as const) describe(`${storage} retained fork replay`, () => {
  it('reconstructs quarantine for late subscribers and after storage reopen', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-fork-replay-'))
    const bytes = new MemoryOperationStore()
    const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
    const signer = webFeedSigner(feedIdFromPublicKey(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))), keys.privateKey)
    const openStore = async (): Promise<FeedStorePort> => storage === 'portable'
      ? DurableFeedStore.open(bytes, webFeedCrypto) : new FeedStore(join(directory, 'feeds.sqlite'))
    let store = await openStore(), transport: PortableFeedTransport | undefined
    try {
      const first = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(1))
      const fork = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(2))
      await store.append(first, 10)
      await store.append(fork, 20)
      await store.append(fork, 30)
      for (let restart = 0; restart < 2; restart += 1) {
        transport = new PortableFeedTransport({ store, signer, crypto: webFeedCrypto })
        const history = await transport.history()
        expect(history.map((record) => record.id)).toEqual([first.id, fork.id])
        const registry = new FeedForkRegistry()
        for (const record of history) registry.observe(record)
        expect(registry.quarantined(signer.identity)).toBe(true)
        expect((await take(transport, 2)).map((record) => record.id)).toEqual([first.id, fork.id])
        // Conflicts do not advance the accepted feed or duplicate on repeated receipt.
        expect(await transport.feedContiguousThrough(signer.identity)).toBe(1n)
        expect(await store.count()).toBe(1)
        expect((await store.forksAfter(0n, 1)).map(({ record }) => record.receivedAtMs)).toEqual([20])
        expect(await store.forksAfter(1n, 1)).toEqual([])
        await transport.close()
        transport = undefined
        if (restart === 0) store = await openStore()
      }
    } finally { await transport?.close(); await rm(directory, { recursive: true, force: true }) }
  })
})

it('delivers newly detected forks and replays them to later subscribers without an in-memory fork queue', async () => {
  const bytes = new MemoryOperationStore(), store = await DurableFeedStore.open(bytes, webFeedCrypto)
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const signer = webFeedSigner(feedIdFromPublicKey(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))), keys.privateKey)
  const first = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(1))
  const fork = await createFeedRecord(signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(2))
  await store.append(first)
  const transport = new PortableFeedTransport({ store, signer, crypto: webFeedCrypto })
  const controller = new AbortController(), iterator = transport.subscribe(controller.signal)[Symbol.asyncIterator]()
  try {
    expect((await iterator.next()).value?.id).toBe(first.id)
    const conflict = iterator.next()
    transport.connect({ identity: signer.identity, head: async () => 2n, evidenceHead: async () => 0n, read: async () => [fork.raw],
      readEvidence: async () => [], readPayload: async () => null, async *watch() {} })
    await expect(transport.catchUp()).rejects.toThrow('FEED_RANGE_NO_PROGRESS')
    expect((await conflict).value?.id).toBe(fork.id)
    expect((await take(transport, 2)).map((record) => record.id)).toEqual([first.id, fork.id])
  } finally { controller.abort(); await iterator.return?.(); await transport.close() }
})

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { ChronologNode } from '@chronolog/node-core'
import { bytesToBase64Url, generateEd25519KeyPair } from '@chronolog/protocol'
import { feedIdFromPublicKey, PortableFeedTransport } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService, type SubmitTransactionRequest } from '@chronolog/rpc'
import { FeedStore, nativeFeedCrypto, type ChronologTransport } from '@chronolog/transport-ssb'
import { expect, it } from 'vitest'

import { SqliteOperationStore } from '../apps/chronologd/src/operation-store.js'

it('recovers the exact signed transaction after a lost RPC response and full replica restart', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-rpc-retry-'))
  const identity = await generateEd25519KeyPair()
  const groupId = new Uint8Array(32).fill(1)
  let writable = true
  let loseResponse = true
  const open = async () => {
    const state = new DatabaseSync(join(directory, 'operations.sqlite'))
    state.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL')
    const feed = new PortableFeedTransport({
      store: new FeedStore(join(directory, 'feed.sqlite')),
      crypto: nativeFeedCrypto,
      signer: { identity: feedIdFromPublicKey(identity.publicKeyBytes),
        sign: async (bytes) => new Uint8Array(await crypto.subtle.sign('Ed25519', identity.privateKey, Uint8Array.from(bytes))) },
    })
    const transport: ChronologTransport = {
      identity: feed.identity,
      async publish(bytes, options) {
        const record = await feed.publish(bytes, options)
        if (loseResponse) { loseResponse = false; throw new Error('lost durable append response') }
        return record
      },
      get: (id) => feed.get(id), history: () => feed.history(), status: () => feed.status(),
      getPayload: (hash) => feed.getPayload(hash),
      subscribe: (signal) => feed.subscribe(signal), close: () => feed.close(),
      feedContiguousThrough: (id) => feed.feedContiguousThrough(id),
    }
    const materializer = await DeterministicMaterializer.open({ path: join(directory, 'application.db'),
      executionManifest: createDoltLiteExecutionManifest(), rootAdministrator: identity.publicKeyBytes })
    const node = new ChronologNode({
      identity, groupId, membershipRevision: new Uint8Array(32).fill(2), validationPolicy: new Uint8Array(32).fill(3),
      operationStore: new SqliteOperationStore(state), transport,
      materialization: createDoltLiteMaterializationRuntime(materializer),
      membership: { canWrite: () => writable, canValidate: () => false, threshold: () => 1 },
      clock: { now: () => 1_234 },
    })
    await node.start()
    const rpc = new InProcessRpcTransport(new NodeRpcService({ node }))
    let closed = false
    return { node, feed, rpc, async close() {
      if (closed) return
      closed = true
      await rpc.close()
      await node.close()
      state.close()
    } }
  }
  let replica: Awaited<ReturnType<typeof open>> | undefined
  try {
    replica = await open()
    const request: SubmitTransactionRequest = { groupId: bytesToBase64Url(groupId), requestId: 'stable-request', steps: [{ sql: 'SELECT 1', bindings: [] }] }
    await expect(replica.rpc.unary('transaction.submit', request)).rejects.toThrow('lost durable append response')
    const saved = await replica.feed.history()
    expect(saved).toHaveLength(1)
    await replica.close()

    replica = await open()
    writable = false
    const recovered = await replica.rpc.unary('transaction.submit', request)
    expect(recovered.authorTimestampMs).toBe('1234')
    expect(recovered.publishedAt).toBe('1970-01-01T00:00:01.234Z')
    expect(await replica.feed.history()).toEqual(saved)
    // Recreating the facade and changing a connection address do not change the
    // authenticated principal's operation identity or require a live grant.
    const service = new NodeRpcService({ node: replica.node })
    expect(await service.submitTransaction(request, { method: 'transaction.submit', peer: 'new-connection' })).toEqual(recovered)
    await expect(service.submitTransaction({ ...request, steps: [{ sql: 'SELECT 2', bindings: [] }] }, { method: 'transaction.submit' }))
      .rejects.toMatchObject({ code: 'already_exists' })
    await expect(service.submitTransaction({ ...request, requestId: 'new-request' }, { method: 'transaction.submit' }))
      .rejects.toMatchObject({ code: 'failed_precondition' })
    expect(await replica.feed.history()).toEqual(saved)
  } finally {
    await replica?.close()
    await rm(directory, { recursive: true, force: true })
  }
})

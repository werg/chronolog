import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { ChronologNode } from '@chronolog/node-core'
import { equalBytes, generateEd25519KeyPair, program } from '@chronolog/protocol'
import { feedIdFromPublicKey, PortableFeedTransport } from '@chronolog/records'
import { FeedStore, nativeFeedCrypto } from '@chronolog/transport-ssb'
import { afterEach, expect, it } from 'vitest'

import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '../packages/control-store/src/index.js'
import { daemonHealth } from '../apps/chronologd/src/observability.js'
import { SqliteOperationStore } from '../apps/chronologd/src/operation-store.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-node-recovery-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const identity = await generateEd25519KeyPair()
  const capability = new Uint8Array(32).fill(4)
  let clock = 1_000
  let slowRecovery = false
  let failure: Error | undefined
  const open = async () => {
    const state = new NodeStateDatabase(join(directory, 'node-state.sqlite'))
    const feed = new PortableFeedTransport({
      store: new FeedStore(join(directory, 'feeds.sqlite')), crypto: nativeFeedCrypto,
      signer: { identity: feedIdFromPublicKey(identity.publicKeyBytes),
        sign: async (bytes) => new Uint8Array(await crypto.subtle.sign('Ed25519', identity.privateKey, Uint8Array.from(bytes))) },
    })
    const materializer = await DeterministicMaterializer.open({ path: join(directory, 'application.db'),
      executionManifest: createDoltLiteExecutionManifest(), rootAdministrator: identity.publicKeyBytes })
    const runtime = createDoltLiteMaterializationRuntime(materializer)
    let restoredWriters = 0
    const node = new ChronologNode({
      identity, groupId: new Uint8Array(32).fill(1), membershipRevision: new Uint8Array(32).fill(2),
      validationPolicy: new Uint8Array(32).fill(3), transport: feed,
      controlStore: new ControlStore(new SqliteControlStorePersistence(state)),
      operationStore: new SqliteOperationStore(state.database),
      materialization: { ...runtime, coordinator: { ...runtime.coordinator,
        materialize: async (ordered) => {
          if (failure !== undefined) throw failure
          return runtime.coordinator.materialize(ordered)
        },
      } },
      membership: {
        canWrite: () => true,
        canValidate: ({ validatorId, validatorCapability }) => equalBytes(validatorId, identity.publicKeyBytes) && equalBytes(validatorCapability, capability),
        canUseTransportAuthor: async ({ role, transportAuthor }) => {
          // Real async membership resolution may take longer than the SQL
          // debounce while a restored control index already knows later rows.
          if (slowRecovery && role === 'writer' && ++restoredWriters === 2) {
            await new Promise((resolve) => setTimeout(resolve, 70))
          }
          return transportAuthor === feed.identity
        },
        threshold: () => 1,
      },
      validator: { capabilityId: capability, cutoffLagMs: 1_000 },
      clock: { now: () => ++clock },
    })
    let closed = false
    const close = async () => {
      if (closed) return
      closed = true
      await node.close()
      state.close()
    }
    cleanup.push(close)
    await node.start()
    return { node, close }
  }
  return { open, slowRecovery: () => { slowRecovery = true }, fail: (value?: Error) => { failure = value } }
}

it('restores every admitted payload before scheduling SQL and returns healthy after a slow restart', async () => {
  const f = await fixture()
  const first = await f.open()
  for (const sql of ['CREATE TABLE notes(id INTEGER PRIMARY KEY) STRICT', 'INSERT INTO notes(id) VALUES(1)', 'INSERT INTO notes(id) VALUES(2)']) {
    const transaction = await first.node.publish({ program: program(sql) })
    await first.node.waitForIdle()
    expect(first.node.outcome(transaction.txId)?.outcome).toBe('accepted')
  }
  expect(first.node.orderLength).toBe(3)
  await first.close()
  f.slowRecovery()
  const reopened = await f.open()
  await reopened.node.waitForIdle()
  expect(reopened.node.localSql('SELECT id FROM notes ORDER BY id').rows)
    .toEqual([[{ kind: 'integer', value: '1' }], [{ kind: 'integer', value: '2' }]])
  expect(daemonHealth(await reopened.node.status())).toMatchObject({ ok: true, state: 'ready' })
  expect((await reopened.node.status()).lastError).toBeUndefined()
})

it('reports an active materialization failure and clears it only after successful SQL recovery', async () => {
  const f = await fixture()
  const replica = await f.open()
  f.fail(new Error('temporary materializer I/O failure'))
  const transaction = await replica.node.publish({ program: program('CREATE TABLE recovered(id INTEGER PRIMARY KEY)') })
  await expect.poll(async () => (await replica.node.status()).lastError).toBe('temporary materializer I/O failure')
  expect(daemonHealth(await replica.node.status()).ok).toBe(false)
  expect(replica.node.outcome(transaction.txId)).toBeNull()
  f.fail()
  await expect.poll(async () => (await replica.node.status()).materializationPending).toBe(false)
  expect(replica.node.outcome(transaction.txId)?.outcome).toBe('accepted')
  expect(daemonHealth(await replica.node.status())).toMatchObject({ ok: true, state: 'ready' })
  expect((await replica.node.status()).lastError).toBeUndefined()
})

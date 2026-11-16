import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativeAgentStore } from '@chronolog/agent-service'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { createGovernedNode } from '@chronolog/node-core'
import { executionManifestArtifacts, generateEd25519KeyPair } from '@chronolog/protocol'
import {
  DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner,
} from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { createDaemonAgentRuntime, waitForFinalAcceptance } from './agent-runtime.js'
import { loadOrCreateGovernanceBootstrap } from './governance-config.js'

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('native agent composition', () => {
  it('runs a SQL-free governed native authority and final-intent worker through the actual peer core', async () => {
    const dataDirectory = await mkdtemp(join(tmpdir(), 'chronolog-resident-agent-'))
    cleanup.push(() => rm(dataDirectory, { recursive: true, force: true }))
    const store = new NativeAgentStore(join(dataDirectory, 'agent.sqlite'))
    cleanup.push(() => store.close())
    const identity = await generateEd25519KeyPair(), groupId = new Uint8Array(32).fill(71)
    const { executionManifestDigest } = await executionManifestArtifacts(await eventExecutionManifest())
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    const bootstrap = await loadOrCreateGovernanceBootstrap({ dataDirectory, groupId, schemaId: executionManifestDigest,
      identity, transportAuthor: transport.identity, historyPolicy: 'coordinated' })
    const governed = await createGovernedNode({ genesis: bootstrap.genesis, groupRoute: new Uint8Array(32).fill(72), identity,
      transport, operationStore: store, materialization: await createEventMaterializationRuntime({ store, namespace: 'agent-events' }),
      recipient: { id: bootstrap.recipientId, privateKey: bootstrap.recipientPrivateKey }, initialEpochContentKey: new Uint8Array(32).fill(73) })
    cleanup.push(() => governed.close())
    await governed.start()
    let dispatches = 0
    const agent = await createDaemonAgentRuntime({ node: governed.node, identity, history: governed.descriptor.history, store, transport,
      activeMembership: () => governed.activeSnapshot,
      application: { createAgent: () => ({ effects: [{ resultTopic: 'jobs.results', handler: {
        id: 'echo', version: '1', topics: ['jobs.requested'], recovery: 'idempotent',
        dispatch: async ({ event }) => { dispatches += 1; return { echo: event.payload } },
      } }] }) } })
    cleanup.push(() => agent.close())
    const running = agent.run()
    void running.catch(() => undefined)
    expect(agent.taskIds).toEqual(['authority', 'effect:echo'])
    expect(agent.authority).not.toBeNull()
    const transaction = await governed.node.events.publish('jobs.requested', { input: 'hello' }, { operationId: 'request-1' })
    const deadline = new AbortController()
    const timeout = setTimeout(() => deadline.abort(), 5_000)
    try {
      await waitForFinalAcceptance(governed.node, transaction.txId, deadline.signal)
      let completed = false
      for await (const batch of governed.node.events.subscribe({ topics: ['jobs.results'], signal: deadline.signal })) {
        const event = batch.transactions[0]?.events[0]
        if (event !== undefined) {
          expect(event.payload).toMatchObject({ type: 'effect.completed', result: { echo: { input: 'hello' } } })
          completed = true
          break
        }
      }
      expect(completed).toBe(true)
      expect(dispatches).toBe(1)
      const duplicate = await governed.node.events.publish('jobs.requested', { input: 'hello' }, { operationId: 'request-1' })
      expect(duplicate.txId).toEqual(transaction.txId)
      await waitForFinalAcceptance(governed.node, duplicate.txId, deadline.signal)
      expect(dispatches).toBe(1)
      expect(() => governed.node.localSql('SELECT 1')).toThrow('SQL_DISABLED_FOR_EVENT_PROFILE')
    } finally { clearTimeout(timeout); deadline.abort() }
    const publication = new AbortController(), reason = new Error('resident task stopped')
    const waiting = agent.context.publisher.publishFinal('jobs.results', { cancelledWait: true },
      { operationId: 'cancel-publication-wait', signal: publication.signal })
    publication.abort(reason)
    await expect(waiting).rejects.toBe(reason)
    await agent.close()
    await running
  })
})

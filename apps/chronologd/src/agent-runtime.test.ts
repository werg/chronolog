import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativeAgentStore, framePeerStream, waitForAbortableDelay, type AgentApplicationContext } from '@chronolog/agent-service'
import { signGenesis } from '@chronolog/capabilities'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { createGovernedNode, decodeLedgerRecord, isFinalityClosureRecord, membershipDescriptor } from '@chronolog/node-core'
import { decodeEnvelope, executionManifestArtifacts, generateEd25519KeyPair } from '@chronolog/protocol'
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
    let clockNow = Date.now()
    const { executionManifestDigest } = await executionManifestArtifacts(await eventExecutionManifest())
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    const bootstrap = await loadOrCreateGovernanceBootstrap({ dataDirectory, groupId, schemaId: executionManifestDigest,
      identity, transportAuthor: transport.identity, historyPolicy: 'coordinated',
      clockPolicy: { cutoffLagMs: 1_000n, maxFutureSkewMs: 30_000n, heartbeatIntervalMs: 100n } })
    const governed = await createGovernedNode({ genesis: bootstrap.genesis, groupRoute: new Uint8Array(32).fill(72), identity,
      transport, operationStore: store, clock: { now: () => clockNow },
      materialization: await createEventMaterializationRuntime({ store, namespace: 'agent-events' }),
      recipient: { id: bootstrap.recipientId, privateKey: bootstrap.recipientPrivateKey }, initialEpochContentKey: new Uint8Array(32).fill(73) })
    cleanup.push(() => governed.close())
    await governed.start()
    const history = governed.descriptor.history
    if (history.kind !== 'coordinated') throw new Error('Expected signed-inclusion fixture')
    const customGenesis = await signGenesis({ ...bootstrap.genesis.manifest,
      historyPolicy: { ...bootstrap.genesis.manifest.historyPolicy!, providerId: 'example-finality-v1' },
    }, identity.privateKey)
    const custom = await createDaemonAgentRuntime({ node: governed.node, identity, store, transport,
      descriptor: await membershipDescriptor(customGenesis, governed.descriptor.groupRoute) })
    expect(custom.finality).toBeNull()
    expect(custom.taskIds).toEqual([])
    await custom.close()
    // Application setup can start a connection and fail before the returned
    // runtime is assigned to the daemon. The factory still owns that resource.
    const incoming = new TransformStream<Uint8Array, Uint8Array>(), outgoing = new TransformStream<Uint8Array, Uint8Array>()
    const framed = framePeerStream({ readable: incoming.readable, writable: outgoing.writable })
    let opening: ReturnType<AgentApplicationContext['connectPeer']> | undefined, connectionClosed = false
    const setupFailure = new Error('application setup failed')
    await expect(createDaemonAgentRuntime({ node: governed.node, identity, descriptor: governed.descriptor, store, transport,
      activeMembership: () => governed.activeSnapshot,
      peerLinks: { local: transport.asLink(), attach: link => transport.connect(link) },
      application: { createAgent(context) {
        opening = context.connectPeer({ connection: { ...framed,
          async close() { connectionClosed = true; await framed.close() } } })
        void opening.catch(() => undefined)
        throw setupFailure
      } },
    })).rejects.toBe(setupFailure)
    expect(connectionClosed).toBe(true)
    await expect(opening).rejects.toThrow()
    let dispatches = 0
    const agent = await createDaemonAgentRuntime({ node: governed.node, identity, descriptor: governed.descriptor, store, transport,
      activeMembership: () => governed.activeSnapshot, finalityClock: () => clockNow,
      application: { createAgent: () => ({ effects: [{ resultTopic: 'jobs.results', handler: {
        id: 'echo', version: '1', topics: ['jobs.requested'], recovery: 'idempotent',
        dispatch: async ({ event }) => { dispatches += 1; return { echo: event.payload } },
      } }] }) } })
    cleanup.push(() => agent.close())
    const running = agent.run()
    let serviceFailure: Error | undefined
    void running.catch(error => { serviceFailure = error instanceof Error ? error : new Error('AGENT_RUNTIME_FAILED', { cause: error }) })
    expect(agent.taskIds).toEqual(['finality', 'effect:echo'])
    expect(agent.finality).not.toBeNull()
    const transaction = await governed.node.events.publish('jobs.requested', { input: 'hello' }, { operationId: 'request-1' })
    const deadline = new AbortController()
    const timeout = setTimeout(() => deadline.abort(), 5_000)
    // This checks the real inclusion loop and worker, independently of the
    // machine's scheduling latency. Advance author/finality time only after
    // the exact published candidate body has its actual retained receipt.
    const closePublishedCandidate = async (count: number) => {
      for (;;) {
        deadline.signal.throwIfAborted()
        if (serviceFailure !== undefined) throw serviceFailure
        const candidates = (await transport.history()).filter(record => decodeEnvelope(record.payload).messageType === 'candidate')
        if (candidates.length >= count) {
          expect(candidates).toHaveLength(count)
          const hash = createHash('sha256').update(candidates[count - 1]!.payload).digest('hex')
          const receipts = await agent.finality!.read({ limit: 256 })
          expect(receipts.hasMore).toBe(false)
          if (receipts.entries.some(entry => !isFinalityClosureRecord(entry.bytes) && decodeLedgerRecord(entry.bytes).payloadHash === hash)) {
            clockNow += Number(bootstrap.genesis.manifest.clockPolicy.cutoffLagMs) + 1
            return
          }
        }
        await waitForAbortableDelay(5, deadline.signal)
      }
    }
    try {
      await closePublishedCandidate(1)
      await waitForFinalAcceptance(governed.node, transaction.txId, deadline.signal)
      await closePublishedCandidate(2)
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

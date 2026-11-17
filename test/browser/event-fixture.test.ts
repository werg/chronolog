import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createGovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { decodeSignedGenesis } from '@chronolog/capabilities'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { createGovernedNode, loadOrCreateEnrollmentIdentity, MemoryOperationStore } from '@chronolog/node-core'
import { base64UrlToBytes, bytesToBase64Url } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { waitForFinalAcceptance } from '../../apps/chronologd/src/agent-runtime.js'
import { createNativeBrowserFixture } from '../../tools/browser-event-fixture.js'
import { createAgent } from '../../examples/resident-agent.js'
import { connectGovernedBrowserPeer } from './event-connection.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('browser qualification native fixture', () => {
  it('runs the actual SQL task-summary module and publishes its correlated final result', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-pilot-native-worker-'))
    cleanup.push(() => rm(directory, { recursive: true, force: true }))
    const native = await createNativeBrowserFixture({ directory, browsers: [], manifest: createDoltLiteExecutionManifest(),
      application: { createAgent }, materialization: async ({ identity, executionManifest }) =>
        createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({
          path: join(directory, 'application.db'), executionManifest, rootAdministrator: identity.signing.publicKeyBytes,
        })) })
    cleanup.push(() => native.close())
    const setup = await native.client.transaction([
      'CREATE TABLE tasks(id TEXT PRIMARY KEY, title TEXT NOT NULL, claimed_by TEXT, status TEXT NOT NULL)',
      "INSERT INTO tasks(id,title,status) VALUES('task-1','Inspect evidence','open')",
    ], { operationId: 'native-pilot-schema' })
    try { expect((await setup.final({ signal: AbortSignal.timeout(5000) })).outcome.type).toBe('accepted') }
    finally { setup.dispose() }
    const request = await native.client.events.publish('job-requests', { type: 'job.requested', version: 1,
      kind: 'summarize-task', jobId: 'job-1', taskId: 'task-1' }, { operationId: 'native-pilot-job' })
    try { expect((await request.final({ signal: AbortSignal.timeout(5000) })).outcome.type).toBe('accepted') }
    finally { request.dispose() }
    let result
    for await (const batch of native.node.events.subscribe({ topics: ['job-results'], signal: AbortSignal.timeout(5000) })) {
      result = batch.transactions[0]?.events[0]
      if (result !== undefined) break
    }
    expect(result?.payload).toMatchObject({ type: 'effect.completed', originEventId: `${request.proposalId}:0`,
      result: { type: 'job.completed', version: 1, jobId: 'job-1', taskId: 'task-1', text: 'Inspect evidence — status: open.' } })
    native.assertHealthy()
  })

  it('runs real HTTP framed authenticated ranges bidirectionally against the durable native authority', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-http-framing-'))
    cleanup.push(() => rm(directory, { recursive: true, force: true }))
    const store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'replica')
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey) })
    const native = await createNativeBrowserFixture({ directory, browsers: [{ identity: bytesToBase64Url(identity.signing.publicKeyBytes),
      readerKey: bytesToBase64Url(identity.reader.publicKeyBytes), transportAuthor: transport.identity }], topics: ['chat'] })
    cleanup.push(() => native.close())
    const replica = await createGovernedNode({ genesis: decodeSignedGenesis(base64UrlToBytes(native.bootstrap.genesis)),
      groupRoute: base64UrlToBytes(native.bootstrap.groupRoute), identity: identity.signing, transport, operationStore: store,
      materialization: await createEventMaterializationRuntime({ store, namespace: 'replica-events' }),
      recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey },
      initialEpochContentKey: base64UrlToBytes(native.bootstrap.epochContentKey) })
    cleanup.push(() => replica.close())
    await replica.start()
    const peerService = await createGovernedPeerService({ identity: identity.signing, groupId: replica.descriptor.history.groupId,
      activeMembership: () => replica.activeSnapshot, local: transport.asLink(), attach: link => transport.connect(link) })
    cleanup.push(() => peerService.close())
    const session = await connectGovernedBrowserPeer({ bootstrap: native.bootstrap, peer: peerService })
    cleanup.push(() => session.close())
    await transport.catchUp()
    await replica.node.waitForIdle()
    const first = await replica.node.events.publish('chat', { text: 'replica' }, { operationId: 'replica-1' })
    await waitForFinalAcceptance(replica.node, first.txId, AbortSignal.timeout(10_000))
    const second = await native.node.events.publish('chat', { text: 'native' }, { operationId: 'native-1' })
    await waitForFinalAcceptance(native.node, second.txId, AbortSignal.timeout(10_000))
    await waitForFinalAcceptance(replica.node, second.txId, AbortSignal.timeout(10_000))
    const events = await replica.node.events.read()
    expect(events.transactions.map((transaction) => transaction.events[0]?.payload)).toEqual([{ text: 'replica' }, { text: 'native' }])
    expect((await native.node.events.read()).transactions).toEqual(events.transactions)
    expect(replica.node.finalThrough).toBe(native.node.finalThrough)
    expect((await transport.evidenceHistory()).length).toBeGreaterThan(0)
    expect((await native.transport.history()).some((record) => record.author === transport.identity)).toBe(true)
    native.assertHealthy()
  })
})

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { decodeSignedGenesis } from '@chronolog/capabilities'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { createGovernedNode, loadOrCreateEnrollmentIdentity, MemoryOperationStore } from '@chronolog/node-core'
import { base64UrlToBytes, bytesToBase64Url } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { waitForFinalAcceptance } from '../../apps/chronologd/src/agent-runtime.js'
import { createNativeBrowserFixture } from '../../tools/browser-event-fixture.js'
import { connectGovernedBrowserPeer } from './event-connection.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('browser qualification native fixture', () => {
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
    const session = await connectGovernedBrowserPeer({ bootstrap: native.bootstrap, identity, transport,
      activeMembership: () => replica.activeSnapshot })
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

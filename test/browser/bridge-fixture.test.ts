import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativeAgentStore } from '@chronolog/agent-service'
import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { createGovernedNode, encodeSignedEnrollmentRequest, loadOrCreateEnrollmentIdentity, prepareEnrollmentRequest } from '@chronolog/node-core'
import { LedgerRecordError } from '@chronolog/node-core/ledger'
import { bytesToBase64Url } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { createCertificateFetcher, TendrillerTransport } from '@chronolog/transport-tendriller'
import { createRecordLogClient } from '@tendriller/core/records'
import { afterEach, expect, it } from 'vitest'

import { createBrowserBridgeFixture } from '../../tools/browser-bridge-fixture.js'
import { connectGovernedBrowserPeer } from './event-connection.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

it('bootstraps the public retained-log bridge before fetching SQL bodies from its authenticated native peer', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-bridge-payloads-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const native = await createBrowserBridgeFixture({ rootDirectory: join(directory, 'native') })
  cleanup.push(() => native.close())
  const store = new NativeAgentStore(join(directory, 'joining.sqlite'))
  cleanup.push(() => store.close())
  const identity = await loadOrCreateEnrollmentIdentity(store, 'joining')
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey) })
  const headers = () => ({ Authorization: `Bearer ${native.bootstrap.token}` })
  if (native.descriptor.history.kind !== 'coordinated') throw new Error('COORDINATED_FIXTURE_REQUIRED')
  const relay = new TendrillerTransport({ local: transport, configuration: native.descriptor.history,
    groupRoute: native.descriptor.groupRoute, watch: false,
    records: createRecordLogClient({ base: native.bootstrap.hubUrl, headers }),
    certificate: createCertificateFetcher({ url: `${native.bootstrap.hubUrl}/_chronolog/certificate`, headers }) })
  const replica = await createGovernedNode({ genesis: native.descriptor.genesis, groupRoute: native.descriptor.groupRoute,
    identity: identity.signing, transport: relay, operationStore: store,
    recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey },
    materialization: createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({
      path: join(directory, 'joining-application.sqlite'), executionManifest: createDoltLiteExecutionManifest(),
      rootAdministrator: native.descriptor.genesis.manifest.schemaAdminPublicKey,
    })) })
  cleanup.push(() => replica.close())
  await relay.catchUp()
  await replica.start()
  const request = await prepareEnrollmentRequest({ descriptor: native.descriptor, store, requestId: 'bridge-join',
    identity: identity.signing, readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: transport.identity,
    requestedRoles: ['reader', 'writer'] })
  await native.approveEnrollment(bytesToBase64Url(encodeSignedEnrollmentRequest(request)), 'bridge-approve')
  await relay.catchUp()
  await expect(replica.node.waitForIdle()).rejects.toMatchObject({ cause: expect.objectContaining({ code: 'LEDGER_PAYLOAD_UNAVAILABLE' }) })
  expect(replica.governance.cipherRing.epochs().length).toBeGreaterThan(0)
  expect(replica.node.finalThrough).toBeLessThan((await native.snapshot()).finalThrough)
  // The public peer handshake proves the grant before any payload lookup.
  const peer = await connectGovernedBrowserPeer({ bootstrap: native.bootstrap, identity, transport,
    activeMembership: () => replica.activeSnapshot })
  cleanup.push(() => peer.close())
  await transport.catchUp()
  await expect.poll(async () => {
    try { await replica.node.waitForIdle(); return true }
    catch (error) {
      if (error instanceof Error && error.cause instanceof LedgerRecordError && error.cause.code === 'LEDGER_PAYLOAD_UNAVAILABLE') return false
      throw error
    }
  }).toBe(true)
  expect(replica.node.localSql('SELECT id, value FROM history', [], { view: 'final' }).rows)
    .toEqual([[{ kind: 'integer', value: '1' }, { kind: 'text', value: 'before-enrollment' }]])
  expect(replica.node.finalThrough).toBeGreaterThanOrEqual((await native.snapshot()).finalThrough)
}, 30_000)

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativeAgentStore } from '@chronolog/agent-service'
import { encodeSignedGenesis, isCapabilityActive } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { createEnrollmentService, createGovernedNode } from '@chronolog/node-core'
import { encodeOrderingEvidence } from '@chronolog/node-core/history'
import { LedgerRecordError } from '@chronolog/node-core/ledger'
import {
  MembershipAdministrator, createMembershipLedgerClient, encodeSignedEnrollmentApproval, loadOrCreateEnrollmentIdentity,
  prepareEnrollmentRequest, provisionMembership, verifyEnrollmentApproval,
} from '@chronolog/node-core/membership'
import { bytesToBase64Url, equalBytes } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import { afterEach, describe, expect, it } from 'vitest'

import { createThinMembershipNative } from '../tools/thin-membership-native.js'
import { connectGovernedBrowserPeer } from './browser/event-connection.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('thin membership qualification native boundary', () => {
  it('keeps large SQL payloads off the administrator and recovers a lost enrollment append through the real native handler', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-thin-membership-'))
    cleanup.push(() => rm(directory, { recursive: true, force: true }))
    const native = await createThinMembershipNative({ directory: join(directory, 'native') })
    cleanup.push(() => native.close())
    let store = new NativeAgentStore(join(directory, 'administrator.sqlite'))
    cleanup.push(() => store.close())
    const provision = () => provisionMembership({ store, executionManifestDigest: native.executionManifestDigest,
      schemaAdministratorPublicKey: native.identity.signing.publicKeyBytes,
      nativeAuthority: { historyId: native.historyId, publicKey: native.identity.signing.publicKeyBytes },
      initialCapabilities: native.initialCapabilities })
    let provisioned = await provision()
    const originalGenesis = bytesToBase64Url(encodeSignedGenesis(provisioned.descriptor.genesis))
    await native.start({ genesis: originalGenesis, groupRoute: bytesToBase64Url(provisioned.descriptor.groupRoute) })
    const open = () => MembershipAdministrator.open({ ...provisioned, store, ledger: createMembershipLedgerClient({
      url: native.membershipUrl, ...provisioned,
    }) })
    let administrator = await open()
    cleanup.push(() => administrator.close())
    expect([...administrator.snapshot.capabilities.values()].filter(capability =>
      equalBytes(capability.grant.signingPublicKey, provisioned.identity.publicKeyBytes)).map(capability => capability.grant.role)).toEqual(['administrator'])

    const small = await native.publishWorkload({ namespace: 'small', count: 4, payloadBytes: 16 })
    await administrator.sync()
    const large = await native.publishWorkload({ namespace: 'large', count: 4, payloadBytes: 196_608 })
    await administrator.sync()
    expect(small.count).toBe(4); expect(large.count).toBe(4)
    expect(large.detachedEnvelopeBytes).toBeGreaterThan(700_000)
    expect(large.detachedEnvelopeBytes).toBeGreaterThan(small.detachedEnvelopeBytes * 100)
    // A larger encoded length can add a few bytes to the canonical descriptor;
    // the application data itself must not travel with it.
    expect(Math.abs(large.descriptorBytes - small.descriptorBytes)).toBeLessThanOrEqual(16)
    const beforeJoin = native.traffic()
    expect(beforeJoin.candidateDescriptorBytes).toBeGreaterThan(0)
    expect(beforeJoin.inlineControlEnvelopeBytes).toBeGreaterThan(0)
    expect(beforeJoin.applicationEnvelopeBytesToAdministrator).toBe(0)
    expect(beforeJoin.unexpectedAdministratorRequests).toBe(0)
    expect(administrator.progress.verifiedThrough).toBe((await native.snapshot()).head.position)
    expect((await native.snapshot()).schemaRoles).toEqual({ nativeSchemaAdministrators: 1, membershipRootGroupMembers: 0 })

    const deviceStore = new NativeAgentStore(join(directory, 'device.sqlite'))
    cleanup.push(() => deviceStore.close())
    const device = await loadOrCreateEnrollmentIdentity(deviceStore, 'peer')
    const request = await prepareEnrollmentRequest({ descriptor: provisioned.descriptor, store: deviceStore,
      requestId: 'account:test-device:after-large-history', requestedRoles: ['reader', 'writer'],
      writerProgram: { sql: true, topics: ['qualification'], signals: [] }, identity: device.signing,
      readerPublicKey: device.reader.publicKeyBytes, transportAuthor: feedIdFromPublicKey(device.signing.publicKeyBytes) })
    const decision = { operationId: 'approve-after-large-history', roles: ['reader', 'writer'] as const,
      grantFullHistory: true, writerProgram: { sql: true, topics: ['qualification'], signals: [] } }
    native.loseNextAppendReply()
    await expect(administrator.approve(request, decision)).rejects.toThrow()
    await administrator.close(); store.close()
    store = new NativeAgentStore(join(directory, 'administrator.sqlite'))
    provisioned = await provision()
    expect(bytesToBase64Url(encodeSignedGenesis(provisioned.descriptor.genesis))).toBe(originalGenesis)
    administrator = await open()
    const approval = await administrator.approve(request, decision)
    await verifyEnrollmentApproval(provisioned.descriptor, request, approval)
    const original = bytesToBase64Url(encodeSignedEnrollmentApproval(approval))
    expect(bytesToBase64Url(encodeSignedEnrollmentApproval(await administrator.approve(request, decision)))).toBe(original)
    await expect(administrator.approve(request, { ...decision, roles: ['reader'] })).rejects.toThrow()
    await administrator.sync()
    const activeDevice = [...administrator.snapshot.capabilities.values()].filter(capability =>
      equalBytes(capability.grant.signingPublicKey, device.signing.publicKeyBytes) && isCapabilityActive(capability, administrator.snapshot.revision))
    expect(activeDevice.map(capability => capability.grant.role).sort()).toEqual(['reader', 'writer'])

    // Use a second actual full SQL replica to qualify the same late-join path
    // before the separate workerd/Chromium gate runs. Only certified small
    // history comes from the administrator; bodies use the authenticated link.
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(deviceStore, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(device.signing.publicKeyBytes), device.signing.privateKey) })
    const replica = await createGovernedNode({ genesis: provisioned.descriptor.genesis, groupRoute: provisioned.descriptor.groupRoute,
      identity: device.signing, transport, operationStore: deviceStore,
      recipient: { id: device.signing.publicKeyBytes, privateKey: device.reader.privateKey },
      materialization: createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({
        path: join(directory, 'device-application.sqlite'), executionManifest: createDoltLiteExecutionManifest(),
        rootAdministrator: provisioned.descriptor.genesis.manifest.schemaAdminPublicKey })) })
    cleanup.push(() => replica.close())
    await replica.start()
    let session: Awaited<ReturnType<typeof connectGovernedBrowserPeer>> | undefined
    cleanup.push(() => session?.close())
    const enrollment = createEnrollmentService({ descriptor: replica.descriptor, store: deviceStore, identity: device.signing,
      readerPublicKey: device.reader.publicKeyBytes, transportAuthor: transport.identity, governance: replica.governance,
      activeMembership: () => replica.activeSnapshot, connected: () => session !== undefined,
      executionManifestDigest: replica.node.executionManifestDigest, isFinalTargetApplied: target => replica.node.isFinalTargetApplied(target.frontier) })
    const client = new ChronologClient({ groupId: bytesToBase64Url(replica.descriptor.history.groupId),
      transport: new InProcessRpcTransport(new NodeRpcService({ node: replica.node, enrollment })), unaryRetryAttempts: 1 })
    cleanup.push(() => client.close())
    expect((await client.enrollment.getStatus(request.request.requestId, { signedApproval: original })).state).not.toBe('ready')
    const hydrateControls = async () => {
      await administrator.sync()
      let after = 0
      for (;;) {
        const page = administrator.read({ after, limit: 128 })
        for (const entry of page.entries) await transport.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
        await transport.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: page.certificate }))
        if (!page.hasMore) break
        after = page.entries.at(-1)!.position
      }
      try { await replica.node.waitForIdle() }
      catch (error) {
        if (!(error instanceof Error && error.cause instanceof LedgerRecordError && error.cause.code === 'LEDGER_PAYLOAD_UNAVAILABLE')) throw error
      }
    }
    await hydrateControls()
    expect([...replica.activeSnapshot.capabilities.values()].filter(capability =>
      equalBytes(capability.grant.signingPublicKey, device.signing.publicKeyBytes) && isCapabilityActive(capability, replica.activeSnapshot.revision))
      .map(capability => capability.grant.role).sort()).toEqual(['reader', 'writer'])
    expect(replica.governance.cipherRing.epochs().length).toBeGreaterThan(0)
    expect(replica.node.finalThrough).toBeLessThan(administrator.progress.verifiedThrough)
    expect((await client.enrollment.getStatus(request.request.requestId)).state).not.toBe('ready')
    const connect = async () => {
      session = await connectGovernedBrowserPeer({ bootstrap: native.bootstrap(), identity: device, transport,
        activeMembership: () => replica.activeSnapshot })
      await transport.catchUp(); await replica.node.waitForIdle()
    }
    await connect()
    await expect.poll(async () => (await client.enrollment.getStatus(request.request.requestId)).state, { timeout: 10_000 }).toBe('ready')
    expect((await client.events.read({ topics: ['qualification'] })).transactions).toHaveLength(8)

    const first = await client.events.publish('qualification', { text: 'before writer removal' }, { operationId: 'device-before-removal' })
    try { expect((await first.final({ signal: AbortSignal.timeout(10_000) })).outcome.type).toBe('accepted') }
    finally { first.dispose() }
    await session!.close(); session = undefined
    const writer = activeDevice.find(capability => capability.grant.role === 'writer')!
    await administrator.revoke({ operationId: 'remove-writer', capabilityIds: [writer.id] })
    const rejected = await client.events.publish('qualification', { text: 'after writer removal' }, { operationId: 'device-after-removal' })
    await connect()
    try { expect((await rejected.final({ signal: AbortSignal.timeout(10_000) })).outcome.type).toBe('rejected') }
    finally { rejected.dispose() }
    const retry = await client.events.publish('qualification', { text: 'before writer removal' }, { operationId: 'device-before-removal' })
    try { expect(retry.proposalId).toBe(first.proposalId); expect((await retry.final()).outcome.type).toBe('accepted') }
    finally { retry.dispose() }
    await session!.close(); session = undefined
    const reader = activeDevice.find(capability => capability.grant.role === 'reader')!
    const revoked = await administrator.revoke({ operationId: 'remove-reader', capabilityIds: [reader.id] })
    await hydrateControls()
    expect(replica.governance.knownEpochs).toContain(revoked.epoch)
    expect(replica.governance.cipherRing.epochs()).not.toContain(revoked.epoch)
    await native.publishWorkload({ namespace: 'future-epoch', count: 1, payloadBytes: 4096 })
    expect((await native.snapshot()).availableEpochs).toContain(String(revoked.epoch))
    expect(native.traffic().applicationEnvelopeBytesToAdministrator).toBe(0)
    expect(native.traffic().unexpectedAdministratorRequests).toBe(0)
    native.assertHealthy()
  }, 60_000)
})

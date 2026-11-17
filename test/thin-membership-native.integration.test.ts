import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativeAgentStore } from '@chronolog/agent-service'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
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
import { createHttpWebRtcSignaling, openWebRtcConnection } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'
import { afterEach, describe, expect, it, onTestFailed } from 'vitest'

import { createThinMembershipNative } from '../tools/thin-membership-native.js'
import { attachMembershipPeer } from './thin-membership/peer.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('thin membership qualification native boundary', () => {
  // Large-body replay, lost-reply recovery and two revocations take about 64 s
  // under V8 coverage; retain headroom for shared CI runners without shortcuts.
  it('keeps large SQL payloads off the administrator and recovers a lost enrollment append through the real native handler', async () => {
    const started = performance.now()
    let phase = 'create native fixture'
    const phases = [{ phase, elapsedMs: 0 }]
    let failureDiagnostic: () => unknown = () => undefined
    const observe = (name: string): void => {
      phase = name
      const elapsedMs = Math.round(performance.now() - started)
      phases.push({ phase, elapsedMs })
      if (process.env.CHRONOLOG_TEST_TRACE_PHASES === '1') process.stderr.write(`Thin native phase ${elapsedMs}ms: ${phase}\n`)
    }
    onTestFailed(() => {
      const elapsedMs = Math.round(performance.now() - started)
      process.stderr.write(`Thin native failed phase: ${JSON.stringify({ phase, elapsedMs,
        phaseElapsedMs: elapsedMs - phases.at(-1)!.elapsedMs, phases, native: failureDiagnostic() })}\n`)
    })
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-thin-membership-'))
    cleanup.push(() => rm(directory, { recursive: true, force: true }))
    const native = await createThinMembershipNative({ directory: join(directory, 'native') })
    failureDiagnostic = () => native.diagnostics()
    cleanup.push(() => native.close())
    let store = new NativeAgentStore(join(directory, 'administrator.sqlite'))
    cleanup.push(() => store.close())
    const provision = () => provisionMembership({ store, executionManifestDigest: native.executionManifestDigest,
      schemaAdministratorPublicKey: native.identity.signing.publicKeyBytes,
      nativeAuthority: { historyId: native.historyId, publicKey: native.identity.signing.publicKeyBytes },
      initialCapabilities: native.initialCapabilities })
    observe('provision and start native')
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

    observe('small native workload')
    const small = await native.publishWorkload({ namespace: 'small', count: 4, payloadBytes: 16 })
    await administrator.sync()
    observe('large native workload')
    const large = await native.publishWorkload({ namespace: 'large', count: 4, payloadBytes: 196_608 })
    observe('large native workload snapshot')
    const beforeJoinSnapshot = await native.snapshot()
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
    expect(administrator.progress.verifiedThrough).toBeGreaterThanOrEqual(beforeJoinSnapshot.head.position)
    expect(administrator.read({ after: beforeJoinSnapshot.head.position - 1, limit: 1 }).entries[0]?.root).toBe(beforeJoinSnapshot.head.root)
    expect(beforeJoinSnapshot.schemaRoles).toEqual({ nativeSchemaAdministrators: 1, membershipRootGroupMembers: 0 })

    const deviceStore = new NativeAgentStore(join(directory, 'device.sqlite'))
    cleanup.push(() => deviceStore.close())
    const device = await loadOrCreateEnrollmentIdentity(deviceStore, 'peer')
    const request = await prepareEnrollmentRequest({ descriptor: provisioned.descriptor, store: deviceStore,
      requestId: 'account:test-device:after-large-history', requestedRoles: ['reader', 'writer'],
      writerProgram: { sql: true, topics: ['qualification'], signals: [] }, identity: device.signing,
      readerPublicKey: device.reader.publicKeyBytes, transportAuthor: feedIdFromPublicKey(device.signing.publicKeyBytes) })
    const decision = { operationId: 'approve-after-large-history', roles: ['reader', 'writer'] as const,
      grantFullHistory: true, writerProgram: { sql: true, topics: ['qualification'], signals: [] } }
    observe('lost approval and administrator recovery')
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
    observe('open native replica')
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
    let session: Awaited<ReturnType<typeof attachMembershipPeer>> | undefined
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
      const label = phase
      await administrator.sync()
      let after = 0
      for (;;) {
        const page = administrator.read({ after, limit: 128 })
        for (const entry of page.entries) await transport.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
        await transport.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: page.certificate }))
        if (!page.hasMore) break
        after = page.entries.at(-1)!.position
      }
      observe(`${label}: local replay`)
      try { await replica.node.waitForIdle() }
      catch (error) {
        if (!(error instanceof Error && error.cause instanceof LedgerRecordError && error.cause.code === 'LEDGER_PAYLOAD_UNAVAILABLE')) throw error
      }
    }
    observe('initial certified control hydration')
    await hydrateControls()
    expect([...replica.activeSnapshot.capabilities.values()].filter(capability =>
      equalBytes(capability.grant.signingPublicKey, device.signing.publicKeyBytes) && isCapabilityActive(capability, replica.activeSnapshot.revision))
      .map(capability => capability.grant.role).sort()).toEqual(['reader', 'writer'])
    expect(replica.governance.cipherRing.epochs().length).toBeGreaterThan(0)
    expect(replica.node.finalThrough).toBeLessThan(administrator.progress.verifiedThrough)
    expect((await client.enrollment.getStatus(request.request.requestId)).state).not.toBe('ready')
    const connect = async () => {
      const label = phase
      const bootstrap = native.bootstrap()
      const signaling = createHttpWebRtcSignaling({ url: bootstrap.rtcUrl, headers: { Authorization: `Bearer ${bootstrap.rtcToken}` } })
      const connection = await openWebRtcConnection({ role: 'offerer', signaling, configuration: { iceServers: [] },
        createPeerConnection: configuration => createNativePeerConnection(configuration,
          { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false }) })
      observe(`${label}: authenticate peer`)
      session = await attachMembershipPeer({ connection, nativeIdentity: bootstrap.nativeIdentity, identity: device, transport,
        activeMembership: () => replica.activeSnapshot })
      observe(`${label}: retained feed catch-up`)
      await transport.catchUp()
      observe(`${label}: local replay`)
      await replica.node.waitForIdle()
      expect(signaling.stats).toMatchObject({ requests: 1, closed: true })
    }
    observe('first authenticated RTC connection and replay')
    await connect()
    await expect.poll(async () => (await client.enrollment.getStatus(request.request.requestId)).state, { timeout: 10_000 }).toBe('ready')
    expect((await client.events.read({ topics: ['qualification'] })).transactions).toHaveLength(8)

    observe('original accepted device operation')
    const first = await client.events.publish('qualification', { text: 'before writer removal' }, { operationId: 'device-before-removal' })
    try { expect((await first.final({ signal: AbortSignal.timeout(10_000) })).outcome.type).toBe('accepted') }
    finally { first.dispose() }
    await session!.close(); session = undefined
    const writer = activeDevice.find(capability => capability.grant.role === 'writer')!
    observe('writer revocation')
    await administrator.revoke({ operationId: 'remove-writer', capabilityIds: [writer.id] })
    const rejected = await client.events.publish('qualification', { text: 'after writer removal' }, { operationId: 'device-after-removal' })
    observe('RTC reconnect and rejected writer operation')
    await connect()
    try { expect((await rejected.final({ signal: AbortSignal.timeout(10_000) })).outcome.type).toBe('rejected') }
    finally { rejected.dispose() }
    observe('original accepted operation retry')
    const retry = await client.events.publish('qualification', { text: 'before writer removal' }, { operationId: 'device-before-removal' })
    try { expect(retry.proposalId).toBe(first.proposalId); expect((await retry.final()).outcome.type).toBe('accepted') }
    finally { retry.dispose() }
    await session!.close(); session = undefined
    const reader = activeDevice.find(capability => capability.grant.role === 'reader')!
    observe('reader revocation')
    const revoked = await administrator.revoke({ operationId: 'remove-reader', capabilityIds: [reader.id] })
    observe('revoked reader certified control hydration')
    await hydrateControls()
    expect(replica.governance.knownEpochs).toContain(revoked.epoch)
    expect(replica.governance.cipherRing.epochs()).not.toContain(revoked.epoch)
    observe('future epoch workload')
    await native.publishWorkload({ namespace: 'future-epoch', count: 1, payloadBytes: 4096 })
    observe('future epoch healthy snapshot')
    expect((await native.snapshot()).availableEpochs).toContain(String(revoked.epoch))
    expect(native.traffic().applicationEnvelopeBytesToAdministrator).toBe(0)
    expect(native.traffic().unexpectedAdministratorRequests).toBe(0)
    expect(native.traffic().rtcSignalingDescriptions).toBe(4)
    expect(native.traffic().rtcSdpBytes).toBeGreaterThan(0)
    expect(native.traffic().peerOutboundBytes).toBeGreaterThan(large.detachedEnvelopeBytes)
    native.assertHealthy()

    // A real denied peer must leave its originating native error observable
    // even though the success snapshot now refuses to return healthy evidence.
    observe('diagnostic revoked-reader RTC introduction')
    const bootstrap = native.bootstrap()
    const connection = await openWebRtcConnection({ role: 'offerer',
      signaling: createHttpWebRtcSignaling({ url: bootstrap.rtcUrl, headers: { Authorization: `Bearer ${bootstrap.rtcToken}` } }),
      configuration: { iceServers: [] }, createPeerConnection: configuration => createNativePeerConnection(configuration,
        { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false }) })
    cleanup.push(() => connection.close())
    observe('diagnostic revoked-reader authentication')
    const denied = await openAuthenticatedPeerLink({ connection, local: transport.asLink(),
      groupId: replica.descriptor.history.groupId, identity: device.signing, grantId: reader.id, authorizePeer: () => true })
      .then(async peer => {
        cleanup.push(() => peer.close())
        observe('diagnostic revoked-reader authenticated connection termination')
        await peer.completion
      }).catch((error: unknown) => error)
    observe('retained failure diagnostics')
    expect(denied).toBeInstanceOf(Error)
    await expect.poll(() => native.diagnostics().failure).toMatchObject({ source: 'peer', message: 'PEER_READ_UNAUTHORIZED' })
    await expect(native.snapshot()).rejects.toThrow('PEER_READ_UNAUTHORIZED')
    const diagnostic = native.diagnostics()
    expect(diagnostic.finalThrough).toBeGreaterThan(0)
    expect(diagnostic.availableEpochs).toContain(String(revoked.epoch))
    expect(diagnostic.traffic.rtcSignalingDescriptions).toBe(6)
    expect(diagnostic.traffic.peerOutboundBytes).toBeGreaterThan(large.detachedEnvelopeBytes)
    expect(diagnostic.failure).toEqual(native.diagnostics().failure)
    observe('complete')
  }, 120_000)
})

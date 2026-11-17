import { controlCommitmentForClosure, evaluateFinalitySnapshot } from './finality.js'
import type { CapabilityGrant } from '@chronolog/capabilities'
import { decodeSignedEpochManifest, unwrapEpochKey } from '@chronolog/crypto'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { assertCanonicalCbor, bytesToHex, decodeEnvelope, encodeCanonicalCbor, encodeEnvelope, generateEd25519KeyPair } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { encodeSignedEnrollmentApproval, loadOrCreateEnrollmentIdentity, prepareEnrollmentRequest, verifyEnrollmentApproval } from './enrollment.js'
import { createPrefixAuthority, ReferenceRecordLog, verifyPrefixCertificate } from './history-policy.js'
import { createFinalityClosureRecord, decodeFinalityClosureRecord, isFinalityClosureRecord } from './finality.js'
import { createLedgerRecord, decodeLedgerRecord } from './ledger-record.js'
import {
  MembershipAdministrator, provisionMembership, createMembershipLedgerClient, encodeMembershipLedgerResponse,
  signMembershipLedgerRequest, verifyMembershipLedgerRequest, type MembershipLedger,
} from './membership.js'
import { MemoryOperationStore } from './operations.js'
import { createGovernedNode } from './governed-node.js'

const open = new Set<MembershipAdministrator>()
afterEach(async () => { await Promise.all([...open].map(administrator => administrator.close())); open.clear() })

describe('portable thin membership administrator', () => {
  it('creates one durable root-only group and empty-reader epoch without a reader key or SQL engine', async () => {
    const fixture = await setup(false)
    expect([...fixture.administrator.snapshot.capabilities.values()].map(value => value.grant.role)).toEqual(['administrator'])
    expect(fixture.administrator.epochs).toEqual([0n])
    const entries = await fixture.log.read(), record = decodeLedgerRecord(entries[0]!.bytes)
    expect(record.kind).toBe('epoch-manifest')
    const epoch = epochFromEnvelope(record.inlinePayload!)
    expect(epoch.manifest.wraps).toEqual([])
    const again = await provisionMembership(fixture.provisionOptions)
    expect(again.descriptor).toEqual(fixture.provisioned.descriptor)
    expect(again.identity.publicKeyBytes).toEqual(fixture.provisioned.identity.publicKeyBytes)
    await expect(provisionMembership({ ...fixture.provisionOptions, executionManifestDigest: new Uint8Array(32).fill(11) }))
      .rejects.toThrow('MEMBERSHIP_CONFIGURATION_CONFLICT')
  })

  it('keeps certified grants inactive until author time is closed, then resumes the exact approval', async () => {
    const fixture = await setup(false), applicant = await joinRequest(fixture, 'await-closure')
    const closeAndRead = fixture.ledger.read.bind(fixture.ledger)
    fixture.ledger.read = async ({ after, limit = 128 }) => {
      const retained = await fixture.log.read()
      const snapshot = await evaluateFinalitySnapshot(fixture.configuration, retained)
      const checkpoint = retained.find(entry => entry.position === snapshot.closures.at(-1)!.position)!
      const authority = createPrefixAuthority({ configuration: fixture.configuration, identity: fixture.native.signing,
        readHead: async () => ({ historyId: checkpoint.historyId, position: checkpoint.position, root: checkpoint.root }) })
      const entries = snapshot.controls.slice(after, after + limit)
      return { entries, checkpoint, certificate: await authority.certify(), hasMore: after + entries.length < snapshot.controls.length }
    }

    const decision = { operationId: 'approve-after-closure', roles: ['reader'] as const, grantFullHistory: true }
    await expect(fixture.administrator.approve(applicant.request, decision)).rejects.toThrow('MEMBERSHIP_PREFIX_PENDING')
    expect(fixture.administrator.snapshot.revision).toBe(0n)
    const pendingHead = await fixture.log.head()
    fixture.ledger.read = closeAndRead
    const approval = await fixture.administrator.approve(applicant.request, decision)
    expect(fixture.administrator.snapshot.revision).toBe(1n)
    expect((await fixture.log.head()).position).toBe(pendingHead.position + 1)
    await verifyEnrollmentApproval(fixture.provisioned.descriptor, applicant.request, approval)
  })

  it('preserves the signed finality provider selection through provisioning and restart', async () => {
    const fixture = await setup(false)
    const options = { ...fixture.provisionOptions, store: new MemoryOperationStore(),
      providerId: 'alternate-finality-v1', providerParameters: new Uint8Array([7, 8]) }
    const provisioned = await provisionMembership(options)
    expect(provisioned.descriptor.history).toMatchObject({ providerId: options.providerId, providerParameters: options.providerParameters })
    expect(provisioned.descriptor.genesis.manifest.historyPolicy).toMatchObject({ providerId: options.providerId,
      providerParameters: options.providerParameters })
    expect((await provisionMembership(options)).descriptor).toEqual(provisioned.descriptor)
    await expect(provisionMembership({ ...options, providerParameters: new Uint8Array([7, 9]) }))
      .rejects.toThrow('MEMBERSHIP_CONFIGURATION_CONFLICT')
    // This native HTTP adapter must not silently substitute its built-in verifier.
    await expect(MembershipAdministrator.open({ ...provisioned, store: options.store, ledger: fixture.ledger }))
      .rejects.toThrow('FINALITY_PROVIDER_UNAVAILABLE')
  })

  it('keeps application descriptors off the administrator, then enrolls and delivers historical keys', async () => {
    const fixture = await setup()
    let applicationBytes = 0
    for (let i = 0; i < 140; i++) {
      const envelope = encodeEnvelope({ groupRoute: fixture.provisioned.descriptor.groupRoute, messageType: 'candidate',
        encryptionEpoch: new Uint8Array([0]), payload: new Uint8Array(50_000).fill(i) })
      applicationBytes += envelope.length
      const descriptor = await createLedgerRecord(envelope)
      expect(descriptor.recordBytes.length).toBeLessThan(300)
      await fixture.log.append(descriptor.recordBytes)
    }
    const before = fixture.traffic.bytes
    await fixture.administrator.sync()
    expect(fixture.administrator.progress.verifiedThrough).toBe(1)
    expect(fixture.administrator.progress.receiptThrough).toBe(142)
    expect(fixture.traffic.bytes - before).toBe(0)
    expect(fixture.traffic.bytes - before).toBeLessThan(applicationBytes / 100)
    const prefixThrough = fixture.administrator.progress.verifiedThrough
    const applicant = await joinRequest(fixture, 'browser')
    const approval = await fixture.administrator.approve(applicant.request, {
      operationId: 'approve-browser', roles: ['reader', 'writer'], grantFullHistory: true,
      writerProgram: { sql: true, topics: ['chat/message'], signals: ['typing'] },
    })
    await verifyEnrollmentApproval(fixture.provisioned.descriptor, applicant.request, approval)
    expect(fixture.administrator.snapshot.revision).toBe(1n)
    const frontier = assertCanonicalCbor(approval.approval.target.frontier)
    const closure = decodeFinalityClosureRecord((await fixture.log.read()).at(-1)!.bytes)
    expect(frontier).toEqual([4n, fixture.provisioned.descriptor.history.groupId, 'chronological', fixture.historyId,
      BigInt(closure.includedHead.position), closure.includedHead.root, closure.closedThroughMs])
    const page = fixture.administrator.read({ after: prefixThrough })
    await verifyPrefixCertificate(page.certificate, fixture.configuration)
    const deliveries = page.entries.map(control => decodeLedgerRecord(control.entry.bytes)).filter(record => record.kind === 'epoch-manifest')
    expect(deliveries).toHaveLength(1)
    const key = await unwrapEpochKey({ signedManifest: epochFromEnvelope(deliveries[0]!.inlinePayload!),
      trustedSigner: fixture.provisioned.identity.publicKeyBytes, recipientId: applicant.identity.signing.publicKeyBytes,
      recipientPrivateKey: applicant.identity.reader.privateKey })
    const nativeKey = await unwrapEpochKey({ signedManifest: epochFromEnvelope(decodeLedgerRecord((await fixture.log.read())[0]!.bytes).inlinePayload!),
      trustedSigner: fixture.provisioned.identity.publicKeyBytes, recipientId: fixture.native.signing.publicKeyBytes,
      recipientPrivateKey: fixture.native.reader.privateKey })
    expect(key).toEqual(nativeKey)
  })

  it('recovers a lost approval response and a revoke/rotate interruption with the original identities', async () => {
    const fixture = await setup(false), applicant = await joinRequest(fixture, 'only-reader')
    const decision = { operationId: 'approve-once', roles: ['reader'] as const, grantFullHistory: true }
    const approved = await fixture.administrator.approve(applicant.request, decision)
    const before = await fixture.log.head()
    await fixture.administrator.close(); open.delete(fixture.administrator)
    let administrator = await reopen(fixture)
    expect(encodeSignedEnrollmentApproval(await administrator.approve(applicant.request, decision)))
      .toEqual(encodeSignedEnrollmentApproval(approved))
    expect(await fixture.log.head()).toEqual(before)
    let loseReply = true
    const ledger: MembershipLedger = { ...fixture.ledger, append: async (bytes, options) => {
      const accepted = await fixture.ledger.append(bytes, options)
      if (loseReply && decodeLedgerRecord(bytes).kind === 'capability') { loseReply = false; throw new Error('lost revoke reply') }
      return accepted
    } }
    await administrator.close(); open.delete(administrator)
    administrator = await reopen(fixture, ledger)
    const revoke = { operationId: 'remove-reader', capabilityIds: approved.approval.capabilityIds }
    await expect(administrator.revoke(revoke)).rejects.toThrow('lost revoke reply')
    await administrator.close(); open.delete(administrator)
    administrator = await reopen(fixture)
    const result = await administrator.revoke(revoke), head = await fixture.log.head()
    expect(result.epoch).toBe(1n)
    expect(administrator.snapshot.capabilities.get(bytesToHex(approved.approval.capabilityIds[0]!))!.revokedAtRevision).toBe(2n)
    const lastEpoch = [...await fixture.log.read()].reverse().filter(entry => !isFinalityClosureRecord(entry.bytes)).map(entry => decodeLedgerRecord(entry.bytes)).find(record => record.kind === 'epoch-manifest')!
    expect(epochFromEnvelope(lastEpoch.inlinePayload!).manifest.wraps).toEqual([])
    expect(await administrator.revoke(revoke)).toEqual(result)
    expect(await fixture.log.head()).toEqual(head)
    await expect(administrator.revoke({ operationId: 'remove-reader', capabilityIds: [new Uint8Array(32)] })).rejects.toThrow('OPERATION_ID_CONFLICT')
  })

  it('pins a finite control target while concurrent participant changes keep extending the native head', async () => {
    const fixture = await setup(false)
    let value = 0, calls = 0
    const add = async () => fixture.log.append((await createLedgerRecord(encodeEnvelope({
      groupRoute: new Uint8Array(32).fill(99), messageType: 'capability', encryptionEpoch: null, payload: new Uint8Array([++value]),
    }))).recordBytes)
    await add(); await add(); await add()
    const read = fixture.ledger.read.bind(fixture.ledger)
    fixture.ledger.read = async options => {
      if (++calls > 1) await add()
      if (calls > 8) throw new Error('UNBOUNDED_MEMBERSHIP_SYNC')
      return read({ ...options, limit: 1 })
    }
    await fixture.administrator.sync()
    expect(calls).toBe(3)
    expect(fixture.administrator.progress.verifiedThrough).toBe(4)
    expect((await evaluateFinalitySnapshot(fixture.configuration, await fixture.log.read())).control.count).toBe(6)
    expect(fixture.administrator.snapshot.revision).toBe(0n)
  })

  it('bootstraps and reopens a full peer with reader keys but requires complete original history for application readiness', async () => {
    const profile = await createEventMaterializationRuntime({ store: new MemoryOperationStore(), namespace: 'profile' })
    const fixture = await setup(false, profile.queries.executionManifestDigest)
    await profile.close()
    const applicant = await joinRequest(fixture, 'compact-device')
    const approval = await fixture.administrator.approve(applicant.request, {
      operationId: 'compact-approve', roles: ['reader'], grantFullHistory: true,
    })
    const openPeer = async () => {
      const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(applicant.store, webFeedCrypto), crypto: webFeedCrypto,
        signer: webFeedSigner(feedIdFromPublicKey(applicant.identity.signing.publicKeyBytes), applicant.identity.signing.privateKey) })
      const governed = await createGovernedNode({ genesis: fixture.provisioned.descriptor.genesis,
        groupRoute: fixture.provisioned.descriptor.groupRoute, identity: applicant.identity.signing,
        recipient: { id: applicant.identity.signing.publicKeyBytes, privateKey: applicant.identity.reader.privateKey },
        operationStore: applicant.store, transport,
        materialization: await createEventMaterializationRuntime({ store: applicant.store, namespace: 'device' }) })
      await governed.start()
      return { governed, transport }
    }
    let peer = await openPeer()
    try {
      await peer.governed.ingestMembership(fixture.administrator.read({ after: 0 }))
      expect(peer.governed.activeSnapshot.revision).toBe(1n)
      expect(peer.governed.governance.cipherRing.epochs()).toEqual([0n])
      expect((await peer.transport.status()).records).toBe(0)
      expect(await peer.transport.evidenceHistory()).toEqual([])
      expect(peer.governed.node.finalThrough).toBe(0)
      expect(await peer.governed.node.isFinalTargetApplied(approval.approval.target.frontier)).toBe(false)
      await peer.governed.close()
      peer = await openPeer()
      expect(peer.governed.activeSnapshot.revision).toBe(1n)
      expect(peer.governed.governance.cipherRing.epochs()).toEqual([0n])
      expect(peer.governed.node.finalThrough).toBe(0)
      // The ordinary full-replica verifier still authenticates every receipt
      // and recomputes the control root before applying the captured target.
      for (const entry of await fixture.log.read()) await peer.governed.node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
      const authority = createPrefixAuthority({ configuration: fixture.configuration, identity: fixture.native.signing, readHead: () => fixture.log.head() })
      await peer.governed.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate: await authority.certify() })
      await peer.governed.node.waitForIdle()
      expect(await peer.governed.node.isFinalTargetApplied(approval.approval.target.frontier)).toBe(true)
    } finally { await peer.governed.close() }
  })

  it('does not activate governance from unverified gaps or forged prefix certificates', async () => {
    const fixture = await setup(), target = fixture.administrator.progress.verifiedThrough
    const original = fixture.ledger.read.bind(fixture.ledger)
    fixture.ledger.read = async options => {
      const page = await original(options)
      return { ...page, certificate: { ...page.certificate, signature: new Uint8Array(64) } }
    }
    await expect(fixture.administrator.sync()).rejects.toThrow('HISTORY_CERTIFICATE_SIGNATURE_INVALID')
    expect(fixture.administrator.progress.verifiedThrough).toBe(target)
    fixture.ledger.read = original
    const envelope = encodeEnvelope({ groupRoute: fixture.provisioned.descriptor.groupRoute, messageType: 'capability',
      encryptionEpoch: null, payload: new Uint8Array([1]) })
    await fixture.log.append((await createLedgerRecord(envelope)).recordBytes)
    fixture.ledger.read = async options => ({ ...await original(options), entries: [] })
    await expect(fixture.administrator.sync()).rejects.toThrow('CONTROL_PAGE_PROGRESS_INVALID')
    expect(fixture.administrator.progress.verifiedThrough).toBe(target)
  })

  it('projects only typed controls, retaining foreign controls without blocking valid governance', async () => {
    const fixture = await setup(false)
    const malformed = new Uint8Array([0xff])
    const foreign = await createLedgerRecord(encodeEnvelope({ groupRoute: new Uint8Array(32).fill(99),
      messageType: 'capability', encryptionEpoch: null, payload: new Uint8Array([1]) }))
    await fixture.log.append(malformed)
    await fixture.log.append(foreign.recordBytes)
    await fixture.administrator.sync()
    expect(fixture.administrator.progress.verifiedThrough).toBe(2)
    expect(fixture.administrator.snapshot.revision).toBe(0n)
    const applicant = await joinRequest(fixture, 'after-invalid-position')
    const approval = await fixture.administrator.approve(applicant.request, {
      operationId: 'approve-after-invalid', roles: ['reader'], grantFullHistory: true,
    })
    await verifyEnrollmentApproval(fixture.provisioned.descriptor, applicant.request, approval)
    expect(fixture.administrator.snapshot.revision).toBe(1n)
    const retained = fixture.administrator.read({ after: 1 })
    expect(retained.entries[0]!.entry.bytes).toEqual(foreign.recordBytes)
    expect(retained.entries.every(control => !control.entry.bytes.every((byte, index) => byte === malformed[index]))).toBe(true)
    await verifyPrefixCertificate(retained.certificate, fixture.configuration)
    await fixture.administrator.close(); open.delete(fixture.administrator)
    const restored = await reopen(fixture)
    expect(restored.progress).toEqual(fixture.administrator.progress)
    expect(restored.snapshot.revision).toBe(1n)
  })
})

describe('signed native membership ledger protocol', () => {
  it('pins root, genesis/profile/authority configuration, request contents and expiry', async () => {
    const fixture = await setup(), descriptor = fixture.provisioned.descriptor
    const request = { kind: 'read' as const, after: 0, limit: 128 }
    const signed = await signMembershipLedgerRequest({ descriptor, identity: fixture.provisioned.identity, request, now: 1_000 })
    expect(await verifyMembershipLedgerRequest(signed, descriptor, 1_000)).toEqual(request)
    await expect(verifyMembershipLedgerRequest(signed, descriptor, 61_001)).rejects.toThrow('MEMBERSHIP_REQUEST_INVALID')
    const other = structuredClone(descriptor)
    other.history.executionManifestDigest.fill(5)
    await expect(verifyMembershipLedgerRequest(signed, other, 1_000)).rejects.toThrow('MEMBERSHIP_REQUEST_INVALID')
    const value = assertCanonicalCbor(signed) as Uint8Array[]
    value[1] = new Uint8Array(64)
    await expect(verifyMembershipLedgerRequest(encodeCanonicalCbor(value), descriptor, 1_000)).rejects.toThrow('MEMBERSHIP_REQUEST_UNAUTHORIZED')
    await expect(signMembershipLedgerRequest({ descriptor, identity: await generateEd25519KeyPair(), request, now: 1_000 }))
      .rejects.toThrow('MEMBERSHIP_ROOT_KEY_REQUIRED')
    const candidate = await createLedgerRecord(encodeEnvelope({ groupRoute: descriptor.groupRoute,
      messageType: 'candidate', encryptionEpoch: null, payload: new Uint8Array([1]) }))
    await expect(signMembershipLedgerRequest({ descriptor, identity: fixture.provisioned.identity,
      request: { kind: 'append', recordBytes: candidate.recordBytes }, now: 1_000 })).rejects.toThrow('MEMBERSHIP_CONTROL_RECORD_REQUIRED')
  })

  it('uses the same portable HTTP codec for bounded native read and exact control retries', async () => {
    const fixture = await setup(), descriptor = fixture.provisioned.descriptor
    const fetcher: typeof fetch = async (_url, init) => {
      const request = await verifyMembershipLedgerRequest(new Uint8Array(init!.body as ArrayBuffer), descriptor, 1_000)
      const response = request.kind === 'read' ? await fixture.ledger.read(request) : await fixture.ledger.append(request.recordBytes)
      return new Response(encodeMembershipLedgerResponse(response).slice().buffer, { headers: { 'Content-Type': 'application/cbor' } })
    }
    const client = createMembershipLedgerClient({ url: 'http://127.0.0.1/_chronolog/membership', descriptor,
      identity: fixture.provisioned.identity, now: () => 1_000, fetch: fetcher })
    const page = await client.read({ after: 0, limit: 1 })
    expect(page.entries).toHaveLength(1)
    expect(await client.append(page.entries[0]!.entry.bytes)).toEqual(page.entries[0]!.entry)
    expect(await fixture.log.head()).toMatchObject({ position: 2 })
  })
})

async function setup(withNativeReader = true, executionManifestDigest: Uint8Array = new Uint8Array(32).fill(10)) {
  const store = new MemoryOperationStore(), native = await loadOrCreateEnrollmentIdentity(new MemoryOperationStore(), 'native')
  const historyId = 'h_' + crypto.randomUUID().replaceAll('-', '')
  const common = { subjectId: native.signing.publicKeyBytes, signingPublicKey: native.signing.publicKeyBytes,
    transportAuthor: feedIdFromPublicKey(native.signing.publicKeyBytes), validFromRevision: 0n }
  const initialCapabilities: CapabilityGrant[] = withNativeReader
    ? [{ ...common, role: 'reader', hpkePublicKey: native.reader.publicKeyBytes },
      { ...common, role: 'writer', program: { sql: true, topics: ['*'], signals: ['*'] } }] : []
  const provisionOptions = { store, executionManifestDigest,
    schemaAdministratorPublicKey: native.signing.publicKeyBytes,
    nativeAuthority: { historyId, publicKey: native.signing.publicKeyBytes }, initialCapabilities }
  const provisioned = await provisionMembership(provisionOptions)
  if (provisioned.descriptor.history.kind !== 'coordinated') throw new Error('wrong test policy')
  const configuration = provisioned.descriptor.history
  const log = await ReferenceRecordLog.open(historyId, new MemoryOperationStore())
  const authority = createPrefixAuthority({ configuration, identity: native.signing, readHead: () => log.head() })
  const traffic = { bytes: 0 }
  let closureClock = 100_000n
  const ledger: MembershipLedger = {
    append: bytes => log.append(bytes),
    read: async ({ after, limit }) => {
      const previous = await log.read()
      if (previous.length && !isFinalityClosureRecord(previous.at(-1)!.bytes)) {
        await log.append(await createFinalityClosureRecord({ configuration, identity: native.signing,
          includedHead: await log.head(), closedThroughMs: ++closureClock,
          control: await controlCommitmentForClosure(configuration, previous, closureClock) }))
      }
      const all = await log.read(), snapshot = await evaluateFinalitySnapshot(configuration, all)
      const entries = snapshot.controls.slice(after, after + limit)
      traffic.bytes += entries.reduce((sum, control) => sum + control.entry.bytes.length, 0)
      return { entries, checkpoint: all.at(-1) ?? null, certificate: await authority.certify(), hasMore: after + entries.length < snapshot.controls.length }
    },
  }
  const administrator = await MembershipAdministrator.open({ ...provisioned, store, ledger })
  open.add(administrator)
  return { store, native, historyId, provisionOptions, provisioned, configuration, log, ledger, administrator, traffic }
}

async function reopen(fixture: Awaited<ReturnType<typeof setup>>, ledger = fixture.ledger) {
  const administrator = await MembershipAdministrator.open({ ...fixture.provisioned, store: fixture.store, ledger })
  open.add(administrator)
  return administrator
}

async function joinRequest(fixture: Awaited<ReturnType<typeof setup>>, name: string) {
  const store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, name)
  const request = await prepareEnrollmentRequest({ descriptor: fixture.provisioned.descriptor, store, identity: identity.signing,
    readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: feedIdFromPublicKey(identity.signing.publicKeyBytes),
    requestId: 'join', requestedRoles: ['reader', 'writer'], writerProgram: { sql: true, topics: ['chat/message'], signals: ['typing'] } })
  return { store, identity, request }
}

function epochFromEnvelope(bytes: Uint8Array) {
  const envelope = decodeEnvelope(bytes), signed = assertCanonicalCbor(envelope.payload) as Uint8Array[]
  const tagged = assertCanonicalCbor(signed[1]!) as Uint8Array[]
  return decodeSignedEpochManifest(tagged[1]!)
}

import type { CapabilityGrant } from '@chronolog/capabilities'
import { decodeSignedEpochManifest, unwrapEpochKey } from '@chronolog/crypto'
import { assertCanonicalCbor, bytesToHex, decodeEnvelope, encodeCanonicalCbor, encodeEnvelope, generateEd25519KeyPair } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { encodeSignedEnrollmentApproval, loadOrCreateEnrollmentIdentity, prepareEnrollmentRequest, verifyEnrollmentApproval } from './enrollment.js'
import { createPrefixAuthority, ReferenceRecordLog, verifyPrefixCertificate } from './history-policy.js'
import { createLedgerRecord, decodeLedgerRecord } from './ledger-record.js'
import {
  MembershipAdministrator, provisionMembership, createMembershipLedgerClient, encodeMembershipLedgerResponse,
  signMembershipLedgerRequest, verifyMembershipLedgerRequest, type MembershipLedger,
} from './membership.js'
import { MemoryOperationStore } from './operations.js'

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

  it('verifies a large application prefix using descriptors only, then enrolls and delivers historical keys', async () => {
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
    expect(fixture.administrator.progress.verifiedThrough).toBe(141)
    expect(fixture.traffic.bytes - before).toBeLessThan(applicationBytes / 100)
    const applicant = await joinRequest(fixture, 'browser')
    const approval = await fixture.administrator.approve(applicant.request, {
      operationId: 'approve-browser', roles: ['reader', 'writer'], grantFullHistory: true,
      writerProgram: { sql: true, topics: ['chat/message'], signals: ['typing'] },
    })
    await verifyEnrollmentApproval(fixture.provisioned.descriptor, applicant.request, approval)
    expect(fixture.administrator.snapshot.revision).toBe(1n)
    const frontier = assertCanonicalCbor(approval.approval.target.frontier)
    expect(frontier).toEqual([3n, fixture.provisioned.descriptor.history.groupId, 'coordinated', fixture.historyId,
      BigInt(fixture.administrator.progress.verifiedThrough), fixture.administrator.progress.root])
    const page = fixture.administrator.read({ after: 141 })
    await verifyPrefixCertificate(page.certificate, fixture.configuration)
    const deliveries = page.entries.map(entry => decodeLedgerRecord(entry.bytes)).filter(record => record.kind === 'epoch-manifest')
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
    const lastEpoch = [...await fixture.log.read()].reverse().map(entry => decodeLedgerRecord(entry.bytes)).find(record => record.kind === 'epoch-manifest')!
    expect(epochFromEnvelope(lastEpoch.inlinePayload!).manifest.wraps).toEqual([])
    expect(await administrator.revoke(revoke)).toEqual(result)
    expect(await fixture.log.head()).toEqual(head)
    await expect(administrator.revoke({ operationId: 'remove-reader', capabilityIds: [new Uint8Array(32)] })).rejects.toThrow('OPERATION_ID_CONFLICT')
  })

  it('does not activate governance from unverified gaps or forged prefix certificates', async () => {
    const fixture = await setup(), target = (await fixture.log.head()).position
    const original = fixture.ledger.read.bind(fixture.ledger)
    fixture.ledger.read = async options => {
      const page = await original(options)
      return { ...page, certificate: { ...page.certificate, signature: new Uint8Array(64) } }
    }
    await expect(fixture.administrator.sync()).rejects.toThrow('HISTORY_CERTIFICATE_SIGNATURE_INVALID')
    expect(fixture.administrator.progress.verifiedThrough).toBe(target)
    fixture.ledger.read = original
    const envelope = encodeEnvelope({ groupRoute: fixture.provisioned.descriptor.groupRoute, messageType: 'candidate',
      encryptionEpoch: null, payload: new Uint8Array([1]) })
    await fixture.log.append((await createLedgerRecord(envelope)).recordBytes)
    fixture.ledger.read = async options => ({ ...await original(options), entries: [] })
    await expect(fixture.administrator.sync()).rejects.toThrow('MEMBERSHIP_RANGE_GAP')
    expect(fixture.administrator.progress.verifiedThrough).toBe(target)
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
    expect(await client.append(page.entries[0]!.bytes)).toEqual(page.entries[0])
    expect(await fixture.log.head()).toMatchObject({ position: 1 })
  })
})

async function setup(withNativeReader = true) {
  const store = new MemoryOperationStore(), native = await loadOrCreateEnrollmentIdentity(new MemoryOperationStore(), 'native')
  const historyId = 'h_' + crypto.randomUUID().replaceAll('-', '')
  const common = { subjectId: native.signing.publicKeyBytes, signingPublicKey: native.signing.publicKeyBytes,
    transportAuthor: feedIdFromPublicKey(native.signing.publicKeyBytes), validFromRevision: 0n }
  const initialCapabilities: CapabilityGrant[] = withNativeReader
    ? [{ ...common, role: 'reader', hpkePublicKey: native.reader.publicKeyBytes },
      { ...common, role: 'writer', program: { sql: true, topics: ['*'], signals: ['*'] } }] : []
  const provisionOptions = { store, executionManifestDigest: new Uint8Array(32).fill(10),
    schemaAdministratorPublicKey: native.signing.publicKeyBytes,
    nativeAuthority: { historyId, publicKey: native.signing.publicKeyBytes }, initialCapabilities }
  const provisioned = await provisionMembership(provisionOptions)
  if (provisioned.descriptor.history.kind !== 'coordinated') throw new Error('wrong test policy')
  const configuration = provisioned.descriptor.history
  const log = await ReferenceRecordLog.open(historyId, new MemoryOperationStore())
  const authority = createPrefixAuthority({ configuration, identity: native.signing, readHead: () => log.head() })
  const traffic = { bytes: 0 }
  const ledger: MembershipLedger = {
    append: bytes => log.append(bytes),
    read: async ({ after, limit }) => {
      const all = await log.read(), entries = all.slice(after, after + limit)
      traffic.bytes += entries.reduce((sum, entry) => sum + entry.bytes.length, 0)
      return { entries, certificate: await authority.certify(), hasMore: after + entries.length < all.length }
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

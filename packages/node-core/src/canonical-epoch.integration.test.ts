import { encodeGenesisManifest, signGenesis, type GenesisManifest } from '@chronolog/capabilities'
import { sha256 } from '@chronolog/canonical'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import {
  DOMAINS, assertCanonicalCbor, bytesToHex, decodeEnvelope, digestExecutionManifest, emit, encodeCanonicalCbor,
  encodeTransactionCore, generateEd25519KeyPair, hashDomain, program, transactionDigest, utf8,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner,
  type PublishOptions, type TransportRecord } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { loadOrCreateEnrollmentIdentity } from './enrollment.js'
import { createEpochEnvelopeCipher } from './cipher.js'
import { createGovernedNode } from './governed-node.js'
import { createPrefixAuthority, encodeOrderingEvidence, ReferenceRecordLog, type CoordinatedHistoryConfiguration } from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { createFinalityClosureRecord } from './finality.js'
import { MemoryOperationStore } from './operations.js'
import { ChronologNode } from './node.js'
import { encodeSignedEnvelope } from './wire.js'

class ControlledTransport extends PortableFeedTransport {
  blockCandidates = false
  loseNextCandidateReply = false
  lastPreparedEnvelope: Uint8Array | null = null
  constructor(options: ConstructorParameters<typeof PortableFeedTransport>[0], readonly log: ReferenceRecordLog,
    readonly detached = new Map<string, Uint8Array | null>()) { super(options) }
  override getPayload(hash: string): Promise<Uint8Array | null> {
    return this.detached.has(hash) ? Promise.resolve(this.detached.get(hash)?.slice() ?? null) : super.getPayload(hash)
  }
  override async publish(payload: Uint8Array, options?: PublishOptions): Promise<TransportRecord> {
    const candidate = decodeEnvelope(payload).messageType === 'candidate'
    if (candidate) {
      this.lastPreparedEnvelope = payload.slice()
      if (this.blockCandidates) throw new Error('candidate route unavailable')
    }
    const record = await super.publish(payload, options)
    await this.ensurePublished(record)
    if (candidate && this.loseNextCandidateReply) { this.loseNextCandidateReply = false; throw new Error('candidate reply lost') }
    return record
  }
  async ensurePublished(record: TransportRecord): Promise<void> {
    const entry = await this.log.append((await createLedgerRecord(record.payload)).recordBytes)
    await this.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
  }
}

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture(options: { readonly closeBootstrap?: boolean } = {}) {
  const store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'epoch-writer')
  const detached = new Map<string, Uint8Array | null>()
  const authorityIdentity = await generateEd25519KeyPair(), historyId = 'h_0123456789abcdef0123456789abcdef'
  const groupId = new Uint8Array(32).fill(51), groupRoute = new Uint8Array(32).fill(52)
  const executionManifestDigest = await digestExecutionManifest(await eventExecutionManifest())
  const transportAuthor = feedIdFromPublicKey(identity.signing.publicKeyBytes)
  const common = { subjectId: identity.signing.publicKeyBytes, signingPublicKey: identity.signing.publicKeyBytes, transportAuthor, validFromRevision: 0n }
  const manifest: GenesisManifest = {
    groupId, schemaId: executionManifestDigest, rootAdminPublicKey: identity.signing.publicKeyBytes,
    schemaAdminPublicKey: identity.signing.publicKeyBytes, capabilityLogFeed: utf8(transportAuthor),
    historyPolicy: { kind: 'coordinated', executionManifestDigest, historyId, authorityPublicKey: authorityIdentity.publicKeyBytes },
    initialCapabilities: [{ ...common, role: 'writer', program: { sql: false, topics: ['chat'], signals: [] } },
      { ...common, role: 'reader', hpkePublicKey: identity.reader.publicKeyBytes }],
    validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }
  const genesis = await signGenesis(manifest, identity.signing.privateKey)
  const configuration: CoordinatedHistoryConfiguration = { kind: 'coordinated', historyId, groupId, executionManifestDigest,
    authorityPublicKey: authorityIdentity.publicKeyBytes, genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(manifest)) }
  const log = await ReferenceRecordLog.open(historyId, new MemoryOperationStore())
  const authority = createPrefixAuthority({ configuration, identity: authorityIdentity, readHead: () => log.head() })
  let now = 1_000, bootstrapped = false
  const certify = async (peer: { readonly node: ChronologNode }) => {
    now += 100
    await log.append(await createFinalityClosureRecord({ configuration, identity: authorityIdentity,
      includedHead: await log.head(), closedThroughMs: BigInt(now) }))
    now += 1
    for (const entry of await log.read()) await peer.node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
    await peer.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate: await authority.certify() })
    await peer.node.waitForIdle()
  }
  const open = async () => {
    const transport = new ControlledTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(transportAuthor, identity.signing.privateKey) }, log, detached)
    const governed = await createGovernedNode({ genesis, groupRoute, identity: identity.signing, transport, operationStore: store,
      materialization: await createEventMaterializationRuntime({ store, namespace: 'canonical-epoch-events' }), clock: { now: () => now },
      recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey } })
    cleanup.push(() => governed.close())
    await governed.start()
    if (!bootstrapped && options.closeBootstrap !== false) { bootstrapped = true; await certify(governed) }
    return Object.assign(governed, { transport })
  }
  return { identity, groupRoute, log, open, certify, detached, now: () => now }
}

describe('chronological encryption epoch acceptance fence', () => {
  it('accepts a genesis-authorized event when epoch zero and the event share the first closure', async () => {
    const f = await fixture({ closeBootstrap: false }), peer = await f.open()
    const transaction = await peer.node.publish({ operationId: 'bootstrap-with-first-event', program: program(emit('chat', 'first')) })
    expect(peer.node.isFinal(transaction.txId)).toBe(false)
    await f.certify(peer)
    expect(peer.node.outcome(transaction.txId)?.outcome).toBe('accepted')
    expect(peer.node.isFinal(transaction.txId)).toBe(true)
    await peer.close()
    const reopened = await f.open()
    await f.certify(reopened)
    expect(reopened.node.outcome(transaction.txId)?.outcome).toBe('accepted')
    expect((await reopened.node.events.read()).transactions.map(item => item.proposalId)).toEqual([transaction.txIdText])
  })

  it.each(['epoch', 'length', 'envelope'] as const)('waits for authentic detached bytes, then skips a contradictory committed %s across restart', async (field) => {
    const f = await fixture(), peer = await f.open()
    const first = await peer.node.publish({ operationId: 'metadata-before', program: program(emit('chat', 'before')) })
    const core = { ...first.core, operationId: 'contradictory-metadata', nonce: new Uint8Array(32).fill(151),
      program: program(emit('chat', 'must not execute')) }
    const canonical = encodeTransactionCore(core), proposalId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    let envelope = await encodeSignedEnvelope(f.groupRoute, 'candidate', canonical, f.identity.signing, peer.governance.cipherRing)
    const prepared = await createLedgerRecord(envelope)
    let payloadHash = prepared.record.payloadHash
    const descriptor = assertCanonicalCbor(prepared.recordBytes)
    if (!Array.isArray(descriptor)) throw new Error('wrong test descriptor')
    if (field === 'epoch') descriptor[4] = encodeCanonicalCbor(999n)
    else if (field === 'length') descriptor[6] = BigInt(envelope.length + 1)
    else {
      envelope = new Uint8Array([0xff])
      payloadHash = bytesToHex(await sha256(envelope))
      descriptor[5] = payloadHash; descriptor[6] = BigInt(envelope.length)
    }
    await f.log.append(encodeCanonicalCbor(descriptor))
    f.detached.set(payloadHash, null)
    const following = await peer.node.publish({ operationId: 'metadata-after', program: program(emit('chat', 'after')) })
    await expect(f.certify(peer)).rejects.toThrow('LEDGER_PAYLOAD_UNAVAILABLE')
    expect(peer.node.isFinal(following.txId)).toBe(false)
    const corrupt = envelope.slice(); corrupt[corrupt.length - 1]! ^= 1
    f.detached.set(payloadHash, corrupt)
    await expect(f.certify(peer)).rejects.toThrow(field === 'length' ? 'LEDGER_PAYLOAD_LENGTH_INVALID' : 'LEDGER_PAYLOAD_DIGEST_MISMATCH')
    expect(peer.node.isFinal(following.txId)).toBe(false)
    f.detached.set(payloadHash, envelope)
    await f.certify(peer)
    expect(peer.node.outcome(proposalId)).toBeNull()
    expect(peer.node.outcome(following.txId)?.outcome).toBe('accepted')
    expect(peer.node.isFinal(following.txId)).toBe(true)
    expect((await peer.node.events.read()).transactions.map(transaction => transaction.proposalId)).toEqual([first.txIdText, following.txIdText])
    await peer.close()
    const reopened = await f.open()
    await f.certify(reopened)
    expect(reopened.node.outcome(proposalId)).toBeNull()
    expect((await reopened.node.events.read()).transactions.map(transaction => transaction.proposalId)).toEqual([first.txIdText, following.txIdText])
    expect((await reopened.node.status()).lastError).toBeUndefined()
  })

  it.each(['unknown', 'future'] as const)('rejects or skips the %s epoch that is not active at the signed author timestamp', async (kind) => {
    const f = await fixture(), peer = await f.open()
    const first = await peer.node.publish({ operationId: 'epoch-before', program: program(emit('chat', 'before')) })
    const core = { ...first.core, operationId: 'unissued-epoch', nonce: new Uint8Array(32).fill(161),
      program: program(emit('chat', 'must not execute')) }
    const canonical = encodeTransactionCore(core), proposalId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    const key = new Uint8Array(32).fill(162), epoch = kind === 'future' ? 1n : 999n
    const envelope = await encodeSignedEnvelope(f.groupRoute, 'candidate', canonical, f.identity.signing, createEpochEnvelopeCipher(key, epoch))
    await peer.node.ingest(await peer.transport.publish(envelope))
    const following = await peer.node.publish({ operationId: 'epoch-after', program: program(emit('chat', 'after')) })
    if (kind === 'future') await peer.governance.rotateEpoch(f.identity.signing.privateKey, key, { operationId: 'later-rotation' })
    await f.certify(peer)
    if (kind === 'unknown') expect(peer.node.outcome(proposalId)).toBeNull()
    else expect(peer.node.outcome(proposalId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ENCRYPTION_EPOCH_CLOSED' })
    expect(peer.node.outcome(following.txId)?.outcome).toBe('accepted')
    expect(peer.node.isFinal(following.txId)).toBe(true)
    expect((await peer.node.events.read()).transactions.map(transaction => transaction.proposalId)).toEqual([first.txIdText, following.txIdText])
    expect((await peer.node.status()).ingest?.retryRecords).toBe(0)
    await peer.close()
    const reopened = await f.open()
    await f.certify(reopened)
    if (kind === 'unknown') expect(reopened.node.outcome(proposalId)).toBeNull()
    else expect(reopened.node.outcome(proposalId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ENCRYPTION_EPOCH_CLOSED' })
    expect((await reopened.node.events.read()).transactions.map(transaction => transaction.proposalId)).toEqual([first.txIdText, following.txIdText])
    expect((await reopened.node.status()).lastError).toBeUndefined()
  })

  it('does not retroactively issue an excluded descriptor when an epoch appears in a later closure', async () => {
    const f = await fixture(), peer = await f.open()
    const first = await peer.node.publish({ operationId: 'before-late-epoch', program: program(emit('chat', 'before')) })
    const key = new Uint8Array(32).fill(191)
    const core = { ...first.core, operationId: 'epoch-not-in-inclusion-set', nonce: new Uint8Array(32).fill(192),
      program: program(emit('chat', 'must remain excluded')) }
    const canonical = encodeTransactionCore(core), proposalId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    await peer.transport.publish(await encodeSignedEnvelope(f.groupRoute, 'candidate', canonical, f.identity.signing,
      createEpochEnvelopeCipher(key, 1n)))
    await f.certify(peer)
    expect(peer.node.outcome(proposalId)).toBeNull()
    await peer.governance.rotateEpoch(f.identity.signing.privateKey, key, { operationId: 'issue-in-later-closure' })
    await f.certify(peer)
    expect(peer.node.outcome(proposalId)).toBeNull()
    await peer.close()
    const reopened = await f.open()
    await f.certify(reopened)
    expect(reopened.node.outcome(proposalId)).toBeNull()
    expect((await reopened.node.events.read()).transactions.map(item => item.proposalId)).toEqual([first.txIdText])
  })

  it('keeps an issued historical epoch blocked until its missing local key is delivered', async () => {
    const f = await fixture(), peer = await f.open()
    const transaction = await peer.node.publish({ operationId: 'issued-historical-epoch', program: program(emit('chat', 'must wait')) })
    await peer.governance.rotateEpoch(f.identity.signing.privateKey, undefined, { operationId: 'next-epoch' })
    peer.governance.cipherRing.remove(0n)
    await expect(f.certify(peer)).rejects.toThrow('WIRE_ENCRYPTION_EPOCH_UNAVAILABLE')
    expect(peer.node.isFinal(transaction.txId)).toBe(false)
    expect((await peer.node.events.read()).transactions).toHaveLength(0)
    await peer.governance.grantHistoricalAccess(f.identity.signing.publicKeyBytes, f.identity.signing.privateKey,
      { operationId: 'restore-issued-key' })
    await f.certify(peer)
    expect(peer.node.outcome(transaction.txId)?.outcome).toBe('accepted')
    expect(peer.node.isFinal(transaction.txId)).toBe(true)
    expect((await peer.node.events.read()).transactions.map(item => item.proposalId)).toEqual([transaction.txIdText])
  })

  it('rejects a foreign execution profile after time closes and continues across restart', async () => {
    const f = await fixture(), peer = await f.open()
    const first = await peer.node.publish({ operationId: 'profile-before', program: program(emit('chat', 'before')) })
    const foreignCore = { ...first.core, operationId: 'foreign-profile', nonce: new Uint8Array(32).fill(121),
      executionManifestDigest: new Uint8Array(32).fill(122), program: program(emit('chat', 'must not execute')) }
    const canonical = encodeTransactionCore(foreignCore)
    const proposalId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    const envelope = await encodeSignedEnvelope(f.groupRoute, 'candidate', canonical, f.identity.signing, peer.governance.cipherRing)
    const record = await peer.transport.publish(envelope)
    await peer.node.ingest(record)
    expect(peer.node.outcome(proposalId)).toBeNull()
    expect((await peer.node.status()).ingest?.retryRecords).toBe(0)
    const following = await peer.node.publish({ operationId: 'profile-after', program: program(emit('chat', 'after')) })
    await f.certify(peer)
    expect(peer.node.outcome(proposalId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'EXECUTION_PROFILE_MISMATCH' })
    expect(peer.node.isFinal(proposalId)).toBe(true)
    expect(peer.node.outcome(following.txId)?.outcome).toBe('accepted')
    expect((await peer.node.events.read()).transactions.map(transaction => transaction.proposalId)).toEqual([first.txIdText, following.txIdText])
    const head = await f.log.head()
    await peer.transport.ensurePublished(record)
    expect(await f.log.head()).toEqual(head)
    await peer.close()
    const reopened = await f.open()
    await f.certify(reopened)
    expect(reopened.node.outcome(proposalId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'EXECUTION_PROFILE_MISMATCH' })
    expect(reopened.node.isFinal(proposalId)).toBe(true)
    expect((await reopened.node.status()).lastError).toBeUndefined()
  })

  it('keeps an unavailable profile pending in the low-level unordered peer path', async () => {
    const store = new MemoryOperationStore(), identity = await generateEd25519KeyPair()
    const groupId = new Uint8Array(32).fill(131), membershipRevision = new Uint8Array(32).fill(132), validationPolicy = new Uint8Array(32).fill(133)
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    const node = new ChronologNode({ groupId, membershipRevision, validationPolicy, identity, transport,
      materialization: await createEventMaterializationRuntime({ store, namespace: 'unordered-profile' }),
      membership: { canWrite: () => true, canValidate: () => false, threshold: () => 1 } })
    cleanup.push(() => node.close())
    await node.start()
    const canonical = encodeTransactionCore({ operationId: 'unordered-foreign-profile', groupId, membershipRevision, validationPolicy,
      authorId: identity.publicKeyBytes, authorTimestampMs: 1n, nonce: new Uint8Array(32).fill(134),
      executionManifestDigest: new Uint8Array(32).fill(135), program: program(emit('chat', 'waiting')) })
    const proposalId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    await node.ingest(await transport.publish(await encodeSignedEnvelope(groupId, 'candidate', canonical, identity)))
    expect(await node.status()).toMatchObject({ lastError: 'CANDIDATE_EXECUTION_MANIFEST_UNAVAILABLE', ingest: { retryRecords: 1 } })
    expect(node.outcome(proposalId)).toBeNull()
    expect(node.isFinal(proposalId)).toBe(false)
  })

  it('preserves earlier ordered lost replies and rejects stale prepared bytes durably without reauthoring', async () => {
    const f = await fixture(), peer = await f.open()
    const acceptedInput = { operationId: 'ordered-before-rotation', program: program(emit('chat', { text: 'accepted once' })) }
    peer.transport.loseNextCandidateReply = true
    await expect(peer.node.publish(acceptedInput)).rejects.toThrow('candidate reply lost')
    const acceptedEnvelope = peer.transport.lastPreparedEnvelope!.slice()
    const acceptedOperation = (await peer.node.operation(acceptedInput.operationId))!
    expect(acceptedOperation.final).toBe(false)
    // Received keys advance before the next closure. Acceptance still uses
    // the epoch effective at the original signed author timestamp.
    await peer.governance.rotateEpoch(f.identity.signing.privateKey, undefined, { operationId: 'rotate-1' })
    await f.certify(peer)
    expect(await peer.node.operation(acceptedInput.operationId)).toMatchObject({ proposalId: acceptedOperation.proposalId,
      final: true, outcome: { outcome: 'accepted' } })
    const acceptedHead = await f.log.head()
    const acceptedRetry = await peer.node.publish(acceptedInput)
    expect(acceptedRetry.txIdText).toBe(acceptedOperation.proposalId)
    expect(await f.log.head()).toEqual(acceptedHead)
    expect(decodeEnvelope(acceptedEnvelope).encryptionEpoch).toEqual(encodeCanonicalCbor(0n))

    const staleInput = { operationId: 'prepared-before-rotation', program: program(emit('chat', { text: 'must reject' })) }
    peer.transport.blockCandidates = true
    await expect(peer.node.publish(staleInput)).rejects.toThrow('candidate route unavailable')
    const staleEnvelope = peer.transport.lastPreparedEnvelope!.slice()
    const staleOperation = (await peer.node.operation(staleInput.operationId))!
    expect(decodeEnvelope(staleEnvelope).encryptionEpoch).toEqual(encodeCanonicalCbor(1n))
    await peer.governance.rotateEpoch(f.identity.signing.privateKey, undefined, { operationId: 'rotate-2' })
    await f.certify(peer)
    peer.transport.blockCandidates = false
    const stale = await peer.node.publish(staleInput)
    expect(stale.txIdText).toBe(staleOperation.proposalId)
    expect(peer.transport.lastPreparedEnvelope).toEqual(staleEnvelope)
    await f.certify(peer)
    expect(await peer.node.operation(staleInput.operationId)).toMatchObject({ proposalId: staleOperation.proposalId, final: true,
      outcome: { outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' } })
    const rejectedHead = await f.log.head()
    expect((await peer.node.publish(staleInput)).txIdText).toBe(stale.txIdText)
    expect(await f.log.head()).toEqual(rejectedHead)
    expect((await peer.node.events.read()).transactions).toHaveLength(1)

    const fresh = await peer.node.publish({ operationId: 'explicit-fresh-operation', program: program(emit('chat', { text: 'new intent' })) })
    await f.certify(peer)
    expect(peer.node.outcome(fresh.txId)?.outcome).toBe('accepted')
    const unknownCore = { ...fresh.core, operationId: 'unknown-membership', membershipRevision: new Uint8Array(32).fill(254),
      authorTimestampMs: BigInt(f.now()), nonce: new Uint8Array(32).fill(99), program: program(emit('chat', { text: 'unknown revision' })) }
    const canonical = encodeTransactionCore(unknownCore)
    const unknownId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    await peer.transport.publish(await encodeSignedEnvelope(f.groupRoute, 'candidate', canonical, f.identity.signing, peer.governance.cipherRing))
    await f.certify(peer)
    expect(peer.node.outcome(unknownId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'WRITER_UNAUTHORIZED' })
    expect(peer.node.isFinal(unknownId)).toBe(true)
    expect((await peer.node.events.read()).transactions).toHaveLength(2)
    await peer.close()
    const reopened = await f.open()
    await f.certify(reopened)
    expect(await reopened.node.operation(staleInput.operationId)).toMatchObject({ proposalId: staleOperation.proposalId, final: true,
      outcome: { outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' } })
    expect(await reopened.node.operation(acceptedInput.operationId)).toMatchObject({ proposalId: acceptedOperation.proposalId,
      final: true, outcome: { outcome: 'accepted' } })
    expect((await reopened.node.events.read()).transactions.map(transaction => transaction.proposalId))
      .toEqual([acceptedOperation.proposalId, fresh.txIdText])
    expect((await reopened.node.status()).lastError).toBeUndefined()
  }, 30_000)
})

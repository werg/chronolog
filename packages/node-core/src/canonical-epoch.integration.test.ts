import { encodeGenesisManifest, signGenesis, type GenesisManifest } from '@chronolog/capabilities'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import {
  DOMAINS, bytesToHex, decodeEnvelope, digestExecutionManifest, emit, encodeCanonicalCbor,
  encodeTransactionCore, generateEd25519KeyPair, hashDomain, program, transactionDigest, utf8,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner,
  type PublishOptions, type TransportRecord } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { loadOrCreateEnrollmentIdentity } from './enrollment.js'
import { createGovernedNode } from './governed-node.js'
import { createPrefixAuthority, encodeOrderingEvidence, ReferenceRecordLog, type CoordinatedHistoryConfiguration } from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { MemoryOperationStore } from './operations.js'
import { ChronologNode } from './node.js'
import { encodeSignedEnvelope } from './wire.js'

class ControlledTransport extends PortableFeedTransport {
  blockCandidates = false
  loseNextCandidateReply = false
  lastPreparedEnvelope: Uint8Array | null = null
  constructor(options: ConstructorParameters<typeof PortableFeedTransport>[0], readonly log: ReferenceRecordLog) { super(options) }
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

async function fixture() {
  const store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'epoch-writer')
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
  const open = async () => {
    const transport = new ControlledTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(transportAuthor, identity.signing.privateKey) }, log)
    const governed = await createGovernedNode({ genesis, groupRoute, identity: identity.signing, transport, operationStore: store,
      materialization: await createEventMaterializationRuntime({ store, namespace: 'canonical-epoch-events' }),
      recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey } })
    cleanup.push(() => governed.close())
    await governed.start()
    return Object.assign(governed, { transport })
  }
  const certify = async (peer: Awaited<ReturnType<typeof open>>) => {
    for (const entry of await log.read()) await peer.node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
    await peer.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate: await authority.certify() })
    await peer.node.waitForIdle()
  }
  return { identity, groupRoute, log, open, certify }
}

describe('canonical encryption epoch acceptance fence', () => {
  it('rejects a foreign execution profile at its certified position and continues across restart', async () => {
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
    // Received keys advance before any certificate is delivered. Acceptance
    // still uses the epoch at each earlier immutable position.
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
      outcome: { outcome: 'rejected', rejectionCode: 'ENCRYPTION_EPOCH_CLOSED' } })
    const rejectedHead = await f.log.head()
    expect((await peer.node.publish(staleInput)).txIdText).toBe(stale.txIdText)
    expect(await f.log.head()).toEqual(rejectedHead)
    expect((await peer.node.events.read()).transactions).toHaveLength(1)

    const fresh = await peer.node.publish({ operationId: 'explicit-fresh-operation', program: program(emit('chat', { text: 'new intent' })) })
    await f.certify(peer)
    expect(peer.node.outcome(fresh.txId)?.outcome).toBe('accepted')
    const unknownCore = { ...fresh.core, operationId: 'unknown-membership', membershipRevision: new Uint8Array(32).fill(254),
      nonce: new Uint8Array(32).fill(99), program: program(emit('chat', { text: 'unknown revision' })) }
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
      outcome: { outcome: 'rejected', rejectionCode: 'ENCRYPTION_EPOCH_CLOSED' } })
    expect(await reopened.node.operation(acceptedInput.operationId)).toMatchObject({ proposalId: acceptedOperation.proposalId,
      final: true, outcome: { outcome: 'accepted' } })
    expect((await reopened.node.events.read()).transactions.map(transaction => transaction.proposalId))
      .toEqual([acceptedOperation.proposalId, fresh.txIdText])
    expect((await reopened.node.status()).lastError).toBeUndefined()
  }, 30_000)
})

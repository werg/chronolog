import { controlCommitmentForClosure } from './finality.js'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { encodeGenesisManifest, signGenesis } from '@chronolog/capabilities'
import type { CapabilityGrant, GenesisManifest } from '@chronolog/capabilities'
import {
  createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer,
} from '@chronolog/materializer-doltlite'
import {
  bytesToHex, decodeEnvelope, digestExecutionManifest, DOMAINS, encodeTransactionCore,
  generateEd25519KeyPair, hashDomain, program, transactionDigest, utf8,
} from '@chronolog/protocol'
import type { ChangeProgram, TransactionCore } from '@chronolog/protocol'
import {
  connectInProcess, DurableFeedStore, feedIdFromPublicKey, PortableFeedTransport, webFeedCrypto, webFeedSigner,
} from '@chronolog/records'
import type { PublishOptions, TransportRecord } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { enrollmentProgress, loadOrCreateEnrollmentIdentity, prepareEnrollmentRequest } from './enrollment.js'
import type { EnrollmentIdentity } from './enrollment.js'
import { createGovernedNode } from './governed-node.js'
import { createPrefixAuthority, encodeOrderingEvidence, ReferenceRecordLog } from './history-policy.js'
import type { CoordinatedHistoryConfiguration } from './history-policy.js'
import { MemoryOperationStore } from './operations.js'
import { createLedgerRecord } from './ledger-record.js'
import { createFinalityClosureRecord } from './finality.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes32 = (value: number) => new Uint8Array(32).fill(value)

/** Test connection: signatures/storage are real; certification is explicitly delayed. */
class ReferenceSubmissionTransport extends PortableFeedTransport {
  constructor(options: ConstructorParameters<typeof PortableFeedTransport>[0], readonly log: ReferenceRecordLog) { super(options) }

  override async publish(payload: Uint8Array, options?: PublishOptions): Promise<TransportRecord> {
    const record = await super.publish(payload, options)
    await this.ensurePublished(record)
    return record
  }

  async ensurePublished(record: TransportRecord): Promise<void> {
    const type = decodeEnvelope(record.payload).messageType
    if (type !== 'candidate' && type !== 'capability' && type !== 'epoch-manifest') return
    const entry = await this.log.append((await createLedgerRecord(record.payload)).recordBytes)
    await this.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
  }
}

describe('governed chronological native replicas with a finality provider', () => {
  it('activates membership at closed author-time boundaries, rejects backdating and never revives an old grant', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-governed-coordinated-'))
    cleanup.push(() => rm(directory, { recursive: true, force: true, maxRetries: 5 }))
    const administratorStore = new MemoryOperationStore(), joiningStore = new MemoryOperationStore()
    const administrator = await loadOrCreateEnrollmentIdentity(administratorStore, 'administrator')
    const joining = await loadOrCreateEnrollmentIdentity(joiningStore, 'joining')
    const authorityIdentity = await generateEd25519KeyPair()
    const executionManifest = createDoltLiteExecutionManifest()
    const executionManifestDigest = await digestExecutionManifest(executionManifest)
    const administratorFeed = feedIdFromPublicKey(administrator.signing.publicKeyBytes)
    const groupRoute = bytes32(20)
    const historyId = 'h_0123456789abcdef0123456789abcdef'
    const initialCapabilities: CapabilityGrant[] = [
      { subjectId: administrator.signing.publicKeyBytes, signingPublicKey: administrator.signing.publicKeyBytes,
        transportAuthor: administratorFeed, role: 'writer', program: { sql: true, topics: [], signals: [] }, validFromRevision: 0n },
      { subjectId: administrator.signing.publicKeyBytes, signingPublicKey: administrator.signing.publicKeyBytes,
        transportAuthor: administratorFeed, role: 'reader', hpkePublicKey: administrator.reader.publicKeyBytes, validFromRevision: 0n },
    ]
    const manifest: GenesisManifest = {
      groupId: bytes32(21), schemaId: executionManifestDigest, rootAdminPublicKey: administrator.signing.publicKeyBytes, schemaAdminPublicKey: administrator.signing.publicKeyBytes,
      capabilityLogFeed: utf8(administratorFeed), initialCapabilities,
      historyPolicy: { kind: 'coordinated', executionManifestDigest, historyId, authorityPublicKey: authorityIdentity.publicKeyBytes },
      validationPolicies: [{ version: 1n, minimumValidators: 1n }],
      clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
      resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
      encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
    }
    const genesis = await signGenesis(manifest, administrator.signing.privateKey)
    const configuration: CoordinatedHistoryConfiguration = {
      kind: 'coordinated', historyId, groupId: manifest.groupId, executionManifestDigest,
      genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(manifest)), authorityPublicKey: authorityIdentity.publicKeyBytes,
    }
    const log = await ReferenceRecordLog.open(historyId, new MemoryOperationStore())
    const authority = createPrefixAuthority({ configuration, identity: authorityIdentity, readHead: () => log.head() })
    let now = 1_000

    const open = async (name: string, identity: EnrollmentIdentity, store: MemoryOperationStore) => {
      const transport = new ReferenceSubmissionTransport({
        store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
        signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey),
      }, log)
      const materializer = await DeterministicMaterializer.open({ path: join(directory, `${name}.db`), executionManifest,
        rootAdministrator: administrator.signing.publicKeyBytes })
      const governed = await createGovernedNode({ genesis, groupRoute, identity: identity.signing, transport,
        operationStore: store, materialization: createDoltLiteMaterializationRuntime(materializer), clock: { now: () => now },
        recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey }, initialEpochContentKey: bytes32(22),
      })
      cleanup.push(() => governed.close())
      await governed.start()
      return Object.assign(governed, { transport })
    }
    const admin = await open('administrator', administrator, administratorStore)
    const peers = [admin]
    const certify = async () => {
      now += 100
      await log.append(await createFinalityClosureRecord({ configuration, identity: authorityIdentity,
        includedHead: await log.head(), closedThroughMs: BigInt(now),
      control: await controlCommitmentForClosure(configuration, await log.read(), BigInt(now)) }))
      now += 1
      const entries = await log.read(), certificate = await authority.certify()
      for (const peer of peers) {
        for (const entry of entries) await peer.node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
        await peer.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate })
        await peer.node.waitForIdle()
      }
    }
    await certify()
    const schema = await admin.node.publish({ operationId: 'schema', program: program(
      'CREATE TABLE notes (id INTEGER PRIMARY KEY, value INTEGER NOT NULL) STRICT',
      'INSERT INTO notes (id, value) VALUES (1, 10)',
    ) })
    await certify()
    expect(admin.node.outcome(schema.txId)?.outcome).toBe('accepted')
    const newcomer = await open('joining', joining, joiningStore)
    peers.push(newcomer)
    const disconnect = connectInProcess(admin.transport, newcomer.transport)
    cleanup.push(async () => { disconnect() })
    const request = await prepareEnrollmentRequest({ descriptor: admin.descriptor, store: joiningStore,
      identity: joining.signing, readerPublicKey: joining.reader.publicKeyBytes, transportAuthor: newcomer.transport.identity,
      requestId: 'live-writer', requestedRoles: ['reader', 'writer'], writerProgram: { sql: true, topics: [], signals: [] } })
    const approval = await admin.enrollmentIssuer!.approve(request, {
      operationId: 'approve-live-writer', roles: ['reader', 'writer'], grantFullHistory: true, writerProgram: { sql: true, topics: [], signals: [] },
    })
    await newcomer.transport.catchUp()
    for (const record of await newcomer.transport.history()) await newcomer.governance.ingest(record)
    expect(newcomer.governance.snapshot.revision).toBe(1n)
    expect(newcomer.activeSnapshot.revision).toBe(0n)
    const progress = () => enrollmentProgress({ descriptor: admin.descriptor, request, approval,
      activeMembership: newcomer.activeSnapshot, connected: true,
      availableEpochs: newcomer.governance.cipherRing.epochs(), executionManifestDigest,
      isFinalTargetApplied: (target) => newcomer.node.isFinalTargetApplied(target.frontier),
    })
    expect((await progress()).state).toBe('approved')
    await expect(newcomer.node.publish({ operationId: 'before-certified-grant', program: program('INSERT INTO notes VALUES (2, 20)') }))
      .rejects.toThrow('WRITER_UNAUTHORIZED')

    await certify()
    expect(newcomer.activeSnapshot.revision).toBe(1n)
    expect((await progress()).state).toBe('ready')
    const accepted = await newcomer.node.publish({ operationId: 'first-member-write',
      program: program('INSERT INTO notes (id, value) VALUES (2, 20)') })
    await certify()
    expect(newcomer.node.outcome(accepted.txId)?.outcome).toBe('accepted')
    const oldRevision = newcomer.node.membershipRevision
    const oldWriter = [...newcomer.activeSnapshot.capabilities.values()].find((capability) =>
      capability.grant.role === 'writer' && bytesToHex(capability.grant.signingPublicKey) === bytesToHex(joining.signing.publicKeyBytes))!
    const staleProposal = async (nonce: number, program: ChangeProgram, authorTimestampMs = BigInt(now)) => {
      const core: TransactionCore = {
        operationId: `stale-${nonce}`,
        groupId: manifest.groupId, membershipRevision: oldRevision, validationPolicy: newcomer.node.validationPolicy,
        authorId: joining.signing.publicKeyBytes, authorTimestampMs, nonce: bytes32(nonce),
        executionManifestDigest, writerCapability: oldWriter.id, program,
      }
      const canonical = encodeTransactionCore(core)
      const envelope = await encodeSignedEnvelope(groupRoute, 'candidate', canonical, joining.signing, newcomer.governance.cipherRing)
      return { envelope, txId: utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`) }
    }
    const delayed = await staleProposal(23, program('INSERT INTO notes (id, value) VALUES (3, 999)'), 0n)
    const priorRows = admin.node.localSql('SELECT id, value FROM notes ORDER BY id', [], { view: 'final' }).rows
    await admin.governance.revoke([oldWriter.id], administrator.signing.privateKey, { operationId: 'revoke-writer' })
    await newcomer.transport.catchUp()
    for (const record of await newcomer.transport.history()) await newcomer.governance.ingest(record)
    expect(newcomer.governance.snapshot.revision).toBe(2n)
    expect(newcomer.activeSnapshot.revision).toBe(1n)
    await certify()
    expect(newcomer.activeSnapshot.revision).toBe(2n)
    await newcomer.transport.publish(delayed.envelope)
    // Consume the unfinalized proposal before recording notification progress.
    // The closed-time rejection changes finality without changing SQL.
    for (const peer of peers) {
      await peer.transport.catchUp()
      for (const record of await peer.transport.history()) await peer.node.ingest(record)
      await peer.node.waitForIdle()
    }
    const beforeRejection = peers.map((peer) => ({ revision: peer.node.revision, sql: peer.node.materializedRevision, final: peer.node.finalOrderLength }))
    await certify()
    for (const [index, peer] of peers.entries()) {
      expect(peer.activeSnapshot.revision).toBe(2n)
      expect(peer.node.outcome(delayed.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' })
      expect(peer.node.isFinal(delayed.txId)).toBe(true)
      expect(peer.node.outcome(accepted.txId)?.outcome).toBe('accepted')
      expect(peer.node.localSql('SELECT id, value FROM notes ORDER BY id', [], { view: 'final' }).rows).toEqual(priorRows)
      expect(peer.node.materializedRevision).toBe(beforeRejection[index]!.sql)
      expect(peer.node.finalOrderLength).toBe(beforeRejection[index]!.final)
      expect(peer.node.revision).toBeGreaterThan(beforeRejection[index]!.revision)
    }
    expect((await progress()).state).toBe('revoked')

    await admin.governance.publishCapabilityChange({ grants: [{ subjectId: joining.signing.publicKeyBytes,
      signingPublicKey: joining.signing.publicKeyBytes, transportAuthor: newcomer.transport.identity, role: 'writer', program: { sql: true, topics: [], signals: [] } }] },
    administrator.signing.privateKey, { operationId: 'regrant-same-key' })
    await certify()
    const staleAgain = await staleProposal(24, program('INSERT INTO notes (id, value) VALUES (3, 999)'))
    await newcomer.transport.publish(staleAgain.envelope)
    const fresh = await newcomer.node.publish({ operationId: 'new-grant-write', program: program('INSERT INTO notes (id, value) VALUES (4, 40)') })
    await certify()
    for (const peer of peers) {
      expect(peer.activeSnapshot.revision).toBe(3n)
      expect(peer.node.outcome(delayed.txId)?.rejectionCode).toBe('FINALITY_TIMESTAMP_CLOSED')
      expect(peer.node.outcome(staleAgain.txId)?.rejectionCode).toBe('WRITER_UNAUTHORIZED')
      expect(peer.node.outcome(fresh.txId)?.outcome).toBe('accepted')
      expect(peer.node.localSql('SELECT id, value FROM notes ORDER BY id', [], { view: 'final' }).rows).toEqual([
        [{ kind: 'integer', value: '1' }, { kind: 'integer', value: '10' }],
        [{ kind: 'integer', value: '2' }, { kind: 'integer', value: '20' }],
        [{ kind: 'integer', value: '4' }, { kind: 'integer', value: '40' }],
      ])
    }
    disconnect()
    // Shared immutable storage is not a trusted certificate database. Foreign
    // evidence and a forged signature must not poison later node recovery.
    await newcomer.transport.putEvidence(utf8('unrelated immutable evidence'))
    await newcomer.transport.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: {
      ...await authority.certify(), signature: new Uint8Array(64),
    } }))
    await newcomer.close()
    // Rebuild membership and wrapped keys from small descriptors alone. Missing
    // SQL bodies cannot prevent the reader grant from becoming effective.
    const relayOnly = await open('relay-only', joining, new MemoryOperationStore())
    for (const entry of await log.read()) await relayOnly.node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
    const retainedCertificate = await authority.certify()
    await expect(relayOnly.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate: retainedCertificate }))
      .rejects.toThrow('LEDGER_PAYLOAD_UNAVAILABLE')
    expect(relayOnly.activeSnapshot.revision).toBe(3n)
    // Fetch application envelopes by hash without replicating any author feed.
    relayOnly.transport.connect({ ...admin.transport.asLink(), head: async () => 0n, read: async () => [] })
    await relayOnly.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate: retainedCertificate })
    expect(relayOnly.node.outcome(staleAgain.txId)?.rejectionCode).toBe('WRITER_UNAUTHORIZED')
    expect(relayOnly.node.localSql('SELECT id, value FROM notes ORDER BY id', [], { view: 'final' }).rows)
      .toEqual(admin.node.localSql('SELECT id, value FROM notes ORDER BY id', [], { view: 'final' }).rows)
    const reopened = await open('joining', joining, joiningStore)
    await reopened.node.waitForIdle()
    expect((await reopened.node.status()).lastError).toBeUndefined()
    expect(reopened.activeSnapshot.revision).toBe(3n)
    expect(reopened.node.outcome(delayed.txId)?.rejectionCode).toBe('FINALITY_TIMESTAMP_CLOSED')
    expect(reopened.node.outcome(staleAgain.txId)?.rejectionCode).toBe('WRITER_UNAUTHORIZED')
    expect(reopened.node.outcome(fresh.txId)?.outcome).toBe('accepted')
    expect(reopened.node.localSql('SELECT id, value FROM notes ORDER BY id', [], { view: 'final' }).rows)
      .toEqual(admin.node.localSql('SELECT id, value FROM notes ORDER BY id', [], { view: 'final' }).rows)
  }, 30_000)
})

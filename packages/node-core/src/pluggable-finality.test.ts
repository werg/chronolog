import { controlCommitmentForClosure } from './finality.js'
import { signGenesis, type GenesisManifest } from '@chronolog/capabilities'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import {
  bytesToHex, compareTransactionOrder, emit, encodeTransactionCore, equalBytes, generateEd25519KeyPair,
  program, transactionDigest, transactionOrderKey, utf8, type Ed25519KeyPair, type TransactionCore,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { createFinalityClosureRecord, type FinalityProvider, type FinalitySnapshot } from './finality.js'
import { createGovernedNode, type GovernedNodeOptions } from './governed-node.js'
import { createPrefixAuthority, ReferenceRecordLog, SignedInclusionFinalityProvider, type CoordinatedHistoryConfiguration } from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number) => new Uint8Array(32).fill(value)
const groupId = bytes(71), membershipRevision = bytes(72), validationPolicy = bytes(73)

async function replica(decorate?: (provider: SignedInclusionFinalityProvider) => FinalityProvider,
  options: { readonly futureAdmissionWindowMs?: number } = {}) {
  const identity = await generateEd25519KeyPair(), authorityIdentity = await generateEd25519KeyPair()
  const store = new MemoryOperationStore(), bodies = new Map<string, Uint8Array | null>()
  const initialRuntime = await createEventMaterializationRuntime({ store, namespace: 'finality-integration' })
  const configuration: CoordinatedHistoryConfiguration = {
    kind: 'coordinated', groupId, genesisDigest: bytes(74),
    executionManifestDigest: initialRuntime.queries.executionManifestDigest,
    historyId: 'h_0123456789abcdef0123456789abcdef', authorityPublicKey: authorityIdentity.publicKeyBytes,
  }
  await initialRuntime.close()
  const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
  const authority = createPrefixAuthority({ configuration, identity: authorityIdentity, readHead: () => log.head() })
  const open = async () => {
    const policy = await SignedInclusionFinalityProvider.open(configuration, store)
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    const originalGetPayload = transport.getPayload.bind(transport)
    transport.getPayload = async hash => bodies.has(hash) ? bodies.get(hash)?.slice() ?? null : originalGetPayload(hash)
    const node = new ChronologNode({ identity, groupId, membershipRevision, validationPolicy, operationStore: store, transport,
      historyPolicy: { kind: 'coordinated', policy: decorate?.(policy) ?? policy, ...options },
      membership: { canWrite: () => true, canValidate: () => false, threshold: () => 1 },
      materialization: await createEventMaterializationRuntime({ store, namespace: 'finality-integration' }),
    })
    cleanup.push(() => node.close())
    await node.start()
    return { node, transport, policy }
  }
  let current = await open()
  const include = async (proposal: Proposal, available = true) => {
    bodies.set(proposal.descriptor.record.payloadHash, available ? proposal.envelope.slice() : null)
    return log.append(proposal.descriptor.recordBytes)
  }
  const certify = async () => {
    for (const entry of await log.read()) await current.node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
    await current.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate: await authority.certify() })
    await current.node.waitForIdle()
  }
  const closeThrough = async (closedThroughMs: bigint) => {
    await log.append(await createFinalityClosureRecord({ configuration, identity: authorityIdentity,
      includedHead: await log.head(), closedThroughMs,
      control: await controlCommitmentForClosure(configuration, await log.read(), closedThroughMs) }))
    await certify()
  }
  return { configuration, identity, bodies, log, include, certify, closeThrough,
    get current() { return current },
    async restart() { await current.node.close(); current = await open(); await current.node.waitForIdle() },
  }
}

async function proposal(configuration: CoordinatedHistoryConfiguration, identity: Ed25519KeyPair,
  name: string, timestamp: bigint) {
  const core: TransactionCore = { groupId, membershipRevision, validationPolicy, authorId: identity.publicKeyBytes,
    authorTimestampMs: timestamp, operationId: name, nonce: bytes(75),
    executionManifestDigest: configuration.executionManifestDigest, program: program(emit('events', name)) }
  const canonical = encodeTransactionCore(core)
  const txId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
  const envelope = await encodeSignedEnvelope(groupId, 'candidate', canonical, identity)
  return { core, txId, envelope, descriptor: await createLedgerRecord(envelope) }
}
type Proposal = Awaited<ReturnType<typeof proposal>>
async function eventNames(node: ChronologNode) {
  return (await node.events.read()).transactions.flatMap(transaction => transaction.events.map(event => event.payload))
}

describe('pluggable inclusion finality with one chronological execution order', () => {
  it('produces the same final events for reversed receipt order, including timestamp ties', async () => {
    const left = await replica(), right = await replica()
    const secondAuthor = await generateEd25519KeyPair()
    const proposals = await Promise.all([
      proposal(left.configuration, left.identity, 'late', 30n),
      proposal(left.configuration, left.identity, 'same-author-b', 20n),
      proposal(left.configuration, secondAuthor, 'other-author', 20n),
      proposal(left.configuration, left.identity, 'same-author-a', 20n),
      proposal(left.configuration, left.identity, 'early', 10n),
    ])
    for (const value of proposals) await left.include(value)
    for (const value of [...proposals].reverse()) await right.include(value)
    await left.closeThrough(50n); await right.closeThrough(50n)
    const expected = [...proposals].sort((a, b) => compareTransactionOrder(
      transactionOrderKey(a.core, { authorFeedSequence: 0n, txId: a.txId }),
      transactionOrderKey(b.core, { authorFeedSequence: 0n, txId: b.txId }),
    )).map(value => value.core.operationId)
    expect(await eventNames(left.current.node)).toEqual(expected)
    expect(await eventNames(right.current.node)).toEqual(expected)
    expect(left.current.node.finalOrderLength).toBe(5)
    expect(right.current.node.finalOrderLength).toBe(5)
  })

  it('keeps certified inclusion pending until a closure covers author time', async () => {
    const f = await replica(), first = await proposal(f.configuration, f.identity, 'first', 10n)
    await f.include(first); await f.certify()
    expect(f.current.node.isFinal(first.txId)).toBe(false)
    expect(await eventNames(f.current.node)).toEqual([])
    await f.closeThrough(20n)
    expect(f.current.node.isFinal(first.txId)).toBe(true)
    expect(await eventNames(f.current.node)).toEqual(['first'])
  })

  it('rejects new backdated inclusion and preserves exact retries, cursors and final events', async () => {
    const f = await replica(), first = await proposal(f.configuration, f.identity, 'first', 10n)
    const originalReceipt = await f.include(first)
    await f.closeThrough(20n)
    const before = await f.current.node.events.read(), outcome = f.current.node.outcome(first.txId)
    const late = await proposal(f.configuration, f.identity, 'too-late', 15n)
    await f.include(late); await f.closeThrough(30n)
    expect(f.current.node.outcome(late.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' })
    expect(f.current.node.isFinal(late.txId)).toBe(true)
    expect(await f.include(first)).toEqual(originalReceipt)
    await f.certify()
    expect(f.current.node.outcome(first.txId)).toEqual(outcome)
    expect(await eventNames(f.current.node)).toEqual(['first'])
    expect((await f.current.node.events.read({ cursor: before.scannedThrough })).transactions).toEqual([])
    await f.restart()
    expect(f.current.node.outcome(first.txId)).toEqual(outcome)
    expect(f.current.node.outcome(late.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' })
    expect(await eventNames(f.current.node)).toEqual(['first'])
  })

  it('leaves future-dated inclusion pending until a later idle closure', async () => {
    const f = await replica(), future = await proposal(f.configuration, f.identity, 'future', 100n)
    await f.include(future); await f.closeThrough(50n)
    expect(f.current.node.candidate(future.txId)?.state).toBe('pending_validation')
    expect(f.current.node.isFinal(future.txId)).toBe(false)
    expect(f.current.node.outcome(future.txId)).toBeNull()
    await f.closeThrough(100n)
    expect(f.current.node.isFinal(future.txId)).toBe(true)
    expect(await eventNames(f.current.node)).toEqual(['future'])
  })

  it('finally rejects author time beyond the first closure window without blocking later valid work', async () => {
    const f = await replica(undefined, { futureAdmissionWindowMs: 20 })
    const tooFuture = await proposal(f.configuration, f.identity, 'years-ahead', 31_536_000_000n)
    await f.include(tooFuture); await f.closeThrough(50n)
    expect(f.current.node.outcome(tooFuture.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_FUTURE' })
    expect(f.current.node.isFinal(tooFuture.txId)).toBe(true)
    expect(await eventNames(f.current.node)).toEqual([])

    const valid = await proposal(f.configuration, f.identity, 'valid-after-rejection', 60n)
    await f.include(valid); await f.closeThrough(70n)
    expect(f.current.node.isFinal(valid.txId)).toBe(true)
    expect(await eventNames(f.current.node)).toEqual(['valid-after-rejection'])
    await f.restart()
    expect(f.current.node.isFinal(tooFuture.txId)).toBe(true)
    expect(f.current.node.outcome(tooFuture.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_FUTURE' })
    expect(await eventNames(f.current.node)).toEqual(['valid-after-rejection'])
  })

  it('admits the exact future-window boundary and keeps it pending until author time closes', async () => {
    const f = await replica(undefined, { futureAdmissionWindowMs: 20 })
    const boundary = await proposal(f.configuration, f.identity, 'future-boundary', 70n)
    const beyond = await proposal(f.configuration, f.identity, 'one-millisecond-beyond', 71n)
    await f.include(boundary); await f.include(beyond); await f.closeThrough(50n)
    expect(f.current.node.isFinal(boundary.txId)).toBe(false)
    expect(f.current.node.outcome(boundary.txId)).toBeNull()
    expect(f.current.node.isFinal(beyond.txId)).toBe(true)
    expect(f.current.node.outcome(beyond.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_FUTURE' })
    await f.closeThrough(70n)
    expect(f.current.node.isFinal(boundary.txId)).toBe(true)
    expect(await eventNames(f.current.node)).toEqual(['future-boundary'])
  })

  it('blocks application finality on a missing body and recovers its exact included proposal', async () => {
    const f = await replica(), first = await proposal(f.configuration, f.identity, 'missing', 10n)
    await f.include(first, false)
    await expect(f.closeThrough(20n)).rejects.toThrow('LEDGER_PAYLOAD_UNAVAILABLE')
    expect(f.current.node.isFinal(first.txId)).toBe(false)
    expect(f.current.node.finalOrderLength).toBe(0)
    f.bodies.set(first.descriptor.record.payloadHash, first.envelope)
    await f.certify()
    expect(f.current.node.isFinal(first.txId)).toBe(true)
    expect(await eventNames(f.current.node)).toEqual(['missing'])
  })

  it('lets an alternative proof gate change finality without providing an execution sorter', async () => {
    const releaseProof = utf8('external-checkpoint-approved')
    const f = await replica(base => {
      const empty = base.snapshot()
      let released = false
      return {
        configuration: base.configuration,
        snapshot: () => released ? base.snapshot() : structuredClone(empty),
        evidenceBytes: () => base.evidenceBytes(),
        async ingestEvidence(evidence) {
          if (equalBytes(evidence, releaseProof)) released = true
          else await base.ingestEvidence(evidence)
        },
      }
    })
    const later = await proposal(f.configuration, f.identity, 'later', 20n)
    const earlier = await proposal(f.configuration, f.identity, 'earlier', 10n)
    await f.include(later); await f.include(earlier); await f.closeThrough(30n)
    expect(f.current.node.finalOrderLength).toBe(0)
    await f.current.node.ingestFinalityEvidence(releaseProof)
    expect(await eventNames(f.current.node)).toEqual(['earlier', 'later'])
  })
})

describe('signed provider selection', () => {
  async function configured() {
    const store = new MemoryOperationStore(), identity = await generateEd25519KeyPair()
    const runtime = await createEventMaterializationRuntime({ store, namespace: 'custom-provider' })
    const transportAuthor = feedIdFromPublicKey(identity.publicKeyBytes)
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(transportAuthor, identity.privateKey) })
    const manifest: GenesisManifest = {
      groupId, schemaId: runtime.queries.executionManifestDigest, rootAdminPublicKey: identity.publicKeyBytes,
      schemaAdminPublicKey: identity.publicKeyBytes, capabilityLogFeed: utf8(transportAuthor),
      historyPolicy: { kind: 'coordinated', executionManifestDigest: runtime.queries.executionManifestDigest,
        historyId: 'h_0123456789abcdef0123456789abcdef', authorityPublicKey: identity.publicKeyBytes,
        providerId: 'custom-inclusion-v1', providerParameters: Uint8Array.of(9, 8, 7) },
      initialCapabilities: [{ role: 'administrator', subjectId: identity.publicKeyBytes, signingPublicKey: identity.publicKeyBytes,
        transportAuthor, validFromRevision: 0n }],
      validationPolicies: [{ version: 1n, minimumValidators: 1n }],
      clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 100n, heartbeatIntervalMs: 100n },
      resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 1_000n, maxPreconditions: 100n, maxMutations: 100n },
      encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
    }
    const genesis = await signGenesis(manifest, identity.privateKey)
    cleanup.push(async () => { await transport.close(); await runtime.close() })
    return { genesis, groupRoute: groupId, identity, transport, operationStore: store, materialization: runtime }
  }

  it('selects an injected verifier by the signed provider ID and passes opaque proof bytes', async () => {
    const options = await configured(), seen: Uint8Array[] = []
    let selected: CoordinatedHistoryConfiguration | undefined
    const factory: NonNullable<GovernedNodeOptions['finalityProviders']>[string] = async configuration => {
      selected = structuredClone(configuration)
      const snapshot: FinalitySnapshot = { checkpointId: 'custom-proof-state', receivedThrough: 0, includedThrough: 0,
        closedReceiptThrough: 0, closedThroughMs: -1n, records: [], closures: [] }
      const provider: FinalityProvider = {
        configuration, snapshot: () => structuredClone(snapshot), evidenceBytes: () => [],
        async ingestEvidence(proof) { seen.push(proof.slice()) },
      }
      return provider
    }
    const governed = await createGovernedNode({ ...options, finalityProviders: { 'custom-inclusion-v1': factory } })
    cleanup.push(() => governed.close())
    await governed.start()
    const proof = utf8('an alternative provider proof, deliberately not a built-in CBOR certificate')
    await governed.node.ingestFinalityEvidence(proof)
    expect(seen.some(bytes => bytesToHex(bytes) === bytesToHex(proof))).toBe(true)
    expect(selected).toMatchObject({ providerId: 'custom-inclusion-v1', providerParameters: Uint8Array.of(9, 8, 7) })
  })

  it('refuses an unavailable or mismatched provider rather than falling back to different finality', async () => {
    const options = await configured()
    await expect(createGovernedNode(options)).rejects.toThrow('FINALITY_PROVIDER_UNAVAILABLE')
    await expect(createGovernedNode({ ...options, finalityProviders: {
      'custom-inclusion-v1': async configuration => ({ configuration: { ...configuration, providerParameters: Uint8Array.of(0) },
        snapshot: () => { throw new Error('mismatched provider must never run') },
        ingestEvidence: async () => { throw new Error('mismatched provider must never run') }, evidenceBytes: () => [] }),
    } })).rejects.toThrow('FINALITY_PROVIDER_CONFIGURATION_MISMATCH')
  })

  it('refuses a signed future-admission window that cannot be represented exactly', async () => {
    const options = await configured()
    const genesis = await signGenesis({ ...options.genesis.manifest,
      clockPolicy: { ...options.genesis.manifest.clockPolicy, maxFutureSkewMs: BigInt(Number.MAX_SAFE_INTEGER), cutoffLagMs: 1n },
    }, options.identity.privateKey)
    await expect(createGovernedNode({ ...options, genesis })).rejects.toThrow('FINALITY_FUTURE_ADMISSION_WINDOW_INVALID')
  })

  it('refuses signing a peer history with an unsupported provider', async () => {
    const options = await configured()
    const manifest: GenesisManifest = { ...options.genesis.manifest,
      historyPolicy: { kind: 'peer', executionManifestDigest: options.materialization.queries.executionManifestDigest,
        providerId: 'custom-peer-v1' },
    }
    await expect(signGenesis(manifest, options.identity.privateKey)).rejects.toThrow('Unknown validator finality provider')
  })
})

import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'
import {
  bytesToHex, emit, encodeTransactionCore, encodeValidatorAttestation, encodeValidatorHeartbeat,
  generateEd25519KeyPair, program, transactionDigest, utf8, type TransactionCore,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { createFinalityClosureRecord, controlCommitmentForClosure } from './finality.js'
import { createPrefixAuthority, ReferenceRecordLog, SignedInclusionFinalityProvider } from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number) => new Uint8Array(32).fill(value)
const groupId = bytes(121), membershipRevision = bytes(122), validationPolicy = bytes(123), capabilityId = bytes(124)

async function fixture(mode: 'peer' | 'coordinated') {
  const identity = await generateEd25519KeyPair(), authorityIdentity = await generateEd25519KeyPair()
  const store = new MemoryOperationStore(), denied = new Set<bigint>()
  let failReplay = false, failFinalReply = false, now = 1_000
  const descriptorRuntime = await createEventMaterializationRuntime({ store, namespace: 'profile' })
  const configuration = { kind: 'coordinated' as const, groupId, genesisDigest: bytes(125),
    executionManifestDigest: descriptorRuntime.queries.executionManifestDigest,
    historyId: 'h_0123456789abcdef0123456789abcdef', authorityPublicKey: authorityIdentity.publicKeyBytes }
  await descriptorRuntime.close()
  const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
  const authority = createPrefixAuthority({ configuration, identity: authorityIdentity, readHead: () => log.head() })
  const watermark = { kind: 'threshold' as const, policyId: bytesToHex(validationPolicy),
    validatorIds: [identity.publicKeyBytes], threshold: 1 }
  const open = async () => {
    const base = await createEventMaterializationRuntime({ store, namespace: 'preview' })
    const runtime: ChronologMaterializationRuntime = { ...base,
      coordinator: { ...base.coordinator, async materialize(input) {
        if (failReplay) throw new Error('REPLAY_TEMPORARILY_UNAVAILABLE')
        return base.coordinator.materialize(input)
      }, async publishFinal(length) {
        await base.coordinator.publishFinal!(length)
        if (failFinalReply && length > 0) throw new Error('FINAL_PUBLICATION_REPLY_LOST')
      } },
    }
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    const node = new ChronologNode({ identity, groupId, membershipRevision, validationPolicy,
      transport, materialization: runtime, operationStore: store, clock: { now: () => now }, live: { maxFutureSkewMs: 30 },
      membership: {
        canWrite: context => context.authorTimestampMs === undefined || !denied.has(context.authorTimestampMs),
        canValidate: () => true, threshold: () => 1,
        watermarkPolicy: () => watermark,
        admissionScopes: () => [{ membershipRevision, authorTimeAfterMs: -1n, policies: [watermark] }],
      },
      ...(mode === 'peer' ? {} : { historyPolicy: { kind: 'coordinated' as const,
        policy: await SignedInclusionFinalityProvider.open(configuration, store) } }),
    })
    cleanup.push(() => node.close())
    await node.start()
    return { node, transport }
  }
  let current = await open()
  const records: Array<{ core: TransactionCore; txId: Uint8Array; canonical: Uint8Array; envelope: Uint8Array }> = []
  const propose = async (name: string, timestamp: bigint, operationId = name) => {
    const core: TransactionCore = { groupId, membershipRevision, validationPolicy, authorId: identity.publicKeyBytes,
      authorTimestampMs: timestamp, operationId, nonce: bytes(126), executionManifestDigest: configuration.executionManifestDigest,
      program: program(emit('preview', name)) }
    const canonical = encodeTransactionCore(core), txId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    const envelope = await encodeSignedEnvelope(groupId, 'candidate', canonical, identity)
    await current.node.ingest(await current.transport.publish(envelope))
    await current.node.waitForIdle()
    const value = { core, txId, canonical, envelope }
    records.push(value)
    return value
  }
  const finalize = async (accepted: readonly Awaited<ReturnType<typeof propose>>[], cutoff: bigint) => {
    if (mode === 'coordinated') {
      for (const record of records) await log.append((await createLedgerRecord(record.envelope)).recordBytes)
      await log.append(await createFinalityClosureRecord({ configuration, identity: authorityIdentity,
        includedHead: await log.head(), closedThroughMs: cutoff,
        control: await controlCommitmentForClosure(configuration, await log.read(), cutoff) }))
      for (const entry of await log.read()) await current.node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
      await current.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate: await authority.certify() })
    } else {
      for (const proposal of accepted) {
        await current.node.ingest(await current.transport.publish(await encodeSignedEnvelope(groupId, 'attestation', encodeValidatorAttestation({
          groupId, membershipRevision, validatorCapability: capabilityId, validatorId: identity.publicKeyBytes,
          txId: proposal.txId, authorTimestampMs: proposal.core.authorTimestampMs,
          candidateDigest: await transactionDigest(proposal.canonical), acceptedAboveMs: 0n, decision: 'admit', policyVersion: 1n,
        }), identity)))
      }
      await current.node.ingest(await current.transport.publish(await encodeSignedEnvelope(groupId, 'heartbeat', encodeValidatorHeartbeat({
        groupId, membershipRevision, validatorCapability: capabilityId, validatorId: identity.publicKeyBytes, acceptanceCutoffMs: cutoff,
      }), identity)))
    }
    await current.node.waitForIdle()
  }
  return { propose, finalize, denied, get node() { return current.node },
    set failReplay(value: boolean) { failReplay = value },
    set failFinalReply(value: boolean) { failFinalReply = value },
    set now(value: number) { now = value },
    async restart() { await current.node.close(); current = await open(); await current.node.waitForIdle() },
  }
}

async function view(node: ChronologNode, selected: 'local' | 'final') {
  const lease = await node.readView({ view: selected })
  try { return { revision: lease.revision, finalRevision: lease.finalRevision,
    events: lease.readEvents().transactions.flatMap(transaction => transaction.events.map(event => event.payload)) } }
  finally { lease.release() }
}

describe.each(['peer', 'coordinated'] as const)('%s live provisional execution', mode => {
  it('authors new intent after observed work and closed time while exact retries retain their original timestamp', async () => {
    const f = await fixture(mode), observed = await f.propose('observed', 1_010n)
    const input = { operationId: 'dependent', program: program(emit('preview', 'dependent')) }
    const dependent = await f.node.publish(input)
    expect(dependent.core.authorTimestampMs).toBe(1_011n)
    await f.node.waitForIdle()
    f.failFinalReply = true
    try {
      await expect(f.finalize([observed], 1_020n)).rejects.toThrow('FINAL_PUBLICATION_REPLY_LOST')
      expect(f.node.isFinal(observed.txId)).toBe(true)
      expect((await view(f.node, 'final')).events).toEqual(['observed'])
      const afterClosure = await f.node.publish({ operationId: 'after-closure', program: program(emit('preview', 'after')) })
      expect(afterClosure.core.authorTimestampMs).toBe(1_021n)
      // A backwards wall clock cannot silently rewrite an existing operation.
      f.now = 900
      expect((await f.node.publish(input)).core).toEqual(dependent.core)
      await expect(f.node.publish({ operationId: 'clock-ahead', program: program(emit('preview', 'new')) }))
        .rejects.toThrow('AUTHOR_CLOCK_AHEAD')
    } finally { f.failFinalReply = false; await f.node.waitForIdle() }
  })

  it('applies a raw authorized proposal before consensus and freezes the same outcome after closure', async () => {
    const f = await fixture(mode), proposal = await f.propose('prompt', 10n)
    expect(f.node.candidate(proposal.txId)?.state).toBe('provisional')
    expect(f.node.outcome(proposal.txId)?.outcome).toBe('accepted')
    expect(f.node.isFinal(proposal.txId)).toBe(false)
    expect((await view(f.node, 'local')).events).toEqual(['prompt'])
    expect((await view(f.node, 'final')).events).toEqual([])
    await f.finalize([proposal], 100n)
    expect(f.node.isFinal(proposal.txId)).toBe(true)
    expect((await view(f.node, 'final')).events).toEqual(['prompt'])
    await f.restart()
    expect(f.node.isFinal(proposal.txId)).toBe(true)
    expect(f.node.candidate(proposal.txId)?.canonicalPayload).toEqual(proposal.canonical)
    expect((await view(f.node, 'final')).events).toEqual(['prompt'])
  })

  it('withdraws and restores previews with deterministic redo while a failed replay keeps the applied view coherent', async () => {
    const f = await fixture(mode), early = await f.propose('early', 10n, 'same-operation')
    const late = await f.propose('late', 20n, 'same-operation')
    expect(f.node.outcome(late.txId)?.rejectionCode).toBe('operation_conflict')
    const before = await view(f.node, 'local')
    expect(before.events).toEqual(['early'])
    f.failReplay = true; f.denied.add(10n)
    await f.node.refreshMembership()
    await expect(f.node.waitForIdle()).rejects.toThrow('REPLAY_TEMPORARILY_UNAVAILABLE')
    expect(f.node.controlStore.orderedTransactionIds()).toEqual([late.txId])
    expect(await view(f.node, 'local')).toEqual(before)
    expect(f.node.outcome(late.txId)?.rejectionCode).toBe('operation_conflict')
    expect(f.node.isFinal(early.txId)).toBe(false)

    f.failReplay = false; await f.node.waitForIdle()
    expect(f.node.outcome(early.txId)).toBeNull()
    expect(f.node.outcome(late.txId)?.outcome).toBe('accepted')
    expect((await view(f.node, 'local')).events).toEqual(['late'])
    f.denied.clear(); await f.node.refreshMembership()
    expect((await view(f.node, 'local')).events).toEqual(['early'])
    expect(f.node.outcome(late.txId)?.rejectionCode).toBe('operation_conflict')
    expect(f.node.candidate(early.txId)?.canonicalPayload).toEqual(early.canonical)
    await f.finalize([early, late], 100n)
    expect((await view(f.node, 'final')).events).toEqual(['early'])
  })

  it('bounds readers previews by the shared clock policy without rejecting an unchanged future proposal', async () => {
    const f = await fixture(mode), future = await f.propose('future', 1_031n)
    expect(f.node.candidate(future.txId)).toMatchObject({ state: 'pending_validation', stateReason: 'AUTHOR_TIMESTAMP_FUTURE' })
    expect(f.node.outcome(future.txId)).toBeNull()
    expect(f.node.isFinal(future.txId)).toBe(false)
    f.now = 1_001; await f.node.refreshMembership()
    expect(f.node.candidate(future.txId)?.state).toBe('provisional')
    expect((await view(f.node, 'local')).events).toEqual(['future'])
    expect(f.node.candidate(future.txId)?.canonicalPayload).toEqual(future.canonical)
  })

  it('keeps a withdrawn proposal pending until consensus excludes it and retains its original signed identity', async () => {
    const f = await fixture(mode), denied = await f.propose('revoked-preview', 10n)
    const valid = await f.propose('still-authorized', 20n)
    f.denied.add(10n); await f.node.refreshMembership()
    expect(f.node.candidate(denied.txId)?.state).toBe('pending_validation')
    expect(f.node.outcome(denied.txId)).toBeNull()
    expect(f.node.isFinal(denied.txId)).toBe(false)
    expect((await view(f.node, 'local')).events).toEqual(['still-authorized'])
    await f.finalize([valid], 100n)
    expect(f.node.outcome(denied.txId)).toMatchObject({ outcome: 'rejected',
      rejectionCode: mode === 'peer' ? 'ADMISSION_CLOSED' : 'WRITER_UNAUTHORIZED' })
    expect(f.node.isFinal(denied.txId)).toBe(true)
    expect(f.node.candidate(denied.txId)?.canonicalPayload).toEqual(denied.canonical)
    f.denied.clear(); await f.node.refreshMembership()
    expect((await view(f.node, 'final')).events).toEqual(['still-authorized'])
    expect(f.node.outcome(denied.txId)?.outcome).toBe('rejected')
  })
})

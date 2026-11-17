import { controlGenesisRoot } from './control-chain.js'
import { controlCommitmentForClosure } from './finality.js'
import { describe, expect, it, vi } from 'vitest'
import { encodeEnvelope, generateEd25519KeyPair, utf8 } from '@chronolog/protocol'

import {
  createFinalityClosureRecord, decodeFinalityClosureRecord, encodeFinalityClosureRecord,
  evaluateFinalitySnapshot, verifyFinalityClosureRecord,
} from './finality.js'
import {
  SignedInclusionFinalityProvider, ReferenceRecordLog, createPrefixAuthority, encodeOrderingEvidence,
  type CoordinatedHistoryConfiguration,
} from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { MemoryOperationStore } from './operations.js'

async function fixture() {
  const identity = await generateEd25519KeyPair()
  const configuration: CoordinatedHistoryConfiguration = {
    kind: 'coordinated', historyId: 'h_0123456789abcdef0123456789abcdef',
    authorityPublicKey: identity.publicKeyBytes, groupId: new Uint8Array(32).fill(1),
    genesisDigest: new Uint8Array(32).fill(2), executionManifestDigest: new Uint8Array(32).fill(3),
  }
  const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
  const storage = new MemoryOperationStore()
  const policy = await SignedInclusionFinalityProvider.open(configuration, storage)
  const authority = createPrefixAuthority({ configuration, identity, readHead: () => log.head() })
  const close = async (closedThroughMs: bigint) => log.append(await createFinalityClosureRecord({
    configuration, identity, includedHead: await log.head(), closedThroughMs,
    control: await controlCommitmentForClosure(configuration, await log.read(), closedThroughMs),
  }))
  const share = async () => {
    for (const entry of await log.read()) await policy.ingestEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
    await policy.ingestEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: await authority.certify() }))
  }
  return { configuration, identity, log, storage, policy, authority, close, share }
}

describe('inclusion and chronological closure proofs', () => {
  it('verifies each newly certified closure once while standalone verification and reopen still verify the complete prefix', async () => {
    const f = await fixture(), updates = []
    for (let index = 1; index <= 8; index++) {
      const entry = await f.close(BigInt(index * 100))
      updates.push({ entry, certificate: await f.authority.certify() })
    }
    const entries = await f.log.read(), verify = vi.spyOn(crypto.subtle, 'verify')
    try {
      for (const { entry, certificate } of updates) {
        await f.policy.ingest({ kind: 'ordered-entry', entry })
        await f.policy.ingest({ kind: 'prefix-certificate', certificate })
      }
      // Eight independent inclusion signatures and eight new closure promises;
      // historical promises are not verified again at each later checkpoint.
      expect(verify).toHaveBeenCalledTimes(updates.length * 2)
      const expected = f.policy.snapshot()
      verify.mockClear()
      await f.policy.ingest({ kind: 'prefix-certificate', certificate: updates.at(-1)!.certificate })
      expect(verify).toHaveBeenCalledTimes(1)
      expect(f.policy.snapshot()).toEqual(expected)
      verify.mockClear()
      expect(await evaluateFinalitySnapshot(f.configuration, entries)).toEqual(expected)
      expect(verify).toHaveBeenCalledTimes(updates.length)
      verify.mockClear()
      expect((await SignedInclusionFinalityProvider.open(f.configuration, f.storage)).snapshot()).toEqual(expected)
      expect(verify).toHaveBeenCalledTimes(updates.length * 2)
      const altered = structuredClone(entries)
      altered[0]!.bytes[0]! ^= 1
      await expect(evaluateFinalitySnapshot(f.configuration, altered)).rejects.toThrow('ORDERED_RECORD_DIGEST_MISMATCH')
    } finally { verify.mockRestore() }
  })

  it('extends uncovered records and controls without changing their first covering closure or admission floor', async () => {
    const f = await fixture()
    const control = async (value: number) => f.log.append((await createLedgerRecord(encodeEnvelope({
      groupRoute: new Uint8Array(32).fill(4), messageType: 'capability', encryptionEpoch: null,
      payload: Uint8Array.of(value),
    }))).recordBytes)
    const first = await control(1)
    await f.share() // An authenticated inclusion can still be uncovered.
    expect(f.policy.snapshot().controls).toEqual([])
    await f.log.append(utf8('application one'))
    await f.close(100n)
    await f.share()
    const firstSnapshot = f.policy.snapshot(), firstControl = structuredClone(firstSnapshot.controls[0]!)
    // Public snapshots cannot change the privately owned prefix used by the next extension.
    firstSnapshot.records[0]!.entry.bytes.fill(0)
    firstSnapshot.controls[0]!.entry.bytes.fill(0)
    const second = await control(2)
    await f.share()
    expect(f.policy.snapshot().controls).toEqual([firstControl])
    expect(f.policy.snapshot().records.find(record => record.entry.position === second.position))
      .toMatchObject({ admissionFloorMs: 100n, closedThroughMs: -1n, closureBoundary: null })
    await f.log.append(utf8('application two'))
    await f.close(200n)
    await f.share()
    await f.close(300n)
    await f.share()
    const expected = await evaluateFinalitySnapshot(f.configuration, await f.log.read())
    expect(f.policy.snapshot()).toEqual(expected)
    expect(expected.controls.map(item => [item.index, item.entry.position, item.cutoffMs]))
      .toEqual([[1, first.position, 100n], [2, second.position, 200n]])
    expect(expected.controls[0]).toEqual(firstControl)
    expect(expected.records.map(record => [record.admissionFloorMs, record.closedThroughMs]))
      .toEqual([[-1n, 100n], [-1n, 100n], [100n, 200n], [100n, 200n]])
    const offline = await SignedInclusionFinalityProvider.open(f.configuration, new MemoryOperationStore())
    await offline.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() })
    for (const entry of [...await f.log.read()].reverse()) await offline.ingest({ kind: 'ordered-entry', entry })
    expect(offline.snapshot()).toEqual(expected)
    expect((await SignedInclusionFinalityProvider.open(f.configuration, f.storage)).snapshot()).toEqual(expected)
  })

  it('reopens after a failed durable write before re-verifying and publishing the staged suffix', async () => {
    const f = await fixture()
    await f.log.append(utf8('first proposal')); await f.close(100n)
    await f.share()
    let fail = false
    const policy = await SignedInclusionFinalityProvider.open(f.configuration, {
      get: key => f.storage.get(key),
      put: async (key, bytes) => { if (fail) throw new Error('disk full'); await f.storage.put(key, bytes) },
    })
    const proposal = await f.log.append(utf8('next proposal')), closure = await f.close(200n)
    await policy.ingest({ kind: 'ordered-entry', entry: proposal })
    await policy.ingest({ kind: 'ordered-entry', entry: closure })
    const certificate = await f.authority.certify(), prior = policy.snapshot(), verify = vi.spyOn(crypto.subtle, 'verify')
    try {
      fail = true
      await expect(policy.ingest({ kind: 'prefix-certificate', certificate })).rejects.toThrow('disk full')
      expect(verify).toHaveBeenCalledTimes(2)
      expect(policy.snapshot()).toEqual(prior)
      expect((await SignedInclusionFinalityProvider.open(f.configuration, f.storage)).snapshot()).toEqual(prior)
      verify.mockClear()
      fail = false
      await expect(policy.ingest({ kind: 'prefix-certificate', certificate })).rejects.toThrow('HISTORY_STORAGE_UNCERTAIN_REOPEN_REQUIRED')
      expect(verify).not.toHaveBeenCalled()
      const reopened = await SignedInclusionFinalityProvider.open(f.configuration, f.storage)
      verify.mockClear()
      await reopened.ingest({ kind: 'prefix-certificate', certificate })
      // A failed stage is not a reusable verification cache, even for exact bytes.
      expect(verify).toHaveBeenCalledTimes(2)
      expect(reopened.snapshot().closedThroughMs).toBe(200n)
      expect(reopened.snapshot()).toEqual(await evaluateFinalitySnapshot(f.configuration, await f.log.read()))
    } finally { verify.mockRestore() }
  })

  it('cannot overwrite a newer durable certified prefix after its storage acknowledgment is lost', async () => {
    const f = await fixture()
    await f.log.append(utf8('first proposal')); await f.close(100n)
    await f.share()
    let loseReply = true, writes = 0
    const policy = await SignedInclusionFinalityProvider.open(f.configuration, {
      get: key => f.storage.get(key),
      async put(key, bytes) {
        await f.storage.put(key, bytes); writes++
        if (loseReply) { loseReply = false; throw new Error('storage acknowledgment lost') }
      },
    })
    const prior = policy.snapshot()
    const proposal = await f.log.append(utf8('next proposal')), closure = await f.close(200n)
    const evidence = [{ kind: 'ordered-entry' as const, entry: proposal }, { kind: 'ordered-entry' as const, entry: closure },
      { kind: 'prefix-certificate' as const, certificate: await f.authority.certify() }]
    await expect(policy.ingestBatch(evidence)).rejects.toThrow('storage acknowledgment lost')
    expect(policy.snapshot()).toEqual(prior)
    await expect(policy.ingestBatch(evidence)).rejects.toThrow('HISTORY_STORAGE_UNCERTAIN_REOPEN_REQUIRED')
    const next = await f.log.append(utf8('later receipt'))
    await expect(policy.ingest({ kind: 'ordered-entry', entry: next })).rejects.toThrow('HISTORY_STORAGE_UNCERTAIN_REOPEN_REQUIRED')
    expect(writes).toBe(1)

    const reopened = await SignedInclusionFinalityProvider.open(f.configuration, f.storage)
    expect(reopened.snapshot().closedThroughMs).toBe(200n)
    await reopened.ingestBatch(evidence)
    await reopened.ingest({ kind: 'ordered-entry', entry: next })
    expect(reopened.snapshot()).toMatchObject({ closedThroughMs: 200n, includedThrough: closure.position, receivedThrough: next.position })
    expect((await SignedInclusionFinalityProvider.open(f.configuration, f.storage)).snapshot()).toEqual(reopened.snapshot())
  })

  it('does not publish staged control coverage when a later signed closure omits a newly included control', async () => {
    const f = await fixture()
    const control = async (value: number) => f.log.append((await createLedgerRecord(encodeEnvelope({
      groupRoute: new Uint8Array(32).fill(4), messageType: 'capability', encryptionEpoch: null, payload: Uint8Array.of(value),
    }))).recordBytes)
    await control(1); await f.close(100n); await f.share()
    const oldCommitment = f.policy.snapshot().control
    const newControl = await control(2)
    const invalidClosure = await f.log.append(await createFinalityClosureRecord({ configuration: f.configuration,
      identity: f.identity, includedHead: await f.log.head(), closedThroughMs: 200n, control: oldCommitment }))
    await f.policy.ingest({ kind: 'ordered-entry', entry: newControl })
    await f.policy.ingest({ kind: 'ordered-entry', entry: invalidClosure })
    const prior = f.policy.snapshot()
    await expect(f.policy.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() }))
      .rejects.toThrow('FINALITY_CONTROL_PROJECTION_MISMATCH')
    expect(f.policy.snapshot()).toEqual(prior)
    expect((await SignedInclusionFinalityProvider.open(f.configuration, f.storage)).snapshot()).toEqual(prior)
    await expect(evaluateFinalitySnapshot(f.configuration, await f.log.read())).rejects.toThrow('FINALITY_CONTROL_PROJECTION_MISMATCH')
  })

  it('does not turn a certified receipt into application finality', async () => {
    const f = await fixture()
    const entry = await f.log.append(utf8('an opaque encrypted proposal'))
    await f.share()
    expect(f.policy.snapshot()).toMatchObject({ includedThrough: 1, closedReceiptThrough: 0, closedThroughMs: -1n,
      records: [{ entry, admissionFloorMs: -1n, closedThroughMs: -1n, closureBoundary: null }] })
    expect(f.policy.boundaryForEntry(1)).toBeNull()
  })

  it('separates the prior admission cutoff, first covering closure and current frontier', async () => {
    const f = await fixture()
    const first = await f.log.append(utf8('first included proposal'))
    const closure = await f.close(100n)
    const second = await f.log.append(utf8('a later proposal, whose timestamp remains encrypted'))
    await f.close(200n)
    await f.close(300n) // Idle time can close without adding another application record.
    await f.share()
    const snapshot = f.policy.snapshot()
    expect(snapshot.closedThroughMs).toBe(300n)
    expect(snapshot.records.map(record => [record.entry.position, record.admissionFloorMs, record.closedThroughMs]))
      .toEqual([[first.position, -1n, 100n], [second.position, 100n, 200n]])
    expect(f.policy.admissionFloor(second.position)).toBe(100n)
    expect(f.policy.boundaryForEntry(first.position)).toBe(100n)
    expect(f.policy.isClosure(closure.position)).toBe(true)
    expect(snapshot.records.some(record => record.entry.position === closure.position)).toBe(false)
    // A body later proving timestamp <= 100 is late, even though frontier is now 300.
    expect(75n <= f.policy.admissionFloor(second.position)).toBe(true)
    // Caller mutation cannot reopen an already-closed interval.
    snapshot.records[0]!.entry.bytes.fill(0)
    expect(f.policy.snapshot().records[0]!.entry).toEqual(first)
  })

  it('requires historical closure bytes even when only the latest certificate is available', async () => {
    const f = await fixture()
    const first = await f.log.append(utf8('first'))
    const firstClosure = await f.close(100n)
    const second = await f.log.append(utf8('second'))
    const lastClosure = await f.close(200n)
    await f.policy.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() })
    for (const entry of [lastClosure, second, first]) await f.policy.ingest({ kind: 'ordered-entry', entry })
    expect(f.policy.snapshot()).toMatchObject({ includedThrough: 0, closedThroughMs: -1n })
    expect(f.policy.progress.missing).toContain(firstClosure.position)
    await f.policy.ingest({ kind: 'ordered-entry', entry: firstClosure })
    const reopened = await SignedInclusionFinalityProvider.open(f.configuration, f.storage)
    const offline = await SignedInclusionFinalityProvider.open(f.configuration, new MemoryOperationStore())
    for (const bytes of [...reopened.evidenceBytes()].reverse()) await offline.ingestEvidence(bytes)
    expect(reopened.snapshot()).toEqual(f.policy.snapshot())
    expect(offline.snapshot()).toEqual(reopened.snapshot())
    expect(offline.admissionFloor(second.position)).toBe(100n)
  })

  it('does not let a stale-head closure cover a concurrently appended record', async () => {
    const f = await fixture()
    await f.log.append(utf8('already included'))
    const marker = await createFinalityClosureRecord({ configuration: f.configuration, identity: f.identity,
      control: { count: 0, root: await controlGenesisRoot(f.configuration) }, includedHead: await f.log.head(), closedThroughMs: 100n })
    await f.log.append(utf8('concurrent append'))
    await f.log.append(marker)
    await expect(f.share()).rejects.toThrow('FINALITY_CLOSURE_HEAD_MISMATCH')
    expect(f.policy.closedThroughMs).toBe(-1n)
    await expect(evaluateFinalitySnapshot(f.configuration, await f.log.read()))
      .rejects.toThrow('FINALITY_CLOSURE_HEAD_MISMATCH')
  })

  it('rejects a regressing closure without publishing or persisting the new frontier', async () => {
    const f = await fixture()
    await f.close(100n)
    await f.share()
    const prior = f.policy.snapshot()
    await f.close(99n)
    await expect(f.share()).rejects.toThrow('FINALITY_CLOSURE_REGRESSION')
    expect(f.policy.snapshot().closedThroughMs).toBe(100n)
    expect(f.policy.snapshot().includedThrough).toBe(prior.includedThrough)
    const reopened = await SignedInclusionFinalityProvider.open(f.configuration, f.storage)
    expect(reopened.closedThroughMs).toBe(100n)
  })

  it('authenticates the independent closure signature, provider binding and included head', async () => {
    const f = await fixture()
    const marker = await createFinalityClosureRecord({ configuration: f.configuration, identity: f.identity,
      control: { count: 0, root: await controlGenesisRoot(f.configuration) }, includedHead: await f.log.head(), closedThroughMs: 100n })
    const altered = decodeFinalityClosureRecord(marker)
    altered.signature[0]! ^= 1
    await expect(verifyFinalityClosureRecord(encodeFinalityClosureRecord(altered), f.configuration))
      .rejects.toThrow('FINALITY_CLOSURE_SIGNATURE_INVALID')
    await expect(verifyFinalityClosureRecord(marker, { ...f.configuration, providerId: 'another-provider-v1' }))
      .rejects.toThrow('FINALITY_CLOSURE_CONFIGURATION_MISMATCH')
    await expect(createFinalityClosureRecord({ configuration: f.configuration, identity: f.identity,
      control: { count: 0, root: await controlGenesisRoot(f.configuration) }, includedHead: await f.log.head(), closedThroughMs: -1n })).rejects.toThrow('FINALITY_CLOSURE_INVALID')
    await expect(createFinalityClosureRecord({ configuration: f.configuration, identity: f.identity,
      control: { count: 0, root: await controlGenesisRoot(f.configuration) }, includedHead: await f.log.head(), closedThroughMs: 1n << 63n })).rejects.toThrow('FINALITY_CLOSURE_INVALID')
  })

  it('does not publish a new closure when its evidence checkpoint cannot be persisted', async () => {
    const f = await fixture()
    await f.log.append(utf8('proposal'))
    await f.close(100n)
    let fail = false
    const store = {
      get: (key: string) => f.storage.get(key),
      put: (key: string, bytes: Uint8Array) => fail ? Promise.reject(new Error('disk full')) : f.storage.put(key, bytes),
    }
    const policy = await SignedInclusionFinalityProvider.open(f.configuration, store)
    for (const entry of await f.log.read()) await policy.ingest({ kind: 'ordered-entry', entry })
    fail = true
    await expect(policy.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() })).rejects.toThrow('disk full')
    expect(policy.closedThroughMs).toBe(-1n)
    expect((await SignedInclusionFinalityProvider.open(f.configuration, f.storage)).closedThroughMs).toBe(-1n)
  })

  it('keeps forged and foreign marker-shaped writer bytes inert in an opaque hosted log', async () => {
    const f = await fixture()
    const marker = await createFinalityClosureRecord({ configuration: f.configuration, identity: f.identity,
      control: { count: 0, root: await controlGenesisRoot(f.configuration) }, includedHead: await f.log.head(), closedThroughMs: 10_000n })
    const forged = decodeFinalityClosureRecord(marker)
    forged.signature[0]! ^= 1
    await f.log.append(encodeFinalityClosureRecord(forged))
    const foreign = await createFinalityClosureRecord({ configuration: { ...f.configuration, providerId: 'foreign-v1' },
      identity: f.identity, control: { count: 0, root: await controlGenesisRoot(f.configuration) }, includedHead: await f.log.head(), closedThroughMs: 10_000n })
    await f.log.append(foreign)
    await f.log.append(utf8('valid application proposal'))
    await f.close(100n)
    await f.share()
    expect(f.policy.closedThroughMs).toBe(100n)
    expect(f.policy.snapshot().closures).toHaveLength(1)
    expect(f.policy.snapshot().records).toHaveLength(3)
  })
})

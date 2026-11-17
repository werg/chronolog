import { controlGenesisRoot } from './control-chain.js'
import { controlCommitmentForClosure } from './finality.js'
import { describe, expect, it } from 'vitest'
import { generateEd25519KeyPair, utf8 } from '@chronolog/protocol'

import {
  createFinalityClosureRecord, decodeFinalityClosureRecord, encodeFinalityClosureRecord,
  evaluateFinalitySnapshot, verifyFinalityClosureRecord,
} from './finality.js'
import {
  CoordinatedHistoryPolicy, ReferenceRecordLog, createPrefixAuthority, encodeOrderingEvidence,
  type CoordinatedHistoryConfiguration,
} from './history-policy.js'
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
  const policy = await CoordinatedHistoryPolicy.open(configuration, storage)
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
    const reopened = await CoordinatedHistoryPolicy.open(f.configuration, f.storage)
    const offline = await CoordinatedHistoryPolicy.open(f.configuration, new MemoryOperationStore())
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
    const reopened = await CoordinatedHistoryPolicy.open(f.configuration, f.storage)
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
    const policy = await CoordinatedHistoryPolicy.open(f.configuration, store)
    for (const entry of await f.log.read()) await policy.ingest({ kind: 'ordered-entry', entry })
    fail = true
    await expect(policy.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() })).rejects.toThrow('disk full')
    expect(policy.closedThroughMs).toBe(-1n)
    expect((await CoordinatedHistoryPolicy.open(f.configuration, f.storage)).closedThroughMs).toBe(-1n)
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

import { encodeEnvelope, generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { appendControl, controlGenesisRoot } from './control-chain.js'
import { ControlHistory, decodeControlPage, encodeControlPage, type MembershipLedgerPage } from './control-proof.js'
import { controlCommitmentForClosure, createFinalityClosureRecord, evaluateFinalitySnapshot } from './finality.js'
import { ReferenceRecordLog, createPrefixAuthority, type CoordinatedHistoryConfiguration } from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { MemoryOperationStore } from './operations.js'

async function fixture() {
  const identity = await generateEd25519KeyPair()
  const configuration: CoordinatedHistoryConfiguration = { kind: 'coordinated', historyId: 'h_0123456789abcdef0123456789abcdef',
    authorityPublicKey: identity.publicKeyBytes, groupId: new Uint8Array(32).fill(1), genesisDigest: new Uint8Array(32).fill(2),
    executionManifestDigest: new Uint8Array(32).fill(3) }
  const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
  const authority = createPrefixAuthority({ configuration, identity, readHead: () => log.head() })
  const add = async (kind: 'candidate' | 'capability', value: number) => log.append((await createLedgerRecord(encodeEnvelope({
    groupRoute: new Uint8Array(32).fill(4), messageType: kind, encryptionEpoch: null, payload: new Uint8Array([value]),
  }))).recordBytes)
  const close = async (time: bigint) => log.append(await createFinalityClosureRecord({ configuration, identity,
    includedHead: await log.head(), closedThroughMs: time, control: await controlCommitmentForClosure(configuration, await log.read(), time) }))
  const page = async (after = 0, limit = 128): Promise<MembershipLedgerPage> => {
    const retained = await log.read(), snapshot = await evaluateFinalitySnapshot(configuration, retained)
    const entries = snapshot.controls.slice(after, after + limit)
    return { entries, checkpoint: retained.at(-1) ?? null, certificate: await authority.certify(),
      hasMore: after + entries.length < snapshot.controls.length }
  }
  return { configuration, identity, log, authority, add, close, page }
}

describe('authenticated compact control projection', () => {
  it('retains only controls and one checkpoint while application history grows', async () => {
    const f = await fixture(), store = new MemoryOperationStore()
    const history = await ControlHistory.open(f.configuration, store)
    await f.add('capability', 1); await f.close(100n)
    const first = await f.page()
    await history.ingest(first)
    const before = encodeControlPage(history.read({ after: 0 })).length
    for (let index = 0; index < 160; index++) await f.add('candidate', index)
    await f.close(200n)
    const incremental = await f.page(1)
    expect(incremental.entries).toEqual([])
    await history.ingest(decodeControlPage(encodeControlPage(incremental)))
    expect(history.progress).toMatchObject({ verifiedThrough: 1, receiptThrough: 162, closedThroughMs: 200n })
    expect(history.entries()[0]!.cutoffMs).toBe(100n)
    expect(encodeControlPage(history.read({ after: 0 })).length - before).toBeLessThan(32)
    const reopened = await ControlHistory.open(f.configuration, store)
    expect(reopened.progress).toEqual(history.progress)
    expect(reopened.entries()).toEqual(history.entries())
  })

  it('does not activate or persist incomplete pages and recovers after interruption', async () => {
    const f = await fixture(), store = new MemoryOperationStore()
    await f.add('capability', 1); await f.add('capability', 2); await f.close(100n)
    const history = await ControlHistory.open(f.configuration, store)
    await history.ingest(await f.page(0, 1))
    expect(history.progress).toMatchObject({ receivedThrough: 1, verifiedThrough: 0 })
    expect(history.entries()).toEqual([])
    expect((await ControlHistory.open(f.configuration, store)).progress.verifiedThrough).toBe(0)
    history.restart()
    await history.ingest(await f.page(0, 1)); await history.ingest(await f.page(1, 1))
    expect(history.progress.verifiedThrough).toBe(2)
    expect((await ControlHistory.open(f.configuration, store)).entries()).toEqual(history.entries())
  })

  it('refuses to replace a newer partially received checkpoint with an older signed one', async () => {
    const f = await fixture(), history = await ControlHistory.open(f.configuration, new MemoryOperationStore())
    await f.add('capability', 1); await f.add('capability', 2); await f.close(100n)
    const old = await f.page(1, 1)
    await f.add('capability', 3); await f.close(200n)
    await history.ingest(await f.page(0, 1))
    await expect(history.ingest(old)).rejects.toThrow('CONTROL_CHECKPOINT_REGRESSION')
    expect(history.progress.verifiedThrough).toBe(0)
  })

  it('enforces the memory budget while a signed projection is still incomplete', async () => {
    const f = await fixture(), store = new MemoryOperationStore()
    for (let index = 0; index < 8; index++) await f.add('capability', index)
    await f.close(100n)
    const history = await ControlHistory.open(f.configuration, store, { quotaBytes: 1024 })
    await history.ingest(await f.page(0, 1))
    await expect(history.ingest(await f.page(1, 2))).rejects.toThrow('CONTROL_STORAGE_QUOTA_EXCEEDED')
    expect(history.progress).toMatchObject({ receivedThrough: 0, verifiedThrough: 0 })
    expect((await ControlHistory.open(f.configuration, store)).entries()).toEqual([])
  })

  it.each(['omit', 'reorder', 'cutoff', 'body', 'group', 'checkpoint'] as const)('rejects %s tampering before publishing controls', async mode => {
    const f = await fixture()
    await f.add('capability', 1); await f.close(100n); await f.add('capability', 2); await f.close(200n)
    const page = structuredClone(await f.page()), entries = [...page.entries]
    if (mode === 'omit') entries.shift()
    if (mode === 'reorder') entries.reverse()
    if (mode === 'cutoff') entries[0] = { ...entries[0]!, cutoffMs: 200n }
    if (mode === 'body') entries[0]!.entry.bytes[0]! ^= 1
    if (mode === 'checkpoint') page.checkpoint!.bytes[0]! ^= 1
    const configuration = mode === 'group' ? { ...f.configuration, groupId: new Uint8Array(32).fill(9) } : f.configuration
    const history = await ControlHistory.open(configuration, new MemoryOperationStore())
    await expect(history.ingest({ ...page, entries })).rejects.toThrow()
    expect(history.progress.verifiedThrough).toBe(0)
  })

  it('rejects a recomputed substituted chain even when its individual hashes are valid', async () => {
    const f = await fixture()
    await f.add('capability', 1); await f.close(100n)
    const page = await f.page(), control = page.entries[0]!
    const replaced = await appendControl({ count: 0, root: await controlGenesisRoot(f.configuration) }, control.entry, 99n)
    const history = await ControlHistory.open(f.configuration, new MemoryOperationStore())
    await expect(history.ingest({ ...page, entries: [replaced] })).rejects.toThrow('CONTROL_PROJECTION_ROOT_MISMATCH')
  })

  it('rejects rollback and signed equivocation after a durable checkpoint', async () => {
    const f = await fixture(), store = new MemoryOperationStore()
    await f.add('capability', 1); await f.close(100n)
    const old = await f.page(), history = await ControlHistory.open(f.configuration, store)
    await history.ingest(old)
    await f.add('candidate', 1); await f.close(200n)
    await history.ingest(await f.page(1))
    await expect(history.ingest(old)).rejects.toThrow('CONTROL_CHECKPOINT_REGRESSION')
    // The same authority signs a conflicting control root at a later receipt.
    const commitment = { count: 1, root: 'f'.repeat(64) }
    const checkpoint = await f.log.append(await createFinalityClosureRecord({ configuration: f.configuration, identity: f.identity,
      includedHead: await f.log.head(), closedThroughMs: 300n, control: commitment }))
    await expect(history.ingest({ entries: [], checkpoint, certificate: await f.authority.certify(), hasMore: false }))
      .rejects.toThrow('CONTROL_CHECKPOINT_EQUIVOCATION')
    expect((await ControlHistory.open(f.configuration, store)).progress).toEqual(history.progress)
  })

  it('requires full replicas to audit the authority projection against every original receipt', async () => {
    const f = await fixture()
    await f.add('capability', 1)
    await f.log.append(await createFinalityClosureRecord({ configuration: f.configuration, identity: f.identity,
      includedHead: await f.log.head(), closedThroughMs: 100n,
      control: { count: 0, root: await controlGenesisRoot(f.configuration) } }))
    await expect(evaluateFinalitySnapshot(f.configuration, await f.log.read())).rejects.toThrow('FINALITY_CONTROL_PROJECTION_MISMATCH')
  })

  it('does not publish a verified checkpoint when its durable write fails', async () => {
    const f = await fixture(), store = new MemoryOperationStore()
    const history = await ControlHistory.open(f.configuration, { get: key => store.get(key), put: async () => { throw new Error('disk full') } })
    await f.add('capability', 1); await f.close(100n)
    await expect(history.ingest(await f.page())).rejects.toThrow('disk full')
    expect(history.progress.verifiedThrough).toBe(0)
    expect((await ControlHistory.open(f.configuration, store)).progress.verifiedThrough).toBe(0)
  })
})

import { describe, expect, it } from 'vitest'
import { generateEd25519KeyPair, utf8 } from '@chronolog/protocol'

import {
  CoordinatedHistoryPolicy, ReferenceRecordLog, createPrefixAuthority,
  decodeOrderingEvidence, encodeOrderingEvidence, orderedGenesisRoot,
  type CoordinatedHistoryConfiguration,
} from './history-policy.js'
import { MemoryOperationStore } from './operations.js'

const historyId = 'h_0123456789abcdef0123456789abcdef'

async function fixture() {
  const identity = await generateEd25519KeyPair()
  const configuration: CoordinatedHistoryConfiguration = {
    kind: 'coordinated', historyId, authorityPublicKey: identity.publicKeyBytes,
    groupId: new Uint8Array(32).fill(1), genesisDigest: new Uint8Array(32).fill(2),
    executionManifestDigest: new Uint8Array(32).fill(3),
  }
  const storage = new MemoryOperationStore()
  const log = await ReferenceRecordLog.open(historyId, storage)
  const authority = createPrefixAuthority({ configuration, identity, readHead: () => log.head() })
  const peerStorage = new MemoryOperationStore()
  const peer = await CoordinatedHistoryPolicy.open(configuration, peerStorage)
  return { configuration, storage, log, authority, peer, peerStorage, identity }
}

describe('portable coordinated prefix evidence', () => {
  it('makes exact append retries durable across reopening and refuses quota loss', async () => {
    const f = await fixture()
    const first = await f.log.append(utf8('first'))
    const reopened = await ReferenceRecordLog.open(historyId, f.storage, 5)
    expect(await reopened.append(utf8('first'))).toEqual(first)
    await expect(reopened.append(utf8('second'))).rejects.toThrow('QUOTA_EXCEEDED')
    expect((await reopened.head()).position).toBe(1)
  })

  it('requires the complete chain before treating a signed prefix as final', async () => {
    const f = await fixture()
    const entries = await Promise.all(['one', 'two', 'three'].map((s) => f.log.append(utf8(s))))
    const certificate = await f.authority.certify()
    await f.peer.ingest({ kind: 'prefix-certificate', certificate })
    await f.peer.ingest({ kind: 'ordered-entry', entry: entries[2]! })
    await f.peer.ingest({ kind: 'ordered-entry', entry: entries[0]! })
    expect(f.peer.progress).toMatchObject({ verifiedThrough: 0, certifiedThrough: 3, finalThrough: 0, missing: [2] })
    await f.peer.ingest({ kind: 'ordered-entry', entry: entries[1]! })
    expect(f.peer.progress).toMatchObject({ verifiedThrough: 3, finalThrough: 3, root: certificate.root })
  })

  it('rebuilds from evidence relayed by a peer after the authority is gone', async () => {
    const f = await fixture()
    for (const value of ['one', 'two']) await f.peer.ingest({ kind: 'ordered-entry', entry: await f.log.append(utf8(value)) })
    await f.peer.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() })
    const second = await CoordinatedHistoryPolicy.open(f.configuration, new MemoryOperationStore())
    for (const evidence of [...f.peer.evidence()].reverse()) {
      await second.ingest(decodeOrderingEvidence(encodeOrderingEvidence(evidence)))
    }
    expect(second.progress).toEqual(f.peer.progress)
    const reopened = await CoordinatedHistoryPolicy.open(f.configuration, f.peerStorage)
    expect(reopened.progress).toEqual(f.peer.progress)
    expect(reopened.entries()).toEqual(f.peer.entries())
  })

  it('does not infer freshness or new finality from an old certificate', async () => {
    const f = await fixture()
    const one = await f.log.append(utf8('one'))
    const old = await f.authority.certify()
    const two = await f.log.append(utf8('two'))
    await f.peer.ingest({ kind: 'ordered-entry', entry: one })
    await f.peer.ingest({ kind: 'ordered-entry', entry: two })
    await f.peer.ingest({ kind: 'prefix-certificate', certificate: old })
    expect(f.peer.progress).toMatchObject({ receivedThrough: 2, verifiedThrough: 1, finalThrough: 1 })
  })

  it('selects the certified chain when a self-consistent counterfeit entry arrived first', async () => {
    const f = await fixture()
    const fakeLog = await ReferenceRecordLog.open(historyId, new MemoryOperationStore())
    const fake = await fakeLog.append(utf8('fabricated first position'))
    await f.peer.ingest({ kind: 'ordered-entry', entry: fake })
    expect(f.peer.progress.finalThrough).toBe(0)
    const first = await f.log.append(utf8('authentic first'))
    const second = await f.log.append(utf8('authentic second'))
    await f.peer.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() })
    await f.peer.ingest({ kind: 'ordered-entry', entry: second })
    expect(f.peer.progress).toMatchObject({ finalThrough: 0, missing: [1] })
    await f.peer.ingest({ kind: 'ordered-entry', entry: first })
    expect(f.peer.entries()).toEqual([first, second])
    const reopened = await CoordinatedHistoryPolicy.open(f.configuration, f.peerStorage)
    expect(reopened.entries()).toEqual([first, second])
    expect(reopened.evidence().filter((item) => item.kind === 'ordered-entry')).toHaveLength(2)
  })

  it('does not permit contradictory authority commitments at the same or later positions', async () => {
    const f = await fixture()
    const first = await f.log.append(utf8('original'))
    await f.peer.ingest({ kind: 'ordered-entry', entry: first })
    await f.peer.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() })
    const fork = await ReferenceRecordLog.open(historyId, new MemoryOperationStore())
    await fork.append(utf8('forked original'))
    const forkAuthority = createPrefixAuthority({ configuration: f.configuration, identity: f.identity, readHead: () => fork.head() })
    await expect(f.peer.ingest({ kind: 'prefix-certificate', certificate: await forkAuthority.certify() }))
      .rejects.toThrow('HISTORY_AUTHORITY_EQUIVOCATION')
    const second = await fork.append(utf8('forked successor'))
    await f.peer.ingest({ kind: 'prefix-certificate', certificate: await forkAuthority.certify() })
    await expect(f.peer.ingest({ kind: 'ordered-entry', entry: second })).rejects.toThrow('HISTORY_AUTHORITY_EQUIVOCATION')
    expect(f.peer.entries()).toEqual([first])
  })

  it('serializes independent log handles sharing one storage owner and protects configuration pins', async () => {
    const f = await fixture()
    const secondHandle = await ReferenceRecordLog.open(historyId, f.storage)
    await Promise.all([f.log.append(utf8('one')), secondHandle.append(utf8('two'))])
    expect((await f.log.read()).map((entry) => entry.position)).toEqual([1, 2])
    const exposed = f.peer.configuration
    exposed.authorityPublicKey.fill(0)
    exposed.executionManifestDigest.fill(0)
    for (const entry of await f.log.read()) await f.peer.ingest({ kind: 'ordered-entry', entry })
    await f.peer.ingest({ kind: 'prefix-certificate', certificate: await f.authority.certify() })
    expect(f.peer.progress.finalThrough).toBe(2)
  })

  it('rejects altered bytes, configuration, signature and conflicting committed positions', async () => {
    const f = await fixture()
    const entry = await f.log.append(utf8('one'))
    await expect(f.peer.ingest({ kind: 'ordered-entry', entry: { ...entry, bytes: utf8('tampered') } })).rejects.toThrow('DIGEST_MISMATCH')
    const certificate = await f.authority.certify()
    const altered = structuredClone(certificate); altered.signature[0]! ^= 1
    await expect(f.peer.ingest({ kind: 'prefix-certificate', certificate: altered })).rejects.toThrow('SIGNATURE_INVALID')
    const other = await CoordinatedHistoryPolicy.open({ ...f.configuration, executionManifestDigest: new Uint8Array(32).fill(4) }, new MemoryOperationStore())
    await expect(other.ingest({ kind: 'prefix-certificate', certificate })).rejects.toThrow('CONFIGURATION_MISMATCH')
    await f.peer.ingest({ kind: 'ordered-entry', entry })
    await f.peer.ingest({ kind: 'prefix-certificate', certificate })
    const restoredOldLog = await ReferenceRecordLog.open(historyId, new MemoryOperationStore())
    const conflicting = await restoredOldLog.append(utf8('replacement'))
    await expect(f.peer.ingest({ kind: 'ordered-entry', entry: conflicting })).rejects.toThrow('POSITION_CONFLICT')
    expect(f.peer.progress.finalThrough).toBe(1)
  })

  it('does not publish in-memory progress when the durable write fails', async () => {
    const f = await fixture()
    const store = { get: async () => null, put: async () => { throw new Error('disk full') } }
    const peer = await CoordinatedHistoryPolicy.open(f.configuration, store)
    await expect(peer.ingest({ kind: 'ordered-entry', entry: await f.log.append(utf8('one')) })).rejects.toThrow('disk full')
    expect(peer.progress.verifiedThrough).toBe(0)
  })

  it('retains a complete bounded page once and validates exact retries without writing', async () => {
    const f = await fixture(), storage = new MemoryOperationStore()
    let writes = 0
    const peer = await CoordinatedHistoryPolicy.open(f.configuration, {
      get: key => storage.get(key), put: async (key, value) => { await storage.put(key, value); writes += 1 },
    })
    const entries = await Promise.all(Array.from({ length: 128 }, (_, i) => f.log.append(utf8(`entry-${i}`))))
    const certificate = await f.authority.certify()
    const batch = [...entries.map(entry => ({ kind: 'ordered-entry' as const, entry })), { kind: 'prefix-certificate' as const, certificate }]
    await peer.ingestBatch(batch)
    expect(writes).toBe(1)
    expect(peer.entries()).toEqual(entries)
    expect((await CoordinatedHistoryPolicy.open(f.configuration, storage)).progress).toEqual(peer.progress)
    await peer.ingestBatch(batch)
    await peer.ingest({ kind: 'prefix-certificate', certificate })
    expect(writes).toBe(1)
    const altered = structuredClone(certificate); altered.signature[0]! ^= 1
    await expect(peer.ingest({ kind: 'prefix-certificate', certificate: altered })).rejects.toThrow('SIGNATURE_INVALID')
    await expect(peer.ingestBatch([...batch, batch[0]!])).rejects.toThrow('HISTORY_EVIDENCE_BATCH_INVALID')
    expect(writes).toBe(1)
  })

  it('rejects an invalid late item without retaining an earlier part of its batch', async () => {
    const f = await fixture()
    const one = await f.log.append(utf8('one')), two = await f.log.append(utf8('two'))
    await expect(f.peer.ingestBatch([
      { kind: 'ordered-entry', entry: one },
      { kind: 'ordered-entry', entry: { ...two, bytes: utf8('tampered') } },
      { kind: 'prefix-certificate', certificate: await f.authority.certify() },
    ])).rejects.toThrow('DIGEST_MISMATCH')
    expect(f.peer.evidence()).toEqual([])
    expect((await CoordinatedHistoryPolicy.open(f.configuration, f.peerStorage)).evidence()).toEqual([])
  })

  it('refuses a conflicting certified batch without replacing the existing final prefix', async () => {
    const f = await fixture()
    const first = await f.log.append(utf8('original'))
    await f.peer.ingestBatch([{ kind: 'ordered-entry', entry: first }, { kind: 'prefix-certificate', certificate: await f.authority.certify() }])
    const fork = await ReferenceRecordLog.open(historyId, new MemoryOperationStore())
    await fork.append(utf8('forked first'))
    const successor = await fork.append(utf8('forked successor'))
    const authority = createPrefixAuthority({ configuration: f.configuration, identity: f.identity, readHead: () => fork.head() })
    await expect(f.peer.ingestBatch([
      { kind: 'ordered-entry', entry: successor }, { kind: 'prefix-certificate', certificate: await authority.certify() },
    ])).rejects.toThrow('HISTORY_AUTHORITY_EQUIVOCATION')
    expect(f.peer.entries()).toEqual([first])
    expect((await CoordinatedHistoryPolicy.open(f.configuration, f.peerStorage)).entries()).toEqual([first])
  })

  it('keeps a failed batch unpublished and permits the exact page after storage recovery', async () => {
    const f = await fixture(), storage = new MemoryOperationStore()
    let full = true
    const peer = await CoordinatedHistoryPolicy.open(f.configuration, {
      get: key => storage.get(key), put: async (key, value) => { if (full) throw new Error('disk full'); await storage.put(key, value) },
    })
    const entry = await f.log.append(utf8('one')), certificate = await f.authority.certify()
    const batch = [{ kind: 'ordered-entry' as const, entry }, { kind: 'prefix-certificate' as const, certificate }]
    await expect(peer.ingestBatch(batch)).rejects.toThrow('disk full')
    expect(peer.evidence()).toEqual([])
    expect((await CoordinatedHistoryPolicy.open(f.configuration, storage)).progress.finalThrough).toBe(0)
    full = false
    await peer.ingestBatch(batch)
    expect(peer.progress.finalThrough).toBe(1)
  })

  it('signs a head it reads and binds empty histories', async () => {
    const f = await fixture()
    const certificate = await f.authority.certify()
    expect(certificate.position).toBe(0)
    expect(certificate.root).toBe(await orderedGenesisRoot(historyId))
    await f.peer.ingest({ kind: 'prefix-certificate', certificate })
    await expect(CoordinatedHistoryPolicy.open({ ...f.configuration, historyId: 'h_00000000000000000000000000000000' }, f.peerStorage)).rejects.toThrow('CONFIGURATION_MISMATCH')
  })
})

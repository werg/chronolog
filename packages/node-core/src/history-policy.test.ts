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
  return { configuration, storage, log, authority, peer, peerStorage }
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
    expect(f.peer.progress).toMatchObject({ verifiedThrough: 1, certifiedThrough: 3, finalThrough: 0, missing: [2] })
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
    expect(f.peer.progress).toMatchObject({ verifiedThrough: 2, finalThrough: 1 })
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

  it('signs a head it reads and binds empty histories', async () => {
    const f = await fixture()
    const certificate = await f.authority.certify()
    expect(certificate.position).toBe(0)
    expect(certificate.root).toBe(await orderedGenesisRoot(historyId))
    await f.peer.ingest({ kind: 'prefix-certificate', certificate })
    await expect(CoordinatedHistoryPolicy.open({ ...f.configuration, historyId: 'h_00000000000000000000000000000000' }, f.peerStorage)).rejects.toThrow('CONFIGURATION_MISMATCH')
  })
})

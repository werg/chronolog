import { bytesToHex } from '@chronolog/canonical'
import { encodeCanonicalCbor, generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import {
  CoordinatedHistoryPolicy, ReferenceRecordLog, createPrefixAuthority, encodeHistoryConfiguration,
  encodeOrderingEvidence, orderedEntryRoot, orderedGenesisRoot, orderedRecordId,
} from './history-policy.js'
import type { CoordinatedHistoryConfiguration, OrderedRecordEntry } from './history-policy.js'
import { MemoryOperationStore } from './operations.js'

describe('retained history decode bounds', () => {
  it('reopens and extends a valid retained log/evidence checkpoint beyond the wire decoder ceiling', async () => {
    const identity = await generateEd25519KeyPair(), store = new MemoryOperationStore()
    const historyId = 'h_0123456789abcdef0123456789abcdef'
    const configuration: CoordinatedHistoryConfiguration = { kind: 'coordinated', historyId, authorityPublicKey: identity.publicKeyBytes,
      groupId: new Uint8Array(32).fill(81), genesisDigest: new Uint8Array(32).fill(82), executionManifestDigest: new Uint8Array(32).fill(83) }
    const entries: OrderedRecordEntry[] = []
    let root = await orderedGenesisRoot(historyId)
    for (let index = 0; index < 17; index += 1) {
      const bytes = new Uint8Array(1_048_576 - 1024).fill(index)
      const fields = { historyId, position: index + 1, previousRoot: root, recordId: await orderedRecordId(bytes) }
      root = await orderedEntryRoot(fields)
      entries.push({ ...fields, root, bytes })
    }
    const encoded = entries.map((entry) => encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
    await store.put(`record-log/${historyId}`, encodeCanonicalCbor(encoded))
    const log = await ReferenceRecordLog.open(historyId, store)
    expect((await log.head()).position).toBe(17)
    const next = await log.append(Uint8Array.of(99))
    expect(next.position).toBe(18)
    const authority = createPrefixAuthority({ configuration, identity, readHead: () => log.head() })
    const certificate = await authority.certify()
    const evidenceStore = new MemoryOperationStore()
    await evidenceStore.put(`history/${bytesToHex(configuration.groupId)}/coordinated`, encodeCanonicalCbor([
      1n, encodeHistoryConfiguration(configuration), [...encoded, encodeOrderingEvidence({ kind: 'ordered-entry', entry: next }),
        encodeOrderingEvidence({ kind: 'prefix-certificate', certificate })],
    ]))
    const policy = await CoordinatedHistoryPolicy.open(configuration, evidenceStore, { quotaBytes: 24 * 1024 * 1024 })
    expect(policy.progress.finalThrough).toBe(18)
    await policy.ingest({ kind: 'prefix-certificate', certificate })
    expect((await CoordinatedHistoryPolicy.open(configuration, evidenceStore)).progress.finalThrough).toBe(18)
  })

  it('refuses a local evidence quota before committing or advancing progress', async () => {
    const identity = await generateEd25519KeyPair(), store = new MemoryOperationStore()
    const configuration: CoordinatedHistoryConfiguration = { kind: 'coordinated', historyId: 'h_abcdef0123456789abcdef0123456789',
      authorityPublicKey: identity.publicKeyBytes, groupId: new Uint8Array(32).fill(91),
      genesisDigest: new Uint8Array(32).fill(92), executionManifestDigest: new Uint8Array(32).fill(93) }
    const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
    const entry = await log.append(new Uint8Array(2048))
    const policy = await CoordinatedHistoryPolicy.open(configuration, store, { quotaBytes: 1024 })
    await expect(policy.ingest({ kind: 'ordered-entry', entry })).rejects.toThrow('HISTORY_STORAGE_QUOTA_EXCEEDED')
    expect(policy.progress.receivedThrough).toBe(0)
    expect((await CoordinatedHistoryPolicy.open(configuration, store, { quotaBytes: 1024 })).progress.receivedThrough).toBe(0)
  })
})

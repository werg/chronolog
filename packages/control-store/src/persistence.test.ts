import { bytesToHex, sha256Sync, utf8 } from '@chronolog/canonical'
import { describe, expect, it } from 'vitest'

import { ControlStore } from './control-store.js'
import { decodeControlStoreJournal, decodeControlStoreSnapshot, encodeControlStoreJournalEntry, encodeControlStoreSnapshot } from './persistence.js'
import type { ControlStoreSnapshot } from './types.js'

function snapshot(): ControlStoreSnapshot {
  const store = new ControlStore()
  store.putCandidate({
    txId: Uint8Array.of(1), groupId: Uint8Array.of(2), candidateDigest: Uint8Array.of(3),
    validationPolicy: Uint8Array.of(4), canonicalPayload: Uint8Array.of(5), state: 'pending_validation',
    orderKey: { authorTimestampMs: 10n, authorId: Uint8Array.of(6), txId: Uint8Array.of(1) },
  })
  return store.snapshot()
}

describe('control index format', () => {
  it('round-trips a current snapshot and rejects old or transport-bearing order keys', () => {
    const input = snapshot(), encoded = encodeControlStoreSnapshot(input)
    expect(decodeControlStoreSnapshot(encoded)).toEqual(input)
    for (const state of ['waiting_for_payload', 'invalid_protocol', 'quarantined', 'inadmissible']) {
      expect(() => decodeControlStoreSnapshot(encoded.replace('pending_validation', state))).toThrow('CONTROL_STORE_SNAPSHOT_INVALID')
    }
    const bodyless = JSON.parse(encoded) as { candidates: Record<string, unknown>[] }
    delete bodyless.candidates[0]!.canonicalPayload
    expect(() => decodeControlStoreSnapshot(JSON.stringify(bodyless))).toThrow('CONTROL_STORE_SNAPSHOT_INVALID')
    const obsoletePolicy = { ...input, orderPolicy: 'peer' }
    expect(() => decodeControlStoreSnapshot(encodeControlStoreSnapshot(obsoletePolicy)))
      .toThrow('CONTROL_STORE_SNAPSHOT_INVALID')
    expect(() => decodeControlStoreSnapshot(encoded.replace('chronolog-control-store/v2', 'chronolog-control-store/v1')))
      .toThrow('CONTROL_STORE_UNSUPPORTED_FORMAT')
    const obsolete = { ...input, candidates: input.candidates.map(candidate => ({
      ...candidate, orderKey: { ...candidate.orderKey, authorFeedSequence: 7n },
    })) }
    expect(() => decodeControlStoreSnapshot(encodeControlStoreSnapshot(obsolete))).toThrow('CONTROL_STORE_SNAPSHOT_INVALID')
  })

  it('requires a current journal envelope and excludes transport sequence from candidate mutations', () => {
    const candidate = snapshot().candidates[0]!
    const entry = { sequence: 1n, operation: { kind: 'put_candidate' as const, candidate } }
    const encoded = encodeControlStoreJournalEntry(entry)
    expect(decodeControlStoreJournal(encoded)).toEqual([entry])
    const legacyBody = encoded.slice(17).trim().replace('"format":"chronolog-control-journal/v2",', '')
    const oldJournal = `${bytesToHex(sha256Sync(utf8(legacyBody))).slice(0, 16)} ${legacyBody}\n`
    expect(() => decodeControlStoreJournal(oldJournal)).toThrow('CONTROL_STORE_JOURNAL_INVALID')
    const obsolete = { ...entry, operation: { ...entry.operation, candidate: {
      ...candidate, orderKey: { ...candidate.orderKey, authorFeedSequence: 7n },
    } } }
    expect(() => decodeControlStoreJournal(encodeControlStoreJournalEntry(obsolete))).toThrow('CONTROL_STORE_JOURNAL_INVALID')
  })
})

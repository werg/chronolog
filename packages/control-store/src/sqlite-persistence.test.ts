import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { ControlStore } from './control-store.js'
import { encodeControlStoreSnapshot } from './persistence.js'
import { NodeStateDatabase, SqliteControlStorePersistence } from './sqlite-persistence.js'

const directories: string[] = []
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }) })

function path(): string {
  const directory = mkdtempSync(join(tmpdir(), 'chronolog-node-state-'))
  directories.push(directory)
  return join(directory, 'node-state.sqlite')
}

function addCandidates(store: ControlStore, from: number, to: number): void {
  for (let id = from; id <= to; id += 1) {
    store.putCandidate({
      txId: Uint8Array.of(id),
      groupId: Uint8Array.of(1),
      candidateDigest: Uint8Array.of(100 + id),
      validationPolicy: Uint8Array.of(2),
      orderKey: { authorTimestampMs: BigInt(id), authorId: Uint8Array.of(3), txId: Uint8Array.of(id) },
      canonicalPayload: Uint8Array.of(4, id),
      state: 'pending_validation',
    })
    store.setCandidateState(Uint8Array.of(id), 'admissible', { proofAttestationIds: [] })
  }
}

function open(file: string, compactAfterEntries?: number): { store: ControlStore; state: NodeStateDatabase } {
  const state = new NodeStateDatabase(file)
  return { state, store: new ControlStore(new SqliteControlStorePersistence(state, compactAfterEntries === undefined ? {} : { compactAfterEntries })) }
}

describe('SqliteControlStorePersistence', () => {
  it('journals mutations and restores the exact index after reopen', () => {
    const file = path()
    const first = open(file)
    addCandidates(first.store, 1, 30)
    first.store.flush()
    const expected = encodeControlStoreSnapshot(first.store.snapshot())
    first.state.close()

    const second = open(file)
    expect(encodeControlStoreSnapshot(second.store.snapshot())).toBe(expected)
    addCandidates(second.store, 31, 32)
    second.store.flush()
    const next = encodeControlStoreSnapshot(second.store.snapshot())
    second.state.close()
    const third = open(file)
    expect(encodeControlStoreSnapshot(third.store.snapshot())).toBe(next)
    third.state.close()
  })

  it('compacts the journal into a snapshot without changing state', () => {
    const file = path()
    const first = open(file, 8)
    addCandidates(first.store, 1, 20)
    first.store.flush()
    const expected = encodeControlStoreSnapshot(first.store.snapshot())
    const journal = first.state.database.prepare('SELECT count(*) AS n FROM control_journal').get() as { n: number }
    expect(Number(journal.n)).toBeLessThan(40)
    first.state.close()
    const reopened = open(file, 8)
    expect(encodeControlStoreSnapshot(reopened.store.snapshot())).toBe(expected)
    reopened.state.close()
  })

  it('persists validator cutoffs synchronously and never lets them regress', () => {
    const file = path()
    const first = open(file)
    first.store.persistValidatorCutoff(Uint8Array.of(7), 123n)
    first.state.close()
    const second = open(file)
    expect(second.store.validatorCutoff(Uint8Array.of(7))).toBe(123n)
    expect(() => second.store.persistValidatorCutoff(Uint8Array.of(7), 100n)).toThrow()
    second.store.persistValidatorCutoff(Uint8Array.of(7), 200n)
    second.state.close()
    const third = open(file)
    expect(third.store.validatorCutoff(Uint8Array.of(7))).toBe(200n)
    third.state.close()
  })
})

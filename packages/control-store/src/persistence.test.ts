import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { ControlStore } from './control-store.js'
import {
  JsonFileControlStorePersistence,
  MemoryControlStorePersistence,
  encodeControlStoreSnapshot,
  readControlStoreSnapshot,
} from './persistence.js'
import type { PutCandidateInput, StoredAttestation } from './types.js'

const directories: string[] = []

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true })
})

describe('JsonFileControlStorePersistence', () => {
  it('coalesces rebuildable snapshots and flushes the latest state on demand', () => {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-control-persistence-'))
    directories.push(directory)
    const path = join(directory, 'control.json')
    const store = new ControlStore(new JsonFileControlStorePersistence(path))
    for (let id = 1; id <= 20; id += 1) {
      store.putCandidate({
        txId: Uint8Array.of(id),
        groupId: Uint8Array.of(1),
        candidateDigest: Uint8Array.of(100 + id),
        validationPolicy: Uint8Array.of(2),
        orderKey: {
          authorTimestampMs: BigInt(id),
          authorId: Uint8Array.of(3),
          authorFeedSequence: BigInt(id),
          txId: Uint8Array.of(id),
        },
        canonicalPayload: Uint8Array.of(4, id),
        state: 'pending_validation',
      })
    }
    expect(existsSync(path)).toBe(false)

    store.flush()
    const restored = new ControlStore(new JsonFileControlStorePersistence(path))
    expect(restored.listCandidates()).toHaveLength(20)
    expect(restored.sequence).toBe(store.sequence)
  })

  it('persists validator cutoff signing state synchronously', () => {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-cutoff-persistence-'))
    directories.push(directory)
    const path = join(directory, 'control.json')
    const store = new ControlStore(new JsonFileControlStorePersistence(path))

    store.persistValidatorCutoff(Uint8Array.of(7), 123n)

    expect(existsSync(path)).toBe(false)
    expect(existsSync(`${path}.validator-cutoffs`)).toBe(true)
    const restored = new ControlStore(new JsonFileControlStorePersistence(path))
    expect(restored.validatorCutoff(Uint8Array.of(7))).toBe(123n)
  })

  it('preserves a persisted but unpublished cutoff when the rebuildable snapshot is corrupt', () => {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-cutoff-recovery-'))
    directories.push(directory)
    const path = join(directory, 'control.json')
    const validatorId = Uint8Array.of(7)
    const store = new ControlStore(new JsonFileControlStorePersistence(path))
    store.persistValidatorCutoff(validatorId, 500n)
    // Simulate a crash after the cutoff journal commit but before publishing
    // an attestation/heartbeat, followed by damage to the rebuildable index.
    writeFileSync(path, '{corrupt rebuildable snapshot', 'utf8')

    const restored = new ControlStore(new JsonFileControlStorePersistence(path))

    expect(restored.validatorCutoff(validatorId)).toBe(500n)
    expect(restored.sequence).toBe(0n)
    expect(readdirSync(directory).some((name) => name.startsWith('control.json.corrupt-'))).toBe(true)
  })

  it('migrates a higher legacy snapshot cutoff into the independent journal', () => {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-cutoff-migration-'))
    directories.push(directory)
    const path = join(directory, 'control.json')
    const validatorId = Uint8Array.of(8)
    const persistence = new JsonFileControlStorePersistence(path)
    new ControlStore(persistence) // establishes an empty v1 cutoff journal
    const legacy = new ControlStore()
    legacy.persistValidatorCutoff(validatorId, 700n)
    persistence.save(legacy.snapshot())

    expect(new ControlStore(new JsonFileControlStorePersistence(path)).validatorCutoff(validatorId)).toBe(700n)
    writeFileSync(path, '{corrupt after migration', 'utf8')
    expect(new ControlStore(new JsonFileControlStorePersistence(path)).validatorCutoff(validatorId)).toBe(700n)
  })

  it('rolls back an in-memory cutoff when its durable write fails so it can be retried', () => {
    const delegate = new MemoryControlStorePersistence()
    let fail = true
    const store = new ControlStore({
      load: () => delegate.load(),
      save: (snapshot) => {
        if (fail) throw new Error('DISK_TEMPORARILY_UNAVAILABLE')
        delegate.save(snapshot)
      },
    })

    expect(() => store.persistValidatorCutoff(Uint8Array.of(7), 123n)).toThrow(
      'DISK_TEMPORARILY_UNAVAILABLE',
    )
    expect(store.validatorCutoff(Uint8Array.of(7))).toBeNull()
    fail = false
    store.persistValidatorCutoff(Uint8Array.of(7), 123n)
    expect(new ControlStore(delegate).validatorCutoff(Uint8Array.of(7))).toBe(123n)
  })

  it('quarantines corrupt rebuildable snapshots and starts from an empty index', () => {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-corrupt-persistence-'))
    directories.push(directory)
    const path = join(directory, 'control.json')
    new ControlStore(new JsonFileControlStorePersistence(path))
    writeFileSync(path, '{invalid json', 'utf8')

    const store = new ControlStore(new JsonFileControlStorePersistence(path))

    expect(store.sequence).toBe(0n)
    expect(existsSync(path)).toBe(false)
    expect(readdirSync(directory).some((name) => name.startsWith('control.json.corrupt-'))).toBe(true)
  })

  it('quarantines structurally invalid snapshots discovered during restoration', () => {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-structural-persistence-'))
    directories.push(directory)
    const path = join(directory, 'control.json')
    new ControlStore(new JsonFileControlStorePersistence(path))
    writeFileSync(path, JSON.stringify({ format: 'chronolog-control-store/v1' }), 'utf8')

    const store = new ControlStore(new JsonFileControlStorePersistence(path))

    expect(store.listCandidates()).toEqual([])
    expect(readdirSync(directory).some((name) => name.startsWith('control.json.corrupt-'))).toBe(true)
  })

  it('fails closed when a corrupt legacy snapshot has no cutoff journal', () => {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-missing-cutoff-journal-'))
    directories.push(directory)
    const path = join(directory, 'control.json')
    writeFileSync(path, '{invalid json', 'utf8')

    expect(() => new ControlStore(new JsonFileControlStorePersistence(path))).toThrow(
      'CONTROL_STORE_CUTOFF_JOURNAL_MISSING',
    )
    expect(existsSync(path)).toBe(true)
  })
})

describe('JsonFileControlStorePersistence journal', () => {
  function temporaryPath(): string {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-control-journal-'))
    directories.push(directory)
    return join(directory, 'control.json')
  }

  const bytes = (...values: number[]) => Uint8Array.from(values)
  function candidate(id: number): PutCandidateInput {
    return {
      txId: bytes(id),
      groupId: bytes(1),
      candidateDigest: bytes(100, id),
      validationPolicy: bytes(2),
      orderKey: {
        authorTimestampMs: BigInt(1_000 - id),
        authorId: bytes(3),
        authorFeedSequence: BigInt(id),
        txId: bytes(id),
      },
      canonicalPayload: bytes(4, id),
      state: 'pending_validation',
    }
  }
  function attestation(id: number): StoredAttestation {
    return {
      attestationId: bytes(50, id),
      txId: bytes(id),
      validatorId: bytes(9),
      validatorCapability: bytes(9, 1),
      membershipRevision: bytes(1),
      candidateDigest: bytes(100, id),
      validatorFeedSequence: BigInt(id),
      authorTimestampMs: BigInt(1_000 - id),
      acceptedAboveMs: 0n,
      policyVersion: 1n,
      transportAuthor: '@validator.ed25519',
    }
  }
  /** Exercises every journaled operation kind; admission inserts out of order. */
  function mutate(store: ControlStore, from: number, to: number): void {
    for (let id = from; id <= to; id += 1) {
      store.putCandidate(candidate(id))
      store.putAttestation(attestation(id))
      store.setCandidateState(bytes(id), 'admissible', { proofAttestationIds: [bytes(50, id)] })
      store.recordHeartbeat({
        heartbeatId: bytes(60, id),
        validatorId: bytes(9),
        validatorCapability: bytes(9, 1),
        membershipRevision: bytes(1),
        validatorFeedSequence: BigInt(100 + id),
        acceptanceCutoffMs: BigInt(id),
        feedContiguous: true,
      })
      store.publishMaterializedHead({
        localRevision: BigInt(id),
        headRef: `rev-${id}`,
        orderLength: store.orderedTransactionIds().length,
        orderDigest: bytes(70, id),
      })
      store.putCheckpoint({
        prefixLength: store.orderedTransactionIds().length,
        checkpointRef: `cp-${id}`,
        prefixDigest: bytes(80, id),
        pinned: id % 2 === 0,
      })
    }
  }
  const encoded = (store: ControlStore) => encodeControlStoreSnapshot(store.snapshot())
  const journalLines = (path: string) => readFileSync(`${path}.journal`, 'utf8').split('\n').filter((line) => line !== '')

  it('appends operations instead of rewriting the snapshot and replays them exactly', () => {
    const path = temporaryPath()
    const store = new ControlStore(new JsonFileControlStorePersistence(path))
    mutate(store, 1, 3)
    store.flush()
    expect(existsSync(path)).toBe(false)
    const firstFlush = statSync(`${path}.journal`).size
    expect(journalLines(path)).toHaveLength(18)
    mutate(store, 4, 5)
    store.flush()
    // The earlier bytes are untouched; only the new operations were appended.
    expect(statSync(`${path}.journal`).size).toBeGreaterThan(firstFlush)
    expect(journalLines(path)).toHaveLength(30)
    expect(existsSync(path)).toBe(false)

    expect(readControlStoreSnapshot(path)).toEqual(store.snapshot())
    expect(existsSync(`${path}.journal`)).toBe(true) // the reader is read-only

    const reopened = new ControlStore(new JsonFileControlStorePersistence(path))
    expect(encoded(reopened)).toBe(encoded(store))
    expect(reopened.changesSince(10n)).toEqual(store.changesSince(10n))
    // Reopening compacts the journal into the snapshot.
    expect(existsSync(`${path}.journal`)).toBe(false)
    expect(existsSync(path)).toBe(true)
    mutate(reopened, 6, 6)
    reopened.flush()
    expect(journalLines(path)).toHaveLength(6)
    expect(encoded(new ControlStore(new JsonFileControlStorePersistence(path)))).toBe(encoded(reopened))
  })

  it('coalesces appends and compacts after the configured number of entries', async () => {
    const path = temporaryPath()
    const store = new ControlStore(new JsonFileControlStorePersistence(path, { compactAfterEntries: 10, flushDelayMs: 5 }))
    mutate(store, 1, 1)
    expect(existsSync(`${path}.journal`)).toBe(false) // buffered until the flush window
    await new Promise((resolve) => setTimeout(resolve, 30))
    expect(journalLines(path)).toHaveLength(6)
    mutate(store, 2, 2) // twelve entries: compaction requested
    store.flush()
    expect(existsSync(`${path}.journal`)).toBe(false)
    expect(encoded(new ControlStore(new JsonFileControlStorePersistence(path)))).toBe(encoded(store))
  })

  it('ignores a torn final append and compacts it away before appending', () => {
    const path = temporaryPath()
    const store = new ControlStore(new JsonFileControlStorePersistence(path))
    mutate(store, 1, 2)
    store.flush()
    const complete = new ControlStore(new MemoryControlStorePersistence())
    mutate(complete, 1, 2)
    // Crash in the middle of the next appended batch.
    mutate(store, 3, 3)
    store.flush()
    const journal = readFileSync(`${path}.journal`, 'utf8')
    const lines = journal.split('\n')
    const torn = `${lines.slice(0, 12).join('\n')}\n${lines[12]!.slice(0, 40)}`
    writeFileSync(`${path}.journal`, torn)

    const reopened = new ControlStore(new JsonFileControlStorePersistence(path))
    expect(encoded(reopened)).toBe(encoded(complete))
    expect(existsSync(`${path}.journal`)).toBe(false)
    mutate(reopened, 3, 3)
    reopened.flush()
    expect(encoded(new ControlStore(new JsonFileControlStorePersistence(path)))).toBe(encoded(reopened))
  })

  it('skips entries already contained in a snapshot written just before a crash', () => {
    const path = temporaryPath()
    const persistence = new JsonFileControlStorePersistence(path)
    const store = new ControlStore(persistence)
    mutate(store, 1, 2)
    store.flush()
    const journal = readFileSync(`${path}.journal`, 'utf8')
    // Crash after the compacted snapshot was renamed into place but before
    // the journal was removed.
    persistence.save(store.snapshot())
    writeFileSync(`${path}.journal`, journal)
    expect(encoded(new ControlStore(new JsonFileControlStorePersistence(path)))).toBe(encoded(store))
  })

  it('quarantines snapshot and journal on corruption other than a torn tail', () => {
    for (const damage of [
      (lines: string[]) => { lines[3] = lines[3]!.replace('"', "'") }, // checksum mismatch
      (lines: string[]) => { lines.splice(4, 1) }, // intact lines, missing operation
      (lines: string[]) => { lines.splice(5, 0, lines[5]!) }, // duplicated operation
    ]) {
      const path = temporaryPath()
      const store = new ControlStore(new JsonFileControlStorePersistence(path))
      store.persistValidatorCutoff(bytes(9), 777n)
      mutate(store, 1, 2)
      store.flush()
      const lines = readFileSync(`${path}.journal`, 'utf8').split('\n')
      damage(lines)
      writeFileSync(`${path}.journal`, lines.join('\n'))

      const restored = new ControlStore(new JsonFileControlStorePersistence(path))
      expect(restored.sequence).toBe(0n)
      expect(restored.validatorCutoff(bytes(9))).toBe(777n)
      const names = readdirSync(join(path, '..'))
      expect(names.some((name) => name.startsWith('control.json.journal.corrupt-'))).toBe(true)
      expect(existsSync(`${path}.journal`)).toBe(false)
    }
  })

  it('fails closed on a corrupt journal when no cutoff journal exists', () => {
    const path = temporaryPath()
    const store = new ControlStore(new JsonFileControlStorePersistence(path))
    mutate(store, 1, 1)
    store.flush()
    rmSync(`${path}.validator-cutoffs`)
    appendFileSync(`${path}.journal`, 'not a journal line\n')
    expect(() => new ControlStore(new JsonFileControlStorePersistence(path))).toThrow('CONTROL_STORE_JOURNAL_INVALID')
    expect(existsSync(`${path}.journal`)).toBe(true)
  })

  it('keeps validator cutoffs synchronous while index operations are buffered', () => {
    const path = temporaryPath()
    const store = new ControlStore(new JsonFileControlStorePersistence(path))
    mutate(store, 1, 1)
    store.persistValidatorCutoff(bytes(9), 900n)
    // Crash before the buffered journal flush: the index operations are lost
    // (they are rebuilt from the transport), the signing cutoff is not.
    const restored = new ControlStore(new JsonFileControlStorePersistence(path))
    expect(restored.validatorCutoff(bytes(9))).toBe(900n)
    expect(restored.sequence).toBe(0n)
  })
})

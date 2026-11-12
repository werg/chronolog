import { createHash } from 'node:crypto'
import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { dirname } from 'node:path'

import { ControlStore } from './control-store.js'
import type {
  ControlStoreJournalEntry,
  ControlStorePersistence,
  ControlStoreSnapshot,
  ValidatorCutoffState,
} from './types.js'

const BYTES_TAG = '$chronologBytes'
const BIGINT_TAG = '$chronologBigInt'

function encodeTagged(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => {
    if (typeof item === 'bigint') return { [BIGINT_TAG]: item.toString(10) }
    if (item instanceof Uint8Array) {
      return { [BYTES_TAG]: Buffer.from(item).toString('base64') }
    }
    return item
  })
}

function decodeTagged(text: string): unknown {
  return JSON.parse(text, (_key, value: unknown) => {
    if (isTagged(value, BIGINT_TAG)) return BigInt(value[BIGINT_TAG]!)
    if (isTagged(value, BYTES_TAG)) {
      return Uint8Array.from(Buffer.from(value[BYTES_TAG]!, 'base64'))
    }
    return value
  })
}

export function encodeControlStoreSnapshot(snapshot: ControlStoreSnapshot): string {
  return encodeTagged(snapshot)
}

export function decodeControlStoreSnapshot(text: string): ControlStoreSnapshot {
  const parsed = decodeTagged(text) as ControlStoreSnapshot

  if (parsed.format !== 'chronolog-control-store/v1') {
    throw new Error('CONTROL_STORE_UNSUPPORTED_FORMAT')
  }
  return parsed
}

const JOURNAL_CHECKSUM_LENGTH = 16
const JOURNAL_OPERATION_KINDS = new Set([
  'put_candidate',
  'put_attestation',
  'set_candidate_state',
  'record_heartbeat',
  'publish_materialized_head',
  'put_checkpoint',
])

/** One journal line: a truncated SHA-256 of the body, a space, the body. */
export function encodeControlStoreJournalEntry(entry: ControlStoreJournalEntry): string {
  const body = encodeTagged({ sequence: entry.sequence, operation: entry.operation })
  return `${journalChecksum(body)} ${body}\n`
}

/**
 * Decodes a journal file. Only the text after the last newline may be
 * incomplete: it is an append torn by a crash, whose operation had not been
 * reported durable, and is ignored. Any other malformed line fails closed.
 */
export function decodeControlStoreJournal(text: string): ControlStoreJournalEntry[] {
  const lines = text.split('\n')
  return lines.slice(0, -1).map((line) => {
    const body = line.slice(JOURNAL_CHECKSUM_LENGTH + 1)
    if (line[JOURNAL_CHECKSUM_LENGTH] !== ' ' || line.slice(0, JOURNAL_CHECKSUM_LENGTH) !== journalChecksum(body)) {
      throw new Error('CONTROL_STORE_JOURNAL_INVALID')
    }
    let value: unknown
    try { value = decodeTagged(body) } catch (error) {
      throw new Error('CONTROL_STORE_JOURNAL_INVALID', { cause: error })
    }
    if (
      !isRecord(value) || typeof value.sequence !== 'bigint' || value.sequence < 1n ||
      !isRecord(value.operation) || typeof value.operation.kind !== 'string' ||
      !JOURNAL_OPERATION_KINDS.has(value.operation.kind)
    ) throw new Error('CONTROL_STORE_JOURNAL_INVALID')
    return value as unknown as ControlStoreJournalEntry
  })
}

function journalChecksum(body: string): string {
  return createHash('sha256').update(body, 'utf8').digest('hex').slice(0, JOURNAL_CHECKSUM_LENGTH)
}

function isTagged(value: unknown, tag: string): value is Record<string, string> {
  return (
    typeof value === 'object' &&
    value !== null &&
    Object.keys(value).length === 1 &&
    typeof (value as Record<string, unknown>)[tag] === 'string'
  )
}

export class MemoryControlStorePersistence implements ControlStorePersistence {
  #encoded: string | null = null
  readonly #cutoffs = new Map<string, ValidatorCutoffState>()

  load(): ControlStoreSnapshot | null {
    return this.#encoded === null ? null : decodeControlStoreSnapshot(this.#encoded)
  }

  save(snapshot: ControlStoreSnapshot): void {
    this.#encoded = encodeControlStoreSnapshot(snapshot)
  }

  loadValidatorCutoffs(): readonly ValidatorCutoffState[] {
    return [...this.#cutoffs.values()].map(cloneCutoff)
  }

  initializeValidatorCutoffs(cutoffs: readonly ValidatorCutoffState[]): void {
    for (const cutoff of cutoffs) this.saveValidatorCutoff(cutoff)
  }

  saveValidatorCutoff(cutoff: ValidatorCutoffState): void {
    const key = Buffer.from(cutoff.validatorId).toString('base64url')
    const previous = this.#cutoffs.get(key)
    if (previous !== undefined && cutoff.acceptedAboveMs < previous.acceptedAboveMs) {
      throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_REGRESSION')
    }
    this.#cutoffs.set(key, cloneCutoff(cutoff))
  }
}

export interface JsonFileControlStorePersistenceOptions {
  /**
   * Minimum journal entries before compaction. Compaction additionally waits
   * until the journal is at least as large as the last snapshot, so the
   * amortized bytes written per operation stay constant as history grows.
   */
  readonly compactAfterEntries?: number
  /** Coalescing window for journal appends and snapshot writes. */
  readonly flushDelayMs?: number
}

/**
 * Crash-safe persistence for the rebuildable control index: a snapshot
 * (`control.json`, written atomically) plus an append-only operation journal
 * (`control.json.journal`). Mutations are buffered and appended in one write
 * plus fsync at most once per flush window, so per-mutation cost no longer
 * grows with history. The journal is compacted into a fresh snapshot on open
 * and once it holds `compactAfterEntries` entries and at least as many bytes
 * as the previous snapshot. Validator signing cutoffs are not
 * rebuildable and live in a separate file that is written synchronously.
 */
export class JsonFileControlStorePersistence implements ControlStorePersistence {
  readonly #path: string
  readonly #journalPath: string
  readonly #cutoffPath: string
  readonly #compactAfterEntries: number
  readonly #flushDelayMs: number
  #cutoffs: Map<string, ValidatorCutoffState> | null = null
  #pendingSnapshot: (() => ControlStoreSnapshot) | null = null
  #pendingJournal: string[] = []
  #journalEntries = 0
  #journalBytes = 0
  #snapshotBytes = 0
  #journalPresent = false
  #saveTimer: ReturnType<typeof setTimeout> | undefined

  constructor(path: string, options: JsonFileControlStorePersistenceOptions = {}) {
    this.#path = path
    this.#journalPath = `${path}.journal`
    this.#cutoffPath = `${path}.validator-cutoffs`
    this.#compactAfterEntries = options.compactAfterEntries ?? 1_024
    this.#flushDelayMs = options.flushDelayMs ?? 100
    if (!Number.isSafeInteger(this.#compactAfterEntries) || this.#compactAfterEntries < 1) {
      throw new RangeError('CONTROL_STORE_INVALID_COMPACTION_INTERVAL')
    }
  }

  load(): ControlStoreSnapshot | null {
    this.flush()
    try {
      const text = readFileSync(this.#path, 'utf8')
      this.#snapshotBytes = Buffer.byteLength(text)
      return decodeControlStoreSnapshot(text)
    } catch (error) {
      if (isMissingFile(error)) return null
      if (isCorruptSnapshot(error)) {
        if (!existsSync(this.#cutoffPath)) {
          throw new Error('CONTROL_STORE_CUTOFF_JOURNAL_MISSING', { cause: error })
        }
        this.#quarantine()
        return null
      }
      throw error
    }
  }

  /** Writes a full snapshot atomically; it supersedes every journal entry. */
  save(snapshot: ControlStoreSnapshot): void {
    this.#write(snapshot)
  }

  loadJournal(): readonly ControlStoreJournalEntry[] {
    let text: string
    try {
      text = readFileSync(this.#journalPath, 'utf8')
    } catch (error) {
      if (isMissingFile(error)) {
        this.#journalPresent = false
        this.#journalEntries = 0
        this.#journalBytes = 0
        return []
      }
      throw error
    }
    this.#journalPresent = true
    const entries = decodeControlStoreJournal(text)
    this.#journalEntries = entries.length
    this.#journalBytes = Buffer.byteLength(text)
    return entries
  }

  journalPresent(): boolean {
    return this.#journalPresent
  }

  appendJournal(entry: ControlStoreJournalEntry): boolean {
    const line = encodeControlStoreJournalEntry(entry)
    this.#pendingJournal.push(line)
    this.#journalEntries += 1
    this.#journalBytes += Buffer.byteLength(line)
    this.#scheduleFlush()
    return this.#journalEntries >= this.#compactAfterEntries && this.#journalBytes >= this.#snapshotBytes
  }

  loadValidatorCutoffs(): readonly ValidatorCutoffState[] | null {
    try {
      const cutoffs = decodeValidatorCutoffs(readFileSync(this.#cutoffPath, 'utf8'))
      this.#cutoffs = new Map(cutoffs.map((cutoff) => [cutoffKey(cutoff.validatorId), cutoff]))
      return cutoffs.map(cloneCutoff)
    } catch (error) {
      if (isMissingFile(error)) return null
      throw new Error('CONTROL_STORE_CUTOFF_JOURNAL_CORRUPT', { cause: error })
    }
  }

  initializeValidatorCutoffs(cutoffs: readonly ValidatorCutoffState[]): void {
    if (this.#cutoffs === null && existsSync(this.#cutoffPath)) this.loadValidatorCutoffs()
    this.#cutoffs ??= new Map()
    let changed = !existsSync(this.#cutoffPath)
    for (const cutoff of cutoffs) {
      const key = cutoffKey(cutoff.validatorId)
      const previous = this.#cutoffs.get(key)
      if (previous === undefined || cutoff.acceptedAboveMs > previous.acceptedAboveMs) {
        this.#cutoffs.set(key, cloneCutoff(cutoff))
        changed = true
      }
    }
    if (changed) this.#writeCutoffs()
  }

  saveValidatorCutoff(cutoff: ValidatorCutoffState): void {
    if (this.#cutoffs === null) this.loadValidatorCutoffs()
    this.#cutoffs ??= new Map()
    const key = cutoffKey(cutoff.validatorId)
    const previous = this.#cutoffs.get(key)
    if (previous !== undefined && cutoff.acceptedAboveMs < previous.acceptedAboveMs) {
      throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_REGRESSION')
    }
    if (previous?.acceptedAboveMs === cutoff.acceptedAboveMs) return
    this.#cutoffs.set(key, cloneCutoff(cutoff))
    try {
      this.#writeCutoffs()
    } catch (error) {
      if (previous === undefined) this.#cutoffs.delete(key)
      else this.#cutoffs.set(key, previous)
      throw error
    }
  }

  requestSave(snapshot: () => ControlStoreSnapshot): void {
    this.#pendingSnapshot = snapshot
    this.#scheduleFlush()
  }

  flush(): void {
    if (this.#saveTimer !== undefined) {
      clearTimeout(this.#saveTimer)
      this.#saveTimer = undefined
    }
    const snapshot = this.#pendingSnapshot
    this.#pendingSnapshot = null
    if (snapshot !== null) {
      // The snapshot is taken now, so it contains every buffered operation.
      this.#write(snapshot())
      return
    }
    if (this.#pendingJournal.length === 0) return
    const lines = this.#pendingJournal.join('')
    mkdirSync(dirname(this.#journalPath), { recursive: true })
    const created = !existsSync(this.#journalPath)
    const descriptor = openSync(this.#journalPath, 'a', 0o600)
    try {
      const size = fstatSync(descriptor).size
      try {
        writeAll(descriptor, lines)
        fsyncSync(descriptor)
      } catch (error) {
        // Do not leave a partial line for a later append to follow; the
        // buffered entries stay pending and are retried on the next flush.
        try { ftruncateSync(descriptor, size) } catch { /* reported below */ }
        throw error
      }
    } finally {
      closeSync(descriptor)
    }
    if (created) syncPath(dirname(this.#journalPath))
    this.#journalPresent = true
    this.#pendingJournal = []
  }

  recoverCorruptSnapshot(error: unknown): boolean {
    // I/O failures are not corruption and must not discard state.
    if (isFileSystemError(error)) return false
    if (!existsSync(this.#cutoffPath)) return false
    this.#quarantine()
    return true
  }

  #scheduleFlush(): void {
    if (this.#saveTimer !== undefined) return
    this.#saveTimer = setTimeout(() => {
      this.#saveTimer = undefined
      this.flush()
    }, this.#flushDelayMs)
    this.#saveTimer.unref?.()
  }

  #write(snapshot: ControlStoreSnapshot): void {
    const encoded = encodeControlStoreSnapshot(snapshot)
    writeCrashSafe(this.#path, encoded)
    this.#snapshotBytes = Buffer.byteLength(encoded)
    this.#journalBytes = 0
    // Buffered operations are contained in the snapshot. A crash before the
    // journal is removed leaves entries at or below the snapshot sequence,
    // which replay skips.
    this.#pendingJournal = []
    this.#journalEntries = 0
    if (this.#journalPresent || existsSync(this.#journalPath)) {
      rmSync(this.#journalPath, { force: true })
      syncPath(dirname(this.#journalPath))
    }
    this.#journalPresent = false
  }

  #writeCutoffs(): void {
    writeCrashSafe(this.#cutoffPath, encodeValidatorCutoffs([...(this.#cutoffs?.values() ?? [])]))
  }

  #quarantine(): void {
    // The journal only has meaning on top of its snapshot; set both aside.
    const suffix = `corrupt-${process.pid}-${Date.now()}`
    for (const [source, target] of [
      [this.#path, `${this.#path}.${suffix}`],
      [this.#journalPath, `${this.#journalPath}.${suffix}`],
    ] as const) {
      try {
        renameSync(source, target)
      } catch (error) {
        if (!isMissingFile(error)) throw error
      }
    }
    syncPath(dirname(this.#path))
    this.#pendingJournal = []
    this.#journalEntries = 0
    this.#journalBytes = 0
    this.#journalPresent = false
  }
}

/**
 * Reads the effective control index (snapshot plus journal) without
 * quarantining, compacting or otherwise writing. For inspection tools.
 */
export function readControlStoreSnapshot(path: string): ControlStoreSnapshot | null {
  let snapshot: ControlStoreSnapshot | null = null
  try {
    snapshot = decodeControlStoreSnapshot(readFileSync(path, 'utf8'))
  } catch (error) {
    if (!isMissingFile(error)) throw error
  }
  let journal: ControlStoreJournalEntry[] = []
  try {
    journal = decodeControlStoreJournal(readFileSync(`${path}.journal`, 'utf8'))
  } catch (error) {
    if (!isMissingFile(error)) throw error
  }
  if (snapshot === null && journal.length === 0) return null
  return new ControlStore({ load: () => snapshot, save: () => {}, loadJournal: () => journal }).snapshot()
}

function writeAll(descriptor: number, text: string): void {
  const buffer = Buffer.from(text, 'utf8')
  let offset = 0
  while (offset < buffer.length) offset += writeSync(descriptor, buffer, offset, buffer.length - offset)
}

function isFileSystemError(error: unknown): boolean {
  return (
    typeof error === 'object' && error !== null &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { syscall?: unknown }).syscall === 'string'
  )
}

function writeCrashSafe(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true })
  const temporaryPath = `${path}.tmp`
  writeFileSync(temporaryPath, contents, {
    encoding: 'utf8',
    mode: 0o600,
  })
  syncPath(temporaryPath)
  // Only the rename needs a durable directory entry; the temporary name's
  // entry is irrelevant after a crash, so no directory fsync before it.
  renameSync(temporaryPath, path)
  syncPath(dirname(path))
}

function encodeValidatorCutoffs(cutoffs: readonly ValidatorCutoffState[]): string {
  return JSON.stringify({
    format: 'chronolog-validator-cutoffs/v1',
    cutoffs: cutoffs.map((cutoff) => ({
      validatorId: Buffer.from(cutoff.validatorId).toString('base64'),
      acceptedAboveMs: cutoff.acceptedAboveMs.toString(10),
    })),
  })
}

function decodeValidatorCutoffs(text: string): ValidatorCutoffState[] {
  const value = JSON.parse(text) as unknown
  if (!isRecord(value) || value.format !== 'chronolog-validator-cutoffs/v1' || !Array.isArray(value.cutoffs)) {
    throw new Error('CONTROL_STORE_CUTOFF_JOURNAL_INVALID')
  }
  const cutoffs = value.cutoffs.map((item) => {
    if (
      !isRecord(item) || typeof item.validatorId !== 'string' ||
      typeof item.acceptedAboveMs !== 'string' || !/^(0|[1-9][0-9]*)$/.test(item.acceptedAboveMs)
    ) throw new Error('CONTROL_STORE_CUTOFF_JOURNAL_INVALID')
    const validatorId = Uint8Array.from(Buffer.from(item.validatorId, 'base64'))
    if (
      validatorId.length === 0 ||
      Buffer.from(validatorId).toString('base64') !== item.validatorId
    ) throw new Error('CONTROL_STORE_CUTOFF_JOURNAL_INVALID')
    return { validatorId, acceptedAboveMs: BigInt(item.acceptedAboveMs) }
  })
  if (new Set(cutoffs.map((cutoff) => cutoffKey(cutoff.validatorId))).size !== cutoffs.length) {
    throw new Error('CONTROL_STORE_CUTOFF_JOURNAL_DUPLICATE')
  }
  return cutoffs
}

function cutoffKey(validatorId: Uint8Array): string {
  return Buffer.from(validatorId).toString('base64url')
}

function cloneCutoff(cutoff: ValidatorCutoffState): ValidatorCutoffState {
  return { validatorId: cutoff.validatorId.slice(), acceptedAboveMs: cutoff.acceptedAboveMs }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function syncPath(path: string): void {
  const descriptor = openSync(path, 'r')
  try {
    fsyncSync(descriptor)
  } finally {
    closeSync(descriptor)
  }
}

function isMissingFile(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'ENOENT'
  )
}

function isCorruptSnapshot(error: unknown): boolean {
  return error instanceof SyntaxError || (
    error instanceof Error && error.message.startsWith('CONTROL_STORE_')
  )
}

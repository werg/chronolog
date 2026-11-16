import { assertCanonicalCbor, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, equalBytes, sha256Sync, bytesToHex } from '@chronolog/canonical'
import {
  decodeControlStoreSnapshot, encodeControlStoreSnapshot, decodeControlStoreJournal, encodeControlStoreJournalEntry,
  type ControlStorePersistence, type ControlStoreSnapshot, type ControlStoreJournalEntry, type ValidatorCutoffState,
} from '@chronolog/control-store/browser'

export interface SyncDurableFile {
  getSize(): number
  read(buffer: Uint8Array, options: { at: number }): number
  write(buffer: Uint8Array, options: { at: number }): number
  truncate(size: number): void
  flush(): void
  close(): void
}

/**
 * SQL-free private control journal. Each checksum-protected frame is flushed
 * synchronously before acknowledgement, including irrecoverable signing
 * cutoffs. A partial unacknowledged tail is discarded; corrupt complete frames
 * fail closed. The owning Worker holds the database's exclusive Web Lock.
 */
export class SyncControlPersistence implements ControlStorePersistence {
  readonly #file: SyncDurableFile
  readonly #quota: number
  #offset = 0
  #snapshot: ControlStoreSnapshot | null = null
  #journal: ControlStoreJournalEntry[] = []
  readonly #cutoffs = new Map<string, ValidatorCutoffState>()
  #failed = false
  #closed = false

  constructor(file: SyncDurableFile, options: { readonly maxBytes?: number } = {}) {
    this.#file = file
    this.#quota = options.maxBytes ?? 64 * 1024 * 1024
    if (!Number.isSafeInteger(this.#quota) || this.#quota < 1024) throw new Error('CONTROL_STORE_QUOTA_INVALID')
    try {
      const size = file.getSize()
      if (size > this.#quota) throw new Error('CONTROL_STORE_QUOTA_EXCEEDED')
      const bytes = new Uint8Array(size)
      if (file.read(bytes, { at: 0 }) !== size) throw new Error('CONTROL_STORE_READ_INCOMPLETE')
      while (this.#offset < size) {
        if (size - this.#offset < 36) break
        const length = new DataView(bytes.buffer, bytes.byteOffset + this.#offset, 4).getUint32(0)
        if (length === 0 || length > this.#quota - 36) throw new Error('CONTROL_STORE_FRAME_INVALID')
        if (this.#offset + 36 + length > size) break
        const body = bytes.subarray(this.#offset + 36, this.#offset + 36 + length)
        if (!equalBytes(sha256Sync(body), bytes.subarray(this.#offset + 4, this.#offset + 36))) throw new Error('CONTROL_STORE_FRAME_CORRUPT')
        this.#restore(body)
        this.#offset += 36 + length
      }
      if (this.#offset !== size) { file.truncate(this.#offset); file.flush() }
    } catch (error) { file.close(); throw error }
  }
  load(): ControlStoreSnapshot | null { return this.#snapshot === null ? null : structuredClone(this.#snapshot) }
  loadJournal(): readonly ControlStoreJournalEntry[] { return structuredClone(this.#journal) }
  loadValidatorCutoffs(): readonly ValidatorCutoffState[] { return structuredClone([...this.#cutoffs.values()]) }
  initializeValidatorCutoffs(cutoffs: readonly ValidatorCutoffState[]): void {
    for (const cutoff of cutoffs) this.saveValidatorCutoff(cutoff)
  }
  save(snapshot: ControlStoreSnapshot): void {
    this.#append(encodeCanonicalCbor(['snapshot', encodeControlStoreSnapshot(snapshot)]))
    this.#snapshot = structuredClone(snapshot)
    this.#journal = []
  }
  appendJournal(entry: ControlStoreJournalEntry): boolean {
    this.#append(encodeCanonicalCbor(['operation', encodeControlStoreJournalEntry(entry)]))
    this.#journal.push(structuredClone(entry))
    // Retention is explicit and bounded; compaction is a separate future format.
    return false
  }
  saveValidatorCutoff(cutoff: ValidatorCutoffState): void {
    if (cutoff.validatorId.length !== 32 || cutoff.acceptedAboveMs < 0n) throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_INVALID')
    const key = bytesToHex(cutoff.validatorId), previous = this.#cutoffs.get(key)
    if (previous !== undefined && cutoff.acceptedAboveMs < previous.acceptedAboveMs) throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_REGRESSION')
    if (previous?.acceptedAboveMs === cutoff.acceptedAboveMs) return
    this.#append(encodeCanonicalCbor(['cutoff', cutoff.validatorId, cutoff.acceptedAboveMs]))
    this.#cutoffs.set(key, structuredClone(cutoff))
  }
  flush(): void { this.#assertOpen(); this.#file.flush() }
  close(): void { if (!this.#closed) { this.#closed = true; this.#file.close() } }
  #assertOpen(): void {
    if (this.#closed) throw new Error('CONTROL_STORE_CLOSED')
    if (this.#failed) throw new Error('CONTROL_STORE_REOPEN_REQUIRED')
  }
  #append(body: Uint8Array): void {
    this.#assertOpen()
    const frame = new Uint8Array(36 + body.length)
    if (this.#offset + frame.length > this.#quota) throw new Error('CONTROL_STORE_QUOTA_EXCEEDED')
    new DataView(frame.buffer).setUint32(0, body.length)
    frame.set(sha256Sync(body), 4); frame.set(body, 36)
    try {
      if (this.#file.write(frame, { at: this.#offset }) !== frame.length) throw new Error('CONTROL_STORE_WRITE_INCOMPLETE')
      this.#file.flush()
      this.#offset += frame.length
    } catch (error) { this.#failed = true; throw error }
  }
  #restore(body: Uint8Array): void {
    const value = assertCanonicalCbor(body, { ...DEFAULT_DECODE_LIMITS, maxBytes: this.#quota, maxTextBytes: this.#quota })
    if (!Array.isArray(value)) throw new Error('CONTROL_STORE_FRAME_INVALID')
    if (value.length === 2 && value[0] === 'snapshot' && typeof value[1] === 'string') {
      this.#snapshot = decodeControlStoreSnapshot(value[1]); this.#journal = []
    } else if (value.length === 2 && value[0] === 'operation' && typeof value[1] === 'string') {
      const entries = decodeControlStoreJournal(value[1])
      if (entries.length !== 1) throw new Error('CONTROL_STORE_FRAME_INVALID')
      this.#journal.push(entries[0]!)
    } else if (value.length === 3 && value[0] === 'cutoff' && value[1] instanceof Uint8Array && value[1].length === 32 && typeof value[2] === 'bigint' && value[2] >= 0n) {
      const key = bytesToHex(value[1]), previous = this.#cutoffs.get(key)
      if (previous !== undefined && value[2] < previous.acceptedAboveMs) throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_REGRESSION')
      this.#cutoffs.set(key, { validatorId: value[1], acceptedAboveMs: value[2] })
    } else throw new Error('CONTROL_STORE_FRAME_INVALID')
  }
}

export async function openSyncControl(directory: FileSystemDirectoryHandle): Promise<SyncControlPersistence> {
  const file = await directory.getFileHandle('private-control.journal', { create: true })
  const sync = file as FileSystemFileHandle & { createSyncAccessHandle?(): Promise<SyncDurableFile> }
  if (sync.createSyncAccessHandle === undefined) throw new Error('BROWSER_SYNC_STORAGE_UNAVAILABLE')
  return new SyncControlPersistence(await sync.createSyncAccessHandle())
}

import { bytesToHex, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
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
      return { [BYTES_TAG]: bytesToHex(item) }
    }
    return item
  })
}

function decodeTagged(text: string): unknown {
  return JSON.parse(text, (_key, value: unknown) => {
    if (isTagged(value, BIGINT_TAG)) return BigInt(value[BIGINT_TAG]!)
    if (isTagged(value, BYTES_TAG)) {
      return hexToBytes(value[BYTES_TAG]!)
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
  return bytesToHex(sha256Sync(utf8(body))).slice(0, JOURNAL_CHECKSUM_LENGTH)
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

  saveValidatorCutoff(cutoff: ValidatorCutoffState): void {
    const key = bytesToHex(cutoff.validatorId)
    const previous = this.#cutoffs.get(key)
    if (previous !== undefined && cutoff.acceptedAboveMs < previous.acceptedAboveMs) {
      throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_REGRESSION')
    }
    this.#cutoffs.set(key, cloneCutoff(cutoff))
  }
}

function cloneCutoff(cutoff: ValidatorCutoffState): ValidatorCutoffState {
  return { validatorId: cutoff.validatorId.slice(), acceptedAboveMs: cutoff.acceptedAboveMs }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

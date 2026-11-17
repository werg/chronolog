import { bytesToHex, sha256 } from '@chronolog/canonical'
import { encodeCanonicalCbor } from '@chronolog/protocol'

import { encodeHistoryConfiguration, encodeOrderingEvidence, verifyOrderedEntry,
  type CoordinatedHistoryConfiguration, type OrderedRecordEntry } from './history-policy.js'
import { decodeLedgerRecord } from './ledger-record.js'

/** A cumulative commitment to all finalized control descriptors, in receipt order. */
export interface ControlCommitment {
  readonly count: number
  readonly root: string
}

export interface FinalizedControl {
  readonly index: number
  readonly previousRoot: string
  readonly root: string
  readonly entry: OrderedRecordEntry
  /** The first closure covering this receipt. Later checkpoints cannot rewrite it. */
  readonly cutoffMs: bigint
}

export async function controlGenesisRoot(configuration: CoordinatedHistoryConfiguration): Promise<string> {
  return bytesToHex(await sha256(encodeCanonicalCbor([
    'chronolog/control-projection/v1', encodeHistoryConfiguration(configuration),
  ])))
}

/** Classification is total over generic retained bytes; invalid records have no control interpretation. */
export function isControlRecord(bytes: Uint8Array): boolean {
  try { return decodeLedgerRecord(bytes).kind !== 'candidate' } catch { return false }
}

export async function appendControl(previous: ControlCommitment, entry: OrderedRecordEntry, cutoffMs: bigint): Promise<FinalizedControl> {
  if (!Number.isSafeInteger(previous.count) || previous.count < 0 || previous.count >= Number.MAX_SAFE_INTEGER ||
      !/^[0-9a-f]{64}$/u.test(previous.root) || cutoffMs < 0n || cutoffMs > (1n << 63n) - 1n || !isControlRecord(entry.bytes)) {
    throw new Error('CONTROL_PROJECTION_INVALID')
  }
  entry = structuredClone(entry)
  const index = previous.count + 1
  const root = bytesToHex(await sha256(encodeCanonicalCbor([
    'chronolog/control-entry/v1', BigInt(index), previous.root,
    encodeOrderingEvidence({ kind: 'ordered-entry', entry }), cutoffMs,
  ])))
  return { index, previousRoot: previous.root, root, entry, cutoffMs }
}

export async function verifyControl(control: FinalizedControl, configuration: CoordinatedHistoryConfiguration): Promise<void> {
  if (control.entry.historyId !== configuration.historyId || !Number.isSafeInteger(control.index) || control.index < 1) {
    throw new Error('CONTROL_PROJECTION_INVALID')
  }
  await verifyOrderedEntry(control.entry)
  const expected = await appendControl({ count: control.index - 1, root: control.previousRoot }, control.entry, control.cutoffMs)
  if (expected.root !== control.root) throw new Error('CONTROL_PROJECTION_ROOT_MISMATCH')
}

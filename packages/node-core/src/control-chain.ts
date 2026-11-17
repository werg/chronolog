import { bytesToHex, sha256 } from '@chronolog/canonical'
import { encodeCanonicalCbor } from '@chronolog/protocol'

import { encodeHistoryConfiguration, encodeFinalityEvidence, verifyOrderedEntry,
  type HistoryConfiguration, type OrderedRecordEntry } from './history-policy.js'
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
  /** The batch that finalized this control; it takes effect in the following batch. */
  readonly batchNumber: number
}

export async function controlGenesisRoot(configuration: HistoryConfiguration): Promise<string> {
  return bytesToHex(await sha256(encodeCanonicalCbor([
    'chronolog/control-projection/v1', encodeHistoryConfiguration(configuration),
  ])))
}

/** Classification is total over generic retained bytes; invalid records have no control interpretation. */
export function isControlRecord(bytes: Uint8Array): boolean {
  try { return decodeLedgerRecord(bytes).kind !== 'candidate' } catch { return false }
}

export async function appendControl(previous: ControlCommitment, entry: OrderedRecordEntry, batchNumber: number): Promise<FinalizedControl> {
  if (!Number.isSafeInteger(previous.count) || previous.count < 0 || previous.count >= Number.MAX_SAFE_INTEGER ||
      !/^[0-9a-f]{64}$/u.test(previous.root) || !Number.isSafeInteger(batchNumber) || batchNumber < 1 || !isControlRecord(entry.bytes)) {
    throw new Error('CONTROL_PROJECTION_INVALID')
  }
  entry = structuredClone(entry)
  const index = previous.count + 1
  const root = bytesToHex(await sha256(encodeCanonicalCbor([
    'chronolog/control-entry/v1', BigInt(index), previous.root,
    encodeFinalityEvidence({ kind: 'record', entry }), BigInt(batchNumber),
  ])))
  return { index, previousRoot: previous.root, root, entry, batchNumber }
}

export async function verifyControl(control: FinalizedControl, configuration: HistoryConfiguration): Promise<void> {
  if (control.entry.historyId !== configuration.historyId || !Number.isSafeInteger(control.index) || control.index < 1) {
    throw new Error('CONTROL_PROJECTION_INVALID')
  }
  await verifyOrderedEntry(control.entry)
  const expected = await appendControl({ count: control.index - 1, root: control.previousRoot }, control.entry, control.batchNumber)
  if (expected.root !== control.root) throw new Error('CONTROL_PROJECTION_ROOT_MISMATCH')
}

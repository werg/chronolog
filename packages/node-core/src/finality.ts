import {
  assertCanonicalCbor, concatBytes, encodeCanonicalCbor, equalBytes, utf8,
  type Ed25519KeyPair,
} from '@chronolog/protocol'
import { appendControl, controlGenesisRoot, isControlRecord, type ControlCommitment, type FinalizedControl } from './control-chain.js'

import {
  encodeHistoryConfiguration, orderedGenesisRoot, verifyOrderedEntry,
  type CoordinatedHistoryConfiguration, type HistoryConfiguration,
  type OrderedRecordEntry, type OrderedRecordHead,
} from './history-policy.js'
import type { AdmissionFrontier } from '@chronolog/control-store/browser'

/**
 * Live history closes an irrevocable chronological prefix. The proof mechanism
 * may be a validator set or an inclusion signer; neither chooses execution
 * order. Asynchronous branching has no finality; it shares proposal identity,
 * chronological ordering and replay without implementing this live-only port.
 */
export interface LiveFinalityFrontier extends AdmissionFrontier {
  readonly mode: 'live'
  readonly checkpointId?: string
}

/** Runtime timers are derived from the authenticated genesis, never local defaults. */
export function resolveFinalityClockPolicy(policy: {
  readonly maxFutureSkewMs: bigint
  readonly cutoffLagMs: bigint
  readonly heartbeatIntervalMs: bigint
}): {
  readonly maxFutureSkewMs: number
  readonly cutoffLagMs: number
  readonly heartbeatIntervalMs: number
  readonly futureAdmissionWindowMs: number
} {
  const maxFutureSkewMs = Number(policy.maxFutureSkewMs)
  const cutoffLagMs = Number(policy.cutoffLagMs)
  const heartbeatIntervalMs = Number(policy.heartbeatIntervalMs)
  const futureAdmissionWindowMs = Number(policy.maxFutureSkewMs + policy.cutoffLagMs)
  if (![maxFutureSkewMs, cutoffLagMs, futureAdmissionWindowMs].every(value => Number.isSafeInteger(value) && value >= 0) ||
      !Number.isSafeInteger(heartbeatIntervalMs) || heartbeatIntervalMs < 1 || heartbeatIntervalMs > 60_000) {
    throw new Error('FINALITY_CLOCK_POLICY_INVALID')
  }
  return { maxFutureSkewMs, cutoffLagMs, heartbeatIntervalMs, futureAdmissionWindowMs }
}

/**
 * A provider proves inclusion and closes author time. It never chooses the
 * application execution order: every replica uses the protocol comparator.
 * Provider evidence is deliberately opaque to the node and its SQL reducer.
 * This port currently normalizes a signed-inclusion receipt/closure history;
 * it does not define arbitrary consensus or dynamic signer reconfiguration.
 */
export interface FinalityProvider {
  readonly configuration: HistoryConfiguration
  ingestEvidence(bytes: Uint8Array): Promise<unknown>
  snapshot(): FinalitySnapshot
  evidenceBytes(): readonly Uint8Array[]
}

/** A closure is itself included in the authenticated receipt log. */
export interface FinalityClosureBoundary {
  readonly position: number
  readonly root: string
  readonly includedThrough: number
  readonly includedRoot: string
  readonly closedThroughMs: bigint
}

export interface IncludedRecord {
  readonly entry: OrderedRecordEntry
  /** New proposals at or below this already-closed time cannot be admitted. */
  readonly admissionFloorMs: bigint
  /** The first later closure covering this receipt, or -1 if still open. */
  readonly closedThroughMs: bigint
  readonly closureBoundary: FinalityClosureBoundary | null
}

export interface FinalitySnapshot {
  readonly checkpointId: string
  readonly receivedThrough: number
  /** Complete authenticated receipt prefix, including closure markers. */
  readonly includedThrough: number
  /** Receipt prefix covered by the latest verified closure. */
  readonly closedReceiptThrough: number
  /** Latest monotone author-time frontier; -1 means nothing is closed. */
  readonly closedThroughMs: bigint
  /** Receipt enumeration only. Applications must use chronological order. */
  readonly records: readonly IncludedRecord[]
  readonly closures: readonly FinalityClosureBoundary[]
}

/** Additional proof state owned by the signed-inclusion provider. */
export interface SignedInclusionSnapshot extends FinalitySnapshot {
  readonly control: ControlCommitment
  readonly controls: readonly FinalizedControl[]
}

export interface SignedFinalityClosure {
  readonly configuration: Uint8Array
  readonly includedHead: OrderedRecordHead
  readonly closedThroughMs: bigint
  readonly control: ControlCommitment
  readonly signature: Uint8Array
}

const FORMAT = 'chronolog/finality-closure'
const SIGNING_DOMAIN = 'chronolog/finality-closure/v2\0'
const MAX_TIMESTAMP = (1n << 63n) - 1n
const MAX_CLOSURE_BYTES = 32_768

/**
 * Sign a closure over an exact committed inclusion head. The caller must hold
 * the log append lock and append these bytes immediately after that head.
 * Persisting the marker before publishing its prefix certificate makes the
 * promise recoverable without a latest-certificate side channel.
 */
export async function createFinalityClosureRecord(options: {
  readonly configuration: CoordinatedHistoryConfiguration
  readonly identity: Ed25519KeyPair
  readonly includedHead: OrderedRecordHead
  readonly closedThroughMs: bigint
  readonly control: ControlCommitment
}): Promise<Uint8Array> {
  const configuration = encodeHistoryConfiguration(options.configuration)
  const includedHead = structuredClone(options.includedHead)
  const closedThroughMs = options.closedThroughMs
  const publicKey = options.identity.publicKeyBytes.slice()
  if (!equalBytes(publicKey, options.configuration.authorityPublicKey)) throw new Error('FINALITY_CLOSURE_SIGNER_MISMATCH')
  if (includedHead.historyId !== options.configuration.historyId) throw new Error('FINALITY_CLOSURE_CONFIGURATION_MISMATCH')
  const unsigned = { configuration, includedHead, closedThroughMs, control: structuredClone(options.control) }
  const payload = closureSigningPayload(unsigned)
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', options.identity.privateKey, payload.slice().buffer))
  return encodeFinalityClosureRecord({ ...unsigned, signature })
}

export function encodeFinalityClosureRecord(value: SignedFinalityClosure): Uint8Array {
  const fields = closureFields(value)
  if (!(value.signature instanceof Uint8Array) || value.signature.length !== 64) throw new Error('FINALITY_CLOSURE_INVALID')
  return encodeCanonicalCbor([...fields, value.signature])
}

/** Recognition is not verification. The complete included prefix is verified below. */
export function isFinalityClosureRecord(bytes: Uint8Array): boolean {
  try {
    const value = assertCanonicalCbor(bytes, { maxBytes: 1_048_576, maxDepth: 16, maxItems: 256 })
    return Array.isArray(value) && value[1] === FORMAT
  } catch { return false }
}

export function decodeFinalityClosureRecord(bytes: Uint8Array): SignedFinalityClosure {
  let value: ReturnType<typeof assertCanonicalCbor>
  try { value = assertCanonicalCbor(bytes, { maxBytes: MAX_CLOSURE_BYTES, maxDepth: 2, maxItems: 10 }) }
  catch { throw new Error('FINALITY_CLOSURE_INVALID') }
  if (!Array.isArray(value) || value.length !== 10 || value[0] !== 2n || value[1] !== FORMAT ||
      !(value[2] instanceof Uint8Array) || typeof value[3] !== 'string' ||
      typeof value[4] !== 'bigint' || typeof value[5] !== 'string' || typeof value[6] !== 'bigint' ||
      typeof value[7] !== 'bigint' || typeof value[8] !== 'string' || !(value[9] instanceof Uint8Array)) throw new Error('FINALITY_CLOSURE_INVALID')
  const position = Number(value[4])
  if (!Number.isSafeInteger(position) || BigInt(position) !== value[4]) throw new Error('FINALITY_CLOSURE_INVALID')
  const closure: SignedFinalityClosure = {
    configuration: value[2], includedHead: { historyId: value[3], position, root: value[5] },
    closedThroughMs: value[6], control: { count: Number(value[7]), root: value[8] }, signature: value[9],
  }
  encodeFinalityClosureRecord(closure)
  return structuredClone(closure)
}

export async function verifyFinalityClosureRecord(bytes: Uint8Array,
  configuration: CoordinatedHistoryConfiguration): Promise<SignedFinalityClosure> {
  const expected = encodeHistoryConfiguration(configuration)
  const publicKey = configuration.authorityPublicKey.slice()
  const historyId = configuration.historyId
  const closure = decodeFinalityClosureRecord(bytes.slice())
  if (closure.includedHead.historyId !== historyId || !equalBytes(closure.configuration, expected)) {
    throw new Error('FINALITY_CLOSURE_CONFIGURATION_MISMATCH')
  }
  const key = await crypto.subtle.importKey('raw', publicKey.slice().buffer, 'Ed25519', false, ['verify'])
  if (!await crypto.subtle.verify('Ed25519', key, closure.signature.slice().buffer,
    closureSigningPayload(closure).slice().buffer)) throw new Error('FINALITY_CLOSURE_SIGNATURE_INVALID')
  return closure
}

/**
 * Derive admission floors from every closure in a complete included prefix.
 * Replaying only the newest certificate is insufficient: an earlier closure
 * decides whether a subsequently included backdated proposal is late.
 * Unknown bodies do not affect this proof; replicas check signed author time
 * after decryption and block application progress while a body is unavailable.
 */
export async function evaluateFinalitySnapshot(configuration: CoordinatedHistoryConfiguration,
  entries: readonly OrderedRecordEntry[], receivedThrough?: number): Promise<SignedInclusionSnapshot> {
  configuration = structuredClone(configuration)
  entries = structuredClone(entries)
  const records: IncludedRecord[] = []
  const closures: FinalityClosureBoundary[] = []
  let root = await orderedGenesisRoot(configuration.historyId)
  let position = 0
  let closedThroughMs = -1n
  let coveredRecords = 0
  const controls: FinalizedControl[] = []
  let control: ControlCommitment = { count: 0, root: await controlGenesisRoot(configuration) }
  for (const entry of entries) {
    if (entry.historyId !== configuration.historyId || entry.position !== position + 1 || entry.previousRoot !== root) {
      throw new Error('FINALITY_CLOSURE_PREFIX_INCOMPLETE')
    }
    await verifyOrderedEntry(entry)
    let closure: SignedFinalityClosure | null = null
    if (isFinalityClosureRecord(entry.bytes)) {
      try { closure = await verifyFinalityClosureRecord(entry.bytes, configuration) }
      catch (error) {
        // Generic retained logs can contain arbitrary writer bytes. A forged,
        // foreign or malformed marker makes no authority promise and cannot
        // poison the whole history. Authenticated contradictory promises below
        // remain fatal continuity errors.
        if (!(error instanceof Error) || !/^FINALITY_CLOSURE_(INVALID|SIGNATURE_INVALID|CONFIGURATION_MISMATCH)$/u.test(error.message)) throw error
      }
    }
    if (closure !== null) {
      if (closure.includedHead.position !== position || closure.includedHead.root !== root) {
        throw new Error('FINALITY_CLOSURE_HEAD_MISMATCH')
      }
      if (closure.closedThroughMs < closedThroughMs) throw new Error('FINALITY_CLOSURE_REGRESSION')
      const boundary: FinalityClosureBoundary = {
        position: entry.position, root: entry.root, includedThrough: position,
        includedRoot: root, closedThroughMs: closure.closedThroughMs,
      }
      closures.push(boundary)
      for (; coveredRecords < records.length; coveredRecords += 1) {
        const included = records[coveredRecords]!
        if (isControlRecord(included.entry.bytes)) {
          const next = await appendControl(control, included.entry, boundary.closedThroughMs)
          controls.push(next); control = { count: next.index, root: next.root }
        }
        records[coveredRecords] = { ...included,
          closureBoundary: boundary, closedThroughMs: boundary.closedThroughMs }
      }
      if (closure.control.count !== control.count || closure.control.root !== control.root) throw new Error('FINALITY_CONTROL_PROJECTION_MISMATCH')
      closedThroughMs = closure.closedThroughMs
    } else records.push({ entry, admissionFloorMs: closedThroughMs, closedThroughMs: -1n, closureBoundary: null })
    root = entry.root
    position = entry.position
  }
  const received = receivedThrough ?? position
  if (!Number.isSafeInteger(received) || received < position) throw new Error('FINALITY_CLOSURE_PREFIX_INCOMPLETE')
  return {
    checkpointId: root, receivedThrough: received, includedThrough: position,
    closedReceiptThrough: closures.at(-1)?.includedThrough ?? 0, closedThroughMs,
    records, closures, control, controls,
  }
}

function closureFields(value: Omit<SignedFinalityClosure, 'signature'>) {
  const { configuration, includedHead: head, closedThroughMs, control } = value
  if (!(configuration instanceof Uint8Array) || configuration.length < 1 || configuration.length > 32_000 ||
      !/^h_[0-9a-f]{32}$/u.test(head.historyId) || !Number.isSafeInteger(head.position) || head.position < 0 ||
      !/^[0-9a-f]{64}$/u.test(head.root) || typeof closedThroughMs !== 'bigint' ||
      closedThroughMs < 0n || closedThroughMs > MAX_TIMESTAMP ||
      !control || !Number.isSafeInteger(control.count) || control.count < 0 || control.count > head.position ||
      !/^[0-9a-f]{64}$/u.test(control.root)) throw new Error('FINALITY_CLOSURE_INVALID')
  return [2n, FORMAT, configuration, head.historyId, BigInt(head.position), head.root, closedThroughMs, BigInt(control.count), control.root] as const
}

function closureSigningPayload(value: Omit<SignedFinalityClosure, 'signature'>): Uint8Array {
  return concatBytes(utf8(SIGNING_DOMAIN), encodeCanonicalCbor(closureFields(value)))
}

/** Compute the cumulative control root a new closure must authenticate. */
export async function controlCommitmentForClosure(configuration: CoordinatedHistoryConfiguration,
  entries: readonly OrderedRecordEntry[], closedThroughMs: bigint): Promise<ControlCommitment> {
  return extendFinalityControlCommitment(await evaluateFinalitySnapshot(configuration, entries), closedThroughMs)
}

export async function extendFinalityControlCommitment(snapshot: SignedInclusionSnapshot, closedThroughMs: bigint): Promise<ControlCommitment> {
  let control = snapshot.control
  for (const record of snapshot.records) {
    if (record.closureBoundary !== null || !isControlRecord(record.entry.bytes)) continue
    const next = await appendControl(control, record.entry, closedThroughMs)
    control = { count: next.index, root: next.root }
  }
  return control
}

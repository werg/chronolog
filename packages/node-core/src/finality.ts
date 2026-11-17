import { bytesToHex, sha256 } from '@chronolog/canonical'
import { assertCanonicalCbor, encodeCanonicalCbor, equalBytes, type Ed25519KeyPair } from '@chronolog/protocol'

import { Mutex } from './async.js'
import { appendControl, controlGenesisRoot, isControlRecord, type ControlCommitment, type FinalizedControl } from './control-chain.js'
import { encodeHistoryConfiguration, orderedGenesisRoot, verifyOrderedEntry,
  type HistoryConfiguration, type OrderedRecordEntry, type OrderedRecordHead } from './history-policy.js'
import type { DurableOperationStore } from './operations.js'

/** A verifier proves exact sealed batches. The execution core interprets their records. */
export interface FinalityProvider {
  readonly configuration: HistoryConfiguration
  ingestEvidence(bytes: Uint8Array): Promise<unknown>
  snapshot(): FinalitySnapshot
  evidenceBytes(): readonly Uint8Array[]
}

export interface FinalityBatch {
  readonly configuration: Uint8Array
  readonly number: number
  readonly parentId: string
  readonly includedHead: OrderedRecordHead
  readonly control: ControlCommitment
}

export interface FinalitySignature { readonly publicKey: Uint8Array; readonly signature: Uint8Array }
export interface SignedFinalityBatch extends FinalityBatch { readonly signatures: readonly FinalitySignature[] }

export interface FinalityBatchBoundary {
  readonly number: number
  readonly id: string
  readonly parentId: string
  readonly includedFrom: number
  readonly includedThrough: number
  readonly includedRoot: string
}
export interface IncludedRecord { readonly entry: OrderedRecordEntry; readonly batch: FinalityBatchBoundary | null }
export interface FinalitySnapshot {
  readonly checkpointId: string
  readonly receivedThrough: number
  readonly includedThrough: number
  readonly finalizedThrough: number
  readonly records: readonly IncludedRecord[]
  readonly batches: readonly FinalityBatchBoundary[]
}
export interface SealedBatchSnapshot extends FinalitySnapshot {
  readonly control: ControlCommitment
  readonly controls: readonly FinalizedControl[]
}

const DOMAIN = 'chronolog/sealed-batch/v1'
const MAX_BATCH_BYTES = 32_768
const MAX_VALIDATORS = 64
const hashPattern = /^[0-9a-f]{64}$/u

export async function finalityGenesisId(configuration: HistoryConfiguration): Promise<string> {
  return bytesToHex(await sha256(encodeCanonicalCbor(['chronolog/batch-genesis/v1', encodeHistoryConfiguration(configuration)])))
}

export function encodeFinalityBatch(batch: FinalityBatch): Uint8Array {
  const { configuration, includedHead: head, control } = batch
  if (!(configuration instanceof Uint8Array) || configuration.length < 1 || configuration.length > 16_384 ||
      !Number.isSafeInteger(batch.number) || batch.number < 1 || !hashPattern.test(batch.parentId) ||
      !/^h_[0-9a-f]{32}$/u.test(head.historyId) || !Number.isSafeInteger(head.position) || head.position < 1 ||
      !hashPattern.test(head.root) || !Number.isSafeInteger(control.count) || control.count < 0 ||
      control.count > head.position || !hashPattern.test(control.root)) throw new Error('FINALITY_BATCH_INVALID')
  return encodeCanonicalCbor([1n, DOMAIN, configuration, BigInt(batch.number), batch.parentId,
    head.historyId, BigInt(head.position), head.root, BigInt(control.count), control.root])
}

export function decodeFinalityBatch(bytes: Uint8Array): FinalityBatch {
  const value = assertCanonicalCbor(bytes, { maxBytes: MAX_BATCH_BYTES, maxDepth: 2, maxItems: 12 })
  if (!Array.isArray(value) || value.length !== 10 || value[0] !== 1n || value[1] !== DOMAIN ||
      !(value[2] instanceof Uint8Array) || typeof value[3] !== 'bigint' || typeof value[4] !== 'string' ||
      typeof value[5] !== 'string' || typeof value[6] !== 'bigint' || typeof value[7] !== 'string' ||
      typeof value[8] !== 'bigint' || typeof value[9] !== 'string') throw new Error('FINALITY_BATCH_INVALID')
  const batch = { configuration: value[2], number: Number(value[3]), parentId: value[4],
    includedHead: { historyId: value[5], position: Number(value[6]), root: value[7] },
    control: { count: Number(value[8]), root: value[9] } }
  encodeFinalityBatch(batch)
  return batch
}

/** Identity excludes signatures, so independently collected votes name the same batch. */
export async function finalityBatchId(batch: FinalityBatch): Promise<string> {
  return bytesToHex(await sha256(encodeFinalityBatch(batch)))
}

export function encodeSignedFinalityBatch(batch: SignedFinalityBatch): Uint8Array {
  if (!Array.isArray(batch.signatures) || batch.signatures.length < 1 || batch.signatures.length > MAX_VALIDATORS) {
    throw new Error('FINALITY_BATCH_SIGNATURES_INVALID')
  }
  let previous = ''
  const signatures = batch.signatures.map(({ publicKey, signature }) => {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32 ||
        !(signature instanceof Uint8Array) || signature.length !== 64) throw new Error('FINALITY_BATCH_SIGNATURES_INVALID')
    const key = bytesToHex(publicKey)
    if (key <= previous) throw new Error('FINALITY_BATCH_SIGNATURES_INVALID')
    previous = key
    return [publicKey, signature]
  })
  return encodeCanonicalCbor([1n, encodeFinalityBatch(batch), signatures])
}

export function decodeSignedFinalityBatch(bytes: Uint8Array): SignedFinalityBatch {
  const value = assertCanonicalCbor(bytes, { maxBytes: MAX_BATCH_BYTES, maxDepth: 4, maxItems: 200 })
  if (!Array.isArray(value) || value.length !== 3 || value[0] !== 1n || !(value[1] instanceof Uint8Array) ||
      !Array.isArray(value[2])) throw new Error('FINALITY_BATCH_INVALID')
  const signatures = value[2].map(item => {
    if (!Array.isArray(item) || item.length !== 2 || !(item[0] instanceof Uint8Array) || !(item[1] instanceof Uint8Array)) {
      throw new Error('FINALITY_BATCH_SIGNATURES_INVALID')
    }
    return { publicKey: item[0], signature: item[1] }
  })
  const batch = { ...decodeFinalityBatch(value[1]), signatures }
  encodeSignedFinalityBatch(batch)
  return batch
}

export async function verifyFinalitySignature(batch: FinalityBatch, vote: FinalitySignature,
  configuration: HistoryConfiguration): Promise<void> {
  if (!equalBytes(batch.configuration, encodeHistoryConfiguration(configuration)) ||
      batch.includedHead.historyId !== configuration.historyId) throw new Error('FINALITY_BATCH_CONFIGURATION_MISMATCH')
  if (!configuration.validatorPublicKeys.some(key => equalBytes(key, vote.publicKey)) || vote.signature.length !== 64) {
    throw new Error('FINALITY_BATCH_SIGNATURE_INVALID')
  }
  const key = await crypto.subtle.importKey('raw', vote.publicKey.slice().buffer, 'Ed25519', false, ['verify'])
  if (!await crypto.subtle.verify('Ed25519', key, vote.signature.slice().buffer, encodeFinalityBatch(batch).slice().buffer)) {
    throw new Error('FINALITY_BATCH_SIGNATURE_INVALID')
  }
}

export async function verifyFinalityBatch(batch: SignedFinalityBatch, configuration: HistoryConfiguration): Promise<void> {
  encodeSignedFinalityBatch(batch)
  if (batch.signatures.length !== configuration.validatorPublicKeys.length) throw new Error('FINALITY_BATCH_INCOMPLETE')
  for (const vote of batch.signatures) await verifyFinalitySignature(batch, vote, configuration)
}

/** Verify one successor and its exact descriptor range before any validator signs. */
export async function verifyFinalitySuccessor(configuration: HistoryConfiguration, batch: FinalityBatch,
  parent: SignedFinalityBatch | null, records: readonly OrderedRecordEntry[]): Promise<void> {
  encodeFinalityBatch(batch)
  if (!equalBytes(batch.configuration, encodeHistoryConfiguration(configuration)) ||
      batch.includedHead.historyId !== configuration.historyId) throw new Error('FINALITY_BATCH_CONFIGURATION_MISMATCH')
  if (parent !== null) await verifyFinalityBatch(parent, configuration)
  const parentId = parent === null ? await finalityGenesisId(configuration) : await finalityBatchId(parent)
  if (batch.parentId !== parentId || batch.number !== (parent?.number ?? 0) + 1) throw new Error('FINALITY_BATCH_PARENT_MISMATCH')
  let position = parent?.includedHead.position ?? 0
  let root = parent?.includedHead.root ?? await orderedGenesisRoot(configuration.historyId)
  let control = parent?.control ?? { count: 0, root: await controlGenesisRoot(configuration) }
  if (records.length === 0 || batch.includedHead.position <= position) throw new Error('FINALITY_BATCH_EMPTY')
  for (const record of records) {
    await verifyOrderedEntry(record)
    if (record.historyId !== configuration.historyId || record.position !== position + 1 || record.previousRoot !== root) {
      throw new Error('FINALITY_BATCH_PREFIX_INCOMPLETE')
    }
    if (isControlRecord(record.bytes)) {
      const next = await appendControl(control, record, batch.number)
      control = { count: next.index, root: next.root }
    }
    position = record.position; root = record.root
  }
  if (position !== batch.includedHead.position || root !== batch.includedHead.root) throw new Error('FINALITY_BATCH_HEAD_MISMATCH')
  if (control.count !== batch.control.count || control.root !== batch.control.root) throw new Error('FINALITY_CONTROL_PROJECTION_MISMATCH')
}

/** Every complete batch freezes its exact set. New or old author times enter a later batch. */
export async function evaluateFinalitySnapshot(configuration: HistoryConfiguration, entries: readonly OrderedRecordEntry[],
  certificates: readonly SignedFinalityBatch[] = [], receivedThrough = entries.length): Promise<SealedBatchSnapshot> {
  configuration = structuredClone(configuration); entries = structuredClone(entries); certificates = structuredClone(certificates)
  let root = await orderedGenesisRoot(configuration.historyId)
  for (const [index, entry] of entries.entries()) {
    await verifyOrderedEntry(entry)
    if (entry.historyId !== configuration.historyId || entry.position !== index + 1 || entry.previousRoot !== root) {
      throw new Error('FINALITY_BATCH_PREFIX_INCOMPLETE')
    }
    root = entry.root
  }
  if (!Number.isSafeInteger(receivedThrough) || receivedThrough < entries.length) throw new Error('FINALITY_BATCH_PREFIX_INCOMPLETE')
  const records: IncludedRecord[] = entries.map(entry => ({ entry, batch: null }))
  const batches: FinalityBatchBoundary[] = [], controls: FinalizedControl[] = []
  let parent: SignedFinalityBatch | null = null
  let control: ControlCommitment = { count: 0, root: await controlGenesisRoot(configuration) }
  let checkpointId = await finalityGenesisId(configuration), finalizedThrough = 0
  for (const certificate of certificates) {
    await verifyFinalityBatch(certificate, configuration)
    await verifyFinalitySuccessor(configuration, certificate, parent, entries.slice(finalizedThrough, certificate.includedHead.position))
    const id = await finalityBatchId(certificate)
    const boundary = { number: certificate.number, id, parentId: certificate.parentId,
      includedFrom: finalizedThrough + 1, includedThrough: certificate.includedHead.position, includedRoot: certificate.includedHead.root }
    for (let index = finalizedThrough; index < certificate.includedHead.position; index++) {
      const entry = entries[index]!
      records[index] = { entry, batch: boundary }
      if (isControlRecord(entry.bytes)) {
        const next = await appendControl(control, entry, boundary.number)
        controls.push(next); control = { count: next.index, root: next.root }
      }
    }
    batches.push(boundary); parent = certificate; checkpointId = id; finalizedThrough = certificate.includedHead.position
  }
  return { checkpointId, receivedThrough, includedThrough: entries.length, finalizedThrough, records, batches, control, controls }
}

export async function extendFinalityControlCommitment(snapshot: SealedBatchSnapshot, batchNumber: number): Promise<ControlCommitment> {
  if (batchNumber !== snapshot.batches.length + 1) throw new Error('FINALITY_BATCH_PARENT_MISMATCH')
  let control = snapshot.control
  for (const record of snapshot.records) {
    if (record.batch !== null || !isControlRecord(record.entry.bytes)) continue
    const next = await appendControl(control, record.entry, batchNumber)
    control = { count: next.index, root: next.root }
  }
  return control
}

const signerLocks = new WeakMap<DurableOperationStore, Map<string, Mutex>>()
function signerLock(store: DurableOperationStore, key: string): Mutex {
  let locks = signerLocks.get(store)
  if (!locks) { locks = new Map(); signerLocks.set(store, locks) }
  let lock = locks.get(key)
  if (!lock) { lock = new Mutex(); locks.set(key, lock) }
  return lock
}

/** One fenced owner must retain this store for the entire lifetime of a signing key. */
export class DurableBatchSigner {
  readonly #mutex: Mutex
  readonly #prefix: string
  private constructor(readonly configuration: HistoryConfiguration, readonly identity: Ed25519KeyPair,
    readonly store: DurableOperationStore) {
    this.#prefix = `finality/votes/${configuration.historyId}/${bytesToHex(identity.publicKeyBytes)}`
    this.#mutex = signerLock(store, this.#prefix)
  }

  static async open(options: { readonly configuration: HistoryConfiguration; readonly identity: Ed25519KeyPair;
    readonly store: DurableOperationStore; readonly requireExisting?: boolean }): Promise<DurableBatchSigner> {
    const configuration = structuredClone(options.configuration)
    const identity = { ...options.identity, publicKeyBytes: options.identity.publicKeyBytes.slice() }
    const encoded = encodeHistoryConfiguration(configuration)
    if (!configuration.validatorPublicKeys.some(key => equalBytes(key, identity.publicKeyBytes))) throw new Error('FINALITY_SIGNER_UNAUTHORIZED')
    const signer = new DurableBatchSigner(configuration, identity, options.store)
    await signer.#mutex.run(async () => {
      const key = `${signer.#prefix}/configuration`, saved = await options.store.get(key)
      if (saved === null && options.requireExisting === true) throw new Error('FINALITY_SIGNER_STATE_MISSING')
      if (saved !== null && !equalBytes(saved, encoded)) throw new Error('FINALITY_SIGNER_CONFIGURATION_MISMATCH')
      if (saved === null) await options.store.put(key, encoded)
    })
    return signer
  }

  /** A crash after saving the choice can only retry the same successor, never another one. */
  sign(batch: FinalityBatch, parent: SignedFinalityBatch | null,
    records: readonly OrderedRecordEntry[]): Promise<FinalitySignature> {
    const captured = structuredClone(batch), previous = structuredClone(parent), entries = structuredClone(records)
    return this.#mutex.run(async () => {
      await verifyFinalitySuccessor(this.configuration, captured, previous, entries)
      const bytes = encodeFinalityBatch(captured), key = `${this.#prefix}/successor/${captured.parentId}`
      const chosen = await this.store.get(key)
      if (chosen !== null && !equalBytes(chosen, bytes)) throw new Error('FINALITY_SUCCESSOR_ALREADY_SIGNED')
      if (chosen === null) await this.store.put(key, bytes)
      const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', this.identity.privateKey, bytes.slice().buffer))
      const vote = { publicKey: this.identity.publicKeyBytes.slice(), signature }
      await verifyFinalitySignature(captured, vote, this.configuration)
      return vote
    })
  }

  async chosenSuccessor(parentId: string): Promise<FinalityBatch | null> {
    if (!hashPattern.test(parentId)) throw new Error('FINALITY_BATCH_INVALID')
    const bytes = await this.store.get(`${this.#prefix}/successor/${parentId}`)
    return bytes === null ? null : decodeFinalityBatch(bytes)
  }
}

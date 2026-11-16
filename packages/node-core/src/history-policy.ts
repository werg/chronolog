import { bytesToHex, sha256 } from '@chronolog/canonical'
import {
  assertCanonicalCbor, encodeCanonicalCbor, equalBytes, utf8,
  type Ed25519KeyPair,
} from '@chronolog/protocol'

import { Mutex } from './async.js'
import type { DurableOperationStore } from './operations.js'

/** Exactly two built-in policies; the chosen configuration is immutable. */
export type HistoryConfiguration = {
  readonly groupId: Uint8Array
  readonly genesisDigest: Uint8Array
  readonly executionManifestDigest: Uint8Array
} & ({ readonly kind: 'peer' } | {
  readonly kind: 'coordinated'
  readonly historyId: string
  readonly authorityPublicKey: Uint8Array
})

export type CoordinatedHistoryConfiguration = Extract<HistoryConfiguration, { kind: 'coordinated' }>

export interface OrderedRecordEntry {
  readonly historyId: string
  readonly position: number
  readonly recordId: string
  readonly previousRoot: string
  readonly root: string
  readonly bytes: Uint8Array
}

export interface OrderedRecordHead {
  readonly historyId: string
  readonly position: number
  readonly root: string
}

export interface PrefixCertificate extends OrderedRecordHead {
  readonly configuration: Uint8Array
  readonly signature: Uint8Array
}

export type OrderingEvidence =
  | { readonly kind: 'ordered-entry'; readonly entry: OrderedRecordEntry }
  | { readonly kind: 'prefix-certificate'; readonly certificate: PrefixCertificate }

export interface CoordinatedProgress {
  readonly receivedThrough: number
  readonly verifiedThrough: number
  readonly certifiedThrough: number
  readonly finalThrough: number
  readonly root: string
  readonly missing: readonly number[]
}

const LOG_DOMAIN = 'record-log/v1'
const CERTIFICATE_DOMAIN = 'chronolog/prefix-certificate/v1\0'

export function encodeHistoryConfiguration(configuration: HistoryConfiguration): Uint8Array {
  for (const bytes of [configuration.groupId, configuration.genesisDigest, configuration.executionManifestDigest]) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('HISTORY_CONFIGURATION_INVALID')
  }
  if (configuration.kind === 'peer') {
    return encodeCanonicalCbor([1n, 'peer', configuration.groupId, configuration.genesisDigest, configuration.executionManifestDigest])
  }
  assertHistoryId(configuration.historyId)
  if (configuration.authorityPublicKey.length !== 32) throw new Error('HISTORY_AUTHORITY_KEY_INVALID')
  return encodeCanonicalCbor([
    1n, 'coordinated', configuration.groupId, configuration.genesisDigest,
    configuration.executionManifestDigest, configuration.historyId, configuration.authorityPublicKey,
  ])
}

export async function historyConfigurationDigest(configuration: HistoryConfiguration): Promise<Uint8Array> {
  return sha256(encodeHistoryConfiguration(configuration))
}

export async function orderedRecordId(bytes: Uint8Array): Promise<string> {
  return bytesToHex(await sha256(bytes))
}

export async function orderedGenesisRoot(historyId: string): Promise<string> {
  assertHistoryId(historyId)
  return orderedRecordId(utf8(JSON.stringify([LOG_DOMAIN, 'genesis', historyId])))
}

export async function orderedEntryRoot(entry: Omit<OrderedRecordEntry, 'root' | 'bytes'>): Promise<string> {
  assertHistoryId(entry.historyId)
  assertPosition(entry.position, false)
  assertHash(entry.previousRoot)
  assertHash(entry.recordId)
  return orderedRecordId(utf8(JSON.stringify([
    LOG_DOMAIN, 'entry', entry.historyId, entry.position, entry.previousRoot, entry.recordId,
  ])))
}

export async function verifyOrderedEntry(entry: OrderedRecordEntry): Promise<void> {
  if (!(entry.bytes instanceof Uint8Array)) throw new Error('ORDERED_RECORD_BYTES_INVALID')
  if (entry.bytes.byteLength > 1_048_576) throw new Error('ORDERED_RECORD_TOO_LARGE')
  assertHash(entry.root)
  if (await orderedRecordId(entry.bytes) !== entry.recordId) throw new Error('ORDERED_RECORD_DIGEST_MISMATCH')
  if (await orderedEntryRoot(entry) !== entry.root) throw new Error('ORDERED_RECORD_ROOT_MISMATCH')
}

function certificatePayload(certificate: Omit<PrefixCertificate, 'signature'>): Uint8Array {
  assertHistoryId(certificate.historyId)
  assertPosition(certificate.position, true)
  assertHash(certificate.root)
  return encodeCanonicalCbor([
    CERTIFICATE_DOMAIN, certificate.configuration, certificate.historyId,
    BigInt(certificate.position), certificate.root,
  ])
}

/** Reads its own committed head. Caller-supplied roots are never signing inputs. */
export function createPrefixAuthority(options: {
  readonly configuration: CoordinatedHistoryConfiguration
  readonly identity: Ed25519KeyPair
  readonly readHead: () => Promise<OrderedRecordHead>
}): { certify(): Promise<PrefixCertificate> } {
  const configuration = encodeHistoryConfiguration(options.configuration)
  if (!equalBytes(options.identity.publicKeyBytes, options.configuration.authorityPublicKey)) {
    throw new Error('HISTORY_AUTHORITY_KEY_MISMATCH')
  }
  const historyId = options.configuration.historyId
  return {
    async certify() {
      const head = await options.readHead()
      if (head.historyId !== historyId) throw new Error('HISTORY_ID_MISMATCH')
      const unsigned = { ...head, configuration: configuration.slice() }
      const signature = new Uint8Array(await crypto.subtle.sign(
        'Ed25519', options.identity.privateKey, certificatePayload(unsigned).slice().buffer,
      ))
      return { ...unsigned, signature }
    },
  }
}

export async function verifyPrefixCertificate(
  certificate: PrefixCertificate,
  configuration: CoordinatedHistoryConfiguration,
): Promise<void> {
  if (certificate.historyId !== configuration.historyId ||
      !equalBytes(certificate.configuration, encodeHistoryConfiguration(configuration))) {
    throw new Error('HISTORY_CERTIFICATE_CONFIGURATION_MISMATCH')
  }
  if (certificate.signature.length !== 64) throw new Error('HISTORY_CERTIFICATE_SIGNATURE_INVALID')
  const key = await crypto.subtle.importKey('raw', configuration.authorityPublicKey.slice().buffer, 'Ed25519', false, ['verify'])
  if (!await crypto.subtle.verify('Ed25519', key, certificate.signature.slice().buffer, certificatePayload(certificate).slice().buffer)) {
    throw new Error('HISTORY_CERTIFICATE_SIGNATURE_INVALID')
  }
}

/** Evidence is immutable data; it is independent of a relay's author/feed. */
export function encodeOrderingEvidence(evidence: OrderingEvidence): Uint8Array {
  if (evidence.kind === 'ordered-entry') {
    const e = evidence.entry
    return encodeCanonicalCbor([1n, 'ordered-entry', e.historyId, BigInt(e.position), e.recordId, e.previousRoot, e.root, e.bytes])
  }
  const c = evidence.certificate
  return encodeCanonicalCbor([1n, 'prefix-certificate', c.configuration, c.historyId, BigInt(c.position), c.root, c.signature])
}

export function decodeOrderingEvidence(bytes: Uint8Array): OrderingEvidence {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value[0] !== 1n) throw new Error('ORDERING_EVIDENCE_INVALID')
  if (value[1] === 'ordered-entry' && value.length === 8 && typeof value[2] === 'string' &&
      typeof value[3] === 'bigint' && typeof value[4] === 'string' && typeof value[5] === 'string' &&
      typeof value[6] === 'string' && value[7] instanceof Uint8Array) {
    const position = Number(value[3]); assertPosition(position, false)
    if (BigInt(position) !== value[3]) throw new Error('ORDERING_EVIDENCE_INVALID')
    return { kind: 'ordered-entry', entry: {
      historyId: value[2], position, recordId: value[4], previousRoot: value[5], root: value[6], bytes: value[7],
    } }
  }
  if (value[1] === 'prefix-certificate' && value.length === 7 && value[2] instanceof Uint8Array &&
      typeof value[3] === 'string' && typeof value[4] === 'bigint' && typeof value[5] === 'string' &&
      value[6] instanceof Uint8Array) {
    const position = Number(value[4]); assertPosition(position, true)
    if (BigInt(position) !== value[4]) throw new Error('ORDERING_EVIDENCE_INVALID')
    return { kind: 'prefix-certificate', certificate: {
      configuration: value[2], historyId: value[3], position, root: value[5], signature: value[6],
    } }
  }
  throw new Error('ORDERING_EVIDENCE_INVALID')
}

/**
 * Shared durable control storage retains the exact entry mapping and portable
 * certificates. A certified root without every preceding byte is not finality.
 */
export class CoordinatedHistoryPolicy {
  readonly configuration: CoordinatedHistoryConfiguration
  readonly #store: DurableOperationStore
  readonly #key: string
  readonly #mutex = new Mutex()
  #entries = new Map<number, OrderedRecordEntry>()
  #certificates = new Map<number, PrefixCertificate>()
  #progress: CoordinatedProgress

  private constructor(configuration: CoordinatedHistoryConfiguration, store: DurableOperationStore, root: string) {
    this.configuration = structuredClone(configuration)
    this.#store = store
    this.#key = `history/${bytesToHex(configuration.groupId)}/coordinated`
    this.#progress = { receivedThrough: 0, verifiedThrough: 0, certifiedThrough: 0, finalThrough: 0, root, missing: [] }
  }

  static async open(configuration: CoordinatedHistoryConfiguration, store: DurableOperationStore): Promise<CoordinatedHistoryPolicy> {
    encodeHistoryConfiguration(configuration)
    const policy = new CoordinatedHistoryPolicy(configuration, store, await orderedGenesisRoot(configuration.historyId))
    const saved = await store.get(policy.#key)
    if (saved !== null) {
      const decoded = assertCanonicalCbor(saved)
      if (!Array.isArray(decoded) || decoded.length !== 3 || decoded[0] !== 1n ||
          !(decoded[1] instanceof Uint8Array) || !equalBytes(decoded[1], encodeHistoryConfiguration(configuration)) ||
          !Array.isArray(decoded[2])) throw new Error('HISTORY_STORED_CONFIGURATION_MISMATCH')
      for (const bytes of decoded[2]) {
        if (!(bytes instanceof Uint8Array)) throw new Error('HISTORY_STORED_EVIDENCE_INVALID')
        await policy.#validateAndInsert(decodeOrderingEvidence(bytes), policy.#entries, policy.#certificates)
      }
      policy.#progress = await policy.#evaluate(policy.#entries, policy.#certificates)
    }
    return policy
  }

  get progress(): CoordinatedProgress { return structuredClone(this.#progress) }

  entries(through = this.#progress.verifiedThrough): readonly OrderedRecordEntry[] {
    assertPosition(through, true)
    if (through > this.#progress.verifiedThrough) throw new Error('HISTORY_PREFIX_INCOMPLETE')
    return Array.from({ length: through }, (_, i) => structuredClone(this.#entries.get(i + 1)!))
  }

  evidence(): readonly OrderingEvidence[] {
    return [
      ...[...this.#entries.values()].sort((a, b) => a.position - b.position).map((entry): OrderingEvidence => ({ kind: 'ordered-entry', entry: structuredClone(entry) })),
      ...[...this.#certificates.values()].sort((a, b) => a.position - b.position).map((certificate): OrderingEvidence => ({ kind: 'prefix-certificate', certificate: structuredClone(certificate) })),
    ]
  }

  async ingest(evidence: OrderingEvidence): Promise<CoordinatedProgress> {
    return this.#mutex.run(async () => {
      const entries = new Map(this.#entries)
      const certificates = new Map(this.#certificates)
      await this.#validateAndInsert(structuredClone(evidence), entries, certificates)
      const progress = await this.#evaluate(entries, certificates)
      if (progress.finalThrough < this.#progress.finalThrough) throw new Error('HISTORY_FINAL_PREFIX_REGRESSION')
      const all: OrderingEvidence[] = [
        ...[...entries.values()].map((entry): OrderingEvidence => ({ kind: 'ordered-entry', entry })),
        ...[...certificates.values()].map((certificate): OrderingEvidence => ({ kind: 'prefix-certificate', certificate })),
      ]
      await this.#store.put(this.#key, encodeCanonicalCbor([
        1n, encodeHistoryConfiguration(this.configuration), all.map(encodeOrderingEvidence),
      ]))
      this.#entries = entries
      this.#certificates = certificates
      this.#progress = progress
      return this.progress
    })
  }

  async #validateAndInsert(evidence: OrderingEvidence, entries: Map<number, OrderedRecordEntry>, certificates: Map<number, PrefixCertificate>): Promise<void> {
    if (evidence.kind === 'ordered-entry') {
      const entry = evidence.entry
      if (entry.historyId !== this.configuration.historyId) throw new Error('HISTORY_ID_MISMATCH')
      await verifyOrderedEntry(entry)
      const previous = entries.get(entry.position)
      if (previous !== undefined && (previous.root !== entry.root || !equalBytes(previous.bytes, entry.bytes))) {
        throw new Error('HISTORY_POSITION_CONFLICT')
      }
      entries.set(entry.position, entry)
    } else {
      const certificate = evidence.certificate
      await verifyPrefixCertificate(certificate, this.configuration)
      const previous = certificates.get(certificate.position)
      if (previous !== undefined && previous.root !== certificate.root) throw new Error('HISTORY_AUTHORITY_EQUIVOCATION')
      certificates.set(certificate.position, certificate)
    }
  }

  async #evaluate(entries: Map<number, OrderedRecordEntry>, certificates: Map<number, PrefixCertificate>): Promise<CoordinatedProgress> {
    let root = await orderedGenesisRoot(this.configuration.historyId)
    let verifiedThrough = 0
    let finalThrough = 0
    let finalRoot = root
    const genesisCertificate = certificates.get(0)
    if (genesisCertificate !== undefined && genesisCertificate.root !== root) throw new Error('HISTORY_CERTIFICATE_ROOT_MISMATCH')
    while (entries.has(verifiedThrough + 1)) {
      const entry = entries.get(verifiedThrough + 1)!
      if (entry.previousRoot !== root) throw new Error('HISTORY_CHAIN_CONFLICT')
      root = entry.root
      verifiedThrough += 1
      const certificate = certificates.get(verifiedThrough)
      if (certificate !== undefined) {
        if (certificate.root !== root) throw new Error('HISTORY_CERTIFICATE_ROOT_MISMATCH')
        finalThrough = verifiedThrough
        finalRoot = root
      }
    }
    const receivedThrough = Math.max(0, ...entries.keys())
    const certifiedThrough = Math.max(0, ...certificates.keys())
    // Report a bounded gap window; do not allocate a caller-selected huge range.
    const missing: number[] = []
    for (let p = verifiedThrough + 1; p <= Math.min(certifiedThrough, verifiedThrough + 1_024); p += 1) {
      if (!entries.has(p)) missing.push(p)
    }
    return { receivedThrough, verifiedThrough, certifiedThrough, finalThrough, root: finalRoot, missing }
  }
}

/** A reference durable log uses one atomic value in the replica's storage port. */
export class ReferenceRecordLog {
  readonly #mutex = new Mutex()
  private constructor(readonly historyId: string, readonly store: DurableOperationStore, readonly quotaBytes: number) {}

  static async open(historyId: string, store: DurableOperationStore, quotaBytes = 64 * 1024 * 1024): Promise<ReferenceRecordLog> {
    assertHistoryId(historyId)
    if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 1) throw new Error('RECORD_LOG_QUOTA_INVALID')
    const log = new ReferenceRecordLog(historyId, store, quotaBytes)
    await log.read()
    return log
  }

  async read(): Promise<readonly OrderedRecordEntry[]> {
    const bytes = await this.store.get(`record-log/${this.historyId}`)
    if (bytes === null) return []
    const decoded = assertCanonicalCbor(bytes)
    if (!Array.isArray(decoded)) throw new Error('RECORD_LOG_STORAGE_INVALID')
    const entries: OrderedRecordEntry[] = []
    let root = await orderedGenesisRoot(this.historyId)
    for (const encoded of decoded) {
      if (!(encoded instanceof Uint8Array)) throw new Error('RECORD_LOG_STORAGE_INVALID')
      const evidence = decodeOrderingEvidence(encoded)
      if (evidence.kind !== 'ordered-entry') throw new Error('RECORD_LOG_STORAGE_INVALID')
      const entry = evidence.entry
      await verifyOrderedEntry(entry)
      if (entry.historyId !== this.historyId || entry.position !== entries.length + 1 || entry.previousRoot !== root) {
        throw new Error('RECORD_LOG_STORAGE_CONFLICT')
      }
      entries.push(entry); root = entry.root
    }
    return entries
  }

  async head(): Promise<OrderedRecordHead> {
    const entries = await this.read()
    return { historyId: this.historyId, position: entries.length, root: entries.at(-1)?.root ?? await orderedGenesisRoot(this.historyId) }
  }

  async append(bytes: Uint8Array): Promise<OrderedRecordEntry> {
    const exact = bytes.slice()
    return this.#mutex.run(async () => {
      const entries = await this.read()
      const recordId = await orderedRecordId(exact)
      const previous = entries.find((entry) => entry.recordId === recordId)
      if (previous !== undefined) return structuredClone(previous)
      if (entries.reduce((size, entry) => size + entry.bytes.byteLength, 0) + exact.byteLength > this.quotaBytes) {
        throw new Error('RECORD_LOG_QUOTA_EXCEEDED')
      }
      const fields = { historyId: this.historyId, position: entries.length + 1, recordId, previousRoot: entries.at(-1)?.root ?? await orderedGenesisRoot(this.historyId) }
      const entry = { ...fields, root: await orderedEntryRoot(fields), bytes: exact }
      await verifyOrderedEntry(entry)
      await this.store.put(`record-log/${this.historyId}`, encodeCanonicalCbor([
        ...entries, entry,
      ].map((item) => encodeOrderingEvidence({ kind: 'ordered-entry', entry: item }))))
      return structuredClone(entry)
    })
  }
}

function assertHistoryId(value: string): void {
  if (!/^h_[0-9a-f]{32}$/u.test(value)) throw new Error('HISTORY_ID_INVALID')
}
function assertHash(value: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new Error('HISTORY_HASH_INVALID')
}
function assertPosition(value: number, zero: boolean): void {
  if (!Number.isSafeInteger(value) || value < (zero ? 0 : 1)) throw new Error('HISTORY_POSITION_INVALID')
}

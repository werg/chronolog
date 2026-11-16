import {
  assertCanonicalCbor, encodeCanonicalCbor, equalBytes, type Ed25519KeyPair,
} from '@chronolog/protocol'

import type { EnrollmentDescriptor } from './enrollment.js'
import {
  decodeOrderingEvidence, encodeHistoryConfiguration, encodeOrderingEvidence, verifyOrderedEntry, verifyPrefixCertificate,
  type OrderedRecordEntry, type PrefixCertificate,
} from './history-policy.js'
import { decodeLedgerRecord } from './ledger-record.js'

const DOMAIN = 'chronolog/membership-ledger/v1'
export const MAX_MEMBERSHIP_LEDGER_BYTES = 2 * 1024 * 1024
const MAX_TTL_MS = 60_000

export interface MembershipLedgerPage {
  readonly entries: readonly OrderedRecordEntry[]
  readonly certificate: PrefixCertificate
  readonly hasMore: boolean
}

/** Only small ordered descriptors travel through this port. Application bodies never do. */
export interface MembershipLedger {
  read(options: { readonly after: number; readonly limit: number; readonly signal?: AbortSignal }): Promise<MembershipLedgerPage>
  append(recordBytes: Uint8Array, options?: { readonly signal?: AbortSignal }): Promise<OrderedRecordEntry>
}

export type MembershipLedgerRequest =
  | { readonly kind: 'read'; readonly after: number; readonly limit: number }
  | { readonly kind: 'append'; readonly recordBytes: Uint8Array }

/** A replay can only repeat a bounded read or append exactly the same content-addressed control record. */
export async function signMembershipLedgerRequest(options: {
  readonly descriptor: EnrollmentDescriptor
  readonly identity: Ed25519KeyPair
  readonly request: MembershipLedgerRequest
  readonly now?: number
}): Promise<Uint8Array> {
  const descriptor = structuredClone(options.descriptor), request = structuredClone(options.request)
  const privateKey = options.identity.privateKey, publicKey = options.identity.publicKeyBytes.slice()
  if (!equalBytes(publicKey, descriptor.genesis.manifest.rootAdminPublicKey)) throw new Error('MEMBERSHIP_ROOT_KEY_REQUIRED')
  const history = coordinated(descriptor), now = options.now ?? Date.now()
  if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - MAX_TTL_MS) throw new Error('MEMBERSHIP_TIME_INVALID')
  validateRequest(request, descriptor)
  const payload = encodeCanonicalCbor([1n, DOMAIN, history.groupId, history.historyId, encodeHistoryConfiguration(history), BigInt(now + MAX_TTL_MS),
    crypto.getRandomValues(new Uint8Array(16)), request.kind,
    request.kind === 'read' ? BigInt(request.after) : request.recordBytes,
    request.kind === 'read' ? BigInt(request.limit) : null])
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, payload.slice().buffer))
  return encodeCanonicalCbor([payload, signature])
}

/** Native HTTP adapters authenticate against the immutable genesis root, never a host login or bearer role. */
export async function verifyMembershipLedgerRequest(bytes: Uint8Array, descriptor: EnrollmentDescriptor,
  now = Date.now()): Promise<MembershipLedgerRequest> {
  bytes = bytes.slice(); descriptor = structuredClone(descriptor)
  if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - MAX_TTL_MS) throw new Error('MEMBERSHIP_TIME_INVALID')
  if (bytes.length > MAX_MEMBERSHIP_LEDGER_BYTES) throw new Error('MEMBERSHIP_REQUEST_TOO_LARGE')
  const history = coordinated(descriptor), signed = assertCanonicalCbor(bytes)
  if (!Array.isArray(signed) || signed.length !== 2 || !(signed[0] instanceof Uint8Array) ||
      !(signed[1] instanceof Uint8Array) || signed[1].length !== 64) throw new Error('MEMBERSHIP_REQUEST_INVALID')
  const value = assertCanonicalCbor(signed[0])
  if (!Array.isArray(value) || value.length !== 10 || value[0] !== 1n || value[1] !== DOMAIN ||
      !(value[2] instanceof Uint8Array) || !equalBytes(value[2], history.groupId) || value[3] !== history.historyId ||
      !(value[4] instanceof Uint8Array) || !equalBytes(value[4], encodeHistoryConfiguration(history)) ||
      typeof value[5] !== 'bigint' || value[5] < BigInt(now) || value[5] > BigInt(now + MAX_TTL_MS) ||
      !(value[6] instanceof Uint8Array) || value[6].length !== 16) throw new Error('MEMBERSHIP_REQUEST_INVALID')
  const key = await crypto.subtle.importKey('raw', descriptor.genesis.manifest.rootAdminPublicKey.slice().buffer,
    'Ed25519', false, ['verify'])
  if (!await crypto.subtle.verify('Ed25519', key, signed[1].slice().buffer, signed[0].slice().buffer)) {
    throw new Error('MEMBERSHIP_REQUEST_UNAUTHORIZED')
  }
  let request: MembershipLedgerRequest
  if (value[7] === 'read' && typeof value[8] === 'bigint' && typeof value[9] === 'bigint' &&
      value[8] <= BigInt(Number.MAX_SAFE_INTEGER) && value[9] <= 128n) {
    request = { kind: 'read', after: Number(value[8]), limit: Number(value[9]) }
  } else if (value[7] === 'append' && value[8] instanceof Uint8Array && value[9] === null) {
    request = { kind: 'append', recordBytes: value[8].slice() }
  } else throw new Error('MEMBERSHIP_REQUEST_INVALID')
  validateRequest(request, descriptor)
  return request
}

export function encodeMembershipLedgerResponse(value: MembershipLedgerPage | OrderedRecordEntry): Uint8Array {
  return 'entries' in value
    ? encodeCanonicalCbor([1n, 'read', value.entries.map(entry => encodeOrderingEvidence({ kind: 'ordered-entry', entry })),
      encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: value.certificate }), value.hasMore])
    : encodeCanonicalCbor([1n, 'append', encodeOrderingEvidence({ kind: 'ordered-entry', entry: value })])
}

export function decodeMembershipLedgerResponse(bytes: Uint8Array, kind: 'read'): MembershipLedgerPage
export function decodeMembershipLedgerResponse(bytes: Uint8Array, kind: 'append'): OrderedRecordEntry
export function decodeMembershipLedgerResponse(bytes: Uint8Array, kind: 'read' | 'append'): MembershipLedgerPage | OrderedRecordEntry {
  if (bytes.length > MAX_MEMBERSHIP_LEDGER_BYTES) throw new Error('MEMBERSHIP_RESPONSE_TOO_LARGE')
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value[0] !== 1n || value[1] !== kind) throw new Error('MEMBERSHIP_RESPONSE_INVALID')
  const entry = (raw: unknown): OrderedRecordEntry => {
    if (!(raw instanceof Uint8Array)) throw new Error('MEMBERSHIP_RESPONSE_INVALID')
    const evidence = decodeOrderingEvidence(raw)
    if (evidence.kind !== 'ordered-entry') throw new Error('MEMBERSHIP_RESPONSE_INVALID')
    return evidence.entry
  }
  if (kind === 'append' && value.length === 3) return entry(value[2])
  if (kind !== 'read' || value.length !== 5 || !Array.isArray(value[2]) || value[2].length > 128 ||
      !(value[3] instanceof Uint8Array) || typeof value[4] !== 'boolean') throw new Error('MEMBERSHIP_RESPONSE_INVALID')
  const evidence = decodeOrderingEvidence(value[3])
  if (evidence.kind !== 'prefix-certificate') throw new Error('MEMBERSHIP_RESPONSE_INVALID')
  return { entries: value[2].map(entry), certificate: evidence.certificate, hasMore: value[4] }
}

/** Default Cloudflare administrator route to a separately pinned native ordering authority. */
export function createMembershipLedgerClient(options: {
  readonly url: string
  readonly descriptor: EnrollmentDescriptor
  readonly identity: Ed25519KeyPair
  readonly fetch?: typeof globalThis.fetch
  readonly now?: () => number
}): MembershipLedger {
  const descriptor = structuredClone(options.descriptor), identity = { ...options.identity, publicKeyBytes: options.identity.publicKeyBytes.slice() }
  const history = coordinated(descriptor), url = new URL(options.url), fetcher = options.fetch ?? globalThis.fetch
  if (url.username || url.password || url.hash || !(url.protocol === 'https:' || url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new Error('MEMBERSHIP_URL_INVALID')
  const call = async (request: MembershipLedgerRequest, signal?: AbortSignal): Promise<Uint8Array> => {
    const body = await signMembershipLedgerRequest({ descriptor, identity, request, now: options.now?.() ?? Date.now() })
    const response = await fetcher(url, { method: 'POST', body: body.slice().buffer,
      headers: { 'Content-Type': 'application/cbor' }, cache: 'no-store', ...(signal === undefined ? {} : { signal }) })
    if (!response.ok) throw new Error(`MEMBERSHIP_LEDGER_HTTP_${response.status}`)
    if (response.body === null) throw new Error('MEMBERSHIP_RESPONSE_INVALID')
    const reader = response.body.getReader(), chunks: Uint8Array[] = []
    let length = 0
    try {
      for (;;) {
        const item = await reader.read()
        if (item.done) break
        length += item.value.length
        if (length > MAX_MEMBERSHIP_LEDGER_BYTES) throw new Error('MEMBERSHIP_RESPONSE_TOO_LARGE')
        chunks.push(item.value)
      }
    } finally { await reader.cancel().catch(() => undefined); reader.releaseLock() }
    const bytes = new Uint8Array(length)
    let offset = 0
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
    return bytes
  }
  return {
    async read(input) {
      const page = decodeMembershipLedgerResponse(await call({ kind: 'read', after: input.after, limit: input.limit }, input.signal), 'read')
      if (page.entries.length > input.limit) throw new Error('MEMBERSHIP_RANGE_TOO_LARGE')
      await verifyPrefixCertificate(page.certificate, history)
      return page
    },
    async append(recordBytes, input = {}) {
      const exact = recordBytes.slice()
      const entry = decodeMembershipLedgerResponse(await call({ kind: 'append', recordBytes: exact }, input.signal), 'append')
      await verifyOrderedEntry(entry)
      if (entry.historyId !== history.historyId || !equalBytes(entry.bytes, exact)) throw new Error('MEMBERSHIP_APPEND_MISMATCH')
      return entry
    },
  }
}

function coordinated(descriptor: EnrollmentDescriptor) {
  if (descriptor.history.kind !== 'coordinated') throw new Error('MEMBERSHIP_COORDINATED_HISTORY_REQUIRED')
  return descriptor.history
}

function validateRequest(request: MembershipLedgerRequest, descriptor: EnrollmentDescriptor): void {
  if (request.kind === 'read') {
    if (!Number.isSafeInteger(request.after) || request.after < 0 || !Number.isSafeInteger(request.limit) ||
        request.limit < 1 || request.limit > 128) throw new Error('MEMBERSHIP_RANGE_INVALID')
  } else {
    const record = decodeLedgerRecord(request.recordBytes)
    if (record.kind === 'candidate' || !equalBytes(record.groupRoute, descriptor.groupRoute)) {
      throw new Error('MEMBERSHIP_CONTROL_RECORD_REQUIRED')
    }
  }
}

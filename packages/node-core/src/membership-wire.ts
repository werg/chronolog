import {
  assertCanonicalCbor, encodeCanonicalCbor, equalBytes, type Ed25519KeyPair,
} from '@chronolog/protocol'

import type { EnrollmentDescriptor } from './enrollment.js'
import {
  decodeOrderingEvidence, encodeHistoryConfiguration, encodeOrderingEvidence, verifyOrderedEntry,
  type OrderedRecordEntry,
} from './history-policy.js'
import { decodeLedgerRecord } from './ledger-record.js'
import { decodeControlPage, encodeControlPage, verifyControlCheckpoint, type MembershipLedgerPage } from './control-proof.js'
export type { MembershipLedgerPage } from './control-proof.js'

const DOMAIN = 'chronolog/membership-ledger/v2'
export const MAX_MEMBERSHIP_LEDGER_BYTES = 2 * 1024 * 1024
export const MAX_MEMBERSHIP_BODY_FRAGMENTS = 65_536
export const MEMBERSHIP_IO_TIMEOUT_MS = 30_000
const MAX_TTL_MS = 60_000

/** Only finalized governance and its cumulative completeness proof travel through this port. */
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
    ? encodeCanonicalCbor([2n, 'read', encodeControlPage(value)])
    : encodeCanonicalCbor([2n, 'append', encodeOrderingEvidence({ kind: 'ordered-entry', entry: value })])
}

export function decodeMembershipLedgerResponse(bytes: Uint8Array, kind: 'read'): MembershipLedgerPage
export function decodeMembershipLedgerResponse(bytes: Uint8Array, kind: 'append'): OrderedRecordEntry
export function decodeMembershipLedgerResponse(bytes: Uint8Array, kind: 'read' | 'append'): MembershipLedgerPage | OrderedRecordEntry {
  if (bytes.length > MAX_MEMBERSHIP_LEDGER_BYTES) throw new Error('MEMBERSHIP_RESPONSE_TOO_LARGE')
  const value = assertCanonicalCbor(bytes, { maxBytes: MAX_MEMBERSHIP_LEDGER_BYTES, maxByteStringBytes: MAX_MEMBERSHIP_LEDGER_BYTES })
  if (!Array.isArray(value) || value[0] !== 2n || value[1] !== kind) throw new Error('MEMBERSHIP_RESPONSE_INVALID')
  const entry = (raw: unknown): OrderedRecordEntry => {
    if (!(raw instanceof Uint8Array)) throw new Error('MEMBERSHIP_RESPONSE_INVALID')
    const evidence = decodeOrderingEvidence(raw)
    if (evidence.kind !== 'ordered-entry') throw new Error('MEMBERSHIP_RESPONSE_INVALID')
    return evidence.entry
  }
  if (kind === 'append' && value.length === 3) return entry(value[2])
  if (kind !== 'read' || value.length !== 3 || !(value[2] instanceof Uint8Array)) throw new Error('MEMBERSHIP_RESPONSE_INVALID')
  return decodeControlPage(value[2])
}

/** Default Cloudflare administrator route to a separately pinned native ordering authority. */
export function createMembershipLedgerClient(options: {
  readonly url: string
  readonly descriptor: EnrollmentDescriptor
  readonly identity: Ed25519KeyPair
  readonly fetch?: typeof globalThis.fetch
  readonly now?: () => number
  /** One deadline covers signing, response headers and the complete bounded body. */
  readonly timeoutMs?: number
}): MembershipLedger {
  const descriptor = structuredClone(options.descriptor), identity = { ...options.identity, publicKeyBytes: options.identity.publicKeyBytes.slice() }
  const history = coordinated(descriptor), url = new URL(options.url), fetcher = options.fetch ?? globalThis.fetch
  if (url.username || url.password || url.hash || !(url.protocol === 'https:' || url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new Error('MEMBERSHIP_URL_INVALID')
  const timeoutMs = ioTimeout(options.timeoutMs)
  const call = async (request: MembershipLedgerRequest, signal?: AbortSignal): Promise<Uint8Array> => {
    const lifetime = ioLifetime(signal, timeoutMs)
    try {
      lifetime.signal.throwIfAborted()
      const body = await interruptible(signMembershipLedgerRequest({ descriptor, identity, request, now: options.now?.() ?? Date.now() }), lifetime.signal)
      const fetching = fetcher(url, { method: 'POST', body: body.slice().buffer,
        // workerd supports manual/follow, but deliberately rejects redirect:error
        // before any I/O. Never forward a signed control request to another URL.
        headers: { 'Content-Type': 'application/cbor' }, cache: 'no-store', redirect: 'manual', credentials: 'omit', signal: lifetime.signal })
      void fetching.then(response => { if (lifetime.signal.aborted) void response.body?.cancel().catch(() => undefined) }, () => undefined)
      const response = await interruptible(fetching, lifetime.signal)
      if (response.redirected || response.type === 'opaqueredirect' || response.status >= 300 && response.status < 400) {
        void response.body?.cancel().catch(() => undefined)
        throw new Error('MEMBERSHIP_LEDGER_REDIRECT')
      }
      if (!response.ok) {
        void response.body?.cancel().catch(() => undefined)
        throw new Error(`MEMBERSHIP_LEDGER_HTTP_${response.status}`)
      }
      try { return await readMembershipLedgerBody(response, { signal: lifetime.signal, timeoutMs }) }
      catch (error) { if (error instanceof RangeError) throw new Error('MEMBERSHIP_RESPONSE_TOO_LARGE', { cause: error }); throw error }
    } finally { lifetime.close() }
  }
  return {
    async read(input) {
      const page = decodeMembershipLedgerResponse(await call({ kind: 'read', after: input.after, limit: input.limit }, input.signal), 'read')
      if (page.entries.length > input.limit) throw new Error('MEMBERSHIP_RANGE_TOO_LARGE')
      await verifyControlCheckpoint(page, history)
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

/** Fixed allocation, fragment quota and deadline shared by request/response adapters. */
export async function readMembershipLedgerBody(message: Request | Response, options: {
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
} = {}): Promise<Uint8Array> {
  const lifetime = ioLifetime(options.signal ?? ('signal' in message ? message.signal : undefined), ioTimeout(options.timeoutMs))
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  try {
    lifetime.signal.throwIfAborted()
    const declared = message.headers.get('Content-Length')
    if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_MEMBERSHIP_LEDGER_BYTES)) throw new RangeError('MEMBERSHIP_BODY_TOO_LARGE')
    if (message.body === null) throw new TypeError('MEMBERSHIP_BODY_REQUIRED')
    reader = message.body.getReader()
    const bytes = new Uint8Array(MAX_MEMBERSHIP_LEDGER_BYTES)
    let length = 0, fragments = 0
    for (;;) {
      const item = await interruptible(reader.read(), lifetime.signal)
      // Cancellation can make read() return done. It is never a complete body.
      lifetime.signal.throwIfAborted()
      if (item.done) return bytes.slice(0, length)
      if (++fragments > MAX_MEMBERSHIP_BODY_FRAGMENTS || length + item.value.length > bytes.length) throw new RangeError('MEMBERSHIP_BODY_TOO_LARGE')
      bytes.set(item.value, length); length += item.value.length
    }
  } finally {
    lifetime.close()
    // A custom stream's cancellation promise is not allowed to retain a host
    // operation after its deadline. Pending reads already have rejection handlers.
    if (reader !== undefined) { void reader.cancel().catch(() => undefined); reader.releaseLock() }
    else void message.body?.cancel().catch(() => undefined)
  }
}

function ioTimeout(value: number = MEMBERSHIP_IO_TIMEOUT_MS): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 120_000) throw new Error('MEMBERSHIP_TIMEOUT_INVALID')
  return value
}
function ioLifetime(external: AbortSignal | undefined, timeoutMs: number) {
  const controller = new AbortController(), abort = (): void => controller.abort(external?.reason)
  const timer = setTimeout(() => controller.abort(new Error('MEMBERSHIP_IO_TIMEOUT')), timeoutMs)
  external?.addEventListener('abort', abort, { once: true })
  if (external?.aborted === true) abort()
  return { signal: controller.signal, close() { clearTimeout(timer); external?.removeEventListener('abort', abort) } }
}
function interruptible<T>(value: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void value.catch(() => undefined); return Promise.reject(signal.reason) }
  return new Promise((resolve, reject) => {
    const abort = (): void => { reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    void value.then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
  })
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

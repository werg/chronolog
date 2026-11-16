import { verifyEnrollmentDescriptor, type EnrollmentDescriptor } from '@chronolog/node-core'
import {
  encodeHistoryConfiguration, encodeOrderingEvidence, type OrderedRecordEntry, type PrefixCertificate,
} from '@chronolog/node-core/history'
import {
  MAX_MEMBERSHIP_LEDGER_BYTES, encodeMembershipLedgerResponse, verifyMembershipLedgerRequest,
  type MembershipLedgerRequest,
} from '@chronolog/node-core/membership'
import { equalBytes } from '@chronolog/protocol'

import type { EvidenceSink, NativeAuthority } from './authority.js'

export const MEMBERSHIP_LEDGER_PATH = '/_chronolog/membership'
/** The encoded entry budget leaves room for the certificate and response framing. */
export const MAX_MEMBERSHIP_PAGE_ENTRY_BYTES = 1024 * 1024

/**
 * A root-signed control-plane route to the pinned native ordering authority.
 * Reads contain every ordered descriptor, but never fetch detached application
 * payloads. Appends accept only complete inline governance records.
 */
export function createMembershipLedgerHandler(options: {
  readonly authority: NativeAuthority
  readonly descriptor: EnrollmentDescriptor
  readonly sink?: EvidenceSink
  readonly now?: () => number
}): (request: Request) => Promise<Response> {
  const descriptor = structuredClone(options.descriptor)
  const { authority, sink } = options
  const now = options.now ?? Date.now
  if (descriptor.history.kind !== 'coordinated' ||
      !equalBytes(encodeHistoryConfiguration(descriptor.history), encodeHistoryConfiguration(authority.configuration))) {
    throw new Error('MEMBERSHIP_AUTHORITY_CONFIGURATION_MISMATCH')
  }
  const configured = verifyEnrollmentDescriptor(descriptor)
  // Construction is synchronous; surface invalid persisted configuration on the
  // first request without creating an unhandled rejection in the meantime.
  void configured.catch(() => undefined)

  const mirror = async (entries: readonly OrderedRecordEntry[], certificate: PrefixCertificate): Promise<void> => {
    if (sink === undefined) return
    for (const entry of entries) await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
    await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
  }

  return async (request) => {
    const url = new URL(request.url)
    if (url.pathname !== MEMBERSHIP_LEDGER_PATH || url.search !== '' || url.hash !== '') return failure(404, 'MEMBERSHIP_ROUTE_NOT_FOUND')
    if (request.method !== 'POST') return failure(405, 'MEMBERSHIP_POST_REQUIRED', { allow: 'POST' })
    if (request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/cbor') {
      return failure(415, 'MEMBERSHIP_CBOR_REQUIRED')
    }
    let bytes: Uint8Array
    try { bytes = await readBoundedBody(request) }
    catch (error) {
      return failure(error instanceof RangeError ? 413 : 400, error instanceof RangeError
        ? 'MEMBERSHIP_REQUEST_TOO_LARGE' : 'MEMBERSHIP_REQUEST_INVALID')
    }
    try { await configured }
    catch { return failure(503, 'MEMBERSHIP_CONFIGURATION_INVALID') }
    let operation: MembershipLedgerRequest
    try { operation = await verifyMembershipLedgerRequest(bytes, descriptor, now()) }
    catch { return failure(403, 'MEMBERSHIP_REQUEST_UNAUTHORIZED') }

    try {
      request.signal.throwIfAborted()
      let encoded: Uint8Array
      if (operation.kind === 'append') {
        // A failed response or evidence delivery does not undo a durable append.
        // Retrying these exact bytes returns the original position and root.
        const entry = await authority.appendLedgerRecord(operation.recordBytes)
        await mirror([entry], await authority.certify())
        encoded = encodeMembershipLedgerResponse(entry)
      } else {
        const range = await authority.read({ after: operation.after, limit: operation.limit })
        const entries: OrderedRecordEntry[] = []
        let length = 0
        for (const entry of range.entries) {
          const size = encodeOrderingEvidence({ kind: 'ordered-entry', entry }).length
          if (size > MAX_MEMBERSHIP_PAGE_ENTRY_BYTES) throw new Error('MEMBERSHIP_ENTRY_TOO_LARGE')
          if (length + size > MAX_MEMBERSHIP_PAGE_ENTRY_BYTES) break
          entries.push(entry)
          length += size
        }
        const certificate = await authority.certify()
        // A read also heals delivery interrupted after a durable administrative
        // append. It never needs to republish the entire retained history.
        await mirror(entries, certificate)
        encoded = encodeMembershipLedgerResponse({ entries, certificate,
          hasMore: (entries.at(-1)?.position ?? operation.after) < certificate.position })
      }
      if (encoded.length > MAX_MEMBERSHIP_LEDGER_BYTES) throw new Error('MEMBERSHIP_RESPONSE_TOO_LARGE')
      return new Response(encoded.slice().buffer, { headers: { 'content-type': 'application/cbor', 'cache-control': 'no-store' } })
    } catch (error) {
      return failure(error instanceof Error && error.message === 'AUTHORITY_RANGE_AHEAD' ? 409 : 503,
        'MEMBERSHIP_LEDGER_UNAVAILABLE')
    }
  }
}

async function readBoundedBody(request: Request): Promise<Uint8Array> {
  const declared = request.headers.get('content-length')
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_MEMBERSHIP_LEDGER_BYTES)) {
    throw new RangeError('MEMBERSHIP_REQUEST_TOO_LARGE')
  }
  if (request.body === null) throw new TypeError('MEMBERSHIP_REQUEST_INVALID')
  const reader = request.body.getReader(), chunks: Uint8Array[] = []
  let length = 0
  try {
    for (;;) {
      request.signal.throwIfAborted()
      const item = await reader.read()
      if (item.done) break
      length += item.value.length
      if (length > MAX_MEMBERSHIP_LEDGER_BYTES) throw new RangeError('MEMBERSHIP_REQUEST_TOO_LARGE')
      chunks.push(Uint8Array.from(item.value))
    }
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock() }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
  return bytes
}

function failure(status: number, code: string, headers: Readonly<Record<string, string>> = {}): Response {
  return new Response(code, { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...headers } })
}

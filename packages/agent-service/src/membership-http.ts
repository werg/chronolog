import { Mutex, verifyEnrollmentDescriptor, type EnrollmentDescriptor } from '@chronolog/node-core'
import {
  encodeHistoryConfiguration, encodeOrderingEvidence, type PrefixCertificate,
} from '@chronolog/node-core/history'
import {
  MAX_MEMBERSHIP_LEDGER_BYTES, MEMBERSHIP_IO_TIMEOUT_MS, readMembershipLedgerBody, encodeMembershipLedgerResponse, verifyMembershipLedgerRequest,
  type MembershipLedgerRequest,
} from '@chronolog/node-core/membership'
import { equalBytes } from '@chronolog/protocol'

import type { EvidenceSink, NativeFinalityService } from './finality-service.js'

export const MEMBERSHIP_LEDGER_PATH = '/_chronolog/membership'
/** The encoded entry budget leaves room for the certificate and response framing. */
export const MAX_MEMBERSHIP_PAGE_ENTRY_BYTES = 1024 * 1024

/**
 * A root-signed control-plane route to the pinned native finality service.
 * Reads contain only finalized controls and a signed cumulative completeness proof.
 * Appends accept only complete inline governance records; application descriptors and
 * detached payloads stay with the native peer.
 */
export function createMembershipLedgerHandler(options: {
  readonly finality: NativeFinalityService
  readonly descriptor: EnrollmentDescriptor
  readonly sink?: EvidenceSink
  readonly now?: () => number
  readonly bodyTimeoutMs?: number
}): (request: Request) => Promise<Response> {
  const descriptor = structuredClone(options.descriptor)
  const { finality, sink } = options
  const now = options.now ?? Date.now
  const bodyTimeoutMs = options.bodyTimeoutMs ?? MEMBERSHIP_IO_TIMEOUT_MS
  if (!Number.isSafeInteger(bodyTimeoutMs) || bodyTimeoutMs < 1 || bodyTimeoutMs > 120_000) throw new Error('MEMBERSHIP_TIMEOUT_INVALID')
  if (descriptor.history.kind !== 'coordinated' ||
      !equalBytes(encodeHistoryConfiguration(descriptor.history), encodeHistoryConfiguration(finality.configuration))) {
    throw new Error('MEMBERSHIP_AUTHORITY_CONFIGURATION_MISMATCH')
  }
  const configured = verifyEnrollmentDescriptor(descriptor)
  // Construction is synchronous; surface invalid persisted configuration on the
  // first request without creating an unhandled rejection in the meantime.
  void configured.catch(() => undefined)

  let mirroredThrough = 0
  const delivery = new Mutex()
  const mirror = (certificate: PrefixCertificate): Promise<void> => delivery.run(async () => {
    if (sink === undefined) return
    while (mirroredThrough < certificate.position) {
      const range = await finality.read({ after: mirroredThrough, limit: 128 })
      for (const entry of range.entries) {
        if (entry.position > certificate.position) break
        await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
        mirroredThrough = entry.position
      }
    }
    await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
  })

  return async (request) => {
    const url = new URL(request.url)
    if (url.pathname !== MEMBERSHIP_LEDGER_PATH || url.search !== '' || url.hash !== '') return failure(404, 'MEMBERSHIP_ROUTE_NOT_FOUND')
    if (request.method !== 'POST') return failure(405, 'MEMBERSHIP_POST_REQUIRED', { allow: 'POST' })
    if (request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/cbor') {
      return failure(415, 'MEMBERSHIP_CBOR_REQUIRED')
    }
    let bytes: Uint8Array
    try { bytes = await readMembershipLedgerBody(request, { timeoutMs: bodyTimeoutMs }) }
    catch (error) {
      if (request.signal.aborted || error instanceof Error && error.message === 'MEMBERSHIP_IO_TIMEOUT') return failure(408, 'MEMBERSHIP_REQUEST_TIMEOUT')
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
        const entry = await finality.appendLedgerRecord(operation.recordBytes)
        const proof = await finality.certifiedRead({ after: entry.position - 1, limit: 128 })
        await mirror(proof.certificate)
        encoded = encodeMembershipLedgerResponse(entry)
      } else {
        const page = await finality.certifiedControlRead({ after: operation.after, limit: operation.limit })
        // Local evidence delivery heals a previous interrupted administrative
        // append. None of these application descriptors enter the HTTP response.
        await mirror(page.certificate)
        encoded = encodeMembershipLedgerResponse(page)
      }
      if (encoded.length > MAX_MEMBERSHIP_LEDGER_BYTES) throw new Error('MEMBERSHIP_RESPONSE_TOO_LARGE')
      return new Response(encoded.slice().buffer, { headers: { 'content-type': 'application/cbor', 'cache-control': 'no-store' } })
    } catch (error) {
      return failure(error instanceof Error && error.message === 'AUTHORITY_RANGE_AHEAD' ? 409 : 503,
        'MEMBERSHIP_LEDGER_UNAVAILABLE')
    }
  }
}

function failure(status: number, code: string, headers: Readonly<Record<string, string>> = {}): Response {
  return new Response(code, { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...headers } })
}

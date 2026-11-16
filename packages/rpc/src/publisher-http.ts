import { ChronologRpcError, type RpcErrorCode } from './errors.js'

export interface HttpPublisherIngressOptions {
  readonly baseUrl: string
  readonly groupId: string
  readonly fetch?: typeof fetch
  readonly timeoutMs?: number
}

/**
 * Original-signer ingress for a limited publisher. This deliberately exposes
 * only signed submission and never accepts a replica owner's bearer token.
 * The publisher's durable outbox owns retry/recovery of these exact bytes.
 */
export function createHttpPublisherIngress(options: HttpPublisherIngressOptions) {
  const groupId = options.groupId
  const base = new URL(options.baseUrl)
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new TypeError('Publisher ingress requires an HTTP(S) URL without credentials, query or fragment')
  }
  const endpoint = `${base.href.replace(/\/$/u, '')}/rpc/unary/ingress.submit`
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError('Publisher timeoutMs must be positive')
  const send = options.fetch ?? globalThis.fetch
  return Object.freeze({
    async submitSigned(signedWire: Uint8Array, input: { readonly signal?: AbortSignal } = {}): Promise<{ readonly proposalId: string }> {
      if (!(signedWire instanceof Uint8Array) || signedWire.byteLength === 0) throw new ChronologRpcError('invalid_argument', 'Signed proposal bytes are required')
      if (signedWire.byteLength > 3 * 1024 * 1024 - 1024) throw new ChronologRpcError('resource_exhausted', 'Signed proposal exceeds the HTTP request bound')
      input.signal?.throwIfAborted()
      const signal = input.signal === undefined ? AbortSignal.timeout(timeoutMs) : AbortSignal.any([input.signal, AbortSignal.timeout(timeoutMs)])
      // Encode only the fixed ingress request; application JSON remains inside
      // the original signed canonical record, never reserialized by this layer.
      let binary = ''
      for (let offset = 0; offset < signedWire.length; offset += 16_384) binary += String.fromCharCode(...signedWire.subarray(offset, offset + 16_384))
      try {
        const response = await send(endpoint, { method: 'POST', credentials: 'omit', redirect: 'error',
          headers: { 'content-type': 'application/json' }, signal,
          body: JSON.stringify({ groupId, requestId: crypto.randomUUID(), signedWire: { $chronologRpc: ['bytes', btoa(binary)] } }),
        })
        const body: unknown = await response.json()
        if (typeof body !== 'object' || body === null || !('ok' in body)) throw new ChronologRpcError('internal', 'Malformed publisher ingress response')
        if (body.ok === false && 'error' in body && typeof body.error === 'object' && body.error !== null) {
          const error = body.error as { code?: RpcErrorCode; message?: string; retryable?: boolean }
          throw new ChronologRpcError(error.code ?? 'internal', error.message ?? 'Publisher ingress rejected submission', { retryable: error.retryable === true })
        }
        if (!response.ok || body.ok !== true || !('value' in body) || typeof body.value !== 'object' || body.value === null ||
          !('transactionId' in body.value) || typeof body.value.transactionId !== 'string' ||
          !('durableLocalAppend' in body.value) || body.value.durableLocalAppend !== true) throw new ChronologRpcError('internal', 'Malformed publisher ingress receipt')
        return { proposalId: body.value.transactionId }
      } catch (error) {
        if (error instanceof ChronologRpcError) throw error
        if (signal.aborted) throw new ChronologRpcError(input.signal?.aborted === true ? 'cancelled' : 'deadline_exceeded', 'Publisher ingress request was interrupted', { cause: error })
        throw new ChronologRpcError('transport_unavailable', 'Publisher ingress request failed', { cause: error })
      }
    },
  })
}

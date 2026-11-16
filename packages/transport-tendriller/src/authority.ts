import { createRecordLogClient, type RecordLogClient } from '@tendriller/core/records'
import {
  createPrefixAuthority, decodeOrderingEvidence, encodeOrderingEvidence,
  type CoordinatedHistoryConfiguration, type PrefixCertificate,
} from '@chronolog/node-core/history'
import type { Ed25519KeyPair } from '@chronolog/protocol'

export interface EngineHandler<Env, Context> {
  fetch(request: Request, env: Env, context: Context): Response | Promise<Response>
}

export interface TendrillerAuthorityOptions<Env, Context> {
  readonly configuration: CoordinatedHistoryConfiguration
  /** Stable deployment key; never generated per request or stored in Tendriller core. */
  readonly identity: Ed25519KeyPair
  readonly records: RecordLogClient
  readonly path?: string
  /** Reuse the deployment's owner/agent authentication. Omitted authorization denies all. */
  readonly authorize?: (request: Request, env: Env, context: Context) => boolean | Promise<boolean>
}

/** Reuse the public record route's existing owner/agent authorization in-process. */
export function authorizeThroughRecordLog<Env, Context>(
  engine: EngineHandler<Env, Context>,
  options: { readonly base: string; readonly historyId: string },
): (request: Request, env: Env, context: Context) => Promise<boolean> {
  return async (request, env, context) => {
    const headers: Record<string, string> = {}
    request.headers.forEach((value, key) => { headers[key] = value })
    const records = createRecordLogClient({
      base: options.base,
      headers: () => headers,
      fetch: (input, init) => Promise.resolve(engine.fetch(new Request(input, init), env, context)),
    })
    try {
      await records.info({ historyId: options.historyId, signal: request.signal })
      return true
    } catch { return false }
  }
}

/** Compose around the public engine; ordinary requests and scheduled work stay with it. */
export function withTendrillerAuthority<Env, Context, Handler extends EngineHandler<Env, Context>>(
  engine: Handler,
  options: TendrillerAuthorityOptions<Env, Context>,
): Handler {
  const path = options.path ?? '/_chronolog/certificate'
  if (!path.startsWith('/') || path.includes('?') || path.includes('#')) throw new Error('AUTHORITY_PATH_INVALID')
  const historyId = options.configuration.historyId
  const authority = createPrefixAuthority({
    configuration: options.configuration, identity: options.identity,
    readHead: async () => (await options.records.info({ historyId })).head,
  })
  const fetch = async (request: Request, env: Env, context: Context): Promise<Response> => {
    if (new URL(request.url).pathname !== path) return engine.fetch(request, env, context)
    if (request.method !== 'POST') return new Response('Use POST', { status: 405, headers: { Allow: 'POST' } })
    if (options.authorize === undefined || !await options.authorize(request, env, context)) {
      return new Response('Owner or authorized agent access required', { status: 403 })
    }
    // This endpoint has no caller-supplied signing input, including no root/head.
    if (request.body !== null) return new Response('Certificate requests have no body', { status: 400 })
    try {
      const certificate = await authority.certify()
      return new Response(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }).slice().buffer, {
        headers: { 'Content-Type': 'application/cbor', 'Cache-Control': 'no-store' },
      })
    } catch {
      return new Response('Committed head or signing unavailable; retry certification', { status: 503, headers: { 'Cache-Control': 'no-store' } })
    }
  }
  return { ...engine, fetch }
}

/** Native or page credentials authenticate the request; certificate verification is local. */
export function createCertificateFetcher(options: {
  readonly url: string
  readonly headers?: () => Record<string, string>
  readonly fetch?: typeof globalThis.fetch
}): (signal?: AbortSignal) => Promise<PrefixCertificate> {
  const fetcher = options.fetch ?? globalThis.fetch
  return async (signal) => {
    const response = await fetcher(options.url, { method: 'POST', ...(options.headers === undefined ? {} : { headers: options.headers() }),
      ...(signal === undefined ? {} : { signal }), cache: 'no-store' })
    if (!response.ok) throw new Error(`AUTHORITY_HTTP_${response.status}`)
    const bytes = new Uint8Array(await response.arrayBuffer())
    if (bytes.length > 64 * 1024) throw new Error('AUTHORITY_RESPONSE_TOO_LARGE')
    const evidence = decodeOrderingEvidence(bytes)
    if (evidence.kind !== 'prefix-certificate') throw new Error('AUTHORITY_RESPONSE_NOT_CERTIFICATE')
    return evidence.certificate
  }
}

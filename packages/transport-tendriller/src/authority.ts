import { createRecordLogClient, type RecordLogClient } from '@tendriller/core/records'
import {
  createPrefixAuthority, decodeOrderingEvidence, encodeOrderingEvidence,
  type CoordinatedHistoryConfiguration, type PrefixCertificate,
} from '@chronolog/node-core/history'
import type { Ed25519KeyPair } from '@chronolog/protocol'

export interface AuthorityRequest {
  readonly url: string
  readonly method: string
  readonly body: unknown
  readonly headers: { forEach(callback: (value: string, key: string) => void): void }
}

export interface AuthorityResponse {
  readonly status: number
  arrayBuffer(): Promise<ArrayBuffer>
}

export interface AuthorityHttp<HostRequest extends AuthorityRequest, HostResponse extends AuthorityResponse> {
  request(url: string, init: { readonly method: 'GET'; readonly headers: Record<string, string> }): HostRequest
  response(body: string | ArrayBuffer, init: { readonly status?: number; readonly headers?: Record<string, string> }): HostResponse
}

export interface EngineHandler<Env, Context, HostRequest extends AuthorityRequest = Request, HostResponse extends AuthorityResponse = Response> {
  fetch(request: HostRequest, env: Env, context: Context): HostResponse | Promise<HostResponse>
}

export interface TendrillerAuthorityOptions<Env, Context, HostRequest extends AuthorityRequest = Request, HostResponse extends AuthorityResponse = Response> {
  readonly configuration: CoordinatedHistoryConfiguration
  /** Stable deployment key; never generated per request or stored in Tendriller core. */
  readonly identity: Ed25519KeyPair
  readonly records: RecordLogClient
  /** The host's Web API constructors keep Worker and DOM declarations distinct. */
  readonly http: AuthorityHttp<HostRequest, HostResponse>
  readonly path?: string
  /** Reuse the deployment's owner/agent authentication. Omitted authorization denies all. */
  readonly authorize?: (request: HostRequest, env: Env, context: Context) => boolean | Promise<boolean>
}

/** Reuse the public record route's existing owner/agent authorization in-process. */
export function authorizeThroughRecordLog<Env, Context, HostRequest extends AuthorityRequest, HostResponse extends AuthorityResponse>(
  engine: EngineHandler<Env, Context, HostRequest, HostResponse>,
  options: { readonly base: string; readonly historyId: string; readonly http: AuthorityHttp<HostRequest, HostResponse> },
): (request: HostRequest, env: Env, context: Context) => Promise<boolean> {
  return async (request, env, context) => {
    const headers: Record<string, string> = {}
    request.headers.forEach((value, key) => { headers[key] = value })
    const records = createRecordLogClient({
      base: options.base,
      headers: () => headers,
      fetch: async (input) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
        const response = await engine.fetch(options.http.request(url, { method: 'GET', headers }), env, context)
        // The public SDK reads ordinary JSON, so normalize only that response
        // body/status instead of casting host-specific request/response types.
        return new Response(await response.arrayBuffer(), { status: response.status })
      },
    })
    try {
      await records.info({ historyId: options.historyId })
      return true
    } catch { return false }
  }
}

/** Compose around the public engine; ordinary requests and scheduled work stay with it. */
export function withTendrillerAuthority<Env, Context, HostRequest extends AuthorityRequest, HostResponse extends AuthorityResponse,
  Handler extends EngineHandler<Env, Context, HostRequest, HostResponse>>(
  engine: Handler,
  options: TendrillerAuthorityOptions<Env, Context, HostRequest, HostResponse>,
): Handler {
  const path = options.path ?? '/_chronolog/certificate'
  if (!path.startsWith('/') || path.includes('?') || path.includes('#')) throw new Error('AUTHORITY_PATH_INVALID')
  const historyId = options.configuration.historyId
  const authority = createPrefixAuthority({
    configuration: options.configuration, identity: options.identity,
    readHead: async () => (await options.records.info({ historyId })).head,
  })
  const respond = options.http.response.bind(options.http)
  const fetch = async (request: HostRequest, env: Env, context: Context): Promise<HostResponse> => {
    if (new URL(request.url).pathname !== path) return engine.fetch(request, env, context)
    if (request.method !== 'POST') return respond('Use POST', { status: 405, headers: { Allow: 'POST' } })
    if (options.authorize === undefined || !await options.authorize(request, env, context)) {
      return respond('Owner or authorized agent access required', { status: 403 })
    }
    // This endpoint has no caller-supplied signing input, including no root/head.
    if (request.body !== null) return respond('Certificate requests have no body', { status: 400 })
    try {
      const certificate = await authority.certify()
      return respond(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }).slice().buffer, {
        headers: { 'Content-Type': 'application/cbor', 'Cache-Control': 'no-store' },
      })
    } catch {
      return respond('Committed head or signing unavailable; retry certification', { status: 503, headers: { 'Cache-Control': 'no-store' } })
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

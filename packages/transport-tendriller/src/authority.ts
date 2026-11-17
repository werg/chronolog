import { createRecordLogClient, decodeRecord, recordGenesisRoot, type RecordLogClient } from '@tendriller/core/records'
import {
  createPrefixAuthority, decodeOrderingEvidence, encodeOrderingEvidence,
  type CoordinatedHistoryConfiguration, type OrderedRecordEntry, type OrderedRecordHead, type PrefixCertificate,
} from '@chronolog/node-core/history'
import { createFinalityClosureRecord, evaluateFinalitySnapshot, extendFinalityControlCommitment, type SignedInclusionSnapshot } from '@chronolog/node-core/finality'
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
  readonly now?: () => number
  readonly cutoffLagMs?: number
  /** Must equal signed genesis maxFutureSkewMs + cutoffLagMs; defaults to 31,000. */
  readonly futureAdmissionWindowMs?: number
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
  const configuration = structuredClone(options.configuration)
  const identity = { ...options.identity, publicKeyBytes: new Uint8Array(options.identity.publicKeyBytes) }
  const historyId = configuration.historyId
  const now = options.now ?? Date.now, cutoffLagMs = options.cutoffLagMs ?? 1_000
  const futureAdmissionWindowMs = options.futureAdmissionWindowMs ?? 31_000
  if (!Number.isSafeInteger(cutoffLagMs) || cutoffLagMs < 0 ||
      !Number.isSafeInteger(futureAdmissionWindowMs) || futureAdmissionWindowMs < 0) throw new Error('AUTHORITY_CLOCK_CONFIGURATION_INVALID')
  let committedHead: OrderedRecordHead | null = null
  let cachedSnapshot: SignedInclusionSnapshot | null = null
  const authority = createPrefixAuthority({
    configuration, identity,
    readHead: async () => {
      if (committedHead === null) throw new Error('AUTHORITY_HEAD_UNAVAILABLE')
      return structuredClone(committedHead)
    },
  })
  let pending: Promise<void> = Promise.resolve()
  const certify = (): Promise<PrefixCertificate> => {
    const operation = pending.then(async () => {
      for (let attempt = 0; attempt < 64; attempt += 1) {
        const head = structuredClone((await options.records.info({ historyId })).head)
        let snapshot = cachedSnapshot
        if (snapshot === null || snapshot.includedThrough !== head.position || snapshot.checkpointId !== head.root) {
          const entries: OrderedRecordEntry[] = []
          let previous = { historyId, position: 0, root: await recordGenesisRoot(historyId), bytes: 0 }
          while (previous.position < head.position) {
            const page = await options.records.read({ historyId, after: previous.position, previous })
            for (const entry of page.entries) {
              if (entry.position > head.position) break
              const bytes = decodeRecord(entry.record)
              entries.push({ historyId: entry.historyId, position: entry.position, recordId: entry.recordId,
                previousRoot: entry.previousRoot, root: entry.root, bytes })
              previous = { historyId, position: entry.position, root: entry.root, bytes: previous.bytes + bytes.length }
            }
          }
          if (previous.root !== head.root) throw new Error('TENDRILLER_HISTORY_CONFLICT')
          snapshot = await evaluateFinalitySnapshot(configuration, entries)
          cachedSnapshot = snapshot
        }
        const observed = Math.trunc(now())
        if (!Number.isSafeInteger(observed) || observed < 0) throw new Error('AUTHORITY_CLOCK_INVALID')
        const cutoff = BigInt(observed) - BigInt(cutoffLagMs)
        const uncovered = snapshot.records.some((record) => record.closureBoundary === null)
        let coveredDemand = -1n
        for (const record of snapshot.records) {
          if (record.closureBoundary === null) continue
          const horizon = record.closureBoundary.closedThroughMs + BigInt(futureAdmissionWindowMs)
          if (horizon > coveredDemand) coveredDemand = horizon
        }
        const requestedCutoff = uncovered || cutoff < coveredDemand ? cutoff : coveredDemand
        const closedThroughMs = requestedCutoff > snapshot.closedThroughMs ? requestedCutoff : snapshot.closedThroughMs
        if (closedThroughMs >= 0n && (closedThroughMs > snapshot.closedThroughMs || uncovered)) {
          const marker = await createFinalityClosureRecord({ configuration, identity, includedHead: head, closedThroughMs, control: await extendFinalityControlCommitment(snapshot, closedThroughMs) })
          try {
            // The generic conditional append prevents a concurrent submission
            // from separating this signed closure from its exact predecessor.
            const retained = await options.records.append(marker, { historyId,
              expectedHead: { position: head.position, root: head.root } })
            if (retained.position !== head.position + 1 || retained.previousRoot !== head.root) {
              throw new Error('FINALITY_CLOSURE_HEAD_MISMATCH')
            }
            committedHead = { historyId, position: retained.position, root: retained.root }
          } catch (error) {
            if (error !== null && typeof error === 'object' && 'code' in error && error.code === 'record_head_conflict') continue
            throw error
          }
        } else committedHead = head
        return authority.certify()
      }
      throw new Error('AUTHORITY_HEAD_BUSY')
    })
    pending = operation.then(() => undefined, () => undefined)
    return operation
  }
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
      const certificate = await certify()
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

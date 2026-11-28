import {
  assertCanonicalCbor,
  DEFAULT_DECODE_LIMITS,
  encodeCanonicalCbor,
  type CborMapKey,
  type CborValue,
} from '@chronolog/canonical'
import {
  FactIdSet,
  reconcileRanges,
  type ReconcileRange,
} from './reconcile.js'
export { FactIdSet } from './reconcile.js'
import { normalizeVerifiedCasNode, type MirrorCasNode } from './cas-mirror.js'

const HEX32 = /^[0-9a-f]{64}$/u

export const HTTP_SYNC_V3_MEDIA_TYPE = 'application/vnd.chronolog.sync-v3+cbor'

export type HttpSyncScope = 'control' | 'mailbox'

export interface HttpSyncFactItem {
  readonly id: string
  readonly bytes: Uint8Array
}

export interface HttpSyncPayload {
  readonly format: 'chronolog-http-sync/v3'
  readonly ranges: readonly ReconcileRange[]
  readonly push: readonly HttpSyncFactItem[]
  readonly want: readonly string[]
  readonly casPush?: readonly MirrorCasNode[]
  readonly casWant?: readonly string[]
  readonly meta?: Readonly<Record<string, unknown>>
  /** Reply only: the server held back facts or ranges (reply limits); reconcile again from the root. */
  readonly more?: boolean
  /** Reply only: how many of the request's pushed facts the server stored. */
  readonly accepted?: number
}

/** Range entries per message (both directions). */
export const HTTP_SYNC_MAX_RANGES = 256
/** Fact pairs / wanted ids per message. */
export const HTTP_SYNC_MAX_ITEMS = 512
/** Summary ranges a client sends per request, so a 16-way split reply stays within `HTTP_SYNC_MAX_RANGES`. */
const CLIENT_SUMMARIES_PER_REQUEST = HTTP_SYNC_MAX_RANGES / 16

function encodeRanges(ranges: readonly ReconcileRange[]): CborValue[] {
  return ranges.map(r => {
    if ('ids' in r) {
      return new Map<CborMapKey, CborValue>([
        ['ids', [...r.ids]],
        ['prefix', r.prefix],
      ])
    }
    return new Map<CborMapKey, CborValue>([
      ['count', BigInt(r.count)],
      ['fp', r.fp],
      ['prefix', r.prefix],
    ])
  })
}

function decodeRanges(raw: unknown): ReconcileRange[] {
  if (!Array.isArray(raw)) throw new Error('HTTP_SYNC_RANGES_INVALID')
  if (raw.length > HTTP_SYNC_MAX_RANGES) throw new Error('HTTP_SYNC_TOO_MANY_RANGES')
  const out: ReconcileRange[] = []
  for (const item of raw) {
    if (!(item instanceof Map)) throw new Error('HTTP_SYNC_RANGE_INVALID')
    const map = item as ReadonlyMap<CborMapKey, CborValue>
    const prefix = map.get('prefix')
    if (typeof prefix !== 'string') throw new Error('HTTP_SYNC_RANGE_INVALID')
    const ids = map.get('ids')
    if (ids !== undefined) {
      if (!Array.isArray(ids) || ids.length > 512) throw new Error('HTTP_SYNC_RANGE_IDS_INVALID')
      const clean: string[] = []
      for (const id of ids) {
        if (typeof id !== 'string' || !HEX32.test(id)) throw new Error('HTTP_SYNC_RANGE_ID_INVALID')
        clean.push(id)
      }
      out.push({ prefix, ids: clean })
    } else {
      const count = map.get('count')
      const fp = map.get('fp')
      if (typeof count !== 'bigint' || count < 0n || !(fp instanceof Uint8Array) || fp.byteLength !== 16) {
        throw new Error('HTTP_SYNC_RANGE_SUMMARY_INVALID')
      }
      out.push({ prefix, count: Number(count), fp: fp.slice() })
    }
  }
  return out
}

function encodePairs(items: readonly { readonly id?: string; readonly hash?: string; readonly bytes: Uint8Array }[]): CborValue[] {
  return items.map(item => [item.id ?? item.hash ?? '', item.bytes])
}

function decodePairs(raw: unknown, maxItems: number): HttpSyncFactItem[] {
  if (raw === undefined) return []
  if (!Array.isArray(raw) || raw.length > maxItems) throw new Error('HTTP_SYNC_ITEMS_INVALID')
  const out: HttpSyncFactItem[] = []
  for (const item of raw) {
    if (!Array.isArray(item) || item.length !== 2 || typeof item[0] !== 'string' || !HEX32.test(item[0]) || !(item[1] instanceof Uint8Array)) {
      throw new Error('HTTP_SYNC_ITEM_INVALID')
    }
    out.push({ id: item[0], bytes: item[1].slice() })
  }
  return out
}

function decodeStringList(raw: unknown, maxItems: number): string[] {
  if (raw === undefined) return []
  if (!Array.isArray(raw) || raw.length > maxItems) throw new Error('HTTP_SYNC_LIST_INVALID')
  const out: string[] = []
  for (const item of raw) {
    if (typeof item !== 'string' || !HEX32.test(item)) throw new Error('HTTP_SYNC_ID_INVALID')
    out.push(item)
  }
  return out
}

function unknownToCbor(value: unknown, depth = 0): CborValue {
  if (depth > 8 || value === null || value === undefined) return null
  if (typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'number') return Number.isSafeInteger(value) ? BigInt(value) : String(value)
  if (typeof value === 'bigint') return value
  if (value instanceof Uint8Array) return value
  if (Array.isArray(value)) return value.map(v => unknownToCbor(v, depth + 1))
  if (typeof value === 'object') {
    const map = new Map<CborMapKey, CborValue>()
    for (const [k, v] of Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
      if (v !== undefined) map.set(k, unknownToCbor(v, depth + 1))
    }
    return map
  }
  return null
}

function cborToMeta(value: unknown): Record<string, unknown> | undefined {
  if (!(value instanceof Map)) return undefined
  const out: Record<string, unknown> = {}
  for (const [k, v] of value as ReadonlyMap<CborMapKey, CborValue>) {
    if (typeof k !== 'string') continue
    if (typeof v === 'bigint') out[k] = Number(v)
    else if (v instanceof Map) out[k] = cborToMeta(v)
    else out[k] = v
  }
  return out
}

export function encodeHttpSyncPayload(payload: HttpSyncPayload): Uint8Array {
  const map = new Map<CborMapKey, CborValue>([
    ['format', 'chronolog-http-sync/v3'],
    ['push', encodePairs(payload.push)],
    ['ranges', encodeRanges(payload.ranges)],
    ['want', [...payload.want]],
  ])
  if (payload.casPush !== undefined && payload.casPush.length > 0) {
    map.set('casPush', encodePairs(payload.casPush))
  }
  if (payload.casWant !== undefined && payload.casWant.length > 0) {
    map.set('casWant', [...payload.casWant])
  }
  if (payload.meta !== undefined) {
    map.set('meta', unknownToCbor(payload.meta))
  }
  if (payload.more === true) map.set('more', true)
  if (payload.accepted !== undefined) map.set('accepted', BigInt(payload.accepted))
  return encodeCanonicalCbor(map)
}

export function decodeHttpSyncPayload(bytes: Uint8Array, maxBytes = 16 * 1024 * 1024): HttpSyncPayload {
  const decoded = assertCanonicalCbor(bytes, { ...DEFAULT_DECODE_LIMITS, maxBytes })
  if (!(decoded instanceof Map)) throw new Error('HTTP_SYNC_PAYLOAD_INVALID')
  const map = decoded as ReadonlyMap<CborMapKey, CborValue>
  if (map.get('format') !== 'chronolog-http-sync/v3') throw new Error('HTTP_SYNC_FORMAT_INVALID')
  const ranges = decodeRanges(map.get('ranges'))
  const push = decodePairs(map.get('push'), HTTP_SYNC_MAX_ITEMS)
  const want = decodeStringList(map.get('want'), HTTP_SYNC_MAX_ITEMS)
  const casPushRaw = decodePairs(map.get('casPush'), 256)
  const casPush = casPushRaw.map(item => ({ hash: item.id, bytes: item.bytes }))
  const casWant = decodeStringList(map.get('casWant'), 256)
  const meta = cborToMeta(map.get('meta'))
  const more = map.get('more'), accepted = map.get('accepted')
  if (more !== undefined && more !== true) throw new Error('HTTP_SYNC_PAYLOAD_INVALID')
  if (accepted !== undefined && (typeof accepted !== 'bigint' || accepted < 0n || accepted > BigInt(HTTP_SYNC_MAX_ITEMS))) throw new Error('HTTP_SYNC_PAYLOAD_INVALID')
  return {
    format: 'chronolog-http-sync/v3',
    ranges,
    push,
    want,
    ...(casPush.length > 0 ? { casPush } : {}),
    ...(casWant.length > 0 ? { casWant } : {}),
    ...(meta !== undefined ? { meta } : {}),
    ...(more === true ? { more: true } : {}),
    ...(accepted === undefined ? {} : { accepted: Number(accepted) }),
  }
}

/**
 * Backend store contract for WinterCG binary CBOR sync-v3 HTTP reconciliation.
 * Implementations verify incoming signatures / permissions / CAS reachability inside `putFacts`.
 */
export interface BlindSyncStore {
  listIds(scope: HttpSyncScope): Promise<FactIdSet | readonly string[]>
  getFacts(scope: HttpSyncScope, ids: readonly string[]): Promise<readonly HttpSyncFactItem[]>
  putFacts(
    scope: HttpSyncScope,
    items: readonly HttpSyncFactItem[],
    casPush: readonly MirrorCasNode[],
  ): Promise<{ readonly accepted: number; readonly meta?: Readonly<Record<string, unknown>> }>
  getCasNodes?(scope: HttpSyncScope, hashes: readonly string[]): Promise<readonly MirrorCasNode[]>
  getMeta?(scope: HttpSyncScope): Promise<Readonly<Record<string, unknown>> | undefined>
}

export interface HttpSyncHandlerOptions {
  readonly store: BlindSyncStore
  readonly basePath?: string
  readonly maxRequestBytes?: number
  readonly maxPushPerReply?: number
  readonly maxPushBytesPerReply?: number
  readonly headers?: Readonly<Record<string, string>>
}

function toFactIdSet(ids: FactIdSet | readonly string[]): FactIdSet {
  if (ids instanceof FactIdSet) return ids
  const set = new FactIdSet()
  for (const id of ids) set.add(id)
  return set
}

/**
 * WinterCG-native binary CBOR sync-v3 HTTP reconciliation handler (`POST /sync/control` & `POST /sync/mailbox`).
 * Replaces O(N) hex-JSON `knownOpIds`/`knownEnvelopeDigests` lists with O(d · log16(N)) range-fingerprint
 * reconciliation over compact binary CBOR.
 */
export function createHttpSyncHandler(options: HttpSyncHandlerOptions): (request: Request) => Promise<Response> {
  const basePath = (options.basePath ?? '').replace(/\/+$/u, '')
  const maxRequestBytes = options.maxRequestBytes ?? 8 * 1024 * 1024
  const maxPushPerReply = options.maxPushPerReply ?? 256
  const maxPushBytesPerReply = options.maxPushBytesPerReply ?? 4 * 1024 * 1024

  return async (request: Request): Promise<Response> => {
    const extraHeaders = options.headers ?? {}
    const url = new URL(request.url)
    let path = url.pathname
    if (basePath.length > 0) {
      if (!path.startsWith(`${basePath}/`)) return new Response('Not found', { status: 404, headers: extraHeaders })
      path = path.slice(basePath.length)
    }
    const match = /^\/sync\/(control|mailbox)$/u.exec(path)
    if (match === null) return new Response('Not found', { status: 404, headers: extraHeaders })
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: extraHeaders })

    const scope = match[1] as HttpSyncScope
    const rawBody = new Uint8Array(await request.arrayBuffer())
    if (rawBody.byteLength > maxRequestBytes) {
      return new Response('Payload too large', { status: 413, headers: extraHeaders })
    }
    let incoming: HttpSyncPayload
    try {
      incoming = decodeHttpSyncPayload(rawBody, maxRequestBytes)
    } catch (err) {
      return new Response(JSON.stringify({ error: err instanceof Error ? err.message : 'invalid_sync_payload' }), {
        status: 400,
        headers: { ...options.headers, 'Content-Type': 'application/json' },
      })
    }

    // Verify any pushed CAS nodes before handing to store
    const verifiedCas: MirrorCasNode[] = []
    for (const node of incoming.casPush ?? []) {
      const norm = normalizeVerifiedCasNode(node.hash, node.bytes)
      if (norm === null) {
        return new Response(JSON.stringify({ error: 'cas_hash_mismatch', hash: node.hash }), {
          status: 400,
          headers: { ...options.headers, 'Content-Type': 'application/json' },
        })
      }
      verifiedCas.push({ hash: node.hash, bytes: norm })
    }

    let putMeta: Readonly<Record<string, unknown>> | undefined, accepted = 0
    if (incoming.push.length > 0 || verifiedCas.length > 0) {
      const putRes = await options.store.putFacts(scope, incoming.push, verifiedCas)
      putMeta = putRes.meta
      accepted = Math.max(0, Math.min(incoming.push.length, putRes.accepted))
    }

    const localIds = toFactIdSet(await options.store.listIds(scope))
    const step = reconcileRanges(localIds, incoming.ranges)
    // Nothing is dropped silently: whatever does not fit this reply sets `more`, and the client
    // reconciles again from the root, rediscovering exactly what it still lacks.
    let more = step.reply.length > HTTP_SYNC_MAX_RANGES
    const replyRanges = more ? step.reply.slice(0, HTTP_SYNC_MAX_RANGES) : step.reply
    const replyWant = step.want.slice(0, HTTP_SYNC_MAX_ITEMS)
    if (replyWant.length < step.want.length) more = true

    const owed = [...new Set([...incoming.want, ...step.push])]
    const toSendIds = owed.slice(0, Math.min(maxPushPerReply, HTTP_SYNC_MAX_ITEMS))
    if (toSendIds.length < owed.length) more = true
    const rawItems = toSendIds.length > 0 ? await options.store.getFacts(scope, toSendIds) : []
    const boundedPush: HttpSyncFactItem[] = []
    let pushBytes = 0
    for (const item of rawItems) {
      if (pushBytes + item.bytes.byteLength > maxPushBytesPerReply && boundedPush.length > 0) { more = true; break }
      boundedPush.push(item)
      pushBytes += item.bytes.byteLength
    }

    const casNodes = incoming.casWant !== undefined && incoming.casWant.length > 0 && options.store.getCasNodes !== undefined
      ? await options.store.getCasNodes(scope, incoming.casWant)
      : []

    const meta = putMeta ?? (options.store.getMeta !== undefined ? await options.store.getMeta(scope) : undefined)
    const reply = encodeHttpSyncPayload({
      format: 'chronolog-http-sync/v3',
      ranges: replyRanges,
      push: boundedPush,
      want: replyWant,
      ...(casNodes.length > 0 ? { casPush: casNodes } : {}),
      ...(meta !== undefined ? { meta } : {}),
      ...(more ? { more: true } : {}),
      ...(incoming.push.length > 0 ? { accepted } : {}),
    })
    const headers = new Headers(options.headers)
    headers.set('Content-Type', HTTP_SYNC_V3_MEDIA_TYPE)
    headers.set('Cache-Control', 'no-store')
    headers.set('X-Content-Type-Options', 'nosniff')
    return new Response(reply.slice(), { status: 200, headers })
  }
}

export interface HttpSyncClientOptions {
  readonly fetch?: typeof fetch
  readonly headers?: Readonly<Record<string, string>> | (() => Readonly<Record<string, string>> | Promise<Readonly<Record<string, string>>>)
  /** Request budget per `reconcile` call (default 256). */
  readonly maxRounds?: number
  /** Facts pushed per request (default 256, at most 512). */
  readonly maxPushPerRequest?: number
  /** Pushed bytes per request (default 4 MiB). */
  readonly maxPushBytesPerRequest?: number
}

export interface HttpSyncLocalFacts {
  readonly ids: FactIdSet
  readonly getFacts: (ids: readonly string[]) => Promise<readonly HttpSyncFactItem[]>
  /**
   * Verify and store facts the server sent; return the ids actually accepted. Only those are
   * added to `ids`, so rejected or unverifiable bytes are never counted as held.
   */
  readonly onReceive: (items: readonly HttpSyncFactItem[], casNodes: readonly MirrorCasNode[]) => Promise<readonly string[]>
  readonly casPush?: readonly MirrorCasNode[]
  readonly casWant?: readonly string[]
  readonly signal?: AbortSignal
}

export interface HttpSyncReconcileResult {
  readonly rounds: number
  readonly pushed: number
  readonly pulled: number
  /** True when the final root fingerprints matched; false when the budget ran out or no progress was possible. */
  readonly converged: boolean
  readonly meta?: Readonly<Record<string, unknown>>
}

export interface HttpSyncClient {
  readonly baseUrl: string
  reconcile(scope: HttpSyncScope, local: HttpSyncLocalFacts): Promise<HttpSyncReconcileResult>
}

/**
 * Binary CBOR sync-v3 HTTP client implementing O(d · log16(N)) range-fingerprint reconciliation.
 *
 * It runs passes from the root summary until the root fingerprints match. Within a pass, ranges,
 * pushes and wants beyond the per-request limits are queued for the next request; a server
 * reply marked `more` (it held something back) starts another pass. A pass that moves nothing
 * new ends the call with `converged: false` instead of looping.
 */
export function createHttpSyncClient(baseUrl: string, options: HttpSyncClientOptions = {}): HttpSyncClient {
  const base = baseUrl.replace(/\/+$/u, '')
  const doFetch = options.fetch ?? fetch
  const maxRounds = options.maxRounds ?? 256
  const maxPush = Math.min(options.maxPushPerRequest ?? 256, HTTP_SYNC_MAX_ITEMS)
  const maxPushBytes = options.maxPushBytesPerRequest ?? 4 * 1024 * 1024
  const headersFor = async (): Promise<Readonly<Record<string, string>>> =>
    typeof options.headers === 'function' ? await options.headers() : options.headers ?? {}

  return {
    baseUrl: base,
    async reconcile(scope, local) {
      let rounds = 0, pushed = 0, pulled = 0
      let lastMeta: Readonly<Record<string, unknown>> | undefined
      let pendingCasPush = local.casPush ?? [], pendingCasWant = local.casWant ?? []
      const summaries: ReconcileRange[] = [], lists: ReconcileRange[] = []
      const pushQueue = new Set<string>(), wantQueue = new Set<string>()

      while (rounds < maxRounds) {
        // ---- one pass, starting from the root summary ----
        summaries.push(local.ids.summary(''))
        let passRounds = 0, progress = 0, more = false, exchanged = false
        while (summaries.length + lists.length + pushQueue.size + wantQueue.size > 0 && rounds < maxRounds) {
          local.signal?.throwIfAborted()
          rounds++; passRounds++
          const ranges = summaries.splice(0, CLIENT_SUMMARIES_PER_REQUEST)
          ranges.push(...lists.splice(0, HTTP_SYNC_MAX_RANGES - ranges.length))
          const pushIds = take(pushQueue, maxPush)
          const want = take(wantQueue, HTTP_SYNC_MAX_ITEMS)
          const pushItems: HttpSyncFactItem[] = []
          let pushBytes = 0
          for (const item of pushIds.length > 0 ? await local.getFacts(pushIds) : []) {
            if (pushItems.length > 0 && pushBytes + item.bytes.byteLength > maxPushBytes) { pushQueue.add(item.id); continue }
            pushItems.push(item); pushBytes += item.bytes.byteLength
          }
          const body = encodeHttpSyncPayload({
            format: 'chronolog-http-sync/v3',
            ranges,
            push: pushItems,
            want,
            ...(pendingCasPush.length > 0 ? { casPush: pendingCasPush } : {}),
            ...(pendingCasWant.length > 0 ? { casWant: pendingCasWant } : {}),
          })
          pendingCasPush = []; pendingCasWant = []

          const resp = await doFetch(`${base}/sync/${scope}`, {
            method: 'POST',
            headers: { ...await headersFor(), 'Content-Type': HTTP_SYNC_V3_MEDIA_TYPE },
            body: body.slice(),
            ...(local.signal === undefined ? {} : { signal: local.signal }),
          })
          if (!resp.ok) throw new Error(`HTTP_SYNC_FAILED:${resp.status}`)
          const reply = decodeHttpSyncPayload(new Uint8Array(await resp.arrayBuffer()))
          if (reply.meta !== undefined) lastMeta = reply.meta
          if (reply.more === true) more = true
          pushed += pushItems.length
          progress += Math.min(pushItems.length, reply.accepted ?? 0)

          if (reply.push.length > 0 || (reply.casPush?.length ?? 0) > 0) {
            const offered = new Set(reply.push.map(item => item.id))
            const accepted = (await local.onReceive(reply.push, reply.casPush ?? [])).filter(id => offered.has(id) && !local.ids.has(id))
            for (const id of accepted) local.ids.add(id)
            pulled += accepted.length; progress += accepted.length
          }
          if (reply.ranges.length > 0 || reply.push.length > 0 || reply.want.length > 0) exchanged = true

          const step = reconcileRanges(local.ids, reply.ranges)
          for (const range of step.reply) ('ids' in range ? lists : summaries).push(range)
          for (const id of [...reply.want, ...step.push]) pushQueue.add(id)
          for (const id of step.want) if (!local.ids.has(id)) wantQueue.add(id)
        }
        if (summaries.length + lists.length + pushQueue.size + wantQueue.size > 0) break // budget exhausted mid-pass
        // A single round with nothing exchanged means the root fingerprints matched.
        if (passRounds === 1 && !exchanged && !more) {
          return { rounds, pushed, pulled, converged: true, ...(lastMeta === undefined ? {} : { meta: lastMeta }) }
        }
        if (progress === 0) break // nothing new can move (rejected or unverifiable facts)
      }
      return { rounds, pushed, pulled, converged: false, ...(lastMeta === undefined ? {} : { meta: lastMeta }) }
    },
  }
}

function take(queue: Set<string>, count: number): string[] {
  const out: string[] = []
  for (const id of queue) { if (out.length >= count) break; out.push(id) }
  for (const id of out) queue.delete(id)
  return out
}

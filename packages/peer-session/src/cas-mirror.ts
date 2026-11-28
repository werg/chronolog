import {
  assertCanonicalCbor,
  DEFAULT_DECODE_LIMITS,
  encodeCanonicalCbor,
  equalBytes,
  hexToBytes,
  utf8,
  type CborMapKey,
  type CborValue,
} from '@chronolog/canonical'
import { verifyEd25519Sync } from '@chronolog/crypto'
import { canonicalJson, type JsonValue } from '@chronolog/protocol'
import {
  casRef,
  computeCasHash,
  decodeCasNode,
  decodeTreeNode,
  encodeCasNode,
  hashCasNode,
  normalizePosixPath,
  parseCasRef,
  tryParseCasRef,
  type BytesStore,
  type CasPartition,
  type ContentAddressedStore,
} from '@chronolog/records'

const HEX32 = /^[0-9a-f]{64}$/u
const HEX64 = /^[0-9a-f]{128}$/u

export const CAS_NODE_MEDIA_TYPE = 'application/vnd.chronolog.cas-node+cbor'
export const CAS_SUBGRAPH_MEDIA_TYPE = 'application/vnd.chronolog.cas-subgraph+cbor'

export interface MirrorBuildAttestation {
  readonly payload: {
    readonly format: 'chronolog-attestation/v1'
    readonly kind: 'build'
    readonly drvRef: string
    readonly outputRef: string
    readonly runtime: string
  }
  readonly signer: string
  readonly signature: string
}

export interface MirrorAuditAttestation {
  readonly payload: {
    readonly format: 'chronolog-attestation/v1'
    readonly kind: 'audit'
    readonly pkgRef: string
    readonly verdict: 'approved' | 'revoked'
    readonly notes?: string
  }
  readonly signer: string
  readonly signature: string
}

export interface MirrorCasNode {
  readonly hash: string
  readonly bytes: Uint8Array
}

export interface CasMirrorStore {
  getNode(hash: string): Promise<Uint8Array | null>
  hasNode?(hash: string): Promise<boolean>
  putNode?(hash: string, encodedNode: Uint8Array): Promise<void>
  listAttestations?(drvHash: string): Promise<readonly MirrorBuildAttestation[]>
  putAttestation?(drvHash: string, attestation: MirrorBuildAttestation): Promise<void>
  listAudits?(pkgHash: string): Promise<readonly MirrorAuditAttestation[]>
  putAudit?(pkgHash: string, audit: MirrorAuditAttestation): Promise<void>
}

export function verifyMirrorBuildAttestation(att: unknown): att is MirrorBuildAttestation {
  if (att === null || typeof att !== 'object') return false
  const rec = att as Record<string, unknown>
  const payload = rec.payload
  if (payload === null || typeof payload !== 'object') return false
  const p = payload as Record<string, unknown>
  if (p.format !== 'chronolog-attestation/v1' || p.kind !== 'build') return false
  if (typeof p.drvRef !== 'string' || tryParseCasRef(p.drvRef) === null) return false
  if (typeof p.outputRef !== 'string' || tryParseCasRef(p.outputRef) === null) return false
  if (typeof p.runtime !== 'string' || p.runtime.length === 0 || p.runtime.length > 256) return false
  if (typeof rec.signer !== 'string' || !HEX32.test(rec.signer)) return false
  if (typeof rec.signature !== 'string' || !HEX64.test(rec.signature)) return false
  const msg = utf8(`chronolog/attestation/v1:${canonicalJson(p as unknown as JsonValue)}`)
  return verifyEd25519Sync(hexToBytes(rec.signer), msg, hexToBytes(rec.signature))
}

export function verifyMirrorAuditAttestation(att: unknown): att is MirrorAuditAttestation {
  if (att === null || typeof att !== 'object') return false
  const rec = att as Record<string, unknown>
  const payload = rec.payload
  if (payload === null || typeof payload !== 'object') return false
  const p = payload as Record<string, unknown>
  if (p.format !== 'chronolog-attestation/v1' || p.kind !== 'audit') return false
  if (typeof p.pkgRef !== 'string' || tryParseCasRef(p.pkgRef) === null) return false
  if (p.verdict !== 'approved' && p.verdict !== 'revoked') return false
  if (p.notes !== undefined && typeof p.notes !== 'string') return false
  if (typeof rec.signer !== 'string' || !HEX32.test(rec.signer)) return false
  if (typeof rec.signature !== 'string' || !HEX64.test(rec.signature)) return false
  const msg = utf8(`chronolog/attestation/v1:${canonicalJson(p as unknown as JsonValue)}`)
  return verifyEd25519Sync(hexToBytes(rec.signer), msg, hexToBytes(rec.signature))
}

/** Verify raw or pre-encoded CAS node bytes against expectedHash and return canonical CasNode bytes. */
export function normalizeVerifiedCasNode(expectedHash: string, raw: Uint8Array, maxBytes = 4 * 1024 * 1024): Uint8Array | null {
  if (!HEX32.test(expectedHash)) return null
  if (raw.byteLength > maxBytes + 65_536) return null
  if (hashCasNode(raw) === expectedHash) {
    try {
      const node = decodeCasNode(raw)
      if (!equalBytes(encodeCasNode(node.bytes, node.links), raw)) return null
      return raw.slice()
    } catch {
      return null
    }
  }
  if (raw.byteLength <= maxBytes && computeCasHash(raw, []) === expectedHash) {
    return encodeCasNode(raw, [])
  }
  return null
}

/** Encode a CAS subgraph response/batch payload as canonical CBOR. */
export function encodeCasSubgraphBundle(rootHash: string, nodes: readonly MirrorCasNode[]): Uint8Array {
  const entries: CborValue[] = nodes.map(n => [n.hash, n.bytes])
  return encodeCanonicalCbor(new Map<CborMapKey, CborValue>([
    ['format', 'chronolog-cas-subgraph/v1'],
    ['nodes', entries],
    ['root', rootHash],
  ]))
}

/** Decode a CAS subgraph bundle produced by `encodeCasSubgraphBundle`. */
export function decodeCasSubgraphBundle(bytes: Uint8Array): { readonly root: string; readonly nodes: readonly MirrorCasNode[] } {
  const decoded = assertCanonicalCbor(bytes, { ...DEFAULT_DECODE_LIMITS, maxBytes: 32 * 1024 * 1024 })
  if (!(decoded instanceof Map)) throw new Error('CAS_SUBGRAPH_BUNDLE_INVALID')
  const map = decoded as ReadonlyMap<CborMapKey, CborValue>
  if (map.get('format') !== 'chronolog-cas-subgraph/v1') throw new Error('CAS_SUBGRAPH_BUNDLE_INVALID')
  const root = map.get('root')
  const rawNodes = map.get('nodes')
  if (typeof root !== 'string' || !HEX32.test(root) || !Array.isArray(rawNodes)) {
    throw new Error('CAS_SUBGRAPH_BUNDLE_INVALID')
  }
  const nodes: MirrorCasNode[] = []
  for (const item of rawNodes) {
    if (!Array.isArray(item) || item.length !== 2 || typeof item[0] !== 'string' || !(item[1] instanceof Uint8Array)) {
      throw new Error('CAS_SUBGRAPH_BUNDLE_INVALID')
    }
    if (!HEX32.test(item[0])) throw new Error('CAS_SUBGRAPH_BUNDLE_INVALID')
    nodes.push({ hash: item[0], bytes: item[1].slice() })
  }
  return { root, nodes }
}

/**
 * Resolve trusted output consensus from a list of verified build attestations.
 * Returns the agreed outputRef and signing builder public keys when at least `threshold`
 * distinct trusted builders attested to the exact same outputRef.
 */
export function resolveTrustedBuildOutput(
  drvRef: string,
  attestations: readonly MirrorBuildAttestation[],
  trustedBuilders: readonly string[],
  threshold = 1,
): { readonly outputRef: string; readonly outputHash: string; readonly signers: readonly string[] } | null {
  const allowed = new Set(trustedBuilders)
  const required = Math.max(1, Math.floor(threshold))
  const byOutput = new Map<string, Set<string>>()
  for (const att of attestations) {
    if (!verifyMirrorBuildAttestation(att)) continue
    if (att.payload.drvRef !== drvRef) continue
    if (!allowed.has(att.signer)) continue
    const set = byOutput.get(att.payload.outputRef) ?? new Set<string>()
    set.add(att.signer)
    byOutput.set(att.payload.outputRef, set)
  }
  // Pick deterministically if multiple outputs ever meet threshold (lexicographic by outputRef).
  for (const [outputRef, signers] of [...byOutput.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    if (signers.size >= required) {
      return {
        outputRef,
        outputHash: parseCasRef(outputRef),
        signers: [...signers].sort(),
      }
    }
  }
  return null
}

/** Back a `CasMirrorStore` with any Chronolog `BytesStore` (Memory, node:sqlite, DO SQLite, IndexedDB). */
export function createBytesStoreCasMirrorStore(store: BytesStore, prefix = 'mirror/'): CasMirrorStore {
  const dec = new TextDecoder()
  return {
    async getNode(hash: string): Promise<Uint8Array | null> {
      return store.get(`${prefix}cas/${hash}`)
    },
    async hasNode(hash: string): Promise<boolean> {
      return (await store.get(`${prefix}cas/${hash}`)) !== null
    },
    async putNode(hash: string, encodedNode: Uint8Array): Promise<void> {
      await store.put(`${prefix}cas/${hash}`, encodedNode)
    },
    async listAttestations(drvHash: string): Promise<readonly MirrorBuildAttestation[]> {
      const raw = await store.get(`${prefix}drv/${drvHash}`)
      if (raw === null) return []
      try {
        const parsed = JSON.parse(dec.decode(raw)) as unknown
        return Array.isArray(parsed) ? parsed.filter(verifyMirrorBuildAttestation) : []
      } catch {
        return []
      }
    },
    async putAttestation(drvHash: string, attestation: MirrorBuildAttestation): Promise<void> {
      const existing = await this.listAttestations!(drvHash)
      const dup = existing.some(a =>
        a.signer === attestation.signer &&
        a.payload.outputRef === attestation.payload.outputRef &&
        a.payload.runtime === attestation.payload.runtime,
      )
      if (dup) return
      const next = [...existing, attestation]
      await store.put(`${prefix}drv/${drvHash}`, utf8(JSON.stringify(next)))
    },
    async listAudits(pkgHash: string): Promise<readonly MirrorAuditAttestation[]> {
      const raw = await store.get(`${prefix}audit/${pkgHash}`)
      if (raw === null) return []
      try {
        const parsed = JSON.parse(dec.decode(raw)) as unknown
        return Array.isArray(parsed) ? parsed.filter(verifyMirrorAuditAttestation) : []
      } catch {
        return []
      }
    },
    async putAudit(pkgHash: string, audit: MirrorAuditAttestation): Promise<void> {
      const existing = await this.listAudits!(pkgHash)
      const dup = existing.some(a =>
        a.signer === audit.signer &&
        a.payload.verdict === audit.payload.verdict &&
        (a.payload.notes ?? '') === (audit.payload.notes ?? ''),
      )
      if (dup) return
      const next = [...existing, audit]
      await store.put(`${prefix}audit/${pkgHash}`, utf8(JSON.stringify(next)))
    },
  }
}

/** Expose an existing `ContentAddressedStore` directly as a `CasMirrorStore`. */
export function createCasAdapterMirrorStore(
  cas: ContentAddressedStore,
  options: { readonly partition?: CasPartition; readonly attestationStore?: BytesStore; readonly prefix?: string } = {},
): CasMirrorStore {
  const partition: CasPartition = options.partition ?? 'public'
  const attStore = options.attestationStore !== undefined
    ? createBytesStoreCasMirrorStore(options.attestationStore, options.prefix ?? 'mirror/')
    : undefined
  return {
    getNode: hash => cas.getRaw(hash, partition),
    hasNode: async hash => cas.hasSync(hash, partition) || (await cas.getRaw(hash, partition)) !== null,
    putNode: async (hash, encodedNode) => {
      await cas.putRaw(hash, encodedNode, partition)
    },
    ...(attStore === undefined ? {} : {
      listAttestations: drvHash => attStore.listAttestations!(drvHash),
      putAttestation: (drvHash, att) => attStore.putAttestation!(drvHash, att),
      listAudits: pkgHash => attStore.listAudits!(pkgHash),
      putAudit: (pkgHash, audit) => attStore.putAudit!(pkgHash, audit),
    }),
  }
}

function parseHashSegment(segment: string): string | null {
  const stripped = segment.startsWith('sha256-') ? segment.slice('sha256-'.length) : segment
  return HEX32.test(stripped) ? stripped : null
}

function etagMatches(condition: string | null, etag: string): boolean {
  if (condition === null) return false
  const cleanTarget = etag.replace(/^W\//u, '')
  return condition.split(',').some(part => {
    const t = part.trim()
    return t === '*' || t.replace(/^W\//u, '') === cleanTarget
  })
}

function guessMediaType(path: string): string {
  const ext = path.slice(path.lastIndexOf('.') + 1).toLowerCase()
  switch (ext) {
    case 'html': case 'htm': return 'text/html; charset=utf-8'
    case 'js': case 'mjs': return 'text/javascript; charset=utf-8'
    case 'css': return 'text/css; charset=utf-8'
    case 'json': return 'application/json; charset=utf-8'
    case 'svg': return 'image/svg+xml'
    case 'png': return 'image/png'
    case 'jpg': case 'jpeg': return 'image/jpeg'
    case 'webp': return 'image/webp'
    case 'wasm': return 'application/wasm'
    case 'txt': case 'md': return 'text/plain; charset=utf-8'
    default: return 'application/octet-stream'
  }
}

async function readBlobBytesFromMirrorStore(
  store: CasMirrorStore,
  hash: string,
  maxBytes: number,
  depth = 0,
): Promise<Uint8Array | null> {
  if (depth > 8) throw new Error('CAS_BLOB_DEPTH_EXCEEDED')
  const raw = await store.getNode(hash)
  if (raw === null) return null
  const verified = normalizeVerifiedCasNode(hash, raw, maxBytes)
  if (verified === null) throw new Error(`CAS_CORRUPT:${hash}`)
  const node = decodeCasNode(verified)
  if (node.links.length === 0) {
    if (node.bytes.byteLength > maxBytes) throw new Error('CAS_BLOB_TOO_LARGE')
    return node.bytes
  }
  // Try decoding as chronolog-blob/v1 interior tree node
  try {
    const decoded = assertCanonicalCbor(node.bytes, DEFAULT_DECODE_LIMITS)
    if (decoded instanceof Map && decoded.get('format') === 'chronolog-blob/v1') {
      const map = decoded as ReadonlyMap<CborMapKey, CborValue>
      const totalBytes = map.get('bytes')
      const children = map.get('children')
      if (typeof totalBytes === 'bigint' && Number(totalBytes) <= maxBytes && Array.isArray(children)) {
        const out = new Uint8Array(Number(totalBytes))
        let offset = 0
        for (const child of children) {
          if (!Array.isArray(child) || child.length !== 2 || typeof child[0] !== 'string') {
            throw new Error('CAS_BLOB_INVALID')
          }
          const part = await readBlobBytesFromMirrorStore(store, child[0], maxBytes - offset, depth + 1)
          if (part === null) return null
          out.set(part, offset)
          offset += part.byteLength
        }
        return out
      }
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('CAS_BLOB_')) throw err
  }
  return node.bytes
}

function applyRangeResponse(request: Request, bytes: Uint8Array, headers: Headers): Response {
  const size = bytes.byteLength
  headers.set('Accept-Ranges', 'bytes')
  const rangeHeader = request.headers.get('Range')
  const match = rangeHeader === null ? null : /^bytes=(\d*)-(\d*)$/u.exec(rangeHeader)
  if (match !== null && (match[1] !== '' || match[2] !== '')) {
    const start = match[1] !== '' ? Number(match[1]) : Math.max(0, size - Number(match[2]))
    const end = match[1] !== '' && match[2] !== '' ? Math.min(size - 1, Number(match[2])) : size - 1
    if (Number.isSafeInteger(start) && Number.isSafeInteger(end)) {
      if (start >= size || end < start) {
        headers.set('Content-Range', `bytes */${size}`)
        headers.set('Content-Length', '0')
        return new Response(null, { status: 416, headers })
      }
      const slice = bytes.subarray(start, end + 1)
      headers.set('Content-Range', `bytes ${start}-${end}/${size}`)
      headers.set('Content-Length', String(slice.byteLength))
      return new Response(slice.slice(), { status: 206, headers })
    }
  }
  headers.set('Content-Length', String(size))
  return new Response(bytes.slice(), { status: 200, headers })
}

export interface CasMirrorHandlerOptions {
  readonly store: CasMirrorStore
  /** Optional path prefix stripped before matching `/cas/...`, `/derivations/...`, `/audits/...`, `/trees/...`. */
  readonly basePath?: string
  /** Whether PUT/POST writes are enabled (default false unless authorizeWrite is supplied). */
  readonly allowWrites?: boolean
  /** Optional write authorization hook for PUT /cas/:hash, POST /cas/batch, PUT /derivations/:drvHash, PUT /audits/:pkgHash. */
  readonly authorizeWrite?: (request: Request, kind: 'cas' | 'derivation' | 'audit') => boolean | Promise<boolean>
  /** Optional custom media-type resolver for `/trees/:treeHash/*path`. */
  readonly resolveMediaType?: (path: string) => string
  readonly maxNodeBytes?: number
  readonly maxSubgraphNodes?: number
  readonly maxSubgraphBytes?: number
  readonly maxTreeFileBytes?: number
  /** Extra CORS headers (e.g. `{ 'Access-Control-Allow-Origin': '*' }`). */
  readonly headers?: Readonly<Record<string, string>>
}

function jsonResponse(body: unknown, status = 200, extra?: Readonly<Record<string, string>>): Response {
  const headers = new Headers(extra)
  headers.set('Content-Type', 'application/json; charset=utf-8')
  headers.set('X-Content-Type-Options', 'nosniff')
  return new Response(JSON.stringify(body), { status, headers })
}

/**
 * Create a reusable, WinterCG-native (Cloudflare Workers, Deno, Bun, Node 22+) HTTP handler
 * serving content-addressed CAS nodes, BFS subgraphs (`?subgraph=1`), Ed25519-verified
 * derivation/audit attestations, and `chronolog-tree/v1` static files with metadata-first 304 & Range/206.
 */
export function createCasMirrorHandler(options: CasMirrorHandlerOptions): (request: Request) => Promise<Response> {
  const basePath = (options.basePath ?? '').replace(/\/+$/u, '')
  const maxNodeBytes = options.maxNodeBytes ?? 4 * 1024 * 1024
  const maxSubgraphNodes = options.maxSubgraphNodes ?? 256
  const maxSubgraphBytes = options.maxSubgraphBytes ?? 8 * 1024 * 1024
  const maxTreeFileBytes = options.maxTreeFileBytes ?? 16 * 1024 * 1024

  const canWrite = async (request: Request, kind: 'cas' | 'derivation' | 'audit'): Promise<boolean> => {
    if (options.authorizeWrite !== undefined) return Boolean(await options.authorizeWrite(request, kind))
    return options.allowWrites === true
  }

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url)
    let path = url.pathname
    if (basePath.length > 0) {
      if (!path.startsWith(`${basePath}/`) && path !== basePath) {
        return jsonResponse({ error: 'not_found' }, 404, options.headers)
      }
      path = path.slice(basePath.length)
    }

    // 1. POST /cas/batch
    if (path === '/cas/batch' && request.method === 'POST') {
      if (!(await canWrite(request, 'cas')) || options.store.putNode === undefined) {
        return jsonResponse({ error: 'forbidden' }, 403, options.headers)
      }
      const raw = new Uint8Array(await request.arrayBuffer())
      if (raw.byteLength > maxSubgraphBytes + 65_536) {
        return jsonResponse({ error: 'payload_too_large' }, 413, options.headers)
      }
      let bundle: { readonly root: string; readonly nodes: readonly MirrorCasNode[] }
      try {
        bundle = decodeCasSubgraphBundle(raw)
      } catch {
        return jsonResponse({ error: 'invalid_subgraph_bundle' }, 400, options.headers)
      }
      if (bundle.nodes.length > maxSubgraphNodes) {
        return jsonResponse({ error: 'too_many_nodes' }, 413, options.headers)
      }
      let stored = 0
      for (const item of bundle.nodes) {
        const verified = normalizeVerifiedCasNode(item.hash, item.bytes, maxNodeBytes)
        if (verified === null) return jsonResponse({ error: 'hash_mismatch', hash: item.hash }, 400, options.headers)
        await options.store.putNode(item.hash, verified)
        stored += 1
      }
      return jsonResponse({ ok: true, root: bundle.root, stored }, 201, options.headers)
    }

    // 2. GET / HEAD / PUT /cas/:hash
    if (path.startsWith('/cas/')) {
      const seg = path.slice('/cas/'.length)
      const hash = parseHashSegment(seg)
      if (hash === null) return jsonResponse({ error: 'invalid_cas_hash' }, 400, options.headers)

      if (request.method === 'PUT') {
        if (!(await canWrite(request, 'cas')) || options.store.putNode === undefined) {
          return jsonResponse({ error: 'forbidden' }, 403, options.headers)
        }
        const body = new Uint8Array(await request.arrayBuffer())
        const verified = normalizeVerifiedCasNode(hash, body, maxNodeBytes)
        if (verified === null) return jsonResponse({ error: 'hash_mismatch' }, 400, options.headers)
        const existed = options.store.hasNode !== undefined ? await options.store.hasNode(hash) : false
        if (!existed) await options.store.putNode(hash, verified)
        return jsonResponse({ ok: true, hash, ref: casRef(hash) }, existed ? 200 : 201, options.headers)
      }

      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return jsonResponse({ error: 'method_not_allowed' }, 405, options.headers)
      }

      const wantsSubgraph = url.searchParams.get('subgraph') === '1' || url.searchParams.get('subgraph') === 'true'
      const etag = `"${hash}"`
      if (!wantsSubgraph && etagMatches(request.headers.get('If-None-Match'), etag)) {
        const exists = options.store.hasNode !== undefined
          ? await options.store.hasNode(hash)
          : (await options.store.getNode(hash)) !== null
        if (!exists) return jsonResponse({ error: 'not_found' }, 404, options.headers)
        const headers = new Headers(options.headers)
        headers.set('ETag', etag)
        headers.set('Cache-Control', 'public, max-age=31536000, immutable')
        headers.set('X-Content-Type-Options', 'nosniff')
        return new Response(null, { status: 304, headers })
      }

      if (wantsSubgraph) {
        const limitNodes = Math.min(maxSubgraphNodes, Math.max(1, Number(url.searchParams.get('maxNodes') ?? maxSubgraphNodes) || maxSubgraphNodes))
        const limitBytes = Math.min(maxSubgraphBytes, Math.max(1024, Number(url.searchParams.get('maxBytes') ?? maxSubgraphBytes) || maxSubgraphBytes))
        const visited = new Set<string>([hash])
        const queue: string[] = [hash]
        const collected: MirrorCasNode[] = []
        let totalBytes = 0
        while (queue.length > 0 && collected.length < limitNodes) {
          const cur = queue.shift()!
          const raw = await options.store.getNode(cur)
          if (raw === null) {
            if (cur === hash) return jsonResponse({ error: 'not_found' }, 404, options.headers)
            continue
          }
          const verified = normalizeVerifiedCasNode(cur, raw, maxNodeBytes)
          if (verified === null) return jsonResponse({ error: 'integrity_mismatch', hash: cur }, 503, options.headers)
          if (totalBytes + verified.byteLength > limitBytes && collected.length > 0) break
          collected.push({ hash: cur, bytes: verified })
          totalBytes += verified.byteLength
          const decoded = decodeCasNode(verified)
          for (const link of decoded.links) {
            if (!visited.has(link)) { visited.add(link); queue.push(link) }
          }
        }
        const encoded = encodeCasSubgraphBundle(hash, collected)
        const headers = new Headers(options.headers)
        headers.set('Content-Type', CAS_SUBGRAPH_MEDIA_TYPE)
        headers.set('Cache-Control', 'public, max-age=31536000, immutable')
        headers.set('ETag', `"subgraph:${hash}:${collected.length}"`)
        headers.set('X-Content-Type-Options', 'nosniff')
        headers.set('Content-Length', String(encoded.byteLength))
        if (request.method === 'HEAD') return new Response(null, { status: 200, headers })
        return new Response(encoded.slice(), { status: 200, headers })
      }

      const raw = await options.store.getNode(hash)
      if (raw === null) return jsonResponse({ error: 'not_found' }, 404, options.headers)
      const verified = normalizeVerifiedCasNode(hash, raw, maxNodeBytes)
      if (verified === null) return jsonResponse({ error: 'integrity_mismatch' }, 503, options.headers)
      const headers = new Headers(options.headers)
      headers.set('Content-Type', CAS_NODE_MEDIA_TYPE)
      headers.set('ETag', etag)
      headers.set('Cache-Control', 'public, max-age=31536000, immutable')
      headers.set('X-Content-Type-Options', 'nosniff')
      if (request.method === 'HEAD') {
        headers.set('Content-Length', String(verified.byteLength))
        return new Response(null, { status: 200, headers })
      }
      return applyRangeResponse(request, verified, headers)
    }

    // 3. GET / PUT /derivations/:drvHash
    if (path.startsWith('/derivations/')) {
      const seg = path.slice('/derivations/'.length)
      const drvHash = parseHashSegment(seg)
      if (drvHash === null) return jsonResponse({ error: 'invalid_derivation_hash' }, 400, options.headers)
      const drvRef = casRef(drvHash)

      if (request.method === 'PUT') {
        if (!(await canWrite(request, 'derivation')) || options.store.putAttestation === undefined) {
          return jsonResponse({ error: 'forbidden' }, 403, options.headers)
        }
        let body: unknown
        try { body = await request.json() } catch { return jsonResponse({ error: 'invalid_json' }, 400, options.headers) }
        if (!verifyMirrorBuildAttestation(body) || body.payload.drvRef !== drvRef) {
          return jsonResponse({ error: 'invalid_attestation' }, 400, options.headers)
        }
        await options.store.putAttestation(drvHash, body)
        return jsonResponse({ ok: true, drvRef, outputRef: body.payload.outputRef, signer: body.signer }, 201, options.headers)
      }

      if (request.method !== 'GET') return jsonResponse({ error: 'method_not_allowed' }, 405, options.headers)
      const all = options.store.listAttestations !== undefined
        ? (await options.store.listAttestations(drvHash)).filter(a => verifyMirrorBuildAttestation(a) && a.payload.drvRef === drvRef)
        : []
      const buildersParam = url.searchParams.get('builders')
      const builders = buildersParam !== null && buildersParam.length > 0
        ? buildersParam.split(',').map(s => s.trim()).filter(s => HEX32.test(s))
        : null
      const filtered = builders !== null ? all.filter(a => builders.includes(a.signer)) : all
      const threshold = Number(url.searchParams.get('threshold') ?? '1') || 1
      const trusted = builders !== null ? resolveTrustedBuildOutput(drvRef, filtered, builders, threshold) : null
      return jsonResponse({
        format: 'chronolog-derivation-cache/v1',
        drvRef,
        attestations: filtered,
        ...(trusted === null ? {} : { trustedOutputRef: trusted.outputRef, trustedSigners: trusted.signers }),
      }, 200, options.headers)
    }

    // 4. GET / PUT /audits/:pkgHash
    if (path.startsWith('/audits/')) {
      const seg = path.slice('/audits/'.length)
      const pkgHash = parseHashSegment(seg)
      if (pkgHash === null) return jsonResponse({ error: 'invalid_package_hash' }, 400, options.headers)
      const pkgRef = casRef(pkgHash)

      if (request.method === 'PUT') {
        if (!(await canWrite(request, 'audit')) || options.store.putAudit === undefined) {
          return jsonResponse({ error: 'forbidden' }, 403, options.headers)
        }
        let body: unknown
        try { body = await request.json() } catch { return jsonResponse({ error: 'invalid_json' }, 400, options.headers) }
        if (!verifyMirrorAuditAttestation(body) || body.payload.pkgRef !== pkgRef) {
          return jsonResponse({ error: 'invalid_audit' }, 400, options.headers)
        }
        await options.store.putAudit(pkgHash, body)
        return jsonResponse({ ok: true, pkgRef, verdict: body.payload.verdict, signer: body.signer }, 201, options.headers)
      }

      if (request.method !== 'GET') return jsonResponse({ error: 'method_not_allowed' }, 405, options.headers)
      const audits = options.store.listAudits !== undefined
        ? (await options.store.listAudits(pkgHash)).filter(a => verifyMirrorAuditAttestation(a) && a.payload.pkgRef === pkgRef)
        : []
      return jsonResponse({ format: 'chronolog-audit-cache/v1', pkgRef, audits }, 200, options.headers)
    }

    // 5. GET / HEAD /trees/:treeHash/*filePath
    if (path.startsWith('/trees/')) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return jsonResponse({ error: 'method_not_allowed' }, 405, options.headers)
      }
      const rest = path.slice('/trees/'.length)
      const slash = rest.indexOf('/')
      const treeSeg = slash < 0 ? rest : rest.slice(0, slash)
      const rawFilePath = slash < 0 ? 'index.html' : (rest.slice(slash + 1) || 'index.html')
      const treeHash = parseHashSegment(treeSeg)
      if (treeHash === null) return jsonResponse({ error: 'invalid_tree_hash' }, 400, options.headers)

      let filePath: string
      try { filePath = normalizePosixPath(decodeURIComponent(rawFilePath)) } catch {
        return jsonResponse({ error: 'invalid_path' }, 400, options.headers)
      }

      const rawTree = await options.store.getNode(treeHash)
      if (rawTree === null) return jsonResponse({ error: 'not_found' }, 404, options.headers)
      const verifiedTree = normalizeVerifiedCasNode(treeHash, rawTree, maxNodeBytes)
      if (verifiedTree === null) return jsonResponse({ error: 'integrity_mismatch' }, 503, options.headers)
      let treeEntries: Readonly<Record<string, string>>
      try {
        treeEntries = decodeTreeNode(decodeCasNode(verifiedTree).bytes).entries
      } catch {
        return jsonResponse({ error: 'not_a_tree' }, 400, options.headers)
      }
      const targetRef = treeEntries[filePath]
      if (targetRef === undefined) return jsonResponse({ error: 'not_found' }, 404, options.headers)
      const targetHash = parseCasRef(targetRef)
      const etag = `"${targetHash}"`
      const mediaType = options.resolveMediaType !== undefined ? options.resolveMediaType(filePath) : guessMediaType(filePath)

      if (etagMatches(request.headers.get('If-None-Match'), etag)) {
        const headers = new Headers(options.headers)
        headers.set('ETag', etag)
        headers.set('Content-Type', mediaType)
        headers.set('Cache-Control', 'public, max-age=31536000, immutable')
        headers.set('X-Content-Type-Options', 'nosniff')
        return new Response(null, { status: 304, headers })
      }

      const fileBytes = await readBlobBytesFromMirrorStore(options.store, targetHash, maxTreeFileBytes)
      if (fileBytes === null) return jsonResponse({ error: 'not_found' }, 404, options.headers)

      const headers = new Headers(options.headers)
      headers.set('Content-Type', mediaType)
      headers.set('ETag', etag)
      headers.set('Cache-Control', 'public, max-age=31536000, immutable')
      headers.set('X-Content-Type-Options', 'nosniff')
      if (request.method === 'HEAD') {
        headers.set('Content-Length', String(fileBytes.byteLength))
        return new Response(null, { status: 200, headers })
      }
      return applyRangeResponse(request, fileBytes, headers)
    }

    return jsonResponse({ error: 'not_found' }, 404, options.headers)
  }
}

export interface CasMirrorClientOptions {
  readonly fetch?: typeof fetch
  readonly headers?: Readonly<Record<string, string>>
}

export interface CasMirrorClient {
  readonly baseUrl: string
  fetchNode(hash: string): Promise<MirrorCasNode | null>
  fetchSubgraph(hash: string, options?: { readonly maxNodes?: number; readonly maxBytes?: number }): Promise<readonly MirrorCasNode[]>
  pushNode(hash: string, bytes: Uint8Array): Promise<boolean>
  pushSubgraph(rootHash: string, nodes: readonly MirrorCasNode[]): Promise<boolean>
  fetchDerivationAttestations(
    drvRefOrHash: string,
    options?: { readonly trustedBuilders?: readonly string[]; readonly threshold?: number },
  ): Promise<{
    readonly attestations: readonly MirrorBuildAttestation[]
    readonly trusted: { readonly outputRef: string; readonly outputHash: string; readonly signers: readonly string[] } | null
  }>
  publishDerivationAttestation(attestation: MirrorBuildAttestation): Promise<boolean>
  fetchAuditAttestations(pkgRefOrHash: string): Promise<readonly MirrorAuditAttestation[]>
  publishAuditAttestation(audit: MirrorAuditAttestation): Promise<boolean>
}

/**
 * Zero-trust HTTP client for any Chronolog CAS & derivation mirror.
 * Every CAS node hash and every Ed25519 attestation signature is re-verified locally.
 */
export function createCasMirrorClient(baseUrl: string, options: CasMirrorClientOptions = {}): CasMirrorClient {
  const base = baseUrl.replace(/\/+$/u, '')
  const doFetch = options.fetch ?? fetch
  const baseHeaders = options.headers ?? {}

  const fetchNode = async (hash: string): Promise<MirrorCasNode | null> => {
    const clean = tryParseCasRef(hash) ?? hash
    if (!HEX32.test(clean)) return null
    const resp = await doFetch(`${base}/cas/sha256-${clean}`, { headers: baseHeaders })
    if (!resp.ok) return null
    const raw = new Uint8Array(await resp.arrayBuffer())
    const verified = normalizeVerifiedCasNode(clean, raw)
    return verified === null ? null : { hash: clean, bytes: verified }
  }

  const fetchSubgraph = async (
    hash: string,
    opts: { readonly maxNodes?: number; readonly maxBytes?: number } = {},
  ): Promise<readonly MirrorCasNode[]> => {
    const clean = tryParseCasRef(hash) ?? hash
    if (!HEX32.test(clean)) return []
    const params = new URLSearchParams({ subgraph: '1' })
    if (opts.maxNodes !== undefined) params.set('maxNodes', String(opts.maxNodes))
    if (opts.maxBytes !== undefined) params.set('maxBytes', String(opts.maxBytes))
    try {
      const resp = await doFetch(`${base}/cas/sha256-${clean}?${params.toString()}`, { headers: baseHeaders })
      if (resp.ok) {
        const contentType = resp.headers.get('Content-Type') ?? ''
        const buf = new Uint8Array(await resp.arrayBuffer())
        if (contentType.includes('cas-subgraph')) {
          const decoded = decodeCasSubgraphBundle(buf)
          const verified: MirrorCasNode[] = []
          for (const item of decoded.nodes) {
            const norm = normalizeVerifiedCasNode(item.hash, item.bytes)
            if (norm !== null) verified.push({ hash: item.hash, bytes: norm })
          }
          if (verified.length > 0) return verified
        } else {
          // Plain static HTTP mirror that ignored ?subgraph=1 and returned the single node
          const norm = normalizeVerifiedCasNode(clean, buf)
          if (norm !== null) {
            const out: MirrorCasNode[] = [{ hash: clean, bytes: norm }]
            const seen = new Set<string>([clean])
            const queue = [...decodeCasNode(norm).links]
            const limit = opts.maxNodes ?? 128
            while (queue.length > 0 && out.length < limit) {
              const next = queue.shift()!
              if (seen.has(next)) continue
              seen.add(next)
              const child = await fetchNode(next)
              if (child === null) continue
              out.push(child)
              for (const link of decodeCasNode(child.bytes).links) {
                if (!seen.has(link)) queue.push(link)
              }
            }
            return out
          }
        }
      }
    } catch { /* fall through to single-node BFS */ }
    // Fallback for static mirrors / path-exact servers that reject ?subgraph=1 query strings
    const root = await fetchNode(clean)
    if (root === null) return []
    const out: MirrorCasNode[] = [root]
    const seen = new Set<string>([clean])
    const queue = [...decodeCasNode(root.bytes).links]
    const limit = opts.maxNodes ?? 128
    while (queue.length > 0 && out.length < limit) {
      const next = queue.shift()!
      if (seen.has(next)) continue
      seen.add(next)
      const child = await fetchNode(next)
      if (child === null) continue
      out.push(child)
      for (const link of decodeCasNode(child.bytes).links) {
        if (!seen.has(link)) queue.push(link)
      }
    }
    return out
  }

  return {
    baseUrl: base,
    fetchNode,
    fetchSubgraph,
    async pushNode(hash: string, bytes: Uint8Array): Promise<boolean> {
      const clean = tryParseCasRef(hash) ?? hash
      const resp = await doFetch(`${base}/cas/sha256-${clean}`, {
        method: 'PUT',
        headers: { ...baseHeaders, 'Content-Type': CAS_NODE_MEDIA_TYPE },
        body: bytes.slice(),
      })
      return resp.ok
    },
    async pushSubgraph(rootHash: string, nodes: readonly MirrorCasNode[]): Promise<boolean> {
      const clean = tryParseCasRef(rootHash) ?? rootHash
      const bundle = encodeCasSubgraphBundle(clean, nodes)
      const resp = await doFetch(`${base}/cas/batch`, {
        method: 'POST',
        headers: { ...baseHeaders, 'Content-Type': CAS_SUBGRAPH_MEDIA_TYPE },
        body: bundle.slice(),
      })
      return resp.ok
    },
    async fetchDerivationAttestations(drvRefOrHash, opts = {}) {
      const drvHash = tryParseCasRef(drvRefOrHash) ?? drvRefOrHash
      const drvRef = casRef(drvHash)
      const params = new URLSearchParams()
      if (opts.trustedBuilders !== undefined && opts.trustedBuilders.length > 0) {
        params.set('builders', opts.trustedBuilders.join(','))
      }
      if (opts.threshold !== undefined) params.set('threshold', String(opts.threshold))
      const qs = params.toString()
      const resp = await doFetch(`${base}/derivations/sha256-${drvHash}${qs ? `?${qs}` : ''}`, { headers: baseHeaders })
      if (!resp.ok) return { attestations: [], trusted: null }
      const data = await resp.json() as { readonly attestations?: unknown[] }
      const verified = Array.isArray(data.attestations)
        ? data.attestations.filter(verifyMirrorBuildAttestation).filter(a => a.payload.drvRef === drvRef)
        : []
      const trusted = opts.trustedBuilders !== undefined && opts.trustedBuilders.length > 0
        ? resolveTrustedBuildOutput(drvRef, verified, opts.trustedBuilders, opts.threshold ?? 1)
        : null
      return { attestations: verified, trusted }
    },
    async publishDerivationAttestation(attestation): Promise<boolean> {
      const drvHash = parseCasRef(attestation.payload.drvRef)
      const resp = await doFetch(`${base}/derivations/sha256-${drvHash}`, {
        method: 'PUT',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify(attestation),
      })
      return resp.ok
    },
    async fetchAuditAttestations(pkgRefOrHash): Promise<readonly MirrorAuditAttestation[]> {
      const pkgHash = tryParseCasRef(pkgRefOrHash) ?? pkgRefOrHash
      const pkgRef = casRef(pkgHash)
      const resp = await doFetch(`${base}/audits/sha256-${pkgHash}`, { headers: baseHeaders })
      if (!resp.ok) return []
      const data = await resp.json() as { readonly audits?: unknown[] }
      return Array.isArray(data.audits)
        ? data.audits.filter(verifyMirrorAuditAttestation).filter(a => a.payload.pkgRef === pkgRef)
        : []
    },
    async publishAuditAttestation(audit): Promise<boolean> {
      const pkgHash = parseCasRef(audit.payload.pkgRef)
      const resp = await doFetch(`${base}/audits/sha256-${pkgHash}`, {
        method: 'PUT',
        headers: { ...baseHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify(audit),
      })
      return resp.ok
    },
  }
}

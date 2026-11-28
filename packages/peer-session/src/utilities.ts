import {
  computeCasHash,
  decodeCasNode,
  encodeCasNode,
  hashCasNode,
  tryParseCasRef,
  type CasPartition,
} from '@chronolog/records'
import { isControlTopic, type JsonValue, type TopicBinding } from '@chronolog/protocol'

const HEX32 = /^[0-9a-f]{64}$/u

/**
 * Recursively scan any JSON value (topic state, event payloads, etc.) for content-addressed
 * references (`cas:sha256-...`, `chronolog-blob-v2` refs, and `authored-content-v1` ids).
 */
export function collectCasRefsFromValue(
  value: unknown,
  options: { readonly maxDepth?: number; readonly maxRefs?: number } = {},
): { readonly casHashes: readonly string[]; readonly contentIds: readonly string[] } {
  const maxDepth = options.maxDepth ?? 8
  const maxRefs = options.maxRefs ?? 256
  const casHashes = new Set<string>()
  const contentIds = new Set<string>()

  const walk = (v: unknown, depth: number): void => {
    if (depth > maxDepth || casHashes.size + contentIds.size >= maxRefs || v === null || v === undefined) return
    if (typeof v === 'string') {
      const h = tryParseCasRef(v)
      if (h !== null) casHashes.add(h)
      return
    }
    if (Array.isArray(v)) {
      for (const item of v) walk(item, depth + 1)
      return
    }
    if (typeof v === 'object') {
      const rec = v as Record<string, unknown>
      if (rec.profile === 'chronolog-blob-v2' && typeof rec.hash === 'string' && HEX32.test(rec.hash)) {
        casHashes.add(rec.hash)
      }
      if (rec.profile === 'authored-content-v1' && typeof rec.id === 'string' && rec.id.length > 0) {
        contentIds.add(rec.id)
      }
      for (const child of Object.values(rec)) walk(child, depth + 1)
    }
  }
  walk(value, 0)
  return { casHashes: [...casHashes].sort(), contentIds: [...contentIds].sort() }
}

export interface BlueprintSqlSchema {
  readonly statements: readonly string[]
  readonly policies: Readonly<Record<string, JsonValue>>
}

export interface LogBlueprintV1 {
  readonly format: 'chronolog-blueprint/v1'
  readonly privateLog: boolean
  /** Non-control topic bindings (`topicName -> TopicBinding`). */
  readonly topics: Readonly<Record<string, TopicBinding>>
  /** Non-standard specifier -> `cas:sha256-...` import map entries. */
  readonly imports: Readonly<Record<string, string>>
  /** Base64-encoded canonical CAS nodes (including transitive `chronolog-pkg/v1` subgraphs!). */
  readonly casNodes: Readonly<Record<string, string>>
  /** Extracted `chronolog/sql` schema DDL + RLS policies (strictly zero application rows). */
  readonly sqlSchemas: Readonly<Record<string, BlueprintSqlSchema>>
  /** Optional current `$publications` metadata (zero secret data). */
  readonly publication?: JsonValue
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]!)
  return btoa(binary)
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export interface BlueprintSessionLike {
  readonly genesis: { readonly privateLog: boolean }
  topic(name: string): JsonValue | undefined
  query(topic: string, input: JsonValue): Promise<{ readonly value?: unknown }>
  exportCasNodes(
    hashes: readonly string[],
    includePrivate: boolean,
    options?: { readonly subgraph?: boolean; readonly maxNodes?: number; readonly maxBytes?: number },
  ): Promise<readonly { readonly hash: string; readonly bytes: Uint8Array; readonly partition: CasPartition }[]>
}

/**
 * Export a portable, secret-free `chronolog-blueprint/v1` snapshot of a log's application
 * reducers, transitive `chronolog-pkg/v1` / ES module CAS DAG nodes, `chronolog/sql` DDL & RLS
 * policies (zero rows), and optional `$publications` metadata.
 */
export async function exportLogBlueprint(session: BlueprintSessionLike): Promise<LogBlueprintV1> {
  const reducers = session.topic('$reducers') as {
    readonly imports?: Readonly<Record<string, string>>
    readonly topics?: Readonly<Record<string, TopicBinding>>
  } | undefined

  const rawTopics = reducers?.topics ?? {}
  const rawImports = reducers?.imports ?? {}
  const topics: Record<string, TopicBinding> = {}
  const imports: Record<string, string> = {}
  const rootHashes: string[] = []

  for (const [topicName, binding] of Object.entries(rawTopics)) {
    if (isControlTopic(topicName)) continue
    topics[topicName] = binding
    if (binding.module.startsWith('cas:sha256-')) {
      const h = tryParseCasRef(binding.module)
      if (h !== null) rootHashes.push(h)
    } else if (!binding.module.startsWith('chronolog/') && typeof rawImports[binding.module] === 'string') {
      const ref = rawImports[binding.module]!
      imports[binding.module] = ref
      const h = tryParseCasRef(ref)
      if (h !== null) rootHashes.push(h)
    }
  }
  for (const [spec, ref] of Object.entries(rawImports)) {
    if (spec.startsWith('chronolog/')) continue
    if (imports[spec] === undefined && typeof ref === 'string') {
      imports[spec] = ref
      const h = tryParseCasRef(ref)
      if (h !== null) rootHashes.push(h)
    }
  }

  const casNodes: Record<string, string> = {}
  if (rootHashes.length > 0) {
    const exported = await session.exportCasNodes([...new Set(rootHashes)], false, {
      subgraph: true,
      maxNodes: 1024,
      maxBytes: 16 * 1024 * 1024,
    })
    for (const node of exported) {
      casNodes[node.hash] = bytesToBase64(node.bytes)
    }
  }

  const sqlSchemas: Record<string, BlueprintSqlSchema> = {}
  for (const [topicName, binding] of Object.entries(topics)) {
    if (binding.module !== 'chronolog/sql') continue
    try {
      const res = await session.query(topicName, { query: 'schema' })
      if (res.value === null || res.value === undefined || typeof res.value !== 'object' || Array.isArray(res.value)) continue
      const schemaVal = res.value as Record<string, unknown>
      const userOwned = new Set<string>(Array.isArray(schemaVal.userOwnedObjects) ? schemaVal.userOwnedObjects.filter((s): s is string => typeof s === 'string') : [])
      const statements: string[] = []
      const objects = Array.isArray(schemaVal.objects) ? schemaVal.objects : []
      for (const obj of objects) {
        if (obj === null || typeof obj !== 'object') continue
        const o = obj as Record<string, unknown>
        const name = typeof o.name === 'string' ? o.name : ''
        const sql = typeof o.sql === 'string' ? o.sql.trim() : ''
        if (!name || !sql || name.startsWith('sqlite_') || name.startsWith('_rls_') || userOwned.has(name)) continue
        statements.push(sql)
      }
      const policies = schemaVal.policies !== null && typeof schemaVal.policies === 'object' && !Array.isArray(schemaVal.policies)
        ? schemaVal.policies as Record<string, JsonValue>
        : {}
      sqlSchemas[topicName] = { statements, policies }
    } catch { /* ignore unreadable schema */ }
  }

  const pubTopic = session.topic('$publications') as { readonly current?: JsonValue } | undefined
  return {
    format: 'chronolog-blueprint/v1',
    privateLog: session.genesis.privateLog,
    topics,
    imports,
    casNodes,
    sqlSchemas,
    ...(pubTopic?.current !== undefined && pubTopic.current !== null ? { publication: pubTopic.current } : {}),
  }
}

/**
 * Validate a `chronolog-blueprint/v1` object: blocks `$*` control-topic injection and verifies
 * every included CAS node's cryptographic hash.
 */
export function validateLogBlueprint(blueprint: unknown): {
  readonly blueprint: LogBlueprintV1
  readonly casNodes: readonly { readonly hash: string; readonly bytes: Uint8Array; readonly partition: 'public' }[]
} {
  if (blueprint === null || typeof blueprint !== 'object' || Array.isArray(blueprint)) {
    throw new Error('BLUEPRINT_INVALID')
  }
  const b = blueprint as Record<string, unknown>
  if (b.format !== 'chronolog-blueprint/v1') throw new Error('BLUEPRINT_FORMAT_INVALID')
  if (b.topics === null || typeof b.topics !== 'object' || Array.isArray(b.topics)) {
    throw new Error('BLUEPRINT_TOPICS_INVALID')
  }
  for (const topicName of Object.keys(b.topics)) {
    if (isControlTopic(topicName)) throw new Error(`BLUEPRINT_FORBIDS_CONTROL_TOPIC:${topicName}`)
  }
  if (b.casNodes === null || typeof b.casNodes !== 'object' || Array.isArray(b.casNodes)) {
    throw new Error('BLUEPRINT_CAS_INVALID')
  }
  const verifiedNodes: { readonly hash: string; readonly bytes: Uint8Array; readonly partition: 'public' }[] = []
  for (const [hash, b64] of Object.entries(b.casNodes)) {
    if (!HEX32.test(hash) || typeof b64 !== 'string') throw new Error(`BLUEPRINT_CAS_ENTRY_INVALID:${hash}`)
    const raw = base64ToBytes(b64)
    if (hashCasNode(raw) === hash) {
      decodeCasNode(raw)
      verifiedNodes.push({ hash, bytes: raw, partition: 'public' })
    } else if (computeCasHash(raw, []) === hash) {
      verifiedNodes.push({ hash, bytes: encodeCasNode(raw, []), partition: 'public' })
    } else {
      throw new Error(`BLUEPRINT_CAS_HASH_MISMATCH:${hash}`)
    }
  }
  return { blueprint: b as unknown as LogBlueprintV1, casNodes: verifiedNodes }
}

export interface CasPinnerSessionLike {
  topic(name: string): JsonValue | undefined
  readonly content: {
    get(refOrHash: string, options?: { readonly cache?: boolean }): Promise<Uint8Array | null>
    pin?(refOrHash: string): Promise<void>
    pruneCache?(options: { readonly maxBytes: number }): Promise<unknown>
  }
  onChange(listener: () => void): () => void
  onPeerLink?(listener: () => void): () => void
}

/**
 * Attach a bounded proactive CAS/content reference pinner to a running session.
 * Scans specified (or all non-control) topics on changes/peer links, fetches up to
 * `maxRefsPerScan` referenced blobs into local cache, pins them, and enforces `maxBytes`.
 */
export function attachCasPinner(
  session: CasPinnerSessionLike,
  options: {
    readonly topics?: readonly string[]
    readonly maxBytes?: number
    readonly maxRefsPerScan?: number
    readonly maxDepth?: number
  } = {},
): () => void {
  const maxBytes = options.maxBytes ?? 128 * 1024 * 1024
  const maxRefsPerScan = options.maxRefsPerScan ?? 32
  const maxDepth = options.maxDepth ?? 8
  const attempted = new Set<string>()
  let running = false
  let rerun = false

  const scan = async (): Promise<void> => {
    if (running) { rerun = true; return }
    running = true
    try {
      const reducers = session.topic('$reducers') as { readonly topics?: Readonly<Record<string, unknown>> } | undefined
      const topicNames = options.topics ?? Object.keys(reducers?.topics ?? {}).filter(t => !isControlTopic(t))
      const refs: string[] = []
      for (const name of topicNames) {
        const state = session.topic(name)
        if (state === undefined) continue
        const found = collectCasRefsFromValue(state, { maxDepth, maxRefs: maxRefsPerScan })
        for (const h of found.casHashes) refs.push(h)
        for (const id of found.contentIds) refs.push(id)
      }
      let fetched = 0
      for (const ref of refs) {
        if (fetched >= maxRefsPerScan) break
        if (attempted.has(ref)) continue
        attempted.add(ref)
        fetched += 1
        try {
          const data = await session.content.get(ref, { cache: true })
          if (data !== null && session.content.pin !== undefined) {
            await session.content.pin(ref)
          }
        } catch { /* retry on next peer link */ attempted.delete(ref) }
      }
      if (fetched > 0 && session.content.pruneCache !== undefined) {
        await session.content.pruneCache({ maxBytes }).catch(() => {})
      }
    } finally {
      running = false
      if (rerun) { rerun = false; void scan() }
    }
  }

  const offChange = session.onChange(() => { void scan() })
  const offPeer = session.onPeerLink?.(() => { attempted.clear(); void scan() })
  void scan()
  return () => {
    offChange()
    offPeer?.()
  }
}

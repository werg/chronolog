import {
  bytesToHex,
  utf8,
} from '@chronolog/canonical'
import {
  evaluateAdmission,
  type AdmissionDecision,
  type AdmissionEvidence,
  type PinnedFrontier,
} from '@chronolog/authority'
import {
  seedStandardModules,
  TopicKernel,
  type KernelOperationInput,
  type KernelOperationOutcome,
  type QuickJsSandboxOptions,
} from '@chronolog/materializer'
import {
  decodeCasNode,
  encodeCasNode,
  hashCasNode,
  MemoryBytesStore,
  ContentAddressedStore,
  putPackageDag,
  tryParseCasRef,
  type CasPartition,
  type PutPackageInput,
} from '@chronolog/records'
import {
  DEFAULT_GENESIS_LIMITS,
  DEFAULT_RUNTIME_MANIFEST,
  encodeLogGenesis,
  isControlTopic,
  type JsonValue,
  type LogGenesis,
  type OperationCore,
} from '@chronolog/protocol'

const HEX32 = /^[0-9a-f]{64}$/u

export interface BlindHostCasNode {
  readonly hash: string
  readonly bytes: Uint8Array
}

function collectCasStringsFromJson(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 24 || value === null || value === undefined) return
  if (typeof value === 'string') {
    const hash = tryParseCasRef(value)
    if (hash !== null) out.add(hash)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) collectCasStringsFromJson(item, out, depth + 1)
    return
  }
  if (typeof value === 'object') {
    const rec = value as Record<string, unknown>
    // Also retain explicit casRoots arrays (e.g. $mounts.<name>.casRoots)
    if (Array.isArray(rec.casRoots)) {
      for (const h of rec.casRoots) {
        if (typeof h === 'string' && HEX32.test(h)) out.add(h)
      }
    }
    for (const v of Object.values(rec)) collectCasStringsFromJson(v, out, depth + 1)
  }
}

/**
 * Compute the exact set of public CAS node hashes reachable from a log's genesis,
 * materialized `$*` control topics (`$reducers`, `$mounts`, `$builders`, `$publications`),
 * public operation payloads, and transitive `CasNode.links` (including `chronolog-pkg/v1`,
 * `chronolog-tree/v1`, `chronolog-drv/v1`, and mounted subgraphs).
 */
export async function collectControlReferencedCasHashes(options: {
  readonly genesis?: LogGenesis
  readonly topics?: Readonly<Record<string, JsonValue>>
  readonly publicOps?: readonly OperationCore[]
  readonly cas?: ContentAddressedStore
  readonly casNodes?: ReadonlyMap<string, Uint8Array>
}): Promise<Set<string>> {
  const roots = new Set<string>()
  if (options.genesis !== undefined) {
    for (const [topic, val] of Object.entries(options.genesis.initialTopics)) {
      if (isControlTopic(topic)) collectCasStringsFromJson(val, roots)
    }
  }
  if (options.topics !== undefined) {
    for (const [topic, val] of Object.entries(options.topics)) {
      if (isControlTopic(topic)) collectCasStringsFromJson(val, roots)
    }
  }
  if (options.publicOps !== undefined) {
    for (const op of options.publicOps) {
      for (const u of op.updates) {
        if (isControlTopic(u.topic)) collectCasStringsFromJson(u.input, roots)
      }
    }
  }

  // BFS over explicit CasNode.links
  const visited = new Set<string>(roots)
  const queue = [...roots]
  while (queue.length > 0) {
    const hash = queue.shift()!
    let links: readonly string[] = []
    if (options.cas !== undefined) {
      const node = await options.cas.get(hash, 'public')
      if (node !== null) links = node.links
    } else if (options.casNodes !== undefined) {
      const raw = options.casNodes.get(hash)
      if (raw !== undefined) {
        try {
          if (hashCasNode(raw) === hash) {
            links = decodeCasNode(raw).links
          }
        } catch { /* leaf or invalid */ }
      }
    }
    for (const link of links) {
      if (HEX32.test(link) && !visited.has(link)) {
        visited.add(link)
        queue.push(link)
      }
    }
  }
  return visited
}

export interface ControlAdmissionSummary {
  readonly mode: 'attested' | 'multisig' | 'open' | 'custom'
  readonly openRead: boolean
  readonly openWrite: boolean
  readonly members: readonly Record<string, JsonValue>[]
  readonly readers: readonly string[]
  readonly writers: readonly string[]
  readonly administrators: readonly string[]
  readonly publishers: readonly string[]
  readonly finalizers: readonly string[]
  readonly blockedAuthors: readonly string[]
  readonly removedMembers: readonly string[]
  readonly admission: JsonValue | null
}

function stringList(v: unknown): string[] {
  if (!Array.isArray(v)) return []
  return [...new Set(v.filter((x): x is string => typeof x === 'string' && HEX32.test(x)))].sort()
}

/**
 * Extract normalized admission roster from a blind-host `TopicKernel` via the
 * universal `$admission` `{ kind: 'roster' }` query contract.
 */
export async function extractControlAdmission(kernel: TopicKernel): Promise<ControlAdmissionSummary> {
  let summary: Record<string, unknown> = {}
  try {
    const q = await kernel.query('$admission', { kind: 'roster' })
    if (q !== null && typeof q === 'object' && !Array.isArray(q)) {
      summary = q as Record<string, unknown>
    }
  } catch { /* custom $admission without roster query */ }

  const rawMembers = Array.isArray(summary.members)
    ? summary.members.filter((m): m is Record<string, JsonValue> => m !== null && typeof m === 'object' && !Array.isArray(m))
    : []
  const hasWildcard = (v: unknown): boolean => Array.isArray(v) && v.includes('*')
  const readers = stringList(summary.readers)
  const writers = stringList(summary.writers)
  const administrators = stringList(summary.administrators)
  const publishers = stringList(summary.publishers)
  const finalizers = stringList(summary.finalizers)
  const blockedAuthors = stringList(summary.blockedAuthors)
  const removedMembers = stringList(summary.removedMembers)
  const admission = (summary.admission as JsonValue | undefined) ?? null
  const openRead = summary.openReaders === true || summary.openRead === true || hasWildcard(summary.readers)
  const openWrite = summary.openWriters === true || summary.openWrite === true || hasWildcard(summary.writers)
  const mode: ControlAdmissionSummary['mode'] =
    summary.mode === 'open' || summary.mode === 'multisig' || summary.mode === 'attested'
      ? summary.mode
      : 'custom'

  return {
    mode,
    openRead,
    openWrite,
    members: rawMembers,
    readers,
    writers,
    administrators,
    publishers,
    finalizers,
    blockedAuthors,
    removedMembers,
    admission,
  }
}

export interface ReplayBlindHostOptions {
  readonly genesis: LogGenesis
  readonly publicOps: readonly KernelOperationInput[]
  readonly publicCasNodes: readonly BlindHostCasNode[]
  readonly evidence?: readonly AdmissionEvidence[]
  readonly pinnedFrontier?: PinnedFrontier | null
  readonly wasmModule?: QuickJsSandboxOptions['wasmModule']
  /** When true (default), replays finalized control topics if admission evidence closes a frontier. */
  readonly includeFinalized?: boolean
}

export interface BlindHostControlResult {
  readonly stateRoot: string
  readonly historyDigest: string
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly outcomes: readonly KernelOperationOutcome[]
  readonly pendingDependencies: readonly string[]
  readonly roster: ControlAdmissionSummary
  readonly initialRoster: ControlAdmissionSummary
  readonly admission: AdmissionDecision
  readonly finalizedTopics: Readonly<Record<string, JsonValue>> | null
  readonly referencedCasHashes: ReadonlySet<string>
  /** Per-ring per-epoch Ed25519 mailbox verification keys from `$keys` (`{ default: { '0': hex }, ... }`). */
  readonly mailboxVerifyKeys: Readonly<Record<string, Readonly<Record<string, string>>>>
}

/**
 * Reusable blind-host control engine: replays public control operations (`$reducers`,
 * `$admission`, `$keys`, `$publications`, `$mounts`, `$builders`) with `blindHostMode: true`
 * and zero decryption keys, queries `$admission` roster and `admit(...)` over external
 * evidence, and computes exact reachable public CAS hashes for GC.
 */
export async function replayBlindHostControl(options: ReplayBlindHostOptions): Promise<BlindHostControlResult> {
  const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
  await seedStandardModules(cas)
  if (options.publicCasNodes.length > 0) {
    await cas.putManyVerified(options.publicCasNodes.map(n => ({
      hash: n.hash,
      bytes: n.bytes,
      partition: 'public' as const,
    })))
  }

  const kernel = new TopicKernel({
    genesis: options.genesis,
    cas,
    blindHostMode: true,
    ...(options.wasmModule === undefined ? {} : { wasmModule: options.wasmModule }),
  })
  try {
    const initialRoster = await extractControlAdmission(kernel)
    const result = await kernel.materialize(options.publicOps)
    const snap = kernel.snapshot()
    const roster = await extractControlAdmission(kernel)

    const logIdHex = bytesToHex(kernel.logId)
    const opList = options.publicOps.map(op => ({
      opId: bytesToHex(op.opId),
      author: bytesToHex(op.core.author),
      authorTimestampMs: op.core.authorTimestampMs,
      visibility: op.core.visibility,
    }))
    const admission = await evaluateAdmission({
      logId: logIdHex,
      ops: opList,
      evidence: options.evidence ?? [],
      pinnedFrontier: options.pinnedFrontier ?? null,
      evaluator: kernel.createAdmissionEvaluator(),
    })

    let finalizedTopics: Readonly<Record<string, JsonValue>> | null = null
    if (options.includeFinalized !== false && admission.closedThroughMs !== null) {
      const finalOps = options.publicOps.filter(op => admission.includedOpIds.has(bytesToHex(op.opId)))
      const finalKernel = new TopicKernel({
        genesis: options.genesis,
        cas,
        blindHostMode: true,
        ...(options.wasmModule === undefined ? {} : { wasmModule: options.wasmModule }),
      })
      try {
        await finalKernel.materialize(finalOps)
        finalizedTopics = finalKernel.snapshot().topics
      } finally {
        finalKernel.dispose()
      }
    }

    const referencedCasHashes = await collectControlReferencedCasHashes({
      genesis: options.genesis,
      topics: snap.topics,
      publicOps: options.publicOps.map(op => op.core),
      cas,
    })

    let mailboxVerifyKeys: Record<string, Record<string, string>> = { default: {} }
    try {
      const q = await kernel.query('$keys', { kind: 'mailboxKeys' })
      if (q !== null && typeof q === 'object' && !Array.isArray(q)) {
        const cleaned: Record<string, Record<string, string>> = {}
        for (const [ring, epochs] of Object.entries(q as Record<string, unknown>)) {
          if (epochs !== null && typeof epochs === 'object' && !Array.isArray(epochs)) {
            const epMap: Record<string, string> = {}
            for (const [ep, keyHex] of Object.entries(epochs as Record<string, unknown>)) {
              if (typeof keyHex === 'string' && HEX32.test(keyHex)) epMap[ep] = keyHex
            }
            cleaned[ring] = epMap
          }
        }
        mailboxVerifyKeys = cleaned
      }
    } catch { /* custom $keys without mailboxKeys query */ }

    return {
      stateRoot: snap.stateRoot,
      historyDigest: snap.historyDigest,
      topics: snap.topics,
      outcomes: result.outcomes,
      pendingDependencies: result.pendingDependencies,
      roster,
      initialRoster,
      admission,
      finalizedTopics,
      referencedCasHashes,
      mailboxVerifyKeys,
    }
  } finally {
    kernel.dispose()
  }
}

export interface DryRunReducerUpgradeOptions {
  readonly specifier: string
  /** Either a raw UTF-8 ES module source string or a `chronolog-pkg/v1` package input. */
  readonly source?: string
  readonly pkg?: PutPackageInput
  readonly exportName?: string
  /** Optional sample topic name & payloads to dry-run against `reduce()` and `query()`. */
  readonly topic?: string
  readonly initialState?: JsonValue
  readonly sampleInputs?: readonly { readonly payload: JsonValue; readonly author?: string; readonly timestampMs?: bigint }[]
  readonly sampleQuery?: JsonValue
  readonly wasmModule?: QuickJsSandboxOptions['wasmModule']
}

export interface DryRunReducerUpgradeResult {
  readonly ok: boolean
  readonly ref: string
  readonly hash: string
  readonly casNodes: readonly { readonly hash: string; readonly bytes: Uint8Array; readonly partition: CasPartition }[]
  readonly description?: JsonValue
  readonly sampleOutcomes: readonly { readonly ok: boolean; readonly code?: string; readonly state?: JsonValue }[]
  readonly sampleQueryResult?: JsonValue
  readonly error?: string
}

/**
 * Validate a candidate ES module or `chronolog-pkg/v1` reducer in an isolated ephemeral
 * `MemoryBytesStore` QuickJS-NG sandbox before submitting a `$reducers` upgrade operation.
 */
export async function dryRunReducerUpgrade(options: DryRunReducerUpgradeOptions): Promise<DryRunReducerUpgradeResult> {
  if (options.source === undefined && options.pkg === undefined) {
    throw new Error('DRY_RUN_REQUIRES_SOURCE_OR_PACKAGE')
  }
  const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
  await seedStandardModules(cas)

  let rootHash: string
  if (options.pkg !== undefined) {
    const placed = await putPackageDag(cas, options.pkg, 'public')
    rootHash = placed.hash
  } else {
    const rawBytes = utf8(options.source!)
    const encoded = encodeCasNode(rawBytes, [])
    rootHash = hashCasNode(encoded)
    await cas.putRaw(rootHash, encoded, 'public')
  }
  const ref = `cas:sha256-${rootHash}`
  const subgraph = await cas.collectSubgraph([rootHash], { allowedPartition: 'public', maxNodes: 512, maxBytes: 16 * 1024 * 1024 })
  const topicName = options.topic ?? 'dry_run'
  const authorHex = '11'.repeat(32)
  const genesis: LogGenesis = {
    version: 1,
    privateLog: false,
    initialTopics: {
      $reducers: {
        runtime: DEFAULT_RUNTIME_MANIFEST as unknown as JsonValue,
        imports: { [options.specifier]: ref },
        topics: {
          [topicName]: {
            module: options.specifier,
            ...(options.exportName === undefined ? {} : { export: options.exportName }),
          },
        },
      },
      ...(options.initialState === undefined ? {} : { [topicName]: options.initialState }),
    },
    limits: DEFAULT_GENESIS_LIMITS,
    salt: new Uint8Array(16),
  }

  const kernel = new TopicKernel({
    genesis,
    cas,
    ...(options.wasmModule === undefined ? {} : { wasmModule: options.wasmModule }),
  })
  const sampleOutcomes: { readonly ok: boolean; readonly code?: string; readonly state?: JsonValue }[] = []
  try {
    // Trigger module load + optional describe()
    let description: JsonValue | undefined
    try {
      const desc = await kernel.describe()
      if (desc !== null && desc !== undefined) description = desc
    } catch { /* optional describe */ }

    const genesisBytes = encodeLogGenesis(genesis)
    const logIdBytes = kernel.logId
    void genesisBytes

    if (options.sampleInputs !== undefined && options.sampleInputs.length > 0) {
      let idx = 0
      const ops: KernelOperationInput[] = options.sampleInputs.map(sample => {
        idx += 1
        const opId = new Uint8Array(32)
        opId[31] = idx
        const authorBytes = new Uint8Array(32)
        const hex = sample.author ?? authorHex
        for (let i = 0; i < 32; i++) authorBytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
        return {
          opId,
          verified: true,
          core: {
            version: 1,
            logId: logIdBytes,
            visibility: 'public',
            author: authorBytes,
            authorTimestampMs: sample.timestampMs ?? BigInt(1_700_000_000_000 + idx),
            nonce: new Uint8Array(16),
            operationId: `dry-run-${idx}`,
            updates: [{ topic: topicName, input: sample.payload }],
          },
        }
      })
      const mat = await kernel.materialize(ops)
      const finalState = kernel.snapshot().topics[topicName]
      for (const out of mat.outcomes) {
        sampleOutcomes.push({
          ok: out.outcome === 'accepted',
          ...(typeof out.rejectionCode === 'string' ? { code: out.rejectionCode } : {}),
          ...(finalState === undefined ? {} : { state: finalState }),
        })
      }
    }

    let sampleQueryResult: JsonValue | undefined
    try {
      const q = await kernel.query(topicName, options.sampleQuery ?? {})
      if (q !== undefined) sampleQueryResult = q
    } catch (qErr) {
      const msg = qErr instanceof Error ? qErr.message : String(qErr)
      if (!msg.includes('query_not_implemented') && options.sampleQuery !== undefined) {
        return {
          ok: false,
          ref,
          hash: rootHash,
          casNodes: subgraph,
          ...(description === undefined ? {} : { description }),
          sampleOutcomes,
          error: msg,
        }
      }
    }

    return {
      ok: true,
      ref,
      hash: rootHash,
      casNodes: subgraph,
      ...(description === undefined ? {} : { description }),
      sampleOutcomes,
      ...(sampleQueryResult === undefined ? {} : { sampleQueryResult }),
    }
  } catch (err) {
    return {
      ok: false,
      ref,
      hash: rootHash,
      casNodes: subgraph,
      sampleOutcomes,
      error: err instanceof Error ? err.message : String(err),
    }
  } finally {
    kernel.dispose()
  }
}

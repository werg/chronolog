import {
  bytesToHex,
  utf8,
} from '@chronolog/canonical'
import {
  parseFinalitySchedule,
  verifyFinalityV2,
  type BlockchainAnchorVerifier,
  type FinalityCheckpoint,
  type VerifiedFinalityV2,
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

export interface ControlPermissionsSummary {
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
 * Extract normalized permissions capabilities from a blind-host `TopicKernel`,
 * supporting `attestedMembers`, `multisigMembers`, `openMembers`, and custom `$permissions` reducers.
 */
export async function extractControlPermissions(
  kernel: TopicKernel,
  rawPermsTopic: JsonValue | undefined,
): Promise<ControlPermissionsSummary> {
  const rawObj = rawPermsTopic !== null && rawPermsTopic !== undefined && typeof rawPermsTopic === 'object' && !Array.isArray(rawPermsTopic)
    ? rawPermsTopic as Record<string, JsonValue>
    : {}

  let summary: Record<string, unknown> | null = null
  try {
    const q = await kernel.query('$permissions', { summary: true })
    if (q !== null && typeof q === 'object' && !Array.isArray(q)) {
      summary = q as Record<string, unknown>
    }
  } catch { /* custom reducer without summary query */ }

  const queryList = async (role: string): Promise<readonly unknown[] | null> => {
    try {
      const q: unknown = await kernel.query('$permissions', { list: role })
      if (Array.isArray(q)) return q as readonly unknown[]
    } catch { /* ignore */ }
    return null
  }

  const rawMembers = Array.isArray(summary?.members)
    ? summary.members.filter((m): m is Record<string, JsonValue> => m !== null && typeof m === 'object' && !Array.isArray(m))
    : Array.isArray(rawObj.members)
      ? rawObj.members.filter((m): m is Record<string, JsonValue> => m !== null && typeof m === 'object' && !Array.isArray(m))
      : []

  const hasWildcard = (v: unknown): boolean => Array.isArray(v) && v.includes('*')
  const rawReadersList = summary !== null && Array.isArray(summary.readers) ? summary.readers : await queryList('readers')
  const rawWritersList = summary !== null && Array.isArray(summary.writers) ? summary.writers : await queryList('writers')

  const readers = rawReadersList !== null
    ? stringList(rawReadersList)
    : stringList(rawMembers.filter(m => m.reader === true).map(m => m.publicKey))
  const writers = rawWritersList !== null
    ? stringList(rawWritersList)
    : stringList(rawMembers.filter(m => m.writer === true || m.administrator === true).map(m => m.publicKey))
  const administrators = summary !== null && Array.isArray(summary.administrators)
    ? stringList(summary.administrators)
    : stringList(await queryList('administrators') ?? rawMembers.filter(m => m.administrator === true).map(m => m.publicKey))
  const publishers = summary !== null && Array.isArray(summary.publishers)
    ? stringList(summary.publishers)
    : stringList(await queryList('publishers') ?? rawMembers.filter(m => m.publisher === true || m.administrator === true).map(m => m.publicKey))
  const finalizers = summary !== null && Array.isArray(summary.finalizers)
    ? stringList(summary.finalizers)
    : stringList(await queryList('finalizers') ?? rawMembers.filter(m => m.finalizer === true).map(m => m.publicKey))

  const admission = (summary !== null && summary.admission !== undefined ? summary.admission as JsonValue : rawObj.admission) ?? null
  const admissionObj = admission !== null && typeof admission === 'object' && !Array.isArray(admission)
    ? admission as Record<string, JsonValue>
    : null
  const removedMembers = stringList(admissionObj?.removed)
  const blockedAuthors = stringList(summary?.blockedAuthors ?? rawObj.blockedAuthors)
  const openRead = summary?.openReaders === true || summary?.openRead === true || hasWildcard(rawReadersList) || rawObj.openRead === true
  const openWrite = summary?.openWriters === true || summary?.openWrite === true || hasWildcard(rawWritersList) || rawObj.openWrite === true

  let mode: ControlPermissionsSummary['mode'] = 'custom'
  if (summary?.mode === 'open' || summary?.mode === 'multisig' || summary?.mode === 'attested') {
    mode = summary.mode
  } else if (openRead || openWrite || rawObj.openRead !== undefined) mode = 'open'
  else if (typeof rawObj.threshold === 'number' || Array.isArray(rawObj.proposals)) mode = 'multisig'
  else if (Array.isArray(rawObj.members)) mode = 'attested'

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
  readonly checkpoints?: readonly FinalityCheckpoint[]
  readonly anchorVerifier?: BlockchainAnchorVerifier
  readonly wasmModule?: QuickJsSandboxOptions['wasmModule']
  /** When true (default), replays finalized control topics if checkpoints close a non-empty frontier. */
  readonly includeFinalized?: boolean
}

export interface BlindHostControlResult {
  readonly stateRoot: string
  readonly historyDigest: string
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly outcomes: readonly KernelOperationOutcome[]
  readonly pendingDependencies: readonly string[]
  readonly permissions: ControlPermissionsSummary
  readonly initialPermissions: ControlPermissionsSummary
  readonly finality: VerifiedFinalityV2
  readonly finalizedTopics: Readonly<Record<string, JsonValue>> | null
  readonly referencedCasHashes: ReadonlySet<string>
}

/**
 * Reusable blind-host control engine: replays public control operations (`$reducers`,
 * `$permissions`, `$keys`, `$finality`, `$publications`, `$signal_policy`, `$mounts`, `$builders`)
 * with `blindHostMode: true` and zero decryption keys, derives generic `$permissions` capabilities,
 * verifies `$finality` checkpoints, and computes exact reachable public CAS hashes for GC.
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
    const initialPermissions = await extractControlPermissions(kernel, options.genesis.initialTopics.$permissions)
    const result = await kernel.materialize(options.publicOps)
    const snap = kernel.snapshot()
    const permissions = await extractControlPermissions(kernel, snap.topics.$permissions)

    const logIdHex = bytesToHex(kernel.logId)
    const schedule = parseFinalitySchedule(snap.topics.$finality)
    const opList = options.publicOps.map(op => ({
      opId: bytesToHex(op.opId),
      authorTimestampMs: op.core.authorTimestampMs,
    }))
    const finality = await verifyFinalityV2({
      logId: logIdHex,
      schedule,
      checkpoints: options.checkpoints ?? [],
      knownOps: opList,
      ...(options.anchorVerifier === undefined ? {} : { blockchainVerifier: options.anchorVerifier }),
    })

    let finalizedTopics: Readonly<Record<string, JsonValue>> | null = null
    if (options.includeFinalized !== false && (options.checkpoints?.length ?? 0) > 0 && finality.closedThroughMs !== null) {
      const finalOps = options.publicOps.filter(op => finality.includedOpIds.has(bytesToHex(op.opId)))
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

    return {
      stateRoot: snap.stateRoot,
      historyDigest: snap.historyDigest,
      topics: snap.topics,
      outcomes: result.outcomes,
      pendingDependencies: result.pendingDependencies,
      permissions,
      initialPermissions,
      finality,
      finalizedTopics,
      referencedCasHashes,
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

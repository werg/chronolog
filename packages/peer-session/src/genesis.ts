import { bytesToHex, concatBytes, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { hpkeOpenBase, hpkeSealBase } from '@chronolog/crypto'
import {
  computeCasHash,
  ContentAddressedStore,
  MemoryBytesStore,
  putPackageDag,
  type CasPartition,
  type PutPackageInput,
} from '@chronolog/records'
import {
  DEFAULT_GENESIS_LIMITS,
  DEFAULT_RUNTIME_MANIFEST,
  encodeLogGenesis,
  genesisLogId,
  type LogGenesis,
  type GenesisLimits,
  type JsonValue,
  type RuntimeManifest,
  type TopicBinding,
} from '@chronolog/protocol'
import type { ScheduledFinalityEntry } from '@chronolog/authority'
import { STANDARD_MODULE_SOURCES } from '@chronolog/materializer/std-modules'

export interface EpochKeyBox {
  readonly encapsulatedKey: string
  readonly ciphertext: string
}

export function epochKeyCommitmentV2(epochKey: Uint8Array): string {
  if (!(epochKey instanceof Uint8Array) || epochKey.length !== 32) {
    throw new Error('EPOCH_KEY_INVALID')
  }
  return bytesToHex(sha256Sync(concatBytes(utf8('chronolog/epoch-key-commitment/v2:'), epochKey)))
}

export async function hpkeSealEpochKey(
  recipientWrapPublicKeyHex: string,
  epochKey: Uint8Array,
  logIdHex: string,
  epoch: number,
): Promise<EpochKeyBox> {
  const info = utf8(`chronolog/epoch-key/v2:${logIdHex}:${epoch}`)
  const aad = utf8(`epoch:${epoch}`)
  const sealed = await hpkeSealBase(hexToBytes(recipientWrapPublicKeyHex), epochKey, info, aad)
  return {
    encapsulatedKey: bytesToHex(sealed.encapsulatedKey),
    ciphertext: bytesToHex(sealed.ciphertext),
  }
}

export async function hpkeOpenEpochKey(
  recipientWrapPrivateKey: CryptoKey,
  recipientWrapPublicKeyHex: string,
  box: EpochKeyBox,
  logIdHex: string,
  epoch: number,
): Promise<Uint8Array> {
  const info = utf8(`chronolog/epoch-key/v2:${logIdHex}:${epoch}`)
  const aad = utf8(`epoch:${epoch}`)
  return hpkeOpenBase(
    recipientWrapPrivateKey,
    hexToBytes(recipientWrapPublicKeyHex),
    hexToBytes(box.encapsulatedKey),
    hexToBytes(box.ciphertext),
    info,
    aad,
  )
}

export interface LogMemberSeed {
  readonly publicKey: string
  readonly wrapKey?: string
  readonly reader?: boolean
  readonly writer?: boolean
  readonly administrator?: boolean
  readonly publisher?: boolean
  readonly finalizer?: boolean
}

export interface LogTopicSeed {
  readonly module: string
  readonly export?: string
  readonly config?: JsonValue
  readonly initialState?: JsonValue
}

export interface GenesisCasNode {
  readonly hash: string
  readonly bytes: Uint8Array
  readonly partition: CasPartition
}

export interface PackedBundleInput {
  readonly imports: Readonly<Record<string, string>>
  readonly casNodes: readonly GenesisCasNode[]
}

export interface BuildersSeed {
  readonly builders: readonly string[]
  readonly auditors?: readonly string[]
  readonly threshold?: number
  readonly requireAudit?: boolean
  readonly requireMountApproval?: string | null
}

export interface CreateLogGenesisOptions {
  readonly creator: LogMemberSeed
  readonly members?: readonly LogMemberSeed[]
  readonly privateLog?: boolean
  /** When true, omits the `$reducers` reducer so topic bindings and import maps are permanently frozen. */
  readonly frozenReducers?: boolean
  /** ES Module sources (specifier -> UTF-8 JS source) pinned into public CAS and registered in `$reducers.imports`. */
  readonly imports?: Readonly<Record<string, string>>
  /** Private application ES Module sources pinned into `private` CAS (only visible to encrypted ops on `privateLog: true`). */
  readonly privateImports?: Readonly<Record<string, string>>
  /** Multi-file or WASM `chronolog-pkg/v1` packages pinned into CAS and registered in `$reducers.imports`. */
  readonly packages?: Readonly<Record<string, PutPackageInput & { readonly partition?: CasPartition }>>
  /** Pre-packed bundle from `packReducers()` (imports + verified CAS DAG nodes). */
  readonly bundle?: PackedBundleInput
  /** Enable verified cross-log sub-state mounts (`$mounts` bound to `chronolog/mounts:verifiedMounts`). */
  readonly enableMounts?: boolean
  /** Enable M-of-N attested builds/audits (`$builders` + `attestedReducers` on `$reducers`). */
  readonly builders?: BuildersSeed
  /** Application topics to register in `$reducers.topics` alongside standard `$*` control topics. */
  readonly topics?: Readonly<Record<string, LogTopicSeed>>
  /** Optional host public key for `chronolog/permissions` Ed25519 admission attestations. */
  readonly hostPublicKey?: string
  /** Initial `$finality` schedule (defaults to `finality: none`). */
  readonly finalitySchedule?: readonly ScheduledFinalityEntry[]
  readonly signalPolicy?: JsonValue
  readonly runtime?: RuntimeManifest
  readonly limits?: GenesisLimits
  readonly salt?: Uint8Array
  readonly epoch0Key?: Uint8Array
}

export interface CreatedLogGenesis {
  readonly logId: string
  readonly genesis: LogGenesis
  readonly genesisBytes: Uint8Array
  /** CAS nodes (standard + app modules & chronolog-pkg/v1 DAGs) that accompany this genesis. */
  readonly casNodes: readonly GenesisCasNode[]
  /** Epoch 0 key if `privateLog` is true (undefined for public chains). */
  readonly epoch0Key?: Uint8Array
}

/**
 * Create a Chronolog v2 genesis block with hash-pinned standard modules, custom ES modules,
 * multi-file/WASM `chronolog-pkg/v1` packages, optional `$mounts`, and optional `$builders`.
 */
export async function createLogGenesis(options: CreateLogGenesisOptions): Promise<CreatedLogGenesis> {
  const privateLog = options.privateLog ?? true
  const runtime = options.runtime ?? DEFAULT_RUNTIME_MANIFEST
  const casNodesMap = new Map<string, GenesisCasNode>()
  const imports: Record<string, string> = {}

  const addNode = (hash: string, bytes: Uint8Array, partition: CasPartition): void => {
    casNodesMap.set(`${partition}:${hash}`, { hash, bytes: bytes.slice(), partition })
  }

  const pinSource = (spec: string, source: string, partition: CasPartition): void => {
    const bytes = utf8(source)
    const hash = computeCasHash(bytes)
    addNode(hash, bytes, partition)
    imports[spec] = `cas:sha256-${hash}`
  }

  for (const [spec, src] of Object.entries(STANDARD_MODULE_SOURCES)) {
    pinSource(spec, src, 'public')
  }
  if (options.imports !== undefined) {
    for (const [spec, src] of Object.entries(options.imports)) {
      pinSource(spec, src, 'public')
    }
  }
  if (options.privateImports !== undefined) {
    const partition: CasPartition = privateLog ? 'private' : 'public'
    for (const [spec, src] of Object.entries(options.privateImports)) {
      pinSource(spec, src, partition)
    }
  }
  if (options.packages !== undefined) {
    const tempCas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    for (const [spec, pkgInput] of Object.entries(options.packages)) {
      const partition: CasPartition = pkgInput.partition === 'private' && privateLog ? 'private' : 'public'
      const placed = await putPackageDag(tempCas, pkgInput, partition)
      imports[spec] = placed.ref
      const sub = await tempCas.collectSubgraph([placed.hash], { allowedPartition: partition, maxNodes: 4096, maxBytes: 32 * 1024 * 1024 })
      for (const n of sub) addNode(n.hash, n.bytes, n.partition)
    }
  }
  if (options.bundle !== undefined) {
    for (const [spec, ref] of Object.entries(options.bundle.imports)) {
      imports[spec] = ref
    }
    for (const n of options.bundle.casNodes) {
      addNode(n.hash, n.bytes, n.partition)
    }
  }

  const topicBindings: Record<string, TopicBinding> = {
    $permissions: { module: 'chronolog/permissions', export: 'attestedMembers' },
    $keys: { module: 'chronolog/keys', export: 'hpkeEpochs' },
    $finality: { module: 'chronolog/finality', export: 'scheduledFinality' },
    $publications: { module: 'chronolog/publications', export: 'signedReleases' },
    $signal_policy: { module: 'chronolog/permissions', export: 'defaultSignalPolicy' },
  }
  if (options.enableMounts === true || options.builders?.requireMountApproval != null) {
    topicBindings.$mounts = { module: 'chronolog/mounts', export: 'verifiedMounts' }
  }
  if (options.builders !== undefined) {
    topicBindings.$builders = { module: 'chronolog/builders', export: 'attestedBuilders' }
  }
  if (options.frozenReducers !== true) {
    topicBindings.$reducers = options.builders !== undefined
      ? { module: 'chronolog/builders', export: 'attestedReducers' }
      : { module: 'chronolog/permissions', export: 'adminOnlyReducers' }
  }

  const allMembers = [options.creator, ...(options.members ?? [])]
  const memberByKey = new Map<string, LogMemberSeed>()
  for (const m of allMembers) {
    memberByKey.set(m.publicKey, {
      publicKey: m.publicKey,
      ...(m.wrapKey ? { wrapKey: m.wrapKey } : {}),
      reader: m.reader ?? true,
      writer: m.writer ?? true,
      administrator: m.administrator ?? (m.publicKey === options.creator.publicKey),
      publisher: m.publisher ?? (m.publicKey === options.creator.publicKey),
      finalizer: m.finalizer ?? false,
    })
  }
  const members = [...memberByKey.values()].sort((a, b) => a.publicKey.localeCompare(b.publicKey))

  const schedule = (options.finalitySchedule ?? [{ effectiveAfterMs: -1n, policy: { kind: 'none' } }]).map(entry => ({
    effectiveAfterMs: Number(entry.effectiveAfterMs),
    policy: entry.policy,
  }))

  const initialTopics: Record<string, JsonValue> = {
    $permissions: {
      members: members as unknown as JsonValue,
      admission: options.hostPublicKey ? { hostKey: options.hostPublicKey } : null,
    },
    $keys: { currentEpoch: -1, epochs: {} },
    $finality: { schedule },
    $publications: { revision: 0, current: null, history: [] },
    ...(options.signalPolicy === undefined ? {} : { $signal_policy: options.signalPolicy }),
  }
  if (options.enableMounts === true || options.builders?.requireMountApproval != null) {
    initialTopics.$mounts = { mounts: {} }
  }
  if (options.builders !== undefined) {
    initialTopics.$builders = {
      builders: [...new Set(options.builders.builders)].sort(),
      auditors: [...new Set(options.builders.auditors ?? [])].sort(),
      threshold: options.builders.threshold ?? 1,
      requireAudit: options.builders.requireAudit ?? false,
      requireMountApproval: options.builders.requireMountApproval ?? null,
    }
  }

  if (options.topics !== undefined) {
    for (const [topicName, seed] of Object.entries(options.topics)) {
      topicBindings[topicName] = {
        module: seed.module,
        ...(seed.export === undefined ? {} : { export: seed.export }),
        ...(seed.config === undefined ? {} : { config: seed.config }),
      }
      if (seed.initialState !== undefined) {
        initialTopics[topicName] = seed.initialState
      }
    }
  }

  initialTopics.$reducers = {
    runtime: runtime as unknown as JsonValue,
    imports,
    topics: topicBindings as unknown as JsonValue,
  }

  const salt = options.salt ?? crypto.getRandomValues(new Uint8Array(16))
  const genesis: LogGenesis = {
    version: 1,
    privateLog,
    initialTopics,
    limits: options.limits ?? DEFAULT_GENESIS_LIMITS,
    salt,
  }
  const genesisBytes = encodeLogGenesis(genesis)
  const logId = bytesToHex(genesisLogId(genesisBytes))
  const epoch0Key = privateLog ? (options.epoch0Key ?? crypto.getRandomValues(new Uint8Array(32))) : undefined
  const casNodes = [...casNodesMap.values()]

  return {
    logId,
    genesis,
    genesisBytes,
    casNodes,
    ...(epoch0Key === undefined ? {} : { epoch0Key }),
  }
}

/**
 * Create a dogfooded Chronolog Package Registry genesis (public by default, or private org registry).
 * Uses `chronolog/registry` (SQLite + FTS5 full-text search + signed build/audit attestations).
 */
export function createRegistryGenesis(options: {
  readonly creator: LogMemberSeed
  readonly members?: readonly LogMemberSeed[]
  readonly privateLog?: boolean
  readonly salt?: Uint8Array
  readonly epoch0Key?: Uint8Array
}): Promise<CreatedLogGenesis> {
  return createLogGenesis({
    creator: options.creator,
    ...(options.members === undefined ? {} : { members: options.members }),
    privateLog: options.privateLog ?? false,
    ...(options.salt === undefined ? {} : { salt: options.salt }),
    ...(options.epoch0Key === undefined ? {} : { epoch0Key: options.epoch0Key }),
    topics: {
      packages: { module: 'chronolog/registry', export: 'packageRegistry' },
    },
  })
}

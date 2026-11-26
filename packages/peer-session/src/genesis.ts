import { bytesToHex, concatBytes, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { hpkeOpenBase, hpkeSealBase } from '@chronolog/crypto'
import { computeCasHash } from '@chronolog/records'
import {
  DEFAULT_GENESIS_LIMITS,
  DEFAULT_RUNTIME_MANIFEST,
  encodeGenesisBlock,
  genesisChainId,
  type GenesisBlock,
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
  chainIdHex: string,
  epoch: number,
): Promise<EpochKeyBox> {
  const info = utf8(`chronolog/epoch-key/v2:${chainIdHex}:${epoch}`)
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
  chainIdHex: string,
  epoch: number,
): Promise<Uint8Array> {
  const info = utf8(`chronolog/epoch-key/v2:${chainIdHex}:${epoch}`)
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

export interface ChainMemberSeed {
  readonly publicKey: string
  readonly wrapKey?: string
  readonly reader?: boolean
  readonly writer?: boolean
  readonly administrator?: boolean
  readonly publisher?: boolean
  readonly finalizer?: boolean
}

export interface ChainTopicSeed {
  readonly module: string
  readonly export?: string
  readonly config?: JsonValue
  readonly initialState?: JsonValue
}

export interface CreateChainGenesisOptions {
  readonly creator: ChainMemberSeed
  readonly members?: readonly ChainMemberSeed[]
  readonly privateChain?: boolean
  /** When true, omits the `$reducers` reducer so topic bindings and import maps are permanently frozen. */
  readonly frozenReducers?: boolean
  /** ES Module sources (specifier -> UTF-8 JS source) pinned into CAS and registered in `$reducers.imports`. */
  readonly imports?: Readonly<Record<string, string>>
  /** Application topics to register in `$reducers.topics` alongside standard `$*` control topics. */
  readonly topics?: Readonly<Record<string, ChainTopicSeed>>
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

export interface CreatedChainGenesis {
  readonly chainId: string
  readonly genesis: GenesisBlock
  readonly genesisBytes: Uint8Array
  /** Public CAS nodes (standard + app ES module sources) that must accompany this genesis. */
  readonly casNodes: readonly { readonly hash: string; readonly bytes: Uint8Array; readonly partition: 'public' }[]
  /** Epoch 0 key if `privateChain` is true (undefined for public chains). */
  readonly epoch0Key?: Uint8Array
}

/**
 * Create a Chronolog v2 genesis block with hash-pinned standard and application ES Modules.
 * When `privateChain` is true (the default), generates epoch 0 and seals HPKE lockboxes for
 * all initial readers that provide a `wrapKey` after deriving the deterministic `chainId`.
 */
export async function createChainGenesis(options: CreateChainGenesisOptions): Promise<CreatedChainGenesis> {
  const privateChain = options.privateChain ?? true
  const runtime = options.runtime ?? DEFAULT_RUNTIME_MANIFEST
  const casMap = new Map<string, Uint8Array>()
  const imports: Record<string, string> = {}

  const pinSource = (spec: string, source: string): void => {
    const bytes = utf8(source)
    const hash = computeCasHash(bytes)
    casMap.set(hash, bytes)
    imports[spec] = `cas:sha256-${hash}`
  }

  for (const [spec, src] of Object.entries(STANDARD_MODULE_SOURCES)) {
    pinSource(spec, src)
  }
  if (options.imports !== undefined) {
    for (const [spec, src] of Object.entries(options.imports)) {
      pinSource(spec, src)
    }
  }

  const topicBindings: Record<string, TopicBinding> = {
    $permissions: { module: 'chronolog/permissions', export: 'attestedMembers' },
    $keys: { module: 'chronolog/keys', export: 'hpkeEpochs' },
    $finality: { module: 'chronolog/finality', export: 'scheduledFinality' },
    $publications: { module: 'chronolog/publications', export: 'signedReleases' },
    $signal_policy: { module: 'chronolog/permissions', export: 'defaultSignalPolicy' },
  }
  if (options.frozenReducers !== true) {
    topicBindings.$reducers = { module: 'chronolog/permissions', export: 'adminOnlyReducers' }
  }

  const allMembers = [options.creator, ...(options.members ?? [])]
  const memberByKey = new Map<string, ChainMemberSeed>()
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
  const genesis: GenesisBlock = {
    version: 1,
    privateChain,
    initialTopics,
    limits: options.limits ?? DEFAULT_GENESIS_LIMITS,
    salt,
  }
  const genesisBytes = encodeGenesisBlock(genesis)
  const chainId = bytesToHex(genesisChainId(genesisBytes))

  // For private chains, epoch 0 is seeded either via local epoch0Key (and locked into $keys via initial op or epochKeys option).
  // Keeping genesis deterministic without needing chainId-before-genesis circularity!
  const epoch0Key = privateChain ? (options.epoch0Key ?? crypto.getRandomValues(new Uint8Array(32))) : undefined

  const casNodes = [...casMap.entries()].map(([hash, bytes]) => ({
    hash,
    bytes,
    partition: 'public' as const,
  }))

  return {
    chainId,
    genesis,
    genesisBytes,
    casNodes,
    ...(epoch0Key === undefined ? {} : { epoch0Key }),
  }
}

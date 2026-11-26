import {
  assertCanonicalCbor,
  compareBytes,
  DEFAULT_DECODE_LIMITS,
  encodeCanonicalCbor,
  equalBytes,
  hashDomainSync,
  utf8,
  type CborMapKey,
  type CborValue,
} from '@chronolog/canonical'
import { ProtocolError, protocolInvariant } from './errors.js'
import { signDomain, verifyDomain, type ProtocolDomain } from './primitives.js'

export const V2_OP_DOMAIN = 'chronolog/op/v1' as unknown as ProtocolDomain
export const CONTROL_TOPICS = Object.freeze([
  '$reducers',
  '$permissions',
  '$keys',
  '$finality',
  '$publications',
  '$signal_policy',
] as const)

const CONTROL_TOPIC_SET = new Set<string>(CONTROL_TOPICS)
const HEX32 = /^[0-9a-f]{64}$/u
const MAX_TOPIC_NAME_BYTES = 128
const MAX_UPDATES_PER_OP = 64
const MAX_OP_ID_BYTES = 512

export type OperationVisibility = 'public' | 'encrypted'

export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue }
export type EventPayload = JsonValue

export const MAX_EVENT_BYTES = 16_384

/** Bounded canonical JSON, shared by event bodies, attestations, and public application metadata. */
export function canonicalJson(
  payload: JsonValue,
  limits: { readonly maxBytes: number; readonly maxNodes: number; readonly maxDepth: number } = { maxBytes: 65_536, maxNodes: 8192, maxDepth: 32 },
): string {
  for (const bound of [limits.maxBytes, limits.maxNodes, limits.maxDepth]) {
    protocolInvariant(Number.isSafeInteger(bound) && bound > 0, 'SCHEMA_INVALID', 'Invalid JSON limits')
  }
  let nodes = 0
  const visit = (value: unknown, depth: number): string => {
    protocolInvariant(depth <= limits.maxDepth && ++nodes <= limits.maxNodes, 'SCHEMA_INVALID', 'JSON payload is too complex')
    if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
    if (typeof value === 'number') {
      protocolInvariant(Number.isFinite(value), 'SCHEMA_INVALID', 'Numbers must be finite')
      return JSON.stringify(Object.is(value, -0) ? 0 : value)
    }
    if (Array.isArray(value)) {
      protocolInvariant(Reflect.ownKeys(value).length === value.length + 1, 'SCHEMA_INVALID', 'Arrays cannot carry extra properties')
      const entries: string[] = []
      for (let i = 0; i < value.length; i++) {
        const desc = Object.getOwnPropertyDescriptor(value, i)
        protocolInvariant(desc !== undefined && 'value' in desc && desc.enumerable === true, 'SCHEMA_INVALID', 'Arrays require dense elements')
        entries.push(visit(desc.value, depth + 1))
      }
      return `[${entries.join(',')}]`
    }
    protocolInvariant(
      typeof value === 'object' && value !== null && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null),
      'SCHEMA_INVALID',
      'Payload must contain JSON values',
    )
    const keys = Object.keys(value).sort()
    protocolInvariant(Reflect.ownKeys(value).length === keys.length, 'SCHEMA_INVALID', 'Objects require enumerable string keys')
    return `{${keys.map(key => {
      const desc = Object.getOwnPropertyDescriptor(value, key)!
      protocolInvariant('value' in desc, 'SCHEMA_INVALID', 'Accessors are prohibited')
      return `${JSON.stringify(key)}:${visit(desc.value, depth + 1)}`
    }).join(',')}}`
  }
  const encoded = visit(payload, 0)
  protocolInvariant(utf8(encoded).length <= limits.maxBytes, 'SCHEMA_INVALID', 'JSON payload is too large')
  return encoded
}

export function canonicalEventPayload(payload: EventPayload): string {
  return canonicalJson(payload, { maxBytes: MAX_EVENT_BYTES, maxNodes: 4096, maxDepth: 32 })
}

export interface RuntimeManifest {
  readonly js: string
  readonly builtins: Readonly<Record<string, string>>
}

export interface TopicBinding {
  readonly module: string
  readonly export?: string
  readonly config?: JsonValue
}

export interface ReducersConfig {
  readonly runtime: RuntimeManifest
  readonly imports: Readonly<Record<string, string>>
  readonly topics: Readonly<Record<string, TopicBinding>>
}

export interface GenesisLimits {
  readonly maxMemoryBytes: number
  readonly maxTopicStateBytes: number
  readonly maxUpdatesPerOp: number
}

export interface GenesisBlock {
  readonly version: 1
  readonly privateChain: boolean
  readonly initialTopics: Readonly<Record<string, JsonValue>>
  readonly limits: GenesisLimits
  readonly salt: Uint8Array
}

export interface TopicUpdate {
  readonly topic: string
  readonly input: JsonValue
}

export interface OperationCore {
  readonly version: 1
  readonly chainId: Uint8Array
  readonly author: Uint8Array
  readonly operationId: string
  readonly authorTimestampMs: bigint
  readonly nonce: Uint8Array
  readonly visibility: OperationVisibility
  readonly updates: readonly TopicUpdate[]
}

export interface SignedOperation {
  readonly coreBytes: Uint8Array
  readonly signature: Uint8Array
}

export interface EncryptedOperationEnvelope {
  readonly version: 1
  readonly chainId: Uint8Array
  readonly opId: Uint8Array
  readonly author: Uint8Array
  readonly epoch: number
  readonly nonce: Uint8Array
  readonly ciphertext: Uint8Array
}

export interface OperationOrderKey {
  readonly authorTimestampMs: bigint
  readonly author: Uint8Array
  readonly opId: Uint8Array
}

export function isControlTopic(topic: string): boolean {
  return CONTROL_TOPIC_SET.has(topic)
}

export function assertValidTopicName(topic: string): void {
  protocolInvariant(
    typeof topic === 'string' &&
      /^(?:\$[a-z][a-z0-9_]*|[A-Za-z0-9][A-Za-z0-9._/-]*)$/u.test(topic) &&
      utf8(topic).length <= MAX_TOPIC_NAME_BYTES,
    'SCHEMA_INVALID',
    `Invalid topic name: ${String(topic)}`,
  )
}

/**
 * Strictly normalize any JS value into canonical JSON-compatible data (no undefined, NaN, Infinity, -0,
 * accessors, prototypes, or cycles) and convert cleanly to canonical CBOR for hashing & storage.
 */
export function normalizeJsonValue(value: unknown, limits: { readonly maxDepth?: number; readonly maxNodes?: number } = {}): JsonValue {
  const maxDepth = limits.maxDepth ?? 32
  const maxNodes = limits.maxNodes ?? 16_384
  let nodes = 0
  const visit = (v: unknown, depth: number): JsonValue => {
    protocolInvariant(depth <= maxDepth && ++nodes <= maxNodes, 'SCHEMA_INVALID', 'Value exceeds depth/node limits')
    if (v === null || typeof v === 'boolean' || typeof v === 'string') return v
    if (typeof v === 'number') {
      protocolInvariant(Number.isFinite(v), 'SCHEMA_INVALID', 'Non-finite number is prohibited')
      // Normalize -0 to 0 and require safe integer or finite IEEE float via string roundtrip
      return Object.is(v, -0) ? 0 : v
    }
    if (Array.isArray(v)) {
      protocolInvariant(Reflect.ownKeys(v).length === v.length + 1, 'SCHEMA_INVALID', 'Arrays cannot carry extra properties')
      const out: JsonValue[] = []
      for (let i = 0; i < v.length; i++) {
        const desc = Object.getOwnPropertyDescriptor(v, i)
        protocolInvariant(desc !== undefined && 'value' in desc && desc.enumerable === true, 'SCHEMA_INVALID', 'Sparse arrays are prohibited')
        out.push(visit(desc.value, depth + 1))
      }
      return out
    }
    protocolInvariant(
      typeof v === 'object' && v !== null && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null),
      'SCHEMA_INVALID',
      'Value must be plain JSON data',
    )
    const keys = Object.keys(v).sort()
    protocolInvariant(Reflect.ownKeys(v).length === keys.length, 'SCHEMA_INVALID', 'Objects require enumerable string keys only')
    const out: Record<string, JsonValue> = {}
    for (const key of keys) {
      const desc = Object.getOwnPropertyDescriptor(v, key)!
      protocolInvariant('value' in desc, 'SCHEMA_INVALID', 'Accessors are prohibited')
      out[key] = visit(desc.value, depth + 1)
    }
    return out
  }
  return visit(value, 0)
}

/** Encode a normalized JsonValue into deterministic CBOR (integers as bigint; non-integer floats as tagged canonical string map). */
export function jsonToCbor(value: JsonValue): CborValue {
  const normalized = normalizeJsonValue(value)
  const convert = (v: JsonValue): CborValue => {
    if (v === null || typeof v === 'boolean' || typeof v === 'string') return v
    if (typeof v === 'number') {
      if (Number.isSafeInteger(v)) return BigInt(v)
      // Deterministic representation for non-integer finite numbers inside integer-only canonical CBOR profile
      return new Map<CborMapKey, CborValue>([['$f', JSON.stringify(v)]])
    }
    if (Array.isArray(v)) return v.map(convert)
    const entries = Object.keys(v).sort().map(k => [k, convert((v as Readonly<Record<string, JsonValue>>)[k]!)] as const)
    return new Map<CborMapKey, CborValue>(entries)
  }
  return convert(normalized)
}

export function cborToJson(value: CborValue): JsonValue {
  const convert = (v: CborValue): JsonValue => {
    if (v === null || typeof v === 'boolean' || typeof v === 'string') return v
    if (typeof v === 'bigint') {
      protocolInvariant(v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER), 'INTEGER_OUT_OF_RANGE', 'Integer outside safe JS range')
      return Number(v)
    }
    if (Array.isArray(v)) return v.map(convert)
    if (v instanceof Map) {
      if (v.size === 1 && v.has('$f') && typeof v.get('$f') === 'string') {
        const parsed = Number(v.get('$f'))
        protocolInvariant(Number.isFinite(parsed) && !Number.isSafeInteger(parsed), 'SCHEMA_INVALID', 'Invalid float encoding')
        return parsed
      }
      const out: Record<string, JsonValue> = {}
      for (const [k, item] of v as ReadonlyMap<CborMapKey, CborValue>) {
        protocolInvariant(typeof k === 'string', 'SCHEMA_INVALID', 'JSON map keys must be strings')
        out[k] = convert(item)
      }
      return out
    }
    throw new ProtocolError('SCHEMA_INVALID', 'Unsupported CBOR value in JSON bridge')
  }
  return normalizeJsonValue(convert(value))
}

export function encodeCanonicalJsonCbor(value: JsonValue): Uint8Array {
  return encodeCanonicalCbor(jsonToCbor(value))
}

export function decodeCanonicalJsonCbor(bytes: Uint8Array): JsonValue {
  return cborToJson(assertCanonicalCbor(bytes, DEFAULT_DECODE_LIMITS))
}

export function assertValidReducersConfig(value: unknown): ReducersConfig {
  const norm = normalizeJsonValue(value)
  protocolInvariant(norm !== null && typeof norm === 'object' && !Array.isArray(norm), 'SCHEMA_INVALID', '$reducers must be an object')
  const obj = norm as Record<string, JsonValue>
  const runtime = obj.runtime
  protocolInvariant(runtime !== null && typeof runtime === 'object' && !Array.isArray(runtime), 'SCHEMA_INVALID', '$reducers.runtime must be an object')
  const rtObj = runtime as Record<string, JsonValue>
  protocolInvariant(typeof rtObj.js === 'string' && rtObj.js.length > 0 && rtObj.js.length <= 256, 'SCHEMA_INVALID', '$reducers.runtime.js invalid')
  protocolInvariant(rtObj.builtins !== null && typeof rtObj.builtins === 'object' && !Array.isArray(rtObj.builtins), 'SCHEMA_INVALID', '$reducers.runtime.builtins invalid')
  const builtins: Record<string, string> = {}
  for (const [k, v] of Object.entries(rtObj.builtins as Record<string, JsonValue>)) {
    protocolInvariant(k.startsWith('chronolog:') && typeof v === 'string' && v.length > 0 && v.length <= 256, 'SCHEMA_INVALID', `Invalid builtin mapping: ${k}`)
    builtins[k] = v
  }
  protocolInvariant(obj.imports !== null && typeof obj.imports === 'object' && !Array.isArray(obj.imports), 'SCHEMA_INVALID', '$reducers.imports must be an object')
  const imports: Record<string, string> = {}
  for (const [spec, ref] of Object.entries(obj.imports as Record<string, JsonValue>)) {
    protocolInvariant(typeof spec === 'string' && spec.length > 0 && spec.length <= 256 && !spec.startsWith('.') && !spec.startsWith('/'), 'SCHEMA_INVALID', `Invalid import specifier: ${spec}`)
    protocolInvariant(typeof ref === 'string' && /^cas:sha256-[0-9a-f]{64}$/u.test(ref), 'SCHEMA_INVALID', `Import must pin cas:sha256-<hex>: ${spec}`)
    imports[spec] = ref
  }
  protocolInvariant(obj.topics !== null && typeof obj.topics === 'object' && !Array.isArray(obj.topics), 'SCHEMA_INVALID', '$reducers.topics must be an object')
  const topics: Record<string, TopicBinding> = {}
  for (const [topicName, rawBinding] of Object.entries(obj.topics as Record<string, JsonValue>)) {
    assertValidTopicName(topicName)
    protocolInvariant(rawBinding !== null && typeof rawBinding === 'object' && !Array.isArray(rawBinding), 'SCHEMA_INVALID', `Invalid topic binding: ${topicName}`)
    const b = rawBinding as Record<string, JsonValue>
    protocolInvariant(typeof b.module === 'string' && Object.hasOwn(imports, b.module), 'SCHEMA_INVALID', `Topic ${topicName} references unknown import`)
    if (b.export !== undefined) protocolInvariant(typeof b.export === 'string' && b.export.length > 0 && b.export.length <= 128, 'SCHEMA_INVALID', `Invalid export for ${topicName}`)
    topics[topicName] = {
      module: b.module,
      ...(b.export === undefined ? {} : { export: b.export }),
      ...(b.config === undefined ? {} : { config: b.config }),
    }
  }
  return { runtime: { js: rtObj.js, builtins }, imports, topics }
}

export function encodeGenesisBlock(genesis: GenesisBlock): Uint8Array {
  protocolInvariant(genesis.version === 1, 'UNSUPPORTED_VERSION', 'Genesis version must be 1')
  protocolInvariant(typeof genesis.privateChain === 'boolean', 'SCHEMA_INVALID', 'Genesis privateChain must be boolean')
  protocolInvariant(genesis.salt instanceof Uint8Array && genesis.salt.length >= 16 && genesis.salt.length <= 64, 'SCHEMA_INVALID', 'Genesis salt must be 16..64 bytes')
  for (const n of [genesis.limits.maxMemoryBytes, genesis.limits.maxTopicStateBytes, genesis.limits.maxUpdatesPerOp]) {
    protocolInvariant(Number.isSafeInteger(n) && n > 0, 'SCHEMA_INVALID', 'Invalid genesis limits')
  }
  protocolInvariant(Object.hasOwn(genesis.initialTopics, '$reducers'), 'SCHEMA_INVALID', 'Genesis must include $reducers topic')
  assertValidReducersConfig(genesis.initialTopics.$reducers)
  const topicsMap = new Map<CborMapKey, CborValue>()
  for (const key of Object.keys(genesis.initialTopics).sort()) {
    assertValidTopicName(key)
    const val = normalizeJsonValue(genesis.initialTopics[key])
    const encodedTopic = encodeCanonicalJsonCbor(val)
    protocolInvariant(encodedTopic.length <= genesis.limits.maxTopicStateBytes, 'SCHEMA_INVALID', `Initial topic ${key} exceeds maxTopicStateBytes`)
    topicsMap.set(key, jsonToCbor(val))
  }
  const map = new Map<CborMapKey, CborValue>([
    [0n, 1n],
    [1n, genesis.privateChain],
    [2n, topicsMap],
    [3n, new Map<CborMapKey, CborValue>([
      [0n, BigInt(genesis.limits.maxMemoryBytes)],
      [1n, BigInt(genesis.limits.maxTopicStateBytes)],
      [2n, BigInt(genesis.limits.maxUpdatesPerOp)],
    ])],
    [4n, genesis.salt],
  ])
  return encodeCanonicalCbor(map)
}

export function decodeGenesisBlock(bytes: Uint8Array): GenesisBlock {
  const raw = assertCanonicalCbor(bytes, DEFAULT_DECODE_LIMITS)
  protocolInvariant(raw instanceof Map && raw.size === 5, 'SCHEMA_INVALID', 'Genesis must be a 5-entry map')
  const map = raw as ReadonlyMap<CborMapKey, CborValue>
  protocolInvariant(map.get(0n) === 1n, 'UNSUPPORTED_VERSION', 'Unsupported genesis version')
  const privateChain = map.get(1n)
  protocolInvariant(typeof privateChain === 'boolean', 'SCHEMA_INVALID', 'Invalid privateChain')
  const topicsRaw = map.get(2n)
  protocolInvariant(topicsRaw instanceof Map, 'SCHEMA_INVALID', 'Invalid initialTopics')
  const initialTopics: Record<string, JsonValue> = {}
  for (const [k, v] of topicsRaw as ReadonlyMap<CborMapKey, CborValue>) {
    protocolInvariant(typeof k === 'string', 'SCHEMA_INVALID', 'Topic name must be string')
    assertValidTopicName(k)
    initialTopics[k] = cborToJson(v)
  }
  const limitsRaw = map.get(3n)
  protocolInvariant(limitsRaw instanceof Map && limitsRaw.size === 3, 'SCHEMA_INVALID', 'Invalid genesis limits')
  const limitsMap = limitsRaw as ReadonlyMap<CborMapKey, CborValue>
  const num = (v: CborValue | undefined): number => {
    protocolInvariant(typeof v === 'bigint' && v > 0n && v <= BigInt(Number.MAX_SAFE_INTEGER), 'SCHEMA_INVALID', 'Invalid limit')
    return Number(v)
  }
  const salt = map.get(4n)
  protocolInvariant(salt instanceof Uint8Array && salt.length >= 16 && salt.length <= 64, 'SCHEMA_INVALID', 'Invalid genesis salt')
  const genesis: GenesisBlock = {
    version: 1,
    privateChain,
    initialTopics,
    limits: {
      maxMemoryBytes: num(limitsMap.get(0n)),
      maxTopicStateBytes: num(limitsMap.get(1n)),
      maxUpdatesPerOp: num(limitsMap.get(2n)),
    },
    salt: salt.slice(),
  }
  protocolInvariant(equalBytes(encodeGenesisBlock(genesis), bytes), 'CBOR_NON_CANONICAL', 'Genesis bytes not canonical')
  return genesis
}

export function genesisChainId(genesis: GenesisBlock | Uint8Array): Uint8Array {
  const bytes = genesis instanceof Uint8Array ? genesis : encodeGenesisBlock(genesis)
  return hashDomainSync('genesis', bytes)
}

export function encodeOperationCore(core: OperationCore): Uint8Array {
  protocolInvariant(core.version === 1, 'UNSUPPORTED_VERSION', 'Operation version must be 1')
  protocolInvariant(core.chainId instanceof Uint8Array && core.chainId.length === 32, 'SCHEMA_INVALID', 'chainId must be 32 bytes')
  protocolInvariant(core.author instanceof Uint8Array && core.author.length === 32, 'SCHEMA_INVALID', 'author must be 32 bytes')
  protocolInvariant(
    typeof core.operationId === 'string' && core.operationId.length > 0 && utf8(core.operationId).length <= MAX_OP_ID_BYTES &&
      [...core.operationId].every(c => c.charCodeAt(0) >= 32),
    'SCHEMA_INVALID',
    'Invalid operationId',
  )
  protocolInvariant(core.authorTimestampMs >= 0n && core.authorTimestampMs <= (1n << 63n) - 1n, 'INTEGER_OUT_OF_RANGE', 'Invalid authorTimestampMs')
  protocolInvariant(core.nonce instanceof Uint8Array && core.nonce.length >= 16 && core.nonce.length <= 64, 'SCHEMA_INVALID', 'Invalid nonce')
  protocolInvariant(core.visibility === 'public' || core.visibility === 'encrypted', 'SCHEMA_INVALID', 'Invalid visibility')
  protocolInvariant(Array.isArray(core.updates) && core.updates.length > 0 && core.updates.length <= MAX_UPDATES_PER_OP, 'SCHEMA_INVALID', 'Invalid updates list')
  const updatesList: readonly TopicUpdate[] = core.updates
  const encodedUpdates: CborValue[] = updatesList.map((u): CborValue => {
    assertValidTopicName(u.topic)
    return [u.topic, jsonToCbor(normalizeJsonValue(u.input))]
  })
  const map = new Map<CborMapKey, CborValue>([
    [0n, 1n],
    [1n, core.chainId],
    [2n, core.author],
    [3n, core.operationId],
    [4n, core.authorTimestampMs],
    [5n, core.nonce],
    [6n, core.visibility === 'public' ? 0n : 1n],
    [7n, encodedUpdates],
  ])
  return encodeCanonicalCbor(map)
}

export function decodeOperationCore(bytes: Uint8Array): OperationCore {
  const raw = assertCanonicalCbor(bytes, DEFAULT_DECODE_LIMITS)
  protocolInvariant(raw instanceof Map && raw.size === 8, 'SCHEMA_INVALID', 'OperationCore must be an 8-entry map')
  const map = raw as ReadonlyMap<CborMapKey, CborValue>
  protocolInvariant(map.get(0n) === 1n, 'UNSUPPORTED_VERSION', 'Unsupported op version')
  const chainId = map.get(1n)
  const author = map.get(2n)
  const operationId = map.get(3n)
  const authorTimestampMs = map.get(4n)
  const nonce = map.get(5n)
  const vis = map.get(6n)
  const rawUpdates = map.get(7n)
  protocolInvariant(chainId instanceof Uint8Array && chainId.length === 32, 'SCHEMA_INVALID', 'Invalid chainId')
  protocolInvariant(author instanceof Uint8Array && author.length === 32, 'SCHEMA_INVALID', 'Invalid author')
  protocolInvariant(typeof operationId === 'string', 'SCHEMA_INVALID', 'Invalid operationId')
  protocolInvariant(typeof authorTimestampMs === 'bigint', 'SCHEMA_INVALID', 'Invalid authorTimestampMs')
  protocolInvariant(nonce instanceof Uint8Array, 'SCHEMA_INVALID', 'Invalid nonce')
  protocolInvariant(vis === 0n || vis === 1n, 'SCHEMA_INVALID', 'Invalid visibility')
  protocolInvariant(Array.isArray(rawUpdates) && rawUpdates.length > 0 && rawUpdates.length <= MAX_UPDATES_PER_OP, 'SCHEMA_INVALID', 'Invalid updates')
  const updates: TopicUpdate[] = rawUpdates.map(item => {
    protocolInvariant(Array.isArray(item) && item.length === 2 && typeof item[0] === 'string', 'SCHEMA_INVALID', 'Invalid update tuple')
    assertValidTopicName(item[0])
    return { topic: item[0], input: cborToJson(item[1] as CborValue) }
  })
  const core: OperationCore = {
    version: 1,
    chainId: chainId.slice(),
    author: author.slice(),
    operationId,
    authorTimestampMs,
    nonce: nonce.slice(),
    visibility: vis === 0n ? 'public' : 'encrypted',
    updates,
  }
  protocolInvariant(equalBytes(encodeOperationCore(core), bytes), 'CBOR_NON_CANONICAL', 'OperationCore bytes not canonical')
  return core
}

export function operationIdDigest(coreOrBytes: OperationCore | Uint8Array): Uint8Array {
  const bytes = coreOrBytes instanceof Uint8Array ? coreOrBytes : encodeOperationCore(coreOrBytes)
  return hashDomainSync('op', bytes)
}

export async function signOperationCore(core: OperationCore, privateKey: CryptoKey): Promise<SignedOperation> {
  const coreBytes = encodeOperationCore(core)
  const signature = await signDomain(V2_OP_DOMAIN, coreBytes, privateKey)
  return { coreBytes, signature }
}

export async function verifySignedOperation(op: SignedOperation): Promise<{ readonly core: OperationCore; readonly opId: Uint8Array }> {
  const core = decodeOperationCore(op.coreBytes)
  protocolInvariant(op.signature instanceof Uint8Array && op.signature.length === 64, 'INVALID_SIGNATURE', 'Signature must be 64 bytes')
  const valid = await verifyDomain(V2_OP_DOMAIN, op.coreBytes, op.signature, core.author)
  protocolInvariant(valid, 'INVALID_SIGNATURE', 'Operation signature verification failed')
  return { core, opId: operationIdDigest(op.coreBytes) }
}

export function encodeSignedOperation(op: SignedOperation): Uint8Array {
  return encodeCanonicalCbor(new Map<CborMapKey, CborValue>([
    [0n, op.coreBytes],
    [1n, op.signature],
  ]))
}

export function decodeSignedOperation(bytes: Uint8Array): SignedOperation {
  const raw = assertCanonicalCbor(bytes, DEFAULT_DECODE_LIMITS)
  protocolInvariant(raw instanceof Map && raw.size === 2, 'SCHEMA_INVALID', 'SignedOperation invalid')
  const map = raw as ReadonlyMap<CborMapKey, CborValue>
  const coreBytes = map.get(0n), signature = map.get(1n)
  protocolInvariant(coreBytes instanceof Uint8Array && signature instanceof Uint8Array && signature.length === 64, 'SCHEMA_INVALID', 'SignedOperation fields invalid')
  return { coreBytes: coreBytes.slice(), signature: signature.slice() }
}

export function encodeEncryptedEnvelope(env: EncryptedOperationEnvelope): Uint8Array {
  protocolInvariant(env.version === 1, 'UNSUPPORTED_VERSION', 'Envelope version must be 1')
  protocolInvariant(env.chainId.length === 32 && env.opId.length === 32 && env.author.length === 32, 'SCHEMA_INVALID', 'Invalid envelope 32-byte field')
  protocolInvariant(Number.isSafeInteger(env.epoch) && env.epoch >= 0, 'SCHEMA_INVALID', 'Invalid epoch')
  protocolInvariant(env.nonce.length === 12 && env.ciphertext.length > 0, 'SCHEMA_INVALID', 'Invalid ciphertext/nonce')
  return encodeCanonicalCbor(new Map<CborMapKey, CborValue>([
    [0n, 1n],
    [1n, env.chainId],
    [2n, env.opId],
    [3n, env.author],
    [4n, BigInt(env.epoch)],
    [5n, env.nonce],
    [6n, env.ciphertext],
  ]))
}

export function decodeEncryptedEnvelope(bytes: Uint8Array): EncryptedOperationEnvelope {
  const raw = assertCanonicalCbor(bytes, DEFAULT_DECODE_LIMITS)
  protocolInvariant(raw instanceof Map && raw.size === 7, 'SCHEMA_INVALID', 'Invalid envelope')
  const map = raw as ReadonlyMap<CborMapKey, CborValue>
  protocolInvariant(map.get(0n) === 1n, 'SCHEMA_INVALID', 'Invalid envelope')
  const chainId = map.get(1n), opId = map.get(2n), author = map.get(3n), epoch = map.get(4n), nonce = map.get(5n), ciphertext = map.get(6n)
  protocolInvariant(
    chainId instanceof Uint8Array && chainId.length === 32 &&
      opId instanceof Uint8Array && opId.length === 32 &&
      author instanceof Uint8Array && author.length === 32 &&
      typeof epoch === 'bigint' && epoch >= 0n && epoch <= BigInt(Number.MAX_SAFE_INTEGER) &&
      nonce instanceof Uint8Array && nonce.length === 12 &&
      ciphertext instanceof Uint8Array && ciphertext.length > 0,
    'SCHEMA_INVALID',
    'Invalid envelope fields',
  )
  return {
    version: 1,
    chainId: chainId.slice(),
    opId: opId.slice(),
    author: author.slice(),
    epoch: Number(epoch),
    nonce: nonce.slice(),
    ciphertext: ciphertext.slice(),
  }
}

/** Envelope digest used for set reconciliation so decryptable rewraps sync past undecryptable old-epoch envelopes. */
export function encryptedEnvelopeDigest(env: EncryptedOperationEnvelope | Uint8Array): Uint8Array {
  const bytes = env instanceof Uint8Array ? env : encodeEncryptedEnvelope(env)
  return hashDomainSync('envelope', bytes)
}

export function envelopeAad(chainId: Uint8Array, opId: Uint8Array, author: Uint8Array): Uint8Array {
  return encodeCanonicalCbor([chainId, opId, author])
}

export function compareOperationOrder(left: OperationOrderKey, right: OperationOrderKey): number {
  if (left.authorTimestampMs !== right.authorTimestampMs) return left.authorTimestampMs < right.authorTimestampMs ? -1 : 1
  const authorCmp = compareBytes(left.author, right.author)
  if (authorCmp !== 0) return authorCmp
  return compareBytes(left.opId, right.opId)
}

export function assertHex32(value: string, label = 'hash'): string {
  protocolInvariant(typeof value === 'string' && HEX32.test(value), 'SCHEMA_INVALID', `Invalid ${label}`)
  return value
}

export const DEFAULT_RUNTIME_MANIFEST: RuntimeManifest = Object.freeze({
  js: 'quickjs-ng@0.32.0',
  builtins: Object.freeze({
    'chronolog:crypto': 'crypto@1',
    'chronolog:cas': 'cas@1',
    'chronolog:sqlite': 'sqlite-cas@1#sha256-bbc4674a5dd1d11962a8227ce5f1118e2e6ed7d00163ea92f1f35781caf46936',
  }),
})

export const DEFAULT_GENESIS_LIMITS: GenesisLimits = Object.freeze({
  maxMemoryBytes: 64 * 1024 * 1024,
  maxTopicStateBytes: 4 * 1024 * 1024,
  maxUpdatesPerOp: 16,
})

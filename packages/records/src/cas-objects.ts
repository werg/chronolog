import {
  assertCanonicalCbor,
  DEFAULT_DECODE_LIMITS,
  encodeCanonicalCbor,
  type CborMapKey,
  type CborValue,
} from '@chronolog/canonical'
import { computeCasHash, type CasPartition, type ContentAddressedStore } from './cas.js'

const HEX32 = /^[0-9a-f]{64}$/u
const CAS_REF_RE = /^cas:sha256-([0-9a-f]{64})$/u

export const CAS_BLOB_CHUNK_BYTES = 65_536
export const CAS_BLOB_FANOUT = 64

export type ChronologBuiltinName =
  | 'chronolog:crypto'
  | 'chronolog:cas'
  | 'chronolog:sqlite'
  | 'chronolog:wasm'

const ALLOWED_BUILTINS = new Set<string>([
  'chronolog:crypto',
  'chronolog:cas',
  'chronolog:sqlite',
  'chronolog:wasm',
])

export type ChronologPackageRuntime = 'esm-quickjs' | 'wasm-pure' | 'hybrid'

export interface ChronologPackageNode {
  readonly format: 'chronolog-pkg/v1'
  readonly name?: string
  readonly version?: string
  readonly runtime: ChronologPackageRuntime
  /** Normalized POSIX relative paths (e.g. "index.js", "lib/util.js") -> cas:sha256-<64-hex> */
  readonly files: Readonly<Record<string, string>>
  /** Subpath exports (e.g. "." -> "index.js", "./rls" -> "rls.js") */
  readonly exports: Readonly<Record<string, string>>
  /** Scoped bare dependencies -> cas:sha256-<64-hex> */
  readonly dependencies: Readonly<Record<string, string>>
  /** Capability allowlist for THIS package only */
  readonly builtins: readonly ChronologBuiltinName[]
  /** Optional WASM module entry (required when runtime === 'wasm-pure') */
  readonly wasm?: { readonly entry: string; readonly abi: 'chronolog-wasm/v1' }
  /** Optional provenance back-link to chronolog-drv/v1 (deliberately omitted from CasNode.links) */
  readonly derivation?: string
}

export type DerivationProfile = 'quickjs-inline' | 'wasi-cas-v1'

export interface ChronologDerivationNode {
  readonly format: 'chronolog-drv/v1'
  readonly profile: DerivationProfile
  /** Pinned deterministic builder package (cas:sha256-<64-hex>) */
  readonly builder: string
  /** Named input CAS roots (cas:sha256-<64-hex>) */
  readonly inputs: Readonly<Record<string, string>>
  /** Canonical deterministic JSON-compatible builder arguments */
  readonly args: Readonly<Record<string, unknown>>
  readonly limits: {
    readonly maxMemoryBytes: number
    readonly maxFuel: number
  }
}

export interface ChronologTreeNode {
  readonly format: 'chronolog-tree/v1'
  /** Sorted normalized POSIX paths -> cas:sha256-<64-hex> */
  readonly entries: Readonly<Record<string, string>>
}

export interface CasEncryptedBlobChunkRef {
  readonly hash: string
  readonly bytes: number
  readonly plainBytes: number
}

export interface CasEncryptedBlobManifest {
  readonly format: 'chronolog-enc-blob/v1'
  readonly applicationId: string
  readonly epoch: number
  readonly bytes: number
  readonly mediaType: string
  readonly stageId?: string
  readonly chunks: readonly CasEncryptedBlobChunkRef[]
}

export function casRef(hash: string): string {
  if (!HEX32.test(hash)) throw new Error(`CAS_HASH_INVALID:${hash}`)
  return `cas:sha256-${hash}`
}

export function parseCasRef(ref: string): string {
  const match = CAS_REF_RE.exec(ref)
  if (match === null) throw new Error(`CAS_REF_INVALID:${ref}`)
  return match[1]!
}

export function tryParseCasRef(ref: string): string | null {
  const match = CAS_REF_RE.exec(ref)
  return match === null ? null : match[1]!
}

export function normalizePosixPath(input: string): string {
  if (typeof input !== 'string' || input.length === 0 || input.length > 512) {
    throw new Error(`CAS_PATH_INVALID:${String(input)}`)
  }
  const normalized = input.replaceAll('\\', '/').replace(/^\.\//u, '')
  if (normalized.startsWith('/') || normalized.endsWith('/') || normalized.includes('\0')) {
    throw new Error(`CAS_PATH_INVALID:${input}`)
  }
  const parts = normalized.split('/')
  for (const part of parts) {
    if (part.length === 0 || part === '.' || part === '..') {
      throw new Error(`CAS_PATH_INVALID:${input}`)
    }
  }
  return parts.join('/')
}

/** Resolve a relative specifier (./foo.js, ../bar.js) against a POSIX file path inside a package. */
export function resolvePackageRelativePath(baseFilePath: string, relativeSpecifier: string): string {
  const baseParts = normalizePosixPath(baseFilePath).split('/')
  baseParts.pop()
  for (const seg of relativeSpecifier.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (baseParts.length === 0) throw new Error(`PACKAGE_PATH_ESCAPE:${baseFilePath}:${relativeSpecifier}`)
      baseParts.pop()
    } else {
      baseParts.push(seg)
    }
  }
  if (baseParts.length === 0) throw new Error(`PACKAGE_PATH_EMPTY:${baseFilePath}:${relativeSpecifier}`)
  return normalizePosixPath(baseParts.join('/'))
}

function unknownToCbor(value: unknown, depth = 0): CborValue {
  if (depth > 32) throw new Error('CAS_OBJECT_TOO_DEEP')
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('CAS_OBJECT_NON_FINITE_NUMBER')
    if (Number.isSafeInteger(value)) return BigInt(Object.is(value, -0) ? 0 : value)
    return new Map<CborMapKey, CborValue>([['$f', JSON.stringify(value)]])
  }
  if (value instanceof Uint8Array) return value
  if (Array.isArray(value)) return value.map(item => unknownToCbor(item, depth + 1))
  if (typeof value === 'object') {
    const rec = value as Record<string, unknown>
    const map = new Map<CborMapKey, CborValue>()
    for (const k of Object.keys(rec).sort()) {
      const v = rec[k]
      if (v !== undefined) map.set(k, unknownToCbor(v, depth + 1))
    }
    return map
  }
  throw new Error('CAS_OBJECT_UNSUPPORTED_VALUE')
}

function cborToUnknown(value: CborValue): unknown {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'bigint') {
    if (value < BigInt(Number.MIN_SAFE_INTEGER) || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('CAS_OBJECT_INTEGER_OUT_OF_RANGE')
    }
    return Number(value)
  }
  if (value instanceof Uint8Array) return value.slice()
  if (Array.isArray(value)) return value.map(cborToUnknown)
  if (value instanceof Map) {
    if (value.size === 1 && value.has('$f') && typeof value.get('$f') === 'string') {
      const n = Number(value.get('$f'))
      if (!Number.isFinite(n)) throw new Error('CAS_OBJECT_NON_FINITE_NUMBER')
      return n
    }
    const out: Record<string, unknown> = {}
    for (const [k, v] of value as ReadonlyMap<CborMapKey, CborValue>) {
      if (typeof k !== 'string') throw new Error('CAS_OBJECT_KEY_INVALID')
      out[k] = cborToUnknown(v)
    }
    return out
  }
  throw new Error('CAS_OBJECT_UNSUPPORTED_CBOR')
}

// ---------------------------------------------------------------------------
// chronolog-blob/v1 — Chunked Merkle-DAG file storage
// ---------------------------------------------------------------------------

interface BlobTreeNode {
  readonly format: 'chronolog-blob/v1'
  readonly bytes: number
  readonly children: readonly { readonly hash: string; readonly bytes: number }[]
}

function encodeBlobTreeNode(node: BlobTreeNode): { readonly bytes: Uint8Array; readonly links: readonly string[] } {
  const childArr: CborValue[] = node.children.map(c => [c.hash, BigInt(c.bytes)])
  const bytes = encodeCanonicalCbor(new Map<CborMapKey, CborValue>([
    ['bytes', BigInt(node.bytes)],
    ['children', childArr],
    ['format', 'chronolog-blob/v1'],
  ]))
  const links = [...new Set(node.children.map(c => c.hash))].sort()
  return { bytes, links }
}

function tryDecodeBlobTreeNode(rawBytes: Uint8Array, links: readonly string[]): BlobTreeNode | null {
  if (links.length === 0) return null
  try {
    const decoded = assertCanonicalCbor(rawBytes, DEFAULT_DECODE_LIMITS)
    if (!(decoded instanceof Map)) return null
    const map = decoded as ReadonlyMap<CborMapKey, CborValue>
    if (map.get('format') !== 'chronolog-blob/v1') return null
    const totalBytes = map.get('bytes')
    const rawChildren = map.get('children')
    if (typeof totalBytes !== 'bigint' || totalBytes < 0n || !Array.isArray(rawChildren) || rawChildren.length === 0) {
      return null
    }
    const children: { readonly hash: string; readonly bytes: number }[] = []
    for (const item of rawChildren) {
      if (!Array.isArray(item) || item.length !== 2 || typeof item[0] !== 'string' || typeof item[1] !== 'bigint') {
        return null
      }
      if (!HEX32.test(item[0]) || item[1] < 0n) return null
      children.push({ hash: item[0], bytes: Number(item[1]) })
    }
    return { format: 'chronolog-blob/v1', bytes: Number(totalBytes), children }
  } catch {
    return null
  }
}

/** Compute the exact chronolog-blob/v1 CAS root hash for bytes without writing to a store. */
export function computeBlobDagHash(bytes: Uint8Array): string {
  if (bytes.byteLength <= CAS_BLOB_CHUNK_BYTES) {
    return computeCasHash(bytes, [])
  }
  let level: { readonly hash: string; readonly bytes: number }[] = []
  for (let offset = 0; offset < bytes.byteLength; offset += CAS_BLOB_CHUNK_BYTES) {
    const slice = bytes.subarray(offset, Math.min(bytes.byteLength, offset + CAS_BLOB_CHUNK_BYTES))
    level.push({ hash: computeCasHash(slice, []), bytes: slice.byteLength })
  }
  while (level.length > 1) {
    const nextLevel: { readonly hash: string; readonly bytes: number }[] = []
    for (let i = 0; i < level.length; i += CAS_BLOB_FANOUT) {
      const group = level.slice(i, i + CAS_BLOB_FANOUT)
      const total = group.reduce((acc, item) => acc + item.bytes, 0)
      const encoded = encodeBlobTreeNode({ format: 'chronolog-blob/v1', bytes: total, children: group })
      nextLevel.push({ hash: computeCasHash(encoded.bytes, encoded.links), bytes: total })
    }
    level = nextLevel
  }
  return level[0]!.hash
}

/** Store arbitrary bytes into CAS as a leaf (<=64 KiB) or 64-way chunked chronolog-blob/v1 Merkle tree. */
export async function putBlobDag(
  cas: ContentAddressedStore,
  bytes: Uint8Array,
  partition: CasPartition = 'public',
): Promise<{ readonly hash: string; readonly bytes: number }> {
  if (bytes.byteLength <= CAS_BLOB_CHUNK_BYTES) {
    const hash = await cas.put(bytes, [], partition)
    return { hash, bytes: bytes.byteLength }
  }
  let level: { readonly hash: string; readonly bytes: number }[] = []
  for (let offset = 0; offset < bytes.byteLength; offset += CAS_BLOB_CHUNK_BYTES) {
    const slice = bytes.subarray(offset, Math.min(bytes.byteLength, offset + CAS_BLOB_CHUNK_BYTES))
    const hash = await cas.put(slice, [], partition)
    level.push({ hash, bytes: slice.byteLength })
  }
  while (level.length > 1) {
    const nextLevel: { readonly hash: string; readonly bytes: number }[] = []
    for (let i = 0; i < level.length; i += CAS_BLOB_FANOUT) {
      const group = level.slice(i, i + CAS_BLOB_FANOUT)
      const total = group.reduce((acc, item) => acc + item.bytes, 0)
      const encoded = encodeBlobTreeNode({ format: 'chronolog-blob/v1', bytes: total, children: group })
      const hash = await cas.put(encoded.bytes, encoded.links, partition)
      nextLevel.push({ hash, bytes: total })
    }
    level = nextLevel
  }
  return { hash: level[0]!.hash, bytes: bytes.byteLength }
}

/** Return the exact byte length of a leaf or chunked chronolog-blob/v1 root in O(1). */
export async function statBlobDag(
  cas: ContentAddressedStore,
  rootHash: string,
  partition: CasPartition | 'any' = 'any',
): Promise<{ readonly hash: string; readonly bytes: number; readonly chunked: boolean } | null> {
  const node = await cas.get(rootHash, partition)
  if (node === null) return null
  const tree = tryDecodeBlobTreeNode(node.bytes, node.links)
  if (tree !== null) return { hash: rootHash, bytes: tree.bytes, chunked: true }
  return { hash: rootHash, bytes: node.bytes.byteLength, chunked: false }
}

/** Read the full bytes of a leaf or chunked chronolog-blob/v1 DAG from CAS. */
export async function readBlobDag(
  cas: ContentAddressedStore,
  rootHash: string,
  partition: CasPartition | 'any' = 'any',
  options: { readonly maxBytes?: number } = {},
): Promise<Uint8Array | null> {
  const root = await cas.get(rootHash, partition)
  if (root === null) return null
  const tree = tryDecodeBlobTreeNode(root.bytes, root.links)
  if (tree === null) {
    if (options.maxBytes !== undefined && root.bytes.byteLength > options.maxBytes) {
      throw new Error('CAS_BLOB_READ_LIMIT_EXCEEDED')
    }
    return root.bytes
  }
  if (options.maxBytes !== undefined && tree.bytes > options.maxBytes) {
    throw new Error('CAS_BLOB_READ_LIMIT_EXCEEDED')
  }
  const out = new Uint8Array(tree.bytes)
  let offset = 0
  const walk = async (nodeHash: string): Promise<void> => {
    const node = await cas.get(nodeHash, partition)
    if (node === null) throw new Error(`CAS_BLOB_MISSING_NODE:${nodeHash}`)
    const sub = tryDecodeBlobTreeNode(node.bytes, node.links)
    if (sub === null) {
      if (offset + node.bytes.byteLength > out.byteLength) throw new Error('CAS_BLOB_SIZE_MISMATCH')
      out.set(node.bytes, offset)
      offset += node.bytes.byteLength
      return
    }
    for (const child of sub.children) {
      await walk(child.hash)
    }
  }
  for (const child of tree.children) {
    await walk(child.hash)
  }
  if (offset !== out.byteLength) throw new Error('CAS_BLOB_INCOMPLETE')
  return out
}

/** Stream chunks of a leaf or chunked chronolog-blob/v1 DAG from CAS. */
export async function* streamBlobDag(
  cas: ContentAddressedStore,
  rootHash: string,
  partition: CasPartition | 'any' = 'any',
): AsyncIterable<Uint8Array> {
  const root = await cas.get(rootHash, partition)
  if (root === null) throw new Error(`CAS_BLOB_MISSING_NODE:${rootHash}`)
  const tree = tryDecodeBlobTreeNode(root.bytes, root.links)
  if (tree === null) {
    if (root.bytes.byteLength > 0) yield root.bytes
    return
  }
  const stack: string[] = tree.children.map(c => c.hash).reverse()
  while (stack.length > 0) {
    const nextHash = stack.pop()!
    const node = await cas.get(nextHash, partition)
    if (node === null) throw new Error(`CAS_BLOB_MISSING_NODE:${nextHash}`)
    const sub = tryDecodeBlobTreeNode(node.bytes, node.links)
    if (sub === null) {
      if (node.bytes.byteLength > 0) yield node.bytes
    } else {
      for (let i = sub.children.length - 1; i >= 0; i--) stack.push(sub.children[i]!.hash)
    }
  }
}

export interface BlobDagLeaf { readonly hash: string; readonly bytes: number }
/** Interior structure of a chronolog-blob/v1 DAG: everything a peer needs to verify leaves one by one. */
export interface BlobDagIndex {
  readonly hash: string
  readonly bytes: number
  /** Interior tree-node payloads in breadth-first order (root first); empty for a single-leaf blob. */
  readonly nodes: readonly Uint8Array[]
  readonly leaves: readonly BlobDagLeaf[]
}

/** Read the interior nodes and ordered leaf list of a local blob DAG without touching leaf bytes. */
export async function blobDagIndex(
  cas: ContentAddressedStore,
  rootHash: string,
  partition: CasPartition | 'any' = 'any',
): Promise<BlobDagIndex | null> {
  const root = await cas.get(rootHash, partition)
  if (root === null) return null
  const tree = tryDecodeBlobTreeNode(root.bytes, root.links)
  if (tree === null) return { hash: rootHash, bytes: root.bytes.byteLength, nodes: [], leaves: [{ hash: rootHash, bytes: root.bytes.byteLength }] }
  const nodes: Uint8Array[] = [root.bytes], leaves: BlobDagLeaf[] = []
  let level: BlobTreeNode[] = [tree]
  for (let height = blobDagHeight(tree.bytes); height > 1; height--) {
    const next: BlobTreeNode[] = []
    for (const parent of level) {
      for (const child of parent.children) {
        const node = await cas.get(child.hash, partition)
        if (node === null) throw new Error(`CAS_BLOB_MISSING_NODE:${child.hash}`)
        const sub = tryDecodeBlobTreeNode(node.bytes, node.links)
        if (sub === null) throw new Error('CAS_BLOB_SHAPE_INVALID')
        nodes.push(node.bytes); next.push(sub)
      }
    }
    level = next
  }
  for (const parent of level) leaves.push(...parent.children)
  return { hash: rootHash, bytes: tree.bytes, nodes, leaves }
}

/** Number of tree levels above the leaves of the canonical chronolog-blob/v1 DAG for `bytes`. */
function blobDagHeight(bytes: number): number {
  let count = Math.ceil(bytes / CAS_BLOB_CHUNK_BYTES), height = 0
  while (count > 1) { count = Math.ceil(count / CAS_BLOB_FANOUT); height++ }
  return height
}

/**
 * Authenticate peer-supplied interior nodes against `rootHash` (each node hashed once) and return the
 * canonical leaf list, so each leaf can be verified by its own hash as it arrives. Rejects any shape
 * `putBlobDag` would not produce for `bytes`.
 */
export function verifyBlobDagIndex(
  rootHash: string,
  bytes: number,
  nodes: readonly Uint8Array[],
): { readonly leaves: readonly BlobDagLeaf[]; readonly interior: readonly { readonly hash: string; readonly bytes: Uint8Array; readonly links: readonly string[] }[] } {
  if (!HEX32.test(rootHash) || !Number.isSafeInteger(bytes) || bytes < 0) throw new Error('CAS_BLOB_INDEX_INVALID')
  const leafCount = Math.ceil(bytes / CAS_BLOB_CHUNK_BYTES)
  if (leafCount <= 1) {
    if (nodes.length !== 0) throw new Error('CAS_BLOB_INDEX_INVALID')
    return { leaves: [{ hash: rootHash, bytes }], interior: [] }
  }
  const interior: { hash: string; bytes: Uint8Array; links: readonly string[] }[] = []
  let cursor = 0, level: { readonly hash: string; readonly bytes: number }[] = [{ hash: rootHash, bytes }]
  for (let height = blobDagHeight(bytes); height > 0; height--) {
    const next: { readonly hash: string; readonly bytes: number }[] = []
    for (const expected of level) {
      const raw = nodes[cursor++]
      if (raw === undefined) throw new Error('CAS_BLOB_INDEX_INVALID')
      const links = [...new Set(blobTreeChildren(raw).map(child => child.hash))].sort()
      const tree = tryDecodeBlobTreeNode(raw, links)
      if (tree === null || tree.bytes !== expected.bytes || computeCasHash(raw, links) !== expected.hash) throw new Error('CAS_BLOB_INDEX_INVALID')
      if (tree.children.reduce((sum, child) => sum + child.bytes, 0) !== tree.bytes || tree.children.length > CAS_BLOB_FANOUT) throw new Error('CAS_BLOB_INDEX_INVALID')
      interior.push({ hash: expected.hash, bytes: raw, links })
      next.push(...tree.children)
    }
    level = next
  }
  if (cursor !== nodes.length || level.length !== leafCount) throw new Error('CAS_BLOB_INDEX_INVALID')
  for (let index = 0; index < leafCount; index++) {
    const expected = index === leafCount - 1 ? bytes - index * CAS_BLOB_CHUNK_BYTES : CAS_BLOB_CHUNK_BYTES
    if (level[index]!.bytes !== expected) throw new Error('CAS_BLOB_INDEX_INVALID')
  }
  return { leaves: level, interior }
}

function blobTreeChildren(raw: Uint8Array): readonly { readonly hash: string }[] {
  try {
    const decoded = assertCanonicalCbor(raw, DEFAULT_DECODE_LIMITS)
    const children = decoded instanceof Map ? (decoded as ReadonlyMap<CborMapKey, CborValue>).get('children') : undefined
    if (!Array.isArray(children)) return []
    return children.map(item => ({ hash: Array.isArray(item) && typeof item[0] === 'string' ? item[0] : '' }))
  } catch { return [] }
}

/** Synchronous full read of a leaf or chunked chronolog-blob/v1 (for QuickJS/WASM sync loading). */
export function readBlobDagSync(
  cas: ContentAddressedStore,
  rootHash: string,
  partition: CasPartition | 'any',
  onMissing: (hash: string) => never,
): Uint8Array {
  const root = cas.getSync(rootHash, partition)
  if (root === null) onMissing(rootHash)
  const tree = tryDecodeBlobTreeNode(root.bytes, root.links)
  if (tree === null) return root.bytes
  const out = new Uint8Array(tree.bytes)
  let offset = 0
  const stack: string[] = tree.children.map(c => c.hash).reverse()
  while (stack.length > 0) {
    const h = stack.pop()!
    const node = cas.getSync(h, partition)
    if (node === null) onMissing(h)
    const sub = tryDecodeBlobTreeNode(node.bytes, node.links)
    if (sub === null) {
      if (offset + node.bytes.byteLength > out.byteLength) throw new Error('CAS_BLOB_SIZE_MISMATCH')
      out.set(node.bytes, offset)
      offset += node.bytes.byteLength
    } else {
      for (let i = sub.children.length - 1; i >= 0; i--) stack.push(sub.children[i]!.hash)
    }
  }
  if (offset !== out.byteLength) throw new Error('CAS_BLOB_INCOMPLETE')
  return out
}

// ---------------------------------------------------------------------------
// chronolog-enc-blob/v1 — Epoch-encrypted chunked Merkle-DAG blob manifest
// ---------------------------------------------------------------------------

export function encodeEncBlobManifest(manifest: CasEncryptedBlobManifest): {
  readonly bytes: Uint8Array
  readonly links: readonly string[]
} {
  if (manifest.format !== 'chronolog-enc-blob/v1') throw new Error('ENC_BLOB_FORMAT_INVALID')
  if (!HEX32.test(manifest.applicationId)) throw new Error('ENC_BLOB_APP_ID_INVALID')
  if (!Number.isSafeInteger(manifest.epoch) || manifest.epoch < 0) throw new Error('ENC_BLOB_EPOCH_INVALID')
  if (!Number.isSafeInteger(manifest.bytes) || manifest.bytes < 0) throw new Error('ENC_BLOB_BYTES_INVALID')
  if (typeof manifest.mediaType !== 'string' || manifest.mediaType.length === 0 || manifest.mediaType.length > 256) {
    throw new Error('ENC_BLOB_MEDIA_TYPE_INVALID')
  }
  const chunkEntries: CborValue[] = []
  const linkSet = new Set<string>()
  for (const chunk of manifest.chunks) {
    if (!HEX32.test(chunk.hash) || !Number.isSafeInteger(chunk.bytes) || chunk.bytes <= 0 || !Number.isSafeInteger(chunk.plainBytes) || chunk.plainBytes <= 0) {
      throw new Error('ENC_BLOB_CHUNK_INVALID')
    }
    chunkEntries.push([chunk.hash, BigInt(chunk.bytes), BigInt(chunk.plainBytes)])
    linkSet.add(chunk.hash)
  }
  const map = new Map<CborMapKey, CborValue>([
    ['applicationId', manifest.applicationId],
    ['bytes', BigInt(manifest.bytes)],
    ['chunks', chunkEntries],
    ['epoch', BigInt(manifest.epoch)],
    ['format', 'chronolog-enc-blob/v1'],
    ['mediaType', manifest.mediaType],
  ])
  if (manifest.stageId !== undefined) map.set('stageId', manifest.stageId)
  return { bytes: encodeCanonicalCbor(map), links: [...linkSet].sort() }
}

export function decodeEncBlobManifest(rawBytes: Uint8Array): CasEncryptedBlobManifest {
  const decoded = assertCanonicalCbor(rawBytes, DEFAULT_DECODE_LIMITS)
  if (!(decoded instanceof Map)) throw new Error('ENC_BLOB_MANIFEST_INVALID')
  const map = decoded as ReadonlyMap<CborMapKey, CborValue>
  if (map.get('format') !== 'chronolog-enc-blob/v1') {
    throw new Error('ENC_BLOB_MANIFEST_INVALID')
  }
  const applicationId = map.get('applicationId')
  const epoch = map.get('epoch')
  const bytes = map.get('bytes')
  const mediaType = map.get('mediaType')
  const stageId = map.get('stageId')
  const rawChunks = map.get('chunks')
  if (
    typeof applicationId !== 'string' || !HEX32.test(applicationId) ||
    typeof epoch !== 'bigint' || epoch < 0n ||
    typeof bytes !== 'bigint' || bytes < 0n ||
    typeof mediaType !== 'string' || mediaType.length === 0 ||
    !Array.isArray(rawChunks)
  ) {
    throw new Error('ENC_BLOB_MANIFEST_INVALID')
  }
  const chunks: CasEncryptedBlobChunkRef[] = rawChunks.map(item => {
    if (!Array.isArray(item) || item.length !== 3 || typeof item[0] !== 'string' || typeof item[1] !== 'bigint' || typeof item[2] !== 'bigint') {
      throw new Error('ENC_BLOB_CHUNK_INVALID')
    }
    if (!HEX32.test(item[0]) || item[1] <= 0n || item[2] <= 0n) throw new Error('ENC_BLOB_CHUNK_INVALID')
    return { hash: item[0], bytes: Number(item[1]), plainBytes: Number(item[2]) }
  })
  return {
    format: 'chronolog-enc-blob/v1',
    applicationId,
    epoch: Number(epoch),
    bytes: Number(bytes),
    mediaType,
    ...(typeof stageId === 'string' ? { stageId } : {}),
    chunks,
  }
}

// ---------------------------------------------------------------------------
// chronolog-pkg/v1 — Executable Package Merkle-DAG
// ---------------------------------------------------------------------------

export function assertValidPackageNode(pkg: ChronologPackageNode): ChronologPackageNode {
  if (pkg.format !== 'chronolog-pkg/v1') throw new Error('PKG_FORMAT_INVALID')
  if (pkg.runtime !== 'esm-quickjs' && pkg.runtime !== 'wasm-pure' && pkg.runtime !== 'hybrid') {
    throw new Error(`PKG_RUNTIME_INVALID:${String(pkg.runtime)}`)
  }
  if (pkg.name !== undefined && (typeof pkg.name !== 'string' || pkg.name.length === 0 || pkg.name.length > 256)) {
    throw new Error('PKG_NAME_INVALID')
  }
  if (pkg.version !== undefined && (typeof pkg.version !== 'string' || pkg.version.length === 0 || pkg.version.length > 128)) {
    throw new Error('PKG_VERSION_INVALID')
  }
  const files: Record<string, string> = {}
  for (const [rawPath, ref] of Object.entries(pkg.files).sort(([a], [b]) => a.localeCompare(b))) {
    const path = normalizePosixPath(rawPath)
    files[path] = casRef(parseCasRef(ref))
  }
  if (Object.keys(files).length === 0) throw new Error('PKG_FILES_EMPTY')

  const exportsMap: Record<string, string> = {}
  for (const [subpath, target] of Object.entries(pkg.exports).sort(([a], [b]) => a.localeCompare(b))) {
    if (subpath !== '.' && !subpath.startsWith('./')) throw new Error(`PKG_EXPORT_SUBPATH_INVALID:${subpath}`)
    const normTarget = normalizePosixPath(target)
    if (!Object.hasOwn(files, normTarget)) throw new Error(`PKG_EXPORT_MISSING_FILE:${subpath}:${normTarget}`)
    exportsMap[subpath] = normTarget
  }
  if (pkg.runtime !== 'wasm-pure' && Object.keys(exportsMap).length === 0) {
    throw new Error('PKG_EXPORTS_EMPTY')
  }

  const dependencies: Record<string, string> = {}
  for (const [spec, ref] of Object.entries(pkg.dependencies).sort(([a], [b]) => a.localeCompare(b))) {
    if (typeof spec !== 'string' || spec.length === 0 || spec.length > 256 || spec.startsWith('.') || spec.startsWith('/')) {
      throw new Error(`PKG_DEPENDENCY_SPEC_INVALID:${spec}`)
    }
    dependencies[spec] = casRef(parseCasRef(ref))
  }

  const builtinsSet = new Set<ChronologBuiltinName>()
  for (const b of pkg.builtins) {
    if (!ALLOWED_BUILTINS.has(b)) throw new Error(`PKG_BUILTIN_INVALID:${String(b)}`)
    builtinsSet.add(b)
  }
  const builtins = [...builtinsSet].sort()

  let wasm: { readonly entry: string; readonly abi: 'chronolog-wasm/v1' } | undefined
  if (pkg.wasm !== undefined) {
    const entry = normalizePosixPath(pkg.wasm.entry)
    if (!Object.hasOwn(files, entry)) throw new Error(`PKG_WASM_ENTRY_MISSING:${entry}`)
    if (pkg.wasm.abi !== 'chronolog-wasm/v1') throw new Error(`PKG_WASM_ABI_INVALID:${String(pkg.wasm.abi)}`)
    wasm = { entry, abi: 'chronolog-wasm/v1' }
  } else if (pkg.runtime === 'wasm-pure') {
    throw new Error('PKG_WASM_ENTRY_REQUIRED')
  }

  const derivation = pkg.derivation === undefined ? undefined : casRef(parseCasRef(pkg.derivation))

  return {
    format: 'chronolog-pkg/v1',
    ...(pkg.name === undefined ? {} : { name: pkg.name }),
    ...(pkg.version === undefined ? {} : { version: pkg.version }),
    runtime: pkg.runtime,
    files,
    exports: exportsMap,
    dependencies,
    builtins,
    ...(wasm === undefined ? {} : { wasm }),
    ...(derivation === undefined ? {} : { derivation }),
  }
}

export function encodePackageNode(pkg: ChronologPackageNode): {
  readonly bytes: Uint8Array
  readonly links: readonly string[]
} {
  const clean = assertValidPackageNode(pkg)
  const linkSet = new Set<string>()
  const filesMap = new Map<CborMapKey, CborValue>()
  for (const [p, ref] of Object.entries(clean.files)) {
    filesMap.set(p, ref)
    linkSet.add(parseCasRef(ref))
  }
  const exportsMap = new Map<CborMapKey, CborValue>()
  for (const [k, v] of Object.entries(clean.exports)) exportsMap.set(k, v)
  const depsMap = new Map<CborMapKey, CborValue>()
  for (const [k, ref] of Object.entries(clean.dependencies)) {
    depsMap.set(k, ref)
    linkSet.add(parseCasRef(ref))
  }
  const map = new Map<CborMapKey, CborValue>([
    ['builtins', [...clean.builtins]],
    ['dependencies', depsMap],
    ['exports', exportsMap],
    ['files', filesMap],
    ['format', 'chronolog-pkg/v1'],
    ['runtime', clean.runtime],
  ])
  if (clean.name !== undefined) map.set('name', clean.name)
  if (clean.version !== undefined) map.set('version', clean.version)
  if (clean.wasm !== undefined) {
    map.set('wasm', new Map<CborMapKey, CborValue>([
      ['abi', clean.wasm.abi],
      ['entry', clean.wasm.entry],
    ]))
  }
  // Provenance back-link is stored in manifest bytes ONLY — deliberately omitted from CasNode.links
  // so execution replicas pulling a package DAG do not have to download source trees or compilers.
  if (clean.derivation !== undefined) map.set('derivation', clean.derivation)
  return { bytes: encodeCanonicalCbor(map), links: [...linkSet].sort() }
}

export function tryDecodePackageNode(rawBytes: Uint8Array): ChronologPackageNode | null {
  // Fast reject plain JS source text (CBOR maps have major type 5 => 0xa0..0xbf)
  if (rawBytes.byteLength === 0 || (rawBytes[0]! & 0xe0) !== 0xa0) return null
  try {
    const decoded = assertCanonicalCbor(rawBytes, DEFAULT_DECODE_LIMITS)
    if (!(decoded instanceof Map)) return null
    const map = decoded as ReadonlyMap<CborMapKey, CborValue>
    if (map.get('format') !== 'chronolog-pkg/v1') return null
    const runtime = map.get('runtime')
    const rawFiles = map.get('files')
    const rawExports = map.get('exports')
    const rawDeps = map.get('dependencies')
    const rawBuiltins = map.get('builtins')
    if (
      typeof runtime !== 'string' ||
      !(rawFiles instanceof Map) ||
      !(rawExports instanceof Map) ||
      !(rawDeps instanceof Map) ||
      !Array.isArray(rawBuiltins)
    ) {
      return null
    }
    const toStringRecord = (m: ReadonlyMap<CborMapKey, CborValue>): Record<string, string> => {
      const out: Record<string, string> = {}
      for (const [k, v] of m) {
        if (typeof k !== 'string' || typeof v !== 'string') throw new Error('PKG_MAP_INVALID')
        out[k] = v
      }
      return out
    }
    const builtins = rawBuiltins.map(item => {
      if (typeof item !== 'string') throw new Error('PKG_BUILTIN_INVALID')
      return item as ChronologBuiltinName
    })
    const name = map.get('name')
    const version = map.get('version')
    const derivation = map.get('derivation')
    const rawWasm = map.get('wasm')
    let wasm: { readonly entry: string; readonly abi: 'chronolog-wasm/v1' } | undefined
    if (rawWasm !== undefined) {
      if (!(rawWasm instanceof Map)) return null
      const wasmMap = rawWasm as ReadonlyMap<CborMapKey, CborValue>
      const entry = wasmMap.get('entry')
      const abi = wasmMap.get('abi')
      if (typeof entry !== 'string' || abi !== 'chronolog-wasm/v1') return null
      wasm = { entry, abi }
    }
    return assertValidPackageNode({
      format: 'chronolog-pkg/v1',
      ...(typeof name === 'string' ? { name } : {}),
      ...(typeof version === 'string' ? { version } : {}),
      runtime: runtime as ChronologPackageRuntime,
      files: toStringRecord(rawFiles as ReadonlyMap<CborMapKey, CborValue>),
      exports: toStringRecord(rawExports as ReadonlyMap<CborMapKey, CborValue>),
      dependencies: toStringRecord(rawDeps as ReadonlyMap<CborMapKey, CborValue>),
      builtins,
      ...(wasm === undefined ? {} : { wasm }),
      ...(typeof derivation === 'string' ? { derivation } : {}),
    })
  } catch {
    return null
  }
}

export function decodePackageNode(rawBytes: Uint8Array): ChronologPackageNode {
  const pkg = tryDecodePackageNode(rawBytes)
  if (pkg === null) throw new Error('PKG_NODE_INVALID')
  return pkg
}

export interface PutPackageInput {
  readonly name?: string
  readonly version?: string
  readonly runtime?: ChronologPackageRuntime
  /** POSIX path -> raw UTF-8 string or Uint8Array bytes */
  readonly files: Readonly<Record<string, string | Uint8Array>>
  readonly exports?: Readonly<Record<string, string>>
  readonly dependencies?: Readonly<Record<string, string>>
  readonly builtins?: readonly ChronologBuiltinName[]
  readonly wasm?: { readonly entry: string; readonly abi: 'chronolog-wasm/v1' }
  readonly derivation?: string
}

/** Store all package files (as chronolog-blob/v1) and its chronolog-pkg/v1 manifest into CAS. */
export async function putPackageDag(
  cas: ContentAddressedStore,
  input: PutPackageInput,
  partition: CasPartition = 'public',
): Promise<{ readonly hash: string; readonly ref: string; readonly manifest: ChronologPackageNode }> {
  const fileRefs: Record<string, string> = {}
  const enc = new TextEncoder()
  for (const [rawPath, content] of Object.entries(input.files).sort(([a], [b]) => a.localeCompare(b))) {
    const path = normalizePosixPath(rawPath)
    const bytes = typeof content === 'string' ? enc.encode(content) : content
    const stored = await putBlobDag(cas, bytes, partition)
    fileRefs[path] = casRef(stored.hash)
  }
  const runtime = input.runtime ?? (input.wasm !== undefined && Object.keys(fileRefs).length === 1 ? 'wasm-pure' : 'esm-quickjs')
  const firstFile = Object.keys(fileRefs).sort()[0]
  const exportsMap = input.exports ?? (runtime === 'wasm-pure' ? {} : (firstFile === undefined ? {} : { '.': firstFile }))
  const manifest = assertValidPackageNode({
    format: 'chronolog-pkg/v1',
    ...(input.name === undefined ? {} : { name: input.name }),
    ...(input.version === undefined ? {} : { version: input.version }),
    runtime,
    files: fileRefs,
    exports: exportsMap,
    dependencies: input.dependencies ?? {},
    builtins: input.builtins ?? [],
    ...(input.wasm === undefined ? {} : { wasm: input.wasm }),
    ...(input.derivation === undefined ? {} : { derivation: input.derivation }),
  })
  const encoded = encodePackageNode(manifest)
  const hash = await cas.put(encoded.bytes, encoded.links, partition)
  return { hash, ref: casRef(hash), manifest }
}

/** Compute the exact deterministic hash of a package manifest without storing it. */
export function computePackageHash(pkg: ChronologPackageNode): string {
  const encoded = encodePackageNode(pkg)
  return computeCasHash(encoded.bytes, encoded.links)
}

// ---------------------------------------------------------------------------
// chronolog-tree/v1 — Canonical sorted source/directory tree in CAS
// ---------------------------------------------------------------------------

export function encodeTreeNode(tree: ChronologTreeNode): {
  readonly bytes: Uint8Array
  readonly links: readonly string[]
} {
  if (tree.format !== 'chronolog-tree/v1') throw new Error('TREE_FORMAT_INVALID')
  const entriesMap = new Map<CborMapKey, CborValue>()
  const linkSet = new Set<string>()
  for (const [rawPath, ref] of Object.entries(tree.entries).sort(([a], [b]) => a.localeCompare(b))) {
    const path = normalizePosixPath(rawPath)
    const hash = parseCasRef(ref)
    entriesMap.set(path, casRef(hash))
    linkSet.add(hash)
  }
  const map = new Map<CborMapKey, CborValue>([
    ['entries', entriesMap],
    ['format', 'chronolog-tree/v1'],
  ])
  return { bytes: encodeCanonicalCbor(map), links: [...linkSet].sort() }
}

export function decodeTreeNode(rawBytes: Uint8Array): ChronologTreeNode {
  const decoded = assertCanonicalCbor(rawBytes, DEFAULT_DECODE_LIMITS)
  if (!(decoded instanceof Map)) throw new Error('TREE_NODE_INVALID')
  const map = decoded as ReadonlyMap<CborMapKey, CborValue>
  if (map.get('format') !== 'chronolog-tree/v1') {
    throw new Error('TREE_NODE_INVALID')
  }
  const rawEntries = map.get('entries')
  if (!(rawEntries instanceof Map)) throw new Error('TREE_NODE_INVALID')
  const entries: Record<string, string> = {}
  for (const [k, v] of rawEntries as ReadonlyMap<CborMapKey, CborValue>) {
    if (typeof k !== 'string' || typeof v !== 'string') throw new Error('TREE_ENTRY_INVALID')
    entries[normalizePosixPath(k)] = casRef(parseCasRef(v))
  }
  return { format: 'chronolog-tree/v1', entries }
}

export async function putTreeDag(
  cas: ContentAddressedStore,
  files: Readonly<Record<string, string | Uint8Array>>,
  partition: CasPartition = 'public',
): Promise<{ readonly hash: string; readonly ref: string; readonly tree: ChronologTreeNode }> {
  const entries: Record<string, string> = {}
  const enc = new TextEncoder()
  for (const [rawPath, content] of Object.entries(files).sort(([a], [b]) => a.localeCompare(b))) {
    const path = normalizePosixPath(rawPath)
    const bytes = typeof content === 'string' ? enc.encode(content) : content
    const stored = await putBlobDag(cas, bytes, partition)
    entries[path] = casRef(stored.hash)
  }
  const tree: ChronologTreeNode = { format: 'chronolog-tree/v1', entries }
  const encoded = encodeTreeNode(tree)
  const hash = await cas.put(encoded.bytes, encoded.links, partition)
  return { hash, ref: casRef(hash), tree }
}

// ---------------------------------------------------------------------------
// chronolog-drv/v1 — Content-Addressed Build Derivation
// ---------------------------------------------------------------------------

export function assertValidDerivationNode(drv: ChronologDerivationNode): ChronologDerivationNode {
  if (drv.format !== 'chronolog-drv/v1') throw new Error('DRV_FORMAT_INVALID')
  if (drv.profile !== 'quickjs-inline' && drv.profile !== 'wasi-cas-v1') {
    throw new Error(`DRV_PROFILE_INVALID:${String(drv.profile)}`)
  }
  const builder = casRef(parseCasRef(drv.builder))
  const inputs: Record<string, string> = {}
  for (const [k, ref] of Object.entries(drv.inputs).sort(([a], [b]) => a.localeCompare(b))) {
    if (typeof k !== 'string' || k.length === 0 || k.length > 256) throw new Error(`DRV_INPUT_KEY_INVALID:${k}`)
    inputs[k] = casRef(parseCasRef(ref))
  }
  if (drv.args === null || typeof drv.args !== 'object' || Array.isArray(drv.args)) {
    throw new Error('DRV_ARGS_INVALID')
  }
  if (
    !Number.isSafeInteger(drv.limits.maxMemoryBytes) || drv.limits.maxMemoryBytes <= 0 ||
    !Number.isSafeInteger(drv.limits.maxFuel) || drv.limits.maxFuel <= 0
  ) {
    throw new Error('DRV_LIMITS_INVALID')
  }
  return {
    format: 'chronolog-drv/v1',
    profile: drv.profile,
    builder,
    inputs,
    args: drv.args,
    limits: {
      maxMemoryBytes: drv.limits.maxMemoryBytes,
      maxFuel: drv.limits.maxFuel,
    },
  }
}

export function encodeDerivationNode(drv: ChronologDerivationNode): {
  readonly bytes: Uint8Array
  readonly links: readonly string[]
} {
  const clean = assertValidDerivationNode(drv)
  const linkSet = new Set<string>([parseCasRef(clean.builder)])
  const inputsMap = new Map<CborMapKey, CborValue>()
  for (const [k, ref] of Object.entries(clean.inputs)) {
    inputsMap.set(k, ref)
    linkSet.add(parseCasRef(ref))
  }
  const map = new Map<CborMapKey, CborValue>([
    ['args', unknownToCbor(clean.args)],
    ['builder', clean.builder],
    ['format', 'chronolog-drv/v1'],
    ['inputs', inputsMap],
    ['limits', new Map<CborMapKey, CborValue>([
      ['maxFuel', BigInt(clean.limits.maxFuel)],
      ['maxMemoryBytes', BigInt(clean.limits.maxMemoryBytes)],
    ])],
    ['profile', clean.profile],
  ])
  return { bytes: encodeCanonicalCbor(map), links: [...linkSet].sort() }
}

export function decodeDerivationNode(rawBytes: Uint8Array): ChronologDerivationNode {
  const decoded = assertCanonicalCbor(rawBytes, DEFAULT_DECODE_LIMITS)
  if (!(decoded instanceof Map)) throw new Error('DRV_NODE_INVALID')
  const map = decoded as ReadonlyMap<CborMapKey, CborValue>
  if (map.get('format') !== 'chronolog-drv/v1') {
    throw new Error('DRV_NODE_INVALID')
  }
  const profile = map.get('profile')
  const builder = map.get('builder')
  const rawInputs = map.get('inputs')
  const rawArgs = map.get('args')
  const rawLimits = map.get('limits')
  if (
    typeof profile !== 'string' ||
    typeof builder !== 'string' ||
    !(rawInputs instanceof Map) ||
    !(rawArgs instanceof Map) ||
    !(rawLimits instanceof Map)
  ) {
    throw new Error('DRV_NODE_INVALID')
  }
  const inputs: Record<string, string> = {}
  for (const [k, v] of rawInputs as ReadonlyMap<CborMapKey, CborValue>) {
    if (typeof k !== 'string' || typeof v !== 'string') throw new Error('DRV_INPUT_INVALID')
    inputs[k] = v
  }
  const args = cborToUnknown(rawArgs) as Record<string, unknown>
  const limitsMap = rawLimits as ReadonlyMap<CborMapKey, CborValue>
  const maxMemoryBytes = limitsMap.get('maxMemoryBytes')
  const maxFuel = limitsMap.get('maxFuel')
  if (typeof maxMemoryBytes !== 'bigint' || typeof maxFuel !== 'bigint') {
    throw new Error('DRV_LIMITS_INVALID')
  }
  return assertValidDerivationNode({
    format: 'chronolog-drv/v1',
    profile: profile as DerivationProfile,
    builder,
    inputs,
    args,
    limits: {
      maxMemoryBytes: Number(maxMemoryBytes),
      maxFuel: Number(maxFuel),
    },
  })
}

export async function putDerivationNode(
  cas: ContentAddressedStore,
  drv: ChronologDerivationNode,
  partition: CasPartition = 'public',
): Promise<{ readonly hash: string; readonly ref: string; readonly derivation: ChronologDerivationNode }> {
  const clean = assertValidDerivationNode(drv)
  const encoded = encodeDerivationNode(clean)
  const hash = await cas.put(encoded.bytes, encoded.links, partition)
  return { hash, ref: casRef(hash), derivation: clean }
}

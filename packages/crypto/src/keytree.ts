import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, canonicalJson, concatBytes, hexToBytes, protocolInvariant, utf8, type JsonValue } from '@chronolog/protocol'
import { epochKeyCommitment } from './epoch.js'
import { hpkeOpenBase, hpkeSealBase, importX25519PrivateKey } from './hpke.js'
import {
  KEY_BOX_SUITE_X25519,
  KEY_BOX_SUITE_XWING,
  xwingOpenBase,
  xwingPublicKeyFromSeed,
  xwingSealBase,
  type KeyBoxSuite,
} from './xwing.js'

export const KEY_TREE_SUITE_X25519 = 'hpke-tree-x25519-aes256gcm' as const
export const KEY_TREE_SUITE_XWING = 'hpke-tree-xwing-aes256gcm' as const
export type KeyTreeSuite = typeof KEY_TREE_SUITE_X25519 | typeof KEY_TREE_SUITE_XWING

/** RFC 8410 ASN.1 PKCS#8 prefix for a raw 32-byte X25519 private scalar. */
const X25519_PKCS8_PREFIX = Uint8Array.of(
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
)

const TREE_PARENT_INFO = utf8('chronolog/tree-parent/v1')
const TREE_EPOCH_KEY_PREFIX = utf8('chronolog/tree-epoch-key/v1:')
const CAS_REF_PREFIX = 'cas:sha256-'
const HEX32_RE = /^[0-9a-f]{64}$/u
const HEX_XWING_RE = /^[0-9a-f]{2432}$/u
const HEX_DATA_RE = /^[0-9a-f]+$/u
/** Maximum subtree height packed inline into a single CAS node (<= 7 nodes, < 24 KiB even for X-Wing). */
const MAX_INLINE_SUBTREE_HEIGHT = 2
/** Leaf-directory chunk width (slots per `chronolog-keytree-leaves/v1` CAS node). */
export const KEY_TREE_LEAF_CHUNK_SLOTS = 256
/** Largest supported tree (2^20 leaves). */
const MAX_LEAF_COUNT = 1 << 20

export const KEY_TREE_DAG_FORMAT = 'chronolog-keytree-dag/v1' as const
export const KEY_TREE_SUBTREE_FORMAT = 'chronolog-keytree-subtree/v1' as const
export const KEY_TREE_LEAVES_FORMAT = 'chronolog-keytree-leaves/v1' as const

export interface TreeMemberLeafInput {
  readonly publicKey: string
  readonly wrapKey?: string
  readonly pqWrapKey?: string
}

export interface KeyTreeNodePublic {
  /** Heap index (1 = root, 2i/2i+1 = children, leafCount + k = leaf k). */
  readonly index: number
  readonly suite: KeyBoxSuite
  /** Lowercase hex public key (64 hex for X25519, 2432 hex for X-Wing). */
  readonly pubKey: string
  /** SHA-256 hex digest of raw public key bytes (used for Key-Tagged box lookup under undo-do-redo). */
  readonly pubKeyHash: string
  /** Member identity publicKey hex; present exactly on leaf nodes. */
  readonly member?: string
}

export interface KeyTaggedBox {
  readonly targetNode: number
  readonly targetPubKeyHash: string
  /** Heap index of the direct-path node whose 32-byte seed is encrypted inside `box` (an ancestor of `targetNode`). */
  readonly pathNode: number
  readonly suite: KeyBoxSuite
  readonly encapsulatedKey: string
  readonly ciphertext: string
}

/**
 * In-memory view of one Key-Tagged TreeKEM epoch (never stored as-is; see `writeKeyTreeToCas`).
 * Enables O(log N) group key rotation under Chronolog's flat leaderless undo-do-redo order:
 * - Decoupled per-epoch root seeds (no linear transcript chain).
 * - Boxes tagged by `targetPubKeyHash` so out-of-order concurrent commits still decrypt cleanly.
 * - Deterministic X-Wing & X25519 internal node key derivation from 32-byte seeds.
 */
export interface KeyTreeEpochPayload {
  readonly format: 'chronolog-keytree/v1'
  readonly suite: KeyTreeSuite
  readonly epoch: number
  readonly leafCount: number
  /** Active non-blank nodes indexed by heap index string (`"1"`, `"2"`, ...). */
  readonly nodes: Readonly<Record<string, KeyTreeNodePublic>>
  /** Member publicKey -> leaf slot index (0..leafCount-1). */
  readonly memberLeaves: Readonly<Record<string, number>>
  /** O(log N) HPKE copath boxes (plus 1 updater self-box) encrypting direct-path node seeds. */
  readonly copathBoxes: readonly KeyTaggedBox[]
}

/**
 * Root CAS node (canonical JSON) of a Key-Tagged TreeKEM epoch. `leafChunkRefs` point to the
 * compact leaf directory (`chronolog-keytree-leaves/v1`) that `chronolog/keys` reads to derive the
 * epoch's member set without walking the full tree; `readKeyTreeFromCas` rejects any tree whose
 * leaf nodes disagree with that directory.
 */
export interface KeyTreeDagRootNode {
  readonly format: typeof KEY_TREE_DAG_FORMAT
  readonly suite: KeyTreeSuite
  readonly epoch: number
  readonly leafCount: number
  readonly treeRootRef: string
  readonly leafChunkRefs: readonly string[]
  readonly copathBoxes: readonly KeyTaggedBox[]
}

/** Internal or leaf-chunk CAS node (canonical JSON) in a structural-sharing Key-Tagged TreeKEM Merkle-DAG. */
export interface KeyTreeSubtreeNode {
  readonly format: typeof KEY_TREE_SUBTREE_FORMAT
  readonly rootIndex: number
  readonly node?: KeyTreeNodePublic
  readonly leftRef?: string
  readonly rightRef?: string
  readonly inlineNodes?: Readonly<Record<string, KeyTreeNodePublic>>
}

/** One leaf-directory CAS node: `[slot, member, leafPubKeyHash]` triples sorted by slot. */
export interface KeyTreeLeavesNode {
  readonly format: typeof KEY_TREE_LEAVES_FORMAT
  readonly leaves: readonly (readonly [number, string, string])[]
}

export function pubKeyHashHex(pubKeyHex: string): string {
  return bytesToHex(sha256(hexToBytes(pubKeyHex)))
}

export function deriveTreeNodePublicKey(seed32: Uint8Array, suite: KeyBoxSuite): { readonly pubKey: string; readonly pubKeyHash: string } {
  protocolInvariant(seed32.length === 32, 'INVALID_KEY', 'Tree node seed must be 32 bytes')
  const raw = suite === KEY_BOX_SUITE_XWING
    ? xwingPublicKeyFromSeed(seed32)
    : Uint8Array.from(x25519.getPublicKey(seed32))
  const pubKey = bytesToHex(raw)
  return { pubKey, pubKeyHash: bytesToHex(sha256(raw)) }
}

export function deriveParentSeed(childSeed32: Uint8Array): Uint8Array {
  protocolInvariant(childSeed32.length === 32, 'INVALID_KEY', 'Tree child seed must be 32 bytes')
  return Uint8Array.from(hkdf(sha256, childSeed32, new Uint8Array(0), TREE_PARENT_INFO, 32))
}

export function deriveTreeEpochKey(rootSeed32: Uint8Array, scope: string, epoch: number): Uint8Array {
  protocolInvariant(rootSeed32.length === 32, 'INVALID_KEY', 'Tree root seed must be 32 bytes')
  const info = concatBytes(TREE_EPOCH_KEY_PREFIX, utf8(`${scope}:${epoch}`))
  return Uint8Array.from(hkdf(sha256, rootSeed32, new Uint8Array(0), info, 32))
}

/** Box suite of every internal (non-leaf) node of a tree suite. */
export function keyTreeInternalSuite(suite: KeyTreeSuite): KeyBoxSuite {
  return suite === KEY_TREE_SUITE_XWING ? KEY_BOX_SUITE_XWING : KEY_BOX_SUITE_X25519
}

function compareHex(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function nextPowerOfTwo(n: number): number {
  let p = 2
  while (p < n) p *= 2
  return p
}

function isPowerOfTwoLeafCount(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 2 && n <= MAX_LEAF_COUNT && (n & (n - 1)) === 0
}

/** True when `ancestor` is a strict ancestor of heap index `node`. */
function isStrictAncestor(ancestor: number, node: number): boolean {
  let cur = Math.floor(node / 2)
  while (cur >= 1) {
    if (cur === ancestor) return true
    cur = Math.floor(cur / 2)
  }
  return false
}

/**
 * Select the leaf key for a member under a tree suite.
 * - X-Wing trees require every member to have a valid X-Wing `pqWrapKey` (members are rejected, never dropped).
 * - X25519 trees use the member's X25519 `wrapKey`, falling back to `pqWrapKey` for PQ-only devices.
 */
function selectMemberLeafKey(m: TreeMemberLeafInput, treeSuite: KeyTreeSuite): { readonly suite: KeyBoxSuite; readonly pubKey: string } {
  const pq = typeof m.pqWrapKey === 'string' && HEX_XWING_RE.test(m.pqWrapKey) ? m.pqWrapKey : null
  const x = typeof m.wrapKey === 'string' && HEX32_RE.test(m.wrapKey) ? m.wrapKey : null
  if (treeSuite === KEY_TREE_SUITE_XWING) {
    protocolInvariant(pq !== null, 'INVALID_KEY', `Member ${m.publicKey} lacks an X-Wing pqWrapKey required by ${KEY_TREE_SUITE_XWING}`)
    return { suite: KEY_BOX_SUITE_XWING, pubKey: pq }
  }
  if (x !== null) return { suite: KEY_BOX_SUITE_X25519, pubKey: x }
  protocolInvariant(pq !== null, 'INVALID_KEY', `Member ${m.publicKey} lacks a valid wrapKey or pqWrapKey`)
  return { suite: KEY_BOX_SUITE_XWING, pubKey: pq }
}

/** Collect the highest non-blank nodes covering the subtree rooted at `startIndex` (its resolution). */
function resolveSubtree(
  startIndex: number,
  maxNodeIndex: number,
  nodes: Readonly<Record<string, KeyTreeNodePublic>>,
  out: KeyTreeNodePublic[],
): void {
  if (startIndex > maxNodeIndex) return
  const existing = nodes[String(startIndex)]
  if (existing !== undefined) {
    out.push(existing)
    return
  }
  const left = startIndex * 2
  if (left <= maxNodeIndex) {
    resolveSubtree(left, maxNodeIndex, nodes, out)
    resolveSubtree(left + 1, maxNodeIndex, nodes, out)
  }
}

function boxInfo(scope: string, epoch: number, pathNode: number): Uint8Array {
  return utf8(`chronolog/keytree-box/v1:${scope}:${epoch}:${pathNode}`)
}

function boxAad(targetNode: number, targetPubKeyHash: string): Uint8Array {
  return utf8(`node:${targetNode}:${targetPubKeyHash}`)
}

async function sealToTreeNode(
  target: KeyTreeNodePublic,
  seed32: Uint8Array,
  scope: string,
  epoch: number,
  pathNode: number,
): Promise<KeyTaggedBox> {
  const info = boxInfo(scope, epoch, pathNode)
  const aad = boxAad(target.index, target.pubKeyHash)
  const sealed = target.suite === KEY_BOX_SUITE_XWING
    ? await xwingSealBase(hexToBytes(target.pubKey), seed32, info, aad)
    : await hpkeSealBase(hexToBytes(target.pubKey), seed32, info, aad)
  return {
    targetNode: target.index,
    targetPubKeyHash: target.pubKeyHash,
    pathNode,
    suite: target.suite,
    encapsulatedKey: bytesToHex(sealed.encapsulatedKey),
    ciphertext: bytesToHex(sealed.ciphertext),
  }
}

async function openFromSeed(seed32: Uint8Array, suite: KeyBoxSuite, box: KeyTaggedBox, scope: string, epoch: number): Promise<Uint8Array> {
  const info = boxInfo(scope, epoch, box.pathNode)
  const aad = boxAad(box.targetNode, box.targetPubKeyHash)
  if (suite === KEY_BOX_SUITE_XWING) {
    return xwingOpenBase(seed32, hexToBytes(box.encapsulatedKey), hexToBytes(box.ciphertext), info, aad)
  }
  const pubRaw = Uint8Array.from(x25519.getPublicKey(seed32))
  const privKey = await importX25519PrivateKey(concatBytes(X25519_PKCS8_PREFIX, seed32), false)
  return hpkeOpenBase(privKey, pubRaw, hexToBytes(box.encapsulatedKey), hexToBytes(box.ciphertext), info, aad)
}

function blankAncestors(nodes: Record<string, KeyTreeNodePublic>, heapIndex: number): void {
  let cur = Math.floor(heapIndex / 2)
  while (cur >= 1) {
    delete nodes[String(cur)]
    cur = Math.floor(cur / 2)
  }
}

/**
 * Build a Key-Tagged TreeKEM epoch update in O(log N) boxes when updating/removing from an
 * existing tree (or initializing a fresh tree over `activeMembers`).
 *
 * Every active member gets a leaf; a member whose keys do not fit the tree suite is rejected
 * (`INVALID_KEY`), never silently dropped. The updater regenerates the direct path of its own
 * leaf (or, when the updater holds no leaf, of the bytewise-smallest member's leaf) and seals each
 * new path seed to the copath resolution plus one self-box for that leaf.
 *
 * Returns the new 32-byte `epochKey`, the public `KeyTreeEpochPayload`,
 * and the newly derived internal node secrets (`derivedSeeds: pubKeyHash -> seed32`).
 */
export async function buildTreeEpochUpdate(options: {
  readonly scope: string
  readonly epoch: number
  readonly updaterPublicKey: string
  readonly activeMembers: readonly TreeMemberLeafInput[]
  readonly previousTree?: KeyTreeEpochPayload | null
  readonly suite?: KeyTreeSuite
  readonly updaterLeafSeed?: Uint8Array
}): Promise<{
  readonly epochKey: Uint8Array
  readonly payload: KeyTreeEpochPayload
  readonly derivedSeeds: ReadonlyMap<string, Uint8Array>
}> {
  protocolInvariant(Number.isSafeInteger(options.epoch) && options.epoch >= 0, 'INVALID_KEY', 'Tree epoch must be a non-negative safe integer')
  const allHavePq = options.activeMembers.length > 0 &&
    options.activeMembers.every(m => typeof m.pqWrapKey === 'string' && HEX_XWING_RE.test(m.pqWrapKey))
  const treeSuite: KeyTreeSuite = options.suite ?? (allHavePq ? KEY_TREE_SUITE_XWING : KEY_TREE_SUITE_X25519)
  protocolInvariant(treeSuite === KEY_TREE_SUITE_X25519 || treeSuite === KEY_TREE_SUITE_XWING, 'INVALID_KEY', 'Unknown key tree suite')
  const internalBoxSuite = keyTreeInternalSuite(treeSuite)

  const activeByPk = new Map<string, { readonly suite: KeyBoxSuite; readonly pubKey: string }>()
  for (const m of options.activeMembers) {
    protocolInvariant(typeof m.publicKey === 'string' && HEX32_RE.test(m.publicKey), 'INVALID_KEY', 'Tree member publicKey must be 32-byte hex')
    protocolInvariant(!activeByPk.has(m.publicKey), 'INVALID_KEY', `Duplicate tree member ${m.publicKey}`)
    activeByPk.set(m.publicKey, selectMemberLeafKey(m, treeSuite))
  }
  protocolInvariant(activeByPk.size > 0, 'INVALID_KEY', 'At least one active member with a wrap key is required')

  const prev = options.previousTree !== undefined && options.previousTree !== null && options.previousTree.suite === treeSuite
    ? options.previousTree
    : null
  const leafCount = nextPowerOfTwo(Math.max(activeByPk.size, prev?.leafCount ?? 0))
  protocolInvariant(leafCount <= MAX_LEAF_COUNT, 'INVALID_KEY', 'Tree leaf capacity exceeded')
  const maxNodeIndex = leafCount * 2 - 1
  const nodes: Record<string, KeyTreeNodePublic> = {}
  const memberLeaves: Record<string, number> = {}
  const usedSlots = new Set<number>()

  const setLeaf = (pk: string, slot: number, leaf: { readonly suite: KeyBoxSuite; readonly pubKey: string }): void => {
    nodes[String(leafCount + slot)] = {
      index: leafCount + slot,
      suite: leaf.suite,
      pubKey: leaf.pubKey,
      pubKeyHash: pubKeyHashHex(leaf.pubKey),
      member: pk,
    }
  }

  // Carry forward unchanged internal nodes and leaf slots when the previous tree has matching geometry.
  if (prev !== null && prev.leafCount === leafCount) {
    for (const [idxStr, node] of Object.entries(prev.nodes)) {
      if (node.index >= 1 && node.index < leafCount && node.suite === internalBoxSuite && String(node.index) === idxStr) {
        nodes[idxStr] = node
      }
    }
    const changedLeaves: number[] = []
    for (const [pk, slot] of Object.entries(prev.memberLeaves).sort((a, b) => a[1] - b[1])) {
      if (!Number.isSafeInteger(slot) || slot < 0 || slot >= leafCount || usedSlots.has(slot)) continue
      const m = activeByPk.get(pk)
      if (m === undefined) {
        changedLeaves.push(slot) // removed member: blank its whole direct path
        continue
      }
      memberLeaves[pk] = slot
      usedSlots.add(slot)
      const prevLeaf = prev.nodes[String(leafCount + slot)]
      setLeaf(pk, slot, m)
      // A rotated wrapKey / suite change invalidates every ancestor the old leaf key could open.
      if (prevLeaf === undefined || prevLeaf.member !== pk || prevLeaf.pubKey !== m.pubKey || prevLeaf.suite !== m.suite) {
        changedLeaves.push(slot)
      }
    }
    for (const slot of changedLeaves) blankAncestors(nodes, leafCount + slot)
  }

  // Assign slots for newly added members in bytewise publicKey order (deterministic across replicas).
  let nextSlot = 0
  const sortedActive = [...activeByPk.entries()].sort((a, b) => compareHex(a[0], b[0]))
  for (const [pk, m] of sortedActive) {
    if (memberLeaves[pk] !== undefined) continue
    while (nextSlot < leafCount && usedSlots.has(nextSlot)) nextSlot++
    protocolInvariant(nextSlot < leafCount, 'INVALID_KEY', 'Tree leaf capacity exceeded')
    usedSlots.add(nextSlot)
    memberLeaves[pk] = nextSlot
    setLeaf(pk, nextSlot, m)
    // Blank ancestors above a new slot so no stale internal key masks this leaf.
    blankAncestors(nodes, leafCount + nextSlot)
  }

  const updaterSlot = memberLeaves[options.updaterPublicKey] ?? memberLeaves[sortedActive[0]![0]]!
  const updaterLeafIndex = leafCount + updaterSlot
  const derivedSeeds = new Map<string, Uint8Array>()
  const copathBoxes: KeyTaggedBox[] = []

  // Walk the direct path from parent(leaf) to the root, deriving fresh seeds and sealing each to the copath resolution.
  if (options.updaterLeafSeed !== undefined) {
    protocolInvariant(options.updaterLeafSeed.length === 32, 'INVALID_KEY', 'updaterLeafSeed must be 32 bytes')
  }
  let currentSeed: Uint8Array = options.updaterLeafSeed
    ? options.updaterLeafSeed.slice()
    : globalThis.crypto.getRandomValues(new Uint8Array(32))
  let childIdx = updaterLeafIndex
  let parentIdx = Math.floor(childIdx / 2)
  const firstParentIdx = parentIdx
  let firstParentSeed: Uint8Array | null = null

  while (parentIdx >= 1) {
    currentSeed = deriveParentSeed(currentSeed)
    if (firstParentSeed === null) firstParentSeed = currentSeed.slice()
    const { pubKey, pubKeyHash } = deriveTreeNodePublicKey(currentSeed, internalBoxSuite)
    nodes[String(parentIdx)] = { index: parentIdx, suite: internalBoxSuite, pubKey, pubKeyHash }
    derivedSeeds.set(pubKeyHash, currentSeed.slice())

    const targets: KeyTreeNodePublic[] = []
    resolveSubtree(childIdx ^ 1, maxNodeIndex, nodes, targets)
    for (const target of targets) {
      copathBoxes.push(await sealToTreeNode(target, currentSeed, options.scope, options.epoch, parentIdx))
    }
    childIdx = parentIdx
    parentIdx = Math.floor(parentIdx / 2)
  }
  const rootSeed = currentSeed

  // One self-box sealing the first path seed to the path's own leaf, so the leaf owner (the updater,
  // or the chosen member when the updater holds no leaf) recovers the whole path statelessly.
  const pathLeaf = nodes[String(updaterLeafIndex)]!
  copathBoxes.push(await sealToTreeNode(pathLeaf, firstParentSeed!, options.scope, options.epoch, firstParentIdx))

  const epochKey = deriveTreeEpochKey(rootSeed, options.scope, options.epoch)
  return {
    epochKey,
    payload: {
      format: 'chronolog-keytree/v1',
      suite: treeSuite,
      epoch: options.epoch,
      leafCount,
      nodes,
      memberLeaves,
      copathBoxes,
    },
    derivedSeeds,
  }
}

function subtreeHeight(index: number, leafCount: number): number {
  const maxIndex = leafCount * 2 - 1
  let h = 0
  let cur = index
  while (cur * 2 <= maxIndex) {
    cur *= 2
    h++
  }
  return h
}

function collectSubtreeInline(
  index: number,
  maxNodeIndex: number,
  nodes: Readonly<Record<string, KeyTreeNodePublic>>,
  out: Record<string, KeyTreeNodePublic>,
): void {
  if (index > maxNodeIndex) return
  const n = nodes[String(index)]
  if (n !== undefined) out[String(index)] = n
  const left = index * 2
  if (left <= maxNodeIndex) {
    collectSubtreeInline(left, maxNodeIndex, nodes, out)
    collectSubtreeInline(left + 1, maxNodeIndex, nodes, out)
  }
}

function parseCasRefHash(ref: unknown): string | null {
  if (typeof ref !== 'string' || !ref.startsWith(CAS_REF_PREFIX)) return null
  const h = ref.slice(CAS_REF_PREFIX.length)
  return HEX32_RE.test(h) ? h : null
}

const JSON_LIMITS = { maxBytes: 64 * 1024, maxNodes: 8192, maxDepth: 8 } as const
const ROOT_JSON_LIMITS = { maxBytes: 256 * 1024, maxNodes: 32_768, maxDepth: 8 } as const

/**
 * Persist a `KeyTreeEpochPayload` into public CAS as a structural-sharing binary Merkle-DAG of
 * canonical-JSON nodes (canonical JSON so `chronolog/keys` can parse it natively inside QuickJS):
 * - Unchanged subtrees and leaf-directory chunks reuse existing CAS hashes (zero bytes rewritten).
 * - Every CAS node stays well below 64 KiB even for 100,000+ hybrid PQ X-Wing members.
 * - The root (`chronolog-keytree-dag/v1`) is O(log N + N/256) bytes with explicit CAS links to the
 *   tree root and every leaf-directory chunk.
 */
export async function writeKeyTreeToCas(
  payload: KeyTreeEpochPayload,
  putCas: (bytes: Uint8Array, links: readonly string[]) => Promise<string>,
): Promise<string> {
  const maxNodeIndex = payload.leafCount * 2 - 1

  const writeSubtree = async (index: number): Promise<string | null> => {
    const h = subtreeHeight(index, payload.leafCount)
    if (h <= MAX_INLINE_SUBTREE_HEIGHT) {
      const inlineNodes: Record<string, KeyTreeNodePublic> = {}
      collectSubtreeInline(index, maxNodeIndex, payload.nodes, inlineNodes)
      if (Object.keys(inlineNodes).length === 0) return null
      const chunk: KeyTreeSubtreeNode = { format: KEY_TREE_SUBTREE_FORMAT, rootIndex: index, inlineNodes }
      return putCas(utf8(canonicalJson(chunk as unknown as JsonValue, JSON_LIMITS)), [])
    }
    const leftHash = await writeSubtree(index * 2)
    const rightHash = await writeSubtree(index * 2 + 1)
    const selfNode = payload.nodes[String(index)]
    if (selfNode === undefined && leftHash === null && rightHash === null) return null
    const links: string[] = []
    if (leftHash !== null) links.push(leftHash)
    if (rightHash !== null) links.push(rightHash)
    const subtree: KeyTreeSubtreeNode = {
      format: KEY_TREE_SUBTREE_FORMAT,
      rootIndex: index,
      ...(selfNode === undefined ? {} : { node: selfNode }),
      ...(leftHash === null ? {} : { leftRef: `${CAS_REF_PREFIX}${leftHash}` }),
      ...(rightHash === null ? {} : { rightRef: `${CAS_REF_PREFIX}${rightHash}` }),
    }
    return putCas(utf8(canonicalJson(subtree as unknown as JsonValue, JSON_LIMITS)), links)
  }

  const treeRootHash = await writeSubtree(1)
  protocolInvariant(treeRootHash !== null, 'INVALID_KEY', 'Empty key tree cannot be written to CAS')

  const chunks = new Map<number, [number, string, string][]>()
  for (const [member, slot] of Object.entries(payload.memberLeaves)) {
    const leaf = payload.nodes[String(payload.leafCount + slot)]
    protocolInvariant(leaf !== undefined && leaf.member === member, 'INVALID_KEY', `Leaf node missing for member ${member}`)
    const chunkIndex = Math.floor(slot / KEY_TREE_LEAF_CHUNK_SLOTS)
    let list = chunks.get(chunkIndex)
    if (list === undefined) chunks.set(chunkIndex, list = [])
    list.push([slot, member, leaf.pubKeyHash])
  }
  const leafChunkHashes: string[] = []
  for (const chunkIndex of [...chunks.keys()].sort((a, b) => a - b)) {
    const leaves = chunks.get(chunkIndex)!.sort((a, b) => a[0] - b[0])
    const node: KeyTreeLeavesNode = { format: KEY_TREE_LEAVES_FORMAT, leaves }
    leafChunkHashes.push(await putCas(utf8(canonicalJson(node as unknown as JsonValue, JSON_LIMITS)), []))
  }

  const dagRoot: KeyTreeDagRootNode = {
    format: KEY_TREE_DAG_FORMAT,
    suite: payload.suite,
    epoch: payload.epoch,
    leafCount: payload.leafCount,
    treeRootRef: `${CAS_REF_PREFIX}${treeRootHash}`,
    leafChunkRefs: leafChunkHashes.map(h => `${CAS_REF_PREFIX}${h}`),
    copathBoxes: payload.copathBoxes,
  }
  return putCas(utf8(canonicalJson(dagRoot as unknown as JsonValue, ROOT_JSON_LIMITS)), [treeRootHash, ...leafChunkHashes])
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function parseJsonBytes(bytes: Uint8Array): unknown {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { return undefined }
}

function validBoxSuite(v: unknown): v is KeyBoxSuite {
  return v === KEY_BOX_SUITE_X25519 || v === KEY_BOX_SUITE_XWING
}

/** Structural + cryptographic validation of a published node (pubKeyHash must equal SHA-256(pubKey)). */
function validNode(n: unknown, leafCount: number): n is KeyTreeNodePublic {
  if (!isObject(n)) return false
  const { index, suite, pubKey, pubKeyHash, member } = n
  if (typeof index !== 'number' || !Number.isSafeInteger(index) || index < 1 || index >= leafCount * 2) return false
  if (!validBoxSuite(suite) || typeof pubKey !== 'string' || typeof pubKeyHash !== 'string' || !HEX32_RE.test(pubKeyHash)) return false
  if (suite === KEY_BOX_SUITE_XWING ? !HEX_XWING_RE.test(pubKey) : !HEX32_RE.test(pubKey)) return false
  const isLeaf = index >= leafCount
  if (isLeaf ? (typeof member !== 'string' || !HEX32_RE.test(member)) : member !== undefined) return false
  return pubKeyHashHex(pubKey) === pubKeyHash
}

function validBox(b: unknown, leafCount: number): b is KeyTaggedBox {
  if (!isObject(b)) return false
  const { targetNode, targetPubKeyHash, pathNode, suite, encapsulatedKey, ciphertext } = b
  return typeof targetNode === 'number' && Number.isSafeInteger(targetNode) && targetNode >= 1 && targetNode < leafCount * 2 &&
    typeof pathNode === 'number' && Number.isSafeInteger(pathNode) && pathNode >= 1 && pathNode < leafCount &&
    typeof targetPubKeyHash === 'string' && HEX32_RE.test(targetPubKeyHash) && validBoxSuite(suite) &&
    typeof encapsulatedKey === 'string' && HEX_DATA_RE.test(encapsulatedKey) &&
    typeof ciphertext === 'string' && HEX_DATA_RE.test(ciphertext)
}

/** True when heap index `index` lies inside the subtree rooted at `root`. */
function inSubtree(root: number, index: number): boolean {
  let cur = index
  while (cur > root) cur = Math.floor(cur / 2)
  return cur === root
}

/**
 * Reconstruct and validate a `KeyTreeEpochPayload` from a `chronolog-keytree-dag/v1` root in CAS.
 * Rejects (`corrupt: true`) malformed nodes, nodes outside their subtree, `pubKeyHash` values that
 * do not hash their `pubKey`, and any disagreement between leaf nodes and the leaf directory that
 * `chronolog/keys` derives the epoch's member set from. Reports exact missing CAS hashes otherwise.
 */
export async function readKeyTreeFromCas(
  rootHash: string,
  getCas: (hash: string) => Promise<Uint8Array | null>,
): Promise<
  | { readonly ok: true; readonly payload: KeyTreeEpochPayload }
  | { readonly ok: false; readonly missingHashes: readonly string[]; readonly corrupt?: true }
> {
  const corrupt = { ok: false, missingHashes: [], corrupt: true } as const
  const rootBytes = await getCas(rootHash)
  if (rootBytes === null) return { ok: false, missingHashes: [rootHash] }
  const parsed = parseJsonBytes(rootBytes)
  if (!isObject(parsed) || parsed.format !== KEY_TREE_DAG_FORMAT) return corrupt
  const { suite, epoch, leafCount } = parsed
  if (suite !== KEY_TREE_SUITE_X25519 && suite !== KEY_TREE_SUITE_XWING) return corrupt
  if (typeof epoch !== 'number' || !Number.isSafeInteger(epoch) || epoch < 0 || !isPowerOfTwoLeafCount(leafCount)) return corrupt
  const treeRootHash = parseCasRefHash(parsed.treeRootRef)
  if (treeRootHash === null || !Array.isArray(parsed.leafChunkRefs) || !Array.isArray(parsed.copathBoxes)) return corrupt
  const leafChunkHashes: string[] = []
  for (const ref of parsed.leafChunkRefs) {
    const h = parseCasRefHash(ref)
    if (h === null) return corrupt
    leafChunkHashes.push(h)
  }
  const copathBoxes: KeyTaggedBox[] = []
  for (const b of parsed.copathBoxes) {
    if (!validBox(b, leafCount)) return corrupt
    copathBoxes.push(b)
  }
  const internalSuite = keyTreeInternalSuite(suite)

  const nodes: Record<string, KeyTreeNodePublic> = {}
  const missingHashes: string[] = []
  const visited = new Set<string>()
  const addNode = (n: unknown, subtreeRoot: number): boolean => {
    if (!validNode(n, leafCount) || !inSubtree(subtreeRoot, n.index)) return false
    if (n.index < leafCount && n.suite !== internalSuite) return false
    if (nodes[String(n.index)] !== undefined) return false
    nodes[String(n.index)] = n
    return true
  }

  const walk = async (hash: string, expectedRoot: number): Promise<boolean> => {
    if (visited.has(hash)) return false // a tree never shares a subtree with itself
    visited.add(hash)
    const bytes = await getCas(hash)
    if (bytes === null) {
      missingHashes.push(hash)
      return true
    }
    const sub = parseJsonBytes(bytes)
    if (!isObject(sub) || sub.format !== KEY_TREE_SUBTREE_FORMAT || sub.rootIndex !== expectedRoot) return false
    if (sub.inlineNodes !== undefined) {
      if (!isObject(sub.inlineNodes) || sub.node !== undefined || sub.leftRef !== undefined || sub.rightRef !== undefined) return false
      if (subtreeHeight(expectedRoot, leafCount) > MAX_INLINE_SUBTREE_HEIGHT) return false
      for (const [k, v] of Object.entries(sub.inlineNodes)) {
        if (!addNode(v, expectedRoot) || String((v as KeyTreeNodePublic).index) !== k) return false
      }
      return true
    }
    if (subtreeHeight(expectedRoot, leafCount) <= MAX_INLINE_SUBTREE_HEIGHT) return false
    if (sub.node !== undefined && (!addNode(sub.node, expectedRoot) || (sub.node as KeyTreeNodePublic).index !== expectedRoot)) return false
    for (const [ref, child] of [[sub.leftRef, expectedRoot * 2], [sub.rightRef, expectedRoot * 2 + 1]] as const) {
      if (ref === undefined) continue
      const h = parseCasRefHash(ref)
      if (h === null || !(await walk(h, child))) return false
    }
    return true
  }

  if (!(await walk(treeRootHash, 1))) return corrupt

  // Leaf directory: exactly the leaf nodes, by slot, member, and leaf key hash.
  const directory = new Map<number, readonly [string, string]>()
  const directoryMembers = new Set<string>()
  for (const h of leafChunkHashes) {
    const bytes = await getCas(h)
    if (bytes === null) {
      missingHashes.push(h)
      continue
    }
    const chunk = parseJsonBytes(bytes)
    if (!isObject(chunk) || chunk.format !== KEY_TREE_LEAVES_FORMAT || !Array.isArray(chunk.leaves)) return corrupt
    for (const entry of chunk.leaves) {
      if (!Array.isArray(entry) || entry.length !== 3) return corrupt
      const [slot, member, hash] = entry as unknown[]
      if (typeof slot !== 'number' || !Number.isSafeInteger(slot) || slot < 0 || slot >= leafCount || directory.has(slot)) return corrupt
      if (typeof member !== 'string' || !HEX32_RE.test(member) || directoryMembers.has(member)) return corrupt
      if (typeof hash !== 'string' || !HEX32_RE.test(hash)) return corrupt
      directory.set(slot, [member, hash])
      directoryMembers.add(member)
    }
  }
  if (missingHashes.length > 0) return { ok: false, missingHashes }

  const memberLeaves: Record<string, number> = {}
  for (const node of Object.values(nodes)) {
    if (node.index < leafCount) continue
    const slot = node.index - leafCount
    const listed = directory.get(slot)
    if (listed === undefined || listed[0] !== node.member || listed[1] !== node.pubKeyHash) return corrupt
    memberLeaves[listed[0]] = slot
  }
  if (Object.keys(memberLeaves).length !== directory.size) return corrupt

  return {
    ok: true,
    payload: { format: 'chronolog-keytree/v1', suite, epoch, leafCount, nodes, memberLeaves, copathBoxes },
  }
}

/**
 * Unseal a Key-Tagged TreeKEM epoch in O(log N) using this device's own leaf wrap keys
 * AND/OR its rolling cache of previously derived internal node seeds (`cachedNodeSeeds`).
 *
 * Every candidate box addressed to a key this device holds is tried. A candidate is accepted only
 * when (1) its `pathNode` is an ancestor of its `targetNode`, (2) every seed derived from it up to
 * the root reproduces the published node `pubKeyHash` (all path nodes must be present), and (3) the
 * resulting epoch key matches `keyCommitment`. A junk box therefore cannot deny a member access.
 *
 * Returns `{ epochKey, derivedSeeds }` or `null` if no candidate verifies.
 */
export async function openTreeEpoch(options: {
  readonly scope: string
  readonly payload: KeyTreeEpochPayload
  /** `$keys` epoch `keyCommitment` (`epochKeyCommitment(epochKey)`). */
  readonly keyCommitment: string
  readonly wrapPrivateKey: CryptoKey
  readonly wrapPublicKeyHex: string
  readonly pqSecretKey?: Uint8Array
  readonly pqPublicKeyHex?: string
  readonly cachedNodeSeeds?: ReadonlyMap<string, Uint8Array>
}): Promise<{
  readonly epochKey: Uint8Array
  readonly derivedSeeds: ReadonlyMap<string, Uint8Array>
} | null> {
  const { payload, scope } = options
  if (payload.format !== 'chronolog-keytree/v1' || !isPowerOfTwoLeafCount(payload.leafCount)) return null
  const internalSuite = keyTreeInternalSuite(payload.suite)
  const wrapHash = pubKeyHashHex(options.wrapPublicKeyHex)
  const pqHash = options.pqPublicKeyHex !== undefined && options.pqSecretKey !== undefined ? pubKeyHashHex(options.pqPublicKeyHex) : null

  const openCandidate = async (box: KeyTaggedBox): Promise<Uint8Array | null> => {
    const info = boxInfo(scope, payload.epoch, box.pathNode)
    const aad = boxAad(box.targetNode, box.targetPubKeyHash)
    if (pqHash !== null && box.targetPubKeyHash === pqHash && box.suite === KEY_BOX_SUITE_XWING) {
      return xwingOpenBase(options.pqSecretKey!, hexToBytes(box.encapsulatedKey), hexToBytes(box.ciphertext), info, aad)
    }
    if (box.targetPubKeyHash === wrapHash && box.suite === KEY_BOX_SUITE_X25519) {
      return hpkeOpenBase(
        options.wrapPrivateKey,
        hexToBytes(options.wrapPublicKeyHex),
        hexToBytes(box.encapsulatedKey),
        hexToBytes(box.ciphertext),
        info,
        aad,
      )
    }
    const cachedSeed = options.cachedNodeSeeds?.get(box.targetPubKeyHash)
    if (cachedSeed !== undefined && box.suite === internalSuite && box.targetNode < payload.leafCount) {
      return openFromSeed(cachedSeed, internalSuite, box, scope, payload.epoch)
    }
    return null
  }

  for (const box of payload.copathBoxes) {
    if (!isStrictAncestor(box.pathNode, box.targetNode)) continue
    let seed: Uint8Array | null
    try {
      seed = await openCandidate(box)
    } catch {
      seed = null
    }
    if (seed === null || seed.length !== 32) continue

    // Derive upward from box.pathNode to the root, requiring every published path node to match.
    const derivedSeeds = new Map<string, Uint8Array>()
    let curIdx = box.pathNode
    let curSeed = seed
    let pathValid = true
    for (;;) {
      const published = payload.nodes[String(curIdx)]
      const { pubKeyHash } = deriveTreeNodePublicKey(curSeed, internalSuite)
      if (published === undefined || published.suite !== internalSuite || published.pubKeyHash !== pubKeyHash) {
        pathValid = false
        break
      }
      derivedSeeds.set(pubKeyHash, curSeed.slice())
      if (curIdx === 1) break
      curSeed = deriveParentSeed(curSeed)
      curIdx = Math.floor(curIdx / 2)
    }
    if (!pathValid) continue
    const epochKey = deriveTreeEpochKey(curSeed, scope, payload.epoch)
    if (epochKeyCommitment(epochKey) !== options.keyCommitment) continue
    return { epochKey, derivedSeeds }
  }
  return null
}

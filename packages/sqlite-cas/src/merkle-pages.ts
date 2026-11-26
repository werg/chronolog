import { bytesToHex, decodeUtf8, hexToBytes, utf8 } from '@chronolog/canonical'
import type { CasPartition, ContentAddressedStore } from '@chronolog/records'

export const MERKLE_PAGE_SIZE = 4096
export const MERKLE_FANOUT = 64
const HASH_BYTES = 32
const ZERO_HASH = '0'.repeat(64)

interface RootManifest {
  readonly v: 1
  readonly pageSize: 4096
  readonly byteLength: number
  readonly depth: number
  readonly treeRoot: string | null
}

function requiredDepth(pageCount: number): number {
  if (pageCount <= 1) return 0
  let cap = 1
  let depth = 0
  while (cap < pageCount) { cap *= MERKLE_FANOUT; depth++ }
  return depth
}

/**
 * Pure Merkle-paged virtual file backed by ContentAddressedStore.
 * - 4 KiB pages organized in a 64-way Merkle tree (depth 3 covers 1 GiB)
 * - Every interior node stores explicit child links in CAS so cas.reachable([dbRoot]) covers the full DB
 * - Unchanged pages stay untouched; commit() writes only dirty pages + O(log N) interior nodes
 */
export class MerklePageFile {
  readonly #cas: ContentAddressedStore
  readonly #readPartition: CasPartition | 'any'
  readonly #writePartition: CasPartition
  readonly #onMissingCas: (hash: string) => never
  #baseRoot: string | null
  #baseTreeRoot: string | null = null
  #baseDepth = 0
  #baseByteLength = 0
  #byteLength = 0
  #dirtyPages = new Map<number, Uint8Array>()
  #cleanPageCache = new Map<number, Uint8Array>()
  #mutated = false

  constructor(options: {
    readonly dbRoot: string | null
    readonly cas: ContentAddressedStore
    readonly partition: CasPartition
    readonly onMissingCas: (hash: string) => never
  }) {
    this.#cas = options.cas
    this.#readPartition = options.partition === 'public' ? 'public' : 'any'
    this.#writePartition = options.partition
    this.#onMissingCas = options.onMissingCas
    this.#baseRoot = options.dbRoot

    if (options.dbRoot !== null) {
      const node = this.#getNode(options.dbRoot)
      const manifest = JSON.parse(decodeUtf8(node.bytes)) as RootManifest
      if (manifest.v !== 1 || manifest.pageSize !== MERKLE_PAGE_SIZE) {
        throw new Error('SQLITE_CAS_MANIFEST_INVALID')
      }
      this.#baseTreeRoot = manifest.treeRoot
      this.#baseDepth = manifest.depth
      this.#baseByteLength = manifest.byteLength
      this.#byteLength = manifest.byteLength
    }
  }

  get byteLength(): number {
    return this.#byteLength
  }

  #getNode(hash: string): { readonly bytes: Uint8Array; readonly links: readonly string[] } {
    const node = this.#cas.getSync(hash, this.#readPartition)
    if (node === null) this.#onMissingCas(hash)
    return node
  }

  #readCleanPage(pageIndex: number): Uint8Array {
    const cached = this.#cleanPageCache.get(pageIndex)
    if (cached !== undefined) return cached
    const basePages = Math.ceil(this.#baseByteLength / MERKLE_PAGE_SIZE)
    if (this.#baseTreeRoot === null || pageIndex >= basePages) {
      return new Uint8Array(MERKLE_PAGE_SIZE)
    }
    let currentHash: string | null = this.#baseTreeRoot
    let depth = this.#baseDepth
    while (depth > 0 && currentHash !== null) {
      const stride = MERKLE_FANOUT ** (depth - 1)
      const slot = Math.floor(pageIndex / stride) % MERKLE_FANOUT
      const node = this.#getNode(currentHash)
      const slice = node.bytes.subarray(slot * HASH_BYTES, (slot + 1) * HASH_BYTES)
      const hex = bytesToHex(slice)
      currentHash = hex === ZERO_HASH ? null : hex
      depth--
    }
    const page = currentHash === null ? new Uint8Array(MERKLE_PAGE_SIZE) : this.#getNode(currentHash).bytes
    this.#cleanPageCache.set(pageIndex, page)
    return page
  }

  #getPage(pageIndex: number): Uint8Array {
    return this.#dirtyPages.get(pageIndex) ?? this.#readCleanPage(pageIndex)
  }

  readInto(offset: number, dest: Uint8Array): boolean {
    const amt = dest.length
    if (offset >= this.#byteLength) {
      dest.fill(0)
      return false
    }
    let copied = 0
    while (copied < amt) {
      const pos = offset + copied
      if (pos >= this.#byteLength) {
        dest.fill(0, copied)
        return false
      }
      const pageIndex = Math.floor(pos / MERKLE_PAGE_SIZE)
      const pageOffset = pos % MERKLE_PAGE_SIZE
      const availInFile = this.#byteLength - pos
      const chunk = Math.min(amt - copied, MERKLE_PAGE_SIZE - pageOffset, availInFile)
      const page = this.#getPage(pageIndex)
      dest.set(page.subarray(pageOffset, pageOffset + chunk), copied)
      copied += chunk
    }
    return true
  }

  writeFrom(offset: number, src: Uint8Array): void {
    this.#mutated = true
    let written = 0
    while (written < src.length) {
      const pos = offset + written
      const pageIndex = Math.floor(pos / MERKLE_PAGE_SIZE)
      const pageOffset = pos % MERKLE_PAGE_SIZE
      const chunk = Math.min(src.length - written, MERKLE_PAGE_SIZE - pageOffset)
      let page = this.#dirtyPages.get(pageIndex)
      if (page === undefined) {
        page = new Uint8Array(MERKLE_PAGE_SIZE)
        if (chunk < MERKLE_PAGE_SIZE) page.set(this.#readCleanPage(pageIndex))
        this.#dirtyPages.set(pageIndex, page)
      }
      page.set(src.subarray(written, written + chunk), pageOffset)
      written += chunk
    }
    if (offset + src.length > this.#byteLength) {
      this.#byteLength = offset + src.length
    }
  }

  truncate(newSize: number): void {
    this.#mutated = true
    const oldPages = Math.ceil(this.#byteLength / MERKLE_PAGE_SIZE)
    const newPages = Math.ceil(newSize / MERKLE_PAGE_SIZE)
    this.#byteLength = newSize
    for (const p of [...this.#dirtyPages.keys()]) {
      if (p >= newPages) this.#dirtyPages.delete(p)
    }
    if (newPages < oldPages) {
      // Mark truncated tail range dirty as null so tree clears those leaves
      for (let p = newPages; p < oldPages; p++) {
        this.#dirtyPages.set(p, new Uint8Array(0))
      }
    }
  }

  /** Commit all dirty pages into CAS and return the new 32-byte dbRoot hash. */
  commit(): string {
    if (!this.#mutated && this.#baseRoot !== null) return this.#baseRoot

    const pageCount = Math.ceil(this.#byteLength / MERKLE_PAGE_SIZE)
    if (pageCount === 0) {
      const manifest: RootManifest = { v: 1, pageSize: MERKLE_PAGE_SIZE, byteLength: 0, depth: 0, treeRoot: null }
      const root = this.#cas.putSync(utf8(JSON.stringify(manifest)), [], this.#writePartition)
      this.#baseRoot = root
      this.#baseTreeRoot = null
      this.#baseDepth = 0
      this.#baseByteLength = 0
      this.#dirtyPages.clear()
      this.#cleanPageCache.clear()
      this.#mutated = false
      return root
    }

    const targetDepth = requiredDepth(pageCount)
    // Lift existing tree root if depth grew
    let startTreeRoot = this.#baseTreeRoot
    let curDepth = this.#baseDepth
    while (curDepth < targetDepth && startTreeRoot !== null) {
      const buf = new Uint8Array(MERKLE_FANOUT * HASH_BYTES)
      buf.set(hexToBytes(startTreeRoot), 0)
      startTreeRoot = this.#cas.putSync(buf, [startTreeRoot], this.#writePartition)
      curDepth++
    }
    // Descend if tree shrank via truncate
    while (curDepth > targetDepth && startTreeRoot !== null) {
      const node = this.#getNode(startTreeRoot)
      const first = bytesToHex(node.bytes.subarray(0, HASH_BYTES))
      startTreeRoot = first === ZERO_HASH ? null : first
      curDepth--
    }

    // Build leaf hash map for dirty pages
    const dirtyLeaves = new Map<number, string | null>()
    for (const [pageIdx, pageBytes] of this.#dirtyPages) {
      if (pageIdx >= pageCount || pageBytes.length === 0) {
        dirtyLeaves.set(pageIdx, null)
      } else {
        dirtyLeaves.set(pageIdx, this.#cas.putSync(pageBytes, [], this.#writePartition))
      }
    }

    const updateSubtree = (
      existingHash: string | null,
      depth: number,
      baseIndex: number,
      updates: Map<number, string | null>,
    ): string | null => {
      if (updates.size === 0) return existingHash
      if (depth === 0) {
        return updates.get(baseIndex) ?? existingHash
      }
      const stride = MERKLE_FANOUT ** (depth - 1)
      const bySlot = new Map<number, Map<number, string | null>>()
      for (const [idx, val] of updates) {
        const slot = Math.floor((idx - baseIndex) / stride)
        let sub = bySlot.get(slot)
        if (sub === undefined) { sub = new Map(); bySlot.set(slot, sub) }
        sub.set(idx, val)
      }

      const buf = existingHash === null
        ? new Uint8Array(MERKLE_FANOUT * HASH_BYTES)
        : this.#getNode(existingHash).bytes.slice()

      for (const [slot, subUpdates] of bySlot) {
        const childSlice = buf.subarray(slot * HASH_BYTES, (slot + 1) * HASH_BYTES)
        const childHex = bytesToHex(childSlice)
        const existingChild = childHex === ZERO_HASH ? null : childHex
        const nextChild = updateSubtree(existingChild, depth - 1, baseIndex + slot * stride, subUpdates)
        if (nextChild === null) childSlice.fill(0)
        else childSlice.set(hexToBytes(nextChild))
      }

      const links: string[] = []
      for (let slot = 0; slot < MERKLE_FANOUT; slot++) {
        const hex = bytesToHex(buf.subarray(slot * HASH_BYTES, (slot + 1) * HASH_BYTES))
        if (hex !== ZERO_HASH) links.push(hex)
      }
      if (links.length === 0) return null
      return this.#cas.putSync(buf, links, this.#writePartition)
    }

    const nextTreeRoot = updateSubtree(startTreeRoot, targetDepth, 0, dirtyLeaves)
    const manifest: RootManifest = {
      v: 1,
      pageSize: MERKLE_PAGE_SIZE,
      byteLength: this.#byteLength,
      depth: targetDepth,
      treeRoot: nextTreeRoot,
    }
    const nextRoot = this.#cas.putSync(
      utf8(JSON.stringify(manifest)),
      nextTreeRoot === null ? [] : [nextTreeRoot],
      this.#writePartition,
    )

    this.#baseRoot = nextRoot
    this.#baseTreeRoot = nextTreeRoot
    this.#baseDepth = targetDepth
    this.#baseByteLength = this.#byteLength
    this.#dirtyPages.clear()
    this.#cleanPageCache.clear()
    this.#mutated = false
    return nextRoot
  }
}

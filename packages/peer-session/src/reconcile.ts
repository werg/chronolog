/**
 * Range-fingerprint set reconciliation over 32-byte fact identifiers (Chronolog sync v3).
 *
 * Ids are kept sorted as lowercase hex, so a hex prefix names a contiguous range. A range is
 * summarized by `(count, fingerprint)` where the fingerprint is the XOR of the first 16 bytes of
 * every id in the range. Peers compare summaries top-down: equal ranges stop immediately, small
 * ranges are exchanged as explicit id lists, and large differing ranges split into 16 children.
 *
 * Cost: identical sets settle in one message each way; d differences in N ids cost
 * O(d · log16(N)) summaries. Fingerprints are not authenticated (a dishonest peer can only hide
 * facts it could equally withhold), and every fact is still verified on arrival.
 */

const HEX = /^[0-9a-f]{64}$/u

/** Ranges at or below this size are exchanged as explicit id lists instead of being split. */
export const RECONCILE_LIST_THRESHOLD = 32
/** Deepest prefix (in hex nibbles) a peer may ask about; bounds recursion on adversarial input. */
export const RECONCILE_MAX_PREFIX = 16

export interface RangeSummary {
  readonly prefix: string
  readonly count: number
  /** 16-byte XOR fingerprint. */
  readonly fp: Uint8Array
}

function words(hex: string): [number, number, number, number] {
  return [
    Number.parseInt(hex.slice(0, 8), 16) >>> 0,
    Number.parseInt(hex.slice(8, 16), 16) >>> 0,
    Number.parseInt(hex.slice(16, 24), 16) >>> 0,
    Number.parseInt(hex.slice(24, 32), 16) >>> 0,
  ]
}

function lowerBound(ids: readonly string[], target: string): number {
  let lo = 0, hi = ids.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (ids[mid]! < target) lo = mid + 1
    else hi = mid
  }
  return lo
}

/**
 * Unique set of 32-byte ids. Membership is a hash lookup; the sorted index (and its packed
 * fingerprint words) is rebuilt lazily on the first range query after a change, so bulk loads and
 * live appends stay O(1) and reconciliation rounds pay one O(N log N) sort at most.
 */
export class FactIdSet {
  readonly #set = new Set<string>()
  #sorted: string[] | null = []
  #words = new Uint32Array(0)

  get size(): number { return this.#set.size }

  has(id: string): boolean { return this.#set.has(id) }

  add(id: string): boolean {
    if (this.#set.has(id)) return false
    if (!HEX.test(id)) throw new Error('FACT_ID_INVALID')
    this.#set.add(id); this.#sorted = null
    return true
  }

  delete(id: string): boolean {
    if (!this.#set.delete(id)) return false
    this.#sorted = null
    return true
  }

  clear(): void { this.#set.clear(); this.#sorted = [] ; this.#words = new Uint32Array(0) }

  #index(): string[] {
    if (this.#sorted === null) {
      const sorted = [...this.#set].sort()
      const packed = new Uint32Array(sorted.length * 4)
      for (let i = 0; i < sorted.length; i++) packed.set(words(sorted[i]!), i * 4)
      this.#sorted = sorted; this.#words = packed
    }
    return this.#sorted
  }

  #range(prefix: string): readonly [number, number] {
    const ids = this.#index()
    if (prefix === '') return [0, ids.length]
    return [lowerBound(ids, prefix), lowerBound(ids, `${prefix}g`)]
  }

  ids(prefix = ''): string[] {
    const [start, end] = this.#range(prefix)
    return this.#index().slice(start, end)
  }

  count(prefix = ''): number {
    const [start, end] = this.#range(prefix)
    return end - start
  }

  summary(prefix = ''): RangeSummary {
    const [start, end] = this.#range(prefix)
    const w = this.#words
    let a = 0, b = 0, c = 0, d = 0
    for (let i = start; i < end; i++) {
      a ^= w[i * 4]!; b ^= w[i * 4 + 1]!; c ^= w[i * 4 + 2]!; d ^= w[i * 4 + 3]!
    }
    const fp = new Uint8Array(16), view = new DataView(fp.buffer)
    view.setUint32(0, a >>> 0); view.setUint32(4, b >>> 0); view.setUint32(8, c >>> 0); view.setUint32(12, d >>> 0)
    return { prefix, count: end - start, fp }
  }
}

function sameFingerprint(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

/** One range in a reconciliation message: either a summary to compare or an explicit id list. */
export type ReconcileRange =
  | { readonly prefix: string; readonly count: number; readonly fp: Uint8Array }
  | { readonly prefix: string; readonly ids: readonly string[] }

export interface ReconcileStep {
  /** Ranges to send back (summaries need a reply; id lists do not). */
  readonly reply: readonly ReconcileRange[]
  /** Ids the peer lacks that we hold: push these facts. */
  readonly push: readonly string[]
  /** Ids the peer holds that we lack: request these facts. */
  readonly want: readonly string[]
}

const CHILDREN = '0123456789abcdef'

/**
 * Process one batch of peer ranges against the local set. Pure: callers move facts and replies.
 * `peerHas` collects ids the peer revealed holding (used to avoid echoing those facts).
 */
export function reconcileRanges(local: FactIdSet, ranges: readonly ReconcileRange[]): ReconcileStep {
  const reply: ReconcileRange[] = [], push: string[] = [], want: string[] = []
  for (const range of ranges) {
    if (typeof range.prefix !== 'string' || range.prefix.length > RECONCILE_MAX_PREFIX || !/^[0-9a-f]*$/u.test(range.prefix)) {
      throw new Error('RECONCILE_RANGE_INVALID')
    }
    if ('ids' in range) {
      const theirs = new Set<string>()
      for (const id of range.ids) {
        if (!HEX.test(id) || !id.startsWith(range.prefix)) throw new Error('RECONCILE_RANGE_INVALID')
        theirs.add(id)
        if (!local.has(id)) want.push(id)
      }
      for (const id of local.ids(range.prefix)) if (!theirs.has(id)) push.push(id)
      continue
    }
    const mine = local.summary(range.prefix)
    if (mine.count === range.count && sameFingerprint(mine.fp, range.fp)) continue
    if (range.count === 0) { push.push(...local.ids(range.prefix)); continue }
    if (mine.count <= RECONCILE_LIST_THRESHOLD || range.prefix.length >= RECONCILE_MAX_PREFIX) {
      reply.push({ prefix: range.prefix, ids: local.ids(range.prefix) })
      continue
    }
    for (const nibble of CHILDREN) reply.push(local.summary(range.prefix + nibble))
  }
  return { reply, push, want }
}

/** Does a range list contain anything that needs the peer to answer? */
export function rangesNeedReply(ranges: readonly ReconcileRange[]): boolean {
  return ranges.some(range => !('ids' in range))
}

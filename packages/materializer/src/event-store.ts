import { bytesToHex, hexToBytes, sha256 } from '@chronolog/canonical'
import { assertCanonicalCbor, decodeTransactionCore, encodeCanonicalCbor, equalBytes } from '@chronolog/protocol'
import type { ReplayProposal } from './types.js'

export interface EventExecutionStore {
  get(key: string): Promise<Uint8Array | null>
  /** Atomically replace one key durably; a failed reply may still have committed. */
  put(key: string, value: Uint8Array): Promise<void>
}
interface EventHistory {
  readonly order: readonly ReplayProposal[]
  readonly revision: bigint
}
interface AppliedEventHistoryState extends EventHistory {
  readonly kind: 'applied'
}
interface LiveEventHistoryState extends EventHistory {
  readonly kind: 'live'
  readonly finalLength: number
  readonly finalRevision: bigint
}
export type EventHistoryState = AppliedEventHistoryState | LiveEventHistoryState

const HEAD_TAGS = { applied: 'chronolog/event-applied-head/v1', live: 'chronolog/event-live-head/v1' } as const

/** Immutable ordered records plus one small atomic publication pointer. */
export class EventHistoryStore {
  #anchors: string[] = []
  #prefixBytes: number[] = []
  constructor(readonly store: EventExecutionStore, readonly key: string, readonly digest: Uint8Array,
    readonly quota: number, readonly kind: EventHistoryState['kind']) {}

  async load(): Promise<EventHistoryState | null> {
    const bytes = await this.store.get(this.key)
    if (bytes === null) return null
    if (bytes.length > this.quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
    const value = assertCanonicalCbor(bytes, { maxBytes: this.quota, maxByteStringBytes: this.quota, maxItems: 16 })
    if (!Array.isArray(value) || value.length !== (this.kind === 'applied' ? 6 : 8) || value[0] !== HEAD_TAGS[this.kind] ||
        !(value[1] instanceof Uint8Array) || !equalBytes(value[1], this.digest) || typeof value[2] !== 'bigint' ||
        value[2] < 0n || typeof value[3] !== 'bigint' || value[3] < 0n || value[3] > 100_000n ||
        typeof value[5] !== 'bigint' || value[5] < 0n ||
        value[4] !== null && (!(value[4] instanceof Uint8Array) || value[4].length !== 32)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    if (this.kind === 'live' && (typeof value[6] !== 'bigint' || value[6] < 0n || value[6] > value[3] ||
        typeof value[7] !== 'bigint' || value[7] < 0n)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    if (value[5] + BigInt(bytes.length) > BigInt(this.quota)) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
    const count = Number(value[3]), order = new Array<ReplayProposal>(count), sizes = new Array<number>(count)
    const anchors = new Array<string>(count)
    let tail = value[4] as Uint8Array | null, used = bytes.length
    for (let index = count - 1; index >= 0; index--) {
      if (!(tail instanceof Uint8Array)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
      const hash = bytesToHex(tail), node = await this.store.get(`${this.key}/node/${hash}`)
      if (node === null) throw new Error('EVENT_EXECUTION_HISTORY_INCOMPLETE')
      used += node.length
      if (used > this.quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
      if (!equalBytes(await sha256(node), tail)) throw new Error('EVENT_EXECUTION_HISTORY_INCOMPLETE')
      const row = assertCanonicalCbor(node, { maxBytes: this.quota, maxByteStringBytes: this.quota, maxItems: 32 })
      if (!Array.isArray(row) || row.length !== 6 || row[0] !== 'chronolog/event-record/v1' || row[1] !== BigInt(index) ||
          row[2] !== null && (!(row[2] instanceof Uint8Array) || row[2].length !== 32) ||
          !(row[3] instanceof Uint8Array) || !(row[4] instanceof Uint8Array) || !(row[5] instanceof Uint8Array)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
      order[index] = { txId: row[3], candidateDigest: row[4], canonicalCandidate: row[5], core: decodeTransactionCore(row[5]) }
      anchors[index] = hash; sizes[index] = node.length; tail = row[2] as Uint8Array | null
    }
    if (tail !== null || sizes.reduce((sum, size) => sum + size, 0) !== Number(value[5])) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    this.#anchors = anchors
    let total = 0; this.#prefixBytes = sizes.map(size => total += size)
    return this.kind === 'applied' ? { kind: 'applied', order, revision: value[2] } :
      { kind: 'live', order, revision: value[2], finalLength: Number(value[6]), finalRevision: value[7] as bigint }
  }

  async commit(state: EventHistoryState, difference: number): Promise<string> {
    if (state.kind !== this.kind || !Number.isSafeInteger(difference) || difference < 0 ||
        difference > Math.min(this.#anchors.length, state.order.length) || state.order.length > 100_000) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    const anchors = this.#anchors.slice(0, difference), sizes = this.#prefixBytes.slice(0, difference)
    let tail = anchors.at(-1) ?? null, used = sizes.at(-1) ?? 0
    for (let index = difference; index < state.order.length; index++) {
      const entry = state.order[index]!
      const node = encodeCanonicalCbor(['chronolog/event-record/v1', BigInt(index), tail === null ? null : hexToBytes(tail),
        entry.txId, entry.candidateDigest, entry.canonicalCandidate])
      used += node.length
      if (used > this.quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
      const hash = bytesToHex(await sha256(node)), key = `${this.key}/node/${hash}`
      const existing = await this.store.get(key)
      if (existing === null) await this.store.put(key, node)
      else if (!equalBytes(existing, node)) throw new Error('EVENT_EXECUTION_RECORD_CORRUPT')
      anchors.push(hash); sizes.push(used); tail = hash
    }
    const head = encodeCanonicalCbor([HEAD_TAGS[state.kind], this.digest, state.revision,
      BigInt(state.order.length), tail === null ? null : hexToBytes(tail), BigInt(used),
      ...(state.kind === 'applied' ? [] : [BigInt(state.finalLength), state.finalRevision])])
    if (used + head.length > this.quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
    // All immutable bodies precede the one atomic publication boundary. A failed
    // acknowledgment fences the runtime; reopen chooses only the durable head.
    await this.store.put(this.key, head)
    this.#anchors = anchors; this.#prefixBytes = sizes
    return bytesToHex(await sha256(head))
  }
}

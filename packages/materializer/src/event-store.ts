import { writeBytesMany, type BytesStore, type BytesStoreEntry } from '@chronolog/records'
import { bytesToHex, hexToBytes, sha256 } from '@chronolog/canonical'
import { assertCanonicalCbor, decodeTransactionCore, encodeCanonicalCbor, equalBytes } from '@chronolog/protocol'
import type { ReplayProposal } from './types.js'

export interface EventHistoryState {
  readonly order: readonly ReplayProposal[]
  readonly revision: bigint
  readonly finalLength: number
  readonly finalRevision: bigint
}

/** Immutable ordered records plus one small atomic publication pointer. */
export class EventHistoryStore {
  #anchors: string[] = []
  #prefixBytes: number[] = []
  constructor(readonly store: BytesStore, readonly key: string, readonly digest: Uint8Array, readonly quota: number) {}

  async load(): Promise<EventHistoryState | null> {
    const bytes = await this.store.get(this.key)
    if (bytes === null) return null
    if (bytes.length > 1024 || bytes.length > this.quota) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    const value = assertCanonicalCbor(bytes, { maxBytes: 1024, maxItems: 32 })
    if (!Array.isArray(value) || value.length !== 8 || value[0] !== 'chronolog/event-head/v2' ||
        !(value[1] instanceof Uint8Array) || !equalBytes(value[1], this.digest) || typeof value[2] !== 'bigint' ||
        typeof value[3] !== 'bigint' || typeof value[4] !== 'bigint' || typeof value[5] !== 'bigint' ||
        value[2] < 0n || value[3] < 0n || value[3] > value[5] || value[4] < 0n || value[5] < 0n || value[5] > 100_000n ||
        typeof value[7] !== 'bigint' || value[7] < 0n || value[7] + BigInt(bytes.length) > BigInt(this.quota) || value[5] > value[7] / 64n ||
        value[6] !== null && (!(value[6] instanceof Uint8Array) || value[6].length !== 32)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    const count = Number(value[5]), order = new Array<ReplayProposal>(count), sizes = new Array<number>(count)
    const anchors = new Array<string>(count)
    let tail = value[6] as Uint8Array | null, used = bytes.length
    for (let index = count - 1; index >= 0; index--) {
      if (!(tail instanceof Uint8Array)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
      const hash = bytesToHex(tail), node = await this.store.get(`${this.key}/node/${hash}`)
      if (node === null || node.length > this.quota - used || !equalBytes(await sha256(node), tail)) throw new Error('EVENT_EXECUTION_HISTORY_INCOMPLETE')
      used += node.length
      if (used > this.quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
      const row = assertCanonicalCbor(node, { maxBytes: this.quota, maxByteStringBytes: this.quota, maxItems: 32 })
      if (!Array.isArray(row) || row.length !== 6 || row[0] !== 'chronolog/event-record/v1' || row[1] !== BigInt(index) ||
          row[2] !== null && (!(row[2] instanceof Uint8Array) || row[2].length !== 32) ||
          !(row[3] instanceof Uint8Array) || !(row[4] instanceof Uint8Array) || !(row[5] instanceof Uint8Array)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
      order[index] = { txId: row[3], candidateDigest: row[4], canonicalCandidate: row[5], core: decodeTransactionCore(row[5]) }
      anchors[index] = hash; sizes[index] = node.length; tail = row[2] as Uint8Array | null
    }
    if (tail !== null || sizes.reduce((sum, size) => sum + size, 0) !== Number(value[7])) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    this.#anchors = anchors
    let total = 0; this.#prefixBytes = sizes.map(size => total += size)
    return { order, revision: value[2], finalLength: Number(value[3]), finalRevision: value[4] }
  }

  async commit(state: EventHistoryState, difference: number): Promise<string> {
    if (!Number.isSafeInteger(difference) || difference < 0 || difference > this.#anchors.length ||
        difference > state.order.length || state.order.length > 100_000) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    const anchors = this.#anchors.slice(0, difference), sizes = this.#prefixBytes.slice(0, difference)
    let tail = anchors.at(-1) ?? null, used = sizes.at(-1) ?? 0
    const pendingWrites: BytesStoreEntry[] = []
    for (let index = difference; index < state.order.length; index++) {
      const entry = state.order[index]!
      const node = encodeCanonicalCbor(['chronolog/event-record/v1', BigInt(index), tail === null ? null : hexToBytes(tail),
        entry.txId, entry.candidateDigest, entry.canonicalCandidate])
      used += node.length
      if (used > this.quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
      const hash = bytesToHex(await sha256(node)), key = `${this.key}/node/${hash}`
      const existing = await this.store.get(key)
      if (existing === null) pendingWrites.push({ key, value: node })
      else if (!equalBytes(existing, node)) throw new Error('EVENT_EXECUTION_RECORD_CORRUPT')
      anchors.push(hash); sizes.push(used); tail = hash
    }
    const head = encodeCanonicalCbor(['chronolog/event-head/v2', this.digest, state.revision, BigInt(state.finalLength),
      state.finalRevision, BigInt(state.order.length), tail === null ? null : hexToBytes(tail), BigInt(used)])
    if (used + head.length > this.quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
    // All immutable bodies precede the one atomic publication boundary. When the
    // store supports putMany, write nodes and head in a single atomic transaction.
    pendingWrites.push({ key: this.key, value: head })
    for (let offset = 0; offset < pendingWrites.length; offset += 128) {
      await writeBytesMany(this.store, pendingWrites.slice(offset, offset + 128))
    }
    const superseded = this.#anchors.slice(difference)
    this.#anchors = anchors; this.#prefixBytes = sizes
    if (superseded.length > 0 && this.store.delete !== undefined) {
      const active = new Set(anchors)
      for (const oldHash of superseded) {
        if (!active.has(oldHash)) {
          try { await this.store.delete(`${this.key}/node/${oldHash}`) } catch { /* Best-effort node reclamation. */ }
        }
      }
    }
    return bytesToHex(await sha256(head))
  }
}

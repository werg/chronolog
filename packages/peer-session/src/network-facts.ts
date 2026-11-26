import { bytesToHex, sha256Sync } from '@chronolog/canonical'
import { encryptedEnvelopeDigest } from '@chronolog/protocol'
import { recordDigest } from '@chronolog/authority'
import type { SessionCasNode, SessionFacts } from './session.js'

/**
 * Per-connection knowledge tracker for Chronolog v2 facts.
 * - Reconciles encrypted envelopes by `encryptedEnvelopeDigest` (never opId-only),
 *   so rewrapped envelopes for previously-undecryptable operations sync immediately.
 * - Reconciles CAS nodes by `(partition, hash)`.
 * - Reconciles public ops by sha256(rawBytes), retentions and checkpoints by recordDigest.
 */
export class PeerFactKnowledge {
  readonly #known = new Map<string, string>()

  get size(): number { return this.#known.size }

  async #digestItems(facts: SessionFacts) {
    const publicOps = facts.publicOps.map(raw => {
      const digest = bytesToHex(sha256Sync(raw))
      return { key: `pub/${digest}`, digest, value: raw }
    })
    const encryptedEnvelopes = facts.encryptedEnvelopes.map(raw => {
      const digest = bytesToHex(encryptedEnvelopeDigest(raw))
      return { key: `enc/${digest}`, digest, value: raw }
    })
    const casNodes = facts.casNodes.map((node: SessionCasNode) => ({
      key: `cas/${node.partition}/${node.hash}`,
      digest: node.hash,
      value: node,
    }))
    const retentions = await Promise.all(facts.retentions.map(async value => {
      const digest = await recordDigest(value)
      return { key: `ret/${digest}`, digest, value }
    }))
    const checkpoints = await Promise.all(facts.checkpoints.map(async value => {
      const digest = await recordDigest(value)
      return { key: `cp/${await recordDigest(value.payload)}`, digest, value }
    }))
    return { publicOps, encryptedEnvelopes, casNodes, retentions, checkpoints }
  }

  async remember(facts: SessionFacts): Promise<void> {
    const entries = await this.#digestItems(facts)
    for (const group of [entries.publicOps, entries.encryptedEnvelopes, entries.casNodes, entries.retentions, entries.checkpoints]) {
      for (const item of group) this.#known.set(item.key, item.digest)
    }
  }

  async missing(facts: SessionFacts): Promise<SessionFacts> {
    const entries = await this.#digestItems(facts)
    const filter = <T>(list: readonly { readonly key: string; readonly digest: string; readonly value: T }[]): T[] =>
      list.filter(item => this.#known.get(item.key) !== item.digest).map(item => item.value)
    return {
      publicOps: filter(entries.publicOps),
      encryptedEnvelopes: filter(entries.encryptedEnvelopes),
      casNodes: filter(entries.casNodes),
      retentions: filter(entries.retentions),
      checkpoints: filter(entries.checkpoints),
    }
  }
}

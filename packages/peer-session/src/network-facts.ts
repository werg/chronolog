import { recordDigest } from '@chronolog/authority'
import type { SessionFacts } from './session.js'
interface FactEntry<T> { readonly key: string; readonly digest: string; readonly value: T }

/** Knowledge is scoped to one reliable, authenticated connection, never to a peer
 * identity across reconnects. Digests identify complete signed facts, not proposal
 * IDs: alternate envelopes, retention signatures and finality updates all matter. */
export class PeerFactKnowledge {
  readonly #known = new Map<string, string>()
  /** Bounded by durable envelopes, retentions, statements, and one authority slot. */
  get size(): number { return this.#known.size }
  async #entries(facts: SessionFacts) {
    const entries = async <T>(kind: string, values: readonly T[]): Promise<readonly FactEntry<T>[]> => Promise.all(values.map(async value => {
      const digest = await recordDigest(value)
      return { key: `${kind}/${digest}`, digest, value }
    }))
    return {
      authority: facts.authority === undefined ? undefined : { key: 'authority', digest: await recordDigest(facts.authority), value: facts.authority },
      envelopes: await entries('envelope', facts.envelopes),
      retentions: await entries('retention', facts.retentions),
      // A statement can acquire arbitrarily many reordered/subset proof forms
      // without growing the durable proof set. Keep ONE complete-proof digest
      // per fully scoped statement, never a permanent set of those variants.
      finality: await Promise.all(facts.finality.map(async value => ({ key: `finality/${await recordDigest(value.statement)}`, digest: await recordDigest(value), value }))),
    }
  }
  /** Call only after successful authenticated merge, or successful reliable send. */
  async remember(facts: SessionFacts): Promise<void> {
    const entries = await this.#entries(facts)
    if (entries.authority !== undefined) this.#known.set(entries.authority.key, entries.authority.digest)
    for (const entry of [...entries.envelopes, ...entries.retentions, ...entries.finality]) this.#known.set(entry.key, entry.digest)
  }
  async missing(facts: SessionFacts): Promise<SessionFacts> {
    const entries = await this.#entries(facts)
    const unknown = <T>(values: readonly FactEntry<T>[]): T[] => values.filter(entry => this.#known.get(entry.key) !== entry.digest).map(entry => entry.value)
    return {
      ...(entries.authority === undefined || this.#known.get(entries.authority.key) === entries.authority.digest ? {} : { authority: entries.authority.value }),
      envelopes: unknown(entries.envelopes), retentions: unknown(entries.retentions), finality: unknown(entries.finality),
    }
  }
}

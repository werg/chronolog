import type { PeerRevision } from '@chronolog/peer-generation'
import { canonicalJson, type EventPayload } from '@chronolog/protocol'

import type { ApplicationEvent } from '../session.js'
import { ConsumerJournal, assertCurrent, bounded, readBatch, record, revision, sameSelection, topics,
  type ApplicationConsumerOptions } from './source.js'

export interface ApplicationProjectionCheckpoint<State extends EventPayload> {
  readonly revision: PeerRevision
  readonly cursor: string
  readonly state: State
}
export interface ApplicationProjectionOptions<State extends EventPayload> extends ApplicationConsumerOptions {
  readonly topics?: readonly string[]
  readonly initial: () => State
  /** Pure reducer. Rebuilding a projection must never perform external actions. */
  readonly reduce: (state: State, event: ApplicationEvent) => State
  readonly batchTransactions?: number
}

/** A rebuildable application cache; a whole captured revision is published atomically. */
export class ApplicationProjection<State extends EventPayload> {
  readonly #options: ApplicationProjectionOptions<State>
  readonly #journal: ConsumerJournal
  readonly #topics: readonly string[] | null
  readonly #limit: number
  readonly #maxBytes: number

  private constructor(options: ApplicationProjectionOptions<State>) {
    this.#options = options; this.#topics = topics(options.topics)
    this.#limit = bounded(options.batchTransactions ?? 32, 1, 128)
    this.#maxBytes = bounded(options.maxStateBytes ?? 8 * 1024 * 1024, 1024, 64 * 1024 * 1024)
    this.#journal = new ConsumerJournal('projection', options, this.#topics)
  }
  static async open<State extends EventPayload>(options: ApplicationProjectionOptions<State>): Promise<ApplicationProjection<State>> {
    const projection = new ApplicationProjection(options)
    try { await projection.inspect(); return projection }
    catch (error) { await projection.close(); throw error }
  }
  inspect(): Promise<ApplicationProjectionCheckpoint<State> | null> {
    return this.#journal.run(() => this.#load())
  }
  catchUp(options: { readonly signal?: AbortSignal } = {}): Promise<ApplicationProjectionCheckpoint<State> & { readonly reset: boolean }> {
    return this.#journal.run(async () => {
      const signal = options.signal === undefined ? this.#journal.signal : AbortSignal.any([this.#journal.signal, options.signal])
      signal.throwIfAborted()
      const stored = await this.#load(), view = await this.#options.session.readView()
      try {
        const reset = stored !== null && !sameSelection(stored.revision, view.revision)
        let state = this.#clone(stored === null || reset ? this.#options.initial() : stored.state)
        let cursor = stored === null || reset ? undefined : stored.cursor
        for (;;) {
          signal.throwIfAborted()
          const batch = await readBatch(view, { ...(cursor === undefined ? {} : { cursor }),
            ...(this.#topics === null ? {} : { topics: this.#topics }), limit: this.#limit })
          for (const event of batch.events) state = this.#options.reduce(state, event)
          cursor = batch.cursor
          if (!batch.hasMore) break
        }
        signal.throwIfAborted(); assertCurrent(this.#options.session, view)
        const checkpoint = { revision: structuredClone(view.revision), cursor, state: this.#clone(state) }
        // Never replace the visible cache with a partial reset/replay. If put's
        // acknowledgement is lost, the next turn reloads exactly what committed.
        await this.#journal.write(checkpoint)
        return { ...structuredClone(checkpoint), reset }
      } finally { await view.release() }
    })
  }
  follow(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationProjectionCheckpoint<State> & { readonly reset: boolean }> {
    const projection = this
    return { async *[Symbol.asyncIterator]() {
      const signal = options.signal === undefined ? projection.#journal.signal : AbortSignal.any([projection.#journal.signal, options.signal])
      for await (const _change of projection.#options.session.changes({ signal })) {
        try { yield await projection.catchUp({ signal }) }
        catch (error) { if (!(error instanceof Error) || error.message !== 'APPLICATION_CONSUMER_VIEW_CHANGED') throw error }
      }
    } }
  }
  close(): Promise<void> { return this.#journal.close() }
  async #load(): Promise<ApplicationProjectionCheckpoint<State> | null> {
    const value = await this.#journal.read()
    if (value === null) return null
    const checkpoint = record(value)
    if (typeof checkpoint.cursor !== 'string' || checkpoint.cursor.length === 0 || checkpoint.cursor.length > 8192) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
    const at = revision(checkpoint.revision)
    if (at.applicationId !== this.#options.session.applicationId || at.historyId !== this.#options.session.historyId) throw new Error('APPLICATION_CONSUMER_BINDING_MISMATCH')
    return { revision: at, cursor: checkpoint.cursor, state: this.#clone(checkpoint.state as State) }
  }
  #clone(state: State): State {
    return JSON.parse(canonicalJson(state, { maxBytes: this.#maxBytes, maxNodes: Math.min(this.#maxBytes, 1_000_000), maxDepth: 64 })) as State
  }
}

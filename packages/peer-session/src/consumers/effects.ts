import { peerDigest, type PeerRevision } from '@chronolog/peer-generation'
import { canonicalEventPayload, type EventPayload } from '@chronolog/protocol'

import type { ApplicationEvent } from '../session.js'
import { ConsumerJournal, assertCurrent, assertCurrentHead, bounded, clonePayload, consumerId, event, readBatch, record, revision, sameSelection, selected, topics,
  type ApplicationConsumerOperation, type ApplicationConsumerOptions, type ApplicationConsumerView } from './source.js'

export type ApplicationEffectResolution = { readonly kind: 'completed'; readonly result: EventPayload } |
  { readonly kind: 'not-performed' } | { readonly kind: 'uncertain' }
export interface ApplicationEffectContext {
  readonly effectId: string
  readonly idempotencyKey: string
  /** The authenticated original request. Payload labels never establish its author. */
  readonly event: ApplicationEvent
  readonly signal: AbortSignal
  readonly deadlineAtMs: number
}
export interface ApplicationEffectPublication {
  readonly operationId: string
  readonly reapplyOf: string | null
  readonly status: 'pending' | 'applied' | 'rejected' | 'abandoned'
}
export interface ApplicationEffectEntry {
  readonly effectId: string
  readonly intentKey: string
  readonly event: ApplicationEvent
  readonly observedEvents: readonly ApplicationEvent[]
  readonly observedAt: PeerRevision
  readonly stage: 'prepared' | 'dispatching' | 'completed' | 'not-performed' | 'denied'
  readonly reason: 'abandoned' | 'unauthorized' | null
  readonly result: EventPayload | null
  readonly publications: readonly ApplicationEffectPublication[]
}
export interface ApplicationEffectOptions extends ApplicationConsumerOptions {
  readonly topics: readonly string[]
  /** Explicit business identity across reapplication; scoped to the verified original author. */
  readonly intentKey?: (event: ApplicationEvent) => string
  readonly authorize: (input: { readonly event: ApplicationEvent; readonly view: ApplicationConsumerView; readonly signal: AbortSignal }) => boolean | Promise<boolean>
  readonly dispatch: (context: ApplicationEffectContext) => Promise<EventPayload>
  /** An idempotency key alone does not establish a provider's retry guarantee. */
  readonly recovery: 'idempotent' | 'reconcile' | 'manual'
  readonly reconcile?: (context: ApplicationEffectContext) => Promise<ApplicationEffectResolution>
  readonly publishResult?: (entry: ApplicationEffectEntry, options: {
    readonly operationId: string; readonly reapplyOf: string | null; readonly signal: AbortSignal
  }) => Promise<ApplicationConsumerOperation>
  readonly timeoutMs?: number
  readonly maxEntries?: number
  readonly batchTransactions?: number
}
interface EffectState {
  readonly revision: PeerRevision | null
  readonly cursor: string | null
  readonly entries: readonly ApplicationEffectEntry[]
}
export class ApplicationEffectUncertainError extends Error {
  constructor(readonly effectId: string, cause?: unknown) {
    super('APPLICATION_EFFECT_OUTCOME_UNCERTAIN', cause === undefined ? undefined : { cause }); this.name = 'ApplicationEffectUncertainError'
  }
}
const providerCalls = new WeakMap<ApplicationEffectOptions['store'], Map<string, Promise<unknown>>>()

/** Retained external facts survive selected-history resets; only explicit recovery can repeat an uncertain call. */
export class ApplicationEffectWorker {
  readonly #options: ApplicationEffectOptions
  readonly #journal: ConsumerJournal
  readonly #topics: readonly string[]
  readonly #maximum: number
  readonly #limit: number
  readonly #timeout: number
  readonly #providerKey: string
  #running = false

  private constructor(options: ApplicationEffectOptions) {
    this.#options = options; this.#topics = topics(options.topics)!
    this.#maximum = bounded(options.maxEntries ?? 1024, 1, 16_384)
    this.#limit = bounded(options.batchTransactions ?? 8, 1, 64)
    this.#timeout = bounded(options.timeoutMs ?? 60_000, 1, 300_000)
    if (typeof options.authorize !== 'function' || typeof options.dispatch !== 'function' ||
        !['idempotent', 'reconcile', 'manual'].includes(options.recovery) || options.recovery === 'reconcile' && options.reconcile === undefined) {
      throw new Error('APPLICATION_EFFECT_POLICY_REQUIRED')
    }
    this.#providerKey = JSON.stringify([options.session.applicationId, options.session.historyId, options.id])
    this.#journal = new ConsumerJournal('effects', options, [this.#topics, options.recovery, options.intentKey === undefined ? 'event' : 'intent', options.publishResult !== undefined])
  }
  static async open(options: ApplicationEffectOptions): Promise<ApplicationEffectWorker> {
    const worker = new ApplicationEffectWorker(options)
    try { await worker.inspect(); return worker } catch (error) { await worker.close(); throw error }
  }
  inspect(): Promise<readonly ApplicationEffectEntry[]>
  inspect(effectId: string): Promise<ApplicationEffectEntry | null>
  inspect(effectId?: string): Promise<readonly ApplicationEffectEntry[] | ApplicationEffectEntry | null> {
    return this.#journal.run(async () => { const state = await this.#load(); return structuredClone(effectId === undefined ? state.entries : state.entries.find(e => e.effectId === effectId) ?? null) })
  }
  processNext(options: { readonly signal?: AbortSignal } = {}): Promise<{ readonly handled: number; readonly hasMore: boolean; readonly reset: boolean }> {
    if (this.#running) return Promise.reject(new Error('APPLICATION_CONSUMER_BUSY'))
    return this.#journal.run(() => this.#process(this.#signal(options.signal)))
  }
  async run(options: { readonly signal?: AbortSignal } = {}): Promise<void> {
    if (this.#running) throw new Error('APPLICATION_CONSUMER_BUSY')
    this.#running = true; const signal = this.#signal(options.signal)
    try {
      for await (const _change of this.#options.session.changes({ signal })) {
        for (;;) {
          try { if (!(await this.#journal.run(() => this.#process(signal))).hasMore) break }
          catch (error) { if (!(error instanceof Error) || error.message !== 'APPLICATION_CONSUMER_VIEW_CHANGED') throw error }
        }
      }
    } catch (error) { if (!signal.aborted) throw error }
    finally { this.#running = false }
  }
  /** Retry is deliberate; dispatching requires the provider's declared idempotency guarantee. */
  retry(effectId: string, options: { readonly signal?: AbortSignal } = {}): Promise<ApplicationEffectEntry> {
    return this.#journal.run(async () => {
      const state = await this.#load(), entry = this.#find(state, effectId)
      if (entry.stage === 'completed') return structuredClone(entry)
      if (entry.stage === 'dispatching' && this.#options.recovery !== 'idempotent') throw new ApplicationEffectUncertainError(effectId)
      return this.#dispatch(state, entry, this.#signal(options.signal))
    })
  }
  /** Reconciliation observes an external fact even when its application intent was abandoned. */
  reconcile(effectId: string, options: { readonly signal?: AbortSignal } = {}): Promise<ApplicationEffectEntry> {
    return this.#journal.run(async () => {
      const state = await this.#load(), entry = this.#find(state, effectId)
      if (entry.stage !== 'dispatching') throw new Error('APPLICATION_EFFECT_NOT_UNCERTAIN')
      if (this.#options.reconcile === undefined) throw new ApplicationEffectUncertainError(effectId)
      const resolution = await this.#provider(entry, this.#signal(options.signal), context => this.#options.reconcile!(context))
      if (resolution.kind === 'uncertain') return structuredClone(entry)
      const resolved = this.#resolved(entry, resolution)
      await this.#saveEntry(state, resolved); return structuredClone(resolved)
    })
  }
  resolve(effectId: string, resolution: Exclude<ApplicationEffectResolution, { readonly kind: 'uncertain' }>): Promise<void> {
    return this.#journal.run(async () => {
      const state = await this.#load(), entry = this.#find(state, effectId)
      if (entry.stage !== 'dispatching') throw new Error('APPLICATION_EFFECT_NOT_UNCERTAIN')
      await this.#saveEntry(state, this.#resolved(entry, resolution))
    })
  }
  /** Deliberately restore a result record with a linked new ordinary application attempt. */
  republish(effectId: string, options: { readonly operationId: string; readonly signal?: AbortSignal }): Promise<ApplicationEffectEntry> {
    return this.#journal.run(async () => {
      consumerId(options.operationId)
      const state = await this.#load(); let entry = await this.#publish(state, this.#find(state, effectId), this.#signal(options.signal))
      const previous = entry.publications.at(-1)
      if (previous?.status !== 'abandoned' || entry.publications.length >= 16 || entry.publications.some(p => p.operationId === options.operationId)) {
        throw new Error('APPLICATION_EFFECT_REAPPLY_REQUIRED')
      }
      entry = { ...entry, publications: [...entry.publications, { operationId: options.operationId, reapplyOf: previous.operationId, status: 'pending' }] }
      await this.#saveEntry(state, entry)
      return this.#publish(state, entry, this.#signal(options.signal))
    })
  }
  close(): Promise<void> { return this.#journal.close() }

  async #process(signal: AbortSignal) {
    signal.throwIfAborted()
    let state = await this.#load()
    // Refresh result observations independently from source cursors: recovery
    // may exclude a published result while the provider fact remains completed.
    for (const entry of state.entries) if (entry.stage === 'completed') {
      const updated = await this.#publish(state, entry, signal); state = this.#replace(state, updated)
    }
    const view = await this.#options.session.readView()
    let batch, reset: boolean
    try {
      reset = state.revision !== null && !sameSelection(state.revision, view.revision)
      batch = await readBatch(view, { topics: this.#topics, limit: this.#limit,
        ...(state.cursor === null || reset ? {} : { cursor: state.cursor }) })
      assertCurrent(this.#options.session, view)
    } finally { await view.release() }
    let handled = 0
    for (const value of batch.events) {
      signal.throwIfAborted()
      const intentKey = this.#options.intentKey?.(structuredClone(value)) ?? value.id; consumerId(intentKey)
      const effectId = `effect_${await peerDigest(['chronolog/application-effect/v1', this.#options.session.applicationId,
        this.#options.session.historyId, this.#options.id, this.#options.version, value.author, intentKey])}`
      let entry = state.entries.find(e => e.effectId === effectId)
      if (entry === undefined) {
        if (state.entries.length >= this.#maximum) throw new Error('APPLICATION_EFFECT_JOURNAL_LIMIT')
        entry = { effectId, intentKey, event: value, observedEvents: [value], observedAt: batch.revision,
          stage: 'prepared', reason: null, result: null, publications: [] }
        state = this.#replace(state, entry); await this.#journal.write(state)
      } else if (!entry.observedEvents.some(e => e.id === value.id)) {
        if (entry.observedEvents.length >= 32) throw new Error('APPLICATION_EFFECT_PROVENANCE_LIMIT')
        if (entry.event.author !== value.author || entry.event.topic !== value.topic || canonicalEventPayload(entry.event.payload) !== canonicalEventPayload(value.payload)) {
          throw new Error('APPLICATION_EFFECT_INTENT_KEY_REUSED')
        }
        entry = { ...entry, observedEvents: [...entry.observedEvents, value] }
        state = this.#replace(state, entry); await this.#journal.write(state)
      }
      if (entry.stage === 'dispatching') throw new ApplicationEffectUncertainError(effectId)
      if (entry.stage === 'prepared') { entry = await this.#dispatch(state, entry, signal); handled++ }
      state = this.#replace(state, entry)
      if (entry.stage === 'completed') { entry = await this.#publish(state, entry, signal); state = this.#replace(state, entry) }
    }
    // A reset after the capture leaves this explicit old-generation cursor; the
    // next turn rebuilds it. Retained dispatch records are never reset with it.
    await this.#journal.write({ ...state, revision: batch.revision, cursor: batch.cursor })
    return { handled, hasMore: batch.hasMore, reset }
  }
  async #dispatch(state: EffectState, entry: ApplicationEffectEntry, signal: AbortSignal): Promise<ApplicationEffectEntry> {
    signal.throwIfAborted()
    const view = await this.#options.session.readView()
    let selectedEvent: ApplicationEvent | undefined, authorized = false
    try {
      for (const observed of [...entry.observedEvents].reverse()) if (await selected(this.#options.session, observed)) { selectedEvent = observed; break }
      if (selectedEvent !== undefined) {
        const current = selectedEvent
        authorized = await this.#provider(entry, signal, async context => this.#options.authorize({ event: structuredClone(current), view, signal: context.signal }))
      }
      signal.throwIfAborted(); assertCurrentHead(this.#options.session, view)
    } finally { await view.release() }
    if (selectedEvent === undefined || !authorized) {
      if (entry.stage === 'dispatching') throw new ApplicationEffectUncertainError(entry.effectId)
      const denied: ApplicationEffectEntry = { ...entry, stage: 'denied', reason: selectedEvent === undefined ? 'abandoned' : 'unauthorized' }
      await this.#saveEntry(state, denied); return denied
    }
    const dispatching: ApplicationEffectEntry = { ...entry, stage: 'dispatching', reason: null }
    this.#journal.reserve(this.#replace(state, dispatching), 70_000)
    await this.#saveEntry(state, dispatching)
    // A successful journal write can yield to an ordinary permission change.
    // Check again within the provider callback, with no await before dispatch.
    let entered = false
    let result: EventPayload
    try {
      signal.throwIfAborted(); assertCurrentHead(this.#options.session, view)
      result = clonePayload(await this.#provider(entry, signal, context => {
        assertCurrentHead(this.#options.session, view)
        entered = true
        return this.#options.dispatch(context)
      }))
    } catch (cause) {
      if (entered || entry.stage === 'dispatching') throw new ApplicationEffectUncertainError(entry.effectId, cause)
      // No call began, and the dispatching write was acknowledged. Restore the
      // known prior state; an ambiguous write above never reaches this branch.
      if (!this.#journal.signal.aborted) await this.#saveEntry(state, entry)
      throw cause
    }
    const completed: ApplicationEffectEntry = { ...entry, stage: 'completed', reason: null, result }
    await this.#saveEntry(state, completed); return completed
  }
  async #publish(state: EffectState, input: ApplicationEffectEntry, signal: AbortSignal): Promise<ApplicationEffectEntry> {
    if (input.stage !== 'completed' || this.#options.publishResult === undefined) return input
    let entry = input, publication = entry.publications.at(-1)
    if (publication === undefined) {
      publication = { operationId: `effect-result:${entry.effectId}`, reapplyOf: null, status: 'pending' }
      entry = { ...entry, publications: [publication] }; await this.#saveEntry(state, entry)
    }
    let operation = await this.#options.session.operations.get(publication.operationId)
    if (operation === null && publication.status !== 'pending') throw new Error('APPLICATION_EFFECT_PUBLICATION_MISSING')
    if (operation === null || operation.status === 'saved') {
      signal.throwIfAborted()
      const handle = await this.#options.publishResult(structuredClone(entry), { operationId: publication.operationId, reapplyOf: publication.reapplyOf, signal })
      if (handle.operationId !== publication.operationId) throw new Error('APPLICATION_EFFECT_PUBLICATION_MISMATCH')
      try { await handle.applied({ signal }) }
      catch (error) {
        operation = await handle.get()
        if (operation?.status !== 'abandoned' && operation?.status !== 'needsReapply') throw error
      }
      operation = await handle.get()
    }
    const status = operation?.status === 'applied' ? operation.outcome === 'accepted' ? 'applied' : 'rejected' :
      operation?.status === 'abandoned' || operation?.status === 'needsReapply' ? 'abandoned' : 'pending'
    entry = { ...entry, publications: [...entry.publications.slice(0, -1), { ...publication, status }] }
    if (status !== publication.status) await this.#saveEntry(state, entry)
    return entry
  }
  async #provider<T>(entry: ApplicationEffectEntry, signal: AbortSignal, call: (context: ApplicationEffectContext) => Promise<T>): Promise<T> {
    signal.throwIfAborted()
    const calls = providerCalls.get(this.#options.store) ?? new Map<string, Promise<unknown>>()
    providerCalls.set(this.#options.store, calls)
    if (calls.has(this.#providerKey)) throw new Error('APPLICATION_EFFECT_PROVIDER_BUSY')
    const deadline = new AbortController(), abort = AbortSignal.any([signal, deadline.signal]), deadlineAtMs = Date.now() + this.#timeout
    let stop = () => {}
    const interrupted = new Promise<never>((_resolve, reject) => {
      stop = () => reject(new Error('APPLICATION_EFFECT_PROVIDER_INTERRUPTED', { cause: abort.reason }))
      abort.addEventListener('abort', stop, { once: true })
    })
    const timeout = setTimeout(() => deadline.abort(new Error('APPLICATION_EFFECT_PROVIDER_TIMEOUT')), this.#timeout)
    const task = Promise.resolve().then(() => { abort.throwIfAborted(); return call({ effectId: entry.effectId, idempotencyKey: entry.effectId,
      event: structuredClone(entry.event), signal: abort, deadlineAtMs }) })
    calls.set(this.#providerKey, task)
    void task.finally(() => { if (calls.get(this.#providerKey) === task) calls.delete(this.#providerKey) }).catch(() => undefined)
    try { return await Promise.race([task, interrupted]) }
    finally { clearTimeout(timeout); abort.removeEventListener('abort', stop) }
  }
  #resolved(entry: ApplicationEffectEntry, resolution: Exclude<ApplicationEffectResolution, { readonly kind: 'uncertain' }>): ApplicationEffectEntry {
    if (resolution.kind === 'completed') return { ...entry, stage: 'completed', reason: null, result: clonePayload(resolution.result) }
    if (resolution.kind !== 'not-performed') throw new Error('APPLICATION_EFFECT_RESOLUTION_INVALID')
    return { ...entry, stage: 'not-performed', reason: null, result: null }
  }
  #signal(signal?: AbortSignal): AbortSignal { return signal === undefined ? this.#journal.signal : AbortSignal.any([this.#journal.signal, signal]) }
  #find(state: EffectState, effectId: string): ApplicationEffectEntry {
    const entry = state.entries.find(e => e.effectId === effectId)
    if (entry === undefined) throw new Error('APPLICATION_EFFECT_NOT_FOUND')
    return entry
  }
  #replace(state: EffectState, entry: ApplicationEffectEntry): EffectState {
    return { ...state, entries: state.entries.some(e => e.effectId === entry.effectId) ? state.entries.map(e => e.effectId === entry.effectId ? entry : e) : [...state.entries, entry] }
  }
  #saveEntry(state: EffectState, entry: ApplicationEffectEntry): Promise<void> { return this.#journal.write(this.#replace(state, entry)) }
  async #load(): Promise<EffectState> {
    const value = await this.#journal.read()
    if (value === null) return { revision: null, cursor: null, entries: [] }
    const state = record(value)
    if ((state.cursor !== null && (typeof state.cursor !== 'string' || state.cursor.length > 8192)) || !Array.isArray(state.entries) || state.entries.length > this.#maximum) {
      throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
    }
    const entries = state.entries.map(value => {
      const row = record(value)
      if (typeof row.effectId !== 'string' || !/^effect_[0-9a-f]{64}$/u.test(row.effectId) || typeof row.intentKey !== 'string' ||
          !Array.isArray(row.observedEvents) || row.observedEvents.length === 0 || row.observedEvents.length > 32 ||
          !Array.isArray(row.publications) || row.publications.length > 16 ||
          !['prepared', 'dispatching', 'completed', 'not-performed', 'denied'].includes(String(row.stage)) ||
          ![null, 'abandoned', 'unauthorized'].includes(row.reason as null | string)) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
      consumerId(row.intentKey)
      const publications = row.publications.map(value => {
        const p = record(value)
        if (typeof p.operationId !== 'string' || (p.reapplyOf !== null && typeof p.reapplyOf !== 'string') ||
            !['pending', 'applied', 'rejected', 'abandoned'].includes(String(p.status))) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
        consumerId(p.operationId)
        return p as unknown as ApplicationEffectPublication
      })
      return { effectId: row.effectId, intentKey: row.intentKey, event: event(row.event), observedEvents: row.observedEvents.map(event),
        observedAt: revision(row.observedAt), stage: row.stage as ApplicationEffectEntry['stage'], reason: row.reason as ApplicationEffectEntry['reason'],
        result: clonePayload(row.result as EventPayload), publications }
    })
    if (new Set(entries.map(e => e.effectId)).size !== entries.length) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
    return { revision: state.revision === null ? null : revision(state.revision), cursor: state.cursor, entries }
  }
}

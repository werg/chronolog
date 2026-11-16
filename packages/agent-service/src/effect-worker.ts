import { bytesToHex, sha256 } from '@chronolog/canonical'
import { Mutex } from '@chronolog/node-core/browser'
import type { DurableOperationStore } from '@chronolog/node-core'
import { assertCanonicalCbor, assertEventTopic, canonicalEventPayload, encodeCanonicalCbor } from '@chronolog/protocol'
import type { CborValue, EventPayload } from '@chronolog/protocol'

import { CheckpointStore } from './checkpoint.js'
import { batchEvents, canonicalTopics, cloneFinalEvent, validateConsumerId } from './event-source.js'
import type { FinalEvent, FinalEventBatch, FinalEventPublisher, FinalEventSource } from './event-source.js'

export interface EffectContext {
  readonly effectId: string
  /** Pass unchanged to a provider that supports durable idempotency keys. */
  readonly idempotencyKey: string
  readonly event: FinalEvent
}

export type EffectReconciliation =
  | { readonly kind: 'completed'; readonly result: EventPayload }
  | { readonly kind: 'not-performed' }
  | { readonly kind: 'uncertain' }

export interface EffectHandler {
  readonly id: string
  readonly version: string
  readonly topics: readonly string[]
  /** `idempotent` is a provider guarantee, never inferred from a local retry key. */
  readonly recovery: 'idempotent' | 'reconcile' | 'manual'
  dispatch(context: EffectContext): Promise<EventPayload>
  reconcile?(context: EffectContext): Promise<EffectReconciliation>
}

export interface EffectWorkerOptions {
  readonly sourceId: string
  readonly store: DurableOperationStore
  readonly source: FinalEventSource
  readonly publisher: FinalEventPublisher
  readonly handler: EffectHandler
  readonly resultTopic: string
  readonly batchLimit?: number
}

interface ActiveEffect {
  readonly effectId: string
  readonly stage: 'prepared' | 'dispatching' | 'result'
  readonly result: EventPayload | null
}
interface PendingBatch {
  readonly events: readonly FinalEvent[]
  readonly scannedThrough: string
  readonly revision: string
  readonly next: number
  readonly active: ActiveEffect | null
}
interface WorkerState {
  readonly cursor: string | null
  readonly revision: string | null
  readonly pending: PendingBatch | null
}

export class EffectUncertainError extends Error {
  constructor(readonly effectId: string, cause?: unknown) {
    super(`EFFECT_OUTCOME_UNCERTAIN: ${effectId}`, cause === undefined ? undefined : { cause })
  }
}

/**
 * A single designated handler consumes final intent. In-flight effect state,
 * remaining batch and processed cursor live in one atomic local checkpoint.
 * A model, UI reducer or SQL materializer never invokes provider code here.
 */
export class DurableEffectWorker {
  readonly #options: EffectWorkerOptions
  readonly #topics: readonly string[]
  readonly #checkpoint: CheckpointStore
  readonly #limit: number
  readonly #mutex = new Mutex()
  #running = false

  private constructor(options: EffectWorkerOptions) {
    for (const value of [options.sourceId, options.handler.id, options.handler.version]) validateConsumerId(value)
    assertEventTopic(options.resultTopic)
    this.#topics = canonicalTopics(options.handler.topics)
    if (this.#topics.includes(options.resultTopic)) throw new Error('EFFECT_RESULT_TOPIC_IS_INPUT')
    if (options.handler.recovery === 'reconcile' && options.handler.reconcile === undefined) throw new Error('EFFECT_RECONCILER_REQUIRED')
    this.#limit = options.batchLimit ?? 8
    if (!Number.isSafeInteger(this.#limit) || this.#limit < 1 || this.#limit > 64) throw new Error('CONSUMER_BATCH_LIMIT_INVALID')
    this.#options = options
    this.#checkpoint = new CheckpointStore(options.store, {
      id: `effects/${options.handler.id}`,
      binding: encodeCanonicalCbor([1n, 'effects', options.sourceId, options.handler.id, options.handler.version,
        this.#topics, options.resultTopic, options.handler.recovery]),
    })
  }

  static async open(options: EffectWorkerOptions): Promise<DurableEffectWorker> {
    const worker = new DurableEffectWorker(options)
    await worker.#load()
    return worker
  }

  /** Inspects durable processing state, never advances received-only progress. */
  async status(): Promise<{
    readonly cursor: string | null
    readonly revision: string | null
    readonly remaining: number
    readonly effect: ActiveEffect | null
  }> {
    return this.#mutex.run(async () => {
      const state = await this.#load()
      return { cursor: state.cursor, revision: state.revision,
        remaining: state.pending === null ? 0 : state.pending.events.length - state.pending.next,
        effect: structuredClone(state.pending?.active ?? null) }
    })
  }

  /** One bounded read; useful for resident scheduling and deterministic tests. */
  async processNext(): Promise<{ readonly progressed: boolean; readonly hasMore: boolean }> {
    if (this.#running) throw new Error('EFFECT_WORKER_ALREADY_RUNNING')
    return this.#mutex.run(async () => {
      let state = await this.#load()
      if (state.pending !== null) {
        await this.#finish(state)
        return { progressed: true, hasMore: true }
      }
      const batch = await this.#options.source.read({ topics: this.#topics, limit: this.#limit,
        ...(state.cursor === null ? {} : { cursor: state.cursor }) })
      const before = state.cursor
      state = await this.#accept(state, batch)
      await this.#finish(state)
      return { progressed: batch.scannedThrough !== before, hasMore: batch.hasMore }
    })
  }

  async run(signal?: AbortSignal): Promise<void> {
    if (this.#running) throw new Error('EFFECT_WORKER_ALREADY_RUNNING')
    this.#running = true
    try {
      const state = await this.#mutex.run(async () => this.#finish(await this.#load()))
      if (signal?.aborted) return
      for await (const batch of this.#options.source.subscribe({ topics: this.#topics, limit: this.#limit,
        ...(state.cursor === null ? {} : { cursor: state.cursor }), ...(signal === undefined ? {} : { signal }) })) {
        if (signal?.aborted) return
        await this.#mutex.run(async () => this.#finish(await this.#accept(await this.#load(), batch)))
      }
    } finally { this.#running = false }
  }

  /** Explicit operator/provider reconciliation; it cannot silently discard work. */
  async resolve(effectId: string, result: Exclude<EffectReconciliation, { kind: 'uncertain' }>): Promise<void> {
    await this.#mutex.run(async () => {
      const state = await this.#load(), pending = state.pending
      if (pending?.active?.effectId !== effectId || pending.active.stage !== 'dispatching') throw new Error('EFFECT_NOT_UNCERTAIN')
      const active: ActiveEffect = result.kind === 'completed'
        ? { effectId, stage: 'result', result: clonePayload(result.result) }
        : { effectId, stage: 'prepared', result: null }
      await this.#save({ ...state, pending: { ...pending, active } })
    })
  }

  async #accept(state: WorkerState, batch: FinalEventBatch): Promise<WorkerState> {
    if (state.pending !== null) throw new Error('EFFECT_BATCH_IN_PROGRESS')
    const events = batchEvents(batch, this.#limit, this.#topics)
    if (batch.scannedThrough === state.cursor && (batch.hasMore || events.length !== 0)) throw new Error('CONSUMER_NO_PROGRESS')
    const next: WorkerState = { ...state,
      pending: { events, scannedThrough: batch.scannedThrough, revision: batch.revision, next: 0, active: null } }
    await this.#save(next)
    return next
  }

  async #finish(input: WorkerState): Promise<WorkerState> {
    let state = input
    while (state.pending !== null) {
      let pending = state.pending
      if (pending.next === pending.events.length) {
        state = { cursor: pending.scannedThrough, revision: pending.revision, pending: null }
        await this.#save(state)
        return state
      }
      const event = pending.events[pending.next]!
      const effectId = await effectIdentity(this.#options.sourceId, event.id, this.#options.handler.id, this.#options.handler.version)
      let active = pending.active
      if (active === null) {
        active = { effectId, stage: 'prepared', result: null }
        pending = { ...pending, active }
        state = { ...state, pending }
        await this.#save(state)
      }
      if (active.effectId !== effectId) throw new Error('EFFECT_CHECKPOINT_ID_MISMATCH')
      const context: EffectContext = { effectId, idempotencyKey: effectId, event: cloneFinalEvent(event) }
      if (active.stage === 'dispatching') {
        if (this.#options.handler.recovery === 'manual') throw new EffectUncertainError(effectId)
        if (this.#options.handler.recovery === 'reconcile') {
          const reconciliation = await this.#options.handler.reconcile!(context)
          if (reconciliation.kind === 'uncertain') throw new EffectUncertainError(effectId)
          active = reconciliation.kind === 'completed'
            ? { effectId, stage: 'result', result: clonePayload(reconciliation.result) }
            : { effectId, stage: 'prepared', result: null }
          pending = { ...pending, active }; state = { ...state, pending }
          await this.#save(state)
        }
      }
      if (active.stage !== 'result') {
        // A crash from this point may have reached the provider. Retrying needs
        // its idempotency guarantee, reconciliation, or explicit resolution.
        active = { effectId, stage: 'dispatching', result: null }
        pending = { ...pending, active }; state = { ...state, pending }
        await this.#save(state)
        let result: EventPayload
        try { result = clonePayload(await this.#options.handler.dispatch(context)) }
        catch (cause) { throw new EffectUncertainError(effectId, cause) }
        active = { effectId, stage: 'result', result }
        pending = { ...pending, active }; state = { ...state, pending }
        await this.#save(state)
      }
      const result: EventPayload = {
        type: 'effect.completed', version: 1, effectId, originEventId: event.id,
        handlerId: this.#options.handler.id, handlerVersion: this.#options.handler.version,
        result: active.result,
      }
      // A lost publication response repeats this exact result without dispatch.
      await this.#options.publisher.publishFinal(this.#options.resultTopic, result, { operationId: `effect-result:${effectId}` })
      state = { ...state, pending: { ...pending, next: pending.next + 1, active: null } }
      await this.#save(state)
    }
    return state
  }

  async #load(): Promise<WorkerState> {
    const checkpoint = await this.#checkpoint.load()
    if (checkpoint === null) return { cursor: null, revision: null, pending: null }
    const value = assertCanonicalCbor(checkpoint.state)
    if (!Array.isArray(value) || value.length !== 2 || value[0] !== 1n) throw new Error('EFFECT_CHECKPOINT_INVALID')
    let pending: PendingBatch | null = null
    if (value[1] !== null) {
      const batch = value[1]
      if (!Array.isArray(batch) || batch.length !== 5 || !Array.isArray(batch[0]) || typeof batch[1] !== 'string' ||
          typeof batch[2] !== 'string' || typeof batch[3] !== 'bigint' || batch[3] < 0n || batch[3] > BigInt(batch[0].length) ||
          batch[0].length > this.#limit * 64) throw new Error('EFFECT_CHECKPOINT_INVALID')
      const events = batch[0].map(decodeEvent)
      let active: ActiveEffect | null = null
      if (batch[4] !== null) {
        const entry = batch[4]
        if (!Array.isArray(entry) || entry.length !== 3 || typeof entry[0] !== 'string' ||
            (entry[1] !== 'prepared' && entry[1] !== 'dispatching' && entry[1] !== 'result') ||
            (entry[2] !== null && typeof entry[2] !== 'string')) throw new Error('EFFECT_CHECKPOINT_INVALID')
        active = { effectId: entry[0], stage: entry[1], result: entry[2] === null ? null : parsePayload(entry[2]) }
      }
      pending = { events, scannedThrough: batch[1], revision: batch[2], next: Number(batch[3]), active }
    }
    return { cursor: checkpoint.cursor, revision: checkpoint.revision, pending }
  }

  async #save(state: WorkerState): Promise<void> {
    const p = state.pending
    const batch: CborValue = p === null ? null : [p.events.map(encodeEvent), p.scannedThrough, p.revision, BigInt(p.next),
      p.active === null ? null : [p.active.effectId, p.active.stage,
        p.active.stage === 'result' ? canonicalEventPayload(p.active.result) : null]]
    await this.#checkpoint.commit({ cursor: state.cursor, revision: state.revision, state: encodeCanonicalCbor([1n, batch]) })
  }
}

export async function effectIdentity(sourceId: string, eventId: string, handlerId: string, handlerVersion: string): Promise<string> {
  return `effect_${bytesToHex(await sha256(encodeCanonicalCbor(['chronolog/effect/v1', sourceId, eventId, handlerId, handlerVersion])))}`
}

function clonePayload(payload: EventPayload): EventPayload { return parsePayload(canonicalEventPayload(payload)) }
function parsePayload(value: string): EventPayload {
  const payload = JSON.parse(value) as EventPayload
  if (canonicalEventPayload(payload) !== value) throw new Error('EFFECT_PAYLOAD_NOT_CANONICAL')
  return payload
}
function encodeEvent(event: FinalEvent): CborValue {
  return [event.id, event.proposalId, BigInt(event.eventOrdinal), event.topic, canonicalEventPayload(event.payload)]
}
function decodeEvent(value: CborValue): FinalEvent {
  if (!Array.isArray(value) || value.length !== 5 || typeof value[0] !== 'string' || typeof value[1] !== 'string' ||
      typeof value[2] !== 'bigint' || typeof value[3] !== 'string' || typeof value[4] !== 'string') throw new Error('EFFECT_CHECKPOINT_INVALID')
  return cloneFinalEvent({ id: value[0], proposalId: value[1], eventOrdinal: Number(value[2]), topic: value[3], payload: parsePayload(value[4]) })
}

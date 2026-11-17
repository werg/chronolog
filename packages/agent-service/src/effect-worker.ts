import { bytesToHex, sha256 } from '@chronolog/canonical'
import { Mutex } from '@chronolog/node-core/browser'
import type { DurableOperationStore } from '@chronolog/node-core'
import { assertCanonicalCbor, assertEventTopic, canonicalEventPayload, encodeCanonicalCbor } from '@chronolog/protocol'
import type { CborValue, EventPayload } from '@chronolog/protocol'

import { CheckpointStore } from './checkpoint.js'
import { decodeEventOrigin, encodeEventOrigin } from './event-origin.js'
import { batchEvents, canonicalTopics, cloneFinalEvent, FinalEventPublicationRejectedError, validateConsumerId } from './event-source.js'
import type { FinalEvent, FinalEventBatch, FinalEventPublisher, FinalEventPublicationRejection, FinalEventSource } from './event-source.js'
import { decodePublicationRejections, encodePublicationRejections, MAX_PUBLICATION_ATTEMPTS, publicationOperationId as operationIdForPublication } from './publication.js'

export interface EffectContext {
  readonly effectId: string
  /** Pass unchanged to a provider that supports durable idempotency keys. */
  readonly idempotencyKey: string
  readonly event: FinalEvent
  /** Cooperative provider cancellation; an aborted call still has an uncertain external outcome. */
  readonly signal: AbortSignal
  readonly deadlineAtMs: number
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
  /** Bound each provider dispatch/reconciliation. Defaults to 60 seconds. */
  readonly timeoutMs?: number
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
  readonly stage: 'prepared' | 'dispatching' | 'result' | 'publication-rejected'
  readonly result: EventPayload | null
  readonly publicationAttempt: number
  readonly publicationRejections: readonly FinalEventPublicationRejection[]
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
  readonly #timeoutMs: number
  readonly #mutex = new Mutex()
  #running = false

  private constructor(options: EffectWorkerOptions) {
    for (const value of [options.sourceId, options.handler.id, options.handler.version]) validateConsumerId(value)
    assertEventTopic(options.resultTopic)
    this.#topics = canonicalTopics(options.handler.topics)
    if (this.#topics.includes(options.resultTopic)) throw new Error('EFFECT_RESULT_TOPIC_IS_INPUT')
    if (options.handler.recovery === 'reconcile' && options.handler.reconcile === undefined) throw new Error('EFFECT_RECONCILER_REQUIRED')
    this.#limit = options.batchLimit ?? 8
    this.#timeoutMs = options.handler.timeoutMs ?? 60_000
    if (!Number.isSafeInteger(this.#timeoutMs) || this.#timeoutMs < 1 || this.#timeoutMs > 300_000) throw new Error('EFFECT_TIMEOUT_INVALID')
    if (!Number.isSafeInteger(this.#limit) || this.#limit < 1 || this.#limit > 64) throw new Error('CONSUMER_BATCH_LIMIT_INVALID')
    this.#options = options
    this.#checkpoint = new CheckpointStore(options.store, {
      id: `effects/${options.handler.id}`,
      binding: encodeCanonicalCbor([4n, 'effects', options.sourceId, options.handler.id, options.handler.version,
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
    readonly effect: (ActiveEffect & { readonly publicationOperationId: string }) | null
  }> {
    return this.#mutex.run(async () => {
      const state = await this.#load()
      return { cursor: state.cursor, revision: state.revision,
        remaining: state.pending === null ? 0 : state.pending.events.length - state.pending.next,
        effect: state.pending?.active == null ? null : { ...structuredClone(state.pending.active),
          publicationOperationId: publicationOperationId(state.pending.active.effectId, state.pending.active.publicationAttempt) } }
    })
  }

  /** One bounded read; useful for resident scheduling and deterministic tests. */
  async processNext(options: { readonly signal?: AbortSignal } = {}): Promise<{ readonly progressed: boolean; readonly hasMore: boolean }> {
    if (this.#running) throw new Error('EFFECT_WORKER_ALREADY_RUNNING')
    return this.#mutex.run(async () => {
      options.signal?.throwIfAborted()
      let state = await this.#load()
      if (state.pending !== null) {
        await this.#finish(state, options.signal)
        return { progressed: true, hasMore: true }
      }
      const batch = await this.#options.source.read({ topics: this.#topics, limit: this.#limit,
        ...(state.cursor === null ? {} : { cursor: state.cursor }) })
      const before = state.cursor
      state = await this.#accept(state, batch)
      await this.#finish(state, options.signal)
      return { progressed: batch.scannedThrough !== before, hasMore: batch.hasMore }
    })
  }

  async run(signal?: AbortSignal): Promise<void> {
    if (this.#running) throw new Error('EFFECT_WORKER_ALREADY_RUNNING')
    this.#running = true
    try {
      const state = await this.#mutex.run(async () => this.#finish(await this.#load(), signal))
      if (signal?.aborted) return
      for await (const batch of this.#options.source.subscribe({ topics: this.#topics, limit: this.#limit,
        ...(state.cursor === null ? {} : { cursor: state.cursor }), ...(signal === undefined ? {} : { signal }) })) {
        if (signal?.aborted) return
        await this.#mutex.run(async () => this.#finish(await this.#accept(await this.#load(), batch), signal))
      }
    } catch (error) {
      // The durable dispatching state remains for explicit recovery. Shutdown
      // cannot infer that cancellation stopped an external provider action.
      if (signal?.aborted !== true) throw error
    } finally { this.#running = false }
  }

  /** Explicit operator/provider reconciliation; it cannot silently discard work. */
  async resolve(effectId: string, result: Exclude<EffectReconciliation, { kind: 'uncertain' }>): Promise<void> {
    await this.#mutex.run(async () => {
      const state = await this.#load(), pending = state.pending
      if (pending?.active?.effectId !== effectId || pending.active.stage !== 'dispatching') throw new Error('EFFECT_NOT_UNCERTAIN')
      const active: ActiveEffect = result.kind === 'completed'
        ? { ...pending.active, stage: 'result', result: clonePayload(result.result) }
        : { ...pending.active, stage: 'prepared', result: null }
      await this.#save({ ...state, pending: { ...pending, active } })
    })
  }

  /** Explicitly reauthor a saved result after proved rejection, without repeating its external effect. */
  async retryPublication(effectId: string): Promise<{ readonly operationId: string }> {
    return this.#mutex.run(async () => {
      const state = await this.#load(), pending = state.pending
      if (pending?.active?.effectId !== effectId || pending.active.stage !== 'publication-rejected') {
        throw new Error('EFFECT_PUBLICATION_NOT_REJECTED')
      }
      const publicationAttempt = pending.active.publicationAttempt + 1
      if (publicationAttempt >= MAX_PUBLICATION_ATTEMPTS) throw new Error('EFFECT_PUBLICATION_ATTEMPTS_EXHAUSTED')
      const active: ActiveEffect = { ...pending.active, stage: 'result', publicationAttempt }
      await this.#save({ ...state, pending: { ...pending, active } })
      return { operationId: publicationOperationId(effectId, publicationAttempt) }
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

  async #finish(input: WorkerState, signal?: AbortSignal): Promise<WorkerState> {
    let state = input
    while (state.pending !== null) {
      signal?.throwIfAborted()
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
        active = { effectId, stage: 'prepared', result: null, publicationAttempt: 0, publicationRejections: [] }
        pending = { ...pending, active }
        state = { ...state, pending }
        await this.#save(state)
      }
      if (active.effectId !== effectId) throw new Error('EFFECT_CHECKPOINT_ID_MISMATCH')
      if (active.stage === 'publication-rejected') {
        const rejection = active.publicationRejections.at(-1)!
        throw new FinalEventPublicationRejectedError(rejection.proposalId, rejection.rejectionCode)
      }
      const context = { effectId, idempotencyKey: effectId, event: cloneFinalEvent(event) }
      if (active.stage === 'dispatching') {
        if (this.#options.handler.recovery === 'manual') throw new EffectUncertainError(effectId)
        if (this.#options.handler.recovery === 'reconcile') {
          let reconciliation: EffectReconciliation
          try { reconciliation = await this.#provider(context, signal, (request) => this.#options.handler.reconcile!(request)) }
          catch (cause) { throw new EffectUncertainError(effectId, cause) }
          if (reconciliation.kind === 'uncertain') throw new EffectUncertainError(effectId)
          active = reconciliation.kind === 'completed'
            ? { ...active, stage: 'result', result: clonePayload(reconciliation.result) }
            : { ...active, stage: 'prepared', result: null }
          pending = { ...pending, active }; state = { ...state, pending }
          await this.#save(state)
        }
      }
      if (active.stage !== 'result') {
        // A crash from this point may have reached the provider. Retrying needs
        // its idempotency guarantee, reconciliation, or explicit resolution.
        active = { ...active, stage: 'dispatching', result: null }
        pending = { ...pending, active }; state = { ...state, pending }
        await this.#save(state)
        let result: EventPayload
        try { result = clonePayload(await this.#provider(context, signal, (request) => this.#options.handler.dispatch(request))) }
        catch (cause) { throw new EffectUncertainError(effectId, cause) }
        active = { ...active, stage: 'result', result }
        pending = { ...pending, active }; state = { ...state, pending }
        await this.#save(state)
      }
      const result: EventPayload = {
        type: 'effect.completed', version: 2, effectId, originEventId: event.id,
        handlerId: this.#options.handler.id, handlerVersion: this.#options.handler.version,
        result: active.result,
        publication: { attempt: active.publicationAttempt, rejections: active.publicationRejections.map(item => ({ ...item })) },
      }
      // Ambiguous publication repeats this exact attempt. Only a proved final
      // rejection authorizes an explicit new identity for the saved result.
      const operationId = publicationOperationId(effectId, active.publicationAttempt)
      try {
        await this.#options.publisher.publishFinal(this.#options.resultTopic, result, { operationId,
          ...(signal === undefined ? {} : { signal }) })
      } catch (error) {
        if (error instanceof FinalEventPublicationRejectedError) {
          validateConsumerId(error.proposalId)
          active = { ...active, stage: 'publication-rejected', publicationRejections: [...active.publicationRejections,
            { attempt: active.publicationAttempt, operationId, proposalId: error.proposalId, rejectionCode: error.rejectionCode }] }
          state = { ...state, pending: { ...pending, active } }
          await this.#save(state)
        }
        throw error
      }
      state = { ...state, pending: { ...pending, next: pending.next + 1, active: null } }
      await this.#save(state)
    }
    return state
  }

  async #provider<T>(context: Omit<EffectContext, 'signal' | 'deadlineAtMs'>, parent: AbortSignal | undefined,
    operation: (context: EffectContext) => Promise<T>): Promise<T> {
    const controller = new AbortController()
    const deadlineAtMs = Date.now() + this.#timeoutMs
    const cancel = (): void => controller.abort(parent?.reason)
    let onAbort: (() => void) | undefined
    const interrupted = new Promise<never>((_resolve, reject) => {
      onAbort = () => reject(new Error('EFFECT_PROVIDER_INTERRUPTED', { cause: controller.signal.reason }))
      controller.signal.addEventListener('abort', onAbort, { once: true })
    })
    parent?.addEventListener('abort', cancel, { once: true })
    const timeout = setTimeout(() => controller.abort(new Error('EFFECT_PROVIDER_DEADLINE_EXCEEDED')), this.#timeoutMs)
    try {
      if (parent?.aborted) cancel()
      // Promise.race observes a late provider rejection without publishing a
      // late result or advancing the checkpoint after the owner has stopped.
      const call = Promise.resolve().then(() => {
        controller.signal.throwIfAborted()
        return operation({ ...context, signal: controller.signal, deadlineAtMs })
      })
      return await Promise.race([call, interrupted])
    } finally {
      clearTimeout(timeout)
      parent?.removeEventListener('abort', cancel)
      if (onAbort !== undefined) controller.signal.removeEventListener('abort', onAbort)
    }
  }

  async #load(): Promise<WorkerState> {
    const checkpoint = await this.#checkpoint.load()
    if (checkpoint === null) return { cursor: null, revision: null, pending: null }
    const value = assertCanonicalCbor(checkpoint.state)
    if (!Array.isArray(value) || value.length !== 2 || value[0] !== 4n) throw new Error('EFFECT_CHECKPOINT_INVALID')
    let pending: PendingBatch | null = null
    if (value[1] !== null) {
      const batch: unknown = value[1]
      if (!Array.isArray(batch) || batch.length !== 5 || !Array.isArray(batch[0]) || typeof batch[1] !== 'string' ||
          typeof batch[2] !== 'string' || typeof batch[3] !== 'bigint' || batch[3] < 0n || batch[3] > BigInt(batch[0].length) ||
          batch[0].length > this.#limit * 64) throw new Error('EFFECT_CHECKPOINT_INVALID')
      const events = batch[0].map(decodeEvent)
      let active: ActiveEffect | null = null
      if (batch[4] !== null) {
        const entry: unknown = batch[4]
        if (!Array.isArray(entry) || entry.length !== 5 || typeof entry[0] !== 'string' ||
            (entry[1] !== 'prepared' && entry[1] !== 'dispatching' && entry[1] !== 'result' && entry[1] !== 'publication-rejected') ||
            (entry[2] !== null && typeof entry[2] !== 'string') || typeof entry[3] !== 'bigint' || entry[3] < 0n ||
            entry[3] >= BigInt(MAX_PUBLICATION_ATTEMPTS) || !Array.isArray(entry[4]) ||
            entry[4].length > MAX_PUBLICATION_ATTEMPTS) throw new Error('EFFECT_CHECKPOINT_INVALID')
        const effectId = entry[0], publicationAttempt = Number(entry[3])
        validateConsumerId(effectId)
        const publicationRejections = decodePublicationRejections(entry[4], attempt => publicationOperationId(effectId, attempt))
        const hasResult = entry[1] === 'result' || entry[1] === 'publication-rejected'
        if (publicationRejections.length !== publicationAttempt + (entry[1] === 'publication-rejected' ? 1 : 0) ||
            (hasResult ? typeof entry[2] !== 'string' : entry[2] !== null || publicationAttempt !== 0)) {
          throw new Error('EFFECT_CHECKPOINT_INVALID')
        }
        active = { effectId, stage: entry[1] as ActiveEffect['stage'], result: entry[2] === null ? null : parsePayload(entry[2] as string),
          publicationAttempt, publicationRejections }
      }
      pending = { events, scannedThrough: batch[1], revision: batch[2], next: Number(batch[3]), active }
    }
    return { cursor: checkpoint.cursor, revision: checkpoint.revision, pending }
  }

  async #save(state: WorkerState): Promise<void> {
    const p = state.pending
    const batch: CborValue = p === null ? null : [p.events.map(encodeEvent), p.scannedThrough, p.revision, BigInt(p.next),
      p.active === null ? null : [p.active.effectId, p.active.stage,
        p.active.stage === 'result' || p.active.stage === 'publication-rejected' ? canonicalEventPayload(p.active.result) : null,
        BigInt(p.active.publicationAttempt), encodePublicationRejections(p.active.publicationRejections)]]
    await this.#checkpoint.commit({ cursor: state.cursor, revision: state.revision, state: encodeCanonicalCbor([4n, batch]) })
  }
}

function publicationOperationId(effectId: string, attempt: number): string { return operationIdForPublication('effect-result', effectId, attempt) }

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
  return [event.id, event.proposalId, BigInt(event.eventOrdinal), event.topic, canonicalEventPayload(event.payload),
    encodeEventOrigin(event.origin)]
}
function decodeEvent(value: CborValue): FinalEvent {
  if (!Array.isArray(value) || value.length !== 6 || typeof value[0] !== 'string' || typeof value[1] !== 'string' ||
      typeof value[2] !== 'bigint' || typeof value[3] !== 'string' || typeof value[4] !== 'string') throw new Error('EFFECT_CHECKPOINT_INVALID')
  return cloneFinalEvent({ id: value[0], proposalId: value[1], eventOrdinal: Number(value[2]), topic: value[3], payload: parsePayload(value[4]),
    origin: decodeEventOrigin(value[5]) })
}

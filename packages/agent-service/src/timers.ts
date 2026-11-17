import { bytesToHex, sha256 } from '@chronolog/canonical'
import { Mutex } from '@chronolog/node-core/browser'
import type { DurableOperationStore } from '@chronolog/node-core'
import { assertCanonicalCbor, assertEventTopic, canonicalEventPayload, cloneEventOrigin, encodeCanonicalCbor } from '@chronolog/protocol'
import type { CborValue, ChronologEventOrigin, EventPayload } from '@chronolog/protocol'

import { CheckpointStore } from './checkpoint.js'
import { decodeEventOrigin, encodeEventOrigin } from './event-origin.js'
import { batchEvents, FinalEventPublicationRejectedError, validateConsumerId } from './event-source.js'
import type { FinalEvent, FinalEventPublicationRejection, FinalEventSource } from './event-source.js'
import { decodePublicationRejections, encodePublicationRejections, MAX_PUBLICATION_ATTEMPTS, publicationOperationId } from './publication.js'
import { waitForAbortableDelay } from './service.js'

export interface TimerOccurrence {
  readonly type: 'timer.fired'
  readonly version: 2
  readonly timerId: string
  /** Caller allocates this identity before the SQL + emit schedule program. */
  readonly generation: string
  /** Original final configuration event, preserved as audit provenance. */
  readonly configurationEventId: string
  /** Verified configuration provenance; the fired event itself is authored by the scheduler. */
  readonly configurationOrigin: ChronologEventOrigin
  readonly occurrenceId: string
  readonly scheduledAtMs: number
  readonly observedAtMs: number
  readonly payload: EventPayload
  readonly publication: {
    readonly attempt: number
    readonly rejections: readonly FinalEventPublicationRejection[]
  }
}

type ScheduledOccurrence = Omit<TimerOccurrence, 'publication'>
interface PendingTimerOccurrence {
  readonly occurrence: ScheduledOccurrence
  readonly stage: 'publishing' | 'publication-rejected'
  readonly publicationAttempt: number
  readonly publicationRejections: readonly FinalEventPublicationRejection[]
}
export interface TimerPublicationStatus {
  readonly occurrenceId: string
  readonly configurationEventId: string
  readonly configurationOrigin: ChronologEventOrigin
  readonly stage: 'publishing' | 'publication-rejected' | 'accepted' | 'cancelled'
  readonly publicationAttempt: number
  readonly publicationOperationId: string
  readonly publicationRejections: readonly FinalEventPublicationRejection[]
}

export interface TimerOccurrencePublisher {
  /**
   * Atomically validate that generation is still the active schedule and
   * publish the occurrence, then resolve its final accepted/cancelled outcome.
   * A mixed SQL assertion + emit is one implementation. A local-only check is
   * insufficient: a final cancellation may race the timer's clock observation.
   * Exact accepted retries retain their result after a later cancellation.
   * Only a verified final rejection may throw FinalEventPublicationRejectedError;
   * ambiguous transport failure must preserve this operation's exact retry.
   *
   * Authorize the derived action against configurationOrigin, not payload role
   * claims or the scheduler's own tool permissions. Keep original final outcomes
   * on retry; a current policy denial cannot rewrite an earlier publication.
   */
  publishOccurrence(occurrence: TimerOccurrence, options: { readonly operationId: string; readonly signal?: AbortSignal }): Promise<'accepted' | 'cancelled'>
}

export interface TimerSchedulerOptions {
  readonly id: string
  readonly sourceId: string
  readonly configurationTopic: string
  readonly store: DurableOperationStore
  readonly source: FinalEventSource
  readonly publisher: TimerOccurrencePublisher
  readonly now?: () => number
  readonly maxTimers?: number
  readonly maxOccurrencesPerTick?: number
  readonly pollMs?: number
}

interface Schedule {
  readonly timerId: string
  readonly generation: string
  readonly configurationEventId: string
  readonly configurationOrigin: ChronologEventOrigin
  readonly nextDueAtMs: number
  readonly intervalMs: number | null
  readonly payload: EventPayload
  readonly cancelled: boolean
}
interface TimerState {
  readonly cursor: string | null
  readonly revision: string | null
  readonly schedules: ReadonlyMap<string, Schedule>
  readonly pending: PendingTimerOccurrence | null
}

/** Durable wall-clock scheduling; timers author final intent, never call tools. */
export class DurableTimerScheduler {
  readonly #options: TimerSchedulerOptions
  readonly #checkpoint: CheckpointStore
  readonly #mutex = new Mutex()
  readonly #maxTimers: number
  readonly #maxPerTick: number
  readonly #pollMs: number
  #running = false

  private constructor(options: TimerSchedulerOptions) {
    validateConsumerId(options.id); validateConsumerId(options.sourceId); assertEventTopic(options.configurationTopic)
    this.#options = options
    this.#maxTimers = options.maxTimers ?? 4096
    this.#maxPerTick = options.maxOccurrencesPerTick ?? 32
    this.#pollMs = options.pollMs ?? 250
    for (const bound of [this.#maxTimers, this.#maxPerTick, this.#pollMs]) {
      if (!Number.isSafeInteger(bound) || bound < 1) throw new Error('TIMER_BOUNDS_INVALID')
    }
    if (this.#maxPerTick > 1024 || this.#pollMs > 60_000) throw new Error('TIMER_BOUNDS_INVALID')
    this.#checkpoint = new CheckpointStore(options.store, { id: `timers/${options.id}`,
      binding: encodeCanonicalCbor([3n, 'timers', options.sourceId, options.id, options.configurationTopic]) })
  }

  static async open(options: TimerSchedulerOptions): Promise<DurableTimerScheduler> {
    const scheduler = new DurableTimerScheduler(options)
    await scheduler.#load()
    return scheduler
  }

  /**
   * Capture time once for a bounded turn. Catch up configuration before selecting
   * new occurrences; a publisher resolves races at the final history boundary.
   */
  async tick(now = this.#options.now?.() ?? Date.now(), signal?: AbortSignal): Promise<{ readonly emitted: number; readonly needsCatchUp: boolean }> {
    assertTimestamp(now)
    return this.#mutex.run(async () => {
      signal?.throwIfAborted()
      let state = await this.#load()
      const batch = await this.#options.source.read({ topics: [this.#options.configurationTopic], limit: 64,
        ...(state.cursor === null ? {} : { cursor: state.cursor }) })
      const events = batchEvents(batch, 64, [this.#options.configurationTopic])
      if (batch.scannedThrough === state.cursor && (batch.hasMore || events.length > 0)) throw new Error('CONSUMER_NO_PROGRESS')
      const schedules = new Map(state.schedules)
      for (const event of events) applyConfiguration(schedules, event)
      if (schedules.size > this.#maxTimers) throw new Error('TIMER_QUOTA_EXCEEDED')
      state = { ...state, schedules, cursor: batch.scannedThrough, revision: batch.revision }
      // Configuration and its processed position are one commit. Pending
      // occurrence bytes survive even if their generation is now cancelled.
      await this.#save(state)
      if (batch.hasMore) return { emitted: 0, needsCatchUp: true }
      let emitted = 0
      for (let handled = 0; handled < this.#maxPerTick; handled += 1) {
        let pending = state.pending
        if (pending?.stage === 'publication-rejected') {
          const rejection = pending.publicationRejections[pending.publicationRejections.length - 1]!
          throw new FinalEventPublicationRejectedError(rejection.proposalId, rejection.rejectionCode)
        }
        if (pending === null) {
          const due = [...state.schedules.values()].filter((timer) => !timer.cancelled && timer.nextDueAtMs <= now)
            .sort((a, b) => a.nextDueAtMs - b.nextDueAtMs || (a.timerId < b.timerId ? -1 : a.timerId > b.timerId ? 1 : 0))[0]
          if (due === undefined) break
          const occurrenceId = `occurrence_${bytesToHex(await sha256(encodeCanonicalCbor([
            'chronolog/timer-occurrence/v1', this.#options.sourceId, due.timerId, due.generation, BigInt(due.nextDueAtMs),
          ])))}`
          pending = { stage: 'publishing', publicationAttempt: 0, publicationRejections: [],
            occurrence: { type: 'timer.fired', version: 2, timerId: due.timerId, generation: due.generation, configurationEventId: due.configurationEventId,
              configurationOrigin: cloneEventOrigin(due.configurationOrigin), occurrenceId, scheduledAtMs: due.nextDueAtMs, observedAtMs: now, payload: due.payload } }
          state = { ...state, pending }
          await this.#save(state)
        }
        const occurrence: TimerOccurrence = { ...pending.occurrence,
          publication: { attempt: pending.publicationAttempt, rejections: pending.publicationRejections } }
        const operationId = timerOperationId(occurrence.occurrenceId, pending.publicationAttempt)
        // An uncertain reply retains the exact operation and payload. Only a
        // proved rejection pauses the attempt for explicit author recovery.
        let result: 'accepted' | 'cancelled'
        try {
          result = await this.#options.publisher.publishOccurrence(structuredClone(occurrence),
            { operationId, ...(signal === undefined ? {} : { signal }) })
        } catch (error) {
          if (!(error instanceof FinalEventPublicationRejectedError)) throw error
          validateConsumerId(error.proposalId)
          pending = { ...pending, stage: 'publication-rejected', publicationRejections: [...pending.publicationRejections,
            { attempt: pending.publicationAttempt, operationId, proposalId: error.proposalId, rejectionCode: error.rejectionCode }] }
          await this.#savePublicationStatus(publicationStatus(pending))
          await this.#save({ ...state, pending })
          throw error
        }
        if (result !== 'accepted' && result !== 'cancelled') throw new Error('TIMER_PUBLICATION_OUTCOME_INVALID')
        // Preserve rejection history even when cancellation legitimately emits
        // no timer event. A lost audit/checkpoint reply still retries this exact
        // guarded program; it cannot allocate another occurrence.
        await this.#savePublicationStatus({ ...publicationStatus(pending), stage: result })
        if (result === 'accepted') emitted += 1
        const updated = new Map(state.schedules)
        const timer = updated.get(occurrence.timerId)
        if (timer?.generation === occurrence.generation && timer.nextDueAtMs === occurrence.scheduledAtMs) {
          const next = result === 'cancelled' || timer.intervalMs === null ? null : timer.nextDueAtMs + timer.intervalMs
          if (next !== null) assertTimestamp(next)
          updated.set(timer.timerId, { ...timer, nextDueAtMs: next ?? timer.nextDueAtMs,
            cancelled: timer.cancelled || result === 'cancelled' || next === null })
        }
        state = { ...state, schedules: updated, pending: null }
        await this.#save(state)
      }
      return { emitted, needsCatchUp: false }
    })
  }

  /** Allocate a new guarded publication only after a proved final rejection. */
  async retryPublication(occurrenceId: string): Promise<{ readonly operationId: string }> {
    validateConsumerId(occurrenceId)
    return this.#mutex.run(async () => {
      const state = await this.#load(), pending = state.pending
      if (pending?.occurrence.occurrenceId !== occurrenceId || pending.stage !== 'publication-rejected') {
        throw new Error('TIMER_PUBLICATION_NOT_REJECTED')
      }
      const publicationAttempt = pending.publicationAttempt + 1
      if (publicationAttempt >= MAX_PUBLICATION_ATTEMPTS) throw new Error('TIMER_PUBLICATION_ATTEMPTS_EXHAUSTED')
      await this.#save({ ...state, pending: { ...pending, stage: 'publishing', publicationAttempt } })
      return { operationId: timerOperationId(occurrenceId, publicationAttempt) }
    })
  }

  async run(signal?: AbortSignal): Promise<void> {
    if (this.#running) throw new Error('TIMER_SCHEDULER_ALREADY_RUNNING')
    this.#running = true
    try {
      while (signal?.aborted !== true) {
        const result = await this.tick(this.#options.now?.() ?? Date.now(), signal)
        if (!result.needsCatchUp) await waitForAbortableDelay(this.#pollMs, signal)
      }
    } finally { this.#running = false }
  }

  async status(): Promise<{ readonly cursor: string | null; readonly active: number;
    readonly pending: (PendingTimerOccurrence & { readonly publicationOperationId: string }) | null }> {
    return this.#mutex.run(async () => {
      const state = await this.#load()
      return { cursor: state.cursor, active: [...state.schedules.values()].filter((timer) => !timer.cancelled).length,
        pending: state.pending === null ? null : structuredClone({ ...state.pending,
          publicationOperationId: timerOperationId(state.pending.occurrence.occurrenceId, state.pending.publicationAttempt) }) }
    })
  }

  /** Local attempt audit survives terminal cancellation, which emits no occurrence. */
  async publicationStatus(occurrenceId: string): Promise<TimerPublicationStatus | null> {
    validateConsumerId(occurrenceId)
    return this.#mutex.run(async () => {
      const state = await this.#load()
      if (state.pending?.occurrence.occurrenceId === occurrenceId) return structuredClone(publicationStatus(state.pending))
      const bytes = await this.#options.store.get(this.#publicationKey(occurrenceId))
      if (bytes === null) return null
      const value = assertCanonicalCbor(bytes)
      if (!Array.isArray(value) || value.length !== 10 || value[0] !== 2n || value[1] !== this.#options.sourceId ||
          value[2] !== this.#options.id || value[3] !== this.#options.configurationTopic || value[4] !== occurrenceId ||
          (value[5] !== 'publication-rejected' && value[5] !== 'accepted' && value[5] !== 'cancelled') ||
          typeof value[6] !== 'bigint' || value[6] < 0n || value[6] >= BigInt(MAX_PUBLICATION_ATTEMPTS) ||
          typeof value[8] !== 'string') {
        throw new Error('TIMER_PUBLICATION_AUDIT_INVALID')
      }
      const attempt = Number(value[6]), rejections = decodePublicationRejections(value[7], index => timerOperationId(occurrenceId, index))
      if (rejections.length !== attempt + (value[5] === 'publication-rejected' ? 1 : 0)) throw new Error('TIMER_PUBLICATION_AUDIT_INVALID')
      validateConsumerId(value[8])
      return { occurrenceId, configurationEventId: value[8], configurationOrigin: decodeEventOrigin(value[9]),
        stage: value[5] as TimerPublicationStatus['stage'], publicationAttempt: attempt,
        publicationOperationId: timerOperationId(occurrenceId, attempt), publicationRejections: rejections }
    })
  }

  #publicationKey(occurrenceId: string): string {
    return `agent/timer-publication/${encodeURIComponent(this.#options.id)}/${encodeURIComponent(occurrenceId)}`
  }

  async #savePublicationStatus(status: TimerPublicationStatus): Promise<void> {
    await this.#options.store.put(this.#publicationKey(status.occurrenceId), encodeCanonicalCbor([
      2n, this.#options.sourceId, this.#options.id, this.#options.configurationTopic, status.occurrenceId, status.stage,
      BigInt(status.publicationAttempt), encodePublicationRejections(status.publicationRejections),
      status.configurationEventId, encodeEventOrigin(status.configurationOrigin),
    ]))
  }

  async #load(): Promise<TimerState> {
    const checkpoint = await this.#checkpoint.load()
    if (checkpoint === null) return { cursor: null, revision: null, schedules: new Map(), pending: null }
    const value = assertCanonicalCbor(checkpoint.state)
    if (!Array.isArray(value) || value.length !== 3 || value[0] !== 3n || !Array.isArray(value[1]) || value[1].length > this.#maxTimers) {
      throw new Error('TIMER_CHECKPOINT_INVALID')
    }
    const schedules = new Map<string, Schedule>()
    for (const row of value[1]) {
      if (!Array.isArray(row) || row.length !== 8 || typeof row[0] !== 'string' || typeof row[1] !== 'string' || typeof row[2] !== 'string' ||
          typeof row[3] !== 'bigint' || (row[4] !== null && typeof row[4] !== 'bigint') ||
          typeof row[5] !== 'string' || typeof row[6] !== 'boolean') throw new Error('TIMER_CHECKPOINT_INVALID')
      const schedule: Schedule = { timerId: row[0], generation: row[1], configurationEventId: row[2], nextDueAtMs: Number(row[3]),
        intervalMs: row[4] === null ? null : Number(row[4]), payload: parsePayload(row[5]), cancelled: row[6], configurationOrigin: decodeEventOrigin(row[7]) }
      validateConsumerId(schedule.timerId); validateConsumerId(schedule.generation); validateConsumerId(schedule.configurationEventId); assertTimestamp(schedule.nextDueAtMs)
      if (schedule.intervalMs !== null && (!Number.isSafeInteger(schedule.intervalMs) || schedule.intervalMs < 1)) throw new Error('TIMER_CHECKPOINT_INVALID')
      if (schedules.has(schedule.timerId)) throw new Error('TIMER_CHECKPOINT_INVALID')
      schedules.set(schedule.timerId, schedule)
    }
    let pending: PendingTimerOccurrence | null = null
    if (value[2] !== null) {
      const row: unknown = value[2]
      if (!Array.isArray(row) || row.length !== 4 || (row[0] !== 'publishing' && row[0] !== 'publication-rejected') ||
          typeof row[2] !== 'bigint' || row[2] < 0n || row[2] >= BigInt(MAX_PUBLICATION_ATTEMPTS)) throw new Error('TIMER_CHECKPOINT_INVALID')
      const occurrence = decodeOccurrence(row[1]), publicationAttempt = Number(row[2])
      const publicationRejections = decodePublicationRejections(row[3], attempt => timerOperationId(occurrence.occurrenceId, attempt))
      if (publicationRejections.length !== publicationAttempt + (row[0] === 'publication-rejected' ? 1 : 0)) throw new Error('TIMER_CHECKPOINT_INVALID')
      pending = { occurrence, stage: row[0] as PendingTimerOccurrence['stage'], publicationAttempt, publicationRejections }
    }
    return { cursor: checkpoint.cursor, revision: checkpoint.revision, schedules, pending }
  }

  async #save(state: TimerState): Promise<void> {
    await this.#checkpoint.commit({ cursor: state.cursor, revision: state.revision, state: encodeCanonicalCbor([
      3n, [...state.schedules.values()].sort((a, b) => (a.timerId < b.timerId ? -1 : a.timerId > b.timerId ? 1 : 0)).map((timer) => [
        timer.timerId, timer.generation, timer.configurationEventId, BigInt(timer.nextDueAtMs), timer.intervalMs === null ? null : BigInt(timer.intervalMs),
        canonicalEventPayload(timer.payload), timer.cancelled, encodeEventOrigin(timer.configurationOrigin),
      ]), state.pending === null ? null : [state.pending.stage, encodeOccurrence(state.pending.occurrence),
        BigInt(state.pending.publicationAttempt), encodePublicationRejections(state.pending.publicationRejections)],
    ]) })
  }
}

function applyConfiguration(schedules: Map<string, Schedule>, event: FinalEvent): void {
  const payload = event.payload
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('TIMER_CONFIGURATION_INVALID')
  const fields = payload as { readonly [key: string]: EventPayload }
  if (fields.version !== 1 || typeof fields.timerId !== 'string' || typeof fields.generation !== 'string') throw new Error('TIMER_CONFIGURATION_INVALID')
  validateConsumerId(fields.timerId); validateConsumerId(fields.generation)
  if (fields.type === 'timer.scheduled') {
    if (typeof fields.dueAtMs !== 'number' || (fields.intervalMs !== undefined && fields.intervalMs !== null &&
        (typeof fields.intervalMs !== 'number' || !Number.isSafeInteger(fields.intervalMs) || fields.intervalMs < 1))) {
      throw new Error('TIMER_CONFIGURATION_INVALID')
    }
    assertTimestamp(fields.dueAtMs)
    schedules.set(fields.timerId, { timerId: fields.timerId, generation: fields.generation, configurationEventId: event.id, nextDueAtMs: fields.dueAtMs,
      configurationOrigin: cloneEventOrigin(event.origin),
      intervalMs: typeof fields.intervalMs === 'number' ? fields.intervalMs : null,
      payload: parsePayload(canonicalEventPayload(fields.payload ?? null)), cancelled: false })
  } else if (fields.type === 'timer.cancelled') {
    const timer = schedules.get(fields.timerId)
    if (timer?.generation === fields.generation) schedules.set(timer.timerId, { ...timer, cancelled: true })
  } else throw new Error('TIMER_CONFIGURATION_INVALID')
}

function assertTimestamp(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('TIMER_TIME_INVALID')
}
function parsePayload(value: string): EventPayload {
  const parsed = JSON.parse(value) as EventPayload
  if (canonicalEventPayload(parsed) !== value) throw new Error('TIMER_PAYLOAD_INVALID')
  return parsed
}
function timerOperationId(occurrenceId: string, attempt: number): string { return publicationOperationId('timer-occurrence', occurrenceId, attempt) }
function publicationStatus(pending: PendingTimerOccurrence): TimerPublicationStatus {
  return { occurrenceId: pending.occurrence.occurrenceId, configurationEventId: pending.occurrence.configurationEventId,
    configurationOrigin: cloneEventOrigin(pending.occurrence.configurationOrigin), stage: pending.stage, publicationAttempt: pending.publicationAttempt,
    publicationOperationId: timerOperationId(pending.occurrence.occurrenceId, pending.publicationAttempt), publicationRejections: pending.publicationRejections }
}
function encodeOccurrence(value: ScheduledOccurrence): CborValue {
  return [value.timerId, value.generation, value.configurationEventId, value.occurrenceId, BigInt(value.scheduledAtMs), BigInt(value.observedAtMs), canonicalEventPayload(value.payload), encodeEventOrigin(value.configurationOrigin)]
}
function decodeOccurrence(value: unknown): ScheduledOccurrence {
  if (!Array.isArray(value) || value.length !== 8 || typeof value[0] !== 'string' || typeof value[1] !== 'string' ||
      typeof value[2] !== 'string' || typeof value[3] !== 'string' || typeof value[4] !== 'bigint' || typeof value[5] !== 'bigint' || typeof value[6] !== 'string') {
    throw new Error('TIMER_CHECKPOINT_INVALID')
  }
  const occurrence: ScheduledOccurrence = { type: 'timer.fired', version: 2, timerId: value[0], generation: value[1], configurationEventId: value[2], occurrenceId: value[3],
    scheduledAtMs: Number(value[4]), observedAtMs: Number(value[5]), payload: parsePayload(value[6]), configurationOrigin: decodeEventOrigin(value[7]) }
  validateScheduledOccurrence(occurrence)
  return occurrence
}

function validateScheduledOccurrence(value: ScheduledOccurrence): void {
  if (value.type !== 'timer.fired' || value.version !== 2) throw new Error('TIMER_OCCURRENCE_INVALID')
  for (const id of [value.timerId, value.generation, value.configurationEventId, value.occurrenceId]) validateConsumerId(id)
  assertTimestamp(value.scheduledAtMs); assertTimestamp(value.observedAtMs)
  if (value.observedAtMs < value.scheduledAtMs) throw new Error('TIMER_TIME_INVALID')
  canonicalEventPayload(value.payload)
  cloneEventOrigin(value.configurationOrigin)
}

export function validateTimerOccurrence(value: TimerOccurrence): void {
  validateScheduledOccurrence(value)
  const publication = value.publication
  if (publication === undefined || !Number.isSafeInteger(publication.attempt) || publication.attempt < 0 ||
      publication.attempt >= MAX_PUBLICATION_ATTEMPTS || !Array.isArray(publication.rejections) ||
      publication.rejections.length !== publication.attempt) throw new Error('TIMER_PUBLICATION_AUDIT_INVALID')
  for (const [attempt, rejection] of (publication.rejections as readonly FinalEventPublicationRejection[]).entries()) {
    if (rejection.attempt !== attempt || rejection.operationId !== timerOperationId(value.occurrenceId, attempt) ||
        (rejection.rejectionCode !== null && typeof rejection.rejectionCode !== 'string')) throw new Error('TIMER_PUBLICATION_AUDIT_INVALID')
    validateConsumerId(rejection.proposalId)
  }
}

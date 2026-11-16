import { bytesToHex, sha256 } from '@chronolog/canonical'
import { Mutex } from '@chronolog/node-core/browser'
import type { DurableOperationStore } from '@chronolog/node-core'
import { assertCanonicalCbor, assertEventTopic, canonicalEventPayload, encodeCanonicalCbor } from '@chronolog/protocol'
import type { CborValue, EventPayload } from '@chronolog/protocol'

import { CheckpointStore } from './checkpoint.js'
import { batchEvents, validateConsumerId } from './event-source.js'
import type { FinalEvent, FinalEventSource } from './event-source.js'
import { waitForAbortableDelay } from './service.js'

export interface TimerOccurrence {
  readonly type: 'timer.fired'
  readonly version: 1
  readonly timerId: string
  /** The original final schedule event is the cancellation/fencing generation. */
  readonly scheduleEventId: string
  readonly occurrenceId: string
  readonly scheduledAtMs: number
  readonly observedAtMs: number
  readonly payload: EventPayload
}

export interface TimerOccurrencePublisher {
  /**
   * Atomically validate that scheduleEventId is still the active generation and
   * publish the occurrence, then resolve its final accepted/cancelled outcome.
   * A mixed SQL assertion + emit is one implementation. A local-only check is
   * insufficient: a final cancellation may race the timer's clock observation.
   * Exact accepted retries retain their result after a later cancellation.
   */
  publishOccurrence(occurrence: TimerOccurrence, options: { readonly operationId: string }): Promise<'accepted' | 'cancelled'>
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
  readonly scheduleEventId: string
  readonly nextDueAtMs: number
  readonly intervalMs: number | null
  readonly payload: EventPayload
  readonly cancelled: boolean
}
interface TimerState {
  readonly cursor: string | null
  readonly revision: string | null
  readonly schedules: ReadonlyMap<string, Schedule>
  readonly pending: TimerOccurrence | null
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
      binding: encodeCanonicalCbor([1n, 'timers', options.sourceId, options.id, options.configurationTopic]) })
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
  async tick(now = this.#options.now?.() ?? Date.now()): Promise<{ readonly emitted: number; readonly needsCatchUp: boolean }> {
    assertTimestamp(now)
    return this.#mutex.run(async () => {
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
        let occurrence = state.pending
        if (occurrence === null) {
          const due = [...state.schedules.values()].filter((timer) => !timer.cancelled && timer.nextDueAtMs <= now)
            .sort((a, b) => a.nextDueAtMs - b.nextDueAtMs || a.timerId.localeCompare(b.timerId))[0]
          if (due === undefined) break
          const occurrenceId = `occurrence_${bytesToHex(await sha256(encodeCanonicalCbor([
            'chronolog/timer-occurrence/v1', this.#options.sourceId, due.timerId, due.scheduleEventId, BigInt(due.nextDueAtMs),
          ])))}`
          occurrence = { type: 'timer.fired', version: 1, timerId: due.timerId, scheduleEventId: due.scheduleEventId,
            occurrenceId, scheduledAtMs: due.nextDueAtMs, observedAtMs: now, payload: due.payload }
          state = { ...state, pending: occurrence }
          await this.#save(state)
        }
        // This final result, including a rejection, is stable for exact retries.
        const result = await this.#options.publisher.publishOccurrence(structuredClone(occurrence),
          { operationId: `timer-occurrence:${occurrence.occurrenceId}` })
        if (result !== 'accepted' && result !== 'cancelled') throw new Error('TIMER_PUBLICATION_OUTCOME_INVALID')
        if (result === 'accepted') emitted += 1
        const updated = new Map(state.schedules)
        const timer = updated.get(occurrence.timerId)
        if (timer?.scheduleEventId === occurrence.scheduleEventId && timer.nextDueAtMs === occurrence.scheduledAtMs) {
          const next = timer.intervalMs === null ? null : timer.nextDueAtMs + timer.intervalMs
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

  async run(signal?: AbortSignal): Promise<void> {
    if (this.#running) throw new Error('TIMER_SCHEDULER_ALREADY_RUNNING')
    this.#running = true
    try {
      while (signal?.aborted !== true) {
        const result = await this.tick()
        if (!result.needsCatchUp) await waitForAbortableDelay(this.#pollMs, signal)
      }
    } finally { this.#running = false }
  }

  async status(): Promise<{ readonly cursor: string | null; readonly active: number; readonly pending: TimerOccurrence | null }> {
    return this.#mutex.run(async () => {
      const state = await this.#load()
      return { cursor: state.cursor, active: [...state.schedules.values()].filter((timer) => !timer.cancelled).length,
        pending: structuredClone(state.pending) }
    })
  }

  async #load(): Promise<TimerState> {
    const checkpoint = await this.#checkpoint.load()
    if (checkpoint === null) return { cursor: null, revision: null, schedules: new Map(), pending: null }
    const value = assertCanonicalCbor(checkpoint.state)
    if (!Array.isArray(value) || value.length !== 3 || value[0] !== 1n || !Array.isArray(value[1]) || value[1].length > this.#maxTimers) {
      throw new Error('TIMER_CHECKPOINT_INVALID')
    }
    const schedules = new Map<string, Schedule>()
    for (const row of value[1]) {
      if (!Array.isArray(row) || row.length !== 7 || typeof row[0] !== 'string' || typeof row[1] !== 'string' ||
          typeof row[2] !== 'bigint' || (row[3] !== null && typeof row[3] !== 'bigint') ||
          typeof row[4] !== 'string' || typeof row[5] !== 'boolean' || row[6] !== 1n) throw new Error('TIMER_CHECKPOINT_INVALID')
      const schedule: Schedule = { timerId: row[0], scheduleEventId: row[1], nextDueAtMs: Number(row[2]),
        intervalMs: row[3] === null ? null : Number(row[3]), payload: parsePayload(row[4]), cancelled: row[5] }
      validateConsumerId(schedule.timerId); validateConsumerId(schedule.scheduleEventId); assertTimestamp(schedule.nextDueAtMs)
      if (schedule.intervalMs !== null && (!Number.isSafeInteger(schedule.intervalMs) || schedule.intervalMs < 1)) throw new Error('TIMER_CHECKPOINT_INVALID')
      if (schedules.has(schedule.timerId)) throw new Error('TIMER_CHECKPOINT_INVALID')
      schedules.set(schedule.timerId, schedule)
    }
    const pending = value[2] === null ? null : decodeOccurrence(value[2])
    return { cursor: checkpoint.cursor, revision: checkpoint.revision, schedules, pending }
  }

  async #save(state: TimerState): Promise<void> {
    await this.#checkpoint.commit({ cursor: state.cursor, revision: state.revision, state: encodeCanonicalCbor([
      1n, [...state.schedules.values()].sort((a, b) => a.timerId.localeCompare(b.timerId)).map((timer) => [
        timer.timerId, timer.scheduleEventId, BigInt(timer.nextDueAtMs), timer.intervalMs === null ? null : BigInt(timer.intervalMs),
        canonicalEventPayload(timer.payload), timer.cancelled, 1n,
      ]), state.pending === null ? null : encodeOccurrence(state.pending),
    ]) })
  }
}

function applyConfiguration(schedules: Map<string, Schedule>, event: FinalEvent): void {
  const payload = event.payload
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('TIMER_CONFIGURATION_INVALID')
  const fields = payload as { readonly [key: string]: EventPayload }
  if (typeof fields.timerId !== 'string') throw new Error('TIMER_CONFIGURATION_INVALID')
  validateConsumerId(fields.timerId)
  if (fields.type === 'timer.scheduled') {
    if (typeof fields.dueAtMs !== 'number' || (fields.intervalMs !== undefined && fields.intervalMs !== null &&
        (typeof fields.intervalMs !== 'number' || !Number.isSafeInteger(fields.intervalMs) || fields.intervalMs < 1))) {
      throw new Error('TIMER_CONFIGURATION_INVALID')
    }
    assertTimestamp(fields.dueAtMs)
    schedules.set(fields.timerId, { timerId: fields.timerId, scheduleEventId: event.id, nextDueAtMs: fields.dueAtMs,
      intervalMs: typeof fields.intervalMs === 'number' ? fields.intervalMs : null,
      payload: parsePayload(canonicalEventPayload(fields.payload ?? null)), cancelled: false })
  } else if (fields.type === 'timer.cancelled') {
    if (typeof fields.scheduleEventId !== 'string') throw new Error('TIMER_CONFIGURATION_INVALID')
    const timer = schedules.get(fields.timerId)
    if (timer?.scheduleEventId === fields.scheduleEventId) schedules.set(timer.timerId, { ...timer, cancelled: true })
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
function encodeOccurrence(value: TimerOccurrence): CborValue {
  return [value.timerId, value.scheduleEventId, value.occurrenceId, BigInt(value.scheduledAtMs), BigInt(value.observedAtMs), canonicalEventPayload(value.payload)]
}
function decodeOccurrence(value: unknown): TimerOccurrence {
  if (!Array.isArray(value) || value.length !== 6 || typeof value[0] !== 'string' || typeof value[1] !== 'string' ||
      typeof value[2] !== 'string' || typeof value[3] !== 'bigint' || typeof value[4] !== 'bigint' || typeof value[5] !== 'string') {
    throw new Error('TIMER_CHECKPOINT_INVALID')
  }
  for (const id of [value[0], value[1], value[2]]) validateConsumerId(id)
  assertTimestamp(Number(value[3])); assertTimestamp(Number(value[4]))
  return { type: 'timer.fired', version: 1, timerId: value[0], scheduleEventId: value[1], occurrenceId: value[2],
    scheduledAtMs: Number(value[3]), observedAtMs: Number(value[4]), payload: parsePayload(value[5]) }
}

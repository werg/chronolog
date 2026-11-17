import type { ChronologNode } from '@chronolog/node-core'
import { assertEventTopic, canonicalEventPayload, emit, program, sqlStatement, type ChangeProgram } from '@chronolog/protocol'
import type { EventPayload } from '@chronolog/protocol'
import { ChangeSignal } from '@chronolog/records'

import { assertChronologicalHistory, validateConsumerId } from './event-source.js'
import { validateTimerOccurrence, type TimerOccurrence, type TimerOccurrencePublisher } from './timers.js'

export interface SqlTimerSchedule {
  readonly timerId: string
  /** Allocate once before authoring; never reuse a generation for another schedule. */
  readonly generation: string
  readonly dueAtMs: number
  readonly intervalMs?: number | null
  readonly payload?: EventPayload
}
export interface SqlTimerChangeOptions { readonly operationId: string; readonly signal?: AbortSignal }
export interface SqlTimerPublisher extends TimerOccurrencePublisher {
  /** Install the explicit application schema under one stable operation identity. */
  initialize(options: SqlTimerChangeOptions): Promise<string>
  /** null requires an absent timer; replacement binds the exact previous generation. */
  schedule(value: SqlTimerSchedule, options: SqlTimerChangeOptions & { readonly expectedGeneration: string | null }): Promise<string>
  cancel(value: { readonly timerId: string; readonly generation: string }, options: SqlTimerChangeOptions): Promise<string>
}
export class SqlTimerRejectedError extends Error {
  constructor(readonly proposalId: string, readonly rejectionCode: string | null, readonly failingStatementIndex: number | null) {
    super(`Timer program rejected: ${rejectionCode ?? 'unknown'}${failingStatementIndex === null ? '' : ` at step ${failingStatementIndex}`}`)
    this.name = 'SqlTimerRejectedError'
  }
}

type TimerNode = Pick<ChronologNode, 'publish' | 'operation' | 'revisions' | 'revision' | 'events'>
type FinalOutcome = NonNullable<NonNullable<Awaited<ReturnType<TimerNode['operation']>>>['outcome']>
const MAX_TIME = Number.MAX_SAFE_INTEGER
function timestamp(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('TIMER_TIME_INVALID')
}

/**
 * Concrete native timer publication over the ordinary public SQL + emit model.
 * Configuration, cancellation and occurrence admission all share the same final
 * history. No local clock check, provider action, or Cloudflare authority enters
 * SQL execution. The daemon must keep its authority/replication loops running
 * while these methods wait for finality.
 */
export function createSqlTimerPublisher(options: {
  readonly node: TimerNode
  readonly configurationTopic: string
  readonly occurrenceTopic: string
  readonly tablePrefix?: string
}): SqlTimerPublisher {
  const { node, configurationTopic, occurrenceTopic } = options
  assertChronologicalHistory(node.events)
  assertEventTopic(configurationTopic); assertEventTopic(occurrenceTopic)
  if (configurationTopic === occurrenceTopic) throw new Error('TIMER_TOPICS_MUST_DIFFER')
  const prefix = options.tablePrefix ?? 'agent'
  if (!/^[a-z][a-z0-9_]{0,47}$/.test(prefix)) throw new Error('TIMER_TABLE_PREFIX_INVALID')
  const heads = `${prefix}_timer_heads`, generations = `${prefix}_timer_generations`, occurrences = `${prefix}_timer_occurrences`
  const submit = async (change: ChangeProgram, changeOptions: SqlTimerChangeOptions): Promise<{ proposalId: string; outcome: FinalOutcome }> => {
    const operationId = changeOptions.operationId, signal = changeOptions.signal
    if (typeof operationId !== 'string' || !/^[A-Za-z0-9_.:-]{1,200}$/.test(operationId)) throw new Error('TIMER_OPERATION_ID_INVALID')
    signal?.throwIfAborted()
    const receipt = await node.publish({ program: change, operationId })
    // Subscribe before reading the current outcome, so finality during a durable
    // journal lookup cannot leave the caller waiting for a future unrelated write.
    const stop = new AbortController()
    const abort = (): void => stop.abort(signal?.reason)
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
    const changed = new ChangeSignal()
    let ended = false, failure: unknown
    const watch = (async () => {
      try { for await (const _revision of node.revisions(node.revision, stop.signal)) changed.notify() }
      catch (error) { failure = error }
      finally { ended = true; changed.close() }
    })()
    try {
      while (true) {
        signal?.throwIfAborted()
        const version = changed.version
        const state = await node.operation(operationId)
        if (state?.proposalId !== receipt.txIdText) throw new Error('TIMER_OPERATION_RECEIPT_MISMATCH')
        if (state.final && state.outcome !== null) return { proposalId: state.proposalId, outcome: state.outcome }
        if (ended) {
          signal?.throwIfAborted()
          throw new Error('TIMER_FINALITY_UNAVAILABLE', { cause: failure })
        }
        // A revision is a wake hint, not a durable event. Drain and coalesce it
        // independently while the operation journal is read from storage.
        await changed.wait(version, stop.signal)
      }
    } finally {
      stop.abort(); signal?.removeEventListener('abort', abort)
      await watch
    }
  }
  const accepted = async (change: ChangeProgram, changeOptions: SqlTimerChangeOptions): Promise<string> => {
    const result = await submit(change, changeOptions)
    if (result.outcome.outcome === 'rejected') throw new SqlTimerRejectedError(result.proposalId, result.outcome.rejectionCode, result.outcome.failingStatementIndex)
    return result.proposalId
  }
  return Object.freeze({
    historyProfile: 'chronological' as const,
    initialize(changeOptions: SqlTimerChangeOptions) {
      return accepted(program(
        sqlStatement(`CREATE TABLE ${heads} (timer_id TEXT PRIMARY KEY, generation TEXT NOT NULL, next_due_at_ms INTEGER NOT NULL, interval_ms INTEGER, payload_json TEXT NOT NULL, active INTEGER NOT NULL) STRICT`),
        sqlStatement(`CREATE TABLE ${generations} (generation TEXT PRIMARY KEY, timer_id TEXT NOT NULL) STRICT`),
        sqlStatement(`CREATE TABLE ${occurrences} (occurrence_id TEXT PRIMARY KEY, timer_id TEXT NOT NULL, generation TEXT NOT NULL, configuration_event_id TEXT NOT NULL, scheduled_at_ms INTEGER NOT NULL, observed_at_ms INTEGER NOT NULL) STRICT`),
      ), changeOptions)
    },
    schedule(value: SqlTimerSchedule, changeOptions: SqlTimerChangeOptions & { readonly expectedGeneration: string | null }) {
      validateConsumerId(value.timerId); validateConsumerId(value.generation); timestamp(value.dueAtMs)
      const interval = value.intervalMs ?? null
      if (interval !== null && (!Number.isSafeInteger(interval) || interval < 1)) throw new Error('TIMER_INTERVAL_INVALID')
      if (changeOptions.expectedGeneration !== null) validateConsumerId(changeOptions.expectedGeneration)
      const payload = value.payload ?? null, payloadJson = canonicalEventPayload(payload)
      const guard = changeOptions.expectedGeneration === null
        ? sqlStatement(`SELECT chronolog_assert(NOT EXISTS(SELECT 1 FROM ${heads} WHERE timer_id = ?), 'timer_generation_changed')`, [value.timerId])
        : sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE timer_id = ? AND generation = ?), 'timer_generation_changed')`, [value.timerId, changeOptions.expectedGeneration])
      const write = changeOptions.expectedGeneration === null
        ? sqlStatement(`INSERT INTO ${heads} (timer_id, generation, next_due_at_ms, interval_ms, payload_json, active) VALUES (?, ?, ?, ?, ?, 1)`, [value.timerId, value.generation, value.dueAtMs, interval, payloadJson])
        : sqlStatement(`UPDATE ${heads} SET generation = ?, next_due_at_ms = ?, interval_ms = ?, payload_json = ?, active = 1 WHERE timer_id = ?`, [value.generation, value.dueAtMs, interval, payloadJson, value.timerId])
      return accepted(program(guard,
        // The permanent generation ledger prevents a later schedule from reviving
        // pending occurrences under a reused former generation.
        sqlStatement(`INSERT INTO ${generations} (generation, timer_id) VALUES (?, ?)`, [value.generation, value.timerId]),
        write,
        emit(configurationTopic, { type: 'timer.scheduled', version: 1, timerId: value.timerId, generation: value.generation,
          dueAtMs: value.dueAtMs, intervalMs: interval, payload }),
      ), changeOptions)
    },
    cancel(value: { readonly timerId: string; readonly generation: string }, changeOptions: SqlTimerChangeOptions) {
      validateConsumerId(value.timerId); validateConsumerId(value.generation)
      return accepted(program(
        sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE timer_id = ? AND generation = ?), 'timer_generation_changed')`, [value.timerId, value.generation]),
        sqlStatement(`UPDATE ${heads} SET active = 0 WHERE timer_id = ? AND generation = ?`, [value.timerId, value.generation]),
        emit(configurationTopic, { type: 'timer.cancelled', version: 1, timerId: value.timerId, generation: value.generation }),
      ), changeOptions)
    },
    async publishOccurrence(occurrence: TimerOccurrence, changeOptions: SqlTimerChangeOptions) {
      validateTimerOccurrence(occurrence)
      const result = await submit(program(
        sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE timer_id = ? AND generation = ? AND active = 1 AND next_due_at_ms = ? AND payload_json = ?), 'timer_inactive_generation')`,
          [occurrence.timerId, occurrence.generation, occurrence.scheduledAtMs, canonicalEventPayload(occurrence.payload)]),
        sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE timer_id = ? AND (interval_ms IS NULL OR next_due_at_ms <= ? - interval_ms)), 'timer_time_overflow')`, [occurrence.timerId, MAX_TIME]),
        sqlStatement(`INSERT INTO ${occurrences} (occurrence_id, timer_id, generation, configuration_event_id, scheduled_at_ms, observed_at_ms) VALUES (?, ?, ?, ?, ?, ?)`,
          [occurrence.occurrenceId, occurrence.timerId, occurrence.generation, occurrence.configurationEventId, occurrence.scheduledAtMs, occurrence.observedAtMs]),
        sqlStatement(`UPDATE ${heads} SET next_due_at_ms = CASE WHEN interval_ms IS NULL THEN next_due_at_ms ELSE next_due_at_ms + interval_ms END, active = CASE WHEN interval_ms IS NULL THEN 0 ELSE 1 END WHERE timer_id = ? AND generation = ?`, [occurrence.timerId, occurrence.generation]),
        emit(occurrenceTopic, { ...occurrence, configurationOrigin: { ...occurrence.configurationOrigin } }),
      ), changeOptions)
      if (result.outcome.outcome === 'accepted') return 'accepted' as const
      if (result.outcome.rejectionCode === 'assert:timer_inactive_generation') return 'cancelled' as const
      throw new SqlTimerRejectedError(result.proposalId, result.outcome.rejectionCode, result.outcome.failingStatementIndex)
    },
  })
}

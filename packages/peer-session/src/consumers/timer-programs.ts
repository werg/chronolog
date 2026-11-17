import { APPLICATION_COLLECTIVE_ID, OWNER_FOR_KEY_SQL, assertEventTopic, canonicalEventPayload, emit, hexToBytes, program, sqlStatement,
  type ChangeProgram, type EventPayload } from '@chronolog/protocol'
import type { ApplicationInputSchema } from '../definition.js'
import { consumerId } from './source.js'
import { timerTime, validateApplicationTimerOccurrence, type ApplicationTimerOccurrence } from './timers.js'

const id = { type: 'string', minLength: 1, maxLength: 256 } as const
const time = { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER } as const
const interval = { anyOf: [{ type: 'null' }, { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }] } as const
export const applicationTimerCancellationSchema = { type: 'object', properties: { timerId: id, generation: id }, required: ['timerId', 'generation'] } as const

export function applicationTimerScheduleSchema<const S extends ApplicationInputSchema>(payload: S) {
  const schema = { type: 'object', properties: { timerId: id, generation: id, dueAtMs: time, intervalMs: interval, payload,
    expectedGeneration: { anyOf: [{ type: 'null' }, id] } }, required: ['timerId', 'generation', 'dueAtMs', 'payload', 'expectedGeneration'] } as const
  return schema satisfies ApplicationInputSchema
}

/** The command input carries provenance for deterministic checking; copied origin fields are never authentication by themselves. */
export function applicationTimerOccurrenceSchema<const S extends ApplicationInputSchema>(payload: S) {
  const configurationPayload = { type: 'object', properties: { type: { type: 'string', enum: ['timer.scheduled'] }, version: { type: 'integer', minimum: 1, maximum: 1 },
    timerId: id, generation: id, dueAtMs: time, intervalMs: interval, payload }, required: ['type', 'version', 'timerId', 'generation', 'dueAtMs', 'intervalMs', 'payload'] } as const
  const schema = { type: 'object', properties: {
    occurrenceId: id, timerId: id, generation: id, scheduledAtMs: time, observedAtMs: time, payload,
    configuration: { type: 'object', properties: {
      id, attemptId: { type: 'string', minLength: 64, maxLength: 64 }, operationId: id, author: { type: 'string', minLength: 64, maxLength: 64 },
      authorTimestampMs: { type: 'string', minLength: 1, maxLength: 32 }, topic: { type: 'string', minLength: 1, maxLength: 128 }, payload: configurationPayload,
    }, required: ['id', 'attemptId', 'operationId', 'author', 'authorTimestampMs', 'topic', 'payload'] },
  }, required: ['occurrenceId', 'timerId', 'generation', 'configuration', 'scheduledAtMs', 'observedAtMs', 'payload'] } as const
  return schema satisfies ApplicationInputSchema
}

export interface ApplicationTimerScheduleInput {
  readonly timerId: string
  readonly generation: string
  readonly dueAtMs: number
  readonly intervalMs?: number | null
  readonly payload?: EventPayload
  readonly expectedGeneration: string | null
}
export interface ApplicationTimerPrograms {
  readonly schema: ChangeProgram
  schedule(input: ApplicationTimerScheduleInput): ChangeProgram
  cancel(input: { readonly timerId: string; readonly generation: string }): ChangeProgram
  fire(occurrence: ApplicationTimerOccurrence): ChangeProgram
}

/**
 * Shared SQL schedules, guarded occurrences and their configuration events.
 * Schedule emits its configuration first; append any other application emits
 * after these steps. The caller's domain policy decides eligible schedulers.
 * observedAtMs is a signed participant observation, never a global trusted clock.
 */
export function createApplicationTimerPrograms(options: { readonly configurationTopic: string; readonly tablePrefix?: string }): ApplicationTimerPrograms {
  assertEventTopic(options.configurationTopic)
  const prefix = options.tablePrefix ?? 'agent'
  if (!/^[a-z][a-z0-9_]{0,47}$/u.test(prefix)) throw new Error('APPLICATION_TIMER_TABLE_PREFIX_INVALID')
  const heads = `${prefix}_timer_heads`, generations = `${prefix}_timer_generations`, occurrences = `${prefix}_timer_occurrences`
  return Object.freeze({
    schema: program(
      `CREATE TABLE ${heads} (timer_id TEXT PRIMARY KEY, generation TEXT NOT NULL, configuration_event_id TEXT NOT NULL, configuration_author BLOB NOT NULL, next_due_at_ms INTEGER NOT NULL, interval_ms INTEGER, payload_json TEXT NOT NULL, active INTEGER NOT NULL) STRICT`,
      `CREATE TABLE ${generations} (generation TEXT PRIMARY KEY, timer_id TEXT NOT NULL) STRICT`,
      `CREATE TABLE ${occurrences} (occurrence_id TEXT PRIMARY KEY, timer_id TEXT NOT NULL, generation TEXT NOT NULL, configuration_event_id TEXT NOT NULL, scheduled_at_ms INTEGER NOT NULL, observed_at_ms INTEGER NOT NULL) STRICT`,
    ),
    schedule(input: ApplicationTimerScheduleInput) {
      consumerId(input.timerId); consumerId(input.generation); timerTime(input.dueAtMs)
      if (input.expectedGeneration !== null) consumerId(input.expectedGeneration)
      const interval = input.intervalMs ?? null
      if (interval !== null) { timerTime(interval); if (interval < 1) throw new Error('APPLICATION_TIMER_INTERVAL_INVALID') }
      const payload = input.payload ?? null, encoded = canonicalEventPayload(payload)
      const guard = input.expectedGeneration === null
        ? sqlStatement(`SELECT chronolog_assert(NOT EXISTS(SELECT 1 FROM ${heads} WHERE timer_id = ?), 'timer_generation_changed')`, [input.timerId])
        : sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE timer_id = ? AND generation = ?), 'timer_generation_changed')`, [input.timerId, input.expectedGeneration])
      const write = input.expectedGeneration === null
        ? sqlStatement(`INSERT INTO ${heads} (timer_id,generation,configuration_event_id,configuration_author,next_due_at_ms,interval_ms,payload_json,active,chronolog_owner)
            VALUES (?, ?, lower(hex(chronolog_transaction_id())) || ':0', chronolog_actor(), ?, ?, ?, 1, ${OWNER_FOR_KEY_SQL})`,
          [input.timerId, input.generation, input.dueAtMs, interval, encoded, APPLICATION_COLLECTIVE_ID])
        : sqlStatement(`UPDATE ${heads} SET generation=?, configuration_event_id=lower(hex(chronolog_transaction_id())) || ':0', configuration_author=chronolog_actor(),
            next_due_at_ms=?, interval_ms=?, payload_json=?, active=1 WHERE timer_id=? AND generation=?`,
          [input.generation, input.dueAtMs, interval, encoded, input.timerId, input.expectedGeneration])
      return program(guard,
        sqlStatement(`INSERT INTO ${generations} (generation,timer_id,chronolog_owner) VALUES (?, ?, ${OWNER_FOR_KEY_SQL})`, [input.generation, input.timerId, APPLICATION_COLLECTIVE_ID]),
        write, emit(options.configurationTopic, { type: 'timer.scheduled', version: 1, timerId: input.timerId, generation: input.generation,
          dueAtMs: input.dueAtMs, intervalMs: interval, payload }))
    },
    cancel(input: { readonly timerId: string; readonly generation: string }) {
      consumerId(input.timerId); consumerId(input.generation)
      return program(
        sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE timer_id=? AND generation=?), 'timer_generation_changed')`, [input.timerId, input.generation]),
        sqlStatement(`UPDATE ${heads} SET active=0 WHERE timer_id=? AND generation=?`, [input.timerId, input.generation]),
        emit(options.configurationTopic, { type: 'timer.cancelled', version: 1, timerId: input.timerId, generation: input.generation }))
    },
    fire(input: ApplicationTimerOccurrence) {
      const occurrence = validateApplicationTimerOccurrence(input)
      if (occurrence.configuration.topic !== options.configurationTopic) throw new Error('APPLICATION_TIMER_CONFIGURATION_INVALID')
      return program(
        sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE timer_id=? AND generation=? AND active=1
          AND configuration_event_id=? AND configuration_author=? AND next_due_at_ms=? AND payload_json=?), 'timer_inactive_configuration')`,
        [occurrence.timerId, occurrence.generation, occurrence.configuration.id, hexToBytes(occurrence.configuration.author), occurrence.scheduledAtMs, canonicalEventPayload(occurrence.payload)]),
        sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE timer_id=? AND (interval_ms IS NULL OR next_due_at_ms <= ?-interval_ms)), 'timer_time_overflow')`,
          [occurrence.timerId, Number.MAX_SAFE_INTEGER]),
        sqlStatement(`INSERT INTO ${occurrences} (occurrence_id,timer_id,generation,configuration_event_id,scheduled_at_ms,observed_at_ms,chronolog_owner) VALUES (?, ?, ?, ?, ?, ?, ${OWNER_FOR_KEY_SQL})`,
          [occurrence.occurrenceId, occurrence.timerId, occurrence.generation, occurrence.configuration.id, occurrence.scheduledAtMs, occurrence.observedAtMs, APPLICATION_COLLECTIVE_ID]),
        sqlStatement(`UPDATE ${heads} SET next_due_at_ms=CASE WHEN interval_ms IS NULL THEN next_due_at_ms ELSE next_due_at_ms+interval_ms END,
          active=CASE WHEN interval_ms IS NULL THEN 0 ELSE 1 END WHERE timer_id=? AND generation=?`, [occurrence.timerId, occurrence.generation]),
        emit(options.configurationTopic, { type: 'timer.fired', version: 1, occurrenceId: occurrence.occurrenceId, timerId: occurrence.timerId,
          generation: occurrence.generation, configurationEventId: occurrence.configuration.id, scheduledAtMs: occurrence.scheduledAtMs, observedAtMs: occurrence.observedAtMs }))
    },
  })
}

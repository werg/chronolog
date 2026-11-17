import { assertEventTopic, canonicalEventPayload, cloneEventOrigin } from '@chronolog/protocol'
import type { EffectiveEvent, EventBatch, EventPayload, EventReadOptions } from '@chronolog/protocol'

/** Structural public port: provider integrations do not depend on node internals. */
export type FinalEvent = EffectiveEvent
export type FinalEventBatch = EventBatch
export type { EventReadOptions } from '@chronolog/protocol'

/**
 * Accepted events committed and applied under the selected history, with
 * resumable cursors. "Final" describes that history; explicit recovery can
 * abandon recent work and is not ruled out by this interface's name.
 *
 * The current DurableProjection, DurableTimerScheduler, and DurableEffectWorker
 * implementations assume append-only delivery, allowing repeated batches, and
 * have no reset/checkpoint-rebuild protocol. Using them across a generation
 * recovery requires that integration; structural typing and batch validation
 * do not supply it. This is an adapter limitation, not a separate architecture
 * or an across-recovery immutability guarantee.
 *
 * Generation-aware effects may deliberately outlive abandoned source history.
 * Preserve dispatch journals, provider retry identities, and authenticated
 * request origins across resets. Check current tool permissions at dispatch and
 * reconcile uncertain earlier calls under the provider's recovery contract.
 */
export interface FinalEventSource {
  read(options?: EventReadOptions): Promise<FinalEventBatch>
  subscribe(options?: EventReadOptions & { readonly signal?: AbortSignal }): AsyncIterable<FinalEventBatch>
}

export interface FinalEventPublisher {
  /**
   * Resolve after acceptance is committed and applied in the selected history.
   * Explicit recovery may abandon that history. Cancellation interrupts waiting,
   * not a prepared operation's identity. The current adapters have no reset or
   * abandoned-attempt handling; recovery integration must distinguish retrying
   * the original prepared operation from starting a new attempt, while retaining
   * records of any provider action that may already have happened.
   */
  publishFinal(topic: string, payload: EventPayload, options: { readonly operationId: string; readonly signal?: AbortSignal }): Promise<void>
}

export function validateConsumerId(value: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || [...value].some((character) => character.charCodeAt(0) < 32)) throw new Error('CONSUMER_ID_INVALID')
}

export function canonicalTopics(topics: readonly string[]): readonly string[] {
  if (topics.length === 0 || topics.length > 64) throw new Error('CONSUMER_TOPICS_INVALID')
  for (const topic of topics) assertEventTopic(topic)
  return [...new Set(topics)].sort()
}

export function cloneFinalEvent(event: FinalEvent): FinalEvent {
  if (typeof event !== 'object' || event === null) throw new Error('CONSUMER_EVENT_INVALID')
  const { id, proposalId, eventOrdinal, topic, payload } = event
  validateConsumerId(id)
  validateConsumerId(proposalId)
  if (!Number.isSafeInteger(eventOrdinal) || eventOrdinal < 0 || eventOrdinal >= 64) {
    throw new Error('CONSUMER_EVENT_INVALID')
  }
  assertEventTopic(topic)
  if (id !== `${proposalId}:${eventOrdinal}`) throw new Error('CONSUMER_EVENT_INVALID')
  const origin = cloneEventOrigin(event.origin)
  return { id, proposalId, eventOrdinal, topic, payload: JSON.parse(canonicalEventPayload(payload)) as EventPayload, origin }
}

/** A source cannot bypass consumer memory bounds or mix transaction identities. */
export function batchEvents(batch: FinalEventBatch, limit: number, topics: readonly string[]): readonly FinalEvent[] {
  if (typeof batch.scannedThrough !== 'string' || batch.scannedThrough.length === 0 || batch.scannedThrough.length > 16_384 ||
      typeof batch.revision !== 'string' || batch.revision.length === 0 || batch.revision.length > 16_384 ||
      batch.transactions.length > limit) throw new Error('CONSUMER_BATCH_INVALID')
  const events: FinalEvent[] = []
  const seen = new Set<string>()
  let bytes = 0
  for (const transaction of batch.transactions) {
    if (transaction.events.length > 64) throw new Error('CONSUMER_BATCH_TOO_LARGE')
    for (const value of transaction.events) {
      const event = cloneFinalEvent(value)
      if (event.proposalId !== transaction.proposalId || seen.has(event.id) || !topics.includes(event.topic)) {
        throw new Error('CONSUMER_BATCH_INVALID')
      }
      seen.add(event.id)
      bytes += new TextEncoder().encode(JSON.stringify(event)).length
      if (bytes > 1_048_576) throw new Error('CONSUMER_BATCH_TOO_LARGE')
      events.push(event)
    }
  }
  return events
}

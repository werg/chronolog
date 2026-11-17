import { MemoryOperationStore } from '@chronolog/node-core'
import type { DurableOperationStore } from '@chronolog/node-core'
import type { EventPayload } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { DurableTimerScheduler } from './timers.js'
import type { TimerOccurrence } from './timers.js'
import { FinalEventPublicationRejectedError } from './event-source.js'
import type { EventReadOptions, FinalEventBatch, FinalEventSource } from './event-source.js'
import { SqlTimerRejectedError } from './sql-timers.js'

class TimerSource implements FinalEventSource {
  readonly entries: EventPayload[] = []
  maxRead = 64
  async read(options: EventReadOptions = {}): Promise<FinalEventBatch> {
    const after = Number((options.cursor ?? 'c:0').slice(2)), end = Math.min(this.entries.length, after + this.maxRead)
    return { transactions: this.entries.slice(after, end).map((payload, offset) => {
      const proposalId = `proposal-${after + offset}`
      return { proposalId, events: [{ id: `${proposalId}:0`, proposalId, eventOrdinal: 0, topic: 'timers.configuration', payload,
        origin: { kind: 'chronolog' as const, groupId: 'A'.repeat(43), authorId: '11'.repeat(32), operationId: `schedule-${after + offset}`,
          authorTimestampMs: '123', membershipRevision: 'A'.repeat(43), writerCapability: null } }] }
    }), scannedThrough: `c:${end}`, hasMore: end < this.entries.length, revision: `r:${end}` }
  }
  async *subscribe(): AsyncIterable<FinalEventBatch> { throw new Error('timers use durable reads') }
}

function fixture() {
  const source = new TimerSource(), store = new MemoryOperationStore()
  const delivered: { occurrence: TimerOccurrence; operationId: string }[] = []
  const options = { id: 'app-timers', sourceId: 'group/history', configurationTopic: 'timers.configuration', source, store,
    publisher: { publishOccurrence: async (occurrence: TimerOccurrence, { operationId }: { operationId: string }): Promise<'accepted'> => {
      delivered.push({ occurrence: structuredClone(occurrence), operationId }); return 'accepted'
    } } }
  return { source, store, delivered, options }
}

describe('durable agent timers', () => {
  it('keeps one-shot schedules and handled occurrences across restart', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'generation-1', timerId: 'morning', dueAtMs: 100, payload: { message: 'hello' } })
    const scheduler = await DurableTimerScheduler.open(f.options)
    expect(await scheduler.tick(99)).toEqual({ emitted: 0, needsCatchUp: false })
    expect(await scheduler.tick(100)).toEqual({ emitted: 1, needsCatchUp: false })
    const reopened = await DurableTimerScheduler.open(f.options)
    expect(await reopened.tick(200)).toEqual({ emitted: 0, needsCatchUp: false })
    expect(f.delivered).toHaveLength(1)
    expect(f.delivered[0]!.occurrence).toMatchObject({ timerId: 'morning', generation: 'generation-1', configurationEventId: 'proposal-0:0', scheduledAtMs: 100 })
  })

  it('preserves the verified requester through schedule and pending-occurrence restart, ignoring payload provenance claims', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'reviewed-generation', timerId: 'reminder', dueAtMs: 100,
      origin: { authorId: 'forged-owner' }, configurationOrigin: { authorId: 'forged-owner', writerCapability: 'forged-grant' },
      payload: { role: 'administrator', action: 'remind' } })
    const verified = (await f.source.read()).transactions[0]!.events[0]!
    await (await DurableTimerScheduler.open(f.options)).tick(99)
    let lost = true
    const options = { ...f.options, publisher: { async publishOccurrence(occurrence: TimerOccurrence, { operationId }: { operationId: string }): Promise<'accepted'> {
      // The application's publisher receives the verified requester separately
      // from arbitrary requested action data, even after its private restart.
      expect(occurrence.configurationOrigin).toEqual(verified.origin)
      f.delivered.push({ occurrence: structuredClone(occurrence), operationId })
      if (lost) { lost = false; throw new Error('publication reply lost') }
      return 'accepted'
    } } }
    const restarted = await DurableTimerScheduler.open(options)
    await expect(restarted.tick(100)).rejects.toThrow('publication reply lost')
    const saved = (await restarted.status()).pending!
    expect(saved.occurrence.configurationEventId).toBe(verified.id)
    expect(saved.occurrence.configurationOrigin).toEqual(verified.origin)
    Object.assign(saved.occurrence.configurationOrigin, { authorId: '22'.repeat(32) })
    expect(await (await DurableTimerScheduler.open(options)).tick(500)).toEqual({ emitted: 1, needsCatchUp: false })
    expect(f.delivered).toHaveLength(2)
    expect(f.delivered[1]).toEqual(f.delivered[0])
    expect(f.delivered[1]!.occurrence.observedAtMs).toBe(100)
  })

  it('lets the occurrence publisher enforce requester policy without promoting payload role claims', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'unprivileged-generation', timerId: 'tool', dueAtMs: 100,
      payload: { role: 'owner', origin: { authorId: '22'.repeat(32) }, action: 'privileged-tool' } })
    let authorized = 0
    const scheduler = await DurableTimerScheduler.open({ ...f.options, publisher: {
      async publishOccurrence(occurrence) {
        if (occurrence.configurationOrigin.authorId !== '22'.repeat(32)) return 'cancelled'
        authorized++
        return 'accepted'
      },
    } })
    expect(await scheduler.tick(100)).toEqual({ emitted: 0, needsCatchUp: false })
    expect(authorized).toBe(0)
    expect((await scheduler.status()).active).toBe(0)
  })

  it('catches up recurring occurrences in bounded turns without drifting schedule time', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'generation-1', timerId: 'interval', dueAtMs: 10, intervalMs: 10 })
    const scheduler = await DurableTimerScheduler.open({ ...f.options, maxOccurrencesPerTick: 2 })
    expect((await scheduler.tick(35)).emitted).toBe(2)
    expect((await scheduler.tick(35)).emitted).toBe(1)
    expect(f.delivered.map(({ occurrence }) => occurrence.scheduledAtMs)).toEqual([10, 20, 30])
    expect(new Set(f.delivered.map(({ operationId }) => operationId)).size).toBe(3)
  })

  it('consumes all known cancellations before firing and does not cancel a replacement generation', async () => {
    const f = fixture()
    f.source.maxRead = 1
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'generation-1', timerId: 'job', dueAtMs: 10 },
      { type: 'timer.cancelled', version: 1, timerId: 'job', generation: 'generation-1' })
    const scheduler = await DurableTimerScheduler.open(f.options)
    expect(await scheduler.tick(20)).toEqual({ emitted: 0, needsCatchUp: true })
    expect(await scheduler.tick(20)).toEqual({ emitted: 0, needsCatchUp: false })
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'generation-2', timerId: 'job', dueAtMs: 30 },
      { type: 'timer.cancelled', version: 1, timerId: 'job', generation: 'generation-1' })
    await scheduler.tick(40)
    expect((await scheduler.tick(40)).emitted).toBe(1)
    expect(f.delivered[0]!.occurrence.generation).toBe('generation-2')
  })

  it('uses the canonical publisher to resolve a cancellation racing a clock tick', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'generation-1', timerId: 'job', dueAtMs: 10, intervalMs: 10 })
    let calls = 0
    const scheduler = await DurableTimerScheduler.open({ ...f.options, publisher: {
      publishOccurrence: async () => { calls += 1; return 'cancelled' },
    } })
    expect((await scheduler.tick(50)).emitted).toBe(0)
    expect((await scheduler.tick(100)).emitted).toBe(0)
    expect(calls).toBe(1)
  })

  it('preserves exact occurrence identity and captured time after a lost response', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'generation-1', timerId: 'job', dueAtMs: 10 })
    let fail = true
    const publisher = { publishOccurrence: async (occurrence: TimerOccurrence, { operationId }: { operationId: string }): Promise<'accepted'> => {
      f.delivered.push({ occurrence: structuredClone(occurrence), operationId })
      if (fail) { fail = false; throw new Error('lost final response') }
      return 'accepted'
    } }
    await expect((await DurableTimerScheduler.open({ ...f.options, publisher })).tick(20)).rejects.toThrow('lost final response')
    const reopened = await DurableTimerScheduler.open({ ...f.options, publisher })
    expect((await reopened.status()).pending?.occurrence.observedAtMs).toBe(20)
    await reopened.tick(200)
    expect(f.delivered).toHaveLength(2)
    expect(f.delivered[1]).toEqual(f.delivered[0])
  })

  it('recovers a proved rejection across lost checkpoint replies without changing the occurrence or replaying an accepted timer', async () => {
    const f = fixture(), disk = new MemoryOperationStore()
    let loseCheckpointReply = false, losePublicationReply = true
    const store: DurableOperationStore = { get: key => disk.get(key), async put(key, value) {
      await disk.put(key, value)
      if (loseCheckpointReply && key.startsWith('agent/checkpoint/')) {
        loseCheckpointReply = false; throw new Error('checkpoint reply lost')
      }
    } }
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'g1', timerId: 'job', dueAtMs: 10, payload: { job: 'reviewed' } })
    const options = { ...f.options, store, publisher: {
      async publishOccurrence(occurrence: TimerOccurrence, { operationId }: { operationId: string }): Promise<'accepted'> {
        f.delivered.push({ occurrence: structuredClone(occurrence), operationId })
        if (occurrence.publication.attempt === 0) {
          loseCheckpointReply = true
          throw new SqlTimerRejectedError('expired-timer-proposal', 'FINALITY_TIMESTAMP_CLOSED', null)
        }
        if (losePublicationReply) { losePublicationReply = false; throw new Error('publication reply lost') }
        return 'accepted'
      },
    } }
    await expect((await DurableTimerScheduler.open(options)).tick(20)).rejects.toThrow('checkpoint reply lost')
    const rejected = await DurableTimerScheduler.open(options)
    const pending = (await rejected.status()).pending!, occurrenceId = pending.occurrence.occurrenceId
    expect(pending).toMatchObject({ stage: 'publication-rejected', publicationAttempt: 0,
      occurrence: { observedAtMs: 20, scheduledAtMs: 10, payload: { job: 'reviewed' } },
      publicationRejections: [{ attempt: 0, operationId: f.delivered[0]!.operationId,
        proposalId: 'expired-timer-proposal', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' }] })
    await expect(rejected.tick(100)).rejects.toBeInstanceOf(FinalEventPublicationRejectedError)
    expect(f.delivered).toHaveLength(1)

    loseCheckpointReply = true
    await expect(rejected.retryPublication(occurrenceId)).rejects.toThrow('checkpoint reply lost')
    const resumed = await DurableTimerScheduler.open(options)
    expect((await resumed.status()).pending).toMatchObject({ stage: 'publishing', publicationAttempt: 1,
      publicationOperationId: `timer-occurrence:${occurrenceId}:1`, occurrence: pending.occurrence })
    await expect(resumed.tick(200)).rejects.toThrow('publication reply lost')
    await expect(resumed.retryPublication(occurrenceId)).rejects.toThrow('TIMER_PUBLICATION_NOT_REJECTED')
    const reopened = await DurableTimerScheduler.open(options)
    expect(await reopened.tick(300)).toEqual({ emitted: 1, needsCatchUp: false })
    expect(f.delivered).toHaveLength(3)
    expect(f.delivered[2]).toEqual(f.delivered[1])
    expect(f.delivered[1]!.occurrence).toEqual({ ...pending.occurrence,
      publication: { attempt: 1, rejections: pending.publicationRejections } })
    expect(await reopened.publicationStatus(occurrenceId)).toMatchObject({ stage: 'accepted', publicationAttempt: 1,
      publicationRejections: pending.publicationRejections })
    expect(await (await DurableTimerScheduler.open(options)).tick(400)).toEqual({ emitted: 0, needsCatchUp: false })
    expect(f.delivered).toHaveLength(3)
  })

  it('keeps rejected publication audit when a final cancellation wins before explicit recovery', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'g1', timerId: 'job', dueAtMs: 10 })
    const configuration = (await f.source.read()).transactions[0]!.events[0]!
    const accepted: TimerOccurrence[] = []
    const options = { ...f.options, publisher: {
      async publishOccurrence(occurrence: TimerOccurrence, { operationId }: { operationId: string }): Promise<'accepted' | 'cancelled'> {
        f.delivered.push({ occurrence: structuredClone(occurrence), operationId })
        if (occurrence.generation === 'g1') {
          if (occurrence.publication.attempt === 0) throw new SqlTimerRejectedError('old-attempt', 'FINALITY_TIMESTAMP_CLOSED', null)
          return 'cancelled'
        }
        accepted.push(occurrence); return 'accepted'
      },
    } }
    const scheduler = await DurableTimerScheduler.open(options)
    await expect(scheduler.tick(20)).rejects.toThrow('FINALITY_TIMESTAMP_CLOSED')
    const occurrenceId = (await scheduler.status()).pending!.occurrence.occurrenceId
    f.source.entries.push({ type: 'timer.cancelled', version: 1, timerId: 'job', generation: 'g1' },
      { type: 'timer.scheduled', version: 1, timerId: 'job', generation: 'g2', dueAtMs: 200 })
    await expect(scheduler.tick(100)).rejects.toBeInstanceOf(FinalEventPublicationRejectedError)
    expect(f.delivered).toHaveLength(1)
    await scheduler.retryPublication(occurrenceId)
    expect(await scheduler.tick(100)).toEqual({ emitted: 0, needsCatchUp: false })
    expect(accepted).toHaveLength(0)
    expect(await scheduler.status()).toMatchObject({ active: 1, pending: null })
    const reopened = await DurableTimerScheduler.open(options)
    expect(await reopened.publicationStatus(occurrenceId)).toMatchObject({ stage: 'cancelled', publicationAttempt: 1,
      configurationEventId: configuration.id, configurationOrigin: configuration.origin,
      publicationRejections: [{ proposalId: 'old-attempt', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' }] })
    expect(await reopened.tick(200)).toEqual({ emitted: 1, needsCatchUp: false })
    expect(accepted.map(occurrence => occurrence.generation)).toEqual(['g2'])
    await expect(reopened.retryPublication(occurrenceId)).rejects.toThrow('TIMER_PUBLICATION_NOT_REJECTED')
  })

  it('cannot allocate a newer attempt while the current attempt still waits for final acceptance', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, generation: 'g1', timerId: 'job', dueAtMs: 10 })
    let entered!: () => void, finish!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const released = new Promise<void>(resolve => { finish = resolve })
    const scheduler = await DurableTimerScheduler.open({ ...f.options, publisher: {
      async publishOccurrence(occurrence) {
        if (occurrence.publication.attempt === 0) throw new SqlTimerRejectedError('expired', 'FINALITY_TIMESTAMP_CLOSED', null)
        entered(); await released; return 'accepted'
      },
    } })
    await expect(scheduler.tick(20)).rejects.toThrow('FINALITY_TIMESTAMP_CLOSED')
    const occurrenceId = (await scheduler.status()).pending!.occurrence.occurrenceId
    await scheduler.retryPublication(occurrenceId)
    const publishing = scheduler.tick(30)
    await started
    const retry = expect(scheduler.retryPublication(occurrenceId)).rejects.toThrow('TIMER_PUBLICATION_NOT_REJECTED')
    finish()
    expect(await publishing).toEqual({ emitted: 1, needsCatchUp: false })
    await retry
    expect(await scheduler.publicationStatus(occurrenceId)).toMatchObject({ stage: 'accepted', publicationAttempt: 1 })
  })
})

describe('timer shutdown and explicit generations', () => {
  it('aborts a finality wait while preserving the exact pending occurrence for restart', async () => {
    const f = fixture(), stop = new AbortController()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, timerId: 'job', generation: 'reviewed-generation', dueAtMs: 10 })
    let entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const scheduler = await DurableTimerScheduler.open({ ...f.options, publisher: {
      publishOccurrence: async (_occurrence, { signal }) => {
        entered()
        return new Promise<'accepted'>((_, reject) => signal?.addEventListener('abort', () => reject(new Error('stopped')), { once: true }))
      },
    } })
    const tick = scheduler.tick(20, stop.signal)
    await started; stop.abort()
    await expect(tick).rejects.toThrow('stopped')
    const pending = (await scheduler.status()).pending
    expect(pending?.occurrence).toMatchObject({ generation: 'reviewed-generation', configurationEventId: 'proposal-0:0', observedAtMs: 20 })
    const reopened = await DurableTimerScheduler.open(f.options)
    await reopened.tick(100)
    expect(f.delivered[0]!.occurrence).toEqual({ ...pending!.occurrence, publication: { attempt: 0, rejections: [] } })
  })

  it('rejects an event without a preallocated generation before advancing its checkpoint', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', version: 1, timerId: 'job', dueAtMs: 10 })
    const scheduler = await DurableTimerScheduler.open(f.options)
    await expect(scheduler.tick(20)).rejects.toThrow('TIMER_CONFIGURATION_INVALID')
    expect(await scheduler.status()).toEqual({ cursor: null, active: 0, pending: null })
    expect(f.delivered).toHaveLength(0)
  })
})

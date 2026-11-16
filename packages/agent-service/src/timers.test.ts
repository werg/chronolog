import { MemoryOperationStore } from '@chronolog/node-core'
import type { EventPayload } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { DurableTimerScheduler } from './timers.js'
import type { TimerOccurrence } from './timers.js'
import type { EventReadOptions, FinalEventBatch, FinalEventSource } from './event-source.js'

class TimerSource implements FinalEventSource {
  readonly entries: EventPayload[] = []
  maxRead = 64
  async read(options: EventReadOptions = {}): Promise<FinalEventBatch> {
    const after = Number((options.cursor ?? 'c:0').slice(2)), end = Math.min(this.entries.length, after + this.maxRead)
    return { transactions: this.entries.slice(after, end).map((payload, offset) => {
      const proposalId = `proposal-${after + offset}`
      return { proposalId, events: [{ id: `${proposalId}:0`, proposalId, eventOrdinal: 0, topic: 'timers.configuration', payload }] }
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
    f.source.entries.push({ type: 'timer.scheduled', timerId: 'morning', dueAtMs: 100, payload: { message: 'hello' } })
    const scheduler = await DurableTimerScheduler.open(f.options)
    expect(await scheduler.tick(99)).toEqual({ emitted: 0, needsCatchUp: false })
    expect(await scheduler.tick(100)).toEqual({ emitted: 1, needsCatchUp: false })
    const reopened = await DurableTimerScheduler.open(f.options)
    expect(await reopened.tick(200)).toEqual({ emitted: 0, needsCatchUp: false })
    expect(f.delivered).toHaveLength(1)
    expect(f.delivered[0]!.occurrence).toMatchObject({ timerId: 'morning', scheduleEventId: 'proposal-0:0', scheduledAtMs: 100 })
  })

  it('catches up recurring occurrences in bounded turns without drifting schedule time', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', timerId: 'interval', dueAtMs: 10, intervalMs: 10 })
    const scheduler = await DurableTimerScheduler.open({ ...f.options, maxOccurrencesPerTick: 2 })
    expect((await scheduler.tick(35)).emitted).toBe(2)
    expect((await scheduler.tick(35)).emitted).toBe(1)
    expect(f.delivered.map(({ occurrence }) => occurrence.scheduledAtMs)).toEqual([10, 20, 30])
    expect(new Set(f.delivered.map(({ operationId }) => operationId)).size).toBe(3)
  })

  it('consumes all known cancellations before firing and does not cancel a replacement generation', async () => {
    const f = fixture()
    f.source.maxRead = 1
    f.source.entries.push({ type: 'timer.scheduled', timerId: 'job', dueAtMs: 10 },
      { type: 'timer.cancelled', timerId: 'job', scheduleEventId: 'proposal-0:0' })
    const scheduler = await DurableTimerScheduler.open(f.options)
    expect(await scheduler.tick(20)).toEqual({ emitted: 0, needsCatchUp: true })
    expect(await scheduler.tick(20)).toEqual({ emitted: 0, needsCatchUp: false })
    f.source.entries.push({ type: 'timer.scheduled', timerId: 'job', dueAtMs: 30 },
      { type: 'timer.cancelled', timerId: 'job', scheduleEventId: 'proposal-0:0' })
    await scheduler.tick(40)
    expect((await scheduler.tick(40)).emitted).toBe(1)
    expect(f.delivered[0]!.occurrence.scheduleEventId).toBe('proposal-2:0')
  })

  it('uses the canonical publisher to resolve a cancellation racing a clock tick', async () => {
    const f = fixture()
    f.source.entries.push({ type: 'timer.scheduled', timerId: 'job', dueAtMs: 10, intervalMs: 10 })
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
    f.source.entries.push({ type: 'timer.scheduled', timerId: 'job', dueAtMs: 10 })
    let fail = true
    const publisher = { publishOccurrence: async (occurrence: TimerOccurrence, { operationId }: { operationId: string }): Promise<'accepted'> => {
      f.delivered.push({ occurrence: structuredClone(occurrence), operationId })
      if (fail) { fail = false; throw new Error('lost final response') }
      return 'accepted'
    } }
    await expect((await DurableTimerScheduler.open({ ...f.options, publisher })).tick(20)).rejects.toThrow('lost final response')
    const reopened = await DurableTimerScheduler.open({ ...f.options, publisher })
    expect((await reopened.status()).pending?.observedAtMs).toBe(20)
    await reopened.tick(200)
    expect(f.delivered).toHaveLength(2)
    expect(f.delivered[1]).toEqual(f.delivered[0])
  })
})

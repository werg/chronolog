import { MemoryPeerStore } from '@chronolog/peer-generation'
import { afterEach, describe, expect, it } from 'vitest'

import { ApplicationTimerScheduler, type ApplicationTimerOptions } from './timers.js'
import { consumerFixture, publish } from './test-support.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const scheduled = { type: 'timer.scheduled', version: 1, timerId: 'reminder', generation: 'reminder-v1', dueAtMs: 100, intervalMs: null, payload: { message: 'hello' } }

async function setup() {
  const f = await consumerFixture(); cleanup.push(() => f.close())
  const published: string[] = []
  const options: ApplicationTimerOptions = { id: 'reminders', version: '1', session: f.a, store: new MemoryPeerStore(), configurationTopic: 'timer.configuration',
    authorize: ({ configuration }) => configuration.author === f.a.deviceId,
    publish: async (occurrence, { operationId, basedOn, reapplyOf }) => {
      published.push(operationId)
      const input = { topic: 'notification.requested', payload: JSON.stringify(occurrence) }
      return reapplyOf === null ? f.a.command('record', input, { operationId, basedOn }) : f.a.reapply(reapplyOf, 'record', input, { operationId, basedOn })
    } }
  return { ...f, options, published }
}

describe('retained application timers', () => {
  it('bounds recurring catch-up and rebuilds cancellation from verified configuration events', async () => {
    const f = await setup()
    await publish(f.a, 'timer.configuration', { ...scheduled, intervalMs: 10 }, 'configure')
    const scheduler = await ApplicationTimerScheduler.open({ ...f.options, maxOccurrencesPerTick: 2 }); cleanup.push(() => scheduler.close())
    expect(await scheduler.tick(99)).toMatchObject({ emitted: 0, nextDueAtMs: 100 })
    expect(await scheduler.tick(135)).toMatchObject({ emitted: 2, hasMore: true })
    expect(await scheduler.tick(135)).toMatchObject({ emitted: 2, hasMore: false, nextDueAtMs: 140 })
    expect((await scheduler.inspect()).occurrences.map(e => e.occurrence.scheduledAtMs)).toEqual([100, 110, 120, 130])
    expect(new Set(f.published).size).toBe(4)
    await publish(f.a, 'timer.configuration', { type: 'timer.cancelled', version: 1, timerId: scheduled.timerId, generation: scheduled.generation }, 'cancel')
    expect(await scheduler.tick(200)).toMatchObject({ emitted: 0, nextDueAtMs: null })
    expect((await scheduler.inspect()).schedules[0]).toMatchObject({ active: false, configuration: { author: f.a.deviceId, operationId: 'configure' } })
  })

  it('retains occurrence identity across reset and reopen and requires explicit linked reapplication', async () => {
    const f = await setup()
    await publish(f.a, 'timer.configuration', scheduled, 'configure')
    const link = await f.synchronize(), beforeFire = await f.b.recoveryPoint(); link.close()
    let scheduler = await ApplicationTimerScheduler.open(f.options); cleanup.push(() => scheduler.close())
    expect(await scheduler.tick(100)).toMatchObject({ emitted: 1 })
    const original = (await scheduler.inspect()).occurrences[0]!
    await scheduler.close(); await f.recover(beforeFire)
    scheduler = await ApplicationTimerScheduler.open(f.options)
    expect(await scheduler.tick(200)).toMatchObject({ emitted: 0, reset: true, awaitingReconciliation: true })
    const abandoned = (await scheduler.inspect()).occurrences[0]!
    expect(abandoned.occurrence).toEqual(original.occurrence)
    expect(abandoned.publications[0]).toMatchObject({ status: 'abandoned', result: { outcome: 'accepted' } })
    expect(f.published).toHaveLength(1)
    await f.synchronize()
    const restored = await scheduler.reapply(original.occurrence.occurrenceId, { operationId: 'reviewed-timer-reapply', signal: AbortSignal.timeout(5000) })
    expect(restored.occurrence).toEqual(original.occurrence)
    expect(restored.publications.at(-1)).toMatchObject({ status: 'applied', reapplyOf: original.publications[0]!.operationId })
    expect(await scheduler.tick(300)).toMatchObject({ emitted: 0, nextDueAtMs: null })
    expect(f.published).toEqual([original.publications[0]!.operationId, 'reviewed-timer-reapply'])
  })

  it('recovers a lost command reply from the session journal without inventing another attempt', async () => {
    const f = await setup(); await publish(f.a, 'timer.configuration', scheduled, 'configure')
    let lost = true
    const options: ApplicationTimerOptions = { ...f.options, publish: async (occurrence, input) => {
      const operation = await f.options.publish(occurrence, input)
      if (lost) { lost = false; throw new Error('COMMAND_REPLY_LOST') }
      return operation
    } }
    const scheduler = await ApplicationTimerScheduler.open(options)
    await expect(scheduler.tick(100)).rejects.toThrow('COMMAND_REPLY_LOST')
    const saved = (await scheduler.inspect()).occurrences[0]!
    await scheduler.close()
    const reopened = await ApplicationTimerScheduler.open(options); cleanup.push(() => reopened.close())
    await reopened.tick(900)
    const entry = (await reopened.inspect()).occurrences[0]!
    expect(entry.occurrence).toEqual(saved.occurrence)
    expect(entry.publications).toHaveLength(1)
    expect(entry.publications[0]?.status).toBe('applied')
    const view = await f.a.readView()
    try { expect(view.readEvents({ topics: ['notification.requested'] }).events).toHaveLength(1) } finally { view.release() }
    expect(new Set(f.published)).toEqual(new Set([saved.publications[0]!.operationId]))
  })

  it('owns clock wakes and cancellation while idle and discards unselected schedules', async () => {
    const f = await setup(), empty = await f.b.recoveryPoint()
    let now = 99, fired!: () => void
    const observed = new Promise<void>(resolve => { fired = resolve })
    await publish(f.a, 'timer.configuration', scheduled, 'configure')
    const scheduler = await ApplicationTimerScheduler.open({ ...f.options, now: () => now, pollMs: 10,
      publish: async (occurrence, options) => {
        const handle = await f.options.publish(occurrence, options)
        await handle.applied({ signal: options.signal }); fired(); return handle
      } }); cleanup.push(() => scheduler.close())
    await scheduler.tick(99)
    await f.recover(empty)
    expect(await scheduler.tick(500)).toMatchObject({ reset: true, emitted: 0, nextDueAtMs: null })
    expect((await scheduler.inspect()).schedules).toEqual([])
    expect(f.published).toEqual([])
    const stop = new AbortController(), running = scheduler.run({ signal: stop.signal })
    stop.abort(); await running
    await expect(scheduler.run({ signal: AbortSignal.timeout(20) })).resolves.toBeUndefined()
    await f.synchronize()
    await publish(f.a, 'timer.configuration', { ...scheduled, generation: 'waking-version' }, 'wake-configure')
    const waking = scheduler.run({ signal: AbortSignal.timeout(5000) })
    now = 100
    await Promise.race([observed, waking.then(() => { throw new Error('TIMER_DID_NOT_WAKE') })])
    await scheduler.close()
    await waking
    expect(f.published).toHaveLength(1)
    expect(() => scheduler.inspect()).toThrow('APPLICATION_CONSUMER_CLOSED')
  })
})

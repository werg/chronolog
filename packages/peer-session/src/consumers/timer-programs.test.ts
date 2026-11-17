import { MemoryPeerStore } from '@chronolog/peer-generation'
import { emit, program } from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { defineApplication, defineCommand, parseApplicationInput } from '../definition.js'
import { ApplicationTimerRejectedError, ApplicationTimerScheduler, type ApplicationTimerOccurrence } from './timers.js'
import { applicationTimerCancellationSchema, applicationTimerOccurrenceSchema, applicationTimerScheduleSchema, createApplicationTimerPrograms } from './timer-programs.js'
import { consumerSqlFixture } from './sql-test-support.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const payloadSchema = { type: 'object', properties: { message: { type: 'string' } }, required: ['message'] } as const
const occurrenceSchema = applicationTimerOccurrenceSchema(payloadSchema)
const timerPrograms = createApplicationTimerPrograms({ configurationTopic: 'timer.configuration', tablePrefix: 'notification' })
const definition = defineApplication({ id: 'guarded-timer', version: '1', schema: timerPrograms.schema, commands: {
  schedule: defineCommand({ description: 'Schedule a notification', input: applicationTimerScheduleSchema(payloadSchema), prepare: input => timerPrograms.schedule(input) }),
  cancel: defineCommand({ description: 'Cancel this notification version', input: applicationTimerCancellationSchema, prepare: input => timerPrograms.cancel(input) }),
  fire: defineCommand({ description: 'Publish an active due notification', input: occurrenceSchema,
    prepare: input => {
      const message: string = input.payload.message
      return program(...timerPrograms.fire(input).steps, emit('notification.requested', { message }))
    } }),
  reject: defineCommand({ description: 'Require a domain constraint', input: occurrenceSchema,
    prepare: input => program("SELECT chronolog_assert(0, 'notification_constraint')", ...timerPrograms.fire(input).steps) }),
}, queries: {} })
const schedule = { timerId: 'notification', generation: 'generation-1', dueAtMs: 100, intervalMs: 10, payload: { message: 'hello' }, expectedGeneration: null }

async function setup() {
  const f = await consumerSqlFixture(definition); cleanup.push(() => f.close())
  expect((await (await f.session.command('schedule', schedule, { operationId: 'configure' })).applied()).outcome).toBe('accepted')
  return f
}

describe('guarded SQL application timers', () => {
  it('binds due time, original verified configuration and payload to the active SQL schedule', async () => {
    const f = await setup(), view = await f.session.readView()
    const configuration = view.readEvents({ topics: ['timer.configuration'] }).events[0]!; view.release()
    const occurrence: ApplicationTimerOccurrence = { occurrenceId: 'occurrence-1', timerId: schedule.timerId, generation: schedule.generation,
      configuration, scheduledAtMs: 100, observedAtMs: 100, payload: schedule.payload }
    const forged = [
      { ...occurrence, payload: { message: 'changed' }, configuration: { ...configuration, payload: { ...(configuration.payload as object), payload: { message: 'changed' } } } },
      { ...occurrence, configuration: { ...configuration, author: 'ab'.repeat(32) } },
      { ...occurrence, scheduledAtMs: 110, observedAtMs: 110 },
    ]
    for (const [index, input] of forged.entries()) {
      const result = await (await f.session.command('fire', parseApplicationInput(occurrenceSchema, input), { operationId: `forged-${index}` })).applied()
      expect(result).toMatchObject({ outcome: 'rejected', rejectionCode: 'assert:timer_inactive_configuration' })
    }
    expect((await (await f.session.command('fire', parseApplicationInput(occurrenceSchema, occurrence), { operationId: 'correct' })).applied()).outcome).toBe('accepted')
    const current = await f.session.readView()
    try {
      expect(current.readEvents({ topics: ['notification.requested'] }).events.map(e => e.payload)).toEqual([schedule.payload])
      expect(current.query('SELECT next_due_at_ms FROM notification_timer_heads').rows).toEqual([[110]])
    } finally { current.release() }
    expect((await (await f.session.command('schedule', { ...schedule, generation: 'generation-2', expectedGeneration: 'generation-1' }, { operationId: 'replace' })).applied()).outcome).toBe('accepted')
    expect(await (await f.session.command('fire', parseApplicationInput(occurrenceSchema, { ...occurrence, occurrenceId: 'old-version', scheduledAtMs: 110, observedAtMs: 110 }), { operationId: 'stale' })).applied())
      .toMatchObject({ outcome: 'rejected', rejectionCode: 'assert:timer_inactive_configuration' })
  })

  it('rejects a cancellation that wins after the scheduler capture without publishing a notification', async () => {
    const f = await setup()
    let entered!: () => void, release!: () => void
    const ready = new Promise<void>(resolve => { entered = resolve }), waiting = new Promise<void>(resolve => { release = resolve })
    const scheduler = await ApplicationTimerScheduler.open({ id: 'notification', version: '1', session: f.session, store: new MemoryPeerStore(), configurationTopic: 'timer.configuration',
      authorize: ({ configuration }) => configuration.author === f.session.deviceId,
      publish: async (occurrence, options) => { entered(); await waiting; return f.session.command('fire', parseApplicationInput(occurrenceSchema, occurrence), options) } })
    cleanup.push(() => scheduler.close())
    const ticking = scheduler.tick(100)
    await ready
    expect((await (await f.session.command('cancel', { timerId: schedule.timerId, generation: schedule.generation }, { operationId: 'cancel' })).applied()).outcome).toBe('accepted')
    release()
    expect(await ticking).toMatchObject({ emitted: 0, cancelled: 1, nextDueAtMs: null })
    expect((await scheduler.inspect()).occurrences[0]?.publications[0]).toMatchObject({ status: 'cancelled', result: { rejectionCode: 'assert:timer_inactive_configuration' } })
    const view = await f.session.readView()
    try { expect(view.readEvents({ topics: ['notification.requested'] }).events).toEqual([]) } finally { view.release() }
  })

  it('surfaces a domain rejection instead of treating every failed command as cancellation', async () => {
    const f = await setup()
    const scheduler = await ApplicationTimerScheduler.open({ id: 'notification', version: '1', session: f.session, store: new MemoryPeerStore(), configurationTopic: 'timer.configuration',
      authorize: () => true, publish: (occurrence, options) => f.session.command('reject', parseApplicationInput(occurrenceSchema, occurrence), options) })
    cleanup.push(() => scheduler.close())
    await expect(scheduler.tick(100)).rejects.toBeInstanceOf(ApplicationTimerRejectedError)
    expect((await scheduler.inspect()).occurrences[0]?.publications[0]).toMatchObject({ status: 'rejected', result: { rejectionCode: 'assert:notification_constraint' } })
    expect(await scheduler.tick(200)).toMatchObject({ emitted: 0, awaitingReconciliation: true })
  })

  it('continues a recurring schedule after another scheduler wins one due slot', async () => {
    const f = await setup(); let compete = true
    const scheduler = await ApplicationTimerScheduler.open({ id: 'notification', version: '1', session: f.session, store: new MemoryPeerStore(), configurationTopic: 'timer.configuration',
      authorize: () => true, publish: async (occurrence, options) => {
        const input = parseApplicationInput(occurrenceSchema, occurrence)
        if (compete) {
          compete = false
          expect((await (await f.session.command('fire', { ...input, occurrenceId: 'other-scheduler' }, { operationId: 'other-scheduler' })).applied()).outcome).toBe('accepted')
        }
        return f.session.command('fire', input, options)
      } })
    cleanup.push(() => scheduler.close())
    expect(await scheduler.tick(100)).toMatchObject({ emitted: 0, cancelled: 1, nextDueAtMs: 110 })
    expect(await scheduler.tick(110)).toMatchObject({ emitted: 1, nextDueAtMs: 120 })
    const view = await f.session.readView()
    try { expect(view.readEvents({ topics: ['notification.requested'] }).events).toHaveLength(2) } finally { view.release() }
  })
})

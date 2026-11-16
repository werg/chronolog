import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createSqlTimerPublisher, DurableTimerScheduler, SqlTimerRejectedError, type TimerOccurrence } from '@chronolog/agent-service/workers'
import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { afterEach, describe, expect, it } from 'vitest'

import { createNativeBrowserFixture } from '../tools/browser-event-fixture.js'

const configurationTopic = 'timers.configured', occurrenceTopic = 'timers.fired'
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-native-sql-timers-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const native = await createNativeBrowserFixture({ directory, browsers: [], manifest: createDoltLiteExecutionManifest(),
    materialization: async ({ identity, executionManifest }) => createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({
      path: join(directory, 'application.db'), executionManifest, rootAdministrator: identity.signing.publicKeyBytes, checkpointEvery: 1,
    })) })
  cleanup.push(() => native.close())
  const publisher = createSqlTimerPublisher({ node: native.node, configurationTopic, occurrenceTopic })
  await publisher.initialize({ operationId: 'timer-schema', signal: AbortSignal.timeout(10_000) })
  return { native, publisher,
    options: { id: 'native-scheduler', sourceId: 'native-fixture/history', configurationTopic, store: native.store,
      source: native.node.events, publisher, maxOccurrencesPerTick: 2 },
    fired: async () => (await native.node.events.read({ topics: [occurrenceTopic] })).transactions.flatMap((entry) => entry.events),
    configurationId: async (generation: string) => {
      const events = (await native.node.events.read({ topics: [configurationTopic] })).transactions.flatMap((entry) => entry.events)
      const event = events.find((entry) => entry.payload !== null && typeof entry.payload === 'object' &&
        'type' in entry.payload && entry.payload.type === 'timer.scheduled' &&
        'generation' in entry.payload && entry.payload.generation === generation)
      if (event === undefined) throw new Error('TIMER_CONFIGURATION_NOT_APPLIED')
      return event.id
    },
  }
}

describe('native SQL timer publication', () => {
  it('fences cancellation at final admission and retries an accepted occurrence after a lost reply without another event', async () => {
    const f = await fixture()
    await f.publisher.schedule({ timerId: 'alarm', generation: 'g1', dueAtMs: 1000, payload: { action: 'wake' } },
      { operationId: 'schedule-g1', expectedGeneration: null })
    let observed!: (value: TimerOccurrence) => void, release!: () => void
    const pending = new Promise<TimerOccurrence>((resolve) => { observed = resolve })
    const held = new Promise<void>((resolve) => { release = resolve })
    const scheduler = await DurableTimerScheduler.open({ ...f.options, publisher: {
      async publishOccurrence(occurrence, options) { observed(occurrence); await held; return f.publisher.publishOccurrence(occurrence, options) },
    } })
    const racing = scheduler.tick(1000)
    const stale = await pending
    await f.publisher.cancel({ timerId: 'alarm', generation: 'g1' }, { operationId: 'cancel-g1' })
    release()
    expect(await racing).toEqual({ emitted: 0, needsCatchUp: false })
    expect(await f.fired()).toHaveLength(0)
    expect(await f.publisher.publishOccurrence(stale, { operationId: 'stale-g1-retry' })).toBe('cancelled')
    expect(await f.fired()).toHaveLength(0)

    await f.publisher.schedule({ timerId: 'alarm', generation: 'g2', dueAtMs: 2000, payload: { action: 'wake-new' } },
      { operationId: 'schedule-g2', expectedGeneration: 'g1' })
    let lost = true
    const losing = await DurableTimerScheduler.open({ ...f.options, publisher: {
      async publishOccurrence(occurrence, options) {
        const result = await f.publisher.publishOccurrence(occurrence, options)
        if (lost) { lost = false; throw new Error('final occurrence response lost') }
        return result
      },
    } })
    await expect(losing.tick(2000)).rejects.toThrow('final occurrence response lost')
    const saved = (await losing.status()).pending!
    expect(saved.observedAtMs).toBe(2000)
    expect(saved.configurationEventId).toBe(await f.configurationId('g2'))
    const before = await f.fired()
    expect(before).toHaveLength(1)
    const restarted = await DurableTimerScheduler.open(f.options)
    expect(await restarted.tick(9000)).toEqual({ emitted: 1, needsCatchUp: false })
    expect(await restarted.status()).toMatchObject({ pending: null, active: 0 })
    expect(await f.fired()).toEqual(before)
    expect((await f.native.client.query('SELECT count(*) FROM agent_timer_occurrences')).result.rows).toEqual([[1n]])
    await expect(f.publisher.schedule({ timerId: 'alarm', generation: 'g1', dueAtMs: 10_000 },
      { operationId: 'reuse-g1', expectedGeneration: 'g2' })).rejects.toBeInstanceOf(SqlTimerRejectedError)
    expect((await f.native.client.query('SELECT generation FROM agent_timer_heads')).result.rows).toEqual([['g2']])
    f.native.assertHealthy()
  })

  it('rejects stale due times and payloads, advances recurring due times in bounded turns, and refuses overflow', async () => {
    const f = await fixture()
    await f.publisher.schedule({ timerId: 'recurring', generation: 'recurring-g1', dueAtMs: 1000, intervalMs: 100,
      payload: { action: 'poll' } }, { operationId: 'schedule-recurring', expectedGeneration: null })
    const configurationEventId = await f.configurationId('recurring-g1')
    const occurrence: TimerOccurrence = { type: 'timer.fired', version: 1, timerId: 'recurring', generation: 'recurring-g1',
      configurationEventId, occurrenceId: 'mismatched-payload', scheduledAtMs: 1000, observedAtMs: 1250, payload: { action: 'tampered' } }
    expect(await f.publisher.publishOccurrence(occurrence, { operationId: 'mismatched-payload' })).toBe('cancelled')
    expect(await f.publisher.publishOccurrence({ ...occurrence, occurrenceId: 'stale-time', scheduledAtMs: 900,
      payload: { action: 'poll' } }, { operationId: 'stale-time' })).toBe('cancelled')
    expect(await f.fired()).toHaveLength(0)
    expect((await f.native.client.query('SELECT next_due_at_ms FROM agent_timer_heads')).result.rows).toEqual([[1000n]])
    const scheduler = await DurableTimerScheduler.open(f.options)
    expect(await scheduler.tick(1250)).toEqual({ emitted: 2, needsCatchUp: false })
    expect((await f.native.client.query('SELECT next_due_at_ms FROM agent_timer_heads')).result.rows).toEqual([[1200n]])
    const restarted = await DurableTimerScheduler.open(f.options)
    expect(await restarted.tick(1250)).toEqual({ emitted: 1, needsCatchUp: false })
    const fired = await f.fired()
    expect(fired.map((event) => (event.payload as { scheduledAtMs: number }).scheduledAtMs)).toEqual([1000, 1100, 1200])
    expect(fired.map((event) => (event.payload as { observedAtMs: number }).observedAtMs)).toEqual([1250, 1250, 1250])
    expect((await f.native.client.query('SELECT next_due_at_ms FROM agent_timer_heads')).result.rows).toEqual([[1300n]])
    await f.publisher.cancel({ timerId: 'recurring', generation: 'recurring-g1' }, { operationId: 'cancel-recurring' })
    await f.publisher.schedule({ timerId: 'overflow', generation: 'overflow-g1', dueAtMs: Number.MAX_SAFE_INTEGER - 1, intervalMs: 2 },
      { operationId: 'schedule-overflow', expectedGeneration: null })
    await expect(restarted.tick(Number.MAX_SAFE_INTEGER)).rejects.toThrow('timer_time_overflow')
    expect((await restarted.status()).pending?.generation).toBe('overflow-g1')
    expect(await f.fired()).toHaveLength(3)
    f.native.assertHealthy()
  })
})

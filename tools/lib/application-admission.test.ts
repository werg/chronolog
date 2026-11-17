import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { utf8 } from '@chronolog/protocol'
import { afterEach, expect, it, vi } from 'vitest'

import { createNativeBrowserFixture } from '../browser-event-fixture.js'
import { createAdmissionClock, observeIncludedProposals } from './application-admission.js'

afterEach(() => vi.useRealTimers())

it('observes the exact signed proposal before releasing the native clock, then finalizes unchanged', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-admission-'))
  let now = Date.now()
  const clock = createAdmissionClock({ now: () => now })
  const native = await createNativeBrowserFixture({ directory, browsers: [], finalityClock: clock.now })
  try {
    const inclusions = observeIncludedProposals(native)
    const handle = await clock.include('original intent', async () => {
      // Simulate local scheduling advancing beyond the fixture's one-second
      // cutoff. Only the injected authority clock is held; source signing uses
      // its real clock and the publication is never rewritten or submitted twice.
      now += 5_000
      const value = await native.client.events.publish('conversation', { text: 'one signed original' }, { operationId: 'original-intent' })
      return { value, proposalIds: [value.proposalId] }
    }, async ids => {
      const observed = await inclusions()
      expect(native.node.isFinal(utf8(ids[0]!))).toBe(false)
      return ids.every(id => observed.has(id))
    })
    const records = await native.transport.history()
    expect(clock.now()).toBe(now)
    expect(clock.windows[0]).toMatchObject({ status: 'included', proposalIds: [handle.proposalId] })
    try { expect((await handle.final({ signal: AbortSignal.timeout(5_000) })).outcome.type).toBe('accepted') }
    finally { handle.dispose() }
    expect(await native.transport.history()).toEqual(records)
    expect((await native.client.events.read()).transactions.filter(value => value.proposalId === handle.proposalId)).toHaveLength(1)
  } finally { await native.close(); await rm(directory, { recursive: true, force: true }) }
})

it('releases the clock when authoring fails without changing its error', async () => {
  let now = 1_000
  const clock = createAdmissionClock({ now: () => now })
  const failure = new Error('source publication failed')
  await expect(clock.include('failed author', async () => { now = 2_000; throw failure }, async () => true)).rejects.toBe(failure)
  expect(clock.now()).toBe(2_000)
  expect(clock.windows[0]?.status).toBe('failed')
})

it('keeps a timed-out window terminal when its author later resolves during another window', async () => {
  vi.useFakeTimers()
  let now = 1_000, finish!: (value: { value: string; proposalIds: string[] }) => void
  const clock = createAdmissionClock({ now: () => now, timeoutMs: 50 }), included = vi.fn(async () => true)
  const pending = clock.include<string>('slow author', () => new Promise(resolve => { finish = resolve }), included)
  const rejected = expect(pending).rejects.toThrow('PILOT_ADMISSION_WINDOW_TIMEOUT: slow author')
  now = 2_000
  await vi.advanceTimersByTimeAsync(50); await rejected
  expect(clock.now()).toBe(2_000)
  const failure = structuredClone(clock.windows[0])
  await clock.include('next author', async () => {
    now = 3_000
    finish({ value: 'late', proposalIds: ['late-proposal'] })
    await Promise.resolve()
    expect(clock.now()).toBe(2_000)
    return { value: 'next', proposalIds: ['next-proposal'] }
  }, async () => true)
  expect(clock.windows[0]).toEqual(failure)
  expect(included).not.toHaveBeenCalled()
  expect(clock.now()).toBe(3_000)
})

it('ignores late inclusion after the whole authoring and observation deadline', async () => {
  vi.useFakeTimers()
  let finish!: (value: boolean) => void
  const clock = createAdmissionClock({ timeoutMs: 50 })
  const pending = clock.include('slow inclusion', async () => ({ value: 'original', proposalIds: ['original'] }),
    () => new Promise(resolve => { finish = resolve }))
  const rejected = expect(pending).rejects.toThrow('PILOT_ADMISSION_WINDOW_TIMEOUT: slow inclusion')
  await vi.advanceTimersByTimeAsync(50); await rejected
  const failure = structuredClone(clock.windows[0])
  finish(true); await vi.advanceTimersByTimeAsync(100)
  expect(clock.windows[0]).toEqual(failure)
  expect(vi.getTimerCount()).toBe(0)
})

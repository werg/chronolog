import { afterEach, expect, it, vi } from 'vitest'

import { waitFor } from './wait-for.js'

afterEach(() => vi.useRealTimers())

it('bounds a durable-progress phase even when a Worker observation never answers', async () => {
  vi.useFakeTimers()
  const pending = waitFor(() => new Promise<boolean>(() => undefined), 'replica materialization', 1_000)
  const rejected = expect(pending).rejects.toThrow('PILOT_DURABLE_PROGRESS_TIMEOUT: replica materialization')
  await vi.advanceTimersByTimeAsync(1_000)
  await rejected
  expect(vi.getTimerCount()).toBe(0)
})

it('allows repeated partial progress to reach the target without leaving a deadline timer', async () => {
  vi.useFakeTimers()
  let applied = 0
  const pending = waitFor(async () => ++applied === 3, 'final frontier', 1_000)
  await vi.advanceTimersByTimeAsync(200)
  await pending
  expect(applied).toBe(3)
  expect(vi.getTimerCount()).toBe(0)
})

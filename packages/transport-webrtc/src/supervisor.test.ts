import { afterEach, describe, expect, it, vi } from 'vitest'

import { supervisePeerSession, type PeerSessionSupervisor, type SupervisedPeerSession } from './supervisor.js'

const cleanup: Array<PeerSessionSupervisor<SupervisedPeerSession>> = []
afterEach(async () => { await Promise.all(cleanup.splice(0).map(value => value.close())); vi.useRealTimers(); vi.restoreAllMocks() })
const retry = { initialDelayMs: 100, maxDelayMs: 250, maxAttempts: 3, jitter: 0, resetAfterMs: 1_000 }
function session() {
  const controller = new AbortController()
  return { signal: controller.signal, end: () => controller.abort(new Error('route lost')),
    close: vi.fn(() => { controller.abort(new Error('session closed')) }) }
}
function track<S extends SupervisedPeerSession>(value: PeerSessionSupervisor<S>): PeerSessionSupervisor<S> { cleanup.push(value); return value }

describe('peer session supervision', () => {
  it('owns one healthy session with no timer or additional connection work', async () => {
    vi.useFakeTimers()
    const active = session(), connect = vi.fn(async () => active)
    const manager = track(supervisePeerSession({ connect, retry, readiness: 'authenticated' }))
    expect(await manager.ready).toBe(active)
    expect(manager.state).toMatchObject({ phase: 'connected', attempt: 1, readiness: 'authenticated' })
    expect(vi.getTimerCount()).toBe(0)
    await vi.advanceTimersByTimeAsync(60 * 60_000)
    expect(connect).toHaveBeenCalledTimes(1)
    expect(await manager.waitForSession()).toBe(active)
    await manager.close()
    expect(active.close).toHaveBeenCalledTimes(1)
    expect(manager.session).toBeUndefined()
  })

  it('bounds exponential retry with jitter and stops after the explicit budget', async () => {
    vi.useFakeTimers(); vi.spyOn(Math, 'random').mockReturnValue(1)
    const connect = vi.fn(async () => { throw new Error('resident unavailable') })
    const manager = track(supervisePeerSession({ connect, retry: { ...retry, jitter: 0.5 }, readiness: 'transport' }))
    const result = expect(manager.completion).rejects.toThrow('resident unavailable')
    const first = expect(manager.ready).rejects.toThrow('resident unavailable')
    await vi.advanceTimersByTimeAsync(0)
    expect(manager.state).toMatchObject({ phase: 'waiting', attempt: 1, readiness: null, nextRetryAt: Date.now() + 150 })
    await vi.advanceTimersByTimeAsync(149); expect(connect).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1); expect(connect).toHaveBeenCalledTimes(2)
    expect(manager.state.nextRetryAt).toBe(Date.now() + 250)
    await vi.advanceTimersByTimeAsync(250)
    await result; await first
    expect(connect).toHaveBeenCalledTimes(3)
    expect(manager.state).toMatchObject({ phase: 'stopped', attempt: 3 })
    expect(vi.getTimerCount()).toBe(0)
    await expect(manager.waitForSession()).rejects.toThrow('resident unavailable')
  })

  it('cancels an uncooperative dial immediately and retires its late session', async () => {
    let resolve!: (value: ReturnType<typeof session>) => void, attempt: AbortSignal | undefined
    const manager = track(supervisePeerSession({ retry, readiness: 'transport', connect(signal) {
      attempt = signal
      return new Promise<ReturnType<typeof session>>(done => { resolve = done })
    } }))
    const first = expect(manager.ready).rejects.toThrow('PEER_SESSION_SUPERVISOR_CLOSED')
    await Promise.resolve(); await Promise.resolve()
    await manager.close()
    expect(attempt?.aborted).toBe(true)
    await first
    const late = session(); resolve(late)
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve()
    expect(late.close).toHaveBeenCalledTimes(1)
    expect(manager.state.phase).toBe('stopped')
    expect(manager.session).toBeUndefined()
  })

  it('fences the old Worker attempt before reconnect and resolves fresh session waiters', async () => {
    vi.useFakeTimers()
    const sessions = [session(), session()], signals: AbortSignal[] = []
    const manager = track(supervisePeerSession({ retry, readiness: 'authenticated', async connect(signal) {
      signals.push(signal); return sessions[signals.length - 1]!
    } }))
    expect(await manager.ready).toBe(sessions[0])
    sessions[0]!.end()
    expect(signals[0]!.aborted).toBe(true)
    const recovered = manager.waitForSession()
    await vi.advanceTimersByTimeAsync(100)
    expect(await recovered).toBe(sessions[1])
    expect(sessions[0]!.close).toHaveBeenCalledTimes(1)
    expect(signals[1]!.aborted).toBe(false)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not reset the retry budget for flapping connections', async () => {
    vi.useFakeTimers()
    const sessions: ReturnType<typeof session>[] = []
    const manager = track(supervisePeerSession({ retry, readiness: 'transport', async connect() {
      const value = session(); sessions.push(value); return value
    } }))
    const completion = expect(manager.completion).rejects.toThrow('route lost')
    await manager.ready
    sessions[0]!.end(); await vi.advanceTimersByTimeAsync(100)
    expect(manager.state.attempt).toBe(2)
    sessions[1]!.end(); await vi.advanceTimersByTimeAsync(200)
    expect(manager.state.attempt).toBe(3)
    sessions[2]!.end(); await vi.advanceTimersByTimeAsync(0)
    await completion
    expect(sessions).toHaveLength(3)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('resets the budget only after a stable connection, without a health timer', async () => {
    vi.useFakeTimers()
    const sessions: ReturnType<typeof session>[] = []
    const manager = track(supervisePeerSession({ retry: { ...retry, maxAttempts: 2 }, readiness: 'transport', async connect() {
      const value = session(); sessions.push(value); return value
    } }))
    await manager.ready; sessions[0]!.end(); await vi.advanceTimersByTimeAsync(100)
    expect(manager.state.attempt).toBe(2)
    expect(vi.getTimerCount()).toBe(0)
    await vi.advanceTimersByTimeAsync(1_000)
    sessions[1]!.end(); await vi.advanceTimersByTimeAsync(100)
    expect(manager.state).toMatchObject({ phase: 'connected', attempt: 1 })
    expect(sessions).toHaveLength(3)
  })

  it('cancels one waiter independently and closes a retry without another dial', async () => {
    vi.useFakeTimers()
    const connect = vi.fn(async () => { throw new Error('offline') })
    const manager = track(supervisePeerSession({ connect, retry, readiness: 'transport', async onState() { throw new Error('observer failure') } }))
    const controller = new AbortController(), waiter = manager.waitForSession({ signal: controller.signal })
    const rejected = expect(waiter).rejects.toThrow('not waiting')
    controller.abort(new Error('not waiting')); await rejected
    await vi.advanceTimersByTimeAsync(0)
    expect(manager.state.phase).toBe('waiting')
    await manager.close(); await vi.advanceTimersByTimeAsync(10_000)
    expect(connect).toHaveBeenCalledTimes(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('never advertises a session already ended by its connector', async () => {
    const dead = session(); dead.end()
    const manager = track(supervisePeerSession({ retry: { ...retry, maxAttempts: 1 }, readiness: 'authenticated', async connect() { return dead } }))
    await expect(manager.ready).rejects.toThrow('route lost')
    await expect(manager.completion).rejects.toThrow('route lost')
    expect(dead.close).toHaveBeenCalledTimes(1)
    expect(manager.session).toBeUndefined()
  })
})

import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AuthorityBundle } from '@chronolog/peer-generation'
import type { ApplicationBootstrapHost, ApplicationConfiguration } from './bootstrap.js'
import { connectApplicationWorkerHost, serveApplicationWorkerHost } from './worker-host.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
function fixture(overrides: Partial<ApplicationBootstrapHost> = {}) {
  const unavailable = (): Promise<never> => Promise.reject(Object.assign(new Error('peer_control_state_missing'), { status: 503, code: 'peer_control_state_missing' }))
  const host: ApplicationBootstrapHost = { application: vi.fn(unavailable), definition: vi.fn(unavailable),
    configureApplication: vi.fn(unavailable), selectGeneration: vi.fn(unavailable), ...overrides }
  const endpoint = new MessageChannel(), server = serveApplicationWorkerHost(endpoint.port1, host)
  cleanup.push(() => { server.close(); endpoint.port1.close(); endpoint.port2.close() })
  return { host, endpoint, server }
}

describe('page-owned application control bridge', () => {
  it('preserves hosted errors and permits only one current Worker owner', async () => {
    const f = fixture(), host = await connectApplicationWorkerHost(f.endpoint.port2)
    cleanup.push(() => host.close())
    expect(() => serveApplicationWorkerHost(f.endpoint.port1, f.host)).toThrow('APPLICATION_WORKER_HOST_IN_USE')
    await expect(connectApplicationWorkerHost(f.endpoint.port2)).rejects.toThrow('APPLICATION_WORKER_HOST_IN_USE')
    await expect(host.application()).rejects.toMatchObject({ message: 'peer_control_state_missing', code: 'peer_control_state_missing', status: 503 })
    expect(host.signal.aborted).toBe(false)
    await host.close()
    const replacement = await connectApplicationWorkerHost(f.endpoint.port2)
    cleanup.push(() => replacement.close())
    await expect(replacement.definition()).rejects.toThrow('peer_control_state_missing')
    f.server.close()
    await vi.waitFor(() => expect(replacement.signal.aborted).toBe(true))
    await expect(replacement.application()).rejects.toThrow('APPLICATION_WORKER_HOST_CLOSED')
  })

  it('bounds outstanding calls even after observation timeout and discards late completions', async () => {
    const blocked: Array<(reason: Error) => void> = []
    const application = vi.fn(() => new Promise<AuthorityBundle>((_resolve, reject) => blocked.push(reject)))
    const f = fixture({ application }), host = await connectApplicationWorkerHost(f.endpoint.port2, { timeoutMs: 100 })
    cleanup.push(() => host.close())
    const calls = Array.from({ length: 8 }, () => host.application().catch(error => error as Error))
    await expect(host.application()).rejects.toThrow('APPLICATION_WORKER_HOST_REQUEST_LIMIT')
    await vi.waitFor(() => expect(application).toHaveBeenCalledTimes(8))
    expect((await Promise.all(calls)).every(error => error instanceof Error && error.message === 'APPLICATION_WORKER_HOST_TIMEOUT')).toBe(true)
    await expect(host.application()).rejects.toThrow('APPLICATION_WORKER_HOST_REQUEST_LIMIT')
    expect(application).toHaveBeenCalledTimes(8)
    for (const reject of blocked) reject(new Error('late hosted result'))
    await vi.waitFor(async () => { await expect(host.definition()).rejects.toThrow('peer_control_state_missing') })
    expect(host.signal.aborted).toBe(false)
  })

  it('budgets UTF-8 JSON before posting and closes pending observations on lifetime cancellation', async () => {
    const configureApplication = vi.fn(() => Promise.reject(new Error('unexpected configuration')))
    const f = fixture({ configureApplication }), host = await connectApplicationWorkerHost(f.endpoint.port2)
    cleanup.push(() => host.close())
    const oversized = { historyId: '🧭'.repeat(300_000) } as ApplicationConfiguration
    await expect(host.configureApplication(oversized)).rejects.toThrow('JSON payload is too large')
    expect(configureApplication).not.toHaveBeenCalled()
    await expect(host.definition()).rejects.toThrow('peer_control_state_missing')
    const abort = new AbortController()
    const endpoint = new MessageChannel()
    cleanup.push(() => { endpoint.port1.close(); endpoint.port2.close() })
    const waiting = connectApplicationWorkerHost(endpoint.port1, { signal: abort.signal })
    const rejected = expect(waiting).rejects.toThrow('page retired')
    abort.abort(new Error('page retired')); await rejected
  })
})

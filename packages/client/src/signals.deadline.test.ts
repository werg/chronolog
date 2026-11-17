import { bytesToBase64Url } from '@chronolog/protocol'
import { InProcessRpcTransport, NodeRpcService,
  type ChronologRpcNodeService, type RpcCallOptions, type RpcTransport, type SignalSendRequest } from '@chronolog/rpc'
import { DEFAULT_SIGNAL_TTL_MS, SignalChannel, generateSignalIdentity } from '@chronolog/signals'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ChronologClient } from './client.js'

const cleanup: Array<() => void | Promise<void>> = []
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date', 'performance', 'setTimeout', 'clearTimeout'] })
  vi.setSystemTime(1_000_000)
})
afterEach(async () => {
  for (const close of cleanup.splice(0).reverse()) await close()
  vi.restoreAllMocks(); vi.useRealTimers()
})

function deferred() {
  let resolve!: () => void
  return { promise: new Promise<void>(done => { resolve = done }), resolve: () => resolve() }
}

async function delayedRpc() {
  const groupId = new Uint8Array(32).fill(42), group = bytesToBase64Url(groupId)
  let durableAccesses = 0, dispatches = 0
  const node = new Proxy({ groupId }, { get(target, key) {
    if (key === 'groupId') return target.groupId
    durableAccesses++; throw new Error(`Unexpected durable access: ${String(key)}`)
  } }) as unknown as ChronologRpcNodeService
  const sender = new SignalChannel({ scope: group, identity: await generateSignalIdentity(), authorize: () => true })
  const receiver = new SignalChannel({ scope: group, identity: await generateSignalIdentity(), authorize: () => true })
  const incoming = receiver.attachRoute({ send: async () => {} })
  sender.attachRoute({ send: async frame => { dispatches++; await incoming.receive(frame) } })
  const transport = new InProcessRpcTransport(new NodeRpcService({ node, signals: sender }))
  const gate = deferred(), requests: SignalSendRequest[] = []
  let dispatched: Promise<unknown> | undefined, lifetime: AbortSignal | undefined
  const unary = vi.fn((_method: string, request: SignalSendRequest, options: RpcCallOptions) => {
    requests.push(structuredClone(request)); lifetime = options.signal
    // Model a delayed request whose cancellation cannot cross the broken
    // transport. Its absolute expiry must protect the remote service too.
    dispatched = gate.promise.then(() => transport.unary('signals.send', request))
    return dispatched
  })
  const client = new ChronologClient({ groupId: group, unaryRetryAttempts: 20,
    transport: { unary, close: () => transport.close() } as unknown as RpcTransport })
  cleanup.push(() => sender.close(), () => receiver.close(), () => client.close())
  return { client, receiver, requests, unary, release: gate.resolve,
    delivery: () => dispatched!, lifetime: () => lifetime,
    stats: () => ({ durableAccesses, dispatches }),
  }
}

describe('original RPC signal lifetime', () => {
  it.each([1000, undefined])('deducts RPC delay from the signed delivered lifetime (TTL %s)', async ttlMs => {
    const f = await delayedRpc(), originalTtl = ttlMs ?? DEFAULT_SIGNAL_TTL_MS
    const start = Date.now(), delay = Math.floor(originalTtl / 4)
    const reader = f.receiver.subscribe()[Symbol.asyncIterator](), receiving = reader.next()
    const sending = f.client.signals.send('preview', { chunk: 1 }, ttlMs === undefined ? {} : { ttlMs })
    expect(f.requests).toEqual([{ groupId: bytesToBase64Url(new Uint8Array(32).fill(42)),
      topic: 'preview', payload: { chunk: 1 }, ttlMs: originalTtl, expiresAtMs: start + originalTtl }])
    await vi.advanceTimersByTimeAsync(delay)
    f.release()
    const sent = await sending
    expect(sent.issuedAtMs).toBe(start + delay)
    expect(sent.expiresAtMs).toBe(start + originalTtl)
    expect(sent.expiresAtMs - sent.issuedAtMs).toBe(originalTtl - delay)
    expect((await receiving).value).toEqual(sent)
    expect(f.stats()).toEqual({ durableAccesses: 0, dispatches: 1 })
    expect(f.unary).toHaveBeenCalledOnce()
    await reader.return?.()
  })

  it.each([1000, undefined])('expires locally and forbids late remote dispatch even if cancellation is lost (TTL %s)', async ttlMs => {
    const f = await delayedRpc(), lifetime = ttlMs ?? DEFAULT_SIGNAL_TTL_MS
    const sending = f.client.signals.send('typing', true, ttlMs === undefined ? {} : { ttlMs })
    const expired = expect(sending).rejects.toMatchObject({ code: 'deadline_exceeded', retryable: false,
      details: { signalCode: 'signal_expired' } })
    await vi.advanceTimersByTimeAsync(lifetime)
    await expired
    expect(f.lifetime()?.aborted).toBe(true)
    expect(f.stats()).toEqual({ durableAccesses: 0, dispatches: 0 })
    f.release()
    await expect(f.delivery()).rejects.toMatchObject({ code: 'deadline_exceeded', retryable: false,
      details: { signalCode: 'signal_expired' } })
    expect(f.stats()).toEqual({ durableAccesses: 0, dispatches: 0 })
    expect(f.unary).toHaveBeenCalledOnce()
  })

  it('does not renew a pending lifetime when the caller wall clock moves backward', async () => {
    const unary = vi.fn(() => new Promise<never>(() => {}))
    const client = new ChronologClient({ groupId: 'group', transport: { unary } as unknown as RpcTransport })
    cleanup.push(() => client.close())
    const expired = expect(client.signals.send('typing', true, { ttlMs: 100 }))
      .rejects.toMatchObject({ code: 'deadline_exceeded', details: { signalCode: 'signal_expired' } })
    vi.setSystemTime(900_000)
    await vi.advanceTimersByTimeAsync(100)
    await expired
    expect(unary).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('ends a caller-cancelled wait even when the transport ignores the signal', async () => {
    let lifetime: AbortSignal | undefined
    const unary = vi.fn((_method: string, _request: unknown, options: RpcCallOptions) => {
      lifetime = options.signal; return new Promise<never>(() => {})
    })
    const client = new ChronologClient({ groupId: 'group', transport: { unary } as unknown as RpcTransport })
    cleanup.push(() => client.close())
    const caller = new AbortController()
    const cancelled = expect(client.signals.send('typing', true, { signal: caller.signal }))
      .rejects.toMatchObject({ code: 'cancelled', retryable: false })
    caller.abort(new Error('page left'))
    await cancelled
    expect(lifetime?.aborted).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
    expect(unary).toHaveBeenCalledOnce()
  })

  it('does not dispatch an already cancelled or expired call', async () => {
    const unary = vi.fn()
    const client = new ChronologClient({ groupId: 'group', transport: { unary } as unknown as RpcTransport })
    cleanup.push(() => client.close())
    await expect(client.signals.send('typing', true, { signal: AbortSignal.abort() }))
      .rejects.toMatchObject({ code: 'cancelled' })
    vi.spyOn(Date, 'now').mockReturnValueOnce(1_000_000).mockReturnValue(1_000_100)
    await expect(client.signals.send('typing', true, { ttlMs: 100 }))
      .rejects.toMatchObject({ details: { signalCode: 'signal_expired' } })
    expect(unary).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
})

import { bytesToBase64Url } from '@chronolog/protocol'
import { ChronologRpcError, InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import type { ChronologRpcNodeService, RpcInterceptor } from '@chronolog/rpc'
import { SignalChannel, generateSignalIdentity } from '@chronolog/signals'
import type { SignalChannelOptions, SignalRoute, SignalSubscribeOptions } from '@chronolog/signals'
import { afterEach, describe, expect, it } from 'vitest'

import { ChronologClient } from './client.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture(options: { readonly interceptors?: readonly RpcInterceptor[];
  readonly authorize?: SignalChannelOptions['authorize']; readonly maxQueuedSignals?: number; readonly sendTimeoutMs?: number } = {}) {
  const id = new Uint8Array(32).fill(41), groupId = bytesToBase64Url(id)
  let durableAccesses = 0, dispatches = 0, activeSubscriptions = 0
  // Fail on every durable getter/method, not just an expected write method. The
  // real RPC service must use only group identity for the independent live port.
  const node = new Proxy({ groupId: id }, { get(target, key) {
    if (key === 'groupId') return target.groupId
    durableAccesses++; throw new Error(`Durable node accessed by live signal: ${String(key)}`)
  } }) as unknown as ChronologRpcNodeService
  const a = new SignalChannel({ scope: 'rpc:live', identity: await generateSignalIdentity(),
    authorize: options.authorize ?? (() => true), sendTimeoutMs: options.sendTimeoutMs ?? 5000 })
  const b = new SignalChannel({ scope: 'rpc:live', identity: await generateSignalIdentity(),
    authorize: () => true, maxQueuedSignals: options.maxQueuedSignals ?? 64 })
  cleanup.push(() => a.close(), () => b.close())
  const ab: SignalRoute = a.attachRoute({ send: async frame => { dispatches++; await ba.receive(frame) } })
  const ba: SignalRoute = b.attachRoute({ send: async frame => { await ab.receive(frame) } })
  const send = new ChronologClient({ groupId, unaryRetryAttempts: 5, streamRetryDelayMs: () => 0,
    transport: new InProcessRpcTransport(new NodeRpcService({ node, signals: a }), options.interceptors) })
  const receive = new ChronologClient({ groupId, transport: new InProcessRpcTransport(new NodeRpcService({ node, signals: {
    send: (topic, payload, options) => b.send(topic, payload, options),
    async *subscribe(options: SignalSubscribeOptions = {}) {
      activeSubscriptions++
      try { yield* b.subscribe(options) } finally { activeSubscriptions-- }
    },
  } })) })
  cleanup.push(() => send.close(), () => receive.close())
  return { send, receive, node, groupId, disconnect() { ab.close(); ba.close() },
    stats: () => ({ durableAccesses, dispatches, activeSubscriptions }),
  }
}

describe('real public RPC signal composition', () => {
  it('passes FIFO and explicit latest delivery through client, RPC service and actual signed channels without durable access', async () => {
    const f = await fixture(), stop = new AbortController()
    const all = f.receive.signals.subscribe({ topics: ['preview'], signal: stop.signal })[Symbol.asyncIterator](), first = all.next()
    await expect.poll(() => f.stats().activeSubscriptions).toBe(1)
    const sent = await f.send.signals.send('preview', { chunk: 'A' }, { ttlMs: 2000 })
    expect((await first).value).toEqual(sent)
    await f.send.signals.send('preview', { chunk: 'B' }); await f.send.signals.send('preview', { chunk: 'C' })
    expect((await all.next()).value?.payload).toEqual({ chunk: 'B' })
    expect((await all.next()).value?.payload).toEqual({ chunk: 'C' })
    await all.return?.()
    await expect.poll(() => f.stats().activeSubscriptions).toBe(0)

    const latest = f.receive.signals.subscribe({ topics: ['progress'], mode: 'latest' })[Symbol.asyncIterator](), initial = latest.next()
    await expect.poll(() => f.stats().activeSubscriptions).toBe(1)
    await f.send.signals.send('progress', 1); expect((await initial).value?.payload).toBe(1)
    await f.send.signals.send('progress', 2); await f.send.signals.send('progress', 3)
    expect((await latest.next()).value?.payload).toBe(3)
    await latest.return?.()
    expect(f.stats().durableAccesses).toBe(0)
  })

  it('rejects the wrong group and absent live port before any dispatch or durable operation', async () => {
    const f = await fixture()
    const missing = new ChronologClient({ groupId: f.groupId, transport: new InProcessRpcTransport(new NodeRpcService({ node: f.node })) })
    const wrong = new ChronologClient({ groupId: 'unknown', transport: new InProcessRpcTransport(new NodeRpcService({ node: f.node })) })
    cleanup.push(() => missing.close(), () => wrong.close())
    await expect(missing.signals.send('typing', true)).rejects.toMatchObject({ code: 'failed_precondition' })
    await expect(missing.signals.subscribe()[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'failed_precondition' })
    await expect(wrong.signals.send('typing', true)).rejects.toMatchObject({ code: 'not_found' })
    await expect(wrong.signals.subscribe()[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'not_found' })
    expect(f.stats()).toEqual({ durableAccesses: 0, dispatches: 0, activeSubscriptions: 0 })
  })

  it('refuses durable request fields at the raw RPC boundary as well as the client surface', async () => {
    const f = await fixture()
    const transport = new InProcessRpcTransport(new NodeRpcService({ node: f.node, signals: f.send.signals }))
    const expected = { code: 'invalid_argument', retryable: false, details: { signalCode: 'signal_options_invalid' } }
    const sendRequest = { groupId: f.groupId, topic: 'typing', payload: true, expiresAtMs: Date.now() + 5000, operationId: 'durable' }
    await expect(transport.unary('signals.send', sendRequest)).rejects.toMatchObject(expected)
    const subscribeRequest = { groupId: f.groupId, cursor: 'replay' }
    await expect(transport.stream('signals.subscribe', subscribeRequest)[Symbol.asyncIterator]().next()).rejects.toMatchObject(expected)
    expect(f.stats()).toEqual({ durableAccesses: 0, dispatches: 0, activeSubscriptions: 0 })
    await transport.close()
  })

  it('preserves actionable signal errors through real RPC without marking a live message retryable', async () => {
    const f = await fixture({ authorize: input => input.topic !== 'private', maxQueuedSignals: 1 })
    await expect(f.send.signals.send('private', true)).rejects.toMatchObject({ code: 'permission_denied',
      retryable: false, details: { signalCode: 'signal_unauthorized' } })
    await expect(f.send.signals.send('', true)).rejects.toMatchObject({ code: 'invalid_argument',
      retryable: false, details: { signalCode: 'signal_topic_invalid' } })
    await expect(f.send.signals.send('preview', 'x'.repeat(20_000))).rejects.toMatchObject({ code: 'invalid_argument',
      retryable: false, details: { signalCode: 'signal_frame_too_large' } })
    const reader = f.receive.signals.subscribe()[Symbol.asyncIterator](), first = reader.next()
    await expect.poll(() => f.stats().activeSubscriptions).toBe(1)
    await f.send.signals.send('preview', 1); await first
    await f.send.signals.send('preview', 2); await f.send.signals.send('preview', 3)
    await expect(reader.next()).rejects.toMatchObject({ code: 'resource_exhausted',
      retryable: false, details: { signalCode: 'signal_subscription_overflow' } })
    await expect.poll(() => f.stats().activeSubscriptions).toBe(0)
    f.disconnect()
    await expect(f.send.signals.send('typing', true)).rejects.toMatchObject({ code: 'transport_unavailable',
      retryable: false, details: { signalCode: 'signal_disconnected' } })
    expect(f.stats().durableAccesses).toBe(0)

    const stalled = await fixture({ authorize: () => new Promise<boolean>(() => undefined), sendTimeoutMs: 20 })
    await expect(stalled.send.signals.send('typing', true)).rejects.toMatchObject({ code: 'deadline_exceeded',
      retryable: false, details: { signalCode: 'signal_send_timeout' } })
    expect(stalled.stats()).toEqual({ durableAccesses: 0, dispatches: 0, activeSubscriptions: 0 })
  })

  it('does not retry a dispatched message after a lost RPC reply, and cancellation reaches the live subscriber', async () => {
    let calls = 0
    const loseReply: RpcInterceptor = async (_request, context, next) => {
      const result = await next()
      if (context.method === 'signals.send') { calls++; throw new ChronologRpcError('transport_unavailable', 'reply lost after live dispatch') }
      return result
    }
    const f = await fixture({ interceptors: [loseReply] }), stop = new AbortController()
    const reader = f.receive.signals.subscribe({ signal: stop.signal })[Symbol.asyncIterator](), first = reader.next()
    await expect.poll(() => f.stats().activeSubscriptions).toBe(1)
    await expect(f.send.signals.send('typing', true)).rejects.toMatchObject({ code: 'transport_unavailable' })
    expect((await first).value?.payload).toBe(true)
    expect(calls).toBe(1); expect(f.stats().dispatches).toBe(1)
    const pending = reader.next()
    stop.abort(); expect((await pending).done).toBe(true)
    await expect.poll(() => f.stats().activeSubscriptions).toBe(0)
    expect(f.stats().durableAccesses).toBe(0)
  })
})

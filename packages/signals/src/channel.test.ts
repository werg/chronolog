import { afterEach, describe, expect, it, vi } from 'vitest'

import { SignalChannel, SignalError, generateSignalIdentity, isSignalFrame } from './index.js'
import type { SignalChannelOptions, SignalRoute, SignalSendOptions, SignalSubscribeOptions } from './index.js'

const inputs = new WeakMap<SignalChannel, SignalRoute>()
function inputRoute(channel: SignalChannel): SignalRoute {
  let route = inputs.get(channel)
  if (route === undefined) {
    // Unit ingress has its own explicit lifetime and no outgoing transport.
    route = channel.attachRoute({ async send() { throw new SignalError('signal_disconnected') } })
    inputs.set(channel, route)
  }
  return route
}

const channels: SignalChannel[] = []
afterEach(() => { for (const channel of channels.splice(0)) channel.close() })
async function channel(options: Partial<SignalChannelOptions> = {}) {
  const value = new SignalChannel({ scope: 'room:live', identity: await generateSignalIdentity(), authorize: () => true, ...options })
  channels.push(value); return value
}
function connect(a: SignalChannel, b: SignalChannel) {
  const ab: SignalRoute = a.attachRoute({ send: async bytes => { await ba.receive(bytes) } })
  const ba: SignalRoute = b.attachRoute({ send: async bytes => { await ab.receive(bytes) } })
  return () => { ab.close(); ba.close() }
}
async function captured(options: Partial<SignalChannelOptions> = {}) {
  const frames: Uint8Array[] = [], sender = await channel(options)
  const route = sender.attachRoute({ send: async frame => { frames.push(frame) } })
  return { sender, frames, detach: () => route.close() }
}

describe('standalone live signals', () => {
  it('works without a database, record protocol, grants or finality, and preserves FIFO transient chunks', async () => {
    const a = await channel(), b = await channel(), disconnect = connect(a, b)
    const iterator = b.subscribe({ topics: ['chunks'] })[Symbol.asyncIterator](), first = iterator.next()
    const sent = await a.send('chunks', { chunk: 'A' })
    expect((await first).value).toEqual(sent)
    await a.send('chunks', { chunk: 'B' }); await a.send('chunks', { chunk: 'C' })
    expect((await iterator.next()).value?.payload).toEqual({ chunk: 'B' })
    expect((await iterator.next()).value?.payload).toEqual({ chunk: 'C' })
    disconnect()
    await expect(a.send('chunks', 'lost')).rejects.toMatchObject({ code: 'signal_disconnected' })
    connect(a, b)
    const next = iterator.next(); await a.send('chunks', { chunk: 'fresh' })
    expect((await next).value?.payload).toEqual({ chunk: 'fresh' })
    await iterator.return?.()
  })

  it('coalesces only opt-in latest values, keeps sessions separate and never regresses after consumption', async () => {
    const identity = await generateSignalIdentity()
    const f = await captured({ identity }), b = await channel(), replacement = await captured({ identity })
    const latest = b.subscribe({ mode: 'latest' })[Symbol.asyncIterator](), first = latest.next()
    await f.sender.send('pointer', 1); await inputRoute(b).receive(f.frames[0]!); expect((await first).value?.payload).toBe(1)
    await f.sender.send('pointer', 2); await f.sender.send('pointer', 3)
    await inputRoute(b).receive(f.frames[2]!); expect((await latest.next()).value?.payload).toBe(3)
    await inputRoute(b).receive(f.frames[1]!) // A delayed path cannot replace already consumed sequence 3.
    const next = latest.next()
    await f.sender.send('pointer', 4); await inputRoute(b).receive(f.frames[3]!)
    expect((await next).value?.payload).toBe(4)
    await f.sender.send('pointer', 5); await inputRoute(b).receive(f.frames[4]!)
    await f.sender.send('pointer', 6); await inputRoute(b).receive(f.frames[5]!)
    await replacement.sender.send('pointer', 'another session'); await inputRoute(b).receive(replacement.frames[0]!)
    expect((await latest.next()).value?.payload).toBe(6)
    expect((await latest.next()).value?.payload).toBe('another session')
    await latest.return?.()
  })

  it('forwards original signed bytes through a peer mesh without echo loops or resigning', async () => {
    const a = await channel({ relay: true }), relay = await channel({ relay: true }), b = await channel({ relay: true })
    connect(a, relay); connect(relay, b); connect(b, a)
    const abort = new AbortController(), reader = b.subscribe({ signal: abort.signal })[Symbol.asyncIterator]()
    const first = reader.next(), sent = await a.send('presence', { online: true })
    expect((await first).value).toEqual(sent)
    expect(sent.authorId).toBe(a.authorId)
    const next = reader.next(); abort.abort()
    expect((await next).done).toBe(true)
  })

  it('accepts distinct out-of-order FIFO messages, rejects tampering, and deduplicates original identity', async () => {
    const f = await captured(), b = await channel(), reader = b.subscribe()[Symbol.asyncIterator](), first = reader.next()
    await f.sender.send('sample', 1); await f.sender.send('sample', 2)
    expect(isSignalFrame(f.frames[0]!)).toBe(true)
    await inputRoute(b).receive(f.frames[1]!); expect((await first).value?.payload).toBe(2)
    await inputRoute(b).receive(f.frames[0]!); expect((await reader.next()).value?.payload).toBe(1)
    expect(await inputRoute(b).receive(f.frames[0]!)).toBeNull()
    const text = new TextDecoder().decode(f.frames[0]).replace('sample', 'tamper')
    await expect(inputRoute(b).receive(new TextEncoder().encode(text))).rejects.toMatchObject({ code: 'signal_signature_invalid' })
    await reader.return?.()
  })

  it('preserves arrival order when concurrent verification and authorization finish out of order', async () => {
    const f = await captured()
    await f.sender.send('first', 1); await f.sender.send('second', 2)
    let release!: (allowed: boolean) => void, secondChecked = false
    const blocked = new Promise<boolean>(resolve => { release = resolve })
    const receiver = await channel({ authorize: input => {
      if (input.topic === 'first') return blocked
      secondChecked = true; return true
    } })
    const reader = receiver.subscribe()[Symbol.asyncIterator](), first = reader.next()
    const admittedFirst = inputRoute(receiver).receive(f.frames[0]!), admittedSecond = inputRoute(receiver).receive(f.frames[1]!)
    await expect.poll(() => secondChecked).toBe(true)
    release(true)
    await Promise.all([admittedFirst, admittedSecond])
    expect((await first).value?.payload).toBe(1)
    expect((await reader.next()).value?.payload).toBe(2)
    await reader.return?.()
  })

  it('rechecks permission changed while a verified message awaits ordered admission', async () => {
    const f = await captured()
    await f.sender.send('first', 1); await f.sender.send('second', 2)
    let release!: (allowed: boolean) => void, secondChecked = false, allowed = true
    const blocked = new Promise<boolean>(resolve => { release = resolve })
    const receiver = await channel({ authorize: input => {
      if (input.topic === 'first') return blocked
      secondChecked = true; return allowed
    } })
    const admittedFirst = inputRoute(receiver).receive(f.frames[0]!), admittedSecond = inputRoute(receiver).receive(f.frames[1]!)
    const rejected = expect(admittedSecond).rejects.toMatchObject({ code: 'signal_unauthorized' })
    await expect.poll(() => secondChecked).toBe(true)
    allowed = false; release(true)
    await admittedFirst; await rejected
  })

  it('authorizes every send/receive/relay against current policy independently of connection identity', async () => {
    let active = true
    const identity = await generateSignalIdentity(), f = await captured({ identity }), b = await channel({ authorize: input => active && input.authorId === f.sender.authorId && input.topic === 'typing' })
    await f.sender.send('typing', true); expect(await inputRoute(b).receive(f.frames[0]!)).not.toBeNull()
    active = false
    await f.sender.send('typing', false)
    await expect(inputRoute(b).receive(f.frames[1]!)).rejects.toMatchObject({ code: 'signal_unauthorized' })
    const denied = await channel({ authorize: () => false }); denied.attachRoute({ send: async () => undefined })
    await expect(denied.send('typing', true)).rejects.toMatchObject({ code: 'signal_unauthorized' })
    const other = await channel({ scope: 'other' })
    await expect(inputRoute(other).receive(f.frames[0]!)).rejects.toMatchObject({ code: 'signal_scope_mismatch' })
  })

  it('expires pending messages and bounds replay memory without evicting live duplicate protection', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      let now = 100
      const f = await captured({ now: () => now }), b = await channel({ now: () => now, maxReplayEntries: 1 })
      await f.sender.send('typing', 1, { ttlMs: 10 }); await inputRoute(b).receive(f.frames[0]!)
      await f.sender.send('typing', 2)
      await expect(inputRoute(b).receive(f.frames[1]!)).rejects.toMatchObject({ code: 'signal_replay_limit' })
      now = 111
      expect(await inputRoute(b).receive(f.frames[0]!)).toBeNull()
      expect((await inputRoute(b).receive(f.frames[1]!))?.payload).toBe(2)
    } finally { vi.useRealTimers() }
  })

  it('fails FIFO overflow visibly instead of silently coalescing discrete events', async () => {
    const a = await channel(), b = await channel({ maxQueuedSignals: 1 }); connect(a, b)
    const reader = b.subscribe()[Symbol.asyncIterator](), first = reader.next()
    await a.send('chunk', 1); await first
    await a.send('chunk', 2); await a.send('chunk', 3)
    await expect(reader.next()).rejects.toMatchObject({ code: 'signal_subscription_overflow' })
  })

  it('bounds blocked sends and honors cancellation with no retry or send on replacement routes', async () => {
    const a = await channel({ maxPendingSends: 1 }), abort = new AbortController()
    let entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    a.attachRoute({ send: async (_frame, { signal }) => {
      entered(); await new Promise<void>((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }))
    } })
    const sending = a.send('progress', 1, { signal: abort.signal }); await started
    await expect(a.send('progress', 2)).rejects.toMatchObject({ code: 'signal_backpressure' })
    const reason = new Error('view disposed'); abort.abort(reason)
    await expect(sending).rejects.toBe(reason)
    a.close()
    await expect(a.send('progress', 3)).rejects.toMatchObject({ code: 'signal_channel_closed' })
  })

  it('validates bounded JSON messages before they can enter a live route', async () => {
    const f = await captured()
    await expect(f.sender.send('preview', 'x'.repeat(20_000))).rejects.toMatchObject({ code: 'signal_frame_too_large' })
    await expect(f.sender.send('preview', Number.NaN)).rejects.toMatchObject({ code: 'signal_payload_invalid' })
    await expect(f.sender.send('preview', null, { ttlMs: 0 })).rejects.toMatchObject({ code: 'signal_ttl_invalid' })
    expect(f.frames).toHaveLength(0)
  })

  it('rejects durable, misspelled and non-object options before live dispatch or subscription', async () => {
    const f = await captured()
    for (const options of [{ operationId: 'durable' }, { retry: true }, { ttl: 1000 }, [], null]) {
      await expect(f.sender.send('preview', true, options as unknown as SignalSendOptions))
        .rejects.toMatchObject({ code: 'signal_options_invalid' })
    }
    for (const options of [{ cursor: 'replay' }, { operationId: 'durable' }, { topic: 'preview' }, [], null]) {
      expect(() => f.sender.subscribe(options as unknown as SignalSubscribeOptions))
        .toThrow(expect.objectContaining({ code: 'signal_options_invalid' }))
    }
    expect(f.frames).toHaveLength(0)
  })

  it('cancels pending authorization and closes blocked receive work without sending or delivering later', async () => {
    let entered!: () => void, release!: (allowed: boolean) => void
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<boolean>(resolve => { release = resolve })
    const f = await captured(), receiver = await channel({ authorize: () => { entered(); return gate } })
    await f.sender.send('preview', 'blocked')
    const received = inputRoute(receiver).receive(f.frames[0]!)
    await started; receiver.close()
    await expect(received).rejects.toMatchObject({ code: 'signal_channel_closed' })
    release(true)

    const abort = new AbortController(), pending = await channel({ authorize: () => new Promise<boolean>(() => undefined) })
    let sends = 0; pending.attachRoute({ send: async () => { sends++ } })
    const sending = pending.send('typing', true, { signal: abort.signal })
    abort.abort(new Error('cancelled before authentication'))
    await expect(sending).rejects.toThrow('cancelled before authentication')
    expect(sends).toBe(0)
  })

  it('never reuses a replacement route for a send started on a disconnected route', async () => {
    let release!: (allowed: boolean) => void
    const permission = new Promise<boolean>(resolve => { release = resolve })
    const a = await channel({ authorize: () => permission })
    let sent = 0
    const detach = a.attachRoute({ send: async () => { sent++ } })
    const sending = a.send('typing', true)
    detach.close(); a.attachRoute({ send: async () => { sent++ } }); release(true)
    await expect(sending).rejects.toMatchObject({ code: 'signal_route_closed' })
    expect(sent).toBe(0)
  })
})

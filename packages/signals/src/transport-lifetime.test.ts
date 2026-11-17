import { afterEach, describe, expect, it, vi } from 'vitest'

import { SignalChannel, SignalError, generateSignalIdentity } from './index.js'
import type { SignalChannelOptions, SignalRoute } from './index.js'

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
afterEach(() => {
  try { for (const channel of channels.splice(0)) channel.close() } finally { vi.useRealTimers() }
})
async function channel(options: Partial<SignalChannelOptions> = {}) {
  const value = new SignalChannel({ scope: 'live:lifetime', identity: await generateSignalIdentity(), authorize: () => true, ...options })
  channels.push(value); return value
}
async function capture(options: Partial<SignalChannelOptions> = {}) {
  const sender = await channel(options), frames: Uint8Array[] = []
  sender.attachRoute({ send: async frame => { frames.push(frame) } })
  return { sender, frames }
}
function gate() {
  let enter!: () => void, release!: () => void
  const entered = new Promise<void>(resolve => { enter = resolve }), wait = new Promise<void>(resolve => { release = resolve })
  return { enter, entered, wait, release }
}

describe('live signal transport ownership', () => {
  it('preserves every safely congested route for a fresh publication', async () => {
    const sender = await channel(), receiver = await channel()
    let congested = true, retired = 0
    const frames: Uint8Array[] = []
    for (let index = 0; index < 2; index++) sender.attachRoute({
      async send(frame) { if (congested) throw new SignalError('signal_route_backpressure'); frames.push(frame) },
      close() { retired++ },
    })
    await expect(sender.send('typing', 'discarded intent')).rejects.toMatchObject({ code: 'signal_route_backpressure' })
    expect(frames).toEqual([]); expect(retired).toBe(0); expect(sender.routeCount).toBe(2)
    congested = false
    const sent = await sender.send('typing', 'fresh intent')
    expect(frames).toHaveLength(2); expect(frames[0]).toEqual(frames[1])
    expect(await inputRoute(receiver).receive(frames[0]!)).toEqual(sent)
    expect(retired).toBe(0)
  })

  it('does not refresh an intent TTL while queued behind a blocked send', async () => {
    let now = 100
    const blocked = gate(), frames: Uint8Array[] = [], sender = await channel({ now: () => now })
    sender.attachRoute({ async send(frame) { frames.push(frame); blocked.enter(); await blocked.wait } })
    const first = sender.send('typing', 1)
    await blocked.entered
    const stale = sender.send('typing', 2, { ttlMs: 1_000 })
    const rejected = expect(stale).rejects.toMatchObject({ code: 'signal_expired' })
    now = 1_101; blocked.release(); await first; await rejected
    expect(frames).toHaveLength(1)
  })

  it('rejects shared receive overload before authorization without remembering the frame or revoking routes', async () => {
    const f = await capture(), blocked = gate()
    let authorizations = 0, closed = 0
    const receiver = await channel({ maxPendingReceives: 1, async authorize() {
      if (++authorizations === 1) { blocked.enter(); await blocked.wait }
      return true
    } })
    const transport = { async send() {}, close() { closed++ } }
    const first = receiver.attachRoute(transport), second = receiver.attachRoute(transport)
    await f.sender.send('typing', 'held'); await f.sender.send('typing', 'later')
    const admitted = first.receive(f.frames[0]!)
    try {
      await blocked.entered
      await expect(second.receive(f.frames[1]!)).rejects.toMatchObject({ code: 'signal_backpressure' })
      expect(authorizations).toBe(1); expect(closed).toBe(0)
      blocked.release(); expect((await admitted)?.payload).toBe('held')
      expect((await second.receive(f.frames[1]!))?.payload).toBe('later')
      expect(authorizations).toBe(4); expect(closed).toBe(0)
    } finally { blocked.release(); await admitted.catch(() => undefined) }
  })

  it('retires an aborted noncooperative write and counts it across replacement routes', async () => {
    const blocked = gate(), sender = await channel({ maxRoutes: 1 })
    let writes = 0, closes = 0
    sender.attachRoute({ async send() { writes++; blocked.enter(); await blocked.wait }, close() { closes++ } })
    const abort = new AbortController(), pending = sender.send('typing', 1, { signal: abort.signal })
    await blocked.entered
    const rejected = expect(pending).rejects.toThrow('cancelled intent')
    abort.abort(new Error('cancelled intent')); await rejected
    await expect.poll(() => closes).toBe(1)
    expect(sender.routeCount).toBe(0)
    sender.attachRoute({ async send() { writes++ } })
    await expect(sender.send('typing', 2)).rejects.toMatchObject({ code: 'signal_route_backpressure' })
    expect(writes).toBe(1)
    blocked.release()
    await expect.poll(async () => {
      try { await sender.send('typing', 3); return true } catch { return false }
    }).toBe(true)
    expect(writes).toBe(2)
  })

  it('keeps cancelled policy work counted until it settles, then admits fresh intent', async () => {
    const blocked = gate()
    let calls = 0
    const sender = await channel({ maxPendingSends: 1, async authorize() {
      if (++calls === 1) { blocked.enter(); await blocked.wait }
      return true
    } })
    const frames: Uint8Array[] = []
    sender.attachRoute({ async send(frame) { frames.push(frame) } })
    const abort = new AbortController(), pending = sender.send('typing', 1, { signal: abort.signal })
    await blocked.entered
    const rejected = expect(pending).rejects.toThrow('cancelled policy')
    abort.abort(new Error('cancelled policy')); await rejected
    await expect(sender.send('typing', 2)).rejects.toMatchObject({ code: 'signal_backpressure' })
    blocked.release()
    await expect.poll(async () => {
      try { await sender.send('typing', 3); return true } catch { return false }
    }).toBe(true)
    expect(frames).toHaveLength(1)
  })

  it('cancels route-owned receive before admission and retains noncooperative policy capacity', async () => {
    const f = await capture(), blocked = gate()
    const receiver = await channel({ maxPendingReceives: 1, async authorize() { blocked.enter(); await blocked.wait; return true } })
    await f.sender.send('preview', 1)
    const route = receiver.attachRoute({ async send() {} }), receiving = route.receive(f.frames[0]!)
    await blocked.entered
    const rejected = expect(receiving).rejects.toMatchObject({ code: 'signal_route_closed' })
    route.close(); await rejected
    await expect(inputRoute(receiver).receive(f.frames[0]!)).rejects.toMatchObject({ code: 'signal_backpressure' })
    blocked.release()
    await expect.poll(async () => {
      try { return (await inputRoute(receiver).receive(f.frames[0]!))?.payload } catch { return undefined }
    }).toBe(1)
    expect(await inputRoute(receiver).receive(f.frames[0]!)).toBeNull()
  })

  it('releases admission ordering after a receive deadline while keeping underlying work counted', async () => {
    const f = await capture(), blocked = gate()
    const receiver = await channel({ receiveTimeoutMs: 30, maxPendingReceives: 2, async authorize({ topic }) {
      if (topic === 'blocked') { blocked.enter(); await blocked.wait }
      return true
    } })
    await f.sender.send('blocked', 1); await f.sender.send('fresh', 2)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const receiving = inputRoute(receiver).receive(f.frames[0]!)
    const rejected = expect(receiving).rejects.toMatchObject({ code: 'signal_receive_timeout' })
    await blocked.entered
    await vi.advanceTimersByTimeAsync(31); await rejected
    expect((await inputRoute(receiver).receive(f.frames[1]!))?.payload).toBe(2)
    blocked.release()
  })

  it('retires a stalled relay at its deadline without stalling accepted inbound messages', async () => {
    const f = await capture(), blocked = gate(), relay = await channel({ relay: true, sendTimeoutMs: 30 })
    let writes = 0, closes = 0
    relay.attachRoute({ async send() { writes++; blocked.enter(); await blocked.wait }, close() { closes++ } })
    await f.sender.send('typing', 1)
    expect((await inputRoute(relay).receive(f.frames[0]!))?.payload).toBe(1)
    await blocked.entered
    await f.sender.send('typing', 2)
    expect((await inputRoute(relay).receive(f.frames[1]!))?.payload).toBe(2)
    await expect.poll(() => closes).toBe(1)
    expect(writes).toBe(1)
    await expect(relay.send('typing', 3)).rejects.toMatchObject({ code: 'signal_disconnected' })
    blocked.release()
  })

  it('keeps healthy routes usable without awaiting a stalled peer', async () => {
    const blocked = gate(), sender = await channel(), delivered: Uint8Array[] = []
    let stalled = 0
    sender.attachRoute({ async send() { stalled++; blocked.enter(); await blocked.wait } })
    sender.attachRoute({ async send(frame) { delivered.push(frame) } })
    const abort = new AbortController()
    await sender.send('typing', 1, { signal: abort.signal }); await blocked.entered
    await sender.send('typing', 2)
    expect(stalled).toBe(1); expect(delivered).toHaveLength(2)
    abort.abort(); blocked.release()
  })

  it.each([2, 3])('rechecks current permission at async send boundary %i without retiring a healthy route', async boundary => {
    const blocked = gate()
    let allowed = true, calls = 0
    const f = await capture({ async authorize() {
      if (++calls === boundary) { blocked.enter(); await blocked.wait }
      return allowed
    } })
    const pending = f.sender.send('typing', true), rejected = expect(pending).rejects.toMatchObject({ code: 'signal_unauthorized' })
    await blocked.entered; allowed = false; blocked.release(); await rejected
    expect(f.frames).toHaveLength(0); expect(f.sender.routeCount).toBe(1)
    allowed = true; await f.sender.send('typing', false)
    expect(f.frames).toHaveLength(1)
  })

  it('returns an idle iterator immediately and frees a paused aborted subscription quota', async () => {
    const f = await capture(), receiver = await channel({ maxSubscriptions: 1 })
    const idle = receiver.subscribe()[Symbol.asyncIterator](), pending = idle.next()
    expect((await idle.return?.())?.done).toBe(true); expect((await pending).done).toBe(true)
    const abort = new AbortController(), paused = receiver.subscribe({ signal: abort.signal })[Symbol.asyncIterator](), first = paused.next()
    await f.sender.send('sample', 1); await inputRoute(receiver).receive(f.frames[0]!); await first
    abort.abort()
    const replacement = receiver.subscribe()[Symbol.asyncIterator](), next = replacement.next()
    await f.sender.send('sample', 2); await inputRoute(receiver).receive(f.frames[1]!)
    expect((await next).value?.payload).toBe(2)
    await replacement.return?.(); await paused.return?.()
  })

  it('discards expired queued values before a capacity check and never revives them after clock rollback', async () => {
    let now = 100
    const f = await capture({ now: () => now }), receiver = await channel({ maxQueuedSignals: 1, now: () => now })
    const reader = receiver.subscribe()[Symbol.asyncIterator](), first = reader.next()
    await f.sender.send('sample', 'first'); await inputRoute(receiver).receive(f.frames[0]!); await first
    await f.sender.send('sample', 'expired', { ttlMs: 1_000 }); await inputRoute(receiver).receive(f.frames[1]!)
    now = 1_101
    await f.sender.send('sample', 'fresh'); await inputRoute(receiver).receive(f.frames[2]!)
    expect((await reader.next()).value?.payload).toBe('fresh')
    expect(await inputRoute(receiver).receive(f.frames[1]!)).toBeNull()
    now = 100
    expect(await inputRoute(receiver).receive(f.frames[1]!)).toBeNull()
    await reader.return?.()
  })

  it('bounds queued bytes independently of item count and refuses malformed filters', async () => {
    const f = await capture(), receiver = await channel({ maxQueuedSignals: 10, maxQueuedBytes: 600 })
    const reader = receiver.subscribe()[Symbol.asyncIterator](), first = reader.next()
    await f.sender.send('sample', 1); await inputRoute(receiver).receive(f.frames[0]!); await first
    await f.sender.send('sample', 'x'.repeat(400)); await inputRoute(receiver).receive(f.frames[1]!)
    await expect(reader.next()).rejects.toMatchObject({ code: 'signal_subscription_overflow' })
    const invalid = receiver.subscribe({ topics: 'sample' as unknown as readonly string[] })[Symbol.asyncIterator]()
    await expect(invalid.next()).rejects.toMatchObject({ code: 'signal_topic_filter_invalid' })
  })

  it('snapshots bounded plain JSON before async policy and does not invoke accessors', async () => {
    const f = await capture(), receiver = await channel(), payload = { text: 'before', values: [1, 2] }
    const pending = f.sender.send('preview', payload)
    payload.text = 'after'; payload.values.push(3)
    expect((await pending).payload).toEqual({ text: 'before', values: [1, 2] })
    expect((await inputRoute(receiver).receive(f.frames[0]!))?.payload).toEqual({ text: 'before', values: [1, 2] })
    let invoked = false
    const accessor = { get value() { invoked = true; return 'unsafe' } }
    await expect(f.sender.send('preview', accessor)).rejects.toMatchObject({ code: 'signal_payload_invalid' })
    expect(invoked).toBe(false)
    await expect(f.sender.send('preview', Array.from({ length: 4096 }, () => null))).rejects.toMatchObject({ code: 'signal_payload_invalid' })
    expect(f.frames).toHaveLength(1)
  })
})

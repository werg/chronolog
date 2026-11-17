import { assertCanonicalCbor, encodeCanonicalCbor, generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { SignalChannel, type SignalTransport } from './index.js'

async function fixture() {
  const identity = await generateEd25519KeyPair(), receiverIdentity = await generateEd25519KeyPair()
  const scope = 'standalone-room'
  let now = 100, active = true
  const frames: Uint8Array[] = []
  const options = { scope, identity, trySend: async (frame: Uint8Array) => { frames.push(frame); return true },
    now: () => now, authorize: ({ topic }: { topic: string }) => active && topic === 'typing' }
  const sender = new SignalChannel(options)
  const receiver = new SignalChannel({ ...options, identity: receiverIdentity })
  return { sender, receiver, frames, options, setNow(value: number) { now = value }, revoke() { active = false } }
}

describe('authorized ephemeral peer signals', () => {
  it('rejects a saturated publication without retiring routes that refused local dispatch', async () => {
    const f = await fixture(), { trySend: _send, ...options } = f.options
    const channel = new SignalChannel(options)
    let congested = true, retired = 0
    const received: Uint8Array[] = []
    for (let index = 0; index < 2; index++) channel.attachRoute({
      async trySend(frame) { if (congested) return false; received.push(frame); return true },
      close() { retired++ },
    })
    try {
      await expect(channel.send('typing', 'discarded intent')).rejects.toThrow('SIGNAL_BACKPRESSURE')
      expect(received).toEqual([])
      expect(retired).toBe(0)
      congested = false
      const sent = await channel.send('typing', 'fresh intent')
      expect(received).toHaveLength(2)
      expect(received[0]).toEqual(received[1])
      expect((await f.receiver.receive(received[0]!))?.payload).toEqual(sent.payload)
      expect(retired).toBe(0)
    } finally { channel.close(); f.sender.close(); f.receiver.close() }
  })

  it('keeps a route after an explicit refusal before dispatch without retaining a retry', async () => {
    const f = await fixture(), delivered: Uint8Array[] = []
    let congested = true, closed = 0
    const channel = new SignalChannel({ scope: 'room', identity: f.options.identity, authorize: () => true })
    channel.attachRoute({ async trySend(frame) {
      if (congested) return false
      delivered.push(frame)
      return true
    }, close() { closed++ } })
    try {
      await expect(channel.send('typing', 'discard this attempt')).rejects.toThrow('SIGNAL_BACKPRESSURE')
      expect(delivered).toEqual([]); expect(closed).toBe(0)
      congested = false
      await channel.send('typing', 'current value')
      expect(delivered).toHaveLength(1)
      expect((assertCanonicalCbor(delivered[0]!) as unknown[])[10]).toBe('"current value"')
      expect(closed).toBe(0)
    } finally { channel.close(); f.sender.close(); f.receiver.close() }
  })

  it.each(['exception', 'unmarked backpressure exception', 'invalid result'] as const)('retires a route after a transport %s without treating it as a dispatch refusal', async kind => {
    const f = await fixture()
    let closed = 0
    const channel = new SignalChannel({ scope: 'room', identity: f.options.identity, authorize: () => true })
    channel.attachRoute({ trySend: (async () => {
      if (kind === 'exception') throw new Error('transport failed')
      if (kind === 'unmarked backpressure exception') throw Object.assign(new Error('SIGNAL_BACKPRESSURE'), { code: 'SIGNAL_BACKPRESSURE' })
      return { unexpected: 'result' }
    }) as unknown as SignalTransport['trySend'], close() { closed++ } })
    try {
      const reason = kind === 'exception' ? 'transport failed'
        : kind === 'unmarked backpressure exception' ? 'SIGNAL_BACKPRESSURE' : 'SIGNAL_TRANSPORT_RESULT_INVALID'
      await expect(channel.send('typing', 1)).rejects.toThrow(reason)
      expect(closed).toBe(1)
      await expect(channel.send('typing', 2)).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    } finally { channel.close(); f.sender.close(); f.receiver.close() }
  })

  it('drops an attached route frame before shared receive admission without remembering it or revoking routes', async () => {
    const f = await fixture()
    let entered!: () => void, release!: () => void, authorizations = 0, closed = 0
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    const channel = new SignalChannel({ scope: f.options.scope, identity: f.options.identity, maxPendingReceives: 1,
      now: f.options.now, async authorize() { authorizations++; if (authorizations === 1) { entered(); await gate }
        return true } })
    const transport = { async trySend() { return true }, close() { closed++ } }
    const first = channel.attachRoute(transport), second = channel.attachRoute(transport)
    await f.sender.send('typing', 'held'); await f.sender.send('typing', 'later')
    const admitted = first.receive(f.frames[0]!)
    try {
      await started
      expect(await second.receive(f.frames[1]!)).toBeNull()
      await expect(channel.receive(f.frames[1]!)).resolves.toBeNull()
      expect(authorizations).toBe(1); expect(closed).toBe(0)
      release(); expect((await admitted)?.payload).toBe('held')
      expect((await second.receive(f.frames[1]!))?.payload).toBe('later')
      expect(authorizations).toBe(2); expect(closed).toBe(0)
    } finally { release(); await admitted.catch(() => undefined); channel.close(); f.sender.close(); f.receiver.close() }
  })

  it('does not refresh the TTL of a message waiting behind a backpressured send', async () => {
    const f = await fixture()
    let release!: () => void, entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const blocked = new Promise<void>(resolve => { release = resolve })
    const frames: Uint8Array[] = []
    const channel = new SignalChannel({ ...f.options, async trySend(frame) { frames.push(frame); entered(); await blocked; return true } })
    const first = channel.send('typing', 1)
    await started
    const stale = channel.send('typing', 2, { ttlMs: 1_000 })
    f.setNow(1_101); release(); await first
    await expect(stale).rejects.toThrow('SIGNAL_EXPIRED')
    expect(frames).toHaveLength(1)
    channel.close(); f.sender.close(); f.receiver.close()
  })

  it('retires an aborted noncooperative route instead of starting unlimited background sends', async () => {
    const f = await fixture()
    let calls = 0, entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const channel = new SignalChannel({ ...f.options, async trySend() { calls++; entered(); return await new Promise<never>(() => {}) } })
    const abort = new AbortController(), pending = channel.send('typing', 1, { signal: abort.signal })
    await started
    const refused = expect(pending).rejects.toThrow('cancelled')
    abort.abort(new Error('cancelled')); await refused
    // Give a cooperative cancellation one turn before retiring an outstanding write.
    await new Promise(resolve => { setTimeout(resolve, 5) })
    await expect(channel.send('typing', 2)).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    expect(calls).toBe(1)
    channel.close(); f.sender.close(); f.receiver.close()
  })

  it.each(['authorize', 'credential'] as const)('keeps cancelled %s work counted until it settles', async stage => {
    const f = await fixture()
    let entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const channel = new SignalChannel({ ...f.options, maxPendingSends: 1,
      ...(stage === 'authorize' ? { async authorize() { entered(); return new Promise<boolean>(() => {}) } }
        : { async credential() { entered(); return new Promise<Uint8Array>(() => {}) } }),
    })
    const abort = new AbortController(), pending = channel.send('typing', 1, { signal: abort.signal })
    await started
    const refused = expect(pending).rejects.toThrow('cancelled')
    abort.abort(new Error('cancelled')); await refused
    await expect(channel.send('typing', 2)).rejects.toThrow('SIGNAL_BACKPRESSURE')
    channel.close(); f.sender.close(); f.receiver.close()
  })

  it('retires a stalled relay route after its deadline instead of accumulating callbacks', async () => {
    const f = await fixture()
    let calls = 0
    const relay = new SignalChannel({ ...f.options, relay: true, sendTimeoutMs: 20,
      async trySend() { calls++; return await new Promise<never>(() => {}) } })
    await f.sender.send('typing', 1)
    expect((await relay.receive(f.frames[0]!))?.payload).toBe(1)
    await f.sender.send('typing', 2)
    expect((await relay.receive(f.frames[1]!))?.payload).toBe(2)
    expect(calls).toBe(1)
    await expect(relay.send('typing', 3)).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    relay.close(); f.sender.close(); f.receiver.close()
  })

  it('preserves independent sessions in a latest subscription', async () => {
    const f = await fixture(), secondSession = new SignalChannel(f.options)
    const iterator = f.receiver.subscribe({ mode: 'latest' })[Symbol.asyncIterator](), first = iterator.next()
    await f.sender.send('typing', 'start'); await f.receiver.receive(f.frames[0]!); await first
    await f.sender.send('typing', 'tab-one'); await f.receiver.receive(f.frames[1]!)
    await secondSession.send('typing', 'tab-two'); await f.receiver.receive(f.frames[2]!)
    expect((await iterator.next()).value?.payload).toBe('tab-one')
    expect((await iterator.next()).value?.payload).toBe('tab-two')
    await iterator.return?.(); secondSession.close(); f.sender.close(); f.receiver.close()
  })

  it('discards expired pending values before testing a FIFO capacity bound', async () => {
    const f = await fixture(), receiver = new SignalChannel({ ...f.options, maxQueuedSignals: 1 })
    const iterator = receiver.subscribe()[Symbol.asyncIterator](), first = iterator.next()
    await f.sender.send('typing', 'first'); await receiver.receive(f.frames[0]!); await first
    await f.sender.send('typing', 'expired', { ttlMs: 1_000 }); await receiver.receive(f.frames[1]!)
    f.setNow(1_101)
    await f.sender.send('typing', 'fresh'); await receiver.receive(f.frames[2]!)
    expect((await iterator.next()).value?.payload).toBe('fresh')
    await iterator.return?.(); receiver.close(); f.sender.close(); f.receiver.close()
  })

  it('returns an idle iterator immediately and releases its subscription quota', async () => {
    const f = await fixture(), receiver = new SignalChannel({ ...f.options, maxSubscriptions: 1 })
    const iterator = receiver.subscribe()[Symbol.asyncIterator](), pending = iterator.next()
    expect((await iterator.return?.())?.done).toBe(true)
    expect((await pending).done).toBe(true)
    const replacement = receiver.subscribe()[Symbol.asyncIterator](), next = replacement.next()
    await f.sender.send('typing', 1); await receiver.receive(f.frames[0]!)
    expect((await next).value?.payload).toBe(1)
    await replacement.return?.(); receiver.close(); f.sender.close(); f.receiver.close()
  })

  it('keeps healthy routes usable while a slow peer is cancelled', async () => {
    const f = await fixture(), delivered: Uint8Array[] = []
    let stalled = 0
    const channel = new SignalChannel({ ...f.options,
      async trySend() { stalled++; return await new Promise<never>(() => {}) } })
    channel.attachRoute({ async trySend(frame) { delivered.push(frame); return true } })
    const abort = new AbortController()
    await channel.send('typing', 1, { signal: abort.signal })
    await channel.send('typing', 2)
    expect(stalled).toBe(1); expect(delivered).toHaveLength(2)
    abort.abort()
    await Promise.resolve(); await Promise.resolve()
    await channel.send('typing', 3)
    expect(stalled).toBe(1); expect(delivered).toHaveLength(3)
    channel.close(); f.sender.close(); f.receiver.close()
  })
  it('keeps detached noncooperative dispatches in the route budget until actual settlement', async () => {
    const f = await fixture(), { trySend: _trySend, ...options } = f.options
    const channel = new SignalChannel({ ...options, maxRoutes: 2 })
    let release!: () => void, entered!: () => void, settled!: () => void, delivered = 0
    const started = new Promise<void>(resolve => { entered = resolve })
    const gate = new Promise<void>(resolve => { release = resolve })
    const finished = new Promise<void>(resolve => { settled = resolve })
    const stalled = channel.attachRoute({ async trySend() { entered(); await gate; settled(); return true } })
    channel.attachRoute({ async trySend() { delivered++; return true } })
    try {
      await channel.send('typing', 1)
      await started
      stalled.close()
      expect(() => channel.attachRoute({ async trySend() { return true } })).toThrow('SIGNAL_ROUTE_QUOTA_EXCEEDED')
      await channel.send('typing', 2)
      expect(delivered).toBe(2)
      release(); await finished
      await new Promise<void>(resolve => { setTimeout(resolve, 0) })
      const replacement = channel.attachRoute({ async trySend() { return true } })
      await channel.send('typing', 3)
      expect(delivered).toBe(3)
      replacement.close()
    } finally { release(); channel.close(); f.sender.close(); f.receiver.close() }
  })

  it('keeps detached receive authorization counted until the underlying policy settles', async () => {
    const f = await fixture(), { trySend: _trySend, ...options } = f.options
    let release!: () => void, entered!: () => void, authorizations = 0
    const gate = new Promise<void>(resolve => { release = resolve })
    const started = new Promise<void>(resolve => { entered = resolve })
    const channel = new SignalChannel({ ...options, maxPendingReceives: 1, async authorize() {
      authorizations++
      if (authorizations === 1) { entered(); await gate }
      return true
    } })
    const first = channel.attachRoute({ async trySend() { return true } })
    const second = channel.attachRoute({ async trySend() { return true } })
    await f.sender.send('typing', 1); await f.sender.send('typing', 2)
    const receiving = first.receive(f.frames[0]!), cancelled = expect(receiving).rejects.toThrow('SIGNAL_ROUTE_CLOSED')
    try {
      await started; first.close(); await cancelled
      expect(await second.receive(f.frames[1]!)).toBeNull()
      expect(authorizations).toBe(1)
      release(); await new Promise<void>(resolve => { setTimeout(resolve, 0) })
      expect((await second.receive(f.frames[1]!))?.payload).toBe(2)
      expect(authorizations).toBe(2)
    } finally { release(); channel.close(); f.sender.close(); f.receiver.close() }
  })

  it('preserves discrete messages by default and reports overflow instead of silently coalescing', async () => {
    const f = await fixture()
    const receiver = new SignalChannel({ ...f.options, maxQueuedSignals: 2 })
    const iterator = receiver.subscribe()[Symbol.asyncIterator]()
    const first = iterator.next()
    await f.sender.send('typing', 1); await receiver.receive(f.frames[0]!)
    expect((await first).value?.payload).toBe(1)
    await f.sender.send('typing', 2); await receiver.receive(f.frames[1]!)
    await f.sender.send('typing', 3); await receiver.receive(f.frames[2]!)
    expect((await iterator.next()).value?.payload).toBe(2)
    expect((await iterator.next()).value?.payload).toBe(3)
    for (let value = 4; value <= 6; value++) {
      await f.sender.send('typing', value); await receiver.receive(f.frames[value - 1]!)
    }
    await expect(iterator.next()).rejects.toThrow('SIGNAL_SUBSCRIPTION_OVERFLOW')
    receiver.close(); f.sender.close(); f.receiver.close()
  })

  it('accepts async verification completion in either order without accepting duplicates', async () => {
    const f = await fixture()
    let release!: () => void, entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const blocked = new Promise<void>(resolve => { release = resolve })
    let calls = 0
    const receiver = new SignalChannel({ ...f.options, async authorize() {
      if (++calls === 1) { entered(); await blocked }
      return true
    } })
    await f.sender.send('typing', 1); await f.sender.send('typing', 2)
    const earlier = receiver.receive(f.frames[0]!)
    await started
    expect((await receiver.receive(f.frames[1]!))?.payload).toBe(2)
    release()
    expect((await earlier)?.payload).toBe(1)
    await expect(receiver.receive(f.frames[0]!)).resolves.toBeNull()
    await expect(receiver.receive(f.frames[1]!)).resolves.toBeNull()
    receiver.close(); f.sender.close(); f.receiver.close()
  })

  it('does not let reordered older frames replace a latest value already consumed', async () => {
    const f = await fixture()
    const iterator = f.receiver.subscribe({ mode: 'latest' })[Symbol.asyncIterator]()
    const first = iterator.next()
    await f.sender.send('typing', 1); await f.sender.send('typing', 2)
    await f.receiver.receive(f.frames[1]!)
    expect((await first).value?.payload).toBe(2)
    await f.receiver.receive(f.frames[0]!)
    const next = iterator.next()
    await f.sender.send('typing', 3); await f.receiver.receive(f.frames[2]!)
    expect((await next).value?.payload).toBe(3)
    await iterator.return?.(); f.sender.close(); f.receiver.close()
  })

  it('works without credentials, rejects disconnected sends, and never keeps a reconnect outbox', async () => {
    const f = await fixture()
    const channel = new SignalChannel({ scope: 'room', identity: f.options.identity, authorize: () => true })
    await expect(channel.send('cursor', { x: 3 })).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    const delivered: Uint8Array[] = []
    const route = channel.attachRoute({ async trySend(bytes) { delivered.push(bytes); return true } })
    await channel.send('cursor', { x: 4 })
    expect(delivered).toHaveLength(1)
    const frame = assertCanonicalCbor(delivered[0]!) as unknown[]
    expect(frame[2]).toBe('room'); expect(frame[4]).toBeNull()
    route.close()
    await expect(channel.send('cursor', { x: 5 })).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    channel.close(); f.sender.close(); f.receiver.close()
  })

  it('cancels work waiting on policy without sending after close', async () => {
    const f = await fixture()
    let release!: () => void, entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const blocked = new Promise<void>(resolve => { release = resolve })
    const channel = new SignalChannel({ ...f.options, async authorize() { entered(); await blocked; return true } })
    const pending = channel.send('typing', 1)
    await started
    const refused = expect(pending).rejects.toThrow('SIGNAL_CHANNEL_CLOSED')
    channel.close(); release(); await refused
    expect(f.frames).toHaveLength(0)
    f.sender.close(); f.receiver.close()
  })

  it('relays original authenticated frames across live routes without replay loops', async () => {
    const identity = await generateEd25519KeyPair(), middleIdentity = await generateEd25519KeyPair(), rightIdentity = await generateEd25519KeyPair()
    const options = { scope: 'standalone-mesh', authorize: () => true }
    const left = new SignalChannel({ ...options, identity })
    const middle = new SignalChannel({ ...options, identity: middleIdentity, relay: true })
    const right = new SignalChannel({ ...options, identity: rightIdentity })
    left.attachRoute({ async trySend(frame) { await middle.receive(frame); return true } })
    middle.attachRoute({ async trySend(frame) { await left.receive(frame); return true } })
    middle.attachRoute({ async trySend(frame) { await right.receive(frame); return true } })
    const iterator = right.subscribe()[Symbol.asyncIterator]()
    const next = iterator.next()
    const sent = await left.send('progress', { step: 1 })
    expect((await next).value).toEqual(sent)
    await iterator.return?.(); left.close(); middle.close(); right.close()
  })
  it('verifies exact signed identity and rejects replay, tampering and revocation', async () => {
    const f = await fixture()
    const sent = await f.sender.send('typing', { messageId: 'draft', typing: true })
    const received = await f.receiver.receive(f.frames[0]!)
    expect(received).toEqual(sent)
    await expect(f.receiver.receive(f.frames[0]!)).resolves.toBeNull()
    const tampered = assertCanonicalCbor(f.frames[0]!) as unknown[]
    tampered[10] = 'null'
    await expect(f.receiver.receive(encodeCanonicalCbor(tampered as never))).rejects.toThrow('SIGNAL_SIGNATURE_INVALID')
    await f.sender.send('typing', false)
    f.revoke()
    await expect(f.receiver.receive(f.frames[1]!)).resolves.toBeNull()
    await expect(f.sender.send('typing', true)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    f.sender.close(); f.receiver.close()
  })

  it('accepts bounded reordering once without losing replay protection across TTLs', async () => {
    const f = await fixture()
    await f.sender.send('typing', 'older', { ttlMs: 5000 })
    await f.sender.send('typing', 'newer', { ttlMs: 1_000 })
    await f.receiver.receive(f.frames[1]!)
    f.setNow(1_101)
    expect((await f.receiver.receive(f.frames[0]!))?.payload).toBe('older')
    await expect(f.receiver.receive(f.frames[0]!)).resolves.toBeNull()
    f.setNow(5200)
    await expect(f.receiver.receive(f.frames[0]!)).resolves.toBeNull()
    f.sender.close(); f.receiver.close()
  })

  it('coalesces slow-consumer values without making a durable event history', async () => {
    const f = await fixture()
    const iterator = f.receiver.subscribe({ topics: ['typing'], mode: 'latest' })[Symbol.asyncIterator]()
    const first = iterator.next()
    await f.sender.send('typing', 1); await f.receiver.receive(f.frames[0]!)
    expect((await first).value?.payload).toBe(1)
    await f.sender.send('typing', 2); await f.receiver.receive(f.frames[1]!)
    await f.sender.send('typing', 3); await f.receiver.receive(f.frames[2]!)
    expect((await iterator.next()).value?.payload).toBe(3)
    await iterator.return?.()
    f.sender.close(); f.receiver.close()
  })

  it('bounds active sessions without evicting replay protection for live frames', async () => {
    const f = await fixture()
    const receiver = new SignalChannel({ ...f.options, maxSessions: 1 })
    await f.sender.send('typing', 1); await receiver.receive(f.frames[0]!)
    const replacement = new SignalChannel(f.options)
    await replacement.send('typing', 2)
    await expect(receiver.receive(f.frames[1]!)).resolves.toBeNull()
    f.setNow(40_000)
    await replacement.send('typing', 3)
    expect((await receiver.receive(f.frames[2]!))?.payload).toBe(3)
    replacement.close(); receiver.close(); f.sender.close(); f.receiver.close()
  })

  it('bounds outgoing queues and preserves backpressure', async () => {
    const f = await fixture()
    let release!: () => void, entered!: () => void
    const started = new Promise<void>((resolve) => { entered = resolve })
    const blocked = new Promise<void>((resolve) => { release = resolve })
    const channel = new SignalChannel({ ...f.options, maxPendingSends: 1,
      trySend: async () => { entered(); await blocked; return true } })
    const first = channel.send('typing', 1)
    await started
    await expect(channel.send('typing', 2)).rejects.toThrow('SIGNAL_BACKPRESSURE')
    release(); await first
    channel.close(); f.sender.close(); f.receiver.close()
  })
})

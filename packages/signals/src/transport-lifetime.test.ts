import { assertCanonicalCbor, encodeCanonicalCbor, generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { SignalChannel } from './index.js'

async function fixture() {
  const identity = await generateEd25519KeyPair(), receiverIdentity = await generateEd25519KeyPair()
  const scope = 'standalone-room'
  let now = 100, active = true
  const frames: Uint8Array[] = []
  const options = { scope, identity, send: async (frame: Uint8Array) => { frames.push(frame) },
    now: () => now, authorize: ({ topic }: { topic: string }) => active && topic === 'typing' }
  const sender = new SignalChannel(options)
  const receiver = new SignalChannel({ ...options, identity: receiverIdentity })
  return { sender, receiver, frames, options, setNow(value: number) { now = value }, revoke() { active = false } }
}

describe('authorized ephemeral peer signals', () => {
  it('does not refresh the TTL of a message waiting behind a backpressured send', async () => {
    const f = await fixture()
    let release!: () => void, entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const blocked = new Promise<void>(resolve => { release = resolve })
    const frames: Uint8Array[] = []
    const channel = new SignalChannel({ ...f.options, async send(frame) { frames.push(frame); entered(); await blocked } })
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
    const channel = new SignalChannel({ ...f.options, async send() { calls++; entered(); await new Promise<void>(() => {}) } })
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

  it('keeps cancelled policy work counted until it settles', async () => {
    const f = await fixture()
    let entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const channel = new SignalChannel({ ...f.options, maxPendingSends: 1,
      async authorize() { entered(); return new Promise<boolean>(() => {}) } })
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
      async send() { calls++; await new Promise<void>(() => {}) } })
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
      async send() { stalled++; await new Promise<void>(() => {}) } })
    channel.attachRoute({ async send(frame) { delivered.push(frame) } })
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
    const route = channel.attachRoute({ async send(bytes) { delivered.push(bytes) } })
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
    left.attachRoute({ async send(frame) { await middle.receive(frame) } })
    middle.attachRoute({ async send(frame) { await left.receive(frame) } })
    middle.attachRoute({ async send(frame) { await right.receive(frame) } })
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
    await expect(f.receiver.receive(f.frames[1]!)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
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
    await expect(receiver.receive(f.frames[1]!)).rejects.toThrow('SIGNAL_SESSION_QUOTA_EXCEEDED')
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
      send: async () => { entered(); await blocked } })
    const first = channel.send('typing', 1)
    await started
    await expect(channel.send('typing', 2)).rejects.toThrow('SIGNAL_BACKPRESSURE')
    release(); await first
    channel.close(); f.sender.close(); f.receiver.close()
  })
})

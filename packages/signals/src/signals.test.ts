import { assertCanonicalCbor, bytesToHex, encodeCanonicalCbor, generateEd25519KeyPair, type CborValue } from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { SignalChannel, type SignalAuthorization, type SignalChannelOptions, type SignalPolicyContext, type SignalRoute } from './index.js'

const channels: SignalChannel[] = []
afterEach(() => { for (const channel of channels.splice(0)) channel.close() })
async function channel(input: Partial<SignalChannelOptions> = {}) {
  const opened = new SignalChannel({ scope: 'standalone:test', identity: await generateEd25519KeyPair(), authorize: () => true, ...input })
  channels.push(opened)
  return opened
}
async function fixture(receiverOptions: Partial<SignalChannelOptions> = {}, senderOptions: Partial<SignalChannelOptions> = {}) {
  const frames: Uint8Array[] = []
  const sender = await channel({ trySend: async frame => { frames.push(frame.slice()); return true }, ...senderOptions })
  const receiver = await channel(receiverOptions)
  return { sender, receiver, frames }
}
function gate() {
  let enter!: () => void, release!: () => void
  const entered = new Promise<void>(resolve => { enter = resolve }), wait = new Promise<void>(resolve => { release = resolve })
  return { enter, entered, wait, release }
}

describe('standalone live signals', () => {
  it('contains signed clock rejects, reports fixed route counters, and accepts later valid signals', async () => {
    let receiverTime = 10_000, senderTime = 12_000, allowed = true
    const relayed: Uint8Array[] = []
    const { sender, receiver, frames } = await fixture({ now: () => receiverTime, relay: true, authorize: () => allowed }, { now: () => senderTime })
    const route = receiver.attachRoute({ trySend: async () => true })
    receiver.attachRoute({ trySend: async frame => { relayed.push(frame); return true } })
    const boundary = await sender.send('typing', 'at tolerance', { ttlMs: 5000 })
    expect(await route.receive(frames[0]!)).toEqual(boundary)
    senderTime++
    const future = await sender.send('typing', 'outside tolerance', { ttlMs: 5000 })
    for (let count = 0; count < 65; count++) expect(await route.receive(frames[1]!)).toBeNull()
    expect(relayed).toHaveLength(1)
    expect(route.diagnostics).toEqual({ total: 65, clockSkew: 65, expired: 0, unauthorized: 0, duplicate: 0, capacity: 0 })
    const snapshot = route.diagnostics as { total: number }; snapshot.total = -1
    expect(route.diagnostics.total).toBe(65)
    receiverTime = senderTime
    expect(await route.receive(frames[1]!)).toEqual(future)
    expect(await route.receive(frames[1]!)).toBeNull()
    receiverTime = 17_001
    expect(await route.receive(frames[1]!)).toBeNull()
    senderTime = receiverTime = 20_000
    const fresh = await sender.send('typing', 'current', { ttlMs: 5000 })
    allowed = false
    expect(await route.receive(frames[2]!)).toBeNull()
    allowed = true
    expect(await route.receive(frames[2]!)).toEqual(fresh)
    expect(route.diagnostics).toEqual({ total: 68, clockSkew: 65, expired: 1, unauthorized: 1, duplicate: 1, capacity: 0 })
    expect(relayed).toHaveLength(3)
  })

  it('does not classify malformed or unauthenticated timestamps as harmless clock skew', async () => {
    const { sender, receiver, frames } = await fixture({ now: () => 10_000 }, { now: () => 12_001 })
    const route = receiver.attachRoute({ trySend: async () => true })
    await sender.send('typing', 'future', { ttlMs: 1000 })
    const frame = assertCanonicalCbor(frames[0]!) as CborValue[]
    const signature = (frame.at(-1) as Uint8Array).slice(); signature[0] = signature[0]! ^ 1
    frame[frame.length - 1] = signature
    await expect(route.receive(encodeCanonicalCbor(frame))).rejects.toMatchObject({ code: 'SIGNAL_SIGNATURE_INVALID' })
    frame[6] = 0n
    await expect(route.receive(encodeCanonicalCbor(frame))).rejects.toMatchObject({ code: 'SIGNAL_CLOCK_INVALID' })
    frame[6] = 1n; frame[8] = frame[7]!
    await expect(route.receive(encodeCanonicalCbor(frame))).rejects.toMatchObject({ code: 'SIGNAL_CLOCK_INVALID' })
    await expect(route.receive(new Uint8Array(16_385))).rejects.toMatchObject({ code: 'SIGNAL_FRAME_TOO_LARGE' })
    expect(route.diagnostics.total).toBe(0)
  })

  it('counts unsettled route policy work across route replacements until it actually settles', async () => {
    const blocked = gate()
    let heldChecks = 0
    const frames: Uint8Array[] = [], sender = await channel({ maxRoutes: 1, maxPendingSends: 1,
      authorize: async ({ topic }) => {
        if (topic === 'held' && ++heldChecks === 3) { blocked.enter(); await blocked.wait }
        return true
      },
    })
    const route = sender.attachRoute({ async trySend(frame) { frames.push(frame); return true } })
    const controller = new AbortController(), pending = sender.send('held', 'old observation', { signal: controller.signal })
    const cancelled = expect(pending).rejects.toThrow('cancel held policy')
    try {
      await blocked.entered
      controller.abort(new Error('cancel held policy')); await cancelled
      await new Promise<void>(resolve => { setTimeout(resolve, 0) })
      route.close()
      // Closing a route cannot release a noncooperative authorization's slot.
      expect(() => sender.attachRoute({ async trySend(frame) { frames.push(frame); return true } }))
        .toThrow('SIGNAL_ROUTE_QUOTA_EXCEEDED')
      expect(frames).toEqual([])
      blocked.release()
      await new Promise<void>(resolve => { setTimeout(resolve, 0) })
      sender.attachRoute({ async trySend(frame) { frames.push(frame); return true } })
      await sender.send('fresh', 'current observation')
      expect(frames).toHaveLength(1)
      expect((await (await channel()).receive(frames[0]!))?.payload).toBe('current observation')
    } finally { blocked.release() }
  })

  it('does not move a pending send onto a replacement connection', async () => {
    const blocked = gate()
    let first = true
    const sender = await channel({ authorize: async () => {
      if (first) { first = false; blocked.enter(); await blocked.wait }
      return true
    } })
    const oldFrames: Uint8Array[] = [], newFrames: Uint8Array[] = []
    const original = sender.attachRoute({ async trySend(frame) { oldFrames.push(frame); return true } })
    const pending = sender.send('preview', 'old observation')
    const disconnected = expect(pending).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    try {
      await blocked.entered
      original.close()
      sender.attachRoute({ async trySend(frame) { newFrames.push(frame); return true } })
      blocked.release(); await disconnected
      expect(oldFrames).toEqual([]); expect(newFrames).toEqual([])
      await sender.send('preview', 'current observation')
      expect(newFrames).toHaveLength(1)
      expect((await (await channel()).receive(newFrames[0]!))?.payload).toBe('current observation')
    } finally { blocked.release() }
  })

  it('does not relay an admitted frame to a route attached during verification', async () => {
    const blocked = gate()
    let first = true
    const { sender, receiver, frames } = await fixture({ relay: true, authorize: async () => {
      if (first) { first = false; blocked.enter(); await blocked.wait }
      return true
    } })
    const oldFrames: Uint8Array[] = [], newFrames: Uint8Array[] = []
    const original = receiver.attachRoute({ async trySend(frame) { oldFrames.push(frame); return true } })
    await sender.send('preview', 'old observation')
    const pending = receiver.receive(frames[0]!)
    try {
      await blocked.entered
      original.close()
      receiver.attachRoute({ async trySend(frame) { newFrames.push(frame); return true } })
      blocked.release()
      expect((await pending)?.payload).toBe('old observation')
      expect(oldFrames).toEqual([]); expect(newFrames).toEqual([])
      await sender.send('preview', 'current observation')
      await receiver.receive(frames[1]!)
      expect(newFrames).toEqual([frames[1]])
    } finally { blocked.release() }
  })

  it.each([1, 2])('uses boolean dispatch refusal across %i routes and releases replay capacity', async count => {
    let busy = true, closed = 0
    const frames: Uint8Array[] = [], sender = await channel({ maxSequencesPerSession: 1 })
    for (let index = 0; index < count; index++) sender.attachRoute({
      async trySend(frame) { if (busy) return false; frames.push(frame); return true },
      close() { closed++ },
    })
    await expect(sender.send('preview', 'discarded')).rejects.toMatchObject({ code: 'SIGNAL_BACKPRESSURE' })
    expect(frames).toEqual([]); expect(closed).toBe(0)
    busy = false
    const fresh = await sender.send('preview', 'fresh')
    expect(frames).toHaveLength(count); expect(closed).toBe(0)
    expect(await (await channel()).receive(frames[0]!)).toEqual(fresh)
  })

  it.each([undefined, false, true])('retires transport exceptions regardless of claimed backpressure metadata: %s', async dispatched => {
    const failure = Object.assign(new Error('transport failed'), { code: 'SIGNAL_BACKPRESSURE', dispatched })
    let closed = 0
    const sender = await channel()
    sender.attachRoute({ async trySend() { throw failure }, close() { closed++ } })
    await expect(sender.send('preview', 'failed')).rejects.toBe(failure)
    expect(closed).toBe(1)
    await expect(sender.send('preview', 'fresh')).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
  })

  it('refuses congestion without retiring any route or replaying the dropped intent', async () => {
    let busy = true, closed = 0
    const frames: Uint8Array[] = []
    const sender = await channel({ maxSequencesPerSession: 1 })
    sender.attachRoute({ async trySend(frame) {
      if (busy) return false
      frames.push(frame)
      return true
    }, close() { closed++ } })
    sender.attachRoute({ async trySend() { return false }, close() { closed++ } })
    await expect(sender.send('preview', 'discarded')).rejects.toThrow('SIGNAL_BACKPRESSURE')
    expect(frames).toEqual([]); expect(closed).toBe(0)
    busy = false
    const sent = await sender.send('preview', 'fresh')
    expect(frames).toHaveLength(1); expect(closed).toBe(0)
    const receiver = await channel()
    expect(await receiver.receive(frames[0]!)).toEqual(sent)
    expect(sent.payload).toBe('fresh')
  })

  it('keeps a busy relay route for later fresh messages without buffering missed values', async () => {
    let busy = true, closed = 0
    const relayed: Uint8Array[] = []
    const { sender, receiver, frames } = await fixture({ relay: true })
    receiver.attachRoute({ async trySend(frame) {
      if (busy) return false
      relayed.push(frame)
      return true
    }, close() { closed++ } })
    await sender.send('progress', 1)
    expect((await receiver.receive(frames[0]!))?.payload).toBe(1)
    busy = false
    await sender.send('progress', 2)
    expect((await receiver.receive(frames[1]!))?.payload).toBe(2)
    expect(relayed).toEqual([frames[1]])
    expect(closed).toBe(0)
  })

  it.each(['authorize', 'credential'] as const)('cancels cooperative %s work and releases its pending-send budget', async stage => {
    const blocked = gate()
    let first = true, policySignal: AbortSignal | undefined
    const policy = async (signal: AbortSignal): Promise<void> => {
      if (!first) return
      first = false; policySignal = signal; blocked.enter()
      await new Promise<void>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true })
      })
    }
    const { sender, frames } = await fixture({}, { maxPendingSends: 1,
      ...(stage === 'authorize' ? {
        authorize: async (_input: SignalAuthorization, { signal }: SignalPolicyContext) => { await policy(signal); return true },
      } : {
        credential: async (_topic: string, { signal }: SignalPolicyContext) => { await policy(signal); return undefined },
      }),
    })
    const controller = new AbortController()
    const sending = sender.send('progress', 'expired observation', { signal: controller.signal })
    const cancelled = expect(sending).rejects.toThrow('stop policy')
    await blocked.entered
    controller.abort(new Error('stop policy')); await cancelled
    // Public cancellation may win its race before the cooperative callback's
    // finally chain returns the shared work slot. It must settle this turn.
    await new Promise<void>(resolve => { setTimeout(resolve, 0) })
    expect(policySignal?.aborted).toBe(true)
    await sender.send('progress', 'fresh observation')
    expect(frames).toHaveLength(1)
  })

  it('authenticates scoped JSON without a group, grant, database or finality provider', async () => {
    const identity = await generateEd25519KeyPair()
    const { sender, receiver, frames } = await fixture({}, { identity })
    const source = { text: 'before', samples: [1, 2] }
    const sending = sender.send('preview', source)
    source.text = 'after'; source.samples.push(3)
    const published = await sending, received = await receiver.receive(frames[0]!)
    expect(received).toEqual(published)
    expect(received).toMatchObject({ scope: 'standalone:test', authorId: bytesToHex(identity.publicKeyBytes),
      payload: { text: 'before', samples: [1, 2] } })
    expect(typeof received?.sessionId).toBe('string')
    expect(await receiver.receive(frames[0]!)).toBeNull()
    const forged = assertCanonicalCbor(frames[0]!) as CborValue[]
    forged[10] = '{"text":"forged"}'
    await expect(receiver.receive(encodeCanonicalCbor(forged))).rejects.toThrow('SIGNAL_SIGNATURE_INVALID')
    const foreign = await channel({ scope: 'another application' })
    await expect(foreign.receive(frames[0]!)).rejects.toThrow('SIGNAL_FRAME_INVALID')
  })

  it('keeps distinct fresh sequences arriving through reordered paths and suppresses only duplicates', async () => {
    const { sender, receiver, frames } = await fixture()
    for (let n = 1; n <= 3; n += 1) await sender.send('chunks', { n })
    const iterator = receiver.subscribe()[Symbol.asyncIterator](), first = iterator.next()
    expect((await receiver.receive(frames[1]!))?.sequence).toBe(2)
    expect((await first).value?.payload).toEqual({ n: 2 })
    expect((await receiver.receive(frames[0]!))?.sequence).toBe(1)
    expect(await receiver.receive(frames[1]!)).toBeNull()
    expect((await receiver.receive(frames[2]!))?.sequence).toBe(3)
    expect((await iterator.next()).value?.payload).toEqual({ n: 1 })
    expect((await iterator.next()).value?.payload).toEqual({ n: 3 })
    await iterator.return?.()
  })

  it('fails a slow all-mode subscriber visibly instead of discarding a FIFO value', async () => {
    const { sender, receiver, frames } = await fixture({ maxQueuedSignals: 2 })
    const iterator = receiver.subscribe()[Symbol.asyncIterator](), first = iterator.next()
    await sender.send('chunks', 0); await receiver.receive(frames[0]!); await first
    for (let n = 1; n <= 3; n += 1) { await sender.send('chunks', n); await receiver.receive(frames[n]!) }
    await expect(iterator.next()).rejects.toThrow('SIGNAL_SUBSCRIPTION_OVERFLOW')
  })

  it('coalesces latest values by author, session and topic while retaining other sessions', async () => {
    const identity = await generateEd25519KeyPair(), frames: Uint8Array[] = []
    const trySend = async (frame: Uint8Array) => { frames.push(frame); return true }
    const one = await channel({ identity, trySend }), two = await channel({ identity, trySend }), receiver = await channel()
    const iterator = receiver.subscribe({ mode: 'latest' })[Symbol.asyncIterator](), first = iterator.next()
    await one.send('typing', 0); await receiver.receive(frames.shift()!); await first
    await one.send('typing', 1); await one.send('typing', 2); await two.send('typing', 3); await one.send('cursor', 4)
    for (const frame of frames) await receiver.receive(frame)
    const values = [(await iterator.next()).value, (await iterator.next()).value, (await iterator.next()).value]
    expect(values.map(value => value?.payload)).toEqual([2, 3, 4])
    expect(values[0]?.sessionId).not.toBe(values[1]?.sessionId)
    await iterator.return?.()
  })

  it('bounds replay retention without evicting still-fresh sequence identities', async () => {
    let now = 1000
    const { sender, receiver, frames } = await fixture({ now: () => now, maxSequencesPerSession: 2 }, { now: () => now })
    for (let n = 0; n < 3; n += 1) await sender.send('sample', n, { ttlMs: 5000 })
    await receiver.receive(frames[0]!); await receiver.receive(frames[1]!)
    await expect(receiver.receive(frames[2]!)).resolves.toBeNull()
    expect(await receiver.receive(frames[0]!)).toBeNull()
    now += 5001
    await expect(receiver.receive(frames[0]!)).resolves.toBeNull()
    await sender.send('sample', 3, { ttlMs: 5000 })
    expect((await receiver.receive(frames[3]!))?.payload).toBe(3)
  })

  it('keeps the highest pending latest sequence when relay paths deliver three before two', async () => {
    const { sender, receiver, frames } = await fixture()
    const iterator = receiver.subscribe({ mode: 'latest' })[Symbol.asyncIterator](), first = iterator.next()
    for (let n = 1; n <= 3; n += 1) await sender.send('typing', n)
    await receiver.receive(frames[0]!); await first
    await receiver.receive(frames[2]!); await receiver.receive(frames[1]!)
    expect((await iterator.next()).value?.payload).toBe(3)
    await iterator.return?.()
  })

  it.each([2, 3])('rechecks publisher permission at asynchronous send boundary %i without losing the route', async boundary => {
    const blocked = gate()
    let allowed = true, calls = 0
    const { sender, frames } = await fixture({}, { authorize: async () => {
      calls += 1
      if (calls === boundary) { blocked.enter(); await blocked.wait }
      return allowed
    } })
    const sending = sender.send('typing', true)
    const rejected = expect(sending).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    await blocked.entered; allowed = false; blocked.release(); await rejected
    expect(frames).toHaveLength(0)
    allowed = true
    await sender.send('typing', false)
    expect(frames).toHaveLength(1)
  })

  it('cancels queued authorization promptly and keeps a healthy route for a later send', async () => {
    const blocked = gate(), controller = new AbortController()
    let first = true
    const { sender, frames } = await fixture({}, { authorize: async () => {
      if (first) { first = false; blocked.enter(); await blocked.wait }
      return true
    } })
    const sending = sender.send('preview', 'cancelled', { signal: controller.signal })
    const rejected = expect(sending).rejects.toThrow('cancelled intent')
    await blocked.entered; controller.abort(new Error('cancelled intent')); await rejected
    await sender.send('preview', 'new intent')
    blocked.release()
    expect(frames).toHaveLength(1)
    const decoded = assertCanonicalCbor(frames[0]!) as CborValue[]
    expect(decoded[10]).toBe('"new intent"')
  })

  it('expires an intent while queued instead of giving it a fresh TTL on dispatch', async () => {
    let now = 1000, first = true
    const blocked = gate(), frames: Uint8Array[] = []
    const sender = await channel({ now: () => now, trySend: async frame => {
      frames.push(frame)
      if (first) { first = false; blocked.enter(); await blocked.wait }
      return true
    } })
    const firstSend = sender.send('typing', 'first', { ttlMs: 5000 })
    await blocked.entered
    const secondSend = sender.send('typing', 'old queued intent', { ttlMs: 5000 })
    const rejected = expect(secondSend).rejects.toThrow('SIGNAL_EXPIRED')
    now = 6001; blocked.release(); await firstSend; await rejected
    await sender.send('typing', 'fresh', { ttlMs: 5000 })
    expect(frames).toHaveLength(2)
  })

  it('bounds concurrent verification and refuses malformed subscription filters', async () => {
    const blocked = gate()
    const { sender, receiver, frames } = await fixture({ maxPendingReceives: 1,
      authorize: async () => { blocked.enter(); await blocked.wait; return true } })
    await sender.send('preview', 1); await sender.send('preview', 2)
    const route = receiver.attachRoute({ trySend: async () => true })
    const receiving = route.receive(frames[0]!)
    await blocked.entered
    await expect(route.receive(frames[1]!)).resolves.toBeNull()
    expect(route.diagnostics).toEqual({ total: 1, clockSkew: 0, expired: 0, unauthorized: 0, duplicate: 0, capacity: 1 })
    blocked.release(); await receiving
    const invalid = receiver.subscribe({ topics: 'typing' as unknown as readonly string[] })[Symbol.asyncIterator]()
    await expect(invalid.next()).rejects.toThrow('SIGNAL_TOPIC_FILTER_TOO_LARGE')
  })

  it('drops a signed receive denied by current policy without remembering it or ending later delivery', async () => {
    const blocked = gate()
    let allowed = true, first = true
    const { sender, receiver, frames } = await fixture({ authorize: async () => {
      if (first) { first = false; blocked.enter(); await blocked.wait }
      return allowed
    } })
    await sender.send('typing', true)
    const receiving = receiver.receive(frames[0]!), dropped = expect(receiving).resolves.toBeNull()
    await blocked.entered; allowed = false; blocked.release(); await dropped
    allowed = true
    expect((await receiver.receive(frames[0]!))?.payload).toBe(true)
  })

  it('bounds sending and session admission without evicting live duplicate protection', async () => {
    const blocked = gate()
    const sender = await channel({ maxPendingSends: 1, trySend: async () => { blocked.enter(); await blocked.wait; return true } })
    const sending = sender.send('sample', 1)
    await blocked.entered
    await expect(sender.send('sample', 2)).rejects.toThrow('SIGNAL_BACKPRESSURE')
    blocked.release(); await sending
    const frames: Uint8Array[] = [], trySend = async (frame: Uint8Array) => { frames.push(frame); return true }
    const first = await channel({ trySend }), second = await channel({ trySend }), receiver = await channel({ maxSessions: 1 })
    await first.send('sample', 1); await second.send('sample', 2)
    await receiver.receive(frames[0]!)
    await expect(receiver.receive(frames[1]!)).resolves.toBeNull()
    expect(await receiver.receive(frames[0]!)).toBeNull()
  })

  it('releases an aborted paused subscription immediately and never revives expired frames after clock rollback', async () => {
    let now = 1000
    const { sender, receiver, frames } = await fixture({ maxSubscriptions: 1, now: () => now }, { now: () => now })
    const controller = new AbortController(), iterator = receiver.subscribe({ signal: controller.signal })[Symbol.asyncIterator]()
    const next = iterator.next()
    await sender.send('sample', 1, { ttlMs: 5000 }); await receiver.receive(frames[0]!); await next
    controller.abort()
    const fresh = new AbortController(), replacement = receiver.subscribe({ signal: fresh.signal })[Symbol.asyncIterator](), pending = replacement.next()
    fresh.abort(); expect((await pending).done).toBe(true)
    await iterator.return?.()
    now = 6001
    await expect(receiver.receive(frames[0]!)).resolves.toBeNull()
    now = 1000
    await expect(receiver.receive(frames[0]!)).resolves.toBeNull()
  })

  it('relays original authenticated bytes around a mesh once, without retaining an offline outbox', async () => {
    const a = await channel({ relay: true }), b = await channel({ relay: true }), c = await channel({ relay: true })
    const sent: Uint8Array[] = [], deliveries: Array<Promise<unknown>> = [], results: Array<unknown> = []
    const connect = (left: SignalChannel, right: SignalChannel): [SignalRoute, SignalRoute] => {
      const outgoing = left.attachRoute({ async trySend(frame) {
        sent.push(frame.slice()); deliveries.push(incoming.receive(frame).then(value => { results.push(value) }))
        return true
      } })
      const incoming = right.attachRoute({ async trySend(frame) {
        sent.push(frame.slice()); deliveries.push(outgoing.receive(frame).then(value => { results.push(value) }))
        return true
      } })
      return [outgoing, incoming]
    }
    const routes = [...connect(a, b), ...connect(b, c), ...connect(c, a)]
    const value = await a.send('attention', { id: 'one' })
    let settled = 0
    while (settled < deliveries.length) { const batch = deliveries.slice(settled); settled = deliveries.length; await Promise.all(batch) }
    expect(results.filter(result => result !== null)).toEqual([value, value])
    expect(sent).toHaveLength(4)
    for (const frame of sent) expect(frame).toEqual(sent[0])
    for (const route of routes) route.close()
    await expect(a.send('attention', 'offline')).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    const after: Uint8Array[] = []
    a.attachRoute({ async trySend(frame) { after.push(frame); return true } })
    expect(after).toHaveLength(0)
    await a.send('attention', 'new')
    expect(after).toHaveLength(1)
  })
})

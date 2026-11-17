import { assertCanonicalCbor, bytesToHex, encodeCanonicalCbor, generateEd25519KeyPair, type CborValue } from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { SignalChannel, type SignalChannelOptions, type SignalRoute } from './index.js'

const channels: SignalChannel[] = []
afterEach(() => { for (const channel of channels.splice(0)) channel.close() })
async function channel(input: Partial<SignalChannelOptions> = {}) {
  const opened = new SignalChannel({ scope: 'standalone:test', identity: await generateEd25519KeyPair(), authorize: () => true, ...input })
  channels.push(opened)
  return opened
}
async function fixture(receiverOptions: Partial<SignalChannelOptions> = {}, senderOptions: Partial<SignalChannelOptions> = {}) {
  const frames: Uint8Array[] = []
  const sender = await channel({ send: async frame => { frames.push(frame.slice()) }, ...senderOptions })
  const receiver = await channel(receiverOptions)
  return { sender, receiver, frames }
}
function gate() {
  let enter!: () => void, release!: () => void
  const entered = new Promise<void>(resolve => { enter = resolve }), wait = new Promise<void>(resolve => { release = resolve })
  return { enter, entered, wait, release }
}

describe('standalone live signals', () => {
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
    const send = async (frame: Uint8Array) => { frames.push(frame) }
    const one = await channel({ identity, send }), two = await channel({ identity, send }), receiver = await channel()
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
    await expect(receiver.receive(frames[2]!)).rejects.toThrow('SIGNAL_REPLAY_QUOTA_EXCEEDED')
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
    const sender = await channel({ now: () => now, send: async frame => {
      frames.push(frame)
      if (first) { first = false; blocked.enter(); await blocked.wait }
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
    const receiving = receiver.receive(frames[0]!)
    await blocked.entered
    await expect(receiver.receive(frames[1]!)).rejects.toThrow('SIGNAL_BACKPRESSURE')
    blocked.release(); await receiving
    const invalid = receiver.subscribe({ topics: 'typing' as unknown as readonly string[] })[Symbol.asyncIterator]()
    await expect(invalid.next()).rejects.toThrow('SIGNAL_TOPIC_FILTER_TOO_LARGE')
  })

  it('rechecks receiving permission after awaited authorization without retaining an unauthorized frame', async () => {
    const blocked = gate()
    let allowed = true, first = true
    const { sender, receiver, frames } = await fixture({ authorize: async () => {
      if (first) { first = false; blocked.enter(); await blocked.wait }
      return allowed
    } })
    await sender.send('typing', true)
    const receiving = receiver.receive(frames[0]!), rejected = expect(receiving).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    await blocked.entered; allowed = false; blocked.release(); await rejected
    allowed = true
    expect((await receiver.receive(frames[0]!))?.payload).toBe(true)
  })

  it('bounds sending and session admission without evicting live duplicate protection', async () => {
    const blocked = gate()
    const sender = await channel({ maxPendingSends: 1, send: async () => { blocked.enter(); await blocked.wait } })
    const sending = sender.send('sample', 1)
    await blocked.entered
    await expect(sender.send('sample', 2)).rejects.toThrow('SIGNAL_BACKPRESSURE')
    blocked.release(); await sending
    const frames: Uint8Array[] = [], send = async (frame: Uint8Array) => { frames.push(frame) }
    const first = await channel({ send }), second = await channel({ send }), receiver = await channel({ maxSessions: 1 })
    await first.send('sample', 1); await second.send('sample', 2)
    await receiver.receive(frames[0]!)
    await expect(receiver.receive(frames[1]!)).rejects.toThrow('SIGNAL_SESSION_QUOTA_EXCEEDED')
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
      const outgoing = left.attachRoute({ async send(frame) {
        sent.push(frame.slice()); deliveries.push(incoming.receive(frame).then(value => { results.push(value) }))
      } })
      const incoming = right.attachRoute({ async send(frame) {
        sent.push(frame.slice()); deliveries.push(outgoing.receive(frame).then(value => { results.push(value) }))
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
    a.attachRoute({ async send(frame) { after.push(frame) } })
    expect(after).toHaveLength(0)
    await a.send('attention', 'new')
    expect(after).toHaveLength(1)
  })
})

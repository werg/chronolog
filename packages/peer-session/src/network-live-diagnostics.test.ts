import { MessageChannel } from 'node:worker_threads'
import { afterEach, expect, it, vi } from 'vitest'
import type { FramedPeerConnection, PeerLiveLane } from '@chronolog/records'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'
import { createApplicationOwner } from './session-owner.js'
import { connectApplicationOwner } from './worker-application.js'
import { sessionFixture } from './test-fixture.js'

const cleanup: Array<() => Promise<unknown>> = []
afterEach(async () => { vi.restoreAllMocks(); for (const close of cleanup.splice(0).reverse()) await close() })
function pair(withLive = true) {
  const lifetime = new AbortController()
  function queue() {
    const values: Uint8Array[] = []; let wake: (() => void) | undefined
    return { push(bytes: Uint8Array) { values.push(bytes.slice()); wake?.() }, async *frames(this: void, input?: AbortSignal) {
      const signal = input === undefined ? lifetime.signal : AbortSignal.any([lifetime.signal, input]), abort = (): void => { wake?.() }
      signal.addEventListener('abort', abort)
      try { while (!signal.aborted) { if (values.length === 0) await new Promise<void>(resolve => { wake = resolve }); while (!signal.aborted && values.length > 0) yield values.shift()! } }
      finally { signal.removeEventListener('abort', abort) }
    } }
  }
  const reliable = [queue(), queue()], incomingLive = [queue(), queue()], held: Uint8Array[][] = [[], []], attempts = [0, 0]
  let refuseLive = false
  const connections = [0, 1].map(side => {
    const other = 1 - side
    const live: PeerLiveLane = { signal: lifetime.signal, frames: incomingLive[side]!.frames,
      async trySend(bytes, options = {}) { options.signal?.throwIfAborted(); attempts[side] = attempts[side]! + 1; if (refuseLive) return false; held[side]!.push(bytes.slice()); return true }, async close() { lifetime.abort() } }
    const connection: FramedPeerConnection = { signal: lifetime.signal, ...(withLive ? { live } : {}), frames: reliable[side]!.frames,
      async send(bytes, options = {}) { options.signal?.throwIfAborted(); reliable[other]!.push(bytes) }, async close() { lifetime.abort() } }
    return connection
  })
  return { connections, attempts, setRefusal(value: boolean) { refuseLive = value }, deliver(side: number) { const bytes = held[side]!.shift(); if (bytes === undefined) throw new Error('LIVE_FRAME_NOT_DISPATCHED'); incomingLive[1 - side]!.push(bytes) } }
}
async function until(predicate: () => boolean): Promise<void> {
  const deadline = performance.now() + 3000
  while (!predicate()) { if (performance.now() > deadline) throw new Error('LIVE_DIAGNOSTICS_TIMEOUT'); await new Promise<void>(resolve => setImmediate(resolve)) }
}
it('exports actual bounded live protocol bytes and nonfatal authenticated freshness drops without changing the connection', async () => {
  const f = await sessionFixture(), a = await f.open(0), b = await f.open(1), transport = pair()
  cleanup.push(() => a.close(), () => b.close())
  const links = await Promise.all([a.connectPeer({ connection: transport.connections[0]! }), b.connectPeer({ connection: transport.connections[1]! })]); cleanup.push(async () => { await Promise.all(links.map(link => link.close())) })
  await a.retryMaterialization(); await b.retryMaterialization()
  const physical = b.status.connectionRevision, applicationRevision = b.revision.digest, base = Date.now(), clock = vi.spyOn(Date, 'now').mockReturnValue(base)
  const subscription = b.signals.subscribe({ topics: ['qualification'] })[Symbol.asyncIterator]()
  const initial = (await b.diagnostics())[0]!.signalRejections!
  expect(initial).toEqual({ total: 0, clockSkew: 0, expired: 0, unauthorized: 0, duplicate: 0, capacity: 0 })
  transport.setRefusal(true); await a.signals.send('qualification', 'locally dispatched only')
  await until(() => transport.attempts[0]! > 0); await new Promise<void>(resolve => setImmediate(resolve))
  expect(links[0].stats.sentLiveBytes).toBe(0); expect(links[1].stats.receivedLiveBytes).toBe(0); transport.setRefusal(false)
  async function transmit(label: string, issued: number, receiver: number, ttlMs = 5000): Promise<void> {
    const before = links[0].stats.sentLiveBytes!
    clock.mockReturnValue(issued); await a.signals.send('qualification', label, { ttlMs })
    await until(() => links[0].stats.sentLiveBytes! > before)
    // Deliver the genuine encrypted SDK frame only after its sender finished admission.
    clock.mockReturnValue(receiver); transport.deliver(0)
  }
  await transmit('boundary-1999', base + 1999, base); expect((await subscription.next()).value?.payload).toBe('boundary-1999')
  await transmit('boundary-2000', base + 2000, base); expect((await subscription.next()).value?.payload).toBe('boundary-2000')
  for (let index = 0; index < 65; index++) {
    await transmit(`future-${index}`, base + 2001, base)
    await until(() => links[1].stats.signalRejections!.clockSkew === index + 1)
  }
  await transmit('expired', base + 2002, base + 3102, 1000)
  await until(() => links[1].stats.signalRejections!.expired === 1)
  await transmit('healthy-after-drops', base + 3102, base + 3102)
  expect((await subscription.next()).value?.payload).toBe('healthy-after-drops')
  const snapshot = (await b.diagnostics())[0]!
  expect(snapshot.signalRejections).toEqual({ total: 66, clockSkew: 65, expired: 1, unauthorized: 0, duplicate: 0, capacity: 0 })
  expect(snapshot.receivedLiveBytes).toBeGreaterThan(0); expect((await a.diagnostics())[0]!.sentLiveBytes).toBe(snapshot.receivedLiveBytes)
  for (const count of Object.values(snapshot.signalRejections!)) expect(Number.isSafeInteger(count) && count >= 0).toBe(true)
  Reflect.set(snapshot.signalRejections!, 'total', -1); expect((await b.diagnostics())[0]!.signalRejections!.total).toBe(66)
  const owner = createApplicationOwner(b), channel = new MessageChannel(); owner.attach(channel.port1 as unknown as ApplicationWorkerEndpoint, { capabilities: ['diagnostics'] })
  const client = await connectApplicationOwner(channel.port2 as unknown as ApplicationWorkerEndpoint, { applicationId: f.applicationId }); cleanup.push(() => owner.close(), () => client.detach())
  const remote = (await client.diagnostics())[0]!
  expect(remote.signalRejections).toEqual({ total: 66, clockSkew: 65, expired: 1, unauthorized: 0, duplicate: 0, capacity: 0 })
  expect(remote.receivedLiveBytes).toBe(snapshot.receivedLiveBytes); expect(client.status.connectionRevision).toBe(physical)
  expect(b.status.connectionRevision).toBe(physical); expect(b.revision.digest).toBe(applicationRevision); expect(links.every(link => !link.signal.aborted)).toBe(true)
  clock.mockRestore(); await subscription.return?.()
  const operation = await a.command('say', 'durable after skew', { authorTimestampMs: 1n }); await operation.materialized(); await links[0].synchronize(); await b.retryMaterialization()
  expect((await b.readEvents()).events[0]?.payload).toBe('durable after skew'); expect(b.status.connectionRevision).toBe(physical)
})
it('omits unavailable live instrumentation instead of fabricating zero counters', async () => {
  const f = await sessionFixture(), a = await f.open(0), b = await f.open(1), transport = pair(false)
  cleanup.push(() => a.close(), () => b.close())
  const links = await Promise.all([a.connectPeer({ connection: transport.connections[0]! }), b.connectPeer({ connection: transport.connections[1]! })]); cleanup.push(async () => { await Promise.all(links.map(link => link.close())) })
  const snapshot = (await a.diagnostics())[0]!
  expect('sentLiveBytes' in snapshot).toBe(false); expect('receivedLiveBytes' in snapshot).toBe(false); expect('signalRejections' in snapshot).toBe(false)
})

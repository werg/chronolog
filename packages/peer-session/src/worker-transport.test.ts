import { afterEach, describe, expect, it, vi } from 'vitest'
import { openWebRtcConnection, type PeerDescription } from '@chronolog/transport-webrtc'
import type * as WebRtc from '@chronolog/transport-webrtc'
import { openWorkerWebRtcConnection, serveWorkerWebRtcConnections, type ApplicationWorkerEndpoint } from './worker-transport.js'

vi.mock('@chronolog/transport-webrtc', async importOriginal => ({
  ...await importOriginal<typeof WebRtc>(), openWebRtcConnection: vi.fn(),
}))
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close(); vi.useRealTimers(); vi.clearAllMocks() })
const PROTOCOL = 'chronolog/peer-session/rtc-endpoint/v1'
class Endpoint implements ApplicationWorkerEndpoint {
  readonly events = new EventTarget()
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void { this.events.addEventListener(type, listener as EventListener) }
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void { this.events.removeEventListener(type, listener as EventListener) }
  dispatchEvent(event: Event): void { this.events.dispatchEvent(event) }
  peer!: Endpoint
  sent: Array<Record<string, unknown>> = []
  postMessage(...args: [Record<string, unknown>]): void {
    expect(args).toHaveLength(1) // Virtual/Broadcast endpoints cannot transfer ports or RTC objects.
    const data = structuredClone(args[0]); this.sent.push(data)
    queueMicrotask(() => {
      this.peer.dispatchEvent(new MessageEvent('message', { data }))
      this.dispatchEvent(new MessageEvent('message', { data })) // Ignore own broadcasts by direction.
    })
  }
}
function endpoints() { const page = new Endpoint(), worker = new Endpoint(); page.peer = worker; worker.peer = page; return { page, worker } }
function stream(signal: AbortSignal) {
  const queue: Uint8Array[] = []; let wake = () => {}
  signal.addEventListener('abort', () => wake(), { once: true })
  return { push(bytes: Uint8Array) { queue.push(bytes); wake() }, async *frames() {
    while (!signal.aborted) {
      const next = queue.shift()
      if (next !== undefined) yield next
      else await new Promise<void>(resolve => { wake = resolve })
    }
  } }
}
function rtc() {
  const lifetime = new AbortController(), reliable = stream(lifetime.signal), live = stream(lifetime.signal)
  const close = vi.fn(async () => { lifetime.abort(new Error('RTC closed')) })
  const result = { signal: lifetime.signal, ready: Promise.resolve(), close,
    send: vi.fn(async () => {}), frames: () => reliable.frames(),
    live: { signal: lifetime.signal, close, trySend: vi.fn(async () => true), frames: () => live.frames() },
    session: { signal: lifetime.signal, close, getRoute: vi.fn(async () => ({ route: 'direct', localCandidateType: 'host', remoteCandidateType: 'host' })) },
  } as unknown as Awaited<ReturnType<typeof openWebRtcConnection>>
  return { result, close, reliable, live }
}
function signaling(remote: PeerDescription = { type: 'answer', sdp: 'remote SDP' }) {
  return { messages: { async *[Symbol.asyncIterator]() { yield remote } }, send: vi.fn(async () => {}), close: vi.fn(async () => {}) }
}
function negotiate(connection: ReturnType<typeof rtc>) {
  vi.mocked(openWebRtcConnection).mockImplementation(async options => {
    const remote = await options.signaling.messages[Symbol.asyncIterator]().next()
    expect(remote.value).toEqual({ type: options.role === 'offerer' ? 'answer' : 'offer', sdp: 'remote SDP' })
    await options.signaling.send({ type: options.role === 'offerer' ? 'offer' : 'answer', sdp: 'local SDP' })
    await options.signaling.close(); return connection.result
  })
}

describe('portable Worker RTC endpoint', () => {
  it('uses page raw framing, opaque bidirectional lanes and dispatch ACKs without any transfers', async () => {
    const pair = endpoints(), connection = rtc(), observed = signaling(); negotiate(connection)
    const page = serveWorkerWebRtcConnections(pair.page); cleanup.push(() => page.close())
    const opened = await openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: observed, timeoutMs: 5000, gatheringTimeoutMs: 750 })
    cleanup.push(() => opened.close())
    expect(vi.mocked(openWebRtcConnection).mock.calls[0]?.[0].gatheringTimeoutMs).toBe(750)
    expect(observed.send).toHaveBeenCalledWith({ type: 'offer', sdp: 'local SDP' }); expect(observed.close).toHaveBeenCalledOnce()
    await opened.send(new Uint8Array([9]))
    // eslint-disable-next-line @typescript-eslint/unbound-method -- Test spy at raw boundary.
    expect(connection.result.send).toHaveBeenCalledWith(new Uint8Array([9]), { signal: expect.any(AbortSignal) })
    // eslint-disable-next-line @typescript-eslint/unbound-method -- Raw boundary test spy.
    vi.mocked(connection.result.live.trySend).mockResolvedValueOnce(false)
    expect(await opened.live!.trySend(new Uint8Array([8]))).toBe(false)
    expect(await opened.live!.trySend(new Uint8Array([7]))).toBe(true)
    const reader = opened.frames()[Symbol.asyncIterator](), incoming = reader.next()
    connection.reliable.push(new Uint8Array([1, 2, 3]))
    expect(await incoming).toEqual({ done: false, value: new Uint8Array([1, 2, 3]) })
    expect(pair.worker.sent.some(value => value.action === 'ack' && value.lane === 'reliable')).toBe(false)
    const next = reader.next(); void next.catch(() => undefined)
    await vi.waitFor(() => expect(pair.worker.sent.some(value => value.action === 'ack' && value.lane === 'reliable')).toBe(true))
    expect(await opened.getRoute()).toEqual({ route: 'direct', localCandidateType: 'host', remoteCandidateType: 'host' })
    await opened.close(); await expect(next).rejects.toThrow('APPLICATION_RTC_CLOSED')
    await vi.waitFor(() => expect(connection.close).toHaveBeenCalledOnce())
  })

  it('multiplexes concurrent routes and ignores foreign IDs and other application protocols', async () => {
    const pair = endpoints(), connections = [rtc(), rtc()]; let index = 0
    vi.mocked(openWebRtcConnection).mockImplementation(async options => {
      const connection = connections[index++]!
      await options.signaling.send({ type: 'offer', sdp: 'local SDP' }); await options.signaling.close(); return connection.result
    })
    const page = serveWorkerWebRtcConnections(pair.page); cleanup.push(() => page.close())
    const opened = await Promise.all(connections.map(() => openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: signaling() })))
    for (const connection of opened) cleanup.push(() => connection.close())
    pair.page.postMessage({ type: PROTOCOL, from: 'page', id: crypto.randomUUID(), action: 'ended' })
    pair.page.postMessage({ type: 'application-rpc', action: 'ended' })
    await opened[1]!.send(new Uint8Array([2])); await opened[0]!.send(new Uint8Array([1]))
    // eslint-disable-next-line @typescript-eslint/unbound-method -- Raw boundary test spies.
    expect(connections.map(c => vi.mocked(c.result.send).mock.calls[0]?.[0]?.[0])).toEqual([1, 2])
    expect(opened.every(c => !c.signal.aborted)).toBe(true)
  })

  it('bounds negotiations and validates options before creating RTC', async () => {
    vi.mocked(openWebRtcConnection).mockImplementation(() => new Promise(() => {}))
    const pair = endpoints(), page = serveWorkerWebRtcConnections(pair.page); cleanup.push(() => page.close())
    pair.worker.postMessage({ type: PROTOCOL, from: 'worker', id: crypto.randomUUID(), action: 'open', role: 'coordinator', timeoutMs: 5000 })
    await vi.waitFor(() => expect(pair.page.sent.at(-1)?.error).toBe('APPLICATION_WORKER_OPTIONS_INVALID'))
    expect(openWebRtcConnection).not.toHaveBeenCalled()
    for (let i = 0; i < 17; i++) pair.worker.postMessage({ type: PROTOCOL, from: 'worker', id: crypto.randomUUID(), action: 'open', role: 'offerer', timeoutMs: 5000 })
    await vi.waitFor(() => expect(pair.page.sent.at(-1)?.error).toBe('APPLICATION_PEER_LIMIT'))
    expect(openWebRtcConnection).toHaveBeenCalledTimes(16)
    const first = page.close(); expect(page.close()).toBe(first); await first
  })

  it('fences cancelled negotiation and closes a late raw RTC result without publishing ready or data', async () => {
    const pair = endpoints(), connection = rtc(), observed = signaling(), abort = new AbortController()
    let finish!: (value: typeof connection.result) => void
    vi.mocked(openWebRtcConnection).mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const page = serveWorkerWebRtcConnections(pair.page); cleanup.push(() => page.close())
    const opening = openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: observed, signal: abort.signal, timeoutMs: 5000 })
    const rejected = expect(opening).rejects.toThrow('stop owner')
    await vi.waitFor(() => expect(openWebRtcConnection).toHaveBeenCalledOnce())
    abort.abort(new Error('stop owner')); await rejected; finish(connection.result)
    await vi.waitFor(() => expect(connection.close).toHaveBeenCalledOnce())
    expect(observed.close).toHaveBeenCalledOnce(); expect(pair.page.sent.some(v => v.action === 'ready' || v.action === 'frame')).toBe(false)
  })

  it('rejects wrong-role or oversized SDP and premature readiness; bounds a silent endpoint', async () => {
    for (const remote of [{ type: 'offer', sdp: 'wrong role' }, { type: 'answer', sdp: 'x'.repeat(65_537) }] as const) {
      const pair = endpoints(), page = serveWorkerWebRtcConnections(pair.page); cleanup.push(() => page.close())
      vi.mocked(openWebRtcConnection).mockImplementation(() => new Promise(() => {}))
      const observed = signaling(remote)
      await expect(openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: observed, timeoutMs: 5000 })).rejects.toThrow('APPLICATION_WORKER_DESCRIPTION_INVALID')
      expect(observed.close).toHaveBeenCalledOnce()
    }
    const pair = endpoints()
    pair.page.addEventListener('message', (event: Event) => {
      const value = (event as MessageEvent).data as Record<string, unknown>
      if (value.from === 'worker' && value.action === 'open') pair.page.postMessage({ type: PROTOCOL, from: 'page', id: value.id, action: 'ready' })
    })
    await expect(openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: signaling(), timeoutMs: 1000 })).rejects.toThrow('APPLICATION_WORKER_MESSAGE_INVALID')
    const silent = endpoints()
    await expect(openWorkerWebRtcConnection(silent.worker, { role: 'offerer', signaling: signaling(), timeoutMs: 5 })).rejects.toThrow('APPLICATION_WORKER_CONNECTION_TIMEOUT')
  })
})

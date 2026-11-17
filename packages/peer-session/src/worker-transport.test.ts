import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { frameRtcPeerChannels, negotiateWebRtc, type PeerDescription, type WebRtcSession } from '@chronolog/transport-webrtc'
import type * as WebRtc from '@chronolog/transport-webrtc'
import { openWorkerWebRtcConnection, serveWorkerWebRtcConnections, type ApplicationWorkerEndpoint } from './worker-transport.js'

vi.mock('@chronolog/transport-webrtc', async importOriginal => ({
  ...await importOriginal<typeof WebRtc>(), frameRtcPeerChannels: vi.fn(), negotiateWebRtc: vi.fn(),
}))
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => {
  for (const close of cleanup.splice(0).reverse()) await close()
  vi.unstubAllGlobals(); vi.clearAllMocks()
})

/** Transfer ownership is inspected here; actual RTCDataChannel transfer runs in Chromium qualification. */
class Port extends EventTarget {
  peer!: Port
  closed = false
  postMessage(data: unknown): void {
    if (this.closed) return
    queueMicrotask(() => { if (!this.peer.closed) this.peer.dispatchEvent(new MessageEvent('message', { data })) })
  }
  start(): void {}
  close(): void { this.closed = true }
}
class Channel {
  port1 = new Port()
  port2 = new Port()
  constructor() { this.port1.peer = this.port2; this.port2.peer = this.port1 }
}
function endpoints() {
  const channel = new Channel()
  return { page: channel.port1 as unknown as ApplicationWorkerEndpoint, worker: channel.port2 as unknown as ApplicationWorkerEndpoint }
}
function rtc() {
  const lifetime = new AbortController()
  const close = vi.fn(async () => { lifetime.abort(new Error('RTC closed')) })
  const result = { signal: lifetime.signal, close,
    getRoute: vi.fn(async () => ({ route: 'direct', localCandidateType: 'host', remoteCandidateType: 'host' })),
  } as unknown as WebRtcSession
  return { result, close }
}
function frame() {
  const lifetime = new AbortController()
  return { signal: lifetime.signal, ready: Promise.resolve(), live: { signal: lifetime.signal },
    send: vi.fn(async () => {}), frames: vi.fn(async function* () { yield new Uint8Array([1, 2, 3]) }),
    close: vi.fn(async () => { lifetime.abort(new Error('frames closed')) }),
  } as unknown as ReturnType<typeof frameRtcPeerChannels>
}
function signaling(remote: PeerDescription = { type: 'answer', sdp: 'remote SDP' }) {
  return { messages: { async *[Symbol.asyncIterator]() { yield remote } }, send: vi.fn(async () => {}), close: vi.fn(async () => {}) }
}
beforeEach(() => {
  vi.stubGlobal('MessageChannel', Channel)
  vi.mocked(frameRtcPeerChannels).mockImplementation(() => frame())
})

describe('Worker-owned RTC negotiation', () => {
  it('keeps signaling and framing in the owner while the page supplies raw channels', async () => {
    const pair = endpoints(), connection = rtc(), framed = frame(), observed = signaling()
    const transferred = { reliable: { close: vi.fn() }, live: { close: vi.fn() } }
    vi.mocked(frameRtcPeerChannels).mockReturnValue(framed)
    vi.mocked(negotiateWebRtc).mockImplementation(async options => {
      options.onDataChannels(transferred as never)
      const remote = await options.signaling.messages[Symbol.asyncIterator]().next()
      expect(remote.value).toEqual({ type: 'answer', sdp: 'remote SDP' })
      await options.signaling.send({ type: 'offer', sdp: 'local SDP' })
      await options.signaling.close()
      return connection.result
    })
    const page = serveWorkerWebRtcConnections(pair.page); cleanup.push(() => page.close())
    const opened = await openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: observed, timeoutMs: 5000 })
    cleanup.push(() => opened.close())
    expect(frameRtcPeerChannels).toHaveBeenCalledWith(transferred)
    expect(observed.send).toHaveBeenCalledWith({ type: 'offer', sdp: 'local SDP' })
    expect(observed.close).toHaveBeenCalledOnce()
    await opened.send(new Uint8Array([9]))
    // eslint-disable-next-line @typescript-eslint/unbound-method -- The framed boundary is a test spy.
    expect(framed.send).toHaveBeenCalledWith(new Uint8Array([9]), undefined)
    expect(await opened.frames()[Symbol.asyncIterator]().next()).toEqual({ done: false, value: new Uint8Array([1, 2, 3]) })
    expect(await opened.getRoute()).toEqual({ route: 'direct', localCandidateType: 'host', remoteCandidateType: 'host' })
    await opened.close()
    await vi.waitFor(() => expect(connection.close).toHaveBeenCalledOnce())
    // eslint-disable-next-line @typescript-eslint/unbound-method -- The framed boundary is a test spy.
    expect(framed.close).toHaveBeenCalledOnce()
    expect(opened.signal.aborted).toBe(true)
  })

  it('bounds concurrent page negotiations and rejects malformed options before opening RTC', async () => {
    vi.mocked(negotiateWebRtc).mockImplementation(async () => new Promise(() => {}))
    const pair = endpoints(), page = serveWorkerWebRtcConnections(pair.page)
    cleanup.push(() => page.close())
    const request = (fields: Record<string, unknown> = {}) => {
      const channel = new Channel(), values: unknown[] = []
      channel.port1.addEventListener('message', event => values.push((event as MessageEvent).data))
      pair.worker.postMessage({ type: 'chronolog/peer-session/rtc-negotiation/v1', role: 'offerer', timeoutMs: 5000,
        port: channel.port2, ...fields }, [])
      cleanup.push(() => { channel.port1.close(); channel.port2.close() })
      return values
    }
    const invalid = request({ role: 'coordinator' })
    await vi.waitFor(() => expect(invalid).toEqual([{ type: 'ended', error: 'APPLICATION_WORKER_OPTIONS_INVALID' }]))
    expect(negotiateWebRtc).not.toHaveBeenCalled()
    for (let index = 0; index < 8; index++) request()
    const excess = request()
    await vi.waitFor(() => expect(excess).toEqual([{ type: 'ended', error: 'APPLICATION_PEER_LIMIT' }]))
    expect(negotiateWebRtc).toHaveBeenCalledTimes(8)
    const first = page.close(); expect(page.close()).toBe(first); await first
  })

  it('fences a noncooperative page negotiation and closes its late successful result', async () => {
    const pair = endpoints(), connection = rtc(), observed = signaling(), abort = new AbortController()
    let finish!: (value: WebRtcSession) => void
    vi.mocked(negotiateWebRtc).mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const page = serveWorkerWebRtcConnections(pair.page); cleanup.push(() => page.close())
    const opening = openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: observed, signal: abort.signal, timeoutMs: 5000 })
    const rejected = expect(opening).rejects.toThrow('stop owner')
    await vi.waitFor(() => expect(negotiateWebRtc).toHaveBeenCalledOnce())
    abort.abort(new Error('stop owner')); await rejected
    finish(connection.result)
    await vi.waitFor(() => expect(connection.close).toHaveBeenCalledOnce())
    expect(observed.close).toHaveBeenCalledOnce()
    expect(frameRtcPeerChannels).not.toHaveBeenCalled()
  })

  it('rejects wrong-role or oversized descriptions without leaving an open signaling lifetime', async () => {
    const pair = endpoints(), page = serveWorkerWebRtcConnections(pair.page)
    cleanup.push(() => page.close())
    vi.mocked(negotiateWebRtc).mockImplementation(async () => new Promise(() => {}))
    for (const remote of [{ type: 'offer', sdp: 'wrong role' }, { type: 'answer', sdp: 'x'.repeat(65_537) }] as const) {
      const observed = signaling(remote)
      await expect(openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: observed, timeoutMs: 5000 }))
        .rejects.toThrow('APPLICATION_WORKER_DESCRIPTION_INVALID')
      expect(observed.close).toHaveBeenCalledOnce()
    }
  })

  it('rejects readiness without transferred channels and retires duplicate channels', async () => {
    const pair = endpoints(), framed = frame(), transferred = { reliable: { close: vi.fn() }, live: { close: vi.fn() } }
    const duplicate = { reliable: { close: vi.fn() }, live: { close: vi.fn() } }
    vi.mocked(frameRtcPeerChannels).mockReturnValue(framed)
    let repeat = false
    pair.page.addEventListener('message', event => {
      const port = (event.data as { port: Port }).port
      if (!repeat) { port.postMessage({ type: 'ready' }); return }
      port.postMessage({ type: 'channels', ...transferred })
      port.postMessage({ type: 'channels', ...duplicate })
    })
    await expect(openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: signaling(), timeoutMs: 5000 }))
      .rejects.toThrow('APPLICATION_WORKER_MESSAGE_INVALID')
    expect(frameRtcPeerChannels).not.toHaveBeenCalled()
    repeat = true
    await expect(openWorkerWebRtcConnection(pair.worker, { role: 'offerer', signaling: signaling(), timeoutMs: 5000 }))
      .rejects.toThrow('APPLICATION_WORKER_CHANNELS_REPEATED')
    expect(duplicate.reliable.close).toHaveBeenCalledOnce(); expect(duplicate.live.close).toHaveBeenCalledOnce()
    // eslint-disable-next-line @typescript-eslint/unbound-method -- The framed boundary is a test spy.
    expect(framed.close).toHaveBeenCalledOnce()
  })
})

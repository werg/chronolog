import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ApplicationSession } from './session.js'
import { installApplicationWorkerTransport, type ApplicationWorkerEndpoint } from './worker-transport.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

class Channel extends EventTarget {
  readonly maxPacketLifeTime = null
  readonly bufferedAmount = 0
  readonly maxRetransmits: number | null
  readonly ordered: boolean
  binaryType = 'arraybuffer'
  bufferedAmountLowThreshold = 0
  readyState: RTCDataChannelState = 'connecting'
  constructor(live = false) { super(); this.ordered = !live; this.maxRetransmits = live ? 0 : null }
  send(): never { throw new Error('An unopened test channel cannot dispatch') }
  close(): void {
    if (this.readyState === 'closed') return
    this.readyState = 'closed'; this.dispatchEvent(new Event('close'))
  }
}

function owner(connect?: () => Promise<unknown>) {
  const listeners = new Set<(event: MessageEvent) => void>(), lifetime = new AbortController()
  const endpoint: ApplicationWorkerEndpoint = {
    postMessage: () => {}, addEventListener: (_type, listener) => { listeners.add(listener) },
    removeEventListener: (_type, listener) => { listeners.delete(listener) },
  }
  const connectPeer = vi.fn(connect ?? ((...args: unknown[]) => {
    const input = args[0] as { signal: AbortSignal }
    return new Promise((_resolve, reject) => { input.signal.addEventListener('abort', () => reject(input.signal.reason), { once: true }) })
  }))
  const session = { signal: lifetime.signal, connectPeer } as unknown as ApplicationSession
  const transport = installApplicationWorkerTransport(session, endpoint)
  cleanup.push(() => transport.close())
  const transfer = (options: Record<string, unknown> = {}) => {
    const channels = new MessageChannel(), reliable = new Channel(), live = new Channel(true)
    cleanup.push(() => channels.port1.close(), () => channels.port2.close())
    const result = new Promise<Record<string, unknown>>(resolve => {
      channels.port1.addEventListener('message', event => resolve(event.data as Record<string, unknown>), { once: true }); channels.port1.start()
    })
    const data = { type: 'chronolog/peer-session/rtc-channels/v1', port: channels.port2, reliable, live,
      peerIdentity: '11'.repeat(32), timeoutMs: 1000, ...options }
    for (const listener of listeners) listener(new MessageEvent('message', { data }))
    return { result, reliable, live }
  }
  return { connectPeer, transport, transfer }
}

describe('Worker-owned peer channel handoff', () => {
  it('retires both transferred channels when options fail before framing', async () => {
    const worker = owner(), transfer = worker.transfer({ peerIdentity: 'untrusted hint' })
    expect(await transfer.result).toMatchObject({ type: 'ended', error: 'APPLICATION_WORKER_OPTIONS_INVALID' })
    expect(transfer.reliable.readyState).toBe('closed'); expect(transfer.live.readyState).toBe('closed')
    expect(worker.connectPeer).not.toHaveBeenCalled()
  })

  it('bounds opening peers before authentication and joins repeated shutdown', async () => {
    const worker = owner(), opening = Array.from({ length: 8 }, () => worker.transfer())
    const rejected = worker.transfer()
    expect(await rejected.result).toMatchObject({ type: 'ended', error: 'APPLICATION_PEER_LIMIT' })
    expect(rejected.reliable.readyState).toBe('closed'); expect(rejected.live.readyState).toBe('closed')
    expect(worker.connectPeer).toHaveBeenCalledTimes(8)
    const first = worker.transport.close(), second = worker.transport.close()
    expect(first).toBe(second); await first
    for (const transfer of opening) {
      expect(transfer.reliable.readyState).toBe('closed'); expect(transfer.live.readyState).toBe('closed')
      expect(await transfer.result).toMatchObject({ type: 'ended' })
    }
  })

  it('does not publish readiness for a connection that ended before attachment', async () => {
    const ended = new AbortController(); ended.abort(new Error('late authentication'))
    const synchronize = vi.fn(async () => {}), close = vi.fn(async () => {})
    const worker = owner(async () => ({ peerId: '11'.repeat(32), signal: ended.signal, completion: Promise.resolve(),
      stats: { sentBytes: 0, receivedBytes: 0, sentRequests: 0, receivedRequests: 0 }, synchronize, close }))
    const transfer = worker.transfer()
    expect(await transfer.result).toMatchObject({ type: 'ended', error: 'late authentication' })
    expect(synchronize).not.toHaveBeenCalled(); expect(close).toHaveBeenCalledOnce()
    expect(transfer.reliable.readyState).toBe('closed'); expect(transfer.live.readyState).toBe('closed')
  })
})

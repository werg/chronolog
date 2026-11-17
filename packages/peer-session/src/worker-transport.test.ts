import { afterEach, describe, expect, it, vi } from 'vitest'
import type { WebRtcChannels, WebRtcSession } from '@chronolog/transport-webrtc'
import { connectWorkerApplicationWebRtc, type ApplicationWorkerEndpoint } from './worker-transport.js'

const mock = vi.hoisted(() => ({ negotiate: vi.fn() }))
vi.mock('@chronolog/transport-webrtc', async importOriginal => ({
  ...await importOriginal<typeof import('@chronolog/transport-webrtc')>(), negotiateWebRtc: mock.negotiate,
}))
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close(); mock.negotiate.mockReset() })

function fixture(invalid: 'ready' | 'result') {
  const expectedPeerId = '31'.repeat(32), lifetime = new AbortController()
  const close = vi.fn(async () => { lifetime.abort(new Error('RTC_CLOSED')) })
  const rtc = { signal: lifetime.signal, close } as unknown as WebRtcSession
  const validStats = { sentBytes: 0, receivedBytes: 0, sentRequests: 0, receivedRequests: 0 }
  mock.negotiate.mockImplementation(async (options: { onDataChannels(channels: WebRtcChannels): void }) => {
    options.onDataChannels({ reliable: {}, live: {} } as WebRtcChannels)
    return rtc
  })
  const endpoint: ApplicationWorkerEndpoint = {
    postMessage(message) {
      const { port } = message as { port: MessagePort }
      cleanup.push(() => { port.close() })
      port.addEventListener('message', event => {
        const value = event.data as { type: string; id: number }
        if (value.type === 'synchronize') port.postMessage({ type: 'result', id: value.id, stats: { ...validStats, receivedBytes: -1 } })
      })
      port.start()
      port.postMessage({ type: 'ready', peerId: expectedPeerId, stats: invalid === 'ready' ? null : validStats })
    },
    addEventListener() {}, removeEventListener() {},
  }
  const connect = () => connectWorkerApplicationWebRtc(endpoint, {
    expectedPeerId, role: 'offerer', timeoutMs: 1000,
    signaling: { async *messages() {}, async send() {}, close() {} },
  })
  return { connect, close }
}

describe('Worker application transport response ownership', () => {
  it('rejects malformed readiness and retires the RTC lifetime', async () => {
    const f = fixture('ready')
    await expect(f.connect()).rejects.toThrow('APPLICATION_WORKER_STATS_INVALID')
    expect(f.close).toHaveBeenCalledOnce()
  })

  it('rejects a malformed synchronization result instead of orphaning its waiter', async () => {
    const f = fixture('result'), link = await f.connect()
    cleanup.push(() => link.close())
    await expect(link.synchronize()).rejects.toThrow('APPLICATION_WORKER_STATS_INVALID')
    expect(link.signal.aborted).toBe(true)
    await link.close()
    expect(f.close).toHaveBeenCalledOnce()
  })
})

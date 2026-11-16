import { createHttpWebRtcSignaling, negotiateWebRtc } from '@chronolog/transport-webrtc'
import type { HttpWebRtcSignaling, WebRtcSession } from '@chronolog/transport-webrtc'

import type { BrowserEventBootstrap, BrowserEventIdentity } from './event-contract.js'

const worker = new Worker('/webrtc-worker.js', { type: 'module' })
const pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
let nextId = 0, session: WebRtcSession | undefined, attached: Promise<unknown> | undefined
let signaling: HttpWebRtcSignaling | undefined
worker.addEventListener('message', (event: MessageEvent) => {
  const reply = event.data as { id: number; value?: unknown; error?: string }, call = pending.get(reply.id)
  pending.delete(reply.id)
  if (reply.error === undefined) call?.resolve(reply.value)
  else call?.reject(new Error(reply.error))
})
function command(method: string, fields: Record<string, unknown> = {}, transfer: Transferable[] = []): Promise<unknown> {
  const id = ++nextId
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`WEBRTC_WORKER_TIMEOUT: ${method}`)) }, 30_000)
    pending.set(id, { resolve(value) { clearTimeout(timer); resolve(value) }, reject(error) { clearTimeout(timer); reject(error) } })
    worker.postMessage({ id, method, ...fields }, transfer)
  })
}
const api = {
  prepare: (name: string) => command('prepare', { name }) as Promise<BrowserEventIdentity>,
  open: (name: string, bootstrap: BrowserEventBootstrap) => command('open', { name, bootstrap }),
  async connect(options: { url: string; token: string }) {
    signaling = createHttpWebRtcSignaling({ url: options.url, headers: { Authorization: `Bearer ${options.token}` } })
    session = await negotiateWebRtc({ role: 'offerer', configuration: { iceServers: [] }, signaling, onDataChannel(channel) {
      // Transfer immediately: no send(), awaited work or task boundary before
      // postMessage. Private keys and framed application bytes stay in Worker.
      attached = command('channel', { channel }, [channel as RTCDataChannel])
      void attached.catch(() => undefined)
    } })
    try { await attached } catch (error) { await session.close(); throw error }
    return { signalingClosed: signaling.stats.closed, ...session.signaling, http: signaling.stats, workerOwnsChannel: true }
  },
  publish: (operationId: string, text: string) => command('publish', { operationId, text }),
  payload: (hash: string) => command('payload', { hash }),
  state: () => command('state'),
  signaling: () => ({ signalingClosed: signaling!.stats.closed, ...session!.signaling, http: signaling!.stats }),
  async close() { try { await command('close') } finally { await session?.close(); worker.terminate() } },
}
Object.assign(globalThis, { chronologWebRtcTest: api })
export type WebRtcTestApi = typeof api

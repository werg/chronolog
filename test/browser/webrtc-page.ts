import { negotiateWebRtc } from '@chronolog/transport-webrtc'
import type { PeerDescription, WebRtcSession } from '@chronolog/transport-webrtc'

import type { BrowserEventBootstrap, BrowserEventIdentity } from './event-contract.js'

const worker = new Worker('/webrtc-worker.js', { type: 'module' })
const pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
let nextId = 0, session: WebRtcSession | undefined, attached: Promise<unknown> | undefined
let sentMessages = 0, sentBytes = 0, receivedMessages = 0, receivedBytes = 0, signalingClosed = false
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
  async connect() {
    let answer!: (description: PeerDescription) => void
    const received = new Promise<PeerDescription>(resolve => { answer = resolve })
    session = await negotiateWebRtc({ role: 'offerer', configuration: { iceServers: [] }, signaling: {
      messages: { async *[Symbol.asyncIterator]() { yield await received } },
      async send(description) {
        sentMessages += 1; sentBytes += new TextEncoder().encode(description.sdp).length
        const response = await fetch('/signal', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(description) })
        if (!response.ok) throw new Error(`WEBRTC_SIGNAL_HTTP_${response.status}`)
        const value = await response.json() as PeerDescription
        receivedMessages += 1; receivedBytes += new TextEncoder().encode(value.sdp).length
        answer(value)
      },
      close() { signalingClosed = true },
    }, onDataChannel(channel) {
      // Transfer immediately: no send(), awaited work or task boundary before
      // postMessage. Private keys and framed application bytes stay in Worker.
      attached = command('channel', { channel }, [channel as RTCDataChannel])
      void attached.catch(() => undefined)
    } })
    await attached
    return { signalingClosed, sentMessages, receivedMessages, sentBytes, receivedBytes, workerOwnsChannel: true }
  },
  publish: (operationId: string, text: string) => command('publish', { operationId, text }),
  payload: (hash: string) => command('payload', { hash }),
  state: () => command('state'),
  signaling: () => ({ signalingClosed, sentMessages, receivedMessages, sentBytes, receivedBytes }),
  async close() { try { await command('close') } finally { await session?.close(); worker.terminate() } },
}
Object.assign(globalThis, { chronologWebRtcTest: api })
export type WebRtcTestApi = typeof api

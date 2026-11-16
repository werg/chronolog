import { createHttpWebRtcSignaling, negotiateWebRtc, type WebRtcSession } from '@chronolog/transport-webrtc'

import type { ThinMembershipBootstrap } from '../../tools/thin-membership-native.js'

const pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void; timer: ReturnType<typeof setTimeout> }>()
const introductions: Array<{ requests: number; requestBytes: number; responseBytes: number; closed: boolean }> = []
let worker: Worker, sequence = 0, bootstrap: ThinMembershipBootstrap | undefined, session: WebRtcSession | undefined
let opening: Promise<unknown> | undefined
let openingAbort: AbortController | undefined
function open(): void {
  worker = new Worker('/membership-worker.mjs', { type: 'module' })
  worker.onmessage = ({ data }: MessageEvent<{ id: number; error?: string; value: unknown }>) => {
    const entry = pending.get(data.id)
    if (entry === undefined) return
    pending.delete(data.id); clearTimeout(entry.timer)
    document.querySelector('#status')!.textContent = JSON.stringify(data, (_key, value: unknown) => typeof value === 'bigint' ? String(value) : value, 2)
    if (data.error === undefined) entry.resolve(data.value); else entry.reject(new Error(data.error))
  }
  worker.onerror = event => {
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error(event.message)) }
    pending.clear()
  }
}
function command(value: Record<string, unknown>, transfer: Transferable[] = []): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const id = ++sequence
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Device command timed out: ${String(value.method)}`)) }, 75_000)
    pending.set(id, { resolve, reject, timer })
    try { worker.postMessage({ ...value, id }, transfer) }
    catch (error) { clearTimeout(timer); pending.delete(id); reject(error) }
  })
}
async function disconnect(): Promise<void> {
  openingAbort?.abort(new Error('THIN_PAGE_DISCONNECTED'))
  const previous = session
  session = undefined
  try { await command({ method: 'disconnect' }) } finally { await previous?.close() }
}
async function connect(): Promise<unknown> {
  if (session !== undefined) {
    const state = await command({ method: 'status' }) as { connected: boolean }
    if (state.connected) return state
    await session.close(); session = undefined
  }
  if (bootstrap === undefined) throw new Error('THIN_PAGE_NOT_OPEN')
  const controller = new AbortController()
  const signaling = createHttpWebRtcSignaling({ url: bootstrap.rtcUrl,
    headers: { Authorization: `Bearer ${bootstrap.rtcToken}` }, signal: controller.signal })
  openingAbort = controller
  try {
    let attached: Promise<unknown> | undefined
    const introduced = await negotiateWebRtc({ role: 'offerer', signaling, signal: controller.signal, configuration: { iceServers: [] }, onDataChannel(channel) {
      attached = command({ method: 'channel', channel }, [channel as RTCDataChannel])
      void attached.catch(() => undefined)
    } })
    introductions.push(signaling.stats)
    try { const result = await attached; session = introduced; return result }
    catch (error) { await introduced.close(); throw error }
  } catch (error) { signaling.close(); throw error }
  finally { if (openingAbort === controller) openingAbort = undefined }
}
open()
Object.assign(globalThis, { thinMembership: {
  async call(value: Record<string, unknown>): Promise<unknown> {
    if (value.method === 'open') bootstrap = value.bootstrap as ThinMembershipBootstrap
    if (value.method === 'connect') {
      const current = opening ??= connect()
      try { return await current } finally { if (opening === current) opening = undefined }
    }
    if (value.method === 'disconnect') { await disconnect(); return command({ method: 'status' }) }
    if (value.method === 'close') { await disconnect(); return command(value) }
    if (value.method === 'rtcStats') return { transport: 'webrtc', channelOwner: 'DedicatedWorker', introductions }
    return command(value)
  },
  async replaceWorker() {
    // Abrupt storage-owner replacement remains abrupt; no Worker close RPC.
    openingAbort?.abort(new Error('THIN_PAGE_WORKER_REPLACED'))
    const previous = session; session = undefined; bootstrap = undefined
    worker.terminate()
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('Worker replaced')) }
    pending.clear(); await previous?.close(); open()
  },
} })

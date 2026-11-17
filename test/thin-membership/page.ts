import { createHttpWebRtcSignaling, negotiateWebRtc, supervisePeerSession, type WebRtcSession } from '@chronolog/transport-webrtc'

import type { ThinMembershipBootstrap } from '../../tools/thin-membership-native.js'

const pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void; timer: ReturnType<typeof setTimeout> }>()
const introductions: Array<{ requests: number; requestBytes: number; responseBytes: number; closed: boolean }> = []
const commandTimeoutMs = 75_000
let worker: Worker, sequence = 0, connectionSequence = 0, activeConnection = 0, bootstrap: ThinMembershipBootstrap | undefined
let storageName: string | undefined
let owner = new AbortController()
let supervisor: ReturnType<typeof supervisePeerSession<WebRtcSession>> | undefined
function open(): void {
  worker = new Worker('/membership-worker.mjs', { type: 'module' })
  worker.onmessage = ({ data }: MessageEvent<{ id: number; kind?: string; connectionId?: number; error?: string; value: unknown }>) => {
    if (data.kind === 'peer-ended') {
      if (data.connectionId === activeConnection) void supervisor?.session?.close()
      return
    }
    const entry = pending.get(data.id)
    if (entry === undefined) return
    pending.delete(data.id); clearTimeout(entry.timer)
    document.querySelector('#status')!.textContent = JSON.stringify(data, (_key, value: unknown) => typeof value === 'bigint' ? String(value) : value, 2)
    if (data.error === undefined) entry.resolve(data.value); else entry.reject(new Error(data.error))
  }
  worker.onerror = event => {
    owner.abort(new Error(event.message))
    for (const entry of pending.values()) entry.reject(new Error(event.message))
    pending.clear()
  }
}
function command(value: Record<string, unknown>, transfer: Transferable[] = [], signal?: AbortSignal): Promise<unknown> {
  signal?.throwIfAborted()
  return new Promise((resolve, reject) => {
    const id = ++sequence
    const clear = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort) }
    const abort = () => { clear(); pending.delete(id); reject(signal?.reason) }
    const timer = setTimeout(() => { clear(); pending.delete(id); reject(new Error(`Device command timed out: ${String(value.method)}`)) }, commandTimeoutMs)
    pending.set(id, { resolve(value) { clear(); resolve(value) }, reject(error) { clear(); reject(error) }, timer })
    signal?.addEventListener('abort', abort, { once: true })
    try { worker.postMessage({ ...value, id }, transfer) }
    catch (error) { clear(); pending.delete(id); reject(error) }
  })
}
async function disconnect(): Promise<void> {
  const previous = supervisor
  supervisor = undefined
  activeConnection = ++connectionSequence
  const closing = previous?.close()
  try { await command({ method: 'disconnect' }) } finally { await closing }
}
async function connect(): Promise<unknown> {
  if (bootstrap === undefined) throw new Error('THIN_PAGE_NOT_OPEN')
  if (supervisor?.state.phase === 'stopped') supervisor = undefined
  supervisor ??= supervisePeerSession({ signal: owner.signal, readiness: 'authenticated',
    // Membership qualification explicitly controls each reconnect and approval.
    // A revoked reader must wait for the next participant operation.
    retry: { initialDelayMs: 250, maxDelayMs: 1_000, maxAttempts: 1 }, async connect(signal) {
      const signaling = createHttpWebRtcSignaling({ url: bootstrap!.rtcUrl,
        headers: { Authorization: `Bearer ${bootstrap!.rtcToken}` }, signal })
      let introduced: WebRtcSession | undefined
      try {
        let attached: Promise<unknown> | undefined
        introduced = await negotiateWebRtc({ role: 'offerer', signaling, signal, configuration: { iceServers: [] }, onDataChannels(channels) {
          activeConnection = ++connectionSequence
          attached = command({ method: 'channel', channels, connectionId: activeConnection },
            [channels.reliable as RTCDataChannel, channels.live as RTCDataChannel], signal)
          void attached.catch(() => undefined)
        } })
        introductions.push(signaling.stats)
        await attached
        signal.throwIfAborted()
        return introduced
      } catch (error) { signaling.close(); await introduced?.close(); throw error }
    } })
  await supervisor.waitForSession()
  return command({ method: 'progress' })
}
open()
Object.assign(globalThis, { thinMembership: {
  async call(value: Record<string, unknown>): Promise<unknown> {
    if ((value.method === 'prepare' || value.method === 'open') && typeof value.name === 'string') storageName = value.name
    if (value.method === 'open') bootstrap = value.bootstrap as ThinMembershipBootstrap
    if (value.method === 'connect') {
      return connect()
    }
    if (value.method === 'disconnect') { await disconnect(); return null }
    if (value.method === 'close') { await disconnect(); return command(value) }
    if (value.method === 'rtcStats') return { transport: 'webrtc', channelOwner: 'DedicatedWorker', introductions }
    return command(value)
  },
  async replaceWorker() {
    // Abrupt storage-owner replacement remains abrupt; no Worker close RPC.
    owner.abort(new Error('THIN_PAGE_WORKER_REPLACED'))
    const previous = supervisor; supervisor = undefined; bootstrap = undefined
    const previousStorageName = storageName; storageName = undefined
    worker.terminate()
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('Worker replaced')) }
    pending.clear(); await previous?.close()
    // terminate() has no completion promise. Observe release of the actual
    // ownership lock before asking a replacement Worker to claim it.
    if (previousStorageName !== undefined) await navigator.locks.request(`chronolog:${previousStorageName}`,
      { mode: 'exclusive', signal: AbortSignal.timeout(commandTimeoutMs) }, () => undefined)
    owner = new AbortController(); open()
  },
} })

addEventListener('pagehide', () => { owner.abort(new Error('THIN_PAGE_CLOSED')); worker.terminate(); void supervisor?.close() })

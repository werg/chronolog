import type { HttpWebRtcSignaling, WebRtcChannels, SupervisedPeerSession, WebRtcSession, supervisePeerSession } from '@chronolog/transport-webrtc'

import type { BrowserEventBootstrap, BrowserEventIdentity } from './event-contract.js'

type ResidentSession = WebRtcSession & { readonly introduction: HttpWebRtcSignaling['stats'] }
interface ResidentRecipe {
  connectResidentWorker(this: void, options: { readonly endpoint: string; readonly headers: HeadersInit; readonly configuration: RTCConfiguration;
    readonly signal: AbortSignal; readonly retry: { readonly initialDelayMs: number; readonly maxDelayMs: number; readonly maxAttempts: number };
    readonly attach: (channels: WebRtcChannels, signal: AbortSignal) => Promise<SupervisedPeerSession> }): ReturnType<typeof supervisePeerSession<ResidentSession>>
}
// This module is bundled from the exact public contrib recipe supplied to the CLI.
const { connectResidentWorker } = await import(new URL('./connect-resident-worker.js', import.meta.url).href) as ResidentRecipe
const worker = new Worker('/webrtc-worker.js', { type: 'module' })
const lifetime = new AbortController()
const pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
const sessions: ResidentSession[] = []
const attachments = new Map<number, AbortController>()
let nextId = 0, attachmentSequence = 0, supervisor: ReturnType<typeof supervisePeerSession<ResidentSession>> | undefined
worker.addEventListener('message', (event: MessageEvent) => {
  const status = event.data as { kind?: string; attachmentId?: number; error?: string }
  if (status.kind === 'peer-ended') {
    attachments.get(status.attachmentId!)?.abort(new Error(status.error ?? 'WEBRTC_WORKER_PEER_ENDED'))
    return
  }
  const reply = event.data as { id: number; value?: unknown; error?: string }, call = pending.get(reply.id)
  pending.delete(reply.id)
  if (reply.error === undefined) call?.resolve(reply.value)
  else call?.reject(new Error(reply.error))
})
worker.addEventListener('error', event => {
  const error = new Error(event.message)
  lifetime.abort(error)
  for (const waiter of pending.values()) waiter.reject(error)
  pending.clear()
})
function command(method: string, fields: Record<string, unknown> = {}, transfer: Transferable[] = [], signal?: AbortSignal): Promise<unknown> {
  signal?.throwIfAborted()
  const id = ++nextId
  return new Promise((resolve, reject) => {
    const clear = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort) }
    const abort = () => { clear(); pending.delete(id); reject(signal?.reason) }
    const timer = setTimeout(() => { clear(); pending.delete(id); reject(new Error(`WEBRTC_WORKER_TIMEOUT: ${method}`)) }, 30_000)
    pending.set(id, { resolve(value) { clear(); resolve(value) }, reject(error) { clear(); reject(error) } })
    signal?.addEventListener('abort', abort, { once: true })
    try { worker.postMessage({ id, method, ...fields }, transfer) }
    catch (error) { clear(); pending.delete(id); reject(error) }
  })
}
function attach(channels: WebRtcChannels, signal: AbortSignal): Promise<SupervisedPeerSession> {
  const attachmentId = ++attachmentSequence, controller = new AbortController()
  attachments.set(attachmentId, controller)
  let closing: Promise<void> | undefined
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing
    closing = Promise.resolve().then(async () => {
      if (!lifetime.signal.aborted) await command('disconnect', { attachmentId }, [], lifetime.signal)
    })
    signal.removeEventListener('abort', abort)
    attachments.delete(attachmentId)
    controller.abort(new Error('WEBRTC_WORKER_ATTACHMENT_CLOSED'))
    return closing
  }
  const abort = (): void => { controller.abort(signal.reason); void close().catch(() => undefined) }
  signal.addEventListener('abort', abort, { once: true })
  // command transfers synchronously, before this function returns its promise.
  return command('channel', { channels, attachmentId }, [channels.reliable as RTCDataChannel, channels.live as RTCDataChannel], signal).then(
    () => ({ signal: controller.signal, close }),
    async (error: unknown) => { await close().catch(() => undefined); throw error })
}
function signaling(session: ResidentSession) {
  return { signalingClosed: session.introduction.closed, ...session.signaling, http: session.introduction,
    introductions: sessions.map(value => value.introduction), state: supervisor!.state }
}
const api = {
  prepare: (name: string) => command('prepare', { name }) as Promise<BrowserEventIdentity>,
  open: (name: string, bootstrap: BrowserEventBootstrap) => command('open', { name, bootstrap }),
  async connect(options: { url: string; token: string }) {
    supervisor ??= connectResidentWorker({ endpoint: options.url, headers: { Authorization: `Bearer ${options.token}` },
      configuration: { iceServers: [] }, signal: lifetime.signal,
      retry: { initialDelayMs: 50, maxDelayMs: 200, maxAttempts: 4 }, attach })
    const session = await supervisor.waitForSession()
    if (!sessions.includes(session)) sessions.push(session)
    return { ...signaling(session), workerOwnsChannel: true, route: await session.getRoute() }
  },
  async interrupt() {
    if (supervisor === undefined) throw new Error('WEBRTC_SESSION_REQUIRED')
    const previous = await supervisor.waitForSession()
    await command('disconnect')
    const current = await supervisor.waitForSession()
    if (current === previous) throw new Error('WEBRTC_RECONNECT_DID_NOT_REPLACE_SESSION')
    if (!sessions.includes(current)) sessions.push(current)
    return { ...signaling(current), route: await current.getRoute() }
  },
  publish: (operationId: string, text: string) => command('publish', { operationId, text }),
  payload: (hash: string) => command('payload', { hash }),
  state: () => command('state'),
  signaling: async () => signaling(await supervisor!.waitForSession()),
  async close() {
    lifetime.abort(new Error('WEBRTC_WORKER_OWNER_CLOSED'))
    try { await command('close') } finally { await supervisor?.close(); worker.terminate() }
  },
}
addEventListener('pagehide', () => { lifetime.abort(new Error('WEBRTC_WORKER_OWNER_CLOSED')); worker.terminate(); void supervisor?.close() })
Object.assign(globalThis, { chronologWebRtcTest: api })
export type WebRtcTestApi = typeof api

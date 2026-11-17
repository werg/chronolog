import { createHttpWebRtcSignaling } from '@chronolog/transport-webrtc'
import { connectWorkerApplicationWebRtc } from '@chronolog/peer-session/webrtc'
import type { AppliedResult, ContentReference, ContentRetention, SignedAttempt, SignedRetainedCoverage } from '@chronolog/peer-session'
import type { Bootstrap, BrowserState } from './contract.js'

const worker = new Worker('/generation-rtc-worker.js', { type: 'module' })
const pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
let next = 0, link: Awaited<ReturnType<typeof connectWorkerApplicationWebRtc>> | undefined
let closing: Promise<void> | undefined
const introductions: Array<ReturnType<typeof createHttpWebRtcSignaling>> = []
worker.addEventListener('message', event => {
  const reply = event.data as { type?: string; id: number; value?: unknown; error?: string }
  if (reply.type !== 'generation-rtc-fixture-reply') return
  const waiter = pending.get(reply.id); pending.delete(reply.id)
  if (reply.error === undefined) waiter?.resolve(reply.value); else waiter?.reject(new Error(reply.error))
})
worker.addEventListener('error', event => {
  for (const waiter of pending.values()) waiter.reject(new Error(event.message))
  pending.clear()
})
function command<T>(method: string, fields: Record<string, unknown> = {}): Promise<T> {
  if (pending.size >= 16) return Promise.reject(new Error('GENERATION_RTC_FIXTURE_REQUEST_LIMIT'))
  const id = ++next
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`GENERATION_RTC_FIXTURE_TIMEOUT: ${method}`)) }, 45_000)
    pending.set(id, { resolve(value) { clearTimeout(timer); resolve(value as T) }, reject(error) { clearTimeout(timer); reject(error) } })
    try { worker.postMessage({ type: 'generation-rtc-fixture', id, method, ...fields }) }
    catch (error) { clearTimeout(timer); pending.delete(id); reject(error) }
  })
}
const api = {
  prepare: (name: string) => command<{ publicKey: string; storageId: string }>('prepare', { name }),
  open: (bootstrap: Bootstrap) => command<BrowserState>('open', { bootstrap }),
  async connect(options: { url: string; token: string; peerIdentity: string }) {
    const signaling = createHttpWebRtcSignaling({ url: options.url, headers: { Authorization: `Bearer ${options.token}` } })
    introductions.push(signaling)
    link = await connectWorkerApplicationWebRtc(worker, { role: 'offerer', signaling, peerIdentity: options.peerIdentity,
      configuration: { iceServers: [] }, timeoutMs: 30_000 })
    return { peerId: link.peerId, route: await link.rtc.getRoute(), stats: link.stats,
      signaling: signaling.stats, state: await command<BrowserState>('state') }
  },
  async disconnect() { await link?.close(); link = undefined },
  save: (operationId: string, text: string) => command<{ state: { status: string }; attempt: SignedAttempt }>('save', { operationId, text }),
  publish: (operationId: string, text: string) => command<{ applied: AppliedResult; attempt: SignedAttempt }>('publish', { operationId, text }),
  shared: (operationId: string) => command<readonly SignedRetainedCoverage[]>('shared', { operationId }),
  signal: (text: string) => command('signal', { text }),
  content: (reference: ContentReference) => command<{ bytes: number; sha256: string; retained: ContentRetention }>('content', { reference }),
  state: () => command<BrowserState>('state'),
  async transport() { await link!.synchronize(); return { stats: link!.stats, signaling: introductions.map(value => value.stats), route: await link!.rtc.getRoute() } },
  async reopen() { await link?.close(); link = undefined; return command<BrowserState>('reopen') },
  close() {
    closing ??= (async () => {
      try { await link?.close(); await command('close') } finally { worker.terminate() }
    })()
    return closing
  },
}
Object.assign(globalThis, { peerGenerationRtcTest: api })
export type GenerationRtcTestApi = typeof api

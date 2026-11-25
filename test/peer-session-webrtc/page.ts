import type { OperationInspection as InlineOperationInspection } from '@chronolog/peer-session'
import { serveWorkerWebRtcConnections } from '@chronolog/peer-session/webrtc'
import type { MaterializedOperation, ApplicationPeerLink, ContentReference, ContentRetention, SignedOperationEnvelope, RetentionEvidence } from '@chronolog/peer-session'
import type { HttpWebRtcSignaling, WebRtcRoute } from '@chronolog/transport-webrtc'
import type { Bootstrap, BrowserState } from './contract.js'

interface ConnectionObservation {
  readonly peerIdentity: string
  readonly route: WebRtcRoute
  readonly stats: ApplicationPeerLink['stats']
  readonly signaling: HttpWebRtcSignaling['stats']
  readonly state: BrowserState
}
interface TransportObservation {
  readonly stats: ApplicationPeerLink['stats']
  readonly signaling: readonly HttpWebRtcSignaling['stats'][]
  readonly route: WebRtcRoute
}

const worker = new Worker('/authored-rtc-worker.js', { type: 'module' })
const rtc = serveWorkerWebRtcConnections(worker)
const pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
let next = 0
let closing: Promise<void> | undefined
worker.addEventListener('message', event => {
  const reply = event.data as { type?: string; id: number; value?: unknown; error?: string }
  if (reply.type !== 'authored-rtc-fixture-reply') return
  const waiter = pending.get(reply.id); pending.delete(reply.id)
  if (reply.error === undefined) waiter?.resolve(reply.value); else waiter?.reject(new Error(reply.error))
})
worker.addEventListener('error', event => {
  for (const waiter of pending.values()) waiter.reject(new Error(event.message))
  pending.clear()
})
function command<T>(method: string, fields: Record<string, unknown> = {}): Promise<T> {
  if (pending.size >= 16) return Promise.reject(new Error('AUTHORED_RTC_FIXTURE_REQUEST_LIMIT'))
  const id = ++next
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`AUTHORED_RTC_FIXTURE_TIMEOUT: ${method}`)) }, 45_000)
    pending.set(id, { resolve(value) { clearTimeout(timer); resolve(value as T) }, reject(error) { clearTimeout(timer); reject(error) } })
    try { worker.postMessage({ type: 'authored-rtc-fixture', id, method, ...fields }) }
    catch (error) { clearTimeout(timer); pending.delete(id); reject(error) }
  })
}
const api = {
  prepare: (name: string) => command<{ publicKey: string; storageId: string }>('prepare', { name }),
  open: (bootstrap: Bootstrap) => command<BrowserState>('open', { bootstrap }),
  connect: (options: { url: string; token: string; peerIdentity: string }) => command<ConnectionObservation>('connect', { options }),
  disconnect: () => command('disconnect'),
  save: (operationId: string, text: string) => command<{ state: InlineOperationInspection; intent: SignedOperationEnvelope }>('save', { operationId, text }),
  publish: (operationId: string, text: string) => command<{ materialized: MaterializedOperation; intent: SignedOperationEnvelope }>('publish', { operationId, text }),
  retained: (operationId: string) => command<readonly RetentionEvidence[]>('retained', { operationId }),
  signal: (text: string) => command('signal', { text }),
  content: (reference: ContentReference) => command<{ bytes: number; sha256: string; retained: ContentRetention }>('content', { reference }),
  finalize: () => command<{ closedThroughMs: string | null; events: BrowserState['events']; revision: BrowserState['revision']; signer: string }>('finalize'),
  state: () => command<BrowserState>('state'),
  transport: () => command<TransportObservation>('transport'),
  reopen: () => command<BrowserState>('reopen'),
  close() {
    closing ??= (async () => {
      try { await command('close') } finally { await rtc.close(); worker.terminate() }
    })()
    return closing
  },
}
Object.assign(globalThis, { authoredRtcTest: api })
export type AuthoredRtcTestApi = typeof api

import { ChronologClient } from '@chronolog/client'
import { base64UrlToBytes, type EventPayload } from '@chronolog/protocol'
import type { RpcTransport, RpcCallOptions, UnaryRpcMethod, UnaryRequest, UnaryResponse } from '@chronolog/rpc/browser'
import { WorkerRpcTransport } from '@chronolog/runtime-browser'
import { createChronologApplicationBackend } from '@chronolog/transport-tendriller'
import type { EphemeralSignal } from '@chronolog/agent-service/signals'
import type { WebRtcSession } from '@chronolog/transport-webrtc'

import type { BrowserEventIdentity } from '../browser/event-contract.js'
import type { PeerIntroductionModule, PilotBootstrap, PilotWindow, PublicKernel } from './contract.js'

const target = globalThis as unknown as PilotWindow
const device = new URL(globalThis.location.href).searchParams.get('device')
if (device !== 'board' && device !== 'compact') throw new Error('PILOT_DEVICE_REQUIRED')
const name = `application-pilot-${device}`
// Terminating a previous page's Worker releases its OPFS lease asynchronously.
await navigator.locks.request(`chronolog:${name}`, { mode: 'exclusive', signal: AbortSignal.timeout(30_000) }, () => undefined)
const worker = new Worker(new URL('./worker.mjs', import.meta.url), { type: 'module' })
const pending = new Map<number, { resolve(value: unknown): void; reject(error: Error): void }>()
const connectionErrors: string[] = []
let sequence = 0
worker.addEventListener('message', (event: MessageEvent) => {
  const response = event.data as { pilot?: string; id?: number; value?: unknown; error?: string }
  if (response.pilot === 'connection-error') { connectionErrors.push(response.error ?? 'Unknown connection failure'); return }
  if (response.pilot !== 'response' || response.id === undefined) return
  const waiter = pending.get(response.id)
  if (waiter === undefined) return
  pending.delete(response.id)
  if (response.error === undefined) waiter.resolve(response.value)
  else waiter.reject(new Error(response.error))
})
const command = (pilot: string, fields: Record<string, unknown> = {}, timeoutMs = 30_000, transfer: Transferable[] = []): Promise<unknown> => {
  const id = ++sequence
  return new Promise((resolve, reject) => {
    const timer = timeoutMs === 0 ? undefined : setTimeout(() => { pending.delete(id); reject(new Error(`PILOT_WORKER_TIMEOUT: ${pilot}`)) }, timeoutMs)
    const clear = () => { if (timer !== undefined) clearTimeout(timer) }
    pending.set(id, { resolve(value) { clear(); resolve(value) }, reject(error) { clear(); reject(error) } })
    try { worker.postMessage({ pilot, id, ...fields }, transfer) }
    catch (error) { clear(); pending.delete(id); reject(error) }
  })
}
const registration = await fetch(`/pilot/registered?device=${device}`)
if (!registration.ok) throw new Error(`PILOT_REGISTRATION_CHECK_FAILED: ${registration.status}`)
const registered = await registration.json() as { registered: boolean }
const prepared = await command('prepare', { name, createIdentity: !registered.registered }) as BrowserEventIdentity
const response = await fetch('/pilot/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ device, identity: prepared }) })
if (!response.ok) throw new Error(`PILOT_BOOTSTRAP_FAILED: ${response.status}`)
const bootstrap = await response.json() as PilotBootstrap
const opened = await command('open', { name, bootstrap: bootstrap.peer }) as { groupId: string; identity: string }

// The public peer runtime owns explicit host introduction only. Its application
// binding can wait for the Worker without starting a diagnostic/socket lifecycle.
const kernel = await import(new URL('./tendriller/kernel.mjs', import.meta.url).href) as PublicKernel
target.tendril = kernel.startRuntime({ id: 'peer-application-pilot', base: bootstrap.hostBase, version: 0, documentPath: null,
  ws: new URL('_tendril/socket', bootstrap.hostBase).href.replace(/^http/u, 'ws'),
  application: { kind: 'peer', id: bootstrap.applicationId }, features: { push: false, vapid: null, shared_by: '', speech: null } })
// This bundle is built from the exact supplied contrib recipe, not a pilot copy.
const { introducePeerWorker } = await import(new URL('./introduce-peer-worker.mjs', import.meta.url).href) as PeerIntroductionModule
let session: WebRtcSession | undefined
const sessions: WebRtcSession[] = []
async function connect(): Promise<void> {
  if (session !== undefined) return
  let attached: Promise<unknown> | undefined
  const introduced = await introducePeerWorker({ peers: target.tendril.peers, channel: crypto.randomUUID(), peerId: device!,
    configuration: { iceServers: [] }, handoff(channel) {
      // Transfer in the creation callback before any awaited work. The Worker
      // alone frames and authenticates the channel, then opens feed replication.
      attached = command('channel', { channel }, 30_000, [channel as RTCDataChannel])
      void attached.catch(() => undefined)
    } })
  sessions.push(introduced)
  try { await attached; session = introduced }
  catch (error) { await introduced.close(); throw error }
}
async function disconnect(): Promise<void> {
  const previous = session
  session = undefined
  try { await command('disconnect') } finally { await previous?.close() }
}
await connect()
const rpc = new WorkerRpcTransport(worker)
let hold: { promise: Promise<void>; release(): void; receipt: { operationId: string; proposalId: string } | null } | null = null
const transport: RpcTransport = {
  async unary<M extends UnaryRpcMethod>(method: M, request: UnaryRequest<M>, options?: RpcCallOptions): Promise<UnaryResponse<M>> {
    const gate = method === 'change.submit' ? hold : null
    const result = await rpc.unary(method, request, options)
    if (gate !== null) {
      const receipt = result as { operationId: string; proposalId: string }
      gate.receipt = { operationId: receipt.operationId, proposalId: receipt.proposalId }
      await gate.promise
    }
    return result
  },
  stream: (method, request, options) => rpc.stream(method, request, options),
  close: () => rpc.close(),
}
const client = new ChronologClient({ transport, groupId: opened.groupId })
const membership = await client.ownership.acceptInvitation(base64UrlToBytes(bootstrap.teamId), { idempotencyKey: 'accept-pilot-team' })
try {
  const outcome = await membership.handle.final({ signal: AbortSignal.timeout(30_000) })
  if (outcome.outcome.type !== 'accepted') throw new Error(`PILOT_MEMBERSHIP_REJECTED: ${JSON.stringify(outcome.outcome)}`)
} finally { membership.handle.dispose() }
const backend = createChronologApplicationBackend({ id: bootstrap.applicationId, replica: client, sql: true })
target.tendril.application.install(backend)

export const signals = {
  publish: (topic: string, payload: EventPayload, options: { ttlMs?: number } = {}) => command('signalPublish', { topic, payload, ...options }),
  async *subscribe(options: { topics?: readonly string[]; signal?: AbortSignal } = {}): AsyncIterable<EphemeralSignal> {
    const subscriptionId = crypto.randomUUID()
    const cancel = () => { void command('signalCancel', { subscriptionId }).catch(() => undefined) }
    options.signal?.addEventListener('abort', cancel, { once: true })
    try {
      while (options.signal?.aborted !== true) {
        const result = await command('signalNext', { subscriptionId, topics: options.topics }, 0) as IteratorResult<EphemeralSignal>
        if (result.done) return
        options.signal?.throwIfAborted()
        yield result.value
      }
    } finally { options.signal?.removeEventListener('abort', cancel); cancel() }
  },
}
let closed = false
target.applicationPilot = {
  identity: opened.identity, connectionErrors,
  holdNextSubmission() {
    if (hold !== null) throw new Error('PILOT_REPLY_ALREADY_HELD')
    let release!: () => void
    const promise = new Promise<void>(resolve => { release = resolve })
    hold = { promise, release, receipt: null }
  },
  heldSubmission: () => hold?.receipt ?? null,
  releaseSubmission() { const previous = hold; hold = null; previous?.release() },
  disconnect, reconnect: connect, async sync() { await command('sync') },
  routeStats: () => command('routeStats') as ReturnType<PilotWindow['applicationPilot']['routeStats']>,
  signalingStats: () => sessions.map(value => ({ ...value.signaling })),
  routeState: () => command('routeState') as ReturnType<PilotWindow['applicationPilot']['routeState']>,
  events: () => client.events.read(), operation: async operationId => backend.operations.get(operationId),
  async close() {
    if (closed) return
    closed = true
    target.applicationPilot.releaseSubmission()
    try { await client.close() } finally { await session?.close(); worker.terminate() }
    await navigator.locks.request(`chronolog:${name}`, { mode: 'exclusive' }, () => undefined)
  },
}
addEventListener('pagehide', () => { worker.terminate(); void session?.close() })

import { ChronologClient, type ClientReadView } from '@chronolog/client'
import { emit, program, type EventPayload, type EventReadOptions } from '@chronolog/protocol'
import { WorkerRpcTransport } from '@chronolog/runtime-browser/events'
import type { EphemeralSignal, SignalPayload } from '@chronolog/signals'

import type { BrowserEventBootstrap, BrowserEventIdentity } from './event-contract.js'
import type { qualifyStorageQuota } from './storage-quota.js'

class EventPeer {
  readonly worker = new Worker('/event-worker.js', { type: 'module' })
  readonly rpc = new WorkerRpcTransport(this.worker)
  readonly views = new Map<string, ClientReadView>()
  readonly signals = new Map<string, { readonly iterator: AsyncIterator<EphemeralSignal>; next: Promise<IteratorResult<EphemeralSignal>> }>()
  readonly #pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
  readonly #pauses: Array<(value: unknown) => void> = []
  #next = 1
  #name = ''
  client!: ChronologClient
  constructor() {
    this.worker.addEventListener('message', (event: MessageEvent) => {
      const response = event.data as { fixture?: string; id?: number; value?: unknown; error?: string }
      if (response.fixture === 'paused') { this.#pauses.shift()?.(response); return }
      if (response.fixture !== 'response' || response.id === undefined) return
      const pending = this.#pending.get(response.id)
      this.#pending.delete(response.id)
      if (response.error === undefined) pending?.resolve(response.value)
      else pending?.reject(new Error(response.error))
    })
  }
  async open(name: string, bootstrap: BrowserEventBootstrap) {
    this.#name = name
    const result = await this.command('open', { name, bootstrap }) as { groupId: string; identity: string; isolated: boolean }
    this.client = new ChronologClient({ groupId: result.groupId, transport: this.rpc, unaryRetryAttempts: 1 })
    return result
  }
  command(fixture: string, fields: Record<string, unknown> = {}): Promise<unknown> {
    const id = this.#next++
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.#pending.delete(id); reject(new Error(`Event Worker fixture timed out: ${fixture}`)) }, 30_000)
      this.#pending.set(id, { resolve(value) { clearTimeout(timer); resolve(value) }, reject(error) { clearTimeout(timer); reject(error) } })
      this.worker.postMessage({ fixture, id, ...fields })
    })
  }
  async publish(events: readonly { topic: string; payload: EventPayload }[], operationId: string) {
    const handle = await this.client.submit(program(...events.map((event) => emit(event.topic, event.payload))), { operationId })
    try { return { proposalId: handle.proposalId, outcome: await handle.final({ signal: AbortSignal.timeout(20_000) }) } }
    finally { handle.dispose() }
  }
  async subscribeSignals(subscription: string) {
    const iterator = this.client.signals.subscribe({ topics: ['typing'], signal: AbortSignal.timeout(30_000) })[Symbol.asyncIterator]()
    const next = iterator.next()
    void next.catch(() => undefined)
    this.signals.set(subscription, { iterator, next })
    // The Worker stream opens and then pulls in two message turns. These public
    // RPC round trips fence both turns before the native test sends live data.
    await this.client.events.read(); await this.client.events.read()
  }
  async nextSignal(subscription: string) {
    const state = this.signals.get(subscription)!
    const result = await state.next
    if (result.done) throw new Error('EVENT_BROWSER_SIGNAL_SUBSCRIPTION_ENDED')
    state.next = state.iterator.next()
    void state.next.catch(() => undefined)
    return result.value
  }
  async unsubscribeSignals(subscription: string) {
    const state = this.signals.get(subscription)
    this.signals.delete(subscription)
    await state?.iterator.return?.()
  }
  async crash(fixture: string, fields: Record<string, unknown>) {
    let timeout: ReturnType<typeof setTimeout> | undefined
    try {
      const paused = new Promise((resolve, reject) => {
        timeout = setTimeout(() => reject(new Error(`Event Worker crash point not reached: ${fixture}`)), 30_000)
        this.#pauses.push(resolve)
      })
      const running = this.command(fixture, fields)
      // Killing a Worker deliberately prevents its command response.
      void running.catch(() => undefined)
      const result = await Promise.race([paused, running.then(() => { throw new Error('EVENT_BROWSER_PAUSE_NOT_REACHED') })])
      this.worker.terminate()
      for (const pending of this.#pending.values()) pending.reject(new Error('FIXTURE_WORKER_TERMINATED'))
      this.#pending.clear()
      await navigator.locks.request(`chronolog:${this.#name}`, { mode: 'exclusive' }, () => undefined)
      return result
    } finally { if (timeout !== undefined) clearTimeout(timeout) }
  }
  async close() { try { await this.client?.close(); await this.rpc.close() } finally { this.worker.terminate() } }
}

const peers = new Map<string, EventPeer>()
const api = {
  async prepare(name: string): Promise<BrowserEventIdentity> {
    const peer = new EventPeer()
    try { return await peer.command('prepare', { name }) as BrowserEventIdentity }
    finally { peer.worker.terminate() }
  },
  async removeFeedMetadata(name: string) {
    const peer = new EventPeer()
    try { return await peer.command('removeFeedMetadata', { name }) as { manifest: string; binding: string; identity: string } }
    finally { peer.worker.terminate() }
  },
  async restoreFeedMetadata(name: string, manifest: string, binding: string) {
    const peer = new EventPeer()
    try { await peer.command('restoreFeedMetadata', { name, manifest, binding }) }
    finally { peer.worker.terminate() }
  },
  async open(id: string, name: string, bootstrap: BrowserEventBootstrap) {
    const peer = new EventPeer()
    try { const result = await peer.open(name, bootstrap); peers.set(id, peer); return result }
    catch (error) { peer.worker.terminate(); throw error }
  },
  publish(id: string, events: readonly { topic: string; payload: EventPayload }[], operationId: string) { return peers.get(id)!.publish(events, operationId) },
  read(id: string, options: EventReadOptions = {}) { return peers.get(id)!.client.events.read(options) },
  operation(id: string, operationId: string) { return peers.get(id)!.client.operations.get(operationId) },
  sendSignal(id: string, payload: SignalPayload) { return peers.get(id)!.client.signals.send('typing', payload, { ttlMs: 5_000 }) },
  subscribeSignals(id: string, subscription: string) { return peers.get(id)!.subscribeSignals(subscription) },
  nextSignal(id: string, subscription: string) { return peers.get(id)!.nextSignal(subscription) },
  unsubscribeSignals(id: string, subscription: string) { return peers.get(id)!.unsubscribeSignals(subscription) },
  connect(id: string) { return peers.get(id)!.command('connect') },
  disconnect(id: string) { return peers.get(id)!.command('disconnect') },
  privateValue(id: string, value?: string) { return peers.get(id)!.command('privateValue', value === undefined ? {} : { state: value }) },
  quota(id: string) { return peers.get(id)!.command('quota') as ReturnType<typeof qualifyStorageQuota> },
  async readNext(id: string, options: EventReadOptions) {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 20_000)
    try { for await (const batch of peers.get(id)!.client.events.subscribe({ ...options, signal: controller.signal })) return batch }
    finally { clearTimeout(timeout); controller.abort() }
    throw new Error('EVENT_BROWSER_SUBSCRIPTION_ENDED')
  },
  async capture(id: string, viewId: string) { const view = await peers.get(id)!.client.readView(); peers.get(id)!.views.set(viewId, view); return view.revision },
  viewEvents(id: string, viewId: string) { return peers.get(id)!.views.get(viewId)!.readEvents() },
  async release(id: string, viewId: string) { await peers.get(id)!.views.get(viewId)!.release() },
  async sql(id: string) { return peers.get(id)!.client.query('SELECT 1') },
  state(id: string) { return peers.get(id)!.command('state') },
  checkpoint(id: string, fields: { cursor: string; revision: string; state: string }) { return peers.get(id)!.command('checkpoint', fields) },
  checkpointState(id: string) { return peers.get(id)!.command('checkpointState') },
  cutoff(id: string, cutoff?: string) { return peers.get(id)!.command('privateCutoff', cutoff === undefined ? {} : { cutoff }) },
  crashCheckpoint(id: string, fields: { cursor: string; revision: string; state: string; pause: 'before' | 'after' }) {
    return peers.get(id)!.crash('checkpoint', fields)
  },
  crashCutoff(id: string, cutoff: string) { return peers.get(id)!.crash('crashCutoff', { cutoff }) },
  async close(id: string) { await peers.get(id)!.close(); peers.delete(id) },
}
Object.assign(globalThis, { chronologEventTest: api })
export type BrowserEventTestApi = typeof api

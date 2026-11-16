import { ChronologClient, type TransactionHandle } from '@chronolog/client'
import { base64UrlToBytes } from '@chronolog/protocol'
import type { EnrollmentRole } from '@chronolog/rpc'
import { WorkerRpcTransport } from '@chronolog/runtime-browser'

import type { BrowserBridgeBootstrap, BrowserBridgeIdentity, BrowserBridgeSnapshot } from './bridge-contract.js'

class BrowserClaimPeer {
  readonly worker = new Worker('/bridge-worker.js', { type: 'module' })
  readonly rpc = new WorkerRpcTransport(this.worker)
  readonly handles = new Map<string, TransactionHandle>()
  readonly #pending = new Map<number, { resolve(value: unknown): void; reject(error: Error): void }>()
  #next = 0
  #name = ''
  identity!: BrowserBridgeIdentity
  client!: ChronologClient

  constructor() {
    this.worker.addEventListener('message', (event: MessageEvent) => {
      const response = event.data as { fixture?: string; id?: number; value?: unknown; error?: string }
      if (response.fixture !== 'response' || response.id === undefined) return
      const pending = this.#pending.get(response.id)
      this.#pending.delete(response.id)
      if (response.error === undefined) pending?.resolve(response.value)
      else pending?.reject(new Error(response.error))
    })
  }

  async open(name: string, bootstrap: BrowserBridgeBootstrap, relay: boolean, createIdentity?: true): Promise<BrowserBridgeIdentity> {
    this.#name = name
    this.identity = await this.command('open', { name, bootstrap, relay, createIdentity }) as BrowserBridgeIdentity
    this.client = new ChronologClient({ transport: this.rpc, groupId: this.identity.groupId, unaryRetryAttempts: 0 })
    return this.identity
  }

  command(fixture: string, fields: Record<string, unknown> = {}, transfer: Transferable[] = []): Promise<unknown> {
    const id = ++this.#next
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.#pending.delete(id); reject(new Error(`Browser bridge timed out: ${fixture}`)) }, 30_000)
      this.#pending.set(id, {
        resolve: (value) => { clearTimeout(timer); resolve(value) },
        reject: (error) => { clearTimeout(timer); reject(error) },
      })
      this.worker.postMessage({ fixture, id, ...fields }, transfer)
    })
  }

  async claim(operationId: string): Promise<string> {
    const handle = await this.client.transaction([
      "SELECT chronolog_assert((SELECT claimed_by IS NULL FROM tasks WHERE id = 1), 'already_claimed')",
      { sql: 'UPDATE tasks SET claimed_by = ? WHERE id = 1', params: ['browser'] },
    ], { idempotencyKey: operationId })
    this.handles.set(handle.transactionId, handle)
    return handle.transactionId
  }

  async acceptTeam(teamId: string): Promise<string> {
    const change = await this.client.ownership.acceptInvitation(base64UrlToBytes(teamId), { idempotencyKey: 'accept-team' })
    this.handles.set(change.handle.transactionId, change.handle)
    return change.handle.transactionId
  }

  async state(transactionIds: readonly string[]): Promise<BrowserBridgeSnapshot> {
    return {
      ...await this.command('state') as Omit<BrowserBridgeSnapshot, 'outcomes'>,
      outcomes: await Promise.all(transactionIds.map((id) => this.client.getTransactionOutcome(id))),
    }
  }

  async stop(): Promise<void> {
    for (const handle of this.handles.values()) handle.dispose()
    try { await this.client.close() } finally { this.worker.terminate() }
    await navigator.locks.request(`chronolog:${this.#name}`, { mode: 'exclusive' }, () => undefined)
  }
}

const peers = new Map<string, BrowserClaimPeer>()
const api = {
  async open(id: string, name: string, bootstrap: BrowserBridgeBootstrap, relay = true, createIdentity?: true) {
    const peer = new BrowserClaimPeer()
    try { const identity = await peer.open(name, bootstrap, relay, createIdentity); peers.set(id, peer); return identity }
    catch (error) { peer.worker.terminate(); throw error }
  },
  sync(id: string) { return peers.get(id)!.command('sync') },
  request(id: string, requestId: string, roles: readonly EnrollmentRole[]) {
    return peers.get(id)!.client.enrollment.createRequest({ requestId, roles })
  },
  enrollmentStatus(id: string, requestId: string, signedApproval?: string) {
    return peers.get(id)!.client.enrollment.getStatus(requestId, signedApproval === undefined ? {} : { signedApproval })
  },
  acceptTeam(id: string, teamId: string) { return peers.get(id)!.acceptTeam(teamId) },
  claim(id: string, operationId: string) { return peers.get(id)!.claim(operationId) },
  outcome(id: string, transactionId: string) { return peers.get(id)!.client.getTransactionOutcome(transactionId) },
  async query(id: string, sql: string) { return (await peers.get(id)!.client.query(sql, [], { view: 'final' })).result.rows },
  final(id: string, transactionId: string) {
    return peers.get(id)!.handles.get(transactionId)!.final({ signal: AbortSignal.timeout(30_000) })
  },
  state(id: string, transactionIds: readonly string[] = []) { return peers.get(id)!.state(transactionIds) },
  async connect(sourceId: string, targetId: string) {
    const source = peers.get(sourceId)!, target = peers.get(targetId)!
    const channel = new MessageChannel()
    await source.command('serveLink', { port: channel.port1 }, [channel.port1])
    await target.command('receiveLink', { port: channel.port2, identity: source.identity.transportAuthor }, [channel.port2])
  },
  async stop(id: string) { await peers.get(id)!.stop(); peers.delete(id) },
}
Object.assign(globalThis, { chronologBrowserBridge: api })

export type BrowserBridgeApi = typeof api

import { ChronologClient, type QueryOptions } from '@chronolog/client'
import { WorkerRpcTransport } from '@chronolog/runtime-browser'

class TestPeer {
  readonly worker = new Worker('/peer-worker.js', { type: 'module' })
  readonly #pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
  readonly #pauses: Array<(value: unknown) => void> = []
  #next = 1
  client!: ChronologClient
  readonly rpc = new WorkerRpcTransport(this.worker)

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
  async open(name: string) {
    const identity = await this.command('open', { name }) as { groupId: string; identity: string }
    this.client = new ChronologClient({ transport: this.rpc, groupId: identity.groupId, unaryRetryAttempts: 1 })
    return identity
  }
  command(fixture: string, fields: Record<string, unknown> = {}): Promise<unknown> {
    const id = this.#next++
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.#pending.delete(id); reject(new Error(`Browser fixture timed out: ${fixture}`)) }, 30_000)
      this.#pending.set(id, {
        resolve: (value) => { clearTimeout(timer); resolve(value) },
        reject: (error) => { clearTimeout(timer); reject(error) },
      })
      this.worker.postMessage({ fixture, id, ...fields })
    })
  }
  async submit(steps: string[], operationId: string): Promise<string> {
    const handle = await this.client.transaction(steps, { idempotencyKey: operationId })
    try { await handle.accepted(); return handle.transactionId } finally { handle.dispose() }
  }
  async query(sql: string, options: QueryOptions = {}) { return this.client.query(sql, [], options) }
  async stop() { try { await this.rpc.close() } finally { this.worker.terminate() } }
  async crash(steps: string[], operationId: string, point: 'prepared' | 'application'): Promise<unknown> {
    await this.command(point === 'prepared' ? 'armPrepared' : 'armApplication', { operationId })
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      const paused = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`Browser crash boundary timed out: ${point}`)), 30_000)
        this.#pauses.push(resolve)
      })
      const submitted = this.submit(steps, operationId).then(() => { throw new Error(`Crash boundary not reached: ${point}`) })
      const evidence = await Promise.race([paused, submitted])
      this.worker.terminate()
      return evidence
    } finally { if (timer !== undefined) clearTimeout(timer) }
  }
}

const peers = new Map<string, TestPeer>()
const test = {
  async open(id: string, name: string) {
    const peer = new TestPeer()
    try { const result = await peer.open(name); peers.set(id, peer); return result }
    catch (error) { peer.worker.terminate(); throw error }
  },
  submit(id: string, steps: string[], operationId: string) { return peers.get(id)!.submit(steps, operationId) },
  async query(id: string, sql: string, options: QueryOptions = {}) { return (await peers.get(id)!.query(sql, options)).result.rows },
  state(id: string) { return peers.get(id)!.command('state') },
  advanceFinal(id: string) { return peers.get(id)!.command('advanceFinal') },
  async stop(id: string) { await peers.get(id)!.stop(); peers.delete(id) },
  crash(id: string, steps: string[], operationId: string, point: 'prepared' | 'application') { return peers.get(id)!.crash(steps, operationId, point) },
}
Object.assign(globalThis, { chronologBrowserTest: test })

export type BrowserTestApi = typeof test

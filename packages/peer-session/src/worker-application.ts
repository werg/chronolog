import type { EphemeralSignal, SignalSubscribeOptions, SignalSendOptions, SignalPayload } from '@chronolog/signals'
import type { ApplicationEndpointBinding as InlineApplicationEndpointBinding } from './owner-types.js'
import type { ApplicationDescription as InlineApplicationDescription } from '@chronolog/authority'
import type { ApplicationEndpointContext as InlineApplicationEndpointContext } from './owner-types.js'
import type { ApplicationPeerDiagnostics as InlineApplicationPeerDiagnostics } from './network.js'
import type { AuthorityBundle as InlineAuthorityBundle } from '@chronolog/authority'
import type { FinalityProof as InlineFinalityProof } from '@chronolog/authority'
import type { Signed as InlineSigned } from '@chronolog/authority'
import type { FinalityStatement as InlineFinalityStatement } from '@chronolog/authority'
import type { SignedProvisioningRequest as InlineSignedProvisioningRequest } from './provisioning.js'
import type { SignedProvisioningPackage as InlineSignedProvisioningPackage } from './provisioning.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'
import type { SessionFacts as InlineSessionFacts } from './session.js'
import { APPLICATION_OWNER_PROTOCOL, type OwnerNotice, type OwnerResponse } from './worker-application-protocol.js'
import type { ApplicationChange, ApplicationEventOptions, ApplicationReadView, CommandOptions, MaterializedRevision, QueryParameter, QueryRows, SessionStatus, WaitOptions } from './session-types.js'
import type { ApplicationSubmission, MaterializedOperation, OperationInspection, RetentionEvidence } from './operation.js'
import type { ContentReference, ContentUpload, ContentRetention } from './content.js'
import { putContentBytes, readContentBytes, type ContentPutBytesOptions, type ContentReadBytesOptions } from './content-bytes.js'
export interface WorkerApplicationReadView { readonly applicationId: string; readonly revision: MaterializedRevision; query(sql: string, parameters?: readonly QueryParameter[]): Promise<QueryRows>; readEvents(options?: ApplicationEventOptions): Promise<ReturnType<ApplicationReadView['readEvents']>>; release(): Promise<void> }
export class WorkerApplicationOperation {
  readonly stored = true
  constructor(readonly id: string, readonly operationId: string, private readonly session: WorkerApplicationSession) {}
  inspect(): Promise<OperationInspection> { return this.session.request('operation.inspect', [this.id]) }
  materialized(options?: WaitOptions): Promise<MaterializedOperation> { return this.session.wait(this.id, 'materialized', options) }
  retained(options?: WaitOptions): Promise<readonly RetentionEvidence[]> { return this.session.wait(this.id, 'retained', options) }
  finalized(options?: WaitOptions): Promise<MaterializedOperation> { return this.session.wait(this.id, 'finalized', options) }
}
/** Page facade owns bounded RPC and local UI state, never keys, SQL or ordering. */
export class WorkerApplicationSession {
  readonly #endpoint: ApplicationWorkerEndpoint
  readonly #attachment = crypto.randomUUID()
  readonly #lifetime = new AbortController()
  readonly #pending = new Map<number, { method: string; startedAt: number; deadline: number; resolve(value: unknown): void; reject(error: unknown): void; timer: ReturnType<typeof setTimeout>; cleanup(): void }>()
  readonly #statuses = new Set<(value: SessionStatus) => void>()
  readonly #changes = new Set<(value: ApplicationChange) => void>()
  readonly #ownedViews = new Set<string>()
  #next = 0
  #binding: InlineApplicationEndpointBinding | undefined
  #attachmentState: 'active' | 'suspended' | 'detached' = 'active'
  #heartbeat: ReturnType<typeof setInterval> | undefined
  #pinging = false
  #description: InlineApplicationDescription | undefined
  #status: SessionStatus = { canAuthor: false, phase: 'ready', database: 'idle', connectedPeers: 0, pendingOperations: 0, materializationError: null }
  applicationId = ''
  identity: { readonly publicKey: string } = { publicKey: '' }
  constructor(endpoint: ApplicationWorkerEndpoint) { this.#endpoint = endpoint; endpoint.addEventListener('message', this.#receive); const physical = endpoint as unknown as EventTarget & { on?(type: string, listener: () => void): void }; physical.addEventListener('close', this.#physicalClose); physical.addEventListener('messageerror', this.#physicalClose); physical.on?.('close', this.#physicalClose); physical.on?.('messageerror', this.#physicalClose) }
  readonly #physicalClose = (): void => { this.#detach(Object.assign(new Error('OWNER_UNREACHABLE'), { code: 'OWNER_UNREACHABLE' })) }
  get signal(): AbortSignal { return this.#lifetime.signal }
  get status(): SessionStatus { return { ...this.#status, canAuthor: this.#status.canAuthor && this.#attachmentState === 'active' && this.#binding?.capabilities.includes('commands') === true } }
  get endpoint(): InlineApplicationEndpointBinding | undefined { return this.#binding === undefined ? undefined : structuredClone(this.#binding) }
  get attachmentState(): 'active' | 'suspended' | 'detached' { return this.#attachmentState }
  describe(): InlineApplicationDescription { if (this.#description === undefined) throw new Error('ENDPOINT_HANDSHAKE_REQUIRED'); return structuredClone(this.#description) }
  get boundedRequest(): { readonly startedAt: number; readonly deadline: number } | null {
    const requests = [...this.#pending.values()].filter(request => request.method !== 'operation.wait' && request.method !== 'signals.next').sort((a, b) => a.startedAt - b.startedAt)
    const request = requests[0]; return request === undefined ? null : { startedAt: request.startedAt, deadline: request.deadline }
  }
  readonly #receive = (event: MessageEvent): void => {
    const message = event.data as Partial<OwnerResponse> | Partial<OwnerNotice>
    if (message?.protocol !== APPLICATION_OWNER_PROTOCOL || message.attachment !== this.#attachment) return
    if (message.kind === 'response') {
      const response = message as OwnerResponse, pending = this.#pending.get(response.id); if (pending === undefined) return
      this.#pending.delete(response.id); clearTimeout(pending.timer); pending.cleanup(); if (response.error !== undefined) pending.reject(Object.assign(new Error(response.error), { code: response.error })); else pending.resolve(response.value)
    } else if (message.kind === 'notice') {
      const notice = message as OwnerNotice
      if (notice.topic === 'closed') { this.#detach(new Error(String(notice.value))); return }
      if (notice.topic === 'status') { this.#status = notice.value as SessionStatus; for (const listener of this.#statuses) { try { listener(this.status) } catch { /* Isolated observers. */ } } }
      if (notice.topic === 'change') for (const listener of this.#changes) { try { listener(notice.value as ApplicationChange) } catch { /* Isolated observers. */ } }
    }
  }
  request<T>(method: string, args: readonly unknown[], options: WaitOptions = {}): Promise<T> {
    if (this.signal.aborted) return Promise.reject(this.signal.reason)
    if (options.signal?.aborted) return Promise.reject(options.signal.reason)
    const control = ['close', 'attachment.ping', 'attachment.suspend', 'attachment.resume', 'view.release', 'content.cancel', 'signals.close', 'upload.discard'].includes(method)
    if ([...this.#pending.values()].filter(request => ['close', 'attachment.ping', 'attachment.suspend', 'attachment.resume', 'view.release', 'content.cancel', 'signals.close', 'upload.discard'].includes(request.method) === control).length >= (control ? 8 : 32)) return Promise.reject(new Error('ENDPOINT_REQUEST_LIMIT'))
    const timeoutMs = options.timeoutMs ?? 30_000
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) return Promise.reject(new Error('ENDPOINT_TIMEOUT_LIMIT'))
    const id = ++this.#next, startedAt = performance.now()
    return new Promise<T>((resolve, reject) => {
      const cancel = (): void => { try { this.#endpoint.postMessage({ protocol: APPLICATION_OWNER_PROTOCOL, attachment: this.#attachment, kind: 'cancel', id }) } catch { /* A dead owner cannot retain this request's resources. */ } }
      const abort = (): void => { const pending = this.#pending.get(id); if (pending === undefined) return; this.#pending.delete(id); clearTimeout(pending.timer); pending.cleanup(); cancel(); reject(options.signal?.reason) }
      const cleanup = (): void => options.signal?.removeEventListener('abort', abort)
      const timer = setTimeout(() => { this.#pending.delete(id); cleanup(); cancel(); reject(Object.assign(new Error('ENDPOINT_REQUEST_TIMEOUT'), { code: 'ENDPOINT_REQUEST_TIMEOUT' })) }, timeoutMs)
      this.#pending.set(id, { method, startedAt, deadline: startedAt + timeoutMs, resolve: value => resolve(value as T), reject, timer, cleanup }); options.signal?.addEventListener('abort', abort, { once: true })
      try { this.#endpoint.postMessage({ protocol: APPLICATION_OWNER_PROTOCOL, attachment: this.#attachment, kind: 'request', id, method, args }) } catch (error) { this.#pending.delete(id); clearTimeout(timer); cleanup(); reject(error) }
    })
  }
  async initialize(options: { readonly applicationId: string; readonly context?: InlineApplicationEndpointContext }): Promise<void> {
    const value = await this.request<{ applicationId: string; identity: { publicKey: string }; status: SessionStatus; binding: InlineApplicationEndpointBinding; definition: InlineApplicationDescription }>('hello', [options]); this.applicationId = value.applicationId; this.identity = value.identity; this.#status = value.status; this.#binding = value.binding; this.#description = value.definition
    this.#heartbeat = setInterval(() => { if (this.#pinging || this.signal.aborted || this.#attachmentState === 'suspended') return; this.#pinging = true; void this.request('attachment.ping', [], { timeoutMs: 20_000 }).catch(error => this.#detach(error)).finally(() => { this.#pinging = false }) }, 5000)
    this.#heartbeat.unref?.()
  }
  async suspendAttachment(): Promise<void> { await this.request('attachment.suspend', []); this.#attachmentState = 'suspended'; this.#ownedViews.clear() }
  suspend(): Promise<void> { return this.suspendAttachment() }
  async resumeAttachment(): Promise<InlineApplicationEndpointBinding | null> { this.#status = await this.request('attachment.resume', []); this.#attachmentState = 'active'; return this.endpoint ?? null }
  detach(): Promise<void> { return this.close() }
  async submit(input: ApplicationSubmission): Promise<WorkerApplicationOperation> { const value = await this.request<{ id: string; operationId: string }>('submit', [input]); return new WorkerApplicationOperation(value.id, value.operationId, this) }
  async command(name: string, input: unknown, options: CommandOptions = {}): Promise<WorkerApplicationOperation> { const value = await this.request<{ id: string; operationId: string }>('command', [name, input, options]); return new WorkerApplicationOperation(value.id, value.operationId, this) }
  query(name: string, input: unknown): Promise<{ readonly applicationId: string; readonly revision: MaterializedRevision; readonly value: unknown }> { return this.request('query', [name, input]) }
  wait<T>(id: string, fact: string, options: WaitOptions = {}): Promise<T> { const timeoutMs = options.timeoutMs ?? 30_000; return this.request('operation.wait', [id, fact, timeoutMs], { ...options, timeoutMs: Math.min(120_000, timeoutMs + 1000) }) }
  async readView(options: { readonly view?: 'local' | 'final' } = {}): Promise<WorkerApplicationReadView> {
    const captured = await this.request<{ id: string; revision: MaterializedRevision }>('readView', [options]); this.#ownedViews.add(captured.id); let released = false, releasing: Promise<void> | undefined
    return { applicationId: this.applicationId, revision: captured.revision, query: (sql, parameters = []) => { if (released) return Promise.reject(new Error('READ_VIEW_RELEASED')); return this.request('view.query', [captured.id, sql, parameters]) }, readEvents: options => { if (released) return Promise.reject(new Error('READ_VIEW_RELEASED')); return this.request('view.events', [captured.id, options ?? {}]) }, release: () => { if (releasing !== undefined) return releasing; released = true; this.#ownedViews.delete(captured.id); return releasing = this.request<void>('view.release', [captured.id]) } }
  }
  get operations() {
    const session = this
    return { async retry(id: string): Promise<WorkerApplicationOperation> { const value = await session.request<{ id: string; operationId: string }>('operation.retry', [id]); return new WorkerApplicationOperation(value.id, value.operationId, session) }, async get(id: string): Promise<WorkerApplicationOperation | null> { const value = await session.request<{ id: string; operationId: string } | null>('operation.get', [id]); return value === null ? null : new WorkerApplicationOperation(value.id, value.operationId, session) }, async *subscribe(options: { readonly operationId: string; readonly signal?: AbortSignal }): AsyncIterable<OperationInspection> {
      const signal = options.signal === undefined ? session.signal : AbortSignal.any([session.signal, options.signal]); let dirty = true, wake: (() => void) | undefined
      const invalidate = (): void => { dirty = true; wake?.() }; const stop = session.onChange(invalidate), stopStatus = session.onStatus(invalidate); signal.addEventListener('abort', invalidate)
      try { while (!signal.aborted) { if (!dirty) await new Promise<void>(resolve => { wake = resolve }); if (signal.aborted) break; dirty = false; const operation = await session.operations.get(options.operationId); if (operation !== null) yield await operation.inspect() } } finally { stop(); stopStatus(); signal.removeEventListener('abort', invalidate) }
    } }
  }
  onStatus(listener: (status: SessionStatus) => void): () => void { this.#statuses.add(listener); listener(this.status); return () => { this.#statuses.delete(listener) } }
  onChange(listener: (change: ApplicationChange) => void): () => void { this.#changes.add(listener); return () => { this.#changes.delete(listener) } }
  async *changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationChange> {
    const signal = options.signal === undefined ? this.signal : AbortSignal.any([this.signal, options.signal]), queue: ApplicationChange[] = []; let wake: (() => void) | undefined
    const stop = this.onChange(value => { queue.splice(0, queue.length, value); wake?.() }), abort = (): void => { wake?.() }; signal.addEventListener('abort', abort)
    try { while (!signal.aborted) { if (queue.length === 0) await new Promise<void>(resolve => { wake = resolve }); while (queue.length > 0 && !signal.aborted) yield queue.shift()! } } finally { stop(); signal.removeEventListener('abort', abort) }
  }
  diagnostics(): Promise<readonly InlineApplicationPeerDiagnostics[]> { return this.request('diagnostics.peers', []) }
  readAuthority(): Promise<InlineAuthorityBundle> { return this.request('authority.read', []) }
  endpoints(): Promise<readonly (InlineApplicationEndpointBinding & { readonly state: 'active' | 'suspended' })[]> { return this.request('endpoints.list', []) }
  mergeAuthority(bundle: InlineAuthorityBundle): Promise<void> { return this.request('authority.merge', [bundle]) }
  /** The owner's authenticated operation-set facts (signed envelopes, retention and finality evidence). */
  exportFacts(): Promise<InlineSessionFacts> { return this.request('facts.export', []) }
  /** Verify and merge facts from another replica; ordering remains signed author time, never arrival order. */
  mergeFacts(facts: InlineSessionFacts): Promise<void> { return this.request('facts.merge', [facts]) }
  readonly finality = {
    closeAuthorTime: (options: { readonly throughMs: bigint }): Promise<{ readonly closedThroughMs: bigint | null; readonly proofs: readonly InlineFinalityProof[] }> => this.request('finality.closeAuthorTime', [options]),
    voteAuthorTime: (options: { readonly throughMs: bigint }): Promise<readonly InlineSigned<InlineFinalityStatement>[]> => this.request('finality.voteAuthorTime', [options]),
    submitProofs: (proofs: readonly InlineFinalityProof[]): Promise<void> => this.request('finality.submitProofs', [proofs]),
  }
  readonly provisioning = {
    createProvisioningRequest: (): Promise<InlineSignedProvisioningRequest> => this.request('provisioning.createProvisioningRequest', []),
    exportProvisioning: (request: InlineSignedProvisioningRequest): Promise<InlineSignedProvisioningPackage> => this.request('provisioning.exportProvisioning', [request]),
    importProvisioning: (value: InlineSignedProvisioningPackage): Promise<void> => this.request('provisioning.importProvisioning', [value]),
  }
  readonly signals = {
    delivery: 'application' as const,
    send: (topic: string, payload: SignalPayload, options: SignalSendOptions = {}): Promise<EphemeralSignal> => { const { signal, ...rest } = options; return this.request('signals.send', [topic, payload, rest], signal === undefined ? {} : { signal }) },
    subscribe: (options: SignalSubscribeOptions = {}): AsyncIterable<EphemeralSignal> => {
      const session = this, { signal: external, ...rest } = options, signal = external === undefined ? this.signal : AbortSignal.any([this.signal, external])
      return { async *[Symbol.asyncIterator]() {
        const id = await session.request<string>('signals.open', [rest], { signal })
        try { while (!signal.aborted) { const next = await session.request<{ idle?: true; done?: true; value?: EphemeralSignal }>('signals.next', [id], { signal, timeoutMs: 25_000 }); if (next.done) return; if (next.value !== undefined) yield next.value } }
        finally { if (!session.signal.aborted) await session.request('signals.close', [id]).catch(() => undefined) }
      } }
    },
  }
  readonly content = {
    retain: (reference: ContentReference): Promise<ContentRetention> => this.request('content.retain', [reference]),
    retention: (reference: ContentReference): Promise<readonly ContentRetention[]> => this.request('content.retention', [reference]),
    retained: (reference: ContentReference): Promise<readonly ContentRetention[]> => this.request('content.retained', [reference]),
    discard: (reference: ContentReference): Promise<void> => this.request('content.discard', [reference]),
    stage: async (options: { readonly bytes: number; readonly mediaType?: string }): Promise<ContentUpload> => {
      const id = await this.request<string>('content.stage', [options]); return { id, write: (index, bytes) => this.request('upload.write', [id, index, bytes]), progress: () => this.request('upload.progress', [id]), commit: () => this.request('upload.commit', [id]), discard: () => this.request('upload.discard', [id]) }
    },
    read: (reference: ContentReference, options: { readonly signal?: AbortSignal } = {}): AsyncIterable<Uint8Array> => {
      const session = this
      return { async *[Symbol.asyncIterator]() { const id = await session.request<string>('content.openRead', [reference], options); try { while (!options.signal?.aborted) { const chunk = await session.request<Uint8Array | null>('content.next', [id], options); if (chunk === null) return; yield chunk } } finally { void session.request('content.cancel', [id]).catch(() => undefined) } } }
    },
    putBytes: (bytes: Uint8Array, options?: ContentPutBytesOptions) => putContentBytes(this.content, bytes, options),
    readBytes: (reference: ContentReference, options: ContentReadBytesOptions) => readContentBytes(this.content, reference, options),
  }
  readEvents(options: ApplicationEventOptions = {}): Promise<ReturnType<ApplicationReadView['readEvents']>> { return this.request('events.read', [options]) }
  #detach(reason: unknown): void { if (this.signal.aborted) return; this.#attachmentState = 'detached'; clearInterval(this.#heartbeat); this.#status = { ...this.#status, phase: 'closed', database: 'closed', canAuthor: false }; for (const listener of this.#statuses) { try { listener(this.status) } catch { /* Isolated observers. */ } }; this.#lifetime.abort(reason); this.#endpoint.removeEventListener('message', this.#receive); const physical = this.#endpoint as unknown as EventTarget & { off?(type: string, listener: () => void): void }; physical.removeEventListener('close', this.#physicalClose); physical.removeEventListener('messageerror', this.#physicalClose); physical.off?.('close', this.#physicalClose); physical.off?.('messageerror', this.#physicalClose); for (const pending of this.#pending.values()) { clearTimeout(pending.timer); pending.cleanup(); pending.reject(reason) }; this.#pending.clear(); this.#statuses.clear(); this.#changes.clear(); this.#endpoint.close?.() }
  async close(): Promise<void> { if (this.signal.aborted) return; for (const id of this.#ownedViews) void this.request('view.release', [id]).catch(() => undefined); try { await this.request('close', [], { timeoutMs: 1000 }) } finally { this.#detach(new Error('ENDPOINT_CLOSED')) } }
}
export async function connectApplicationOwner(endpoint: ApplicationWorkerEndpoint & { start?(): void }, options: { readonly applicationId: string; readonly context?: InlineApplicationEndpointContext }): Promise<WorkerApplicationSession> {
  const session = new WorkerApplicationSession(endpoint); endpoint.start?.(); try { await session.initialize(options); return session } catch (error) { await session.close().catch(() => undefined); throw error }
}

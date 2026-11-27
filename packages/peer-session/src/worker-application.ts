import type { EphemeralSignal, SignalSubscribeOptions, SignalSendOptions, SignalPayload } from '@chronolog/signals'
import type { JsonValue } from '@chronolog/protocol'
import type { ApplicationEndpointBinding as InlineApplicationEndpointBinding, ApplicationEndpointContext as InlineApplicationEndpointContext } from './owner-types.js'
import type { ApplicationDescription as InlineApplicationDescription, FinalityCheckpoint as InlineFinalityCheckpoint, ScheduledFinalityEntry, VerifiedFinalityV2 } from '@chronolog/authority'
import type { ApplicationPeerDiagnostics as InlineApplicationPeerDiagnostics } from './network.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'
import type { CheckpointBootstrapSnapshot, SessionFacts as InlineSessionFacts } from './session.js'
import { APPLICATION_OWNER_PROTOCOL, type OwnerNotice, type OwnerResponse } from './worker-application-protocol.js'
import type { ApplicationChange, ApplicationEventOptions, ApplicationReadView, CommandOptions, MaterializedRevision, SessionStatus, WaitOptions } from './session-types.js'
import type { ApplicationSubmission, MaterializedOperation, OperationInspection, RetentionEvidence } from './operation.js'
import type { ContentReference, ContentUpload, ContentRetention } from './content.js'
import {
  CONTENT_CHUNK_BYTES, MAX_BLOB_BYTES, isPrivateContentReference, isPublicBlobReference, putContentBytes, readContentBytes,
  type BlobGetOptions, type BlobInfo, type BlobPutOptions, type BlobReference,
  type ContentGetOptions, type ContentPutBytesOptions, type ContentPutOptions, type ContentReadBytesOptions,
} from './content-bytes.js'

export interface WorkerApplicationReadView {
  readonly applicationId: string
  readonly revision: MaterializedRevision
  topic(name: string): Promise<JsonValue | null>
  query(topic: string, input?: JsonValue): Promise<JsonValue>
  readEvents(options?: ApplicationEventOptions): Promise<ReturnType<ApplicationReadView['readEvents']>>
  release(): Promise<void>
}

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
  readonly #extensions = new Set<(value: unknown) => void>()
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

  constructor(endpoint: ApplicationWorkerEndpoint) {
    this.#endpoint = endpoint
    endpoint.addEventListener('message', this.#receive)
    const physical = endpoint as unknown as EventTarget & { on?(type: string, listener: () => void): void }
    physical.addEventListener('close', this.#physicalClose)
    physical.addEventListener('messageerror', this.#physicalClose)
    physical.on?.('close', this.#physicalClose)
    physical.on?.('messageerror', this.#physicalClose)
  }

  readonly #physicalClose = (): void => { this.#detach(Object.assign(new Error('OWNER_UNREACHABLE'), { code: 'OWNER_UNREACHABLE' })) }
  get signal(): AbortSignal { return this.#lifetime.signal }
  get status(): SessionStatus { return { ...this.#status, canAuthor: this.#status.canAuthor && this.#attachmentState === 'active' && this.#binding?.capabilities.includes('commands') === true } }
  get endpoint(): InlineApplicationEndpointBinding | undefined { return this.#binding === undefined ? undefined : structuredClone(this.#binding) }
  get attachmentState(): 'active' | 'suspended' | 'detached' { return this.#attachmentState }
  describe(): InlineApplicationDescription { if (this.#description === undefined) throw new Error('ENDPOINT_HANDSHAKE_REQUIRED'); return structuredClone(this.#description) }
  get boundedRequest(): { readonly startedAt: number; readonly deadline: number } | null {
    const requests = [...this.#pending.values()].filter(request => request.method !== 'operation.wait' && request.method !== 'signals.next').sort((a, b) => a.startedAt - b.startedAt)
    const request = requests[0]
    return request === undefined ? null : { startedAt: request.startedAt, deadline: request.deadline }
  }

  readonly #receive = (event: MessageEvent): void => {
    const message = event.data as Partial<OwnerResponse> | Partial<OwnerNotice>
    if (message?.protocol !== APPLICATION_OWNER_PROTOCOL || message.attachment !== this.#attachment) return
    if (message.kind === 'response') {
      const response = message as OwnerResponse, pending = this.#pending.get(response.id)
      if (pending === undefined) return
      this.#pending.delete(response.id); clearTimeout(pending.timer); pending.cleanup()
      if (response.error !== undefined) pending.reject(Object.assign(new Error(response.error), { code: response.error }))
      else pending.resolve(response.value)
    } else if (message.kind === 'notice') {
      const notice = message as OwnerNotice
      if (notice.topic === 'closed') { this.#detach(new Error(String(notice.value))); return }
      if (notice.topic === 'status') { this.#status = notice.value as SessionStatus; for (const listener of this.#statuses) { try { listener(this.status) } catch { /* ignore */ } } }
      if (notice.topic === 'extension') for (const listener of this.#extensions) { try { listener(notice.value) } catch { /* ignore */ } }
      if (notice.topic === 'change') for (const listener of this.#changes) { try { listener(notice.value as ApplicationChange) } catch { /* ignore */ } }
    }
  }

  request<T>(method: string, args: readonly unknown[], options: WaitOptions = {}): Promise<T> {
    if (this.signal.aborted) return Promise.reject(this.signal.reason)
    if (options.signal?.aborted) return Promise.reject(options.signal.reason)
    const control = ['close', 'attachment.ping', 'attachment.suspend', 'attachment.resume', 'view.release', 'content.cancel', 'content.blobAbortWrite', 'content.blobCloseRead', 'signals.close', 'upload.discard'].includes(method)
    if ([...this.#pending.values()].filter(request => ['close', 'attachment.ping', 'attachment.suspend', 'attachment.resume', 'view.release', 'content.cancel', 'content.blobAbortWrite', 'content.blobCloseRead', 'signals.close', 'upload.discard'].includes(request.method) === control).length >= (control ? 8 : 32)) return Promise.reject(new Error('ENDPOINT_REQUEST_LIMIT'))
    const timeoutMs = options.timeoutMs ?? 30_000
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) return Promise.reject(new Error('ENDPOINT_TIMEOUT_LIMIT'))
    const id = ++this.#next, startedAt = performance.now()
    return new Promise<T>((resolve, reject) => {
      const cancel = (): void => { try { this.#endpoint.postMessage({ protocol: APPLICATION_OWNER_PROTOCOL, attachment: this.#attachment, kind: 'cancel', id }) } catch { /* ignore */ } }
      const abort = (): void => { const pending = this.#pending.get(id); if (pending === undefined) return; this.#pending.delete(id); clearTimeout(pending.timer); pending.cleanup(); cancel(); reject(options.signal?.reason) }
      const cleanup = (): void => options.signal?.removeEventListener('abort', abort)
      const timer = setTimeout(() => { this.#pending.delete(id); cleanup(); cancel(); reject(Object.assign(new Error('ENDPOINT_REQUEST_TIMEOUT'), { code: 'ENDPOINT_REQUEST_TIMEOUT' })) }, timeoutMs)
      this.#pending.set(id, { method, startedAt, deadline: startedAt + timeoutMs, resolve: value => resolve(value as T), reject, timer, cleanup })
      options.signal?.addEventListener('abort', abort, { once: true })
      try { this.#endpoint.postMessage({ protocol: APPLICATION_OWNER_PROTOCOL, attachment: this.#attachment, kind: 'request', id, method, args }) }
      catch (error) { this.#pending.delete(id); clearTimeout(timer); cleanup(); reject(error) }
    })
  }

  async initialize(options: { readonly applicationId: string; readonly context?: InlineApplicationEndpointContext }): Promise<void> {
    const value = await this.request<{ applicationId: string; identity: { publicKey: string }; status: SessionStatus; binding: InlineApplicationEndpointBinding; definition: InlineApplicationDescription }>('hello', [options])
    this.applicationId = value.applicationId; this.identity = value.identity; this.#status = value.status; this.#binding = value.binding; this.#description = value.definition
    this.#heartbeat = setInterval(() => {
      if (this.#pinging || this.signal.aborted || this.#attachmentState === 'suspended') return
      this.#pinging = true
      void this.request('attachment.ping', [], { timeoutMs: 20_000 }).catch(error => this.#detach(error)).finally(() => { this.#pinging = false })
    }, 5000)
    this.#heartbeat.unref?.()
  }

  async suspendAttachment(): Promise<void> { await this.request('attachment.suspend', []); this.#attachmentState = 'suspended'; this.#ownedViews.clear() }
  suspend(): Promise<void> { return this.suspendAttachment() }
  async resumeAttachment(): Promise<InlineApplicationEndpointBinding | null> { this.#status = await this.request('attachment.resume', []); this.#attachmentState = 'active'; return this.endpoint ?? null }
  detach(): Promise<void> { return this.close() }
  async submit(input: ApplicationSubmission): Promise<WorkerApplicationOperation> { const value = await this.request<{ id: string; operationId: string }>('submit', [input]); return new WorkerApplicationOperation(value.id, value.operationId, this) }
  async command(name: string, input: unknown, options: CommandOptions = {}): Promise<WorkerApplicationOperation> { const value = await this.request<{ id: string; operationId: string }>('command', [name, input, options]); return new WorkerApplicationOperation(value.id, value.operationId, this) }
  query(name: string, input: unknown = null): Promise<{ readonly applicationId: string; readonly revision: MaterializedRevision; readonly value: unknown }> { return this.request('query', [name, input]) }
  topic(name: string): Promise<JsonValue | null> { return this.request('topic', [name]) }
  readEvents(options: ApplicationEventOptions & { readonly view?: 'local' | 'final' } = {}): Promise<ReturnType<ApplicationReadView['readEvents']>> { return this.request('readEvents', [options]) }
  wait<T>(id: string, fact: string, options: WaitOptions = {}): Promise<T> { const timeoutMs = options.timeoutMs ?? 30_000; return this.request('operation.wait', [id, fact, timeoutMs], { ...options, timeoutMs: Math.min(120_000, timeoutMs + 1000) }) }

  async readView(options: { readonly view?: 'local' | 'final' } = {}): Promise<WorkerApplicationReadView> {
    const captured = await this.request<{ id: string; revision: MaterializedRevision }>('readView', [options])
    this.#ownedViews.add(captured.id); let released = false, releasing: Promise<void> | undefined
    return {
      applicationId: this.applicationId,
      revision: captured.revision,
      topic: name => { if (released) return Promise.reject(new Error('READ_VIEW_RELEASED')); return this.request('view.topic', [captured.id, name]) },
      query: (topic, input = null) => { if (released) return Promise.reject(new Error('READ_VIEW_RELEASED')); return this.request('view.query', [captured.id, topic, input]) },
      readEvents: evOptions => { if (released) return Promise.reject(new Error('READ_VIEW_RELEASED')); return this.request('view.events', [captured.id, evOptions ?? {}]) },
      release: () => { if (releasing !== undefined) return releasing; released = true; this.#ownedViews.delete(captured.id); return releasing = this.request<void>('view.release', [captured.id]) },
    }
  }

  get operations() {
    const session = this
    return {
      async retry(id: string): Promise<WorkerApplicationOperation> { const value = await session.request<{ id: string; operationId: string }>('operation.retry', [id]); return new WorkerApplicationOperation(value.id, value.operationId, session) },
      async get(id: string): Promise<WorkerApplicationOperation | null> { const value = await session.request<{ id: string; operationId: string } | null>('operation.get', [id]); return value === null ? null : new WorkerApplicationOperation(value.id, value.operationId, session) },
      async *subscribe(options: { readonly operationId: string; readonly signal?: AbortSignal }): AsyncIterable<OperationInspection> {
        const signal = options.signal === undefined ? session.signal : AbortSignal.any([session.signal, options.signal]); let dirty = true, wake: (() => void) | undefined
        const invalidate = (): void => { dirty = true; wake?.() }; const stop = session.onChange(invalidate), stopStatus = session.onStatus(invalidate); signal.addEventListener('abort', invalidate)
        try { while (!signal.aborted) { if (!dirty) await new Promise<void>(resolve => { wake = resolve }); if (signal.aborted) break; dirty = false; const operation = await session.operations.get(options.operationId); if (operation !== null) yield await operation.inspect() } } finally { stop(); stopStatus(); signal.removeEventListener('abort', invalidate) }
      },
    }
  }

  onStatus(listener: (status: SessionStatus) => void): () => void { this.#statuses.add(listener); listener(this.status); return () => { this.#statuses.delete(listener) } }
  onChange(listener: (change: ApplicationChange) => void): () => void { this.#changes.add(listener); return () => { this.#changes.delete(listener) } }

  async *changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationChange> {
    const signal = options.signal === undefined ? this.signal : AbortSignal.any([this.signal, options.signal]), queue: ApplicationChange[] = []; let wake: (() => void) | undefined
    const stop = this.onChange(value => { queue.splice(0, queue.length, value); wake?.() }), abort = (): void => { wake?.() }; signal.addEventListener('abort', abort)
    try { while (!signal.aborted) { if (queue.length === 0) await new Promise<void>(resolve => { wake = resolve }); while (queue.length > 0 && !signal.aborted) yield queue.shift()! } } finally { stop(); signal.removeEventListener('abort', abort) }
  }

  diagnostics(): Promise<readonly InlineApplicationPeerDiagnostics[]> { return this.request('diagnostics.peers', []) }
  endpoints(): Promise<readonly (InlineApplicationEndpointBinding & { readonly state: 'active' | 'suspended' })[]> { return this.request('endpoints.list', []) }
  exportFacts(options?: { readonly includePrivateCas?: boolean; readonly includeGenesis?: boolean }): Promise<InlineSessionFacts> { return this.request('facts.export', options === undefined ? [] : [options]) }
  mergeFacts(facts: InlineSessionFacts): Promise<void> { return this.request('facts.merge', [facts]) }

  readonly finality = {
    status: (): Promise<VerifiedFinalityV2 & { readonly schedule: readonly ScheduledFinalityEntry[] }> => this.request('finality.status', []),
    createCheckpoint: (options: { readonly throughMs: bigint }): Promise<{ readonly checkpoint: InlineFinalityCheckpoint; readonly snapshot: CheckpointBootstrapSnapshot }> => this.request('finality.createCheckpoint', [options]),
    submitCheckpoints: (checkpoints: readonly InlineFinalityCheckpoint[]): Promise<void> => this.request('finality.submitCheckpoints', [checkpoints]),
  }

  readonly extensions = {
    call: <T = unknown>(name: string, args: readonly unknown[] = [], options: WaitOptions = {}): Promise<T> => this.request('extension.call', [name, args], options),
    subscribe: (listener: (value: unknown) => void): (() => void) => { this.#extensions.add(listener); return () => { this.#extensions.delete(listener) } },
  }

  readonly signals = {
    delivery: 'application' as const,
    send: (topic: string, payload: SignalPayload, options: SignalSendOptions = {}): Promise<EphemeralSignal> => { const { signal, ...rest } = options; return this.request('signals.send', [topic, payload, rest], signal === undefined ? {} : { signal }) },
    subscribe: (options: SignalSubscribeOptions = {}): AsyncIterable<EphemeralSignal> => {
      const session = this
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<EphemeralSignal> {
          const { signal, ...rest } = options
          const id = await session.request<string>('signals.open', [rest], signal === undefined ? {} : { signal })
          try {
            while (true) {
              const next = await session.request<EphemeralSignal | null>('signals.next', [id], signal === undefined ? { timeoutMs: 120_000 } : { signal, timeoutMs: 120_000 })
              if (next === null) return
              yield next
            }
          } finally { void session.request('signals.close', [id]).catch(() => undefined) }
        },
      }
    },
  }

  readonly content = {
    stage: async (options: { readonly bytes: number; readonly mediaType?: string }): Promise<ContentUpload> => {
      const id = await this.request<string>('content.stage', [options])
      return {
        id,
        write: (index, bytes) => this.request('upload.write', [id, index, bytes]),
        progress: () => this.request('upload.progress', [id]),
        commit: () => this.request('upload.commit', [id]),
        discard: () => this.request('upload.discard', [id]),
      }
    },
    read: (reference: ContentReference, options: { readonly signal?: AbortSignal } = {}): AsyncIterable<Uint8Array> => {
      const session = this
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
          const id = await session.request<string>('content.openRead', [reference], options)
          try {
            while (true) {
              const chunk = await session.request<Uint8Array | null>('content.next', [id], options)
              if (chunk === null) return
              yield chunk
            }
          } finally { void session.request('content.cancel', [id]).catch(() => undefined) }
        },
      }
    },
    putBytes: (bytes: Uint8Array, options?: ContentPutBytesOptions): Promise<ContentReference> => putContentBytes(this.content, bytes, options),
    readBytes: (reference: ContentReference, options: ContentReadBytesOptions): Promise<Uint8Array> => readContentBytes(this.content, reference, options),
    retain: (reference: ContentReference, options: { readonly signal?: AbortSignal } = {}): Promise<ContentRetention> => this.request('content.retain', [reference], options),
    retention: (reference: ContentReference, options: { readonly signal?: AbortSignal } = {}): Promise<readonly ContentRetention[]> => this.request('content.retention', [reference], options),
    retained: (reference: ContentReference): Promise<readonly ContentRetention[]> => this.request('content.retained', [reference]),
    discard: (reference: ContentReference): Promise<void> => this.request('content.discard', [reference]),
    putBlob: async (bytes: Uint8Array, options: BlobPutOptions = {}): Promise<BlobInfo> => {
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_BLOB_BYTES) throw new Error('CONTENT_RANGE_INVALID')
      const reqOptions = options.signal === undefined ? {} : { signal: options.signal }
      const id = await this.request<string>('content.blobOpenWrite', [bytes.byteLength], reqOptions)
      try {
        for (let offset = 0; offset < bytes.byteLength; offset += CONTENT_CHUNK_BYTES) {
          const chunk = Uint8Array.from(bytes.subarray(offset, Math.min(bytes.byteLength, offset + CONTENT_CHUNK_BYTES)))
          await this.request('content.blobWriteChunk', [id, offset / CONTENT_CHUNK_BYTES, chunk], reqOptions)
        }
        return await this.request<BlobInfo>('content.blobCommitWrite', [id], reqOptions)
      } catch (error) {
        void this.request('content.blobAbortWrite', [id]).catch(() => undefined)
        throw error
      }
    },
    getBlob: async (hash: string, options: BlobGetOptions = {}): Promise<Uint8Array | null> => {
      const { signal, ...rest } = options
      const reqOptions = signal === undefined ? {} : { signal }
      const opened = await this.request<{ readonly id: string; readonly bytes: number } | null>('content.blobOpenRead', [hash, rest], reqOptions)
      if (opened === null) return null
      const result = new Uint8Array(opened.bytes)
      let offset = 0
      try {
        while (offset < opened.bytes) {
          const chunk = await this.request<Uint8Array | null>('content.blobNextChunk', [opened.id], reqOptions)
          if (chunk === null) break
          if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0 || offset + chunk.byteLength > opened.bytes) throw new Error('CONTENT_CHUNK_SIZE_INVALID')
          result.set(chunk, offset)
          offset += chunk.byteLength
        }
        if (offset !== opened.bytes) throw new Error('CONTENT_INCOMPLETE')
        return result
      } finally {
        void this.request('content.blobCloseRead', [opened.id]).catch(() => undefined)
      }
    },
    hasBlob: (hash: string): Promise<boolean> => this.request('content.hasBlob', [hash]),
    deleteBlob: (hash: string): Promise<void> => this.request('content.deleteBlob', [hash]),
    put: async (bytes: Uint8Array, options: ContentPutOptions = {}): Promise<BlobReference> => {
      const visibility = options.visibility ?? 'private'
      const mediaType = options.mediaType ?? 'application/octet-stream'
      if (visibility === 'public') {
        const info = await this.content.putBlob(bytes, options.signal === undefined ? {} : { signal: options.signal })
        return { profile: 'chronolog-blob-v2', visibility: 'public', hash: info.hash, bytes: info.bytes, mediaType }
      }
      if (options.deduplicate === true) {
        if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_BLOB_BYTES) throw new Error('CONTENT_RANGE_INVALID')
        const reqOptions = options.signal === undefined ? {} : { signal: options.signal }
        const id = await this.request<string>('content.blobOpenWrite', [bytes.byteLength], reqOptions)
        try {
          for (let offset = 0; offset < bytes.byteLength; offset += CONTENT_CHUNK_BYTES) {
            const chunk = Uint8Array.from(bytes.subarray(offset, Math.min(bytes.byteLength, offset + CONTENT_CHUNK_BYTES)))
            await this.request('content.blobWriteChunk', [id, offset / CONTENT_CHUNK_BYTES, chunk], reqOptions)
          }
          return await this.request<ContentReference>('content.blobCommitPrivate', [id, mediaType], reqOptions)
        } catch (error) {
          void this.request('content.blobAbortWrite', [id]).catch(() => undefined)
          throw error
        }
      }
      return this.content.putBytes(bytes, { mediaType, ...(options.signal === undefined ? {} : { signal: options.signal }) })
    },
    get: async (target: BlobReference | string, options: ContentGetOptions = {}): Promise<Uint8Array | null> => {
      if (typeof target === 'string') return this.content.getBlob(target, options)
      if (isPublicBlobReference(target)) {
        return this.content.getBlob(target.hash, { ...options, expectedBytes: options.expectedBytes ?? target.bytes })
      }
      if (isPrivateContentReference(target)) {
        try {
          return await this.content.readBytes(target, {
            maxBytes: options.maxBytes ?? target.bytes,
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          })
        } catch (error) {
          if (error instanceof Error && (error.message === 'CONTENT_MANIFEST_MISSING' || error.message === 'CONTENT_CHUNK_MISSING')) {
            return null
          }
          throw error
        }
      }
      throw new Error('CONTENT_REFERENCE_INVALID')
    },
  }

  #detach(error: unknown): void {
    if (this.#attachmentState === 'detached') return
    this.#attachmentState = 'detached'
    clearInterval(this.#heartbeat)
    this.#lifetime.abort(error)
    for (const pending of this.#pending.values()) { clearTimeout(pending.timer); pending.cleanup(); pending.reject(error) }
    this.#pending.clear()
    this.#endpoint.removeEventListener('message', this.#receive)
    const physical = this.#endpoint as unknown as EventTarget & { off?(type: string, listener: () => void): void }
    physical.removeEventListener('close', this.#physicalClose)
    physical.removeEventListener('messageerror', this.#physicalClose)
    physical.off?.('close', this.#physicalClose)
    physical.off?.('messageerror', this.#physicalClose)
    this.#status = { ...this.#status, canAuthor: false, phase: 'closed', database: 'closed' }
    for (const listener of this.#statuses) { try { listener(this.status) } catch { /* ignore */ } }
  }

  async close(): Promise<void> {
    if (this.#attachmentState === 'detached') return
    try { await this.request('close', [], { timeoutMs: 2000 }) } catch { /* ignore */ }
    this.#detach(new Error('ENDPOINT_CLOSED'))
    this.#endpoint.close?.()
  }
}

export async function connectApplicationOwner(
  endpoint: ApplicationWorkerEndpoint & { start?(): void },
  options: { readonly applicationId: string; readonly context?: InlineApplicationEndpointContext },
): Promise<WorkerApplicationSession> {
  endpoint.start?.()
  const session = new WorkerApplicationSession(endpoint)
  try {
    await session.initialize(options)
    return session
  } catch (error) {
    await session.close()
    throw error
  }
}

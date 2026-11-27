import { check, type FinalityCheckpoint } from '@chronolog/authority'
import type { JsonValue } from '@chronolog/protocol'
import type { EphemeralSignal, SignalSubscribeOptions, SignalSendOptions, SignalPayload } from '@chronolog/signals'
import type { ApplicationSession, SessionFacts } from './session.js'
import { awaitOwnedTask } from './lifetime.js'
import {
  APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES,
  type ApplicationAttachmentCapability,
  type ApplicationAttachmentPolicy,
  type ApplicationEndpointBinding,
  type ApplicationEndpointContext,
  type ApplicationOwnerOptions,
  type ApplicationSessionOwner,
} from './owner-types.js'
import { APPLICATION_OWNER_PROTOCOL, type OwnerRequest } from './worker-application-protocol.js'
import type { ApplicationReadView } from './session-types.js'
import type { ContentUpload } from './content.js'
import { CONTENT_CHUNK_BYTES, MAX_BLOB_BYTES, type BlobGetOptions } from './content-bytes.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'

interface SignalStream { readonly iterator: AsyncIterator<EphemeralSignal>; readonly lifetime: AbortController; pending: Promise<IteratorResult<EphemeralSignal>> | null; busy: boolean }
interface Reader { readonly iterator: AsyncIterator<Uint8Array>; readonly lifetime: AbortController; busy: boolean }
interface BlobWrite { readonly totalBytes: number; readonly chunks: (Uint8Array | undefined)[] }
interface BlobRead { readonly bytes: Uint8Array; offset: number }
interface RequestContext { readonly lifetime: AbortController; readonly signal: AbortSignal; readonly method: string; readonly control: boolean }

const isArray = (value: unknown): boolean => Array.isArray(value)
const CONTROLS = new Set(['close', 'attachment.ping', 'attachment.suspend', 'attachment.resume', 'view.release', 'content.cancel', 'content.blobAbortWrite', 'content.blobCloseRead', 'signals.close', 'upload.discard'])

function requestBudget(value: unknown): void {
  let nodes = 0, bytes = 0
  const walk = (item: unknown, depth: number): void => {
    check(++nodes <= 16384 && depth <= 32, 'ENDPOINT_REQUEST_SIZE_LIMIT')
    if (item instanceof Uint8Array) bytes += item.length
    else if (typeof item === 'string') bytes += item.length * 3
    else if (Array.isArray(item)) for (const child of item) walk(child, depth + 1)
    else if (item !== null && typeof item === 'object') for (const [key, child] of Object.entries(item)) { bytes += key.length * 3; walk(child, depth + 1) }
    else check(item === null || typeof item === 'number' || typeof item === 'boolean' || typeof item === 'bigint' || item === undefined, 'ENDPOINT_REQUEST_INVALID')
    check(bytes <= 4 * 1024 * 1024, 'ENDPOINT_REQUEST_SIZE_LIMIT')
  }
  walk(value, 0)
}

function checkedContext(value: ApplicationEndpointContext): ApplicationEndpointContext {
  check(
    value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.entries(value).every(([key, item]) =>
      ['viewId', 'documentPath', 'publicationId', 'runId'].includes(key) &&
      typeof item === 'string' && item.length > 0 && item.length <= (key === 'documentPath' ? 1024 : 128) &&
      ![...item].some(character => character.charCodeAt(0) < 32),
    ),
    'APPLICATION_ENDPOINT_CONTEXT_INVALID',
  )
  return structuredClone(value)
}

function limit(value: number | undefined, fallback: number, maximum: number): number {
  const result = value ?? fallback
  check(Number.isSafeInteger(result) && result > 0 && result <= maximum, 'OWNER_CONFIGURATION_INVALID')
  return result
}

/** One fenced signer/storage owner, with independent bounded and cancellable client attachments. */
export function createApplicationOwner(session: ApplicationSession, options: ApplicationOwnerOptions = {}): ApplicationSessionOwner {
  const ownerInstanceId = crypto.randomUUID(), maxAttachments = limit(options.maxAttachments, 16, 64)
  const attachments = new Map<string, { binding(): ApplicationEndpointBinding; state(): 'active' | 'suspended'; close(): void }>()
  const heldViewIds = new Map<string, string>()
  let closed = false, closing: Promise<void> | undefined

  const owner: ApplicationSessionOwner = {
    ownerInstanceId,
    session,
    endpoints: () => [...attachments.values()].map(value => ({ ...value.binding(), state: value.state() })),
    close: () => closing ??= (async () => { closed = true; for (const attachment of [...attachments.values()]) attachment.close(); await session.close() })(),
    attach(endpoint: ApplicationWorkerEndpoint & { start?(): void }, policy: ApplicationAttachmentPolicy = {}) {
      check(!closed && attachments.size < maxAttachments, 'OWNER_ATTACHMENT_LIMIT')
      const endpointId = crypto.randomUUID(), endpointIncarnation = crypto.randomUUID(), lifetime = new AbortController()
      const views = new Map<string, ApplicationReadView>(), uploads = new Map<string, ContentUpload>(), completedUploads = new Map<string, ContentUpload>(), readers = new Map<string, Reader>(), blobWrites = new Map<string, BlobWrite>(), blobReads = new Map<string, BlobRead>(), streams = new Map<string, SignalStream>(), pending = new Map<number, RequestContext>()
      let effective = policy, attachment = '', initialized = false, detached = false, suspended = false, highestRequest = 0, viewReservations = 0, uploadReservations = 0, lastReceived = performance.now(), context: ApplicationEndpointContext = policy.context ?? {}
      let claimedViewId: string | undefined
      let stopStatus: (() => void) | undefined, stopChange: (() => void) | undefined, stopExtension: (() => void) | undefined
      const physical = endpoint as unknown as { addEventListener(type: string, listener: EventListener): void; removeEventListener(type: string, listener: EventListener): void; on?(type: string, listener: () => void): void; off?(type: string, listener: () => void): void }
      const binding = (): ApplicationEndpointBinding => ({
        ownerInstanceId,
        endpointId,
        endpointIncarnation,
        context: structuredClone(context),
        evidence: 'owner-bound',
        contextEvidence: effective.contextEvidence ?? 'caller-asserted',
        capabilities: [...(effective.capabilities ?? APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES)],
        ...(effective.identity === undefined ? {} : { identity: structuredClone(effective.identity) }),
      })
      const has = (capability: ApplicationAttachmentCapability): boolean => (effective.capabilities ?? APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES).includes(capability)
      const allow = (capability: ApplicationAttachmentCapability): void => check(has(capability), 'ENDPOINT_CAPABILITY_FORBIDDEN')
      const post = (message: unknown): void => { if (!detached) endpoint.postMessage(message) }
      const releaseResources = (): void => {
        for (const view of views.values()) view.release(); views.clear()
        for (const reader of readers.values()) { reader.lifetime.abort(); void reader.iterator.return?.().catch(() => undefined) }; readers.clear()
        blobWrites.clear(); blobReads.clear()
        for (const stream of streams.values()) { stream.lifetime.abort(); void stream.iterator.return?.().catch(() => undefined) }; streams.clear()
      }
      const close = (): void => {
        if (detached) return
        try { post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'notice', topic: 'closed', value: 'ENDPOINT_CLOSED' }) } catch { /* ignore */ }
        detached = true; clearInterval(expiry); lifetime.abort(new Error('ENDPOINT_CLOSED'))
        for (const request of pending.values()) request.lifetime.abort(new Error('ENDPOINT_CLOSED')); pending.clear()
        endpoint.removeEventListener('message', receive); physical.removeEventListener('close', physicalClose); physical.removeEventListener('messageerror', physicalClose); physical.off?.('close', close); physical.off?.('messageerror', close)
        if (claimedViewId !== undefined && heldViewIds.get(claimedViewId) === endpointId) heldViewIds.delete(claimedViewId)
        stopStatus?.(); stopChange?.(); stopExtension?.(); releaseResources(); uploads.clear(); completedUploads.clear(); attachments.delete(endpointId); endpoint.close?.()
        if (!closed && attachments.size === 0 && options.lastClient === 'shutdown') void owner.close()
      }
      const physicalClose: EventListener = () => close()
      const active = (request: RequestContext): void => { request.signal.throwIfAborted(); check(!detached, 'ENDPOINT_CLOSED') }

      const invoke = async (method: string, args: readonly unknown[], request: RequestContext): Promise<unknown> => {
        active(request)
        if (method === 'hello') {
          check(!initialized && typeof args[0] === 'object' && args[0] !== null, 'ENDPOINT_HANDSHAKE_INVALID')
          const handshake = args[0] as { applicationId: string; context?: ApplicationEndpointContext }
          check(handshake.applicationId === session.applicationId, 'ENDPOINT_APPLICATION_MISMATCH')
          effective = { ...policy, ...options.authorize?.(handshake) }
          limit(effective.maxRequests, 32, 64); limit(effective.maxViews, 8, 32)
          check(
            effective.capabilities === undefined ||
            isArray(effective.capabilities) &&
            effective.capabilities.length <= APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES.length &&
            new Set(effective.capabilities).size === effective.capabilities.length &&
            effective.capabilities.every(capability => APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES.includes(capability)),
            'OWNER_CONFIGURATION_INVALID',
          )
          const requested = checkedContext(effective.context ?? handshake.context ?? {})
          let viewId = requested.viewId ?? crypto.randomUUID()
          while (heldViewIds.has(viewId)) viewId = crypto.randomUUID()
          heldViewIds.set(viewId, endpointId); claimedViewId = viewId
          context = { ...requested, viewId }; initialized = true
          stopStatus = session.onStatus(value => { if (!suspended) post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'notice', topic: 'status', value }) })
          stopChange = session.onChange(value => { if (!suspended) post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'notice', topic: 'change', value }) })
          if (has('extensions')) stopExtension = options.extensions?.subscribe?.(value => { if (!suspended) post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'notice', topic: 'extension', value }) })
          const description = await session.describe()
          return { applicationId: session.applicationId, identity: session.identity, definition: description, status: session.status, binding: binding() }
        }
        if (method === 'close') return null
        check(initialized, 'ENDPOINT_HANDSHAKE_REQUIRED')
        if (method === 'attachment.ping') return { ...binding(), state: suspended ? 'suspended' : 'active' }
        if (method === 'attachment.suspend') { suspended = true; for (const work of pending.values()) if (!work.control) work.lifetime.abort(new Error('ENDPOINT_SUSPENDED')); releaseResources(); return null }
        if (method === 'attachment.resume') { suspended = false; return session.status }
        if (method === 'view.release') { const id = String(args[0]), view = views.get(id); views.delete(id); view?.release(); return null }
        if (method === 'content.cancel') { const id = String(args[0]), reader = readers.get(id); readers.delete(id); reader?.lifetime.abort(); await reader?.iterator.return?.(); return null }
        if (method === 'content.blobAbortWrite') { blobWrites.delete(String(args[0])); return null }
        if (method === 'content.blobCloseRead') { blobReads.delete(String(args[0])); return null }
        if (method === 'signals.close') { const id = String(args[0]), stream = streams.get(id); streams.delete(id); stream?.lifetime.abort(); await stream?.iterator.return?.(); return null }
        if (method === 'upload.discard') { const id = String(args[0]), upload = uploads.get(id) ?? completedUploads.get(id); uploads.delete(id); completedUploads.delete(id); await upload?.discard(); return null }
        check(!suspended, 'ENDPOINT_SUSPENDED')

        if (method === 'submit') {
          allow('commands'); check(effective.rawSubmit ?? effective.commands === undefined, 'ENDPOINT_RAW_SUBMIT_FORBIDDEN')
          const operation = await session.submit(args[0] as Parameters<ApplicationSession['submit']>[0])
          return { id: operation.id, operationId: operation.operationId }
        }
        if (method === 'command') {
          allow('commands'); const name = String(args[0])
          check(effective.commands === undefined || effective.commands.includes(name), 'ENDPOINT_COMMAND_FORBIDDEN')
          const input = options.prepareCommand === undefined ? args[1] : options.prepareCommand(binding(), name, args[1])
          const operation = await session.command(name, input, args[2] as Parameters<ApplicationSession['command']>[2])
          return { id: operation.id, operationId: operation.operationId }
        }
        if (method === 'query') {
          allow('queries'); const name = String(args[0])
          check(effective.queries === undefined || effective.queries.includes(name), 'ENDPOINT_QUERY_FORBIDDEN')
          return session.query(name, args[1], { signal: request.signal })
        }
        if (method === 'topic') {
          allow('queries')
          return session.topic(String(args[0]))
        }
        if (method === 'readEvents') {
          allow('events')
          return session.readEvents(args[0] as Parameters<ApplicationSession['readEvents']>[0])
        }
        if (method === 'readView') {
          check(has('queries') || has('events'), 'ENDPOINT_CAPABILITY_FORBIDDEN')
          check(views.size + viewReservations < (effective.maxViews ?? 8), 'ENDPOINT_VIEW_LIMIT')
          viewReservations++
          let view: ApplicationReadView | undefined, deferred = false
          const opening = session.readView(args[0] as Parameters<ApplicationSession['readView']>[0])
          try {
            view = await awaitOwnedTask(request.signal, () => opening)
            active(request)
            const id = crypto.randomUUID()
            views.set(id, view)
            const result = { id, revision: view.revision }
            view = undefined
            return result
          } catch (error) {
            if (request.signal.aborted && view === undefined) {
              deferred = true
              void opening.then(late => late.release()).catch(() => undefined).finally(() => { viewReservations-- })
            }
            throw error
          } finally {
            if (!deferred) viewReservations--
            view?.release()
          }
        }
        if (method === 'view.topic' || method === 'view.query' || method === 'view.events') {
          const view = views.get(String(args[0])); check(view !== undefined, 'ENDPOINT_VIEW_STALE')
          if (method === 'view.topic') { allow('queries'); return view.topic(String(args[1])) }
          if (method === 'view.query') { allow('queries'); return view.query(String(args[1]), args[2] as JsonValue) }
          allow('events'); return view.readEvents(args[1] as Parameters<ApplicationReadView['readEvents']>[0])
        }
        if (method === 'operation.retry') { allow('operations'); const operation = await session.operations.retry(String(args[0])); return { id: operation.id, operationId: operation.operationId } }
        if (method === 'operation.get') { allow('operations'); const operation = session.operations.get(String(args[0])); return operation === null ? null : { id: operation.id, operationId: operation.operationId, inspection: operation.inspect() } }
        if (method === 'operation.inspect') { allow('operations'); return session.inspectOperation(String(args[0])) }
        if (method === 'operation.wait') {
          allow('operations'); const operation = session.operations.get(String(args[0])); check(operation !== null, 'OPERATION_UNKNOWN')
          const fact = args[1]; check(fact === 'materialized' || fact === 'retained' || fact === 'finalized', 'OPERATION_FACT_INVALID')
          return operation[fact]({ signal: request.signal, timeoutMs: Number(args[2] ?? 30_000) })
        }
        if (method === 'diagnostics.peers') { allow('diagnostics'); return session.diagnostics() }
        if (method === 'endpoints.list') { allow('diagnostics'); return owner.endpoints() }
        if (method === 'facts.export') { allow('replication'); return session.exportFacts(args[0] as Parameters<ApplicationSession['exportFacts']>[0]) }
        if (method === 'facts.merge') { allow('replication'); return session.mergeFacts(args[0] as SessionFacts) }
        if (method === 'finality.status') { allow('finality'); return session.finality.status() }
        if (method === 'finality.createCheckpoint') { allow('finality'); return session.finality.createCheckpoint(args[0] as { throughMs: bigint }) }
        if (method === 'finality.submitCheckpoints') { allow('finality'); return session.finality.submitCheckpoints(args[0] as readonly FinalityCheckpoint[]) }
        if (method === 'extension.call') {
          allow('extensions'); check(options.extensions !== undefined, 'ENDPOINT_METHOD_UNKNOWN')
          const name = args[0], input = args[1]
          check(typeof name === 'string' && /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/u.test(name) && Array.isArray(input), 'ENDPOINT_REQUEST_INVALID')
          return options.extensions.call(name, input as readonly unknown[], { endpoint: binding(), signal: request.signal })
        }
        if (['content.retain', 'content.retention', 'content.retained', 'content.discard'].includes(method)) {
          allow('content'); const reference = args[0] as Parameters<ApplicationSession['content']['retain']>[0]
          if (method === 'content.retain') return session.content.retain(reference, { signal: request.signal })
          if (method === 'content.retention') return session.content.retention(reference, { signal: request.signal })
          if (method === 'content.retained') return session.content.retained(reference)
          return session.content.discard(reference)
        }
        if (method === 'content.stage') {
          allow('content'); check(uploads.size + uploadReservations < 4, 'ENDPOINT_UPLOAD_LIMIT'); uploadReservations++
          let upload: ContentUpload | undefined
          try { upload = await session.content.stage(args[0] as Parameters<ApplicationSession['content']['stage']>[0]); active(request); uploads.set(upload.id, upload); const id = upload.id; upload = undefined; return id }
          finally { uploadReservations--; if (upload !== undefined) await upload.discard() }
        }
        if (['upload.write', 'upload.progress', 'upload.commit'].includes(method)) {
          allow('content'); const id = String(args[0]), upload = uploads.get(id) ?? completedUploads.get(id); check(upload !== undefined, 'CONTENT_UPLOAD_UNKNOWN')
          if (method === 'upload.write') { check(args[2] instanceof Uint8Array && args[2].length <= 65536, 'CONTENT_CHUNK_LIMIT'); return upload.write(Number(args[1]), args[2]) }
          if (method === 'upload.progress') return upload.progress()
          const reference = await upload.commit(); uploads.delete(id); completedUploads.set(id, upload)
          while (completedUploads.size > 32) completedUploads.delete(completedUploads.keys().next().value!)
          return reference
        }
        if (method === 'content.openRead') {
          allow('content'); check(readers.size < 4, 'ENDPOINT_READER_LIMIT')
          const id = crypto.randomUUID(), owned = new AbortController()
          const iterator = session.content.read(args[0] as Parameters<ApplicationSession['content']['read']>[0], { signal: AbortSignal.any([owned.signal, lifetime.signal]) })[Symbol.asyncIterator]()
          readers.set(id, { iterator, lifetime: owned, busy: false }); return id
        }
        if (method === 'content.next') {
          allow('content'); const id = String(args[0]), reader = readers.get(id); check(reader !== undefined && !reader.busy, 'CONTENT_READER_UNKNOWN')
          reader.busy = true
          const abort = (): void => { reader.lifetime.abort(); readers.delete(id) }
          request.signal.addEventListener('abort', abort, { once: true })
          try {
            const next = await reader.iterator.next(); active(request)
            if (next.done) { readers.delete(id); return null }
            check(next.value.length <= 65536, 'CONTENT_CHUNK_LIMIT'); return next.value
          } finally { request.signal.removeEventListener('abort', abort); reader.busy = false }
        }
        if (method === 'content.hasBlob') { allow('content'); return session.content.hasBlob(String(args[0])) }
        if (method === 'content.deleteBlob') { allow('content'); return session.content.deleteBlob(String(args[0])) }
        if (method === 'content.blobOpenWrite') {
          allow('content'); check(blobWrites.size < 4, 'ENDPOINT_UPLOAD_LIMIT')
          const totalBytes = Number(args[0])
          check(Number.isSafeInteger(totalBytes) && totalBytes >= 0 && totalBytes <= MAX_BLOB_BYTES, 'CONTENT_RANGE_INVALID')
          const id = crypto.randomUUID(), count = Math.ceil(totalBytes / CONTENT_CHUNK_BYTES)
          blobWrites.set(id, { totalBytes, chunks: new Array<Uint8Array | undefined>(count) })
          return id
        }
        if (method === 'content.blobWriteChunk') {
          allow('content'); const write = blobWrites.get(String(args[0])); check(write !== undefined, 'CONTENT_UPLOAD_UNKNOWN')
          const index = Number(args[1]), chunk = args[2]
          check(Number.isSafeInteger(index) && index >= 0 && index < write.chunks.length && chunk instanceof Uint8Array && chunk.byteLength === Math.min(CONTENT_CHUNK_BYTES, write.totalBytes - index * CONTENT_CHUNK_BYTES), 'CONTENT_CHUNK_SIZE_INVALID')
          write.chunks[index] = chunk.slice(); return null
        }
        if (method === 'content.blobCommitWrite') {
          allow('content'); const id = String(args[0]), write = blobWrites.get(id); check(write !== undefined, 'CONTENT_UPLOAD_UNKNOWN')
          blobWrites.delete(id)
          const assembled = new Uint8Array(write.totalBytes)
          for (let index = 0; index < write.chunks.length; index++) {
            const chunk = write.chunks[index]; check(chunk !== undefined, 'CONTENT_INCOMPLETE')
            assembled.set(chunk, index * CONTENT_CHUNK_BYTES)
          }
          return session.content.putBlob(assembled, { signal: request.signal })
        }
        if (method === 'content.blobCommitPrivate') {
          allow('content'); const id = String(args[0]), write = blobWrites.get(id); check(write !== undefined, 'CONTENT_UPLOAD_UNKNOWN')
          blobWrites.delete(id)
          const assembled = new Uint8Array(write.totalBytes)
          for (let index = 0; index < write.chunks.length; index++) {
            const chunk = write.chunks[index]; check(chunk !== undefined, 'CONTENT_INCOMPLETE')
            assembled.set(chunk, index * CONTENT_CHUNK_BYTES)
          }
          const mediaType = typeof args[1] === 'string' ? args[1] : undefined
          return session.content.put(assembled, {
            visibility: 'private',
            deduplicate: true,
            ...(mediaType === undefined ? {} : { mediaType }),
            signal: request.signal,
          })
        }
        if (method === 'content.blobOpenRead') {
          allow('content'); check(blobReads.size < 4, 'ENDPOINT_READER_LIMIT')
          const rawOptions = (args[1] ?? {}) as Omit<BlobGetOptions, 'signal'>
          const bytes = await session.content.getBlob(String(args[0]), { ...rawOptions, signal: request.signal })
          if (bytes === null) return null
          const id = crypto.randomUUID()
          blobReads.set(id, { bytes, offset: 0 })
          return { id, bytes: bytes.byteLength }
        }
        if (method === 'content.blobNextChunk') {
          allow('content'); const id = String(args[0]), read = blobReads.get(id); check(read !== undefined, 'CONTENT_READER_UNKNOWN')
          if (read.offset >= read.bytes.byteLength) { blobReads.delete(id); return null }
          const nextOffset = Math.min(read.bytes.byteLength, read.offset + CONTENT_CHUNK_BYTES)
          const slice = read.bytes.subarray(read.offset, nextOffset).slice()
          read.offset = nextOffset
          if (read.offset >= read.bytes.byteLength) blobReads.delete(id)
          return slice
        }
        if (method === 'signals.send') {
          allow('signals')
          const supplied = (args[2] ?? {}) as Omit<SignalSendOptions, 'signal'>
          return session.signals.send(String(args[0]), args[1] as SignalPayload, {
            ...supplied,
            signal: request.signal,
            stream: { ...supplied.stream, streamId: supplied.stream?.streamId ?? endpointId, endpointId, endpointIncarnation },
          })
        }
        if (method === 'signals.open') {
          allow('signals'); check(streams.size < 4, 'ENDPOINT_STREAM_LIMIT')
          const id = crypto.randomUUID(), owned = new AbortController()
          const iterator = session.signals.subscribe({ ...(args[0] ?? {}) as SignalSubscribeOptions, signal: AbortSignal.any([owned.signal, lifetime.signal]) })[Symbol.asyncIterator]()
          streams.set(id, { iterator, lifetime: owned, pending: null, busy: false }); return id
        }
        if (method === 'signals.next') {
          allow('signals'); const id = String(args[0]), stream = streams.get(id); check(stream !== undefined && !stream.busy, 'SIGNAL_STREAM_UNKNOWN')
          stream.busy = true
          try {
            const next = await awaitOwnedTask(request.signal, () => stream.pending ??= stream.iterator.next())
            stream.pending = null; active(request)
            if (next.done) { streams.delete(id); return null }
            return next.value
          } finally { stream.busy = false }
        }
        throw new Error('ENDPOINT_METHOD_UNKNOWN')
      }

      const receive = (event: MessageEvent): void => {
        const message = event.data as Partial<Omit<OwnerRequest, 'kind'>> & { readonly kind?: string; readonly id?: number }
        if (message?.protocol !== APPLICATION_OWNER_PROTOCOL || detached) return
        if (attachment === '' && typeof message.attachment === 'string' && message.attachment.length > 0 && message.attachment.length <= 128) attachment = message.attachment
        if (message.attachment !== attachment) return
        lastReceived = performance.now()
        if (message.kind === 'cancel' && typeof message.id === 'number') { pending.get(message.id)?.lifetime.abort(new Error('ENDPOINT_REQUEST_CANCELLED')); return }
        if (message.kind !== 'request' || typeof message.id !== 'number' || !Number.isSafeInteger(message.id) || message.id <= highestRequest || typeof message.method !== 'string' || !Array.isArray(message.args)) return
        const requestId = message.id
        const requestMethod = message.method
        highestRequest = requestId
        const control = CONTROLS.has(requestMethod), inFlight = [...pending.values()].filter(value => value.control === control).length
        if (inFlight >= (control ? 8 : (effective.maxRequests ?? 32))) { post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'response', id: requestId, error: 'ENDPOINT_REQUEST_LIMIT' }); return }
        try { requestBudget(message.args) } catch (error) { post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'response', id: requestId, error: error instanceof Error ? error.message : 'ENDPOINT_REQUEST_INVALID' }); return }
        const requestLifetime = new AbortController(), request: RequestContext = { lifetime: requestLifetime, signal: AbortSignal.any([lifetime.signal, requestLifetime.signal]), method: requestMethod, control }
        pending.set(requestId, request)
        void invoke(requestMethod, message.args, request).then(
          value => { pending.delete(requestId); post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'response', id: requestId, value }); if (requestMethod === 'close') close() },
          error => { pending.delete(requestId); post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'response', id: requestId, error: error instanceof Error ? error.message : String(error) }); if (requestMethod === 'hello' || requestMethod === 'close') close() },
        )
      }
      const expiry = setInterval(() => { if (!suspended && performance.now() - lastReceived > 60_000) close() }, 15_000); expiry.unref?.()
      attachments.set(endpointId, { binding, state: () => suspended ? 'suspended' : 'active', close })
      endpoint.addEventListener('message', receive); physical.addEventListener('close', physicalClose); physical.addEventListener('messageerror', physicalClose); physical.on?.('close', close); physical.on?.('messageerror', close)
      endpoint.start?.()
      return close
    },
  }
  return owner
}

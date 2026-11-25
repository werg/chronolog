import { check, type AuthorityBundle, type FinalityProof } from '@chronolog/authority'
import type { EphemeralSignal, SignalSubscribeOptions, SignalSendOptions, SignalPayload } from '@chronolog/signals'
import type { ApplicationSession } from './session.js'
import { awaitOwnedTask } from './lifetime.js'
import { describeApplication } from './definition.js'
import { APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES, type ApplicationAttachmentCapability, type ApplicationAttachmentPolicy, type ApplicationEndpointBinding, type ApplicationEndpointContext, type ApplicationOwnerOptions, type ApplicationSessionOwner } from './owner-types.js'
import { APPLICATION_OWNER_PROTOCOL, type OwnerRequest } from './worker-application-protocol.js'
import type { ApplicationReadView } from './session-types.js'
import type { ContentUpload } from './content.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'
interface SignalStream { readonly iterator: AsyncIterator<EphemeralSignal>; readonly lifetime: AbortController; pending: Promise<IteratorResult<EphemeralSignal>> | null; busy: boolean }
interface Reader { readonly iterator: AsyncIterator<Uint8Array>; readonly lifetime: AbortController; busy: boolean }
interface RequestContext { readonly lifetime: AbortController; readonly signal: AbortSignal; readonly method: string; readonly control: boolean }
const isArray = (value: unknown): boolean => Array.isArray(value)
const CONTROLS = new Set(['close', 'attachment.ping', 'attachment.suspend', 'attachment.resume', 'view.release', 'content.cancel', 'signals.close', 'upload.discard'])
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
  }; walk(value, 0)
}
function checkedContext(value: ApplicationEndpointContext): ApplicationEndpointContext {
  check(value !== null && typeof value === 'object' && !Array.isArray(value) && Object.entries(value).every(([key, item]) => ['viewId', 'documentPath', 'publicationId', 'runId'].includes(key) && typeof item === 'string' && item.length > 0 && item.length <= (key === 'documentPath' ? 1024 : 128) && ![...item].some(character => character.charCodeAt(0) < 32)), 'APPLICATION_ENDPOINT_CONTEXT_INVALID')
  return structuredClone(value)
}
function limit(value: number | undefined, fallback: number, maximum: number): number { const result = value ?? fallback; check(Number.isSafeInteger(result) && result > 0 && result <= maximum, 'OWNER_CONFIGURATION_INVALID'); return result }
/** One fenced signer/storage owner, with independent bounded and cancellable client attachments. */
export function createApplicationOwner(session: ApplicationSession, options: ApplicationOwnerOptions = {}): ApplicationSessionOwner {
  const ownerInstanceId = crypto.randomUUID(), maxAttachments = limit(options.maxAttachments, 16, 64)
  const attachments = new Map<string, { binding(): ApplicationEndpointBinding; state(): 'active' | 'suspended'; close(): void }>()
  const heldViewIds = new Map<string, string>()
  let closed = false, closing: Promise<void> | undefined
  const owner: ApplicationSessionOwner = {
    ownerInstanceId, session,
    endpoints: () => [...attachments.values()].map(value => ({ ...value.binding(), state: value.state() })),
    close: () => closing ??= (async () => { closed = true; for (const attachment of [...attachments.values()]) attachment.close(); await session.close() })(),
    attach(endpoint: ApplicationWorkerEndpoint & { start?(): void }, policy: ApplicationAttachmentPolicy = {}) {
      check(!closed && attachments.size < maxAttachments, 'OWNER_ATTACHMENT_LIMIT')
      const endpointId = crypto.randomUUID(), endpointIncarnation = crypto.randomUUID(), lifetime = new AbortController()
      const views = new Map<string, ApplicationReadView>(), uploads = new Map<string, ContentUpload>(), completedUploads = new Map<string, ContentUpload>(), readers = new Map<string, Reader>(), streams = new Map<string, SignalStream>(), pending = new Map<number, RequestContext>()
      let effective = policy, attachment = '', initialized = false, detached = false, suspended = false, highestRequest = 0, viewReservations = 0, uploadReservations = 0, lastReceived = performance.now(), context: ApplicationEndpointContext = policy.context ?? {}
      let claimedViewId: string | undefined
      let stopStatus: (() => void) | undefined, stopChange: (() => void) | undefined
      const physical = endpoint as unknown as { addEventListener(type: string, listener: EventListener): void; removeEventListener(type: string, listener: EventListener): void; on?(type: string, listener: () => void): void; off?(type: string, listener: () => void): void }
      const binding = (): ApplicationEndpointBinding => ({ ownerInstanceId, endpointId, endpointIncarnation, context: structuredClone(context), evidence: 'owner-bound', contextEvidence: effective.contextEvidence ?? 'caller-asserted', capabilities: [...(effective.capabilities ?? APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES)], ...(effective.identity === undefined ? {} : { identity: structuredClone(effective.identity) }) })
      const has = (capability: ApplicationAttachmentCapability): boolean => (effective.capabilities ?? APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES).includes(capability)
      const allow = (capability: ApplicationAttachmentCapability): void => check(has(capability), 'ENDPOINT_CAPABILITY_FORBIDDEN')
      const post = (message: unknown): void => { if (!detached) endpoint.postMessage(message) }
      const releaseResources = (): void => {
        for (const view of views.values()) view.release(); views.clear()
        for (const reader of readers.values()) { reader.lifetime.abort(); void reader.iterator.return?.().catch(() => undefined) }; readers.clear()
        for (const stream of streams.values()) { stream.lifetime.abort(); void stream.iterator.return?.().catch(() => undefined) }; streams.clear()
      }
      const close = (): void => {
        if (detached) return
        try { post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'notice', topic: 'closed', value: 'ENDPOINT_CLOSED' }) } catch { /* The physical endpoint may already be gone. */ }
        detached = true; clearInterval(expiry); lifetime.abort(new Error('ENDPOINT_CLOSED'))
        for (const request of pending.values()) request.lifetime.abort(new Error('ENDPOINT_CLOSED')); pending.clear()
        endpoint.removeEventListener('message', receive); physical.removeEventListener('close', physicalClose); physical.removeEventListener('messageerror', physicalClose); physical.off?.('close', close); physical.off?.('messageerror', close)
        if (claimedViewId !== undefined && heldViewIds.get(claimedViewId) === endpointId) heldViewIds.delete(claimedViewId)
        stopStatus?.(); stopChange?.(); releaseResources(); uploads.clear(); completedUploads.clear(); attachments.delete(endpointId); endpoint.close?.()
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
          effective = { ...policy, ...options.authorize?.(handshake) }; limit(effective.maxRequests, 32, 64); limit(effective.maxViews, 8, 32)
          check(effective.capabilities === undefined || isArray(effective.capabilities) && effective.capabilities.length <= APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES.length && new Set(effective.capabilities).size === effective.capabilities.length && effective.capabilities.every(capability => APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES.includes(capability)), 'OWNER_CONFIGURATION_INVALID')
          const requested = checkedContext(effective.context ?? handshake.context ?? {})
          let viewId = requested.viewId ?? crypto.randomUUID()
          while (heldViewIds.has(viewId)) viewId = crypto.randomUUID()
          heldViewIds.set(viewId, endpointId); claimedViewId = viewId
          context = { ...requested, viewId }; initialized = true
          stopStatus = session.onStatus(value => { if (!suspended) post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'notice', topic: 'status', value }) })
          stopChange = session.onChange(value => { if (!suspended) post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'notice', topic: 'change', value }) })
          return { applicationId: session.applicationId, identity: session.identity, definition: describeApplication(session.definition), status: session.status, binding: binding() }
        }
        if (method === 'close') return null
        check(initialized, 'ENDPOINT_HANDSHAKE_REQUIRED')
        if (method === 'attachment.ping') return { ...binding(), state: suspended ? 'suspended' : 'active' }
        if (method === 'attachment.suspend') { suspended = true; for (const work of pending.values()) if (!work.control) work.lifetime.abort(new Error('ENDPOINT_SUSPENDED')); releaseResources(); return null }
        if (method === 'attachment.resume') { suspended = false; return session.status }
        // Lease/resource release and detachment remain usable under suspension and a full ordinary request quota.
        if (method === 'view.release') { const id = String(args[0]), view = views.get(id); views.delete(id); view?.release(); return null }
        if (method === 'content.cancel') { const id = String(args[0]), reader = readers.get(id); readers.delete(id); reader?.lifetime.abort(); await reader?.iterator.return?.(); return null }
        if (method === 'signals.close') { const id = String(args[0]), stream = streams.get(id); streams.delete(id); stream?.lifetime.abort(); await stream?.iterator.return?.(); return null }
        if (method === 'upload.discard') { const id = String(args[0]), upload = uploads.get(id) ?? completedUploads.get(id); uploads.delete(id); completedUploads.delete(id); await upload?.discard(); return null }
        check(!suspended, 'ENDPOINT_SUSPENDED')
        if (method === 'submit') { allow('commands'); check(effective.rawSubmit ?? effective.commands === undefined, 'ENDPOINT_RAW_SUBMIT_FORBIDDEN'); const operation = await session.submit(args[0] as Parameters<ApplicationSession['submit']>[0]); return { id: operation.id, operationId: operation.operationId } }
        if (method === 'command') { allow('commands'); const name = String(args[0]); check(effective.commands === undefined || effective.commands.includes(name), 'ENDPOINT_COMMAND_FORBIDDEN'); const input = options.prepareCommand === undefined ? args[1] : options.prepareCommand(binding(), name, args[1]); const operation = await session.command(name, input, args[2] as Parameters<ApplicationSession['command']>[2]); return { id: operation.id, operationId: operation.operationId } }
        if (method === 'query') { allow('queries'); const name = String(args[0]); check(effective.queries === undefined || effective.queries.includes(name), 'ENDPOINT_QUERY_FORBIDDEN'); return session.query(name, args[1], { signal: request.signal }) }
        if (method === 'readView') {
          check(has('queries') || has('events'), 'ENDPOINT_CAPABILITY_FORBIDDEN'); check(views.size + viewReservations < (effective.maxViews ?? 8), 'ENDPOINT_VIEW_LIMIT'); viewReservations++
          let view: ApplicationReadView | undefined, deferred = false
          const opening = session.readView(args[0] as Parameters<ApplicationSession['readView']>[0])
          try { view = await awaitOwnedTask(request.signal, () => opening); active(request); const id = crypto.randomUUID(); views.set(id, view); const result = { id, revision: view.revision }; view = undefined; return result }
          catch (error) { if (request.signal.aborted && view === undefined) { deferred = true; void opening.then(late => late.release()).catch(() => undefined).finally(() => { viewReservations-- }) }; throw error }
          finally { if (!deferred) viewReservations--; view?.release() }
        }
        if (method === 'view.query' || method === 'view.events') { const view = views.get(String(args[0])); check(view !== undefined, 'ENDPOINT_VIEW_STALE'); if (method === 'view.query') { allow('queries'); check(effective.rawSql ?? effective.queries === undefined, 'ENDPOINT_RAW_SQL_FORBIDDEN'); return view.query(String(args[1]), args[2] as Parameters<ApplicationReadView['query']>[1]) }; allow('events'); return view.readEvents(args[1] as Parameters<ApplicationReadView['readEvents']>[0]) }
        if (method === 'operation.retry') { allow('operations'); const operation = await session.operations.retry(String(args[0])); return { id: operation.id, operationId: operation.operationId } }
        if (method === 'operation.get') { allow('operations'); const operation = session.operations.get(String(args[0])); return operation === null ? null : { id: operation.id, operationId: operation.operationId, inspection: operation.inspect() } }
        if (method === 'operation.inspect') { allow('operations'); return session.inspectOperation(String(args[0])) }
        if (method === 'operation.wait') { allow('operations'); const operation = session.operations.get(String(args[0])); check(operation !== null, 'OPERATION_UNKNOWN'); const fact = args[1]; check(fact === 'materialized' || fact === 'retained' || fact === 'finalized', 'OPERATION_FACT_INVALID'); return operation[fact]({ signal: request.signal, timeoutMs: Number(args[2] ?? 30_000) }) }
        if (method === 'diagnostics.peers') { allow('diagnostics'); return session.diagnostics() }
        if (method === 'authority.read') { allow('diagnostics'); return session.authority.bundle() }
        if (method === 'endpoints.list') { allow('diagnostics'); return owner.endpoints() }
        if (method === 'authority.merge') { allow('diagnostics'); return session.mergeAuthority(args[0] as AuthorityBundle) }
        // Authenticated operation-set exchange for an owner-chosen out-of-band replica (for example a blind
        // envelope relay). Merged envelopes are verified against current authority exactly as peer facts are.
        if (method === 'facts.export') { allow('replication'); return session.exportFacts() }
        if (method === 'facts.merge') { allow('replication'); return session.mergeFacts(args[0] as Parameters<ApplicationSession['mergeFacts']>[0]) }
        if (method === 'finality.closeAuthorTime') { allow('finality'); return session.finality.closeAuthorTime(args[0] as { throughMs: bigint }) }
        if (method === 'finality.voteAuthorTime') { allow('finality'); return session.finality.voteAuthorTime(args[0] as { throughMs: bigint }) }
        if (method === 'finality.submitProofs') { allow('finality'); return session.finality.submitProofs(args[0] as readonly FinalityProof[]) }
        if (method === 'provisioning.createProvisioningRequest') { allow('provisioning'); return session.provisioning.createProvisioningRequest() }
        if (method === 'provisioning.exportProvisioning') { allow('provisioning'); return session.provisioning.exportProvisioning(args[0] as Parameters<ApplicationSession['provisioning']['exportProvisioning']>[0]) }
        if (method === 'provisioning.importProvisioning') { allow('provisioning'); return session.provisioning.importProvisioning(args[0] as Parameters<ApplicationSession['provisioning']['importProvisioning']>[0]) }
        if (['content.retain', 'content.retention', 'content.retained', 'content.discard'].includes(method)) { allow('content'); const reference = args[0] as Parameters<ApplicationSession['content']['retain']>[0]; if (method === 'content.retain') return session.content.retain(reference, { signal: request.signal }); if (method === 'content.retention') return session.content.retention(reference, { signal: request.signal }); if (method === 'content.retained') return session.content.retained(reference); return session.content.discard(reference) }
        if (method === 'content.stage') { allow('content'); check(uploads.size + uploadReservations < 4, 'ENDPOINT_UPLOAD_LIMIT'); uploadReservations++; let upload: ContentUpload | undefined; try { upload = await session.content.stage(args[0] as Parameters<ApplicationSession['content']['stage']>[0]); active(request); uploads.set(upload.id, upload); const id = upload.id; upload = undefined; return id } finally { uploadReservations--; if (upload !== undefined) await upload.discard() } }
        if (['upload.write', 'upload.progress', 'upload.commit'].includes(method)) {
          allow('content'); const id = String(args[0]), upload = uploads.get(id) ?? completedUploads.get(id); check(upload !== undefined, 'CONTENT_UPLOAD_UNKNOWN')
          if (method === 'upload.write') { check(args[2] instanceof Uint8Array && args[2].length <= 65536, 'CONTENT_CHUNK_LIMIT'); return upload.write(Number(args[1]), args[2]) }
          if (method === 'upload.progress') return upload.progress()
          const reference = await upload.commit(); uploads.delete(id); completedUploads.set(id, upload); while (completedUploads.size > 32) completedUploads.delete(completedUploads.keys().next().value!); return reference
        }
        if (method === 'content.openRead') { allow('content'); check(readers.size < 4, 'ENDPOINT_READER_LIMIT'); const id = crypto.randomUUID(), owned = new AbortController(), iterator = session.content.read(args[0] as Parameters<ApplicationSession['content']['read']>[0], { signal: AbortSignal.any([owned.signal, lifetime.signal]) })[Symbol.asyncIterator](); readers.set(id, { iterator, lifetime: owned, busy: false }); return id }
        if (method === 'content.next') { allow('content'); const id = String(args[0]), reader = readers.get(id); check(reader !== undefined && !reader.busy, 'CONTENT_READER_UNKNOWN'); reader.busy = true; const abort = (): void => { reader.lifetime.abort(); readers.delete(id) }; request.signal.addEventListener('abort', abort, { once: true }); try { const next = await reader.iterator.next(); active(request); if (next.done) { readers.delete(id); return null }; check(next.value.length <= 65536, 'CONTENT_CHUNK_LIMIT'); return next.value } finally { request.signal.removeEventListener('abort', abort); reader.busy = false } }
        if (method === 'signals.send') { allow('signals'); const supplied = (args[2] ?? {}) as Omit<SignalSendOptions, 'signal'>; return session.signals.send(String(args[0]), args[1] as SignalPayload, { ...supplied, signal: request.signal, stream: { ...supplied.stream, streamId: supplied.stream?.streamId ?? endpointId, endpointId, endpointIncarnation } }) }
        if (method === 'signals.open') { allow('signals'); check(streams.size < 4, 'ENDPOINT_STREAM_LIMIT'); const id = crypto.randomUUID(), owned = new AbortController(), iterator = session.signals.subscribe({ ...(args[0] ?? {}) as SignalSubscribeOptions, signal: AbortSignal.any([owned.signal, lifetime.signal]) })[Symbol.asyncIterator](); streams.set(id, { iterator, lifetime: owned, pending: null, busy: false }); return id }
        if (method === 'signals.next') {
          allow('signals'); const stream = streams.get(String(args[0])); check(stream !== undefined && !stream.busy, 'ENDPOINT_STREAM_BUSY'); stream.busy = true
          let timer: ReturnType<typeof setTimeout> | undefined
          const abort = (): void => { stream.lifetime.abort(); streams.delete(String(args[0])) }; request.signal.addEventListener('abort', abort, { once: true })
          try { stream.pending ??= stream.iterator.next(); void stream.pending.catch(() => undefined); const idle = Symbol('idle'), next = await Promise.race([stream.pending, new Promise<typeof idle>(resolve => { timer = setTimeout(() => resolve(idle), 20_000) })]); active(request); if (next === idle) return { idle: true }; stream.pending = null; return next.done ? { done: true } : { value: next.value } }
          finally { clearTimeout(timer); request.signal.removeEventListener('abort', abort); stream.busy = false }
        }
        if (method === 'events.read') { allow('events'); return session.readEvents(args[0] as Parameters<ApplicationSession['readEvents']>[0]) }
        throw Object.assign(new Error('ENDPOINT_METHOD_UNKNOWN'), { code: 'ENDPOINT_METHOD_UNKNOWN' })
      }
      const receive = (event: MessageEvent): void => {
        const input = event.data as Partial<OwnerRequest> & { readonly kind?: string }
        if (input?.protocol !== APPLICATION_OWNER_PROTOCOL || detached || typeof input.attachment !== 'string') return
        if (attachment !== '' && input.attachment !== attachment) return
        if ((input.kind as string) === 'cancel') { if (Number.isSafeInteger(input.id)) pending.get(input.id!)?.lifetime.abort(new Error('REQUEST_CANCELLED')); return }
        if (input.kind !== 'request') return
        if (input.attachment.length > 128 || !Number.isSafeInteger(input.id) || input.id! < 1 || typeof input.method !== 'string' || !Array.isArray(input.args)) { close(); return }
        if (attachment === '') attachment = input.attachment
        const id = input.id!; if (id <= highestRequest) return; highestRequest = id; lastReceived = performance.now()
        const reply = (value: unknown, error?: string): void => { try { post({ protocol: APPLICATION_OWNER_PROTOCOL, attachment, kind: 'response', id, ...(error === undefined ? { value } : { error }) }) } catch { close() } }
        try { requestBudget(input.args) } catch { reply(null, 'ENDPOINT_REQUEST_SIZE_LIMIT'); return }
        const control = CONTROLS.has(input.method)
        if ((!control && [...pending.values()].filter(request => !request.control).length >= (effective.maxRequests ?? 32)) || control && [...pending.values()].filter(request => request.control).length >= 8) { reply(null, 'ENDPOINT_REQUEST_LIMIT'); return }
        const owned = new AbortController(), request: RequestContext = { lifetime: owned, signal: AbortSignal.any([lifetime.signal, owned.signal]), method: input.method, control }; pending.set(id, request)
        const timer = setTimeout(() => owned.abort(new Error('ENDPOINT_REQUEST_TIMEOUT')), 120_000)
        void invoke(input.method, input.args, request).then(value => { if (!request.signal.aborted) reply(value); if (input.method === 'close') close() }, (error: unknown) => { if (!request.signal.aborted) reply(null, error instanceof Error ? error.message : 'ENDPOINT_REQUEST_FAILED') }).finally(() => { clearTimeout(timer); pending.delete(id) })
      }
      const expiry = setInterval(() => { if (!suspended && performance.now() - lastReceived > 90_000) close() }, 10_000); expiry.unref?.()
      endpoint.addEventListener('message', receive); physical.addEventListener('close', physicalClose); physical.addEventListener('messageerror', physicalClose); physical.on?.('close', close); physical.on?.('messageerror', close); endpoint.start?.()
      attachments.set(endpointId, { binding, state: () => suspended ? 'suspended' : 'active', close }); return close
    },
  }
  return owner
}

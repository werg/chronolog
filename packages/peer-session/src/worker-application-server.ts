import type { AuthorityBundle } from '@chronolog/peer-generation/control'
import type { RecoveryNotice } from '@chronolog/peer-generation'
import type { ApplicationParticipation, ApplicationParticipationStatus } from './participation-types.js'
import type { SignalPayload, SignalSendOptions, SignalSubscribeOptions } from '@chronolog/signals'
import type { ApplicationSession } from './session.js'
import type { ApplicationEventOptions, ApplicationReadView, CommandOptions, QueryParameter, SessionStatus } from './session-types.js'
import type { ContentReference } from './content.js'
import type { ApplicationControlHost, ApplicationRecoveryExpectation } from './recovery.js'
import { AbandonedOperationError, RecoveredViewError } from './errors.js'
import { APPLICATION_PROJECTION_LIMITS, type ApplicationProjectionHandle } from './projection-types.js'
import { PROTOCOL, MAX_REQUESTS, MAX_RELEASES, MAX_STREAMS, releasesResource, bounded,
  type Endpoint, type Metadata, type Snapshot, type WireError, type Request, type Response } from './worker-application-protocol.js'

interface Stream { readonly iterator: AsyncIterator<unknown>; readonly controller: AbortController; busy: boolean }

/**
 * Serve one page facade beside the owned application. A dedicated port isolates
 * application RPC from RTC handoff and application-owned UI messages. The same
 * pull/cancel contract keeps streams bounded within that one owner.
 */
export function serveApplicationWorker(session: ApplicationSession, endpoint: Endpoint, options: {
  readonly host?: ApplicationControlHost
} = {}): { close(): Promise<void> } {
  let port: MessagePort | undefined, closed = false, lastId = 0, nextView = 0, nextProjection = 0
  let closing: Promise<void> | undefined
  const calls = new Map<number, { readonly controller: AbortController; readonly release: boolean }>(), streams = new Map<number, Stream>()
  const views = new Map<number, { readonly handle: ApplicationReadView; readonly requestId: number }>()
  const projections = new Map<number, ApplicationProjectionHandle>()
  const send = (value: unknown): void => { bounded(value); port?.postMessage(value) }
  const respond = (id: number, value: unknown): void => { send({ id, value, snapshot: snapshot(session) } satisfies Response) }
  const cancelStream = async (id: number): Promise<void> => {
    const stream = streams.get(id)
    if (stream === undefined) return
    streams.delete(id); stream.controller.abort(new Error('APPLICATION_WORKER_CANCELLED'))
    await stream.iterator.return?.().catch(() => undefined)
  }
  const stop = (reason: unknown): Promise<void> => {
    if (closing !== undefined) return closing
    closed = true
    endpoint.removeEventListener('message', connect)
    session.signal.removeEventListener('abort', aborted)
    for (const call of calls.values()) call.controller.abort(reason)
    for (const view of views.values()) view.handle.release()
    views.clear(); projections.clear()
    port?.removeEventListener('message', receive); port?.removeEventListener('messageerror', messageError)
    closing = Promise.allSettled([...streams.keys()].map(cancelStream)).then(async () => {
      try { await session.close() }
      finally {
        // A page can reopen the device immediately after close resolves: send
        // the terminal observation only after the owning store released its lock.
        try { send({ ended: errorValue(reason) }) } catch { /* An unavailable page cannot keep the Worker alive. */ }
        port?.close()
      }
    })
    return closing
  }
  const aborted = (): void => { void stop(session.signal.reason).catch(() => undefined) }
  const messageError = (): void => { void stop(new Error('APPLICATION_WORKER_MESSAGE_INVALID')).catch(() => undefined) }
  const controlHost = (): ApplicationControlHost => {
    if (options.host === undefined) throw new Error('APPLICATION_CONTROL_HOST_UNAVAILABLE')
    return options.host
  }
  const participation = (): ApplicationParticipation => {
    if (session.participation === undefined) throw new Error('APPLICATION_PARTICIPATION_UNAVAILABLE')
    return session.participation
  }
  const view = (id: unknown): ApplicationReadView => {
    const result = typeof id === 'number' ? views.get(id) : undefined
    if (result === undefined) throw new Error('APPLICATION_VIEW_RELEASED')
    return result.handle
  }
  const captureProjection = (name: string): number => {
    const current = session.projection(name)
    for (const [id, handle] of projections) {
      try { if (session.projection(handle.id) !== handle) projections.delete(id) }
      catch { projections.delete(id) }
      if (handle === current) return id
    }
    if (projections.size >= APPLICATION_PROJECTION_LIMITS.active) throw new Error('APPLICATION_PROJECTION_LIMIT')
    const id = ++nextProjection
    if (!Number.isSafeInteger(id)) throw new Error('APPLICATION_WORKER_REQUEST_ID_EXHAUSTED')
    projections.set(id, current); return id
  }
  const projection = (id: unknown): ApplicationProjectionHandle => {
    const handle = typeof id === 'number' ? projections.get(id) : undefined
    if (handle === undefined) throw new Error('APPLICATION_PROJECTION_CLOSED')
    return handle
  }
  const invoke = async (method: string, args: readonly unknown[], signal: AbortSignal, requestId: number): Promise<unknown> => {
    switch (method) {
      case 'command': return (await session.command(args[0] as string, args[1] as never, args[2] as CommandOptions)).operationId
      case 'reapply': return (await session.reapply(args[0] as string, args[1] as string, args[2] as never, args[3] as CommandOptions)).operationId
      case 'query': return session.query(args[0] as string, args[1] as never)
      case 'operation.get': return session.operations.get(args[0] as string, args[1] as { author?: string })
      case 'operation.inspect': return session.operations.inspect(args[0] as string, args[1] as { author?: string })
      case 'operation.wait': return session.operations.wait(args[0] as string, { ...args[1] as { author?: string }, signal })
      case 'operation.shared': return session.waitForCoverage(await session.operations.wait(args[0] as string, { signal }), { signal })
      case 'retry': return session.retry(args[0] as string)
      case 'resume': return session.resume()
      case 'inspectRecovery': return session.inspectRecovery()
      case 'recoveryPoint': return session.recoveryPoint()
      case 'adopt': return session.adopt(args[0] as AuthorityBundle)
      case 'recovery.inspect': return session.recovery.inspect()
      case 'recovery.takeover': return session.recovery.takeover(controlHost(), { ...args[0] as { coordinator?: string; transitionId?: string; expected?: ApplicationRecoveryExpectation }, signal })
      case 'recovery.handover': return session.recovery.handover(controlHost(), { ...args[0] as { coordinator: string; transitionId?: string }, signal })
      case 'participation.approve': return participation().approveRecovery(args[0] as string)
      case 'participation.close': return participation().close()
      case 'signals.send': return session.signals.send(args[0] as string, args[1] as SignalPayload, { ...args[2] as SignalSendOptions, signal })
      case 'view.open': {
        const captured = await session.readView()
        if (signal.aborted) { captured.release(); signal.throwIfAborted() }
        const id = ++nextView; views.set(id, { handle: captured, requestId })
        return { id, revision: captured.revision }
      }
      case 'view.query': return view(args[0]).query(args[1] as string, args[2] as readonly QueryParameter[])
      case 'view.events': return view(args[0]).readEvents(args[1] as ApplicationEventOptions)
      case 'view.release': { const captured = views.get(args[0] as number); views.delete(args[0] as number); captured?.handle.release(); return null }
      case 'projection.open': return captureProjection(args[0] as string)
      case 'projection.read': return projection(args[0]).read({ signal })
      case 'projection.close': {
        const id = args[0] as number, captured = projections.get(id)
        await captured?.close(); projections.delete(id); return null
      }
      case 'content.stage': return (await session.content.stage(args[0] as { bytes: number; mediaType?: string })).id
      case 'content.resume': return (await session.content.resume(args[0] as string)).id
      case 'content.write': return (await session.content.resume(args[0] as string)).write(args[1] as number, args[2] as Uint8Array)
      case 'content.progress': return (await session.content.resume(args[0] as string)).progress()
      case 'content.commit': return (await session.content.resume(args[0] as string)).commit()
      case 'content.retain': return session.content.retain(args[0] as ContentReference, { signal })
      case 'content.retained': return session.content.retained(args[0] as ContentReference)
      case 'content.retention': return session.content.retention(args[0] as ContentReference)
      default: throw new Error('APPLICATION_WORKER_METHOD_UNKNOWN')
    }
  }
  const openStream = (name: unknown, args: readonly unknown[], signal: AbortSignal): AsyncIterator<unknown> => {
    switch (name) {
      case 'changes': return session.changes({ signal })[Symbol.asyncIterator]()
      case 'signals': return session.signals.subscribe({ ...args[0] as SignalSubscribeOptions, signal })[Symbol.asyncIterator]()
      case 'status': return observe<SessionStatus>(listener => session.onStatus(listener), signal)
      case 'participation': return observe<ApplicationParticipationStatus>(listener => participation().onStatus(listener), signal)
      case 'recovery': return observe<RecoveryNotice>(listener => session.onRecovery(listener), signal)
      case 'content': return session.content.read(args[0] as ContentReference, { ...args[1] as { offset?: number; length?: number }, signal })[Symbol.asyncIterator]()
      case 'projection': {
        const captured = projections.get(args[0] as number)
        return captured?.changes({ signal })[Symbol.asyncIterator]() ?? { next: async () => ({ done: true, value: undefined }) }
      }
      default: throw new Error('APPLICATION_WORKER_STREAM_UNKNOWN')
    }
  }
  const handle = async (request: Request): Promise<void> => {
    if (closed) throw new Error('APPLICATION_SESSION_CLOSED')
    // Shutdown must remain available when every ordinary request slot is
    // occupied by a passive operation or stream waiter.
    if (request.method === 'close') { await stop(new Error('APPLICATION_SESSION_CLOSED')); return }
    // Bounded cleanup capacity cannot be consumed by passive application waits.
    const release = releasesResource(request.method)
    if ([...calls.values()].filter(call => call.release === release).length >= (release ? MAX_RELEASES : MAX_REQUESTS)) throw new Error('APPLICATION_WORKER_REQUEST_LIMIT')
    const controller = new AbortController(); calls.set(request.id, { controller, release })
    try {
      let result: unknown
      if (request.method === 'stream.open') {
        if (streams.size >= MAX_STREAMS) throw new Error('APPLICATION_WORKER_STREAM_LIMIT')
        const iterator = openStream(request.args[0], request.args.slice(1), controller.signal)
        streams.set(request.id, { iterator, controller, busy: false }); result = request.id
      } else if (request.method === 'stream.next') {
        const stream = streams.get(request.args[0] as number)
        if (stream === undefined) throw new Error('APPLICATION_WORKER_STREAM_CLOSED')
        if (stream.busy) throw new Error('APPLICATION_WORKER_STREAM_BUSY')
        stream.busy = true
        try { result = await stream.iterator.next() }
        finally { stream.busy = false }
        if ((result as IteratorResult<unknown>).done) await cancelStream(request.args[0] as number)
      } else result = await invoke(request.method, request.args, controller.signal, request.id)
      if (!closed && !controller.signal.aborted) respond(request.id, result)
    } finally { calls.delete(request.id) }
  }
  const receive = (event: MessageEvent): void => {
    const input = event.data as Partial<Request> & { cancel?: unknown }
    try {
      bounded(input)
      if (input?.cancel !== undefined) {
        if (!Number.isSafeInteger(input.cancel)) throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
        calls.get(input.cancel as number)?.controller.abort(new Error('APPLICATION_WORKER_CANCELLED'))
        void cancelStream(input.cancel as number)
        // A captured view can outlive the request that created it. If its reply
        // crossed a cancelled page waiter, that request still owns its disposal.
        for (const [id, captured] of views) {
          if (captured.requestId === input.cancel) { views.delete(id); captured.handle.release() }
        }
        return
      }
      if (!input || !Number.isSafeInteger(input.id) || input.id! <= lastId || typeof input.method !== 'string' || !Array.isArray(input.args)) {
        throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      }
      lastId = input.id!
      void handle(input as Request).catch((error: unknown) => {
        if (!closed) {
          try { send({ id: input.id!, error: errorValue(error), snapshot: snapshot(session) } satisfies Response) }
          catch { void stop(error).catch(() => undefined) }
        }
      })
    } catch (error) { void stop(error).catch(() => undefined) }
  }
  const connect = (event: MessageEvent): void => {
    const input = event.data as { protocol?: unknown; port?: MessagePort } | null
    if (input?.protocol !== PROTOCOL || !input.port || typeof input.port.postMessage !== 'function') return
    if (closed || port !== undefined) {
      input.port.postMessage({ ended: errorValue(new Error(closed ? 'APPLICATION_SESSION_CLOSED' : 'APPLICATION_WORKER_CLIENT_IN_USE')) })
      input.port.close(); return
    }
    port = input.port
    port.addEventListener('message', receive); port.addEventListener('messageerror', messageError); port.start()
    try { send({ ready: { ...snapshot(session), protocol: PROTOCOL, applicationId: session.applicationId, historyId: session.historyId,
      deviceId: session.deviceId, storageId: session.storageId, description: session.describe() } satisfies Metadata }) }
    catch (error) { void stop(error).catch(() => undefined) }
  }
  endpoint.addEventListener('message', connect); endpoint.start?.()
  session.signal.addEventListener('abort', aborted, { once: true })
  if (session.signal.aborted) aborted()
  return { close: () => stop(new Error('APPLICATION_SESSION_CLOSED')) }
}

function snapshot(session: ApplicationSession): Snapshot {
  return { status: session.status, revision: session.revision, participation: session.participation?.status ?? null }
}
function errorValue(error: unknown): WireError {
  if (!(error instanceof Error)) return { name: 'Error', message: String(error) }
  return { name: error.name, message: error.message,
    ...('code' in error && typeof error.code === 'string' ? { code: error.code } : {}),
    ...(error instanceof AbandonedOperationError ? { operation: error.operation } : {}),
    ...(error instanceof RecoveredViewError ? { revision: error.revision } : {}) }
}
/** One coalesced callback value, independent of how long a page stops pulling. */
function observe<T>(subscribe: (listener: (value: T) => void) => () => void, signal: AbortSignal): AsyncIterator<T> {
  let pending: T | undefined, hasValue = false, closed = false, wake: (() => void) | undefined
  const unsubscribe = subscribe(value => { pending = value; hasValue = true; wake?.(); wake = undefined })
  const close = (): void => { if (closed) return; closed = true; unsubscribe(); signal.removeEventListener('abort', close); wake?.(); wake = undefined }
  signal.addEventListener('abort', close, { once: true }); if (signal.aborted) close()
  return {
    async next() {
      while (!hasValue && !closed) await new Promise<void>(resolve => { wake = resolve })
      signal.throwIfAborted()
      if (closed) return { done: true, value: undefined }
      const value = pending!; pending = undefined; hasValue = false
      return { done: false, value }
    },
    async return() { close(); return { done: true, value: undefined } },
  }
}

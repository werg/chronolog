import {
  validateHistoryPoint, verifyAuthorityBundle, type AuthorityBundle, type OrderedCommand, type PeerReplica,
  type PeerRevision, type SignedAttempt, type SignedRetainedCoverage,
} from '@chronolog/peer-generation'
import { bytesToHex, encodeCanonicalCbor, hexToBytes, importEd25519PublicKey } from '@chronolog/protocol'
import type { FramedPeerConnection } from '@chronolog/records'

import type { ApplicationSession } from './session.js'
import { sessionInternals } from './internals.js'
import type { ContentManifest, ContentReference, ContentRetention } from './content.js'

const MAX_MESSAGE_BYTES = 1_048_576, MAX_REQUESTS = 16, MAX_RANGE_RECORDS = 32
const HANDSHAKE_DOMAIN = 'chronolog/peer-generation/connection/v1'
interface Hello { readonly type: 'hello'; readonly applicationId: string; readonly historyId: string; readonly peer: string; readonly nonce: string }
interface RemoteState { readonly authority: AuthorityBundle; readonly revision: PeerRevision | null; readonly count: number }
interface Pending { readonly resolve: (value: unknown) => void; readonly reject: (error: unknown) => void; readonly timer: ReturnType<typeof setTimeout> }
interface Synchronization { readonly promise: Promise<void>; readonly resolve: () => void; readonly reject: (error: unknown) => void; background: boolean }
export interface ApplicationPeerConnection {
  readonly peerId: string
  readonly signal: AbortSignal
  readonly stats: { readonly sentBytes: number; readonly receivedBytes: number; readonly sentRequests: number; readonly receivedRequests: number }
  /** Pulls one captured complete history and acknowledges only after durable retention. */
  synchronize(): Promise<void>
  close(): Promise<void>
}

/**
 * Authenticates both endpoints and owns request IDs, exact-command retries, range
 * transfer and cleanup over one bounded reliable lane. Live signals stay on the
 * optional independent disposable lane. No hosted endpoint participates here.
 */
export async function connectApplicationTransport(session: ApplicationSession, options: {
  readonly connection: FramedPeerConnection
  readonly expectedPeerId?: string
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
}): Promise<ApplicationPeerConnection> {
  const owned = sessionInternals.get(session)
  if (owned === undefined) throw new Error('APPLICATION_SESSION_INVALID')
  const replica = owned.replica, connection = options.connection, timeoutMs = options.timeoutMs ?? 15_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) throw new Error('APPLICATION_PEER_TIMEOUT_INVALID')
  const lifetime = new AbortController()
  const inputSignal = AbortSignal.any([connection.signal, session.signal, ...(options.signal === undefined ? [] : [options.signal])])
  const local: Hello = { type: 'hello', applicationId: replica.descriptor.applicationId, historyId: replica.descriptor.historyId,
    peer: replica.device.publicKey, nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(32))) }
  const requests = new Map<number, Pending>()
  let remote: Hello | undefined, authenticated = false, sequence = 0, serving = 0, closed = false
  let sentBytes = 0, receivedBytes = 0, sentRequests = 0, receivedRequests = 0
  let detach = () => {}, unsubscribe = () => {}, disposeLive = () => {}, signalRoute: ReturnType<typeof owned.signals.attachRoute> | undefined
  let detachContent = () => {}
  let resolveReady!: () => void, rejectReady!: (error: unknown) => void
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  void ready.catch(() => undefined)
  let closing: Promise<void> | undefined
  const close = (reason: unknown = new Error('APPLICATION_PEER_DISCONNECTED')): Promise<void> => {
    if (closing !== undefined) return closing
    closing = Promise.resolve().then(() => connection.close())
    closed = true; lifetime.abort(reason); clearTimeout(handshakeTimer); inputSignal.removeEventListener('abort', abort)
    rejectReady(reason); detach(); unsubscribe(); disposeLive(); signalRoute?.close(); detachContent()
    for (const pending of requests.values()) { clearTimeout(pending.timer); pending.reject(reason) }
    requests.clear()
    void closing.catch(() => undefined)
    return closing
  }
  const abort = (): void => { void close(inputSignal.reason) }
  const handshakeTimer = setTimeout(() => { void close(new Error('APPLICATION_PEER_AUTH_TIMEOUT')) }, timeoutMs)
  inputSignal.addEventListener('abort', abort, { once: true })
  if (inputSignal.aborted) abort()
  const open = (): void => { lifetime.signal.throwIfAborted() }
  const authorized = (): void => {
    open()
    if (!authenticated || remote === undefined || !reader(replica, remote.peer)) throw new Error('APPLICATION_PEER_NOT_AUTHORIZED')
  }
  const send = async (value: unknown): Promise<void> => {
    open()
    const bytes = encode(value)
    if (bytes.length > MAX_MESSAGE_BYTES) throw new Error('APPLICATION_PEER_FRAME_TOO_LARGE')
    await connection.send(bytes, { signal: lifetime.signal }); open(); sentBytes += bytes.length
  }
  const request = async <T>(method: string, value: unknown = null): Promise<T> => {
    authorized()
    if (requests.size >= MAX_REQUESTS) throw new Error('APPLICATION_PEER_REQUEST_LIMIT')
    const id = ++sequence
    sentRequests++
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => { void close(new Error('APPLICATION_PEER_REQUEST_TIMEOUT')) }, timeoutMs)
      requests.set(id, { resolve: value => resolve(value as T), reject, timer })
      void send({ type: 'request', id, method, value }).catch(error => { void close(error) })
    })
  }

  const pull = async (): Promise<void> => {
    authorized()
    const remoteState = await request<RemoteState>('state')
    authorized()
    if (!Number.isSafeInteger(remoteState.count) || remoteState.count < 0) throw new Error('APPLICATION_PEER_STATE_INVALID')
    const authority = await verifyAuthorityBundle(remoteState.authority, replica.authority.descriptor)
    authorized()
    const remoteGeneration = authority.current
    if (remoteGeneration === null) throw new Error('APPLICATION_PEER_GENERATION_MISSING')
    if (remoteState.revision === null) {
      if (remoteState.count !== 0) throw new Error('APPLICATION_PEER_STATE_INVALID')
      return
    }
    if (remoteGeneration.payload.number < replica.generation.payload.number) return
    const target = remoteState.revision
    validateHistoryPoint(target.point)
    const count = authority.selectedSegments().reduce((total, segment) => total + (segment.cutoff?.sequence ?? target.point.sequence), 0)
    if (target.generation !== remoteGeneration.id || target.point.generation !== remoteGeneration.id ||
        target.controlRevision !== remoteGeneration.payload.controlRevision || target.applicationId !== replica.descriptor.applicationId ||
        target.historyId !== replica.descriptor.historyId || !Number.isSafeInteger(count) || count !== remoteState.count) {
      throw new Error('APPLICATION_PEER_STATE_INVALID')
    }
    let offset = 0
    try {
      const view = await replica.capture()
      try { if (view.revision.generation === target.generation) offset = Math.min(view.read.orderLength, count) }
      finally { view.release() }
    } catch (error) { if (!(error instanceof Error) || error.message !== 'PEER_RECOVERING') throw error }
    async function* pages(): AsyncGenerator<readonly OrderedCommand[]> {
      while (offset < count) {
        authorized()
        const limit = Math.min(MAX_RANGE_RECORDS, count - offset)
        const page = await request<readonly OrderedCommand[]>('range', { at: target, offset, limit })
        authorized()
        if (!Array.isArray(page) || page.length < 1 || page.length > limit) throw new Error('APPLICATION_PEER_HISTORY_INCOMPLETE')
        offset += page.length
        yield page
      }
      authorized()
    }
    // The replica retains one bounded page at a time, then checks the captured
    // root before publication. New source writes cannot extend this pass.
    await replica.synchronize(remoteState.authority, pages(), { at: target })
    authorized()
    const coverage = await replica.retainedCoverage(target.point)
    authorized()
    if (coverage.payload.generation !== target.generation) throw new Error('PEER_VIEW_RECOVERY_REQUIRED')
    await request('retain', coverage)
  }
  let running: Synchronization | undefined, queued: Synchronization | undefined
  const start = (job: Synchronization): void => {
    running = job
    const finish = (): void => {
      running = undefined
      if (queued !== undefined) { const next = queued; queued = undefined; start(next) }
    }
    void pull().then(() => { job.resolve(); finish() }, error => {
      job.reject(error)
      if (job.background) void close(error)
      finish()
    })
  }
  const schedule = (background: boolean): Promise<void> => {
    authorized()
    if (queued !== undefined) { queued.background ||= background; return queued.promise }
    let resolve!: () => void, reject!: (error: unknown) => void
    const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no })
    void promise.catch(() => undefined)
    const job = { promise, resolve, reject, background }
    // One active captured pass and one coalesced follow-up keep hint floods
    // bounded. A caller awaits only its own pass, never future source growth.
    if (running === undefined) start(job)
    else queued = job
    return promise
  }
  const synchronize = (): Promise<void> => schedule(false)
  const notify = (): void => { void send({ type: 'changed' }).catch(error => { void close(error) }) }
  const serve = async (id: number, method: string, value: unknown): Promise<void> => {
    try {
      authorized()
      let result: unknown
      switch (method) {
        case 'state': {
          let view
          try { view = await replica.capture() }
          catch (error) { if (!(error instanceof Error) || error.message !== 'PEER_RECOVERING') throw error }
          result = { authority: view?.authority ?? replica.authority, revision: view?.revision ?? null, count: view?.read.orderLength ?? 0 }
          view?.release()
          break
        }
        case 'range': {
          const input = record(value)
          if (!Number.isSafeInteger(input.offset) || Number(input.offset) < 0 || !Number.isSafeInteger(input.limit) ||
              Number(input.limit) < 1 || Number(input.limit) > MAX_RANGE_RECORDS) throw new Error('APPLICATION_PEER_RANGE_INVALID')
          const commands = await replica.exportCommands({ at: input.at as PeerRevision, offset: Number(input.offset), limit: Number(input.limit) })
          const page: OrderedCommand[] = []
          for (const command of commands) {
            page.push(command)
            if (encode({ type: 'response', id, result: page }).length > MAX_MESSAGE_BYTES) { page.pop(); break }
          }
          if (commands.length > 0 && page.length === 0) throw new Error('APPLICATION_PEER_FRAME_TOO_LARGE')
          result = page
          break
        }
        case 'submit': result = await replica.order(value as SignedAttempt); break
        case 'retain': await replica.observeCoverage(value as SignedRetainedCoverage); result = null; break
        case 'contentManifest': result = await owned.content.serveManifest(remote!.peer, value as ContentReference); break
        case 'contentChunk': {
          const input = record(value)
          if (!Number.isSafeInteger(input.index)) throw new Error('APPLICATION_CONTENT_CHUNK_INVALID')
          const bytes = await owned.content.serveChunk(remote!.peer, input.reference as ContentReference, Number(input.index))
          result = bytes === null ? null : bytesToHex(bytes)
          break
        }
        case 'contentRetained': result = await owned.content.retained(value as ContentReference); break
        case 'contentObserveRetention': await owned.content.observeRetention(value as ContentRetention); result = null; break
        default: throw new Error('APPLICATION_PEER_METHOD_UNKNOWN')
      }
      authorized()
      await send({ type: 'response', id, result })
    } catch (error) {
      if (!closed) {
        const code = error instanceof Error && /^[A-Z][A-Z0-9_]{0,127}$/u.test(error.message) ? error.message : 'APPLICATION_PEER_REQUEST_FAILED'
        await send({ type: 'response', id, error: code }).catch(failure => { void close(failure) })
      }
    } finally { serving-- }
  }
  const read = (async () => {
    try {
      for await (const frame of connection.frames(lifetime.signal)) {
        open()
        if (frame.length > MAX_MESSAGE_BYTES) throw new Error('APPLICATION_PEER_FRAME_TOO_LARGE')
        receivedBytes += frame.length
        const value = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(frame)))
        if (value.type === 'hello') {
          if (remote !== undefined || value.applicationId !== local.applicationId || value.historyId !== local.historyId ||
              typeof value.peer !== 'string' || !/^[0-9a-f]{64}$/u.test(value.peer) || value.peer === local.peer ||
              options.expectedPeerId !== undefined && value.peer !== options.expectedPeerId ||
              typeof value.nonce !== 'string' || !/^[0-9a-f]{64}$/u.test(value.nonce) || !reader(replica, value.peer)) throw new Error('APPLICATION_PEER_HELLO_INVALID')
          remote = value as unknown as Hello
          const proof = await crypto.subtle.sign('Ed25519', replica.device.privateKey, transcript(local, remote))
          open()
          // Read independently from writes: a stream can apply backpressure until
          // its remote reader advances to the authentication frame.
          void send({ type: 'authenticate', signature: bytesToHex(new Uint8Array(proof)) }).catch(error => { void close(error) })
          continue
        }
        if (value.type === 'authenticate') {
          if (authenticated || remote === undefined || typeof value.signature !== 'string' || !/^[0-9a-f]{128}$/u.test(value.signature)) throw new Error('APPLICATION_PEER_AUTH_INVALID')
          const verified = await crypto.subtle.verify('Ed25519', await importEd25519PublicKey(hexToBytes(remote.peer)),
            new Uint8Array(hexToBytes(value.signature)), transcript(remote, local))
          open()
          if (!verified || !reader(replica, remote.peer)) throw new Error('APPLICATION_PEER_AUTH_INVALID')
          authenticated = true; clearTimeout(handshakeTimer); resolveReady(); continue
        }
        authorized()
        if (value.type === 'response') {
          if (!Number.isSafeInteger(value.id)) throw new Error('APPLICATION_PEER_RESPONSE_INVALID')
          const pending = requests.get(Number(value.id))
          if (pending === undefined) throw new Error('APPLICATION_PEER_RESPONSE_UNKNOWN')
          requests.delete(Number(value.id)); clearTimeout(pending.timer)
          if (typeof value.error === 'string') pending.reject(new Error(value.error))
          else pending.resolve(value.result)
        } else if (value.type === 'request') {
          if (!Number.isSafeInteger(value.id) || Number(value.id) < 1 || typeof value.method !== 'string' || serving >= MAX_REQUESTS) throw new Error('APPLICATION_PEER_REQUEST_INVALID')
          serving++; receivedRequests++
          void serve(Number(value.id), value.method, value.value).catch(error => { void close(error) })
        } else if (value.type === 'changed') void schedule(true)
        else throw new Error('APPLICATION_PEER_MESSAGE_INVALID')
      }
      if (!closed) await close(new Error('APPLICATION_PEER_STREAM_ENDED'))
    } catch (error) { if (!closed) await close(error) }
  })()
  void read.catch(() => undefined)
  try {
    await send(local); await ready; authorized()
    const peerId = remote!.peer
    const result: ApplicationPeerConnection = {
      peerId, signal: lifetime.signal,
      get stats() { return { sentBytes, receivedBytes, sentRequests, receivedRequests } },
      synchronize,
      close: () => close(),
    }
    let previous = currentRevision(replica)
    unsubscribe = replica.subscribe(() => {
      const current = currentRevision(replica)
      if (current !== previous) { previous = current; notify() }
    })
    if (connection.live !== undefined) {
      const lane = connection.live
      signalRoute = owned.signals.attachRoute({
        trySend: async (frame, sendOptions) => { authorized(); return lane.trySend(frame, sendOptions) },
        // A dispatched callback that cannot stop must retire its physical owner.
        close: () => close(new Error('APPLICATION_PEER_LIVE_WRITE_FAILED')),
      })
      const route = signalRoute
      let liveClosed = false
      disposeLive = () => {
        if (liveClosed) return
        liveClosed = true; route.close(); lane.signal.removeEventListener('abort', disposeLive)
        void lane.close().catch(() => undefined)
      }
      lane.signal.addEventListener('abort', disposeLive, { once: true })
      if (lane.signal.aborted) disposeLive()
      void (async () => {
        try { for await (const frame of lane.frames(lifetime.signal)) { authorized(); await route.receive(frame) } }
        catch (error) { if (!closed && !lane.signal.aborted) await close(error) }
        finally { disposeLive() }
      })().catch(() => undefined)
    }
    await synchronize(); authorized()
    detach = session.attachPeer(peerId, async attempt => {
      authorized()
      await request<OrderedCommand>('submit', attempt)
      authorized()
      await synchronize()
    }, { close: () => close() })
    detachContent = owned.content.attachSource(peerId, {
      manifest: async reference => request<ContentManifest | null>('contentManifest', reference),
      chunk: async (reference, index) => {
        const value = await request<unknown>('contentChunk', { reference, index })
        authorized()
        if (value === null) return null
        if (typeof value !== 'string' || value.length > 2 * (65_536 + 16) || !/^(?:[0-9a-f]{2})*$/u.test(value)) throw new Error('APPLICATION_CONTENT_CHUNK_INVALID')
        return hexToBytes(value)
      },
      retained: async reference => request<ContentRetention>('contentRetained', reference),
      observeRetention: async receipt => { await request('contentObserveRetention', receipt) },
    })
    await session.resume(); authorized()
    return result
  } catch (error) { await close(error); throw error }
}

function reader(replica: PeerReplica, peer: string): boolean {
  return replica.authority.controls.find(value => value.payload.revision === replica.generation.payload.controlRevision)?.payload.grants.some(grant => grant.publicKey === peer && grant.reader) === true
}
function transcript(sender: Hello, recipient: Hello): Uint8Array<ArrayBuffer> {
  return encodeCanonicalCbor([HANDSHAKE_DOMAIN, sender.applicationId, sender.historyId, sender.peer, recipient.peer, sender.nonce, recipient.nonce]).slice()
}
function currentRevision(replica: PeerReplica): string {
  try { return JSON.stringify(replica.revision) }
  catch (error) { if (error instanceof Error && error.message === 'PEER_RECOVERING') return `${replica.generation.id}/recovering`; throw error }
}
function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('APPLICATION_PEER_MESSAGE_INVALID')
  return value as Record<string, unknown>
}
function encode(value: unknown): Uint8Array<ArrayBuffer> { return new TextEncoder().encode(JSON.stringify(value)) }

import { canonicalJson, type EventPayload } from '@chronolog/protocol'
import type { SignedTransitionRequest } from '@chronolog/peer-generation'
import type { ApplicationBootstrapHost, ApplicationConfiguration } from './bootstrap.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'

const PROTOCOL = 'chronolog/peer-session/worker-host/v1'
const MAX_CALLS = 8, MAX_BYTES = 1_048_576
const owners = new WeakSet<object>()
type Endpoint = ApplicationWorkerEndpoint & { start?(): void }
type Method = 'application' | 'definition' | 'configureApplication' | 'selectGeneration'
interface WireError { readonly name: string; readonly message: string; readonly code?: string; readonly status?: number }
interface Request { readonly id: number; readonly method: Method; readonly args: readonly unknown[] }
interface Client {
  readonly port: MessagePort
  readonly calls: Map<number, { cancelled: boolean }>
  readonly receive: (event: MessageEvent) => void
  readonly failed: () => void
  lastId: number
  closed: boolean
}
/** A control-only port; credentials remain on the page and signing keys remain in the Worker. */
export interface WorkerApplicationHost extends ApplicationBootstrapHost {
  readonly signal: AbortSignal
  close(): Promise<void>
}

/** Expose the page's existing signed-in host to one owning application Worker. */
export function serveApplicationWorkerHost(endpoint: Endpoint, host: ApplicationBootstrapHost, options: {
  readonly signal?: AbortSignal
} = {}): { readonly signal: AbortSignal; close(): void } {
  options.signal?.throwIfAborted()
  if (owners.has(endpoint)) throw new Error('APPLICATION_WORKER_HOST_IN_USE')
  owners.add(endpoint)
  const lifetime = new AbortController()
  let client: Client | undefined, active = 0
  const send = (port: MessagePort, value: unknown): void => { port.postMessage(encode(value)) }
  const finish = (connection: Client, reason: unknown, notify = true): void => {
    if (connection.closed) return
    connection.closed = true
    for (const call of connection.calls.values()) call.cancelled = true
    connection.port.removeEventListener('message', connection.receive)
    connection.port.removeEventListener('messageerror', connection.failed)
    if (notify) { try { send(connection.port, { ended: errorValue(reason) }) } catch { /* The observer may already be gone. */ } }
    connection.port.close()
    if (client === connection) client = undefined
  }
  const close = (reason: unknown = new Error('APPLICATION_WORKER_HOST_CLOSED')): void => {
    if (lifetime.signal.aborted) return
    lifetime.abort(reason); owners.delete(endpoint)
    endpoint.removeEventListener('message', connect)
    options.signal?.removeEventListener('abort', aborted)
    if (client !== undefined) finish(client, reason)
  }
  const invoke = (request: Request): Promise<unknown> => {
    switch (request.method) {
      case 'application': return host.application()
      case 'definition': return host.definition()
      case 'configureApplication': return host.configureApplication(request.args[0] as ApplicationConfiguration)
      case 'selectGeneration': return host.selectGeneration(request.args[0] as SignedTransitionRequest)
    }
  }
  const handle = async (connection: Client, request: Request): Promise<void> => {
    if (active >= MAX_CALLS) {
      send(connection.port, { id: request.id, error: errorValue(new Error('APPLICATION_WORKER_HOST_REQUEST_LIMIT')) }); return
    }
    const call = { cancelled: false }
    connection.calls.set(request.id, call); active++
    try {
      const value = await invoke(request)
      if (!connection.closed && !call.cancelled) send(connection.port, { id: request.id, value })
    } catch (error) {
      if (!connection.closed && !call.cancelled) send(connection.port, { id: request.id, error: errorValue(error) })
    } finally { connection.calls.delete(request.id); active-- }
  }
  const connect = (event: MessageEvent): void => {
    const value = event.data as { protocol?: unknown; port?: MessagePort } | null
    if (value?.protocol !== PROTOCOL || value.port === undefined || typeof value.port.postMessage !== 'function') return
    const port = value.port
    if (client !== undefined) {
      send(port, { ended: errorValue(new Error('APPLICATION_WORKER_HOST_IN_USE')) }); port.close(); return
    }
    const connection: Client = { port, lastId: 0, closed: false, calls: new Map(),
      failed() { finish(connection, new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')) },
      receive(message) {
        try {
          const input = decode(message.data)
          if (input.close === true) { finish(connection, new Error('APPLICATION_WORKER_HOST_CLOSED')); return }
          if (input.cancel !== undefined) {
            if (!Number.isSafeInteger(input.cancel) || Number(input.cancel) < 1 || Number(input.cancel) > connection.lastId) throw new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')
            const call = connection.calls.get(Number(input.cancel)); if (call !== undefined) call.cancelled = true
            return
          }
          if (!Number.isSafeInteger(input.id) || Number(input.id) <= connection.lastId || !Array.isArray(input.args) || typeof input.method !== 'string' ||
              !['application', 'definition', 'configureApplication', 'selectGeneration'].includes(String(input.method)) ||
              input.args.length !== (input.method === 'application' || input.method === 'definition' ? 0 : 1)) {
            throw new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')
          }
          connection.lastId = Number(input.id)
          void handle(connection, input as unknown as Request).catch(error => finish(connection, error))
        } catch (error) { finish(connection, error) }
      },
    }
    client = connection
    port.addEventListener('message', connection.receive); port.addEventListener('messageerror', connection.failed); port.start()
    send(port, { ready: true })
  }
  const aborted = (): void => close(options.signal?.reason)
  endpoint.addEventListener('message', connect); endpoint.start?.()
  options.signal?.addEventListener('abort', aborted, { once: true })
  return { signal: lifetime.signal, close: () => close() }
}

/** Connect before opening the Worker session; no functions or account credentials cross the boundary. */
export async function connectApplicationWorkerHost(endpoint: Endpoint, options: {
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
} = {}): Promise<WorkerApplicationHost> {
  options.signal?.throwIfAborted()
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 60_000) throw new Error('APPLICATION_WORKER_HOST_OPTIONS_INVALID')
  const channel = new MessageChannel(), port = channel.port1, lifetime = new AbortController()
  const calls = new Map<number, { resolve(value: unknown): void; reject(reason: unknown): void; timer: ReturnType<typeof setTimeout> }>()
  let sequence = 0, connected = false, resolveReady!: () => void, rejectReady!: (reason: unknown) => void
  let closing: Promise<void> | undefined, resolveClosed: (() => void) | undefined, closingTimer: ReturnType<typeof setTimeout> | undefined
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  void ready.catch(() => undefined)
  const finish = (): void => {
    clearTimeout(closingTimer)
    port.removeEventListener('message', receive); port.removeEventListener('messageerror', failed)
    port.close(); channel.port2.close(); resolveClosed?.()
  }
  const close = (reason: unknown = new Error('APPLICATION_WORKER_HOST_CLOSED'), notify = true): Promise<void> => {
    if (closing !== undefined) { if (!notify) finish(); return closing }
    closing = new Promise(resolve => { resolveClosed = resolve })
    lifetime.abort(reason); clearTimeout(timer); options.signal?.removeEventListener('abort', aborted)
    rejectReady(reason)
    for (const call of calls.values()) { clearTimeout(call.timer); call.reject(reason) }
    calls.clear()
    if (notify) {
      try {
        port.postMessage(encode({ close: true }))
        if (connected) closingTimer = setTimeout(finish, Math.min(timeoutMs, 1000))
        else finish()
      } catch { finish() }
    } else finish()
    return closing
  }
  const receive = (event: MessageEvent): void => {
    try {
      const value = decode(event.data)
      if (value.ended !== undefined) { void close(readError(value.ended), false); return }
      if (lifetime.signal.aborted) return
      if (value.ready === true && !connected) { connected = true; clearTimeout(timer); resolveReady(); return }
      if (!connected || !Number.isSafeInteger(value.id) || Number(value.id) < 1 || Number(value.id) > sequence) throw new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')
      const call = calls.get(Number(value.id))
      if (call === undefined) return // A timed-out observation does not undo the saved hosted request.
      const error = value.error === undefined ? undefined : readError(value.error)
      calls.delete(Number(value.id)); clearTimeout(call.timer)
      if (error === undefined) call.resolve(value.value)
      else call.reject(error)
    } catch (error) { void close(error) }
  }
  const failed = (): void => { void close(new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')) }
  const aborted = (): void => { void close(options.signal?.reason) }
  const timer = setTimeout(() => { void close(new Error('APPLICATION_WORKER_HOST_TIMEOUT')) }, timeoutMs)
  const request = async <T>(method: Method, args: readonly unknown[]): Promise<T> => {
    lifetime.signal.throwIfAborted()
    if (calls.size >= MAX_CALLS) return Promise.reject(new Error('APPLICATION_WORKER_HOST_REQUEST_LIMIT'))
    const id = ++sequence, message = encode({ id, method, args })
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        calls.delete(id); reject(new Error('APPLICATION_WORKER_HOST_TIMEOUT'))
        try { port.postMessage(encode({ cancel: id })) } catch (error) { void close(error) }
      }, timeoutMs)
      calls.set(id, { resolve: value => resolve(value as T), reject, timer })
      try { port.postMessage(message) }
      catch (error) { calls.delete(id); clearTimeout(timer); reject(error) }
    })
  }
  port.addEventListener('message', receive); port.addEventListener('messageerror', failed); port.start()
  options.signal?.addEventListener('abort', aborted, { once: true })
  try {
    endpoint.postMessage({ protocol: PROTOCOL, port: channel.port2 }, [channel.port2])
    await ready; lifetime.signal.throwIfAborted()
    return { signal: lifetime.signal, close: () => close(),
      application: () => request('application', []), definition: () => request('definition', []),
      configureApplication: configuration => request('configureApplication', [configuration]),
      selectGeneration: selection => request('selectGeneration', [selection]),
    }
  } catch (error) { await close(error); throw error }
}

function encode(value: unknown): string {
  return canonicalJson(value as EventPayload, { maxBytes: MAX_BYTES, maxNodes: 131_072, maxDepth: 40 })
}
function decode(value: unknown): Record<string, unknown> {
  if (typeof value !== 'string' || new TextEncoder().encode(value).length > MAX_BYTES) throw new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')
  const parsed = JSON.parse(value) as unknown
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || encode(parsed) !== value) throw new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')
  return parsed as Record<string, unknown>
}
function errorValue(value: unknown): WireError {
  const candidate = value as { code?: unknown; status?: unknown } | null
  return { name: value instanceof Error ? value.name : 'Error', message: String(value instanceof Error ? value.message : value).slice(0, 4096),
    ...(typeof candidate?.code === 'string' ? { code: candidate.code.slice(0, 128) } : {}),
    ...(Number.isSafeInteger(candidate?.status) ? { status: Number(candidate?.status) } : {}),
  }
}
function readError(value: unknown): Error {
  if (value === null || typeof value !== 'object') throw new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')
  const error = value as WireError
  if (typeof error.name !== 'string' || typeof error.message !== 'string' || error.code !== undefined && typeof error.code !== 'string' ||
      error.status !== undefined && !Number.isSafeInteger(error.status)) throw new Error('APPLICATION_WORKER_HOST_MESSAGE_INVALID')
  return Object.assign(new Error(error.message), error)
}

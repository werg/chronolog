import type { ApplicationControlHost } from './recovery.js'
import type { ApplicationSession } from './session.js'
import { createApplicationTools, formatApplicationToolResult } from './tools.js'

type RequestId = string | number
type Response = { readonly jsonrpc: '2.0'; readonly id: RequestId | null } &
  ({ readonly result: unknown } | { readonly error: { readonly code: number; readonly message: string } })
const PROTOCOL = '2025-06-18', MAX_BYTES = 1_048_576, MAX_CALLS = 16
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)
const requestId = (value: unknown): value is RequestId => typeof value === 'string' && value.length > 0 && value.length <= 256 || typeof value === 'number' && Number.isSafeInteger(value)

/** MCP tools execute inside the same local application owner as commands and queries. */
export function createApplicationMcpServer(session: ApplicationSession, options: {
  readonly host?: ApplicationControlHost
  readonly timeoutMs?: number
} = {}) {
  const tools = createApplicationTools(session, options), lifetime = new AbortController()
  const pending = new Map<RequestId, AbortController>()
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new Error('APPLICATION_MCP_TIMEOUT_INVALID')
  let initialized = false
  const error = (id: RequestId | null, code: number, message: string): Response => ({ jsonrpc: '2.0', id, error: { code, message } })
  return {
    async handle(message: unknown, options: { readonly signal?: AbortSignal } = {}): Promise<Response | undefined> {
      lifetime.signal.throwIfAborted(); session.signal.throwIfAborted()
      if (!object(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string' ||
          message.params !== undefined && !object(message.params)) return error(null, -32600, 'Invalid Request')
      const params = message.params
      if (message.id === undefined) {
        if (message.method === 'notifications/cancelled' && requestId(params?.requestId)) {
          pending.get(params.requestId)?.abort(new Error('APPLICATION_MCP_CANCELLED'))
        }
        return undefined
      }
      if (!requestId(message.id)) return error(null, -32600, 'Invalid Request')
      const id = message.id
      if (pending.has(id)) return error(id, -32600, 'Request ID is already active')
      if (message.method === 'initialize') {
        initialized = true
        return { jsonrpc: '2.0', id, result: { protocolVersion: PROTOCOL, capabilities: { tools: {} },
          serverInfo: { name: 'chronolog-application', version: '1' },
          instructions: 'Use domain commands with stable operation IDs. Applied results belong to the selected history; inspect recovery and deliberately reapply abandoned intent.' } }
      }
      if (message.method === 'ping') return { jsonrpc: '2.0', id, result: {} }
      if (!initialized) return error(id, -32000, 'Initialize this application session first')
      if (message.method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: tools.list() } }
      if (message.method !== 'tools/call') return error(id, -32601, 'Method not found')
      if (typeof params?.name !== 'string' || !tools.list().some(tool => tool.name === params.name)) return error(id, -32602, 'Unknown application tool')
      if (pending.size >= MAX_CALLS) return error(id, -32000, 'Application tool concurrency limit reached')
      const controller = new AbortController()
      pending.set(id, controller)
      const signal = AbortSignal.any([controller.signal, lifetime.signal, session.signal, AbortSignal.timeout(timeoutMs),
        ...(options.signal === undefined ? [] : [options.signal])])
      try {
        const work = tools.call(params.name, params.arguments ?? {}, { signal })
        // Cancelling a reply never cancels journalled work or frees its slot.
        // Retain the active request ID and concurrency bound until work settles.
        const settled = (): void => { pending.delete(id) }
        void work.then(settled, settled)
        const value = await waitForResponse(work, signal)
        const text = formatApplicationToolResult(value)
        if (new TextEncoder().encode(text).length > MAX_BYTES) throw new Error('APPLICATION_MCP_RESULT_TOO_LARGE')
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }] } }
      } catch (failure) {
        const text = formatApplicationToolResult({ error: failure instanceof Error ? failure.message : 'APPLICATION_TOOL_FAILED',
          ...(failure instanceof Error && 'operation' in failure ? { operation: failure.operation } : {}) })
        return { jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text }] } }
      }
    },
    close(): void {
      lifetime.abort(new Error('APPLICATION_MCP_CLOSED'))
      for (const controller of pending.values()) controller.abort(lifetime.signal.reason)
    },
  }
}

function waitForResponse<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  return new Promise((resolve, reject) => {
    const abort = (): void => { reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    void work.then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
  })
}

/** Standard MCP JSON-RPC over newline-delimited stdin/stdout; cancellation remains independent of saved commands. */
export async function serveApplicationMcpLines(session: ApplicationSession, options: {
  readonly input: AsyncIterable<string>
  readonly write: (line: string) => void | Promise<void>
  readonly host?: ApplicationControlHost
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
}): Promise<void> {
  const server = createApplicationMcpServer(session, options), tasks = new Set<Promise<void>>()
  const signal = AbortSignal.any([session.signal, ...(options.signal === undefined ? [] : [options.signal])])
  const input = options.input[Symbol.asyncIterator]()
  const next = (): Promise<IteratorResult<string>> => {
    signal.throwIfAborted()
    return new Promise((resolve, reject) => {
      const abort = (): void => { reject(signal.reason) }
      signal.addEventListener('abort', abort, { once: true })
      void Promise.resolve().then(() => input.next()).then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
    })
  }
  let writing = Promise.resolve()
  const write = (value: unknown): Promise<void> => {
    const line = `${formatApplicationToolResult(value)}\n`
    writing = writing.then(async () => { await options.write(line) })
    return writing
  }
  try {
    for (;;) {
      const item = await next()
      if (item.done) break
      const line = item.value
      signal.throwIfAborted()
      let message: unknown
      try {
        if (new TextEncoder().encode(line).length > MAX_BYTES) throw new Error('too large')
        message = JSON.parse(line)
      } catch {
        await write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Invalid JSON-RPC input' } }); continue
      }
      if (tasks.size >= MAX_CALLS && object(message) && message.id !== undefined) {
        await write({ jsonrpc: '2.0', id: requestId(message.id) ? message.id : null, error: { code: -32000, message: 'Application tool concurrency limit reached' } }); continue
      }
      const task = server.handle(message, options).then(async response => { if (response !== undefined) await write(response) })
      tasks.add(task)
      void task.finally(() => tasks.delete(task)).catch(() => undefined)
    }
    await Promise.all(tasks)
    await writing
  } finally {
    server.close()
    // A caller's stream may have a pending read; release it without letting that
    // read delay session shutdown or cancellation.
    void Promise.resolve().then(() => input.return?.()).catch(() => undefined)
  }
}

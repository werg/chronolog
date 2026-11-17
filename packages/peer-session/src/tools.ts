import type { PeerRevision } from '@chronolog/peer-generation'
import type { ApplicationControlHost } from './recovery.js'
import type { ApplicationSession } from './session.js'
import { awaitOwnedTask } from './lifetime.js'

export interface ApplicationTool {
  readonly name: string
  readonly description: string
  readonly inputSchema: Readonly<Record<string, unknown>>
}

/** Local agent tools execute against the same owned session, identity and journal as the UI. */
export function createApplicationTools(session: ApplicationSession, options: { readonly host?: ApplicationControlHost } = {}) {
  const description = session.describe(), operationId = { type: 'string', minLength: 1, maxLength: 256 }
  const object = (properties: Record<string, unknown>, required: readonly string[] = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false })
  const entries = (kind: 'commands' | 'queries', fields: Record<string, unknown>) => ({ oneOf: description[kind].map(entry => object({
    name: { type: 'string', const: entry.name, description: entry.description }, input: entry.input, ...fields,
  })) })
  const tools: readonly ApplicationTool[] = [
    { name: 'describe', description: 'Inspect authenticated application definitions, current role and supported guarantees.', inputSchema: object({}) },
    { name: 'query', description: 'Execute a declared query against one coherent captured application revision.', inputSchema: entries('queries', {}) },
    { name: 'command', description: 'Save one signed command under a caller-owned operation ID. Returns saved or currently applied state.', inputSchema: entries('commands', { operationId }) },
    { name: 'operation', description: 'Inspect saved attempt bytes, current outcome and explicit reapplication linkage.', inputSchema: object({ operationId }) },
    { name: 'retry', description: 'Retry the exact saved command. Never recreates an abandoned operation.', inputSchema: object({ operationId }) },
    { name: 'wait', description: 'Wait for the current applied result. Cancellation only cancels this wait.', inputSchema: object({ operationId }) },
    { name: 'recoveries', description: 'Inspect generation recovery notices and preserved abandoned operations.', inputSchema: object({}) },
    { name: 'reapply', description: 'Deliberately create a newly signed, linked command from current input after abandonment.', inputSchema: entries('commands', { operationId, originalOperationId: operationId }) },
    ...(options.host === undefined ? [] : [{ name: 'takeover', description: 'Select this eligible device\'s complete recovery point through the hosted authority; may abandon a recent suffix.', inputSchema: object({ transitionId: { type: 'string', minLength: 1, maxLength: 128 } }) }]),
  ]
  return {
    list(): readonly ApplicationTool[] { return structuredClone(tools) },
    async call(name: string, input: unknown, callOptions: { readonly signal?: AbortSignal } = {}): Promise<unknown> {
      const signal = callOptions.signal === undefined ? session.signal : AbortSignal.any([session.signal, callOptions.signal])
      return awaitOwnedTask(signal, async () => {
        if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new Error('APPLICATION_TOOL_INPUT_INVALID')
        const value = input as Record<string, unknown>
        const text = (key: string): string => { if (typeof value[key] !== 'string') throw new Error('APPLICATION_TOOL_INPUT_INVALID'); return value[key] }
        const fields = (...keys: string[]): void => { if (Object.keys(value).some(key => !keys.includes(key))) throw new Error('APPLICATION_TOOL_INPUT_INVALID') }
        switch (name) {
          case 'describe': fields(); return { definition: description, status: session.status }
          case 'query': fields('name', 'input'); return session.query(text('name'), value.input as never)
          case 'command': {
            fields('name', 'input', 'operationId', 'basedOn')
            const operation = await session.command(text('name'), value.input as never, { operationId: text('operationId'),
              ...(value.basedOn === undefined ? {} : { basedOn: value.basedOn as PeerRevision }) })
            return operation.get()
          }
          case 'operation': fields('operationId'); return session.operations.inspect(text('operationId'))
          case 'retry': fields('operationId'); await session.retry(text('operationId')); return session.operations.get(text('operationId'))
          case 'wait': fields('operationId'); return session.operations.wait(text('operationId'), callOptions)
          case 'recoveries': fields(); return session.inspectRecovery()
          case 'reapply': {
            fields('name', 'input', 'operationId', 'originalOperationId', 'basedOn')
            const operation = await session.reapply(text('originalOperationId'), text('name'), value.input as never, { operationId: text('operationId'),
              ...(value.basedOn === undefined ? {} : { basedOn: value.basedOn as PeerRevision }) })
            return operation.get()
          }
          case 'takeover':
            fields('transitionId')
            if (options.host === undefined) throw new Error('APPLICATION_TOOL_UNAVAILABLE')
            return session.recovery.takeover(options.host, { transitionId: text('transitionId') })
          default: throw new Error('APPLICATION_TOOL_UNKNOWN')
        }
      })
    },
  }
}

/** JSON-lines/CLI formatting preserves exact SQL integers and binary values explicitly. */
export function formatApplicationToolResult(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => {
    if (typeof item === 'bigint') return { $integer: String(item) }
    if (item instanceof Uint8Array) return { $bytes: Array.from(item, byte => byte.toString(16).padStart(2, '0')).join('') }
    return item
  })
}

/** Per-request deadlines bound tool waits; input/output waits end with the owned lifetime. */
export async function serveApplicationToolLines(session: ApplicationSession, options: {
  readonly input: AsyncIterable<string>
  readonly write: (line: string) => void | Promise<void>
  readonly host?: ApplicationControlHost
  readonly signal?: AbortSignal
}): Promise<void> {
  const tools = createApplicationTools(session, options)
  const lifetime = options.signal === undefined ? session.signal : AbortSignal.any([session.signal, options.signal])
  lifetime.throwIfAborted()
  const iterator = options.input[Symbol.asyncIterator]()
  let ended = false
  try {
    while (true) {
      const next = await awaitOwnedTask(lifetime, () => iterator.next())
      if (next.done) { ended = true; return }
      const line = next.value
      let id: string | number | null = null
      let response: unknown
      try {
        if (new TextEncoder().encode(line).length > 262_144) throw new Error('APPLICATION_TOOL_LINE_TOO_LARGE')
        const request = JSON.parse(line) as { readonly id?: unknown; readonly tool?: unknown; readonly input?: unknown; readonly timeoutMs?: unknown }
        if (request === null || typeof request !== 'object' || Array.isArray(request) ||
            typeof request.id !== 'string' && (typeof request.id !== 'number' || !Number.isSafeInteger(request.id))) throw new Error('APPLICATION_TOOL_REQUEST_INVALID')
        id = request.id
        const timeoutMs = request.timeoutMs ?? 30_000
        if (typeof timeoutMs !== 'number' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new Error('APPLICATION_TOOL_TIMEOUT_INVALID')
        const value = request.tool === 'list' ? tools.list() : typeof request.tool === 'string'
          ? await tools.call(request.tool, request.input ?? {}, { signal: AbortSignal.any([lifetime, AbortSignal.timeout(timeoutMs)]) })
          : (() => { throw new Error('APPLICATION_TOOL_REQUEST_INVALID') })()
        response = { id, result: value }
      } catch (error) {
        lifetime.throwIfAborted()
        const state = error instanceof Error && 'operation' in error ? { operation: error.operation } : {}
        response = { id, error: error instanceof Error ? error.message : 'APPLICATION_TOOL_FAILED', ...state }
      }
      await awaitOwnedTask(lifetime, () => options.write(`${formatApplicationToolResult(response)}\n`))
    }
  } finally {
    if (!ended && iterator.return !== undefined) {
      // The caller owns the stream. Request release but do not let an
      // uncooperative iterator keep a closed application alive.
      try { void Promise.resolve(iterator.return()).catch(() => undefined) } catch { /* The original failure is preserved. */ }
    }
  }
}

import { validatePeerRevision, type PeerRevision } from '@chronolog/peer-generation'
import type { ApplicationControlHost } from './recovery.js'
import type { ApplicationChange, ApplicationSession } from './session.js'
import { awaitOwnedTask } from './lifetime.js'

export interface ApplicationTool {
  readonly name: string
  readonly description: string
  readonly inputSchema: Readonly<Record<string, unknown>>
}

const digestSchema = { type: 'string', pattern: '^[0-9a-f]{64}$' }
const unsignedSchema = { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER }
const revisionSchema = {
  type: 'object', additionalProperties: false,
  required: ['applicationId', 'historyId', 'generation', 'point', 'controlRevision', 'materializationRevision'],
  properties: {
    applicationId: digestSchema, historyId: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[^\\u0000-\\u001f\\u007f]+$' },
    generation: digestSchema, controlRevision: unsignedSchema,
    materializationRevision: { type: 'string', pattern: '^[0-9]{1,32}$' },
    point: { type: 'object', additionalProperties: false, required: ['generation', 'sequence', 'root'],
      properties: { generation: digestSchema, sequence: unsignedSchema, root: digestSchema } },
  },
}

function inputRevision(session: ApplicationSession, value: unknown): PeerRevision | undefined {
  if (value === undefined) return undefined
  const revision = value as PeerRevision
  validatePeerRevision(revision)
  if (revision.applicationId !== session.applicationId || revision.historyId !== session.historyId) {
    throw new Error('APPLICATION_TOOL_REVISION_SCOPE_MISMATCH')
  }
  return revision
}

function sameRevision(left: PeerRevision, right: PeerRevision): boolean {
  return left.applicationId === right.applicationId && left.historyId === right.historyId &&
    left.generation === right.generation && left.controlRevision === right.controlRevision &&
    left.materializationRevision === right.materializationRevision && left.point.generation === right.point.generation &&
    left.point.sequence === right.point.sequence && left.point.root === right.point.root
}

/** A bounded invalidation observation, not another event stream or replay cursor. */
async function observeChange(session: ApplicationSession, after: PeerRevision | undefined, waitMs: unknown, signal: AbortSignal): Promise<{
  readonly change: ApplicationChange | null
  readonly resetRequired: boolean
}> {
  if (typeof waitMs !== 'number' || !Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > 30_000) {
    throw new Error('APPLICATION_TOOL_INPUT_INVALID')
  }
  const deadline = new AbortController(), observation = AbortSignal.any([signal, deadline.signal])
  const iterator = session.changes({ signal: observation })[Symbol.asyncIterator]()
  const timer = setTimeout(() => { deadline.abort() }, waitMs)
  try {
    while (true) {
      const next = await iterator.next()
      signal.throwIfAborted()
      if (next.done === true) return { change: null, resetRequired: false }
      const change = next.value
      if (after !== undefined && sameRevision(after, change.revision)) continue
      const resetRequired = after !== undefined && after.generation !== change.revision.generation
      // A short-lived observer may start after the recovery notification. Reuse
      // the real recorded notice; a generation difference alone invents no loss.
      const recovery = change.recovery ?? (resetRequired
        ? (await session.inspectRecovery()).findLast(notice => notice.generation === change.revision.generation) ?? null : null)
      return { change: recovery === null ? change : { ...change, kind: 'recovery', recovery }, resetRequired }
    }
  } finally {
    clearTimeout(timer)
    await iterator.return?.()
  }
}

/** Local agent tools execute against the same owned session, identity and journal as the UI. */
export function createApplicationTools(session: ApplicationSession, options: { readonly host?: ApplicationControlHost } = {}) {
  const description = session.describe(), operationId = { type: 'string', minLength: 1, maxLength: 256 }
  const object = (properties: Record<string, unknown>, required: readonly string[] = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false })
  const entries = (kind: 'commands' | 'queries', fields: Record<string, unknown>, required = Object.keys(fields)) => ({ oneOf: description[kind].map(entry => object({
    name: { type: 'string', const: entry.name, description: entry.description }, input: entry.input, ...fields,
  }, ['name', 'input', ...required])) })
  const tools: readonly ApplicationTool[] = [
    { name: 'describe', description: 'Inspect authenticated application definitions, current role and supported guarantees.', inputSchema: object({}) },
    { name: 'query', description: 'Execute a declared query against one coherent captured application revision.', inputSchema: entries('queries', {}) },
    { name: 'command', description: 'Save one signed command under a caller-owned operation ID, optionally guarded by a captured revision. Returns saved or currently applied state.', inputSchema: entries('commands', { operationId, basedOn: revisionSchema }, ['operationId']) },
    { name: 'operation', description: 'Inspect saved attempt bytes, current outcome and explicit reapplication linkage. Author defaults to this device; specify the original signer to inspect another participant\'s retained work.', inputSchema: object({ operationId, author: digestSchema }, ['operationId']) },
    { name: 'retry', description: 'Retry this device\'s exact saved command. Never recreates an abandoned operation.', inputSchema: object({ operationId }) },
    { name: 'wait', description: 'Wait for the current applied result of this device or an explicit original author. Cancellation only cancels this wait.', inputSchema: object({ operationId, author: digestSchema }, ['operationId']) },
    { name: 'changes', description: 'Observe one coalesced coherent revision, optionally waiting after a captured revision. A generation change requires a reread; this is not an event replay cursor.',
      inputSchema: object({ after: revisionSchema, waitMs: { type: 'integer', minimum: 0, maximum: 30_000, default: 0 } }, []) },
    { name: 'recoveries', description: 'Inspect generation recovery notices and preserved abandoned operations.', inputSchema: object({}) },
    { name: 'reapply', description: 'Deliberately create a newly signed, linked command from current input after abandonment, optionally guarded by a captured revision. Specify originalAuthor for another participant\'s work; the new command is always signed by this device.', inputSchema: entries('commands', { operationId, originalOperationId: operationId, originalAuthor: digestSchema, basedOn: revisionSchema }, ['operationId', 'originalOperationId']) },
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
        const author = (key: string): string | undefined => {
          if (value[key] === undefined) return undefined
          const identity = text(key)
          if (!/^[0-9a-f]{64}$/u.test(identity)) throw new Error('APPLICATION_TOOL_INPUT_INVALID')
          return identity
        }
        const fields = (...keys: string[]): void => { if (Object.keys(value).some(key => !keys.includes(key))) throw new Error('APPLICATION_TOOL_INPUT_INVALID') }
        switch (name) {
          case 'describe': fields(); return { definition: description, status: session.status }
          case 'query': fields('name', 'input'); return session.query(text('name'), value.input as never)
          case 'command': {
            fields('name', 'input', 'operationId', 'basedOn')
            const basedOn = inputRevision(session, value.basedOn)
            const operation = await session.command(text('name'), value.input as never, { operationId: text('operationId'),
              ...(basedOn === undefined ? {} : { basedOn }) })
            return operation.get()
          }
          case 'operation': {
            fields('operationId', 'author')
            const signer = author('author')
            return session.operations.inspect(text('operationId'), signer === undefined ? {} : { author: signer })
          }
          case 'retry': fields('operationId'); await session.retry(text('operationId')); return session.operations.get(text('operationId'))
          case 'wait': {
            fields('operationId', 'author')
            const signer = author('author')
            return session.operations.wait(text('operationId'), { signal, ...(signer === undefined ? {} : { author: signer }) })
          }
          case 'changes': fields('after', 'waitMs'); return observeChange(session, inputRevision(session, value.after), value.waitMs === undefined ? 0 : value.waitMs, signal)
          case 'recoveries': fields(); return session.inspectRecovery()
          case 'reapply': {
            fields('name', 'input', 'operationId', 'originalOperationId', 'originalAuthor', 'basedOn')
            const basedOn = inputRevision(session, value.basedOn)
            const originalAuthor = author('originalAuthor')
            const operation = await session.reapply(text('originalOperationId'), text('name'), value.input as never, { operationId: text('operationId'),
              ...(originalAuthor === undefined ? {} : { originalAuthor }),
              ...(basedOn === undefined ? {} : { basedOn }) })
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

export interface ScopedApplicationToolCall {
  readonly kind: 'query' | 'command' | 'reapply' | 'operation' | 'retry' | 'wait'
  readonly name: string
  readonly input?: unknown
  readonly operationId?: string
  readonly basedOn?: PeerRevision
  readonly originalOperationId?: string
  readonly originalAuthor?: string
  readonly generation?: string
}

/**
 * Capability-scoped, generation-pinned tool pipe for limited external transports
 * (e.g. an OAuth/MCP gateway or sandboxed agent bridge) over the owned session.
 */
export function createScopedApplicationTools(session: ApplicationSession, options: {
  readonly queries?: readonly string[]
  readonly commands?: readonly string[]
  readonly host?: ApplicationControlHost
} = {}) {
  const allowedQueries = new Set(options.queries ?? [])
  const allowedCommands = new Set(options.commands ?? [])
  const tools = createApplicationTools(session, options.host === undefined ? {} : { host: options.host })
  return Object.freeze({
    allowed: Object.freeze({ queries: Object.freeze([...allowedQueries]), commands: Object.freeze([...allowedCommands]) }),
    async execute(call: ScopedApplicationToolCall, callOptions: { readonly signal?: AbortSignal } = {}): Promise<unknown> {
      const { kind, name, input, operationId, basedOn, originalOperationId, originalAuthor, generation } = call
      const journal = kind === 'operation' || kind === 'retry' || kind === 'wait'
      const write = kind === 'command' || kind === 'reapply'
      if (!(journal || write || kind === 'query') || !(kind === 'query' ? allowedQueries : allowedCommands).has(name)) {
        throw Object.assign(new Error('APPLICATION_TOOL_NOT_ALLOWED'), { code: 'APPLICATION_TOOL_NOT_ALLOWED' })
      }
      if (generation !== undefined && generation !== session.status.generation) {
        throw Object.assign(new Error('APPLICATION_TOOL_GENERATION_CHANGED'), { code: 'APPLICATION_TOOL_GENERATION_CHANGED' })
      }
      const args: Record<string, unknown> = journal
        ? { operationId }
        : {
          name,
          input,
          ...(write ? {
            operationId,
            ...(basedOn === undefined ? {} : { basedOn }),
            ...(kind === 'reapply' ? { originalOperationId, ...(originalAuthor === undefined ? {} : { originalAuthor }) } : {}),
          } : {}),
        }
      const raw = await tools.call(kind, args, callOptions)
      if (generation !== undefined && generation !== session.status.generation) {
        throw Object.assign(new Error('APPLICATION_TOOL_GENERATION_CHANGED'), { code: 'APPLICATION_TOOL_GENERATION_CHANGED' })
      }
      if (raw !== null && raw !== undefined && typeof raw === 'object' && (write || journal)) {
        return {
          ...(raw as Record<string, unknown>),
          operationReference: {
            applicationId: session.applicationId,
            historyId: session.historyId,
            deviceId: session.deviceId,
            operationId,
          },
        }
      }
      return raw
    },
  })
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

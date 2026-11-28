import type { WaitOptions as InlineWaitOptions, CommandOptions as InlineCommandOptions, MaterializedRevision } from './session-types.js'
import type { ApplicationDescription as InlineApplicationDescription } from '@chronolog/authority'
import { check, recordDigest } from '@chronolog/authority'
import type { ApplicationSession } from './session.js'
import { describeApplication } from './definition.js'
import type { OperationInspection } from './operation.js'

interface ToolOperation {
  readonly id: string
  readonly operationId: string
  inspect(): OperationInspection | Promise<OperationInspection>
  materialized(options?: InlineWaitOptions): Promise<unknown>
  retained(options?: InlineWaitOptions): Promise<unknown>
  finalized(options?: InlineWaitOptions): Promise<unknown>
}

interface ToolSession {
  readonly scopeOperationId?: (rawId: string) => string
  readonly definition?: ApplicationSession['definition']
  describe?(): InlineApplicationDescription | Promise<InlineApplicationDescription>
  readonly applicationId: string
  readonly identity: { readonly publicKey: string }
  command(name: string, input: unknown, options?: InlineCommandOptions): Promise<ToolOperation>
  query(name: string, input: unknown): Promise<unknown>
  readonly operations: {
    retry(id: string): Promise<ToolOperation>
    get(id: string): ToolOperation | null | Promise<ToolOperation | null>
  }
  readView(): Promise<{ readonly revision: MaterializedRevision; release(): void | Promise<void> }>
}

export interface ScopedToolRequest {
  readonly kind: 'command' | 'query' | 'inspect' | 'retry' | 'wait'
  readonly name?: string
  readonly input?: unknown
  readonly operationId?: string
  readonly basedOn?: MaterializedRevision
  readonly fact?: 'stored' | 'materialized' | 'retained' | 'finalized'
}

export interface ScopedToolContext {
  readonly signal?: AbortSignal
  readonly caller: string
  readonly timeoutMs?: number
}

/** Named executable allowlists and caller-scoped idempotency cannot be widened by request input. */
export function createScopedApplicationTools(
  session: ToolSession,
  options: {
    readonly commands?: readonly string[]
    readonly queries?: readonly string[]
    readonly description?: InlineApplicationDescription
  } = {},
) {
  const syncDescription = options.description ?? (session.definition !== undefined ? describeApplication(session.definition) : undefined)
  const syncMaybe = syncDescription ?? (session.describe ? session.describe() : undefined)
  const description = syncMaybe !== undefined && !(syncMaybe instanceof Promise) ? syncMaybe : undefined
  check(description !== undefined, 'APPLICATION_TOOL_DESCRIPTION_REQUIRED')

  const commands = options.commands ?? description.commands.map(c => c.name)
  const queries = options.queries ?? description.queries.map(q => q.name)
  for (const name of commands) check(description.commands.some(entry => entry.name === name), 'APPLICATION_TOOL_COMMAND_UNKNOWN')
  for (const name of queries) check(description.queries.some(entry => entry.name === name), 'APPLICATION_TOOL_QUERY_UNKNOWN')

  const result = async (operation: ToolOperation) => {
    const state = await operation.inspect()
    check(state.applicationId === session.applicationId && state.author === session.identity.publicKey, 'APPLICATION_TOOL_OPERATION_FORBIDDEN')
    return {
      state,
      operationReference: {
        applicationId: state.applicationId,
        author: state.author,
        operationId: state.operationId,
        opId: state.opId,
      },
    }
  }

  const scopedOperationId = async (rawId: string, context: { readonly caller: string }): Promise<string> => {
    check(typeof context.caller === 'string' && context.caller.length > 0 && context.caller.length <= 512 && typeof rawId === 'string' && rawId.length > 0 && rawId.length <= 512, 'APPLICATION_TOOL_SCOPE_INVALID')
    const digest = await recordDigest(['scoped-tool-operation', session.applicationId, session.identity.publicKey, context.caller, rawId])
    return session.scopeOperationId?.(digest) ?? digest
  }

  return {
    operationId: scopedOperationId,
    list() {
      return [
        ...description.commands.filter(entry => commands.includes(entry.name)).map(entry => ({ name: entry.name, kind: 'command' as const, description: entry.description, inputSchema: entry.input })),
        ...description.queries.filter(entry => queries.includes(entry.name)).map(entry => ({ name: entry.name, kind: 'query' as const, description: entry.description, inputSchema: entry.input })),
      ]
    },
    async execute(request: ScopedToolRequest, context: ScopedToolContext): Promise<unknown> {
      context.signal?.throwIfAborted()
      check(typeof context.caller === 'string' && context.caller.length > 0 && context.caller.length <= 512, 'APPLICATION_TOOL_CALLER_REQUIRED')
      if (request.kind === 'query') {
        check(request.name !== undefined && queries.includes(request.name), 'APPLICATION_TOOL_QUERY_FORBIDDEN')
        return session.query(request.name, request.input)
      }
      check(typeof request.operationId === 'string' && request.operationId.length > 0 && request.operationId.length <= 512, 'APPLICATION_TOOL_OPERATION_ID_REQUIRED')
      const operationId = await scopedOperationId(request.operationId, context)
      if (request.kind === 'command') {
        check(request.name !== undefined && commands.includes(request.name), 'APPLICATION_TOOL_COMMAND_FORBIDDEN')
        if (request.basedOn !== undefined) {
          const view = await session.readView()
          try { check(view.revision.digest === request.basedOn.digest, 'APPLICATION_TOOL_VIEW_STALE') }
          finally { await view.release() }
        }
        const operation = await session.command(request.name, request.input, { operationId })
        context.signal?.throwIfAborted()
        return result(operation)
      }
      if (request.kind === 'retry') return result(await session.operations.retry(operationId))
      const operation = await session.operations.get(operationId)
      check(operation !== null && (await operation.inspect()).author === session.identity.publicKey, 'APPLICATION_TOOL_OPERATION_FORBIDDEN')
      if (request.kind === 'wait') {
        const fact = request.fact ?? 'materialized'
        check(['stored', 'materialized', 'retained', 'finalized'].includes(fact), 'APPLICATION_TOOL_FACT_INVALID')
        if (fact !== 'stored') {
          await operation[fact]({
            ...(context.signal === undefined ? {} : { signal: context.signal }),
            ...(context.timeoutMs === undefined ? {} : { timeoutMs: context.timeoutMs }),
          })
        }
      } else {
        check(request.kind === 'inspect' || request.kind === 'retry', 'APPLICATION_TOOL_KIND_INVALID')
      }
      return result(operation)
    },
  }
}

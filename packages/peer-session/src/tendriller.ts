import type { OperationState, PeerRevision, RecoveryNotice } from '@chronolog/peer-generation'
import type { ApplicationEventBatch, ApplicationEventOptions, ApplicationSession, QueryParameter } from './session.js'
import type { WorkerApplicationSession } from './worker-application.js'

export interface PeerApplicationProgram { readonly name: string; readonly input: unknown }
interface SubmitOptions { readonly operationId: string; readonly basedOn?: string }
interface ViewOptions { readonly view?: 'applied' | 'local' | 'final' }
interface EventOptions extends ApplicationEventOptions { readonly signal?: AbortSignal }

/**
 * Tendriller's applied backend shape, using the owned public session directly.
 * Domain event publication is opt-in through an ordinary declared command.
 */
export function createPeerGenerationApplicationBackend(options: {
  readonly id: string
  readonly session: ApplicationSession | WorkerApplicationSession
  readonly sql?: boolean
  readonly eventCommand?: string
}) {
  const session = options.session
  if (!/^[A-Za-z0-9_.:-]{1,200}$/u.test(options.id)) throw new Error('APPLICATION_BACKEND_ID_INVALID')
  if (options.id !== session.applicationId) throw new Error('APPLICATION_BACKEND_SCOPE_MISMATCH')
  if (options.eventCommand !== undefined && !session.describe().commands.some(command => command.name === options.eventCommand)) {
    throw new Error('APPLICATION_EVENT_COMMAND_UNKNOWN')
  }
  const submit = async (program: PeerApplicationProgram, input: SubmitOptions): Promise<OperationState> => {
    if (program === null || typeof program !== 'object' || typeof program.name !== 'string') throw new Error('APPLICATION_COMMAND_INVALID')
    const operation = await session.command(program.name, program.input as never, { operationId: input.operationId,
      ...(input.basedOn === undefined ? {} : { basedOn: JSON.parse(input.basedOn) as PeerRevision }) })
    const state = await operation.get()
    if (state === null) throw new Error('APPLICATION_OPERATION_NOT_FOUND')
    return state
  }
  const read = async (input: EventOptions = {}) => {
    input.signal?.throwIfAborted()
    const view = await session.readView()
    try { input.signal?.throwIfAborted(); return eventBatch(await view.readEvents(input)) }
    finally { await view.release() }
  }
  return Object.freeze({
    id: options.id, profile: 'peer-generation-v1' as const,
    capabilities: Object.freeze(['events', 'revision-views', 'operation-status', 'peer-generation-v1',
      ...(options.sql === true ? ['sql'] : []), ...(options.eventCommand === undefined ? [] : ['event-publication'])]),
    get status() { return session.status },
    onStatus: session.onStatus.bind(session),
    submit,
    changes(input: ViewOptions & { readonly signal?: AbortSignal } = {}) {
      assertView(input)
      return { async *[Symbol.asyncIterator]() {
        for await (const change of session.changes(input)) yield { view: 'applied' as const, revision: JSON.stringify(change.revision),
          generation: change.revision.generation, kind: change.kind === 'recovery' ? 'recovery' as const : 'update' as const,
          ...(change.recovery === null ? {} : { recovery: recoveryNotice(change.recovery) }) }
      } }
    },
    async readView(input: ViewOptions = {}) {
      assertView(input)
      const view = await session.readView()
      return Object.freeze({ view: 'applied' as const, revision: JSON.stringify(view.revision), generation: view.revision.generation,
        async query(sql: string, parameters: readonly QueryParameter[] = []) {
          if (options.sql !== true) throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE')
          return await view.query(sql, parameters)
        },
        async readEvents(input: EventOptions = {}) { input.signal?.throwIfAborted(); return eventBatch(await view.readEvents(input)) },
        release: async () => { await view.release() },
      })
    },
    onRecovery: (listener: (notice: ReturnType<typeof recoveryNotice>) => void) => session.onRecovery(notice => { listener(recoveryNotice(notice)) }),
    inspectRecovery: async () => (await session.inspectRecovery()).map(recoveryNotice),
    operations: Object.freeze({
      get: (id: string) => session.operations.get(id),
      subscribe(input: { readonly operationId: string; readonly signal?: AbortSignal }) {
        return { async *[Symbol.asyncIterator]() {
          let previous: string | undefined
          for await (const _change of session.changes(input)) {
            const state = await session.operations.get(input.operationId), encoded = JSON.stringify(state)
            if (state !== null && encoded !== previous) { previous = encoded; yield state }
          }
        } }
      },
    }),
    events: Object.freeze({
      async publish(topic: string, payload: unknown, input: SubmitOptions) {
        if (options.eventCommand === undefined) throw new Error('APPLICATION_EVENT_PUBLICATION_NOT_CONFIGURED')
        return submit({ name: options.eventCommand, input: { topic, payload } }, input)
      },
      read,
      subscribe(input: EventOptions = {}) {
        return { async *[Symbol.asyncIterator]() {
          let cursor = input.cursor
          for await (const _change of session.changes(input)) {
            for (;;) {
              const batch = await read({ ...input, ...(cursor === undefined ? {} : { cursor }) })
              if (batch.scannedThrough === cursor) break
              cursor = batch.scannedThrough
              yield batch
              if (!batch.hasMore) break
            }
          }
        } }
      },
    }),
  })
}

function assertView(input: ViewOptions): void { if (input.view !== undefined && input.view !== 'applied') throw new Error('APPLICATION_VIEW_UNSUPPORTED') }
function recoveryNotice(notice: RecoveryNotice) { return { ...notice, revision: JSON.stringify(notice.revision) } }
function eventBatch(batch: ApplicationEventBatch) {
  const transactions = new Map<string, { proposalId: string; events: Array<{
    id: string; proposalId: string; eventOrdinal: number; topic: string; payload: unknown;
    origin: { kind: string; authorId: string; operationId: string };
  }> }>()
  for (const event of batch.events) {
    let transaction = transactions.get(event.attemptId)
    if (transaction === undefined) { transaction = { proposalId: event.attemptId, events: [] }; transactions.set(event.attemptId, transaction) }
    transaction.events.push({ id: event.id, proposalId: event.attemptId, eventOrdinal: Number(event.id.slice(event.id.lastIndexOf(':') + 1)),
      topic: event.topic, payload: event.payload, origin: { kind: 'peer-generation', authorId: event.author, operationId: event.operationId } })
  }
  return { transactions: [...transactions.values()], scannedThrough: batch.cursor, hasMore: batch.hasMore, revision: JSON.stringify(batch.revision) }
}

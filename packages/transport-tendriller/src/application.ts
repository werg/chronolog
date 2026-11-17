import {
  decodeLocalSqlValue, encodeLocalSqlParameters,
  type ChronologClient, type DecodedLocalSqlValue, type LocalSqlInput,
} from '@chronolog/client'
import type { ChronologNode } from '@chronolog/node-core'
import { emit, program, type ChangeProgram, type EventPayload, type ApplicationChangeOptions } from '@chronolog/protocol'
import { ChangeSignal } from '@chronolog/records'
import {
  assertApplicationOperationId, applicationSelection,
  type ApplicationBackend, type ApplicationOperation, type ApplicationReadView,
  type ApplicationEventReadOptions, type ApplicationEventBatch, type ApplicationSubmitOptions,
} from '@tendriller/core/application'

/** Both native and RPC sources expose the same primitive query rows to a page. */
export interface ChronologApplicationQuery {
  readonly revision: string
  readonly columns: readonly { readonly name: string; readonly declaredType?: string }[]
  readonly rows: readonly (readonly DecodedLocalSqlValue[])[]
  readonly truncated: boolean
}
export type ChronologApplicationBackend = ApplicationBackend<ChangeProgram, ApplicationOperation, ChronologApplicationQuery, LocalSqlInput>
export type NodeApplicationSource = Pick<ChronologNode, 'publish' | 'operation' | 'revisions' | 'revision' | 'readView' | 'events' | 'changes'>
export type ClientApplicationSource = Pick<ChronologClient, 'submit' | 'operations' | 'readView' | 'events' | 'changes'>

interface OperationState {
  readonly operationId: string
  readonly proposalId: string
  readonly final: boolean
  readonly outcome: {
    readonly outcome: 'accepted' | 'rejected'
    readonly rejectionCode: string | null
    readonly failingStatementIndex: number | null
  } | null
}
function operation(value: OperationState): ApplicationOperation {
  const result = value.outcome
  // A speculative rejection can change under replay; never render it as final.
  return {
    operationId: value.operationId, proposalId: value.proposalId,
    status: value.final && result !== null ? 'final'
      : result === null ? 'queued' : 'provisional',
    ...(result === null ? {} : { outcome: result.outcome }),
    ...(result?.rejectionCode == null ? {} : { error: result.rejectionCode,
      message: result.failingStatementIndex === null ? result.rejectionCode : `${result.rejectionCode} at program step ${result.failingStatementIndex}` }),
  }
}
function nodeSource(replica: NodeApplicationSource | ClientApplicationSource): replica is NodeApplicationSource {
  return 'publish' in replica
}

/**
 * No host request, replay queue, signing key, membership decision or SQL translator
 * lives here. The selected Chronolog replica remains the sole application owner.
 * `sql` describes the selected execution profile and grants no permission.
 */
export function createChronologApplicationBackend(options: {
  readonly id: string
  readonly replica: NodeApplicationSource | ClientApplicationSource
  readonly sql: boolean
}): ChronologApplicationBackend {
  const { id, replica, sql: supportsSql } = options
  if (typeof supportsSql !== 'boolean') throw new TypeError('Describe the selected SQL execution profile explicitly')
  applicationSelection({ kind: 'peer', id })
  const get = async (operationId: string): Promise<ApplicationOperation | null> => {
    assertApplicationOperationId(operationId)
    const state = await (nodeSource(replica) ? replica.operation(operationId) : replica.operations.get(operationId))
    return state === null ? null : operation(state)
  }
  const submit: ChronologApplicationBackend['submit'] = async (change, submitOptions) => {
    const operationId = assertApplicationOperationId(submitOptions.operationId)
    if (nodeSource(replica)) {
      const receipt = await replica.publish({ program: change, operationId })
      return await get(operationId) ?? { operationId, proposalId: receipt.txIdText, status: 'queued' }
    }
    const receipt = await replica.submit(change, { operationId })
    try { return await get(operationId) ?? { operationId, proposalId: receipt.proposalId, status: 'queued' } }
    finally { receipt.dispose() }
  }
  const observeOperation = async function* ({ operationId, signal }: { readonly operationId: string; readonly signal?: AbortSignal }): AsyncIterable<ApplicationOperation> {
    assertApplicationOperationId(operationId)
    if (signal?.aborted === true) return
    if (!nodeSource(replica)) {
      for await (const state of replica.operations.subscribe({ operationId, ...(signal === undefined ? {} : { signal }) })) {
        const current = operation(state)
        yield current
        if (current.status === 'final') return
      }
      return
    }
    // Revision notifications are only wake hints. Drain them independently of a
    // slow observer and re-read one current operation; retain no per-revision queue.
    const changed = new ChangeSignal(), abort = new AbortController()
    const cancel = (): void => abort.abort(signal?.reason)
    signal?.addEventListener('abort', cancel, { once: true })
    const source = replica.revisions(replica.revision, abort.signal)
    let ended = false, failure: unknown
    const watch = (async () => {
      try { for await (const _revision of source) changed.notify() }
      catch (error) { failure = error }
      finally { ended = true; changed.close() }
    })()
    let previous: string | undefined
    try {
      while (!abort.signal.aborted) {
        const version = changed.version, current = await get(operationId)
        const encoded = JSON.stringify(current)
        if (current !== null && encoded !== previous) { previous = encoded; yield current }
        if (current?.status === 'final') return
        if (ended) { if (failure !== undefined) throw failure instanceof Error ? failure : new Error('Operation revision stream failed', { cause: failure }); return }
        await changed.wait(version, abort.signal)
      }
    } finally {
      abort.abort(); signal?.removeEventListener('abort', cancel)
      await watch
    }
  }
  const subscribe: ChronologApplicationBackend['operations']['subscribe'] = (options) => ({ [Symbol.asyncIterator]() {
    const stop = new AbortController()
    const signal = options.signal === undefined ? stop.signal : AbortSignal.any([stop.signal, options.signal])
    const iterator = observeOperation({ operationId: options.operationId, signal })[Symbol.asyncIterator]()
    return {
      async next() {
        try { return await iterator.next() }
        catch (error) { if (stop.signal.aborted) return { done: true as const, value: undefined }; throw error }
      },
      async return() { stop.abort(); await iterator.return?.(); return { done: true as const, value: undefined } },
      async throw(error: unknown) { stop.abort(error); await iterator.return?.(); throw error },
    }
  } })
  const wrapView = (view: { readonly view: 'local' | 'final'; readonly revision: string; readonly finalRevision: string;
      readEvents(options?: ApplicationEventReadOptions): ApplicationEventBatch | Promise<ApplicationEventBatch>; release(): void | Promise<void> },
    query: (sql: string, parameters: readonly LocalSqlInput[]) => Promise<ChronologApplicationQuery>): ApplicationReadView<ChronologApplicationQuery, LocalSqlInput> => {
    let released = false
    const assertHeld = (): void => { if (released) throw new Error('APPLICATION_VIEW_RELEASED') }
    return Object.freeze({ view: view.view, revision: view.revision, finalRevision: view.finalRevision,
      async query(sql: string, parameters: readonly LocalSqlInput[] = []) {
        assertHeld()
        if (!supportsSql) throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE')
        return query(sql, parameters)
      },
      readEvents(readOptions?: ApplicationEventReadOptions) { assertHeld(); return view.readEvents(readOptions) },
      async release() { if (released) return; released = true; await view.release() },
    })
  }
  return Object.freeze({
    id, capabilities: Object.freeze([...(supportsSql ? ['sql'] : []), 'events', 'conversation', 'revision-views', 'operation-status']),
    submit,
    changes: (changeOptions: ApplicationChangeOptions = {}) => replica.changes(changeOptions),
    events: Object.freeze({
      publish: (topic: string, payload: unknown, submitOptions: ApplicationSubmitOptions) => submit(program(emit(topic, payload as EventPayload)), submitOptions),
      read: (readOptions: ApplicationEventReadOptions = {}) => replica.events.read(readOptions),
      subscribe: (readOptions: ApplicationEventReadOptions = {}) => replica.events.subscribe(readOptions),
    }),
    operations: Object.freeze({ get, subscribe }),
    async readView(readOptions: { readonly view?: 'local' | 'final' } = {}) {
      if (nodeSource(replica)) {
        const view = await replica.readView(readOptions)
        return wrapView(view, async (sql, parameters) => {
          const result = view.query(sql, encodeLocalSqlParameters(parameters))
          return { revision: view.revision, columns: result.columns, rows: result.rows.map(row => row.map(decodeLocalSqlValue)), truncated: false }
        })
      }
      const view = await replica.readView(readOptions)
      return wrapView(view, async (sql, parameters) => {
        const result = await view.query(sql, parameters)
        return { revision: view.revision, columns: result.columns, rows: result.rows, truncated: result.truncated }
      })
    },
  })
}

import { awaitOwnedTask } from './lifetime.js'
import type { AppliedResult, OperationState, PeerRevision } from '@chronolog/peer-generation'

export type OperationLifecycleState = 'recorded' | 'submitted' | 'applied' | 'rejected' | 'unknown'

export interface OperationLifecycleSummary {
  readonly operationId: string
  readonly lifecycle: OperationLifecycleState
  readonly status: OperationState['status'] | 'unknown'
  readonly outcome: 'accepted' | 'rejected' | null
  readonly sequence: number | null
  readonly generation: string | null
  readonly errorCode: string | null
  readonly reason: string | null
  readonly safeToReconcile: boolean
}

export interface BatchCommandEntry {
  readonly operationId: string
  readonly command: string
  readonly input: unknown
  readonly basedOn?: PeerRevision
}

export interface BatchCommandResult {
  readonly operationId: string
  readonly command: string
  readonly lifecycle: OperationLifecycleState
  readonly applied: AppliedResult | null
  readonly state: OperationState | null
  readonly error: { readonly code: string; readonly message: string } | null
}

export interface BatchSubmitOptions {
  readonly wait?: 'applied' | 'recorded'
  readonly signal?: AbortSignal
  readonly stopOnError?: boolean
  /** Optional durable pre-submission persistence hook called before each command transmits. */
  readonly beforeSubmit?: (entry: BatchCommandEntry) => void | Promise<void>
}

export interface ErgonomicSession {
  readonly signal?: AbortSignal
  readonly applicationId: string
  readonly deviceId: string
  readonly historyId?: string
  readonly status?: unknown
  query(name: string, input: unknown): Promise<{ readonly revision: PeerRevision; readonly value: unknown }>
  command(name: string, input: unknown, options: { readonly operationId: string; readonly basedOn?: PeerRevision }): Promise<{
    get(): Promise<OperationState | null>
    applied(options?: { readonly signal?: AbortSignal }): Promise<AppliedResult>
  }>
  readonly operations: {
    get(operationId: string, options?: { readonly author?: string }): Promise<OperationState | null>
    inspect(operationId: string, options?: { readonly author?: string }): Promise<{ readonly state: OperationState; readonly attempt: unknown } | null>
  }
  close?(): Promise<void> | void
}

/**
 * Map Chronolog's exact operation journal state and optional transport error into
 * the canonical five-state lifecycle envelope without conflating recorded/submitted with applied.
 */
export function describeOperationLifecycle(
  operationId: string,
  state: OperationState | null | undefined,
  options: { readonly transmitted?: boolean; readonly error?: unknown } = {},
): OperationLifecycleSummary {
  if (state === null || state === undefined) {
    const err = options.error as { code?: unknown; message?: unknown } | undefined
    return Object.freeze({
      operationId,
      lifecycle: 'unknown',
      status: 'unknown',
      outcome: null,
      sequence: null,
      generation: null,
      errorCode: typeof err?.code === 'string' ? err.code : null,
      reason: typeof err?.message === 'string' ? err.message : 'Operation outcome is not yet observed; inspect again by operationId.',
      safeToReconcile: true,
    })
  }
  if (state.status === 'applied') {
    const rejected = state.outcome === 'rejected'
    return Object.freeze({
      operationId,
      lifecycle: rejected ? 'rejected' : 'applied',
      status: 'applied',
      outcome: state.outcome,
      sequence: state.sequence,
      generation: state.generation,
      errorCode: rejected ? (state.rejectionCode ?? 'COMMAND_REJECTED') : null,
      reason: rejected ? (state.rejectionCode ?? 'Command rejected by application guard.') : null,
      safeToReconcile: false,
    })
  }
  if (state.status === 'saved') {
    return Object.freeze({
      operationId,
      lifecycle: options.transmitted === true ? 'submitted' : 'recorded',
      status: 'saved',
      outcome: null,
      sequence: null,
      generation: state.generation,
      errorCode: null,
      reason: null,
      safeToReconcile: true,
    })
  }
  // abandoned or needsReapply
  return Object.freeze({
    operationId,
    lifecycle: 'rejected',
    status: state.status,
    outcome: null,
    sequence: null,
    generation: state.generation,
    errorCode: state.status === 'abandoned' ? 'OPERATION_ABANDONED' : 'OPERATION_NEEDS_REAPPLY',
    reason: state.status === 'abandoned'
      ? 'Operation was excluded by a generation recovery; review and deliberately reapply if still needed.'
      : 'Operation requires explicit review and reapplication against current state.',
    safeToReconcile: true,
  })
}

/**
 * Submit an ordered batch of idempotent commands over one session, optionally persisting
 * pre-submission outbox entries and mapping each item to its honest lifecycle state.
 */
export async function submitBatch(
  session: ErgonomicSession,
  entries: readonly BatchCommandEntry[],
  options: BatchSubmitOptions = {},
): Promise<readonly BatchCommandResult[]> {
  if (!Array.isArray(entries) || entries.length > 64) {
    throw Object.assign(new Error('Batch must contain between 0 and 64 commands.'), { code: 'BATCH_LIMIT_EXCEEDED' })
  }
  const lifetime = AbortSignal.any([...(session.signal === undefined ? [] : [session.signal]), ...(options.signal === undefined ? [] : [options.signal])])
  lifetime.throwIfAborted()
  const items = structuredClone(entries as readonly BatchCommandEntry[])
  const seen = new Set<string>()
  if (options.wait !== undefined && !['recorded', 'applied'].includes(options.wait)) throw new Error('BATCH_WAIT_INVALID')
  for (const entry of items) {
    if (entry === null || typeof entry !== 'object' || typeof entry.command !== 'string' || entry.command.length === 0 ||
        typeof entry.operationId !== 'string' || entry.operationId.length === 0 || entry.operationId.length > 512 ||
        [...entry.operationId].some(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)) {
      throw Object.assign(new Error('Each batched command requires a stable command and protocol operationId.'), { code: 'OPERATION_ID_INVALID' })
    }
    if (seen.has(entry.operationId)) throw Object.assign(new Error('Duplicate operationId in batch.'), { code: 'BATCH_DUPLICATE_OPERATION_ID' })
    seen.add(entry.operationId)
  }
  const results: BatchCommandResult[] = []
  for (const entry of items) {
    if (lifetime.aborted && results.length > 0) break
    lifetime.throwIfAborted()
    try {
      if (options.beforeSubmit !== undefined) await awaitOwnedTask(lifetime, () => options.beforeSubmit!(structuredClone(entry)))
      lifetime.throwIfAborted()
    } catch (error) {
      if (lifetime.aborted && results.length > 0) break
      throw error
    }
    let applied: AppliedResult | null = null
    try {
      const handle = await awaitOwnedTask(lifetime, () => session.command(entry.command, entry.input, {
        operationId: entry.operationId, ...(entry.basedOn === undefined ? {} : { basedOn: entry.basedOn }),
      }))
      applied = options.wait === 'recorded' ? null : await awaitOwnedTask(lifetime, () => handle.applied({ signal: lifetime }))
      const state = await awaitOwnedTask(lifetime, () => handle.get())
      const summary = describeOperationLifecycle(entry.operationId, state ?? applied)
      results.push(Object.freeze({ operationId: entry.operationId, command: entry.command, lifecycle: summary.lifecycle, applied, state, error: null }))
      if (options.stopOnError === true && (summary.lifecycle === 'rejected' || summary.lifecycle === 'unknown')) break
    } catch (error) {
      // A rejected call is not evidence that preparation/submission never happened.
      let state: OperationState | null = applied
      try { state = await awaitOwnedTask(lifetime, () => session.operations.get(entry.operationId)) ?? applied }
      catch { /* Cancellation may throw synchronously; preserve the completed batch prefix and known application. */ }
      const summary = describeOperationLifecycle(entry.operationId, state, { error })
      const err = error as { code?: unknown; message?: unknown } | null
      results.push(Object.freeze({ operationId: entry.operationId, command: entry.command, lifecycle: summary.lifecycle,
        applied: state?.status === 'applied' ? state : null, state,
        error: { code: typeof err?.code === 'string' ? err.code : 'OPERATION_OUTCOME_UNKNOWN',
          message: typeof err?.message === 'string' ? err.message : String(error) },
      }))
      if (lifetime.aborted || options.stopOnError === true) break
    }
  }
  return Object.freeze(results)
}

export interface UnifiedAppClient {
  readonly applicationId: string
  readonly deviceId: string
  readonly historyId: string | null
  submitCommand(entry: BatchCommandEntry, options?: { readonly wait?: 'applied' | 'recorded'; readonly signal?: AbortSignal }): Promise<BatchCommandResult>
  submitBatch(entries: readonly BatchCommandEntry[], options?: BatchSubmitOptions): Promise<readonly BatchCommandResult[]>
  inspectOperation(operationId: string): Promise<OperationLifecycleSummary>
  query(name: string, input?: unknown): Promise<{ readonly revision: PeerRevision; readonly value: unknown }>
  flush(): Promise<void>
  close(): Promise<void>
}

/**
 * Uniform five-step ergonomic client over any Chronolog peer session (native, Worker, or attached).
 */
export function createAppClient(
  session: ErgonomicSession,
  options: {
    readonly beforeSubmit?: (entry: BatchCommandEntry) => void | Promise<void>
    readonly flush?: () => void | Promise<void>
    readonly close?: () => void | Promise<void>
  } = {},
): UnifiedAppClient {
  const lifetime = new AbortController()
  const signal = AbortSignal.any([lifetime.signal, ...(session.signal === undefined ? [] : [session.signal])])
  let closing: Promise<void> | undefined
  const client: UnifiedAppClient = {
    applicationId: session.applicationId,
    deviceId: session.deviceId,
    historyId: session.historyId ?? null,
    async submitCommand(entry, callOptions = {}) {
      const [result] = await submitBatch(session, [entry], {
        ...(callOptions.wait === undefined ? {} : { wait: callOptions.wait }),
        signal: callOptions.signal === undefined ? signal : AbortSignal.any([signal, callOptions.signal]),
        ...(options.beforeSubmit === undefined ? {} : { beforeSubmit: options.beforeSubmit }),
      })
      return result!
    },
    submitBatch(entries, callOptions = {}) {
      return submitBatch(session, entries, {
        ...(options.beforeSubmit === undefined ? {} : { beforeSubmit: options.beforeSubmit }),
        ...callOptions,
        signal: callOptions.signal === undefined ? signal : AbortSignal.any([signal, callOptions.signal]),
      })
    },
    async inspectOperation(operationId) {
      const state = await awaitOwnedTask(signal, () => session.operations.get(operationId))
      return describeOperationLifecycle(operationId, state)
    },
    async query(name, input = null) {
      return awaitOwnedTask(signal, () => session.query(name, input))
    },
    async flush() {
      await awaitOwnedTask(signal, () => options.flush?.())
    },
    close() {
      lifetime.abort(new Error('APPLICATION_CLIENT_CLOSED'))
      return closing ??= Promise.resolve().then(async () => {
        if (options.close !== undefined) await options.close()
        else await session.close?.()
      })
    },
  }
  return Object.freeze(client)
}

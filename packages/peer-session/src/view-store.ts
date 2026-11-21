/** Shared session errors, canonical JSON serialization, operation references and local view storage. */
const DEFAULT_PAYLOAD_BYTES = 8192

const sessionActions: Record<string, string> = {
  OWNER_BUSY: 'Attach to the existing owner or deliberately enroll a separate profile.',
  ENDPOINT_STALE: 'Reattach and inspect the original operation before acting again.',
  RECOVERY_REVIEW_REQUIRED: 'Inspect the original operation and deliberately rebind or reapply.',
}

export class SessionError extends Error {
  readonly code: string
  readonly scope: Readonly<Record<string, unknown>>
  readonly retrySafe: boolean
  readonly nextAction: string

  constructor(code: string, message = code, scope: Readonly<Record<string, unknown>> = {}, actions: Readonly<Record<string, string>> = sessionActions) {
    super(message)
    this.name = 'SessionError'
    this.code = code
    this.scope = scope
    this.retrySafe = code === 'OWNER_BUSY' || code === 'RECIPIENT_UNAVAILABLE'
    this.nextAction = actions[code] ?? sessionActions[code] ?? 'Inspect the supplied scope and correct the request.'
  }
}

export function identifier(value: unknown, name = 'identity'): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$/u.test(value)) {
    throw new SessionError('INVALID_IDENTITY', `Invalid ${name}`)
  }
  return value
}

export function signerId(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new SessionError('INVALID_SIGNER', 'A verified signing public key is required')
  }
  return value
}

export function canonicalJson(value: unknown, maxBytes = DEFAULT_PAYLOAD_BYTES): string {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new SessionError('INVALID_PAYLOAD_LIMIT')
  let nodes = 0
  function visit(item: unknown, depth: number): string {
    if (++nodes > 4096 || depth > 24) throw new SessionError('PAYLOAD_TOO_COMPLEX')
    if (item === null || typeof item === 'boolean' || typeof item === 'string') return JSON.stringify(item)
    if (typeof item === 'number' && Number.isFinite(item)) return JSON.stringify(item)
    if (Array.isArray(item)) {
      if (Object.getPrototypeOf(item) !== Array.prototype || Reflect.ownKeys(item).length !== item.length + 1) {
        throw new SessionError('INVALID_PAYLOAD')
      }
      const children: string[] = []
      for (let index = 0; index < item.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(item, String(index))
        if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) throw new SessionError('INVALID_PAYLOAD')
        children.push(visit(descriptor.value, depth + 1))
      }
      return `[${children.join(',')}]`
    }
    if (item === null || typeof item !== 'object') {
      throw new SessionError('INVALID_PAYLOAD')
    }
    const proto: unknown = Object.getPrototypeOf(item)
    if (proto !== Object.prototype && proto !== null) {
      throw new SessionError('INVALID_PAYLOAD')
    }
    const record = item as Record<string, unknown>
    if (Reflect.ownKeys(record).length !== Object.keys(record).length) throw new SessionError('INVALID_PAYLOAD')
    return `{${Object.keys(record).sort().map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(record, key)
      if (descriptor === undefined || !('value' in descriptor)) throw new SessionError('INVALID_PAYLOAD')
      return `${JSON.stringify(key)}:${visit(descriptor.value, depth + 1)}`
    }).join(',')}}`
  }
  const encoded = visit(value, 0)
  if (new TextEncoder().encode(encoded).length > maxBytes) throw new SessionError('PAYLOAD_TOO_LARGE')
  return encoded
}

export interface OperationReference {
  readonly applicationId: string
  readonly historyId: string
  readonly author: string
  readonly operationId: string
  readonly attemptId?: string
  readonly generation?: string
}

export interface RetainedOperation {
  readonly reference: OperationReference
  readonly viewId: string
  readonly context: Readonly<Record<string, unknown>>
}

export interface ViewStorage {
  readonly length: number
  key(index: number): string | null
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export interface ViewStore<Draft = unknown> {
  readonly viewId: string
  readonly historyId?: string
  readDraft(draftId?: string): Draft | null
  writeDraft(value: Draft, draftId?: string): void
  removeDraft(draftId?: string): void
  retainOperation(reference: OperationReference, context?: Record<string, unknown>): RetainedOperation
  inspectOperation(reference: OperationReference): RetainedOperation | null
  removeOperation(reference: OperationReference): void
  pending(options?: { readonly allViews?: boolean }): readonly RetainedOperation[]
}

export function operationReference(
  session: {
    readonly applicationId?: string
    readonly id?: string
    readonly historyId?: string
    readonly deviceId: string
    readonly scopeOperationId?: (localOperationId: string) => string
  },
  operationId: string,
  state?: { readonly operationId?: string; readonly author?: string; readonly attemptId?: string; readonly generation?: string } | null,
): OperationReference {
  const applicationId = session.applicationId ?? session.id
  const historyId = session.historyId
  if (typeof applicationId !== 'string' || !applicationId || typeof historyId !== 'string' || !historyId) {
    throw new SessionError('OPERATION_SCOPE_MISMATCH', 'An attached application and verified history are required')
  }
  const author = signerId(state?.author ?? session.deviceId)
  const scopedId = author === session.deviceId && typeof session.scopeOperationId === 'function'
    ? session.scopeOperationId(operationId) : operationId
  if (state?.operationId !== undefined && state.operationId !== scopedId) {
    throw new SessionError('OPERATION_REFERENCE_CONFLICT', 'The saved state belongs to a different operation')
  }
  return Object.freeze({
    applicationId,
    historyId,
    author,
    operationId: identifier(scopedId, 'operation'),
    ...(state?.attemptId === undefined ? {} : { attemptId: state.attemptId }),
    ...(state?.generation === undefined ? {} : { generation: state.generation }),
  })
}

/** Per-key writes avoid a shared read/modify/write list that loses sibling references. */
export function createViewStore<Draft = unknown>(options: {
  readonly storage: ViewStorage
  readonly applicationId: string
  readonly historyId?: string
  readonly profileId: string
  readonly viewId: string
}): ViewStore<Draft> {
  const { storage, applicationId, historyId, profileId, viewId } = options
  if (storage === null || typeof storage !== 'object' || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function') {
    throw new SessionError('LOCAL_STORAGE_UNAVAILABLE')
  }
  identifier(applicationId)
  identifier(profileId)
  identifier(viewId)
  const segment = (value: string): string => encodeURIComponent(identifier(value))
  const hasControlChar = (value: string): boolean => {
    for (let i = 0; i < value.length; i++) {
      const code = value.charCodeAt(i)
      if (code <= 0x1f || code === 0x7f) return true
    }
    return false
  }
  const historySegment = (value: unknown): string => {
    if (typeof value !== 'string' || !value || value.length > 128 || hasControlChar(value)) {
      throw new SessionError('OPERATION_SCOPE_MISMATCH', 'A verified history identity is required')
    }
    return encodeURIComponent(value)
  }
  const prefix = `chronolog:view-store:${segment(applicationId)}:${segment(profileId)}:` +
    (historyId === undefined ? 'unbound:' : `history:${historySegment(historyId)}:`)
  const viewPrefix = `${prefix}view:${segment(viewId)}:`

  function read<Value>(key: string): Value | null {
    const value = storage.getItem(key)
    if (value === null) return null
    try { return JSON.parse(value) as Value }
    catch { throw new SessionError('LOCAL_REFERENCE_CORRUPT', 'Preserve and inspect the local record before replacing it') }
  }
  function write(key: string, value: unknown): void {
    const encoded = canonicalJson(value, 65536)
    try { storage.setItem(key, encoded) }
    catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new SessionError('LOCAL_STORAGE_UNAVAILABLE', `Could not retain the local record: ${detail}`)
    }
  }
  function operationKey(reference: OperationReference, retainedViewId = viewId): string {
    if (reference.applicationId !== applicationId || (historyId !== undefined && reference.historyId !== historyId)) {
      throw new SessionError('OPERATION_SCOPE_MISMATCH')
    }
    for (const field of ['attemptId', 'generation'] as const) {
      const digest = reference[field]
      if (digest !== undefined && (typeof digest !== 'string' || !/^[0-9a-f]{64}$/u.test(digest))) throw new SessionError('OPERATION_REFERENCE_INVALID')
    }
    return `${prefix}operation:${historySegment(reference.historyId)}:${signerId(reference.author)}:${segment(reference.operationId)}:view:${segment(retainedViewId)}`
  }

  function readRetained(key: string): RetainedOperation | null {
    const encoded = storage.getItem(key)
    if (encoded === null) return null
    try {
      const value = JSON.parse(encoded) as RetainedOperation
      if (value === null || typeof value !== 'object' || typeof value.viewId !== 'string' ||
          value.context === null || typeof value.context !== 'object' || Array.isArray(value.context) ||
          operationKey(value.reference, value.viewId) !== key) throw new Error()
      canonicalJson(value, 65536)
      return value
    } catch {
      throw new SessionError('LOCAL_REFERENCE_CORRUPT', 'Preserve and inspect the local record before replacing it')
    }
  }

  return Object.freeze({
    viewId,
    ...(historyId === undefined ? {} : { historyId }),
    readDraft(draftId = 'main'): Draft | null { return read<Draft>(`${viewPrefix}draft:${segment(draftId)}`) },
    writeDraft(value: Draft, draftId = 'main'): void { write(`${viewPrefix}draft:${segment(draftId)}`, value) },
    removeDraft(draftId = 'main'): void { storage.removeItem(`${viewPrefix}draft:${segment(draftId)}`) },
    retainOperation(reference: OperationReference, context: Record<string, unknown> = {}): RetainedOperation {
      const key = operationKey(reference)
      const existing = readRetained(key)
      if (context === null || typeof context !== 'object' || Array.isArray(context)) throw new SessionError('INVALID_PAYLOAD')
      const captured: OperationReference = { applicationId: reference.applicationId, historyId: reference.historyId,
        author: reference.author, operationId: reference.operationId,
        ...(reference.attemptId === undefined ? {} : { attemptId: reference.attemptId }),
        ...(reference.generation === undefined ? {} : { generation: reference.generation }),
      }
      const value: RetainedOperation = { reference: captured, viewId, context }
      if (existing !== null && canonicalJson(existing.context, 65536) !== canonicalJson(context, 65536)) {
        throw new SessionError('OPERATION_REFERENCE_CONFLICT', 'The original operation input must remain unchanged')
      }
      for (const field of ['attemptId', 'generation'] as const) {
        if (existing?.reference[field] !== undefined && reference[field] !== undefined && existing.reference[field] !== reference[field]) {
          throw new SessionError('OPERATION_REFERENCE_CONFLICT', 'The original signed attempt must remain unchanged')
        }
      }
      const retained: RetainedOperation = existing !== null ? { ...existing, reference: { ...captured,
        ...(existing.reference.attemptId === undefined || reference.attemptId !== undefined ? {} : { attemptId: existing.reference.attemptId }),
        ...(existing.reference.generation === undefined || reference.generation !== undefined ? {} : { generation: existing.reference.generation }),
      } } : value
      write(key, retained)
      return retained
    },
    inspectOperation(reference: OperationReference): RetainedOperation | null { return readRetained(operationKey(reference)) },
    removeOperation(reference: OperationReference): void { storage.removeItem(operationKey(reference)) },
    pending(pendingOptions: { readonly allViews?: boolean } = {}): readonly RetainedOperation[] {
      const allViews = pendingOptions.allViews ?? false
      const values: RetainedOperation[] = []
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i)
        if (key?.startsWith(`${prefix}operation:`) === true) {
          const value = readRetained(key)
          if (value !== null && (allViews || value.viewId === viewId)) values.push(value)
        }
      }
      return values.sort((a, b) => a.reference.operationId.localeCompare(b.reference.operationId))
    },
  })
}

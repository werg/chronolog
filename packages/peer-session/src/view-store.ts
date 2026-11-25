export class SessionError extends Error { constructor(readonly code: string, message = code) { super(message); this.name = 'SessionError' } }
export function canonicalJson(value: unknown, maxBytes = 8192): string {
  let nodes = 0
  const visit = (item: unknown, depth: number): string => {
    if (++nodes > 4096 || depth > 24) throw new SessionError('PAYLOAD_TOO_COMPLEX')
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return JSON.stringify(item)
    if (typeof item === 'number' && Number.isFinite(item)) return JSON.stringify(item)
    if (Array.isArray(item)) { if (Object.keys(item).length !== item.length) throw new SessionError('INVALID_PAYLOAD'); return `[${item.map(child => visit(child, depth + 1)).join(',')}]` }
    if (item === null || typeof item !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(item) as object | null)) throw new SessionError('INVALID_PAYLOAD')
    const record = item as Record<string, unknown>
    return `{${Object.keys(record).sort().map(key => { const descriptor = Object.getOwnPropertyDescriptor(item, key); if (descriptor === undefined || !('value' in descriptor)) throw new SessionError('INVALID_PAYLOAD'); return `${JSON.stringify(key)}:${visit(record[key], depth + 1)}` }).join(',')}}`
  }
  const encoded = visit(value, 0); if (new TextEncoder().encode(encoded).length > maxBytes) throw new SessionError('PAYLOAD_TOO_LARGE'); return encoded
}
export interface OperationReference { readonly applicationId: string; readonly author: string; readonly operationId: string; readonly proposalId: string }
export interface RetainedOperation { readonly reference: OperationReference; readonly viewId: string; readonly context: Readonly<Record<string, unknown>> }
export interface ViewStorage { readonly length: number; key(index: number): string | null; getItem(key: string): string | null; setItem(key: string, value: string): void; removeItem(key: string): void }
export interface ViewStore<Draft = unknown> { readonly viewId: string; readDraft(draftId?: string): Draft | null; writeDraft(value: Draft, draftId?: string): void; removeDraft(draftId?: string): void; retainOperation(reference: OperationReference, context?: Record<string, unknown>): RetainedOperation; inspectOperation(reference: OperationReference): RetainedOperation | null; removeOperation(reference: OperationReference): void; pending(options?: { readonly allViews?: boolean }): readonly RetainedOperation[] }
export function createViewStore<Draft = unknown>(options: { readonly storage: ViewStorage; readonly applicationId: string; readonly profileId: string; readonly viewId: string }): ViewStore<Draft> {
  const { storage, applicationId, profileId, viewId } = options
  const segment = (value: string): string => { if (typeof value !== 'string' || value.length === 0 || value.length > 512) throw new SessionError('INVALID_IDENTITY'); return encodeURIComponent(value) }
  const prefix = `chronolog:view:${segment(applicationId)}:${segment(profileId)}:`, draftPrefix = `${prefix}${segment(viewId)}:draft:`
  const read = <T>(key: string): T | null => { const raw = storage.getItem(key); if (raw === null) return null; try { return JSON.parse(raw) as T } catch { throw new SessionError('LOCAL_REFERENCE_CORRUPT') } }
  const operationKey = (reference: OperationReference, owner = viewId): string => { if (reference.applicationId !== applicationId || !/^[0-9a-f]{64}$/u.test(reference.author) || !/^[0-9a-f]{64}$/u.test(reference.proposalId)) throw new SessionError('OPERATION_SCOPE_MISMATCH'); return `${prefix}operation:${segment(owner)}:${reference.proposalId}` }
  return { viewId, readDraft: (id = 'default') => read<Draft>(draftPrefix + segment(id)), writeDraft(value, id = 'default') { storage.setItem(draftPrefix + segment(id), canonicalJson(value, 65536)) }, removeDraft(id = 'default') { storage.removeItem(draftPrefix + segment(id)) },
    retainOperation(reference, context) {
      const key = operationKey(reference), existing = read<RetainedOperation>(key)
      if (existing !== null) { if (canonicalJson(existing.reference) !== canonicalJson(reference) || context !== undefined && canonicalJson(existing.context, 65536) !== canonicalJson(context, 65536)) throw new SessionError('OPERATION_REFERENCE_CONFLICT'); return structuredClone(existing) }
      const value = { reference, viewId, context: context ?? {} }; storage.setItem(key, canonicalJson(value, 65536)); return structuredClone(value)
    },
    inspectOperation: reference => read<RetainedOperation>(operationKey(reference)), removeOperation(reference) { storage.removeItem(operationKey(reference)) },
    pending(input = {}) { const values: RetainedOperation[] = []; for (let i = 0; i < storage.length; i++) { const key = storage.key(i); if (key === null || !key.startsWith(`${prefix}operation:`)) continue; const value = read<RetainedOperation>(key); if (value !== null && (input.allViews === true || value.viewId === viewId)) { operationKey(value.reference, value.viewId); values.push(value) } }; return values },
  }
}

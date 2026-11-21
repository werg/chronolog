import { expect, it, vi } from 'vitest'
import { canonicalJson, createViewStore, operationReference, type OperationReference } from './view-store.js'

function fixture() {
  const data = new Map<string, string>()
  const storage = { get length() { return data.size }, key: (i: number) => [...data.keys()][i] ?? null,
    getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => { data.set(key, value) }, removeItem: (key: string) => { data.delete(key) } }
  const store = createViewStore({ storage, applicationId: 'app', historyId: 'history', profileId: 'profile', viewId: 'view' })
  const reference = { applicationId: 'app', historyId: 'history', author: 'a'.repeat(64), operationId: 'operation' }
  return { data, storage, store, reference }
}

it('canonical arrays reject accessors, sparse substitutions, hidden properties and symbols without invoking code', () => {
  const getter = vi.fn(() => 'executed'), accessor = [0]
  Object.defineProperty(accessor, '0', { get: getter, enumerable: true })
  const sparse = new Array<unknown>(1); Object.defineProperty(sparse, 'extra', { value: true, enumerable: true })
  const hidden = [1]; Object.defineProperty(hidden, 'hidden', { value: true })
  const symbol = [1]; Object.defineProperty(symbol, Symbol('hidden'), { value: true })
  for (const value of [accessor, sparse, hidden, symbol]) expect(() => canonicalJson(value)).toThrow('INVALID_PAYLOAD')
  expect(getter).not.toHaveBeenCalled(); expect(canonicalJson([null, { b: 1, a: 2 }])).toBe('[null,{"a":2,"b":1}]')
  expect(() => canonicalJson('value', Number.NaN)).toThrow('INVALID_PAYLOAD_LIMIT')
})

it('retaining an uncertain retry with absent optional proof preserves the original attempt and generation', () => {
  const f = fixture(), original = { ...f.reference, attemptId: 'b'.repeat(64), generation: 'c'.repeat(64) }
  f.store.retainOperation(original, { text: 'same input' })
  const retained = f.store.retainOperation({ ...f.reference, attemptId: undefined, generation: undefined } as unknown as OperationReference, { text: 'same input' })
  expect(retained.reference).toEqual(original)
  expect(f.store.inspectOperation(f.reference)?.reference).toEqual(original)
})

for (const corrupt of ['application', 'history', 'view', 'operation', 'context', 'attempt', 'null'] as const) {
  it(`refuses a stored operation with corrupt ${corrupt} metadata and preserves the original bytes`, () => {
    const f = fixture(); f.store.retainOperation(f.reference)
    const key = [...f.data.keys()][0]!
    const value = JSON.parse(f.data.get(key)!)
    if (corrupt === 'application') value.reference.applicationId = 'other-app'
    if (corrupt === 'history') value.reference.historyId = 'other-history'
    if (corrupt === 'view') value.viewId = 'other-view'
    if (corrupt === 'operation') value.reference.operationId = 'other-operation'
    if (corrupt === 'context') value.context = null
    if (corrupt === 'attempt') value.reference.attemptId = 42
    const encoded = JSON.stringify(corrupt === 'null' ? null : value); f.data.set(key, encoded)
    expect(() => f.store.pending({ allViews: true })).toThrow('Preserve and inspect')
    expect(() => f.store.inspectOperation(f.reference)).toThrow('Preserve and inspect')
    expect(() => f.store.retainOperation(f.reference)).toThrow('Preserve and inspect')
    expect(f.data.get(key)).toBe(encoded)
  })
}

it('separates payload validation failures from storage write failures', () => {
  const f = fixture()
  expect(() => f.store.writeDraft({ bad: undefined })).toThrow('INVALID_PAYLOAD')
  f.storage.setItem = () => { throw Error('quota exceeded') }
  expect(() => f.store.writeDraft({ valid: true })).toThrow('Could not retain the local record: quota exceeded')
})


it('references and local storage preserve printable 512-character operation identities without key collisions', () => {
  const f = fixture()
  for (const operationId of ['invoice#42', 'a'.repeat(201), 'b'.repeat(512), 'job 42 🧪', 'a/b', 'a%2Fb']) {
    const reference = operationReference({ applicationId: 'app', historyId: 'history', deviceId: f.reference.author }, operationId)
    f.store.retainOperation(reference)
    expect(f.store.inspectOperation(reference)?.reference).toEqual(reference)
  }
  expect(f.store.pending()).toHaveLength(6)
  for (const id of ['', 'x'.repeat(513), 'line\nbreak', 'bad\u007f']) {
    expect(() => operationReference({ applicationId: 'app', historyId: 'history', deviceId: f.reference.author }, id)).toThrowError(expect.objectContaining({ code: 'INVALID_IDENTITY' }))
  }
})


it('applies a view scope prefix once and retains the full protocol-sized canonical operation identity', () => {
  const f = fixture(), prefix = `view:${'v'.repeat(128)}:`
  const session = { applicationId: 'app', historyId: 'history', deviceId: f.reference.author,
    scopeOperationId: (localId: string) => prefix + localId }
  for (const local of ['local'.repeat(41), 'x'.repeat(512 - prefix.length)]) {
    const canonical = prefix + local
    const reference = operationReference(session, local, { operationId: canonical, author: session.deviceId, attemptId: 'b'.repeat(64) })
    expect(reference.operationId).toBe(canonical); expect(canonical.length).toBeGreaterThan(200)
    f.store.retainOperation(reference)
    expect(f.store.inspectOperation(reference)?.reference).toEqual(reference)
  }
  expect(f.store.pending()).toHaveLength(2)
  expect(() => operationReference(session, 'x'.repeat(513 - prefix.length))).toThrowError(expect.objectContaining({ code: 'INVALID_IDENTITY' }))
  expect(() => createViewStore({ storage: f.storage, applicationId: 'app', profileId: 'p'.repeat(201), viewId: 'v' })).toThrow('Invalid identity')
})

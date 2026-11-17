import { afterEach, expect, it, vi } from 'vitest'
import { MemoryPeerStore } from '@chronolog/peer-generation'
import { bytesDigest, createPeerIdentity, createReleaseRegistry, RELEASE_LIMITS, RELEASE_PROFILE, signReleaseActivationRequest,
  signReleaseManifest, type SignedReleaseActivation } from '@chronolog/peer-generation/control'
import { openReleaseObserver, type ApplicationReleaseObserver } from './release-observer.js'
import type { ReleaseHost } from './releases.js'

const closing: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closing.splice(0).reverse()) await close() })
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
async function fixture() {
  const control = await createPeerIdentity(), publisher = await createPeerIdentity(), applicationId = 'e7'.repeat(32)
  const files = new Map<string, Uint8Array>()
  const registry = await createReleaseRegistry({ store: new MemoryPeerStore(), applicationId, signer: control,
    content: { async *read(asset) { const value = files.get(asset.digest); if (value !== undefined) yield value } } })
  await registry.configure({ requestId: 'publisher', expectedPolicy: null, publishers: [publisher.publicKey] })
  const host: ReleaseHost = { state: () => registry.read(), manifest: id => registry.manifest(id),
    publish: value => registry.publish(value), activate: request => registry.activate(request),
    content: { async put(digest, bytes) { files.set(digest, bytes.slice()) }, async get(digest) {
      const bytes = files.get(digest); if (bytes === undefined) throw new Error('CONTENT_MISSING'); return bytes.slice()
    } } }
  const options = { applicationId, controlPublicKey: control.publicKey, host, store: new MemoryPeerStore() }
  const open = async (extra: Partial<Parameters<typeof openReleaseObserver>[0]> = {}): Promise<ApplicationReleaseObserver> => {
    const observer = await openReleaseObserver({ ...options, ...extra }); closing.push(() => observer.close()); return observer
  }
  const publish = async (name: string) => {
    const bytes = new TextEncoder().encode(`<!doctype html><title>${name}</title>`), digest = await bytesDigest(bytes)
    files.set(digest, bytes)
    const manifest = await signReleaseManifest({ profile: RELEASE_PROFILE, applicationId, scope: 'page', publisher: publisher.publicKey,
      policyRevision: 0, entry: 'index.html', application: null,
      assets: [{ path: 'index.html', digest, bytes: bytes.length, mediaType: 'text/html' }] }, publisher)
    const publication = await registry.publish(manifest)
    const activation = await registry.activate(await signReleaseActivationRequest({ profile: RELEASE_PROFILE, applicationId,
      publisher: publisher.publicKey, policyRevision: 0, requestId: name,
      expectedActivation: (await registry.read()).activations.at(-1)?.id ?? null, releaseId: publication.id }, publisher))
    return { ...publication, activation, bytes, digest }
  }
  return { options, registry, host, files, open, publish }
}

it('observes signed public code without a device, verifies bytes, and reopens under one owner', async () => {
  const f = await fixture(), calls = vi.spyOn(f.host, 'state'), observer = await f.open()
  expect((await observer.state()).selection).toBeNull()
  expect(calls).toHaveBeenCalledTimes(1)
  await expect(f.open()).rejects.toThrow('RELEASE_OBSERVER_IN_USE')
  const first = await f.publish('first'), observation = await observer.refresh()
  expect(observation.selection).toEqual({ activation: first.activation, manifest: first.manifest })
  expect(calls).toHaveBeenCalledTimes(2)
  const get = vi.spyOn(f.host.content, 'get')
  await observer.close()
  const reopened = await f.open()
  expect((await reopened.state()).selection).toEqual(observation.selection)
  expect(get).toHaveBeenCalledTimes(1)
  expect(calls).toHaveBeenCalledTimes(2)
  await reopened.close()
  await expect(f.open({ controlPublicKey: '12'.repeat(32) })).rejects.toThrow('RELEASE_OBSERVER_BINDING_MISMATCH')
})

it('retains a newer signed activation and refuses stale bootstrap or refresh after reopen', async () => {
  const f = await fixture(), first = await f.publish('first'), observer = await f.open()
  const old = await f.registry.read(), second = await f.publish('second')
  expect((await observer.refresh()).selection?.activation).toEqual(second.activation)
  vi.spyOn(f.host, 'state').mockResolvedValue(old)
  await expect(observer.refresh()).rejects.toThrow('RELEASE_STATE_REGRESSION')
  await observer.close()
  await expect(f.open({ initial: { state: old, manifest: first.manifest } })).rejects.toThrow('RELEASE_STATE_REGRESSION')
  const reopened = await f.open()
  expect((await reopened.state()).selection?.activation).toEqual(second.activation)
  await expect(reopened.refresh()).rejects.toThrow('RELEASE_STATE_REGRESSION')
})

it('persists learned controls before missing or corrupt content and exposes no applicable selection', async () => {
  const f = await fixture(), observer = await f.open(), old = await f.registry.read(), selected = await f.publish('selected')
  f.files.delete(selected.digest)
  await expect(observer.refresh()).rejects.toThrow('CONTENT_MISSING')
  expect(await observer.state()).toEqual({ state: await f.registry.read(), selection: null })
  vi.spyOn(f.host, 'state').mockResolvedValueOnce(old)
  await expect(observer.refresh()).rejects.toThrow('RELEASE_STATE_REGRESSION')
  f.files.set(selected.digest, new Uint8Array(selected.bytes.length))
  await expect(observer.refresh()).rejects.toThrow('RELEASE_CONTENT_DIGEST_MISMATCH')
  expect((await observer.state()).selection).toBeNull()
  f.files.set(selected.digest, selected.bytes)
  const manifest = vi.spyOn(f.host, 'manifest').mockResolvedValueOnce({ ...selected.manifest, signature: '00'.repeat(64) })
  await expect(observer.refresh()).rejects.toThrow('PEER_SIGNATURE_INVALID')
  expect((await observer.state()).selection).toBeNull()
  manifest.mockRestore()
  expect((await observer.refresh()).selection?.activation).toEqual(selected.activation)
})

it('checks signed watch hints against the complete state and owns cancellation of a blocked reader', async () => {
  const f = await fixture(), observer = await f.open(), selected = await f.publish('selected')
  const bad = { ...selected.activation, signature: '00'.repeat(64) }
  f.host.watch = () => ({ async *[Symbol.asyncIterator]() { yield bad } })
  await expect(observer.watch()[Symbol.asyncIterator]().next()).rejects.toThrow('RELEASE_ANNOUNCEMENT_MISMATCH')
  f.host.watch = () => ({ async *[Symbol.asyncIterator]() { yield selected.activation } })
  const valid = observer.watch()[Symbol.asyncIterator]()
  expect((await valid.next()).value?.selection?.activation).toEqual(selected.activation)
  await valid.return?.()

  const entered = deferred<void>(), stopped = vi.fn(async () => ({ done: true as const, value: undefined }))
  let received: AbortSignal | undefined
  f.host.watch = options => ({ [Symbol.asyncIterator]() { received = options?.signal; return {
    next: () => { entered.resolve(); return new Promise<IteratorResult<SignedReleaseActivation>>(() => undefined) }, return: stopped,
  } } })
  const abort = new AbortController(), stream = observer.watch({ signal: abort.signal })[Symbol.asyncIterator]()
  const pending = stream.next(), rejected = expect(pending).rejects.toThrow('observer-read-cancelled')
  await entered.promise; abort.abort(new Error('observer-read-cancelled')); await rejected
  expect(received?.aborted).toBe(true); expect(stopped).toHaveBeenCalledTimes(1)
  expect((await observer.state()).selection?.activation).toEqual(selected.activation)
})

it('keeps initial durable writes owned until abort cleanup has observed their completion', async () => {
  const f = await fixture(), entered = deferred<void>(), release = deferred<void>(), put = f.options.store.put.bind(f.options.store)
  vi.spyOn(f.options.store, 'put').mockImplementation(async (key, value) => { entered.resolve(); await release.promise; await put(key, value) })
  const abort = new AbortController(), opening = f.open({ signal: abort.signal })
  const rejected = expect(opening).rejects.toThrow('stop-initial-write')
  await entered.promise; abort.abort(new Error('stop-initial-write'))
  await expect(f.open()).rejects.toThrow('RELEASE_OBSERVER_IN_USE')
  release.resolve(); await rejected
  const reopened = await f.open()
  expect((await reopened.state()).state).toEqual(await f.registry.read())
})

it('fences an ambiguous local write and reloads its committed monotonic head', async () => {
  const f = await fixture(), observer = await f.open(), old = await f.registry.read(), selected = await f.publish('selected')
  const put = f.options.store.put.bind(f.options.store)
  vi.spyOn(f.options.store, 'put').mockImplementationOnce(async (key, value) => { await put(key, value); throw new Error('OBSERVER_ACK_LOST') })
  await expect(observer.refresh()).rejects.toThrow('OBSERVER_ACK_LOST')
  await expect(observer.state()).rejects.toThrow('OBSERVER_ACK_LOST')
  await observer.close()
  const reopened = await f.open()
  expect((await reopened.state()).selection?.activation).toEqual(selected.activation)
  vi.spyOn(f.host, 'state').mockResolvedValue(old)
  await expect(reopened.refresh()).rejects.toThrow('RELEASE_STATE_REGRESSION')
})

it('cancels content verification without yielding an applicable selection or losing the learned head', async () => {
  const f = await fixture(), observer = await f.open(), selected = await f.publish('selected'), entered = deferred<void>()
  let received: AbortSignal | undefined
  const get = vi.spyOn(f.host.content, 'get').mockImplementation((_id, options) => {
    received = options?.signal; entered.resolve(); return new Promise<Uint8Array>(() => undefined)
  })
  const abort = new AbortController(), refreshing = observer.refresh({ signal: abort.signal })
  const rejected = expect(refreshing).rejects.toThrow('stop-content-read')
  await entered.promise; abort.abort(new Error('stop-content-read')); await rejected
  expect(received?.aborted).toBe(true)
  expect((await observer.state()).selection).toBeNull()
  expect((await observer.state()).state.activations.at(-1)).toEqual(selected.activation)
  get.mockRestore()
  expect((await observer.refresh()).selection?.activation).toEqual(selected.activation)
})

it('propagates the total verification deadline to the active content request', async () => {
  const f = await fixture(), observer = await f.open(), selected = await f.publish('selected'), entered = deferred<void>()
  let received: AbortSignal | undefined
  vi.spyOn(f.host.content, 'get').mockImplementation((_id, options) => {
    received = options?.signal; entered.resolve(); return new Promise<Uint8Array>(() => undefined)
  })
  vi.useFakeTimers()
  try {
    const refreshing = observer.refresh(), rejected = expect(refreshing).rejects.toThrow('RELEASE_CONTENT_TIMEOUT')
    await entered.promise
    await vi.advanceTimersByTimeAsync(RELEASE_LIMITS.verificationMs)
    await rejected
    expect(received?.aborted).toBe(true)
    expect(received?.reason.message).toBe('RELEASE_CONTENT_TIMEOUT')
    expect((await observer.state()).selection).toBeNull()
    expect((await observer.state()).state.activations.at(-1)).toEqual(selected.activation)
  } finally { vi.useRealTimers() }
})

import { afterEach, expect, it, vi } from 'vitest'
import { MemoryPeerStore } from '@chronolog/peer-generation'
import { bytesDigest, createPeerIdentity, createReleaseRegistry, peerDigest, RELEASE_PROFILE,
  type ReleaseState, type SignedReleaseActivation } from '@chronolog/peer-generation/control'
import { openApplicationDevice } from './device.js'
import { createReleasePublisher, openReleasePublisher, type ApplicationReleasePublisher, type ReleaseHost } from './releases.js'
import { consumerFixture } from './consumers/test-support.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const encoded = (value: string): Uint8Array => new TextEncoder().encode(value)
const sources = (label = 'first') => ({ operationId: label, entry: 'index.html', assets: [
  { path: 'index.html', mediaType: 'text/html', bytes: encoded(`<!doctype html><title>${label}</title>`) },
  { path: 'assets/data.bin', mediaType: 'application/octet-stream', bytes: new Uint8Array([0, 255, 13, 10, 128]) },
] })
function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}
async function fixture() {
  const signer = await createPeerIdentity(), store = new MemoryPeerStore(), applicationId = 'ef'.repeat(32)
  const device = await openApplicationDevice({ store, create: true }), files = new Map<string, Uint8Array>()
  const registry = await createReleaseRegistry({ store: new MemoryPeerStore(), signer, applicationId,
    content: { async *read(asset) { const bytes = files.get(asset.digest); if (bytes !== undefined) yield bytes } } })
  const policy = await registry.configure({ requestId: 'initial', expectedPolicy: null, publishers: [device.identity.publicKey] })
  const host: ReleaseHost = { state: () => registry.read(), publish: value => registry.publish(value),
    manifest: id => registry.manifest(id), activate: request => registry.activate(request),
    content: { async put(digest, bytes) { expect(await bytesDigest(bytes)).toBe(digest); files.set(digest, bytes.slice()) },
      async get(digest) { const bytes = files.get(digest); if (bytes === undefined) throw new Error('CONTENT_MISSING'); return bytes.slice() } } }
  const publisher = await openReleasePublisher({ device, applicationId, controlPublicKey: signer.publicKey, host })
  cleanup.push(() => publisher.close())
  const reopen = async (): Promise<ApplicationReleasePublisher> => {
    await publisher.close()
    const next = await openReleasePublisher({ device: await openApplicationDevice({ store }), applicationId, controlPublicKey: signer.publicKey, host })
    cleanup.push(() => next.close()); return next
  }
  return { signer, store, applicationId, device, files, registry, policy, host, publisher, reopen }
}

it('stages immutable authored bytes, reopens offline, and learns its signed activation', async () => {
  const f = await fixture(), input = sources(), preparing = f.publisher.prepare(input)
  input.assets[0]!.bytes.fill(0)
  const prepared = await preparing
  expect(f.files.size).toBe(0)
  vi.spyOn(f.host, 'state').mockRejectedValue(new Error('HOST_OFFLINE'))
  const reopened = await f.reopen()
  expect(await reopened.inspect('first')).toEqual(prepared)
  expect(await reopened.publish('first')).toEqual({ id: prepared.id, manifest: prepared.manifest })
  expect([...f.files.values()]).toContainEqual(sources().assets[0]!.bytes)
  expect([...f.files.values()]).toContainEqual(sources().assets[1]!.bytes)
  const activation = await reopened.activate(prepared.id, { requestId: 'select-first', expectedActivation: null })
  expect((await reopened.state()).activations).toEqual([activation])
  expect(await reopened.inspectActivation('select-first')).toEqual({ request: activation.payload.request, result: activation })
})

it('retains the exact signed request after a committed host reply is lost and retries after reopen', async () => {
  const f = await fixture(), prepared = await f.publisher.prepare(sources())
  await f.publisher.publish('first')
  const activate = f.host.activate.bind(f.host); let first = true
  const requests: unknown[] = []
  vi.spyOn(f.host, 'activate').mockImplementation(async request => {
    requests.push(structuredClone(request)); const result = await activate(request)
    if (first) { first = false; throw new Error('HOST_REPLY_LOST') }
    return result
  })
  await expect(f.publisher.activate(prepared.id, { requestId: 'uncertain', expectedActivation: null })).rejects.toThrow('HOST_REPLY_LOST')
  const saved = await f.publisher.inspectActivation('uncertain')
  expect(saved?.result).toBeNull()
  const selected = (await f.registry.read()).activations[0]!
  const reopened = await f.reopen()
  expect(await reopened.retry('uncertain')).toEqual(selected)
  expect(requests).toEqual([saved!.request, saved!.request])
  await expect(reopened.activate('12'.repeat(32), { requestId: 'uncertain', expectedActivation: null })).rejects.toThrow('RELEASE_ACTIVATION_REQUEST_REUSED')
  expect((await f.registry.read()).activations).toHaveLength(1)
})

it('keeps acknowledged outcomes offline after revocation and refuses new publisher work', async () => {
  const f = await fixture(), prepared = await f.publisher.prepare(sources())
  await f.publisher.publish('first')
  const selected = await f.publisher.activate(prepared.id, { requestId: 'selected', expectedActivation: null })
  await f.registry.configure({ requestId: 'revoke', expectedPolicy: await peerDigest(f.policy), publishers: [] })
  await f.publisher.refresh()
  vi.spyOn(f.host, 'activate').mockRejectedValue(new Error('HOST_OFFLINE'))
  vi.spyOn(f.host, 'publish').mockRejectedValue(new Error('HOST_OFFLINE'))
  vi.spyOn(f.host.content, 'put').mockRejectedValue(new Error('HOST_OFFLINE'))
  expect(await f.publisher.retry('selected')).toEqual(selected)
  expect(await f.publisher.publish('first')).toEqual({ id: prepared.id, manifest: prepared.manifest })
  expect(await f.publisher.prepare(sources())).toMatchObject({ id: prepared.id, status: 'published' })
  await expect(f.publisher.prepare(sources('new'))).rejects.toThrow('RELEASE_PUBLISHER_DENIED')
  await expect(f.publisher.activate(prepared.id, { requestId: 'new', expectedActivation: selected.id })).rejects.toThrow('RELEASE_PUBLISHER_DENIED')
})

it('rejects a signed state rollback after an acknowledged activation, including after reopen', async () => {
  const f = await fixture(), old = await f.registry.read(), prepared = await f.publisher.prepare(sources())
  await f.publisher.publish('first')
  const selected = await f.publisher.activate(prepared.id, { requestId: 'select', expectedActivation: null })
  vi.spyOn(f.host, 'state').mockResolvedValue(old)
  await expect(f.publisher.refresh()).rejects.toThrow('RELEASE_STATE_REGRESSION')
  const reopened = await f.reopen()
  await expect(reopened.refresh()).rejects.toThrow('RELEASE_STATE_REGRESSION')
  expect((await reopened.state()).activations).toEqual([selected])
})

it('rejects changed prepared operations and corrupt staged content before transmission', async () => {
  const f = await fixture(), prepared = await f.publisher.prepare(sources())
  await expect(f.publisher.prepare({ ...sources('changed'), operationId: 'first' })).rejects.toThrow('RELEASE_OPERATION_ID_REUSED')
  const asset = prepared.manifest.payload.assets[0]!
  await f.store.put(`peer-session/releases/v1/${f.applicationId}/${f.device.identity.publicKey}/content/${asset.digest}/0`, new Uint8Array(asset.bytes))
  await expect(f.publisher.publish('first')).rejects.toThrow('RELEASE_STAGED_CONTENT_CORRUPT')
  expect(f.files.size).toBe(0)
  expect(await f.registry.manifest(prepared.id)).toBeNull()
})

it('cancels a pending host response on close without losing the recoverable activation request', async () => {
  const f = await fixture(), prepared = await f.publisher.prepare(sources()), entered = deferred()
  await f.publisher.publish('first')
  let receivedSignal: AbortSignal | undefined
  vi.spyOn(f.host, 'activate').mockImplementation((_request, options) => {
    receivedSignal = options?.signal; entered.resolve()
    return new Promise<SignedReleaseActivation>(() => undefined)
  })
  const pending = f.publisher.activate(prepared.id, { requestId: 'pending', expectedActivation: null })
  const rejection = expect(pending).rejects.toThrow('RELEASE_PUBLISHER_CLOSED')
  await entered.promise; await f.publisher.close(); await rejection
  expect(receivedSignal?.aborted).toBe(true)
  vi.spyOn(f.host, 'activate').mockImplementation(request => f.registry.activate(request))
  const reopened = await f.reopen()
  expect((await reopened.inspectActivation('pending'))?.result).toBeNull()
  expect((await reopened.retry('pending')).payload.releaseId).toBe(prepared.id)
})

it('fences ambiguous local writes until reopening reads the acknowledged disk outcome', async () => {
  const f = await fixture(), put = f.store.put.bind(f.store)
  let lose = true
  vi.spyOn(f.store, 'put').mockImplementation(async (key, bytes) => {
    await put(key, bytes)
    if (key.endsWith('/journal') && lose) { lose = false; throw new Error('JOURNAL_ACK_LOST') }
  })
  await expect(f.publisher.prepare(sources())).rejects.toThrow('JOURNAL_ACK_LOST')
  await expect(f.publisher.prepare(sources('second'))).rejects.toThrow('JOURNAL_ACK_LOST')
  expect(f.files.size).toBe(0)
  const reopened = await f.reopen(), saved = await reopened.inspect('first')
  expect(saved?.status).toBe('prepared')
  expect(await reopened.publish('first')).toEqual({ id: saved!.id, manifest: saved!.manifest })
})

it('keeps session storage owned while a publisher is still opening', async () => {
  const f = await consumerFixture(); cleanup.push(() => f.close())
  const get = f.aDevice.store.get.bind(f.aDevice.store), entered = deferred(), resume = deferred()
  vi.spyOn(f.aDevice.store, 'get').mockImplementation(async key => {
    if (key.startsWith('peer-session/releases/')) { entered.resolve(); await resume.promise }
    return get(key)
  })
  const host = { state: async (): Promise<ReleaseState> => { throw new Error('SHOULD_NOT_CONTACT_HOST') } } as ReleaseHost
  const opening = createReleasePublisher({ session: f.a, host })
  const rejected = expect(opening).rejects.toThrow()
  await entered.promise
  let closed = false
  const closing = f.a.close().then(() => { closed = true })
  await Promise.resolve(); await Promise.resolve()
  expect(closed).toBe(false)
  resume.resolve(); await rejected; await closing
  expect(closed).toBe(true)
})

it('can close the shared publisher while its application session remains usable', async () => {
  const f = await consumerFixture(); cleanup.push(() => f.close())
  const bundle = await f.registry.read(), state: ReleaseState = { profile: RELEASE_PROFILE, applicationId: f.a.applicationId,
    controlPublicKey: bundle.descriptor.payload.controlPublicKey, policies: [], activations: [] }
  const host = { state: async () => state } as ReleaseHost
  const publisher = await createReleasePublisher({ session: f.a, host })
  expect(publisher.publisherId).toBe(f.aDevice.identity.publicKey)
  await expect(createReleasePublisher({ session: f.a, host })).rejects.toThrow('RELEASE_PUBLISHER_IN_USE')
  await publisher.close()
  const view = await f.a.readView(); expect(view.readEvents().events).toEqual([]); view.release()
  expect(f.a.signal.aborted).toBe(false)
  const reopened = await createReleasePublisher({ session: f.a, host })
  cleanup.push(() => reopened.close())
  expect(await reopened.state()).toEqual(state)
})

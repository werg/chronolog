import { expect, it, vi } from 'vitest'
import {
  bytesDigest, createPeerIdentity, createReleaseRegistry, MemoryPeerStore, peerDigest, RELEASE_PROFILE,
  signReleaseActivationRequest, signReleaseManifest, type PeerStore, type ReleaseApplicationBinding,
  type ReleaseAsset, type ReleaseContentSource, type SignedReleaseManifest,
} from './index.js'

async function fixture() {
  const signer = await createPeerIdentity(), publisher = await createPeerIdentity(), other = await createPeerIdentity()
  const store = new MemoryPeerStore(), files = new Map<string, Uint8Array>(), applicationId = 'ab'.repeat(32)
  let binding: ReleaseApplicationBinding | null = null, beforeRead: (() => Promise<void>) | undefined
  const content: ReleaseContentSource = { async *read(asset) {
    await beforeRead?.()
    const bytes = files.get(asset.digest)
    if (bytes !== undefined) for (let offset = 0; offset < bytes.length; offset += 16_384) yield bytes.slice(offset, offset + 16_384)
  } }
  const options = { store, applicationId, signer, content, application: async () => binding }
  const registry = await createReleaseRegistry(options)
  const policy = await registry.configure({ requestId: 'initial', expectedPolicy: null, publishers: [publisher.publicKey, other.publicKey].sort() })
  const release = async (label: string, application: ReleaseApplicationBinding | null = binding, policyRevision = 0): Promise<SignedReleaseManifest> => {
    const bytes = new TextEncoder().encode(`<!doctype html><title>${label}</title>`), digest = await bytesDigest(bytes)
    files.set(digest, bytes)
    return signReleaseManifest({ profile: RELEASE_PROFILE, applicationId, scope: 'page', publisher: publisher.publicKey, policyRevision,
      entry: 'index.html', application, assets: [{ path: 'index.html', digest, bytes: bytes.length, mediaType: 'text/html' }] }, publisher)
  }
  const request = (id: string, releaseId: string, expectedActivation: string | null = null, policyRevision = 0, identity = publisher) =>
    signReleaseActivationRequest({ profile: RELEASE_PROFILE, applicationId, requestId: id, publisher: identity.publicKey,
      policyRevision, expectedActivation, releaseId }, identity)
  return { signer, publisher, other, store, files, applicationId, content, options, registry, policy, release, request,
    binding(value: ReleaseApplicationBinding | null) { binding = value }, beforeRead(value?: () => Promise<void>) { beforeRead = value } }
}

it('publishes complete immutable content and selects it independently of application state', async () => {
  const f = await fixture(), manifest = await f.release('first'), id = await peerDigest(manifest)
  expect(await f.registry.manifest(id)).toBeNull()
  expect(await f.registry.publish(manifest)).toEqual({ id, manifest })
  const request = await f.request('first', id), activation = await f.registry.activate(request)
  expect(activation.payload.releaseId).toBe(id)
  expect(await f.registry.publish(manifest)).toEqual({ id, manifest })
  expect(await f.registry.activate(request)).toEqual(activation)
  // Restoring a data-generation key cannot modify the separately owned release head.
  await f.store.put(`peer-generation/registry/${f.applicationId}`, new Uint8Array([1, 2, 3]))
  const reopened = await createReleaseRegistry({ ...f.options, requireExisting: true })
  expect((await reopened.read()).activations).toEqual([activation])
  expect(await reopened.activate(request)).toEqual(activation)
})

it('does not publish a partial or corrupt asset graph', async () => {
  const f = await fixture(), manifest = await f.release('complete'), asset = manifest.payload.assets[0]!, id = await peerDigest(manifest)
  const correct = f.files.get(asset.digest)!
  f.files.delete(asset.digest)
  await expect(f.registry.publish(manifest)).rejects.toThrow('RELEASE_CONTENT_INCOMPLETE')
  expect(await f.registry.manifest(id)).toBeNull()
  const corrupt = correct.slice(); corrupt[0] = corrupt[0]! ^ 1; f.files.set(asset.digest, corrupt)
  await expect(f.registry.publish(manifest)).rejects.toThrow('RELEASE_CONTENT_DIGEST_MISMATCH')
  f.files.set(asset.digest, correct)
  await f.registry.publish(manifest)
  f.files.delete(asset.digest)
  await expect(f.registry.activate(await f.request('missing', id))).rejects.toThrow('RELEASE_CONTENT_INCOMPLETE')
  expect((await f.registry.read()).activations).toEqual([])
})

it('selects exactly one racing activation and rejects changed request reuse', async () => {
  const f = await fixture(), first = await f.registry.publish(await f.release('first')), second = await f.registry.publish(await f.release('second'))
  const requests = await Promise.all([f.request('race-a', first.id), f.request('race-b', second.id)])
  const results = await Promise.allSettled(requests.map(request => f.registry.activate(request)))
  expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1)
  expect(results.find(result => result.status === 'rejected')).toMatchObject({ reason: { message: 'RELEASE_ACTIVATION_CONFLICT' } })
  const selected = (await f.registry.read()).activations[0]!
  await expect(f.registry.activate(await f.request(selected.payload.request.payload.requestId,
    selected.payload.releaseId === first.id ? second.id : first.id))).rejects.toThrow('RELEASE_ACTIVATION_REQUEST_REUSED')
  expect((await f.registry.read()).activations).toHaveLength(1)
})

it('keeps lost durable acknowledgements retryable through restart and revocation', async () => {
  const f = await fixture(), release = await f.registry.publish(await f.release('first')), request = await f.request('uncertain', release.id)
  const put = f.store.put.bind(f.store); let fail = true
  vi.spyOn(f.store, 'put').mockImplementation(async (key, value) => {
    await put(key, value)
    if (key.endsWith('/head') && fail) { fail = false; throw new Error('LOST_ACKNOWLEDGEMENT') }
  })
  await expect(f.registry.activate(request)).rejects.toThrow('LOST_ACKNOWLEDGEMENT')
  const reopened = await createReleaseRegistry({ ...f.options, requireExisting: true })
  const activation = (await reopened.read()).activations[0]!
  const frozen = await reopened.configure({ requestId: 'revoke', expectedPolicy: await peerDigest(f.policy), publishers: [] })
  expect(await reopened.activate(request)).toEqual(activation)
  await expect(reopened.activate(await f.request('new-after-revoke', release.id, activation.id, frozen.payload.revision)))
    .rejects.toThrow('RELEASE_PUBLISHER_DENIED')
  expect((await reopened.read()).activations).toHaveLength(1)
})

it('allows revocation while bytes are being read and rechecks it before publishing', async () => {
  const f = await fixture(), manifest = await f.release('staged')
  let entered!: () => void, resume!: () => void
  const started = new Promise<void>(resolve => { entered = resolve }), waiting = new Promise<void>(resolve => { resume = resolve })
  f.beforeRead(async () => { entered(); await waiting })
  const publication = f.registry.publish(manifest)
  await started
  await f.registry.configure({ requestId: 'revoke-during-copy', expectedPolicy: await peerDigest(f.policy), publishers: [] })
  resume()
  await expect(publication).rejects.toThrow('RELEASE_POLICY_CHANGED')
  expect(await f.registry.manifest(await peerDigest(manifest))).toBeNull()
})

it('rechecks activation authority and CAS after content verification', async () => {
  const f = await fixture(), release = await f.registry.publish(await f.release('staged'))
  let entered!: () => void, resume!: () => void
  const started = new Promise<void>(resolve => { entered = resolve }), waiting = new Promise<void>(resolve => { resume = resolve })
  f.beforeRead(async () => { entered(); await waiting })
  const activation = f.registry.activate(await f.request('activate', release.id))
  await started
  await f.registry.configure({ requestId: 'revoke-during-activation', expectedPolicy: await peerDigest(f.policy), publishers: [] })
  resume()
  await expect(activation).rejects.toThrow('RELEASE_POLICY_CHANGED')
  expect((await f.registry.read()).activations).toEqual([])
})

it('requires a fresh authorized activation to restore an older release', async () => {
  const f = await fixture(), first = await f.registry.publish(await f.release('first')), second = await f.registry.publish(await f.release('second'))
  const a = await f.registry.activate(await f.request('first', first.id))
  const b = await f.registry.activate(await f.request('second', second.id, a.id))
  const policy = await f.registry.configure({ requestId: 'new-publisher', expectedPolicy: await peerDigest(f.policy), publishers: [f.other.publicKey] })
  const rollback = await f.registry.activate(await f.request('reviewed-rollback', first.id, b.id, policy.payload.revision, f.other))
  expect(rollback.payload.revision).toBe(2)
  expect(rollback.payload.previous).toBe(b.id)
  expect(rollback.payload.releaseId).toBe(first.id)
  expect(rollback.payload.request.payload.publisher).toBe(f.other.publicKey)
})

it('requires the release to name the configured application boundary', async () => {
  const f = await fixture(), shell = await f.registry.publish(await f.release('shell'))
  f.binding({ historyId: 'history', definitionDigest: 'cd'.repeat(32), executionManifestDigest: 'ef'.repeat(32), schemaDigest: null })
  await expect(f.registry.activate(await f.request('old-shell', shell.id))).rejects.toThrow('RELEASE_APPLICATION_BOUNDARY_REQUIRED')
  const current = await f.registry.publish(await f.release('current'))
  const activation = await f.registry.activate(await f.request('current', current.id))
  const changed = await f.registry.publish(await f.release('changed-engine', { historyId: 'history', definitionDigest: 'cd'.repeat(32),
    executionManifestDigest: '12'.repeat(32), schemaDigest: null }))
  await expect(f.registry.activate(await f.request('changed-engine', changed.id, activation.id))).rejects.toThrow('RELEASE_APPLICATION_BOUNDARY_REQUIRED')
  expect((await f.registry.read()).activations).toEqual([activation])
})

it('does not expose an orphan manifest after an interrupted publication', async () => {
  const f = await fixture(), value = await f.release('interrupted'), id = await peerDigest(value)
  const put = f.store.put.bind(f.store); let fail = true
  vi.spyOn(f.store, 'put').mockImplementation(async (key, bytes) => {
    if (key.endsWith('/head') && fail) { fail = false; throw new Error('HEAD_WRITE_FAILED') }
    await put(key, bytes)
  })
  await expect(f.registry.publish(value)).rejects.toThrow('HEAD_WRITE_FAILED')
  expect(await f.registry.manifest(id)).toBeNull()
  expect(await f.registry.publish(value)).toEqual({ id, manifest: value })
})

it('fails closed on missing or rolled-back control state', async () => {
  const f = await fixture(), head = `chronolog-release/${f.applicationId}/head`, old = (await f.store.get(head))!
  const release = await f.registry.publish(await f.release('first'))
  await f.registry.activate(await f.request('first', release.id))
  await f.store.put(head, old)
  await expect(f.registry.read()).rejects.toThrow('RELEASE_STATE_REGRESSION')
  const empty: PeerStore = new MemoryPeerStore()
  await expect(createReleaseRegistry({ ...f.options, store: empty, requireExisting: true })).rejects.toThrow('RELEASE_STATE_MISSING')
})

it('bounds source verification and cancels pending content reads', async () => {
  const f = await fixture(), manifest = await f.release('blocked')
  const { verifyReleaseContent } = await import('./release-verify.js')
  const controller = new AbortController(); let stopped = false, received: AbortSignal | undefined
  const content: ReleaseContentSource = { read(_asset: ReleaseAsset, options) {
    received = options?.signal
    return { [Symbol.asyncIterator]() { return { next: () => new Promise<IteratorResult<Uint8Array>>(() => undefined),
      async return() { stopped = true; return { done: true as const, value: undefined } } } } }
  } }
  const read = verifyReleaseContent(manifest, content, { signal: controller.signal })
  controller.abort(new Error('CANCEL_PUBLICATION'))
  await expect(read).rejects.toThrow('CANCEL_PUBLICATION')
  expect(received?.aborted).toBe(true); expect(stopped).toBe(true)
})

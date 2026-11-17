import {
  assertReleaseStateExtension, bytesDigest, decodePeerValue, encodePeerValue, peerDigest, RELEASE_LIMITS, RELEASE_PROFILE,
  signReleaseActivationRequest, signReleaseManifest, validateReleaseApplicationBinding, validateReleaseManifest,
  verifyReleaseActivation, verifyReleaseActivationRequest, verifyReleaseManifest, verifyReleaseState,
  type PeerIdentity, type PeerStore, type ReleaseApplicationBinding, type ReleaseAsset, type ReleasePublication,
  type ReleaseState, type ReleaseTrust, type SignedReleaseActivation, type SignedReleaseActivationRequest, type SignedReleaseManifest,
} from '@chronolog/peer-generation/control'
import { claimApplicationDevice, type ApplicationDevice } from './device.js'
import { ownSessionResource, sessionInternals } from './internals.js'
import type { ApplicationSession } from './session.js'

export * from '@chronolog/peer-generation/control'
export * from './release-observer.js'

export interface ReleaseHost {
  state(options?: { readonly signal?: AbortSignal }): Promise<ReleaseState>
  publish(manifest: SignedReleaseManifest, options?: { readonly signal?: AbortSignal }): Promise<ReleasePublication>
  manifest(id: string, options?: { readonly signal?: AbortSignal }): Promise<SignedReleaseManifest | null>
  activate(request: SignedReleaseActivationRequest, options?: { readonly signal?: AbortSignal }): Promise<SignedReleaseActivation>
  readonly content: {
    put(digest: string, bytes: Uint8Array, options?: { readonly mediaType?: string; readonly signal?: AbortSignal }): Promise<unknown>
    get(digest: string, options?: { readonly signal?: AbortSignal }): Promise<Uint8Array>
  }
  /** Explicitly opened, bounded control notifications. No polling or automatic reload. */
  watch?(options?: { readonly signal?: AbortSignal }): AsyncIterable<SignedReleaseActivation>
}
export interface ReleaseSourceAsset { readonly path: string; readonly mediaType: string; readonly bytes: Uint8Array }
export interface PrepareReleaseOptions {
  readonly operationId: string
  readonly entry: string
  readonly assets: readonly ReleaseSourceAsset[]
  readonly application?: ReleaseApplicationBinding | null
}
export interface PreparedRelease extends ReleasePublication {
  readonly operationId: string
  readonly status: 'prepared' | 'published'
}
export interface ReleaseActivationAttempt {
  readonly request: SignedReleaseActivationRequest
  /** Null means no acknowledged selection is recorded; it may already exist at the host. */
  readonly result: SignedReleaseActivation | null
}
interface Journal {
  readonly version: 1
  readonly trust: ReleaseTrust
  readonly publisher: string
  readonly state: ReleaseState
  readonly publications: readonly PreparedRelease[]
  readonly activations: readonly ReleaseActivationAttempt[]
}
interface PublisherOptions {
  readonly identity: PeerIdentity
  readonly store: PeerStore
  readonly trust: ReleaseTrust
  readonly host: ReleaseHost
  readonly application: ReleaseApplicationBinding | null
  readonly signal?: AbortSignal
  readonly owner?: { readonly signal: AbortSignal }
  readonly closing?: () => void | Promise<void>
}
const PUBLISHER_LIMITS = Object.freeze({ publications: 128, activations: 256, assets: 4096,
  contentBytes: 128 * 1024 * 1024, journalBytes: 4 * 1024 * 1024, calls: 8, watches: 4, requestMs: 30_000 })
const owners = new WeakMap<PeerStore, Set<string>>()

/** One owned release journal; it shares a session's signer without exposing it to a page. */
export class ApplicationReleasePublisher {
  readonly #options: PublisherOptions
  readonly #key: string
  readonly #prefix: string
  readonly #lifetime = new AbortController()
  readonly #stopParent: (() => void) | undefined
  #journal!: Journal
  #tail: Promise<unknown> = Promise.resolve()
  #pending = 0
  #watches = 0
  #closed: Promise<void> | undefined
  #unregister: (() => void) | undefined
  private constructor(options: PublisherOptions) {
    this.#options = options
    this.#prefix = `peer-session/releases/v1/${options.trust.applicationId}/${options.identity.publicKey}`
    this.#key = `${this.#prefix}/journal`
    if (options.signal !== undefined) {
      const abort = (): void => { void this.close().catch(() => undefined) }
      options.signal.addEventListener('abort', abort, { once: true })
      this.#stopParent = () => options.signal?.removeEventListener('abort', abort)
    }
  }
  static async open(options: PublisherOptions): Promise<ApplicationReleasePublisher> {
    let owned = owners.get(options.store)
    if (owned === undefined) { owned = new Set(); owners.set(options.store, owned) }
    if (owned.has(options.trust.applicationId)) throw new Error('RELEASE_PUBLISHER_IN_USE')
    owned.add(options.trust.applicationId)
    const publisher = new ApplicationReleasePublisher(options)
    try {
      if (options.owner !== undefined) publisher.#unregister = ownSessionResource(options.owner, publisher)
      await publisher.#run(async () => {
        options.signal?.throwIfAborted()
        const bytes = await options.store.get(publisher.#key)
        if (bytes === null) {
          const state = await verifyReleaseState(await publisher.#remote(signal => options.host.state({ signal })), options.trust)
          await publisher.#save({ version: 1, trust: options.trust, publisher: options.identity.publicKey, state, publications: [], activations: [] })
        } else {
          if (bytes.length > PUBLISHER_LIMITS.journalBytes) throw new Error('RELEASE_JOURNAL_LIMIT')
          const value = decodePeerValue<Journal>(bytes)
          if (value.version !== 1 || !same(value.trust, options.trust) || value.publisher !== options.identity.publicKey ||
            !isList(value.publications) || value.publications.length > PUBLISHER_LIMITS.publications ||
            !isList(value.activations) || value.activations.length > PUBLISHER_LIMITS.activations) throw new Error('RELEASE_JOURNAL_INVALID')
          await verifyReleaseState(value.state, options.trust)
          const publications = new Set<string>(), activations = new Set<string>()
          for (const prepared of value.publications) {
            text(prepared.operationId); if (publications.has(prepared.operationId)) throw new Error('RELEASE_JOURNAL_INVALID')
            publications.add(prepared.operationId)
            const policy = value.state.policies[prepared.manifest.payload.policyRevision]
            if (policy === undefined || prepared.manifest.payload.publisher !== value.publisher ||
              !['prepared', 'published'].includes(prepared.status) ||
              await verifyReleaseManifest(prepared.manifest, policy, options.trust) !== prepared.id) throw new Error('RELEASE_JOURNAL_INVALID')
          }
          for (const attempt of value.activations) {
            const request = attempt.request.payload
            if (request.publisher !== value.publisher || activations.has(request.requestId)) throw new Error('RELEASE_JOURNAL_INVALID')
            activations.add(request.requestId)
            const policy = value.state.policies[request.policyRevision]
            if (policy === undefined) throw new Error('RELEASE_JOURNAL_INVALID')
            // The saved signature is checked through the same public admission
            // function, including when the publisher was subsequently revoked.
            await verifyReleaseActivationRequest(attempt.request, policy, options.trust)
            if (attempt.result !== null) {
              await verifyReleaseActivation(attempt.result, policy, options.trust)
              if (!same(attempt.result.payload.request, attempt.request) ||
                value.state.activations[attempt.result.payload.revision]?.id !== attempt.result.id) throw new Error('RELEASE_JOURNAL_INVALID')
            }
          }
          publisher.#budget(value); publisher.#journal = value
        }
      })
      publisher.#assertOpen(); return publisher
    } catch (error) { await publisher.close(); throw error }
  }
  get publisherId(): string { return this.#options.identity.publicKey }
  get applicationId(): string { return this.#options.trust.applicationId }
  state(): Promise<ReleaseState> { return this.#run(async () => structuredClone(this.#journal.state)) }
  refresh(): Promise<ReleaseState> {
    return this.#run(async () => {
      const next = await verifyReleaseState(await this.#remote(signal => this.#options.host.state({ signal })), this.#options.trust)
      assertReleaseStateExtension(this.#journal.state, next)
      await this.#save({ ...this.#journal, state: next }); return structuredClone(next)
    })
  }
  prepare(input: PrepareReleaseOptions): Promise<PreparedRelease> {
    text(input.operationId)
    if (!isList(input.assets) || input.assets.length === 0 || input.assets.length > RELEASE_LIMITS.assets) return Promise.reject(new Error('RELEASE_ASSET_LIMIT'))
    let total = 0
    for (const asset of input.assets) {
      if (!(asset.bytes instanceof Uint8Array) || asset.bytes.length > RELEASE_LIMITS.fileBytes) return Promise.reject(new Error('RELEASE_CONTENT_LIMIT'))
      total += asset.bytes.length; if (total > RELEASE_LIMITS.totalBytes) return Promise.reject(new Error('RELEASE_CONTENT_LIMIT'))
    }
    const captured = { ...input, assets: input.assets.map(asset => ({ ...asset, bytes: asset.bytes.slice() })),
      application: structuredClone(input.application === undefined ? this.#options.application : input.application) }
    return this.#run(async () => {
      const prior = this.#journal.publications.find(value => value.operationId === captured.operationId)
      const policy = prior === undefined ? this.#journal.state.policies.at(-1) : this.#journal.state.policies[prior.manifest.payload.policyRevision]
      if (policy === undefined || !policy.payload.publishers.includes(this.publisherId)) throw new Error('RELEASE_PUBLISHER_DENIED')
      const sources = captured.assets.slice().sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
      const assets: ReleaseAsset[] = []
      for (const asset of sources) assets.push({ path: asset.path, mediaType: asset.mediaType, bytes: asset.bytes.length, digest: await bytesDigest(asset.bytes) })
      const payload = { profile: RELEASE_PROFILE, applicationId: this.applicationId, scope: 'page' as const, publisher: this.publisherId,
        policyRevision: policy.payload.revision, entry: captured.entry, assets, application: captured.application }
      validateReleaseManifest(payload)
      if (prior !== undefined) {
        if (!same(prior.manifest.payload, payload)) throw new Error('RELEASE_OPERATION_ID_REUSED')
        return structuredClone(prior)
      }
      const manifest = await signReleaseManifest(payload, this.#options.identity)
      const prepared: PreparedRelease = { operationId: captured.operationId, id: await peerDigest(manifest), manifest, status: 'prepared' }
      const next = { ...this.#journal, publications: [...this.#journal.publications, prepared] }
      this.#budget(next)
      // Exact content precedes the manifest journal. A transport is never called
      // until both have durable acknowledgements under this operation identity.
      for (let index = 0; index < sources.length; index++) {
        const source = sources[index]!, asset = assets[index]!
        for (let offset = 0; offset < source.bytes.length; offset += RELEASE_LIMITS.chunkBytes) {
          const chunk = source.bytes.slice(offset, offset + RELEASE_LIMITS.chunkBytes)
          const key = `${this.#prefix}/content/${asset.digest}/${offset / RELEASE_LIMITS.chunkBytes}`
          const stored = await this.#options.store.get(key)
          if (stored !== null) { if (!equal(stored, chunk)) throw new Error('RELEASE_STAGED_CONTENT_CORRUPT') }
          else await this.#put(key, chunk)
        }
      }
      await this.#save(next); return structuredClone(prepared)
    })
  }
  inspect(operationId: string): Promise<PreparedRelease | null> {
    text(operationId)
    return this.#run(async () => structuredClone(this.#journal.publications.find(value => value.operationId === operationId) ?? null))
  }
  publish(operationId: string): Promise<ReleasePublication> {
    text(operationId)
    return this.#run(async () => {
      const prepared = this.#journal.publications.find(value => value.operationId === operationId)
      if (prepared === undefined) throw new Error('RELEASE_OPERATION_UNKNOWN')
      if (prepared.status === 'published') return { id: prepared.id, manifest: structuredClone(prepared.manifest) }
      const sent = new Set<string>()
      for (const asset of prepared.manifest.payload.assets) {
        if (sent.has(asset.digest)) continue
        const bytes = new Uint8Array(asset.bytes)
        for (let offset = 0; offset < bytes.length; offset += RELEASE_LIMITS.chunkBytes) {
          const chunk = await this.#options.store.get(`${this.#prefix}/content/${asset.digest}/${offset / RELEASE_LIMITS.chunkBytes}`)
          if (chunk === null || chunk.length !== Math.min(RELEASE_LIMITS.chunkBytes, bytes.length - offset)) throw new Error('RELEASE_STAGED_CONTENT_MISSING')
          bytes.set(chunk, offset)
        }
        if (await bytesDigest(bytes) !== asset.digest) throw new Error('RELEASE_STAGED_CONTENT_CORRUPT')
        await this.#remote(signal => this.#options.host.content.put(asset.digest, bytes, { mediaType: asset.mediaType, signal }))
        sent.add(asset.digest)
      }
      const result = await this.#remote(signal => this.#options.host.publish(prepared.manifest, { signal }))
      if (result.id !== prepared.id || !same(result.manifest, prepared.manifest)) throw new Error('RELEASE_PUBLICATION_MISMATCH')
      await this.#save({ ...this.#journal, publications: this.#journal.publications.map(value => value.operationId === operationId ? { ...value, status: 'published' } : value) })
      return structuredClone(result)
    })
  }
  activate(releaseId: string, options: { readonly requestId: string; readonly expectedActivation: string | null }): Promise<SignedReleaseActivation> {
    text(options.requestId)
    return this.#run(async () => {
      let attempt = this.#journal.activations.find(value => value.request.payload.requestId === options.requestId)
      if (attempt !== undefined) {
        if (attempt.request.payload.releaseId !== releaseId || attempt.request.payload.expectedActivation !== options.expectedActivation) throw new Error('RELEASE_ACTIVATION_REQUEST_REUSED')
      } else {
        const policy = this.#journal.state.policies.at(-1)
        if (policy === undefined || !policy.payload.publishers.includes(this.publisherId)) throw new Error('RELEASE_PUBLISHER_DENIED')
        const request = await signReleaseActivationRequest({ profile: RELEASE_PROFILE, applicationId: this.applicationId,
          requestId: options.requestId, publisher: this.publisherId, policyRevision: policy.payload.revision,
          expectedActivation: options.expectedActivation, releaseId }, this.#options.identity)
        attempt = { request, result: null }
        await this.#save({ ...this.#journal, activations: [...this.#journal.activations, attempt] })
      }
      return this.#dispatch(attempt)
    })
  }
  inspectActivation(requestId: string): Promise<ReleaseActivationAttempt | null> {
    text(requestId)
    return this.#run(async () => structuredClone(this.#journal.activations.find(value => value.request.payload.requestId === requestId) ?? null))
  }
  retry(requestId: string): Promise<SignedReleaseActivation> {
    text(requestId)
    return this.#run(async () => {
      const attempt = this.#journal.activations.find(value => value.request.payload.requestId === requestId)
      if (attempt === undefined) throw new Error('RELEASE_ACTIVATION_UNKNOWN')
      return this.#dispatch(attempt)
    })
  }
  async #dispatch(attempt: ReleaseActivationAttempt): Promise<SignedReleaseActivation> {
    if (attempt.result !== null) return structuredClone(attempt.result)
    const result = await this.#remote(signal => this.#options.host.activate(attempt.request, { signal }))
    const policy = this.#journal.state.policies[attempt.request.payload.policyRevision]
    if (policy === undefined) throw new Error('RELEASE_POLICY_MISSING')
    await verifyReleaseActivation(result, policy, this.#options.trust)
    if (!same(result.payload.request, attempt.request)) throw new Error('RELEASE_ACTIVATION_MISMATCH')
    let state = this.#journal.state
    if (result.payload.revision === state.activations.length) {
      state = await verifyReleaseState({ ...state, activations: [...state.activations, result] }, this.#options.trust)
      assertReleaseStateExtension(this.#journal.state, state)
    } else if (state.activations[result.payload.revision]?.id !== result.id) {
      state = await verifyReleaseState(await this.#remote(signal => this.#options.host.state({ signal })), this.#options.trust)
      assertReleaseStateExtension(this.#journal.state, state)
      if (state.activations[result.payload.revision]?.id !== result.id) throw new Error('RELEASE_ACTIVATION_EQUIVOCATION')
    }
    await this.#save({ ...this.#journal, state, activations: this.#journal.activations.map(value =>
      value.request.payload.requestId === attempt.request.payload.requestId ? { ...value, result } : value) })
    return structuredClone(result)
  }
  async *watch(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<SignedReleaseActivation> {
    this.#assertOpen()
    if (this.#options.host.watch === undefined) throw new Error('RELEASE_WATCH_UNAVAILABLE')
    if (this.#watches >= PUBLISHER_LIMITS.watches) throw new Error('RELEASE_WATCH_LIMIT')
    this.#watches++
    const signal = options.signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, options.signal])
    let previous = this.#journal.state.activations.at(-1)?.id
    let iterator: AsyncIterator<SignedReleaseActivation> | undefined
    try {
      iterator = this.#options.host.watch({ signal })[Symbol.asyncIterator]()
      for (;;) {
        const item = await interrupted(iterator.next(), signal)
        if (item.done) return
        if (item.value.id === previous) continue
        const state = await this.refresh()
        const observed = state.activations.find(value => value.id === item.value.id)
        if (observed === undefined || !same(observed, item.value)) throw new Error('RELEASE_ANNOUNCEMENT_MISMATCH')
        const current = state.activations.at(-1)!
        if (current.id !== previous) { previous = current.id; yield structuredClone(current) }
      }
    } finally {
      this.#watches--
      try { void Promise.resolve(iterator?.return?.()).catch(() => undefined) } catch { /* The owner is already stopping. */ }
    }
  }
  close(): Promise<void> {
    if (this.#closed !== undefined) return this.#closed
    this.#lifetime.abort(new Error('RELEASE_PUBLISHER_CLOSED')); this.#stopParent?.()
    this.#closed = this.#tail.catch(() => undefined).then(async () => {
      owners.get(this.#options.store)?.delete(this.applicationId)
      this.#unregister?.(); await this.#options.closing?.()
    })
    return this.#closed
  }
  #assertOpen(): void { this.#options.signal?.throwIfAborted(); this.#lifetime.signal.throwIfAborted() }
  #run<T>(action: () => Promise<T>): Promise<T> {
    try { this.#assertOpen() } catch (error) { return Promise.reject(error) }
    if (this.#pending >= PUBLISHER_LIMITS.calls) return Promise.reject(new Error('RELEASE_REQUEST_LIMIT'))
    this.#pending++
    const next = this.#tail.then(async () => { this.#assertOpen(); const result = await action(); this.#assertOpen(); return result })
    this.#tail = next.catch(() => undefined)
    return next.finally(() => { this.#pending-- })
  }
  async #remote<T>(action: (signal: AbortSignal) => Promise<T>): Promise<T> {
    this.#assertOpen()
    const deadline = new AbortController(), timer = setTimeout(() => deadline.abort(new Error('RELEASE_HOST_TIMEOUT')), PUBLISHER_LIMITS.requestMs)
    const signal = AbortSignal.any([this.#lifetime.signal, deadline.signal])
    try { const result = await interrupted(action(signal), signal); this.#assertOpen(); return result }
    finally { clearTimeout(timer) }
  }
  #budget(value: Journal): Uint8Array {
    if (value.publications.length > PUBLISHER_LIMITS.publications || value.activations.length > PUBLISHER_LIMITS.activations) throw new Error('RELEASE_JOURNAL_LIMIT')
    const assets = new Map<string, number>()
    for (const publication of value.publications) for (const asset of publication.manifest.payload.assets) assets.set(asset.digest, asset.bytes)
    if (assets.size > PUBLISHER_LIMITS.assets || [...assets.values()].reduce((sum, bytes) => sum + bytes, 0) > PUBLISHER_LIMITS.contentBytes) throw new Error('RELEASE_STAGING_LIMIT')
    const bytes = encodePeerValue(value)
    if (bytes.length > PUBLISHER_LIMITS.journalBytes) throw new Error('RELEASE_JOURNAL_LIMIT')
    return bytes
  }
  async #put(key: string, bytes: Uint8Array): Promise<void> {
    this.#assertOpen()
    try { await this.#options.store.put(key, bytes) }
    catch (error) { this.#lifetime.abort(error); throw error }
    this.#assertOpen()
  }
  async #save(value: Journal): Promise<void> {
    await this.#put(this.#key, this.#budget(value)); this.#journal = structuredClone(value)
  }
}

/** Initial publisher with exclusive durable device ownership; successful reopen is offline. */
export async function openReleasePublisher(options: { readonly device: ApplicationDevice; readonly applicationId: string;
  readonly controlPublicKey: string; readonly host: ReleaseHost; readonly signal?: AbortSignal }): Promise<ApplicationReleasePublisher> {
  const release = claimApplicationDevice(options.device)
  try {
    return await ApplicationReleasePublisher.open({ identity: options.device.identity, store: options.device.store,
      trust: { applicationId: options.applicationId, controlPublicKey: options.controlPublicKey }, host: options.host, application: null,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      closing: async () => { release(); await options.device.close() } })
  } catch (error) { release(); await options.device.close(); throw error }
}
/** Adds the publisher facet to the existing owner; signing keys remain in its Worker/process. */
export async function createReleasePublisher(options: { readonly session: ApplicationSession; readonly host: ReleaseHost }): Promise<ApplicationReleasePublisher> {
  const owner = sessionInternals.get(options.session)
  if (owner === undefined) throw new Error('APPLICATION_SESSION_REQUIRED')
  const descriptor = owner.replica.descriptor
  const application = { historyId: descriptor.historyId, definitionDigest: descriptor.definitionDigest,
    executionManifestDigest: descriptor.executionManifestDigest, schemaDigest: descriptor.schemaDigest }
  validateReleaseApplicationBinding(application)
  return ApplicationReleasePublisher.open({ identity: owner.replica.device, store: owner.store,
    trust: { applicationId: descriptor.applicationId, controlPublicKey: descriptor.controlPublicKey }, application,
    host: options.host, signal: options.session.signal, owner: options.session })
}
function text(value: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128 ||
    [...value].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) throw new Error('RELEASE_OPERATION_ID_INVALID')
}
function isList(value: unknown): value is readonly unknown[] { return Array.isArray(value) }
function same(left: unknown, right: unknown): boolean { return equal(encodePeerValue(left), encodePeerValue(right)) }
function equal(left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((value, index) => value === right[index]) }
function interrupted<T>(value: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void value.catch(() => undefined); return Promise.reject(signal.reason) }
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => reject(signal.reason)
    signal.addEventListener('abort', abort, { once: true })
    void value.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
  })
}

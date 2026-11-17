import {
  assertReleaseStateExtension, decodePeerValue, encodePeerValue, RELEASE_LIMITS,
  verifyReleaseContent, verifyReleaseManifest, verifyReleaseState,
  type PeerStore, type ReleaseState, type ReleaseTrust, type SignedReleaseActivation, type SignedReleaseManifest,
} from '@chronolog/peer-generation/control'

import type { ReleaseHost } from './releases.js'

export interface VerifiedReleaseSelection {
  readonly activation: SignedReleaseActivation
  readonly manifest: SignedReleaseManifest
}
export interface ReleaseObservation {
  /** All learned signed controls remain monotonic, even if selected bytes are unavailable. */
  readonly state: ReleaseState
  /** Present only after this owner's manifest/content verification of the selected release. */
  readonly selection: VerifiedReleaseSelection | null
}
export type ReleaseObserverHost = Pick<ReleaseHost, 'state' | 'manifest' | 'watch'> & {
  readonly content: Pick<ReleaseHost['content'], 'get'>
}
export interface ReleaseObserverOptions extends ReleaseTrust {
  readonly host: ReleaseObserverHost
  readonly store: PeerStore
  readonly signal?: AbortSignal
  /** A trusted transport can supply its bootstrap; signatures and retained ancestry are still checked. */
  readonly initial?: { readonly state: ReleaseState; readonly manifest: SignedReleaseManifest | null }
}
interface Journal { readonly version: 1; readonly trust: ReleaseTrust; readonly state: ReleaseState }
const owners = new WeakMap<PeerStore, Set<string>>()
const LIMITS = Object.freeze({ journalBytes: 4 * 1024 * 1024, calls: 8, watches: 4, requestMs: 30_000 })

/** Reads approved public code without a signer, data grant, private key or application replica. */
export class ApplicationReleaseObserver {
  readonly #options: ReleaseObserverOptions
  readonly #trust: ReleaseTrust
  readonly #key: string
  readonly #lifetime = new AbortController()
  readonly #stopParent: () => void
  #state!: ReleaseState
  #selection: VerifiedReleaseSelection | null = null
  #tail: Promise<unknown> = Promise.resolve()
  #pending = 0
  #watches = 0
  #closed: Promise<void> | undefined

  private constructor(options: ReleaseObserverOptions) {
    this.#options = options
    this.#trust = { applicationId: options.applicationId, controlPublicKey: options.controlPublicKey }
    this.#key = `peer-session/release-observer/v1/${options.applicationId}`
    const abort = (): void => { void this.close().catch(() => undefined) }
    options.signal?.addEventListener('abort', abort, { once: true })
    this.#stopParent = () => options.signal?.removeEventListener('abort', abort)
  }
  static async open(input: ReleaseObserverOptions): Promise<ApplicationReleaseObserver> {
    if (!/^[0-9a-f]{64}$/u.test(input.applicationId) || !/^[0-9a-f]{64}$/u.test(input.controlPublicKey)) throw new Error('RELEASE_TRUST_INVALID')
    const options = { ...input, ...(input.initial === undefined ? {} : { initial: structuredClone(input.initial) }) }
    const owned = owners.get(options.store) ?? new Set<string>()
    if (owned.has(options.applicationId)) throw new Error('RELEASE_OBSERVER_IN_USE')
    owned.add(options.applicationId); owners.set(options.store, owned)
    const observer = new ApplicationReleaseObserver(options)
    try {
      // Initial store/transport IO belongs to the same tail as later calls. An
      // abort cannot release ownership while an initial durable write is pending.
      await observer.#run(async () => observer.#initialize())
      return observer
    } catch (error) { await observer.close(); throw error }
  }
  get applicationId(): string { return this.#trust.applicationId }
  state(): Promise<ReleaseObservation> { return this.#run(async () => this.#snapshot()) }
  refresh(options: { readonly signal?: AbortSignal } = {}): Promise<ReleaseObservation> {
    return this.#run(async () => this.#observe(await this.#remote(signal => this.#options.host.state({ signal }), options.signal), undefined, options.signal))
  }
  /** Explicit bounded hints; neither polling nor page replacement happens here. */
  async *watch(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ReleaseObservation> {
    this.#assertOpen()
    if (this.#options.host.watch === undefined) throw new Error('RELEASE_WATCH_UNAVAILABLE')
    if (this.#watches >= LIMITS.watches) throw new Error('RELEASE_WATCH_LIMIT')
    this.#watches++
    const signal = options.signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, options.signal])
    let previous = this.#selection?.activation.id
    let iterator: AsyncIterator<SignedReleaseActivation> | undefined
    try {
      iterator = this.#options.host.watch({ signal })[Symbol.asyncIterator]()
      for (;;) {
        const next = await interrupted(iterator.next(), signal)
        if (next.done) return
        const hint = structuredClone(next.value)
        const observation = await this.#run(async () => {
          const state = await verifyReleaseState(await this.#remote(signal => this.#options.host.state({ signal }), signal), this.#trust)
          const included = state.activations.find(value => value.id === hint.id)
          if (included === undefined || !same(included, hint)) throw new Error('RELEASE_ANNOUNCEMENT_MISMATCH')
          return this.#observe(state, undefined, signal)
        })
        signal.throwIfAborted()
        const current = observation.selection?.activation.id
        if (current !== undefined && current !== previous) { previous = current; yield observation }
      }
    } finally {
      this.#watches--
      try { void Promise.resolve(iterator?.return?.()).catch(() => undefined) } catch { /* A stopped reader cannot retain ownership. */ }
    }
  }
  close(): Promise<void> {
    if (this.#closed !== undefined) return this.#closed
    this.#lifetime.abort(new Error('RELEASE_OBSERVER_CLOSED')); this.#stopParent()
    this.#closed = this.#tail.catch(() => undefined).then(() => { owners.get(this.#options.store)?.delete(this.applicationId) })
    return this.#closed
  }

  async #initialize(): Promise<void> {
    const bytes = await this.#options.store.get(this.#key)
    this.#assertOpen()
    if (bytes !== null) {
      if (bytes.length > LIMITS.journalBytes) throw new Error('RELEASE_OBSERVER_JOURNAL_LIMIT')
      const journal = decodePeerValue<Journal>(bytes)
      if (journal.version !== 1 || !same(journal.trust, this.#trust)) throw new Error('RELEASE_OBSERVER_BINDING_MISMATCH')
      this.#state = await verifyReleaseState(journal.state, this.#trust)
    }
    const initial = this.#options.initial
    const state = initial?.state ?? this.#state ?? await this.#remote(signal => this.#options.host.state({ signal }))
    await this.#observe(state, initial?.manifest)
  }
  async #observe(input: ReleaseState, supplied?: SignedReleaseManifest | null, signal?: AbortSignal): Promise<ReleaseObservation> {
    signal?.throwIfAborted()
    const next = await verifyReleaseState(input, this.#trust)
    this.#assertOpen()
    if (this.#state !== undefined) assertReleaseStateExtension(this.#state, next)
    const activation = next.activations.at(-1)
    if (activation?.id !== this.#selection?.activation.id) this.#selection = null
    // Learn revocations and activation ancestry before fetching optional bytes.
    // A missing asset must not let a later stale signed head erase that knowledge.
    if (this.#state === undefined || !same(this.#state, next)) await this.#save(next)
    signal?.throwIfAborted()
    if (activation === undefined) return this.#snapshot()
    if (this.#selection?.activation.id === activation.id) return this.#snapshot()
    const found = supplied ?? await this.#remote(signal => this.#options.host.manifest(activation.payload.releaseId, { signal }), signal)
    this.#assertOpen()
    if (found === null) throw new Error('RELEASE_MANIFEST_MISSING')
    const manifest = structuredClone(found), policy = next.policies[manifest.payload.policyRevision]
    if (policy === undefined || manifest.payload.policyRevision > activation.payload.policyRevision) throw new Error('RELEASE_POLICY_MISSING')
    if (await verifyReleaseManifest(manifest, policy, this.#trust) !== activation.payload.releaseId) throw new Error('RELEASE_MANIFEST_ID_INVALID')
    const observer = this, contentSignal = signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, signal])
    await verifyReleaseContent(manifest, { async *read(asset, options) {
      const received = await observer.#remote(signal => observer.#options.host.content.get(asset.digest, { signal }), options?.signal)
      if (!(received instanceof Uint8Array)) throw new Error('RELEASE_CONTENT_INVALID')
      if (received.length !== asset.bytes) throw new Error('RELEASE_CONTENT_LENGTH_MISMATCH')
      const bytes = received.slice()
      for (let offset = 0; offset < bytes.length; offset += RELEASE_LIMITS.chunkBytes) {
        observer.#assertOpen(); options?.signal?.throwIfAborted(); yield bytes.subarray(offset, offset + RELEASE_LIMITS.chunkBytes)
      }
    } }, { signal: contentSignal })
    this.#assertOpen(); signal?.throwIfAborted()
    this.#selection = { activation: structuredClone(activation), manifest }
    return this.#snapshot()
  }
  #snapshot(): ReleaseObservation { return structuredClone({ state: this.#state, selection: this.#selection }) }
  async #save(state: ReleaseState): Promise<void> {
    const bytes = encodePeerValue({ version: 1, trust: this.#trust, state } satisfies Journal)
    if (bytes.length > LIMITS.journalBytes) throw new Error('RELEASE_OBSERVER_JOURNAL_LIMIT')
    this.#assertOpen()
    try { await this.#options.store.put(this.#key, bytes) }
    catch (error) {
      // A failed acknowledgement may have committed. Fence this instance; only
      // reopening may decide which signed head was durably learned.
      this.#lifetime.abort(error); void this.close(); throw error
    }
    this.#state = structuredClone(state); this.#assertOpen()
  }
  #assertOpen(): void { this.#options.signal?.throwIfAborted(); this.#lifetime.signal.throwIfAborted() }
  #run<T>(action: () => Promise<T>): Promise<T> {
    try { this.#assertOpen() } catch (error) { return Promise.reject(error) }
    if (this.#pending >= LIMITS.calls) return Promise.reject(new Error('RELEASE_REQUEST_LIMIT'))
    this.#pending++
    const next = this.#tail.then(async () => { this.#assertOpen(); const result = await action(); this.#assertOpen(); return result })
    this.#tail = next.catch(() => undefined)
    return next.finally(() => { this.#pending-- })
  }
  async #remote<T>(action: (signal: AbortSignal) => Promise<T>, operationSignal?: AbortSignal): Promise<T> {
    this.#assertOpen(); operationSignal?.throwIfAborted()
    const deadline = new AbortController(), timer = setTimeout(() => deadline.abort(new Error('RELEASE_HOST_TIMEOUT')), LIMITS.requestMs)
    const signal = AbortSignal.any([this.#lifetime.signal, deadline.signal, ...(operationSignal === undefined ? [] : [operationSignal])])
    try { const value = await interrupted(action(signal), signal); this.#assertOpen(); return value }
    finally { clearTimeout(timer) }
  }
}

export function openReleaseObserver(options: ReleaseObserverOptions): Promise<ApplicationReleaseObserver> {
  return ApplicationReleaseObserver.open(options)
}
function same(left: unknown, right: unknown): boolean {
  const a = encodePeerValue(left), b = encodePeerValue(right)
  return a.length === b.length && a.every((value, index) => value === b[index])
}
function interrupted<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void pending.catch(() => undefined); return Promise.reject(signal.reason) }
  return new Promise((resolve, reject) => {
    const abort = (): void => reject(signal.reason)
    signal.addEventListener('abort', abort, { once: true })
    void pending.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
  })
}

import type { BytesStore } from '@chronolog/records'
import {
  decodePeerValue, encodePeerValue, peerDigest, signTransitionRequest, verifyAuthorityBundle,
  type AuthorityBundle, type PeerReplica, type RecoveryNotice,
  type SignedGeneration, type SignedTransitionRequest,
} from '@chronolog/peer-generation'
import { awaitOwnedTask } from './lifetime.js'

/** The small hosted control port. Calls occur only at explicit lifecycle boundaries. */
export interface ApplicationControlHost {
  application(): Promise<AuthorityBundle>
  /** A lost generation CAS rejects with code `peer_generation_conflict`.
   * Other failures preserve the saved request for an exact retry. Messages are
   * diagnostic only; transport adapters must preserve or map the typed code. */
  selectGeneration(request: SignedTransitionRequest): Promise<SignedGeneration>
}

/** The portable control-port conflict; adapters may preserve an equivalent typed error. */
export class ApplicationControlConflictError extends Error {
  readonly code = 'peer_generation_conflict' as const
  constructor(message = 'The expected application generation is no longer selected.', options?: ErrorOptions) {
    super(message, options)
    this.name = 'ApplicationControlConflictError'
  }
}

function isControlConflict(error: unknown): error is { readonly code: 'peer_generation_conflict' } {
  return error !== null && typeof error === 'object' && 'code' in error && error.code === 'peer_generation_conflict'
}

export interface ApplicationTransition {
  readonly request: SignedTransitionRequest
  readonly selected: string | null
  readonly superseded: boolean
}

/** Exact transition retries use the same durable device journal as ordinary work. */
export class ApplicationRecovery {
  readonly #replica: PeerReplica
  readonly #store: BytesStore
  readonly #signal: AbortSignal
  readonly #lifetime = new AbortController()
  readonly #key: string
  #tail: Promise<unknown> = Promise.resolve()

  constructor(options: { readonly replica: PeerReplica; readonly store: BytesStore; readonly signal: AbortSignal }) {
    this.#replica = options.replica; this.#store = options.store; this.#signal = AbortSignal.any([options.signal, this.#lifetime.signal])
    this.#key = `peer-session/transitions/v1/${options.replica.descriptor.applicationId}`
  }

  async inspect(): Promise<readonly ApplicationTransition[]> {
    await this.#tail
    return structuredClone(await this.#journal())
  }

  /** Select this device's complete usable prefix after the caller's reconnect grace policy. */
  takeover(host: ApplicationControlHost, options: { readonly coordinator?: string; readonly transitionId?: string; readonly signal?: AbortSignal } = {}): Promise<RecoveryNotice | null> {
    return this.#select(host, options.coordinator ?? this.#replica.device.publicKey, 'takeover', options.transitionId, options.signal)
  }

  /** Planned retirement requires the successor's signed retention of the exact current prefix. */
  handover(host: ApplicationControlHost, options: { readonly coordinator: string; readonly transitionId?: string; readonly signal?: AbortSignal }): Promise<RecoveryNotice | null> {
    return this.#select(host, options.coordinator, 'handover', options.transitionId, options.signal)
  }

  /** Fence new work and finish local journal work without waiting for a remote reply. */
  close(): Promise<void> {
    this.#lifetime.abort(new Error('APPLICATION_RECOVERY_CLOSED'))
    return this.#tail.then(() => undefined)
  }

  #select(host: ApplicationControlHost, coordinator: string, reason: 'takeover' | 'handover', transitionId?: string, externalSignal?: AbortSignal): Promise<RecoveryNotice | null> {
    const signal = externalSignal === undefined ? this.#signal : AbortSignal.any([this.#signal, externalSignal])
    const operation = this.#tail.then(async () => {
      signal.throwIfAborted()
      if (transitionId !== undefined && (transitionId.length < 1 || transitionId.length > 128)) throw new Error('APPLICATION_TRANSITION_ID_INVALID')
      if (!/^[0-9a-f]{64}$/u.test(coordinator)) throw new Error('APPLICATION_COORDINATOR_INVALID')
      const journal = await this.#journal(signal)
      let entry = transitionId === undefined ? [...journal].reverse().find(value => value.selected === null && !value.superseded)
        : journal.find(value => value.request.payload.transitionId === transitionId)
      if (entry !== undefined && (entry.request.payload.coordinator !== coordinator || entry.request.payload.reason !== reason)) {
        throw new Error('APPLICATION_TRANSITION_ID_REUSED')
      }
      if (entry?.superseded === true) throw new ApplicationControlConflictError()
      if (entry === undefined) {
        const bundle = await this.#hostCall(() => host.application(), signal)
        signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
        signal.throwIfAborted()
        await this.#replica.adopt(bundle)
        signal.throwIfAborted()
        if (reason === 'takeover' && this.#replica.isCoordinator) return null
        if (reason === 'handover' && (!this.#replica.isCoordinator || coordinator === this.#replica.device.publicKey)) {
          throw new Error('APPLICATION_HANDOVER_REQUIRES_CURRENT_COORDINATOR')
        }
        const base = await this.#replica.recoveryPoint()
        signal.throwIfAborted()
        if ((reason === 'handover' || coordinator !== this.#replica.device.publicKey) &&
            !this.#replica.shared(base.point).some(receipt => receipt.payload.peer === coordinator &&
              receipt.payload.point.generation === base.point.generation && receipt.payload.point.sequence === base.point.sequence && receipt.payload.point.root === base.point.root)) {
          throw new Error(reason === 'handover' ? 'APPLICATION_HANDOVER_REQUIRES_RETAINED_PREFIX' : 'APPLICATION_TAKEOVER_REQUIRES_RETAINED_PREFIX')
        }
        if (journal.length >= 64) throw new Error('APPLICATION_TRANSITION_JOURNAL_FULL')
        const descriptor = this.#replica.descriptor
        const request = await signTransitionRequest({ applicationId: descriptor.applicationId, profile: descriptor.profile,
          policy: descriptor.policy, expectedGeneration: this.#replica.generation.id, coordinator, requester: this.#replica.device.publicKey,
          controlRevision: this.#replica.generation.payload.controlRevision, base, transitionId: transitionId ?? crypto.randomUUID(), reason }, this.#replica.device)
        signal.throwIfAborted()
        entry = { request, selected: null, superseded: false }
        journal.push(entry)
        // A dropped hosted reply cannot make a later retry choose a different base.
        await this.#store.put(this.#key, encodePeerValue(journal))
      }
      signal.throwIfAborted()
      const request = entry.request
      const previousGeneration = this.#replica.generation.id
      try {
        const selected = await this.#hostCall(() => host.selectGeneration(request), signal)
        signal.throwIfAborted()
        const bundle = await this.#hostCall(() => host.application(), signal)
        signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
        signal.throwIfAborted()
        const observed = bundle.generations.find(generation => generation.id === selected.id)
        if (observed === undefined || await peerDigest(observed.payload.transition) !== await peerDigest(entry.request)) {
          throw new Error('APPLICATION_TRANSITION_REPLY_MISMATCH')
        }
        // The attached control participant durably observes new authority on
        // read. It may already have published this recovery while fetching the
        // selected bundle; return that same notice without publishing a reset twice.
        const notice = await this.#replica.adopt(bundle) ?? this.#replica.inspectRecovery().findLast(value =>
          value.previousGeneration === previousGeneration && value.generation === this.#replica.generation.id) ?? null
        signal.throwIfAborted()
        const index = journal.indexOf(entry)
        journal[index] = { request: entry.request, selected: selected.id, superseded: false }
        await this.#store.put(this.#key, encodePeerValue(journal))
        return notice
      } catch (error) {
        // Competing permitted successors are resolved by the host CAS, never by
        // silently changing this request's expected generation or recovery base.
        if (isControlConflict(error)) {
          const bundle = await this.#hostCall(() => host.application(), signal)
          signal.throwIfAborted()
          await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
          signal.throwIfAborted()
          const expected = entry.request.payload.expectedGeneration
          if (bundle.generations.at(-1)?.id === expected || !bundle.generations.some(generation => generation.id === expected)) {
            throw new Error('APPLICATION_TRANSITION_CONFLICT_UNCONFIRMED', { cause: error })
          }
          journal[journal.indexOf(entry)] = { ...entry, superseded: true }
          await this.#store.put(this.#key, encodePeerValue(journal))
          signal.throwIfAborted()
          await this.#replica.adopt(bundle)
        }
        throw error
      }
    })
    this.#tail = operation.catch(() => undefined)
    return operation
  }

  async #journal(signal = this.#signal): Promise<ApplicationTransition[]> {
    signal.throwIfAborted()
    const bytes = await this.#store.get(this.#key)
    signal.throwIfAborted()
    if (bytes === null) return []
    const value = decodePeerValue<ApplicationTransition[]>(bytes)
    if (!Array.isArray(value) || value.length > 64 || value.some(entry => entry.request?.payload?.applicationId !== this.#replica.descriptor.applicationId ||
        entry.request.payload.requester !== this.#replica.device.publicKey || typeof entry.superseded !== 'boolean' ||
        entry.selected !== null && !/^[0-9a-f]{64}$/u.test(entry.selected))) throw new Error('APPLICATION_TRANSITION_JOURNAL_INVALID')
    return value
  }

  #hostCall<T>(call: () => Promise<T>, signal: AbortSignal): Promise<T> {
    // A remote mutation may still finish. Its original signed request stays
    // durable; cancellation only ends this owner's wait and subsequent work.
    return awaitOwnedTask(signal, call)
  }
}

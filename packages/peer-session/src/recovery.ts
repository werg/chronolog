import {
  decodePeerValue, encodePeerValue, signTransitionRequest, verifyAuthorityBundle,
  type AuthorityBundle, type PeerReplica, type PeerStore, type RecoveryNotice,
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
  readonly #store: PeerStore
  readonly #signal: AbortSignal
  readonly #lifetime = new AbortController()
  readonly #key: string
  #tail: Promise<unknown> = Promise.resolve()

  constructor(options: { readonly replica: PeerReplica; readonly store: PeerStore; readonly signal: AbortSignal }) {
    this.#replica = options.replica; this.#store = options.store; this.#signal = AbortSignal.any([options.signal, this.#lifetime.signal])
    this.#key = `peer-session/transitions/v1/${options.replica.descriptor.applicationId}`
  }

  async inspect(): Promise<readonly ApplicationTransition[]> {
    await this.#tail
    return structuredClone(await this.#journal())
  }

  /** Select this device's complete usable prefix after the caller's reconnect grace policy. */
  takeover(host: ApplicationControlHost, options: { readonly transitionId?: string } = {}): Promise<RecoveryNotice | null> {
    return this.#select(host, this.#replica.device.publicKey, 'takeover', options.transitionId)
  }

  /** Planned retirement requires the successor's signed retention of the exact current prefix. */
  handover(host: ApplicationControlHost, options: { readonly coordinator: string; readonly transitionId?: string }): Promise<RecoveryNotice | null> {
    return this.#select(host, options.coordinator, 'handover', options.transitionId)
  }

  /** Fence new work and finish local journal work without waiting for a remote reply. */
  close(): Promise<void> {
    this.#lifetime.abort(new Error('APPLICATION_RECOVERY_CLOSED'))
    return this.#tail.then(() => undefined)
  }

  #select(host: ApplicationControlHost, coordinator: string, reason: 'takeover' | 'handover', transitionId?: string): Promise<RecoveryNotice | null> {
    const operation = this.#tail.then(async () => {
      this.#signal.throwIfAborted()
      if (transitionId !== undefined && (transitionId.length < 1 || transitionId.length > 128)) throw new Error('APPLICATION_TRANSITION_ID_INVALID')
      if (!/^[0-9a-f]{64}$/u.test(coordinator)) throw new Error('APPLICATION_COORDINATOR_INVALID')
      const journal = await this.#journal()
      let entry = transitionId === undefined ? [...journal].reverse().find(value => value.selected === null && !value.superseded)
        : journal.find(value => value.request.payload.transitionId === transitionId)
      if (entry !== undefined && (entry.request.payload.coordinator !== coordinator || entry.request.payload.reason !== reason)) {
        throw new Error('APPLICATION_TRANSITION_ID_REUSED')
      }
      if (entry?.superseded === true) throw new ApplicationControlConflictError()
      if (entry === undefined) {
        const bundle = await this.#hostCall(() => host.application())
        this.#signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
        this.#signal.throwIfAborted()
        await this.#replica.adopt(bundle)
        this.#signal.throwIfAborted()
        if (reason === 'takeover' && this.#replica.isCoordinator) return null
        if (reason === 'handover' && (!this.#replica.isCoordinator || coordinator === this.#replica.device.publicKey)) {
          throw new Error('APPLICATION_HANDOVER_REQUIRES_CURRENT_COORDINATOR')
        }
        const base = await this.#replica.recoveryPoint()
        this.#signal.throwIfAborted()
        if (reason === 'handover' && !this.#replica.shared(base.point).some(receipt => receipt.payload.peer === coordinator)) {
          throw new Error('APPLICATION_HANDOVER_REQUIRES_RETAINED_PREFIX')
        }
        if (journal.length >= 64) throw new Error('APPLICATION_TRANSITION_JOURNAL_FULL')
        const descriptor = this.#replica.descriptor
        const request = await signTransitionRequest({ applicationId: descriptor.applicationId, profile: descriptor.profile,
          policy: descriptor.policy, expectedGeneration: this.#replica.generation.id, coordinator, requester: this.#replica.device.publicKey,
          controlRevision: this.#replica.generation.payload.controlRevision, base, transitionId: transitionId ?? crypto.randomUUID(), reason }, this.#replica.device)
        this.#signal.throwIfAborted()
        entry = { request, selected: null, superseded: false }
        journal.push(entry)
        // A dropped hosted reply cannot make a later retry choose a different base.
        await this.#store.put(this.#key, encodePeerValue(journal))
      }
      this.#signal.throwIfAborted()
      const request = entry.request
      try {
        const selected = await this.#hostCall(() => host.selectGeneration(request))
        this.#signal.throwIfAborted()
        const bundle = await this.#hostCall(() => host.application())
        this.#signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
        this.#signal.throwIfAborted()
        if (!bundle.generations.some(generation => generation.id === selected.id && generation.payload.transition.payload.transitionId === entry.request.payload.transitionId)) {
          throw new Error('APPLICATION_TRANSITION_REPLY_MISMATCH')
        }
        const notice = await this.#replica.adopt(bundle)
        this.#signal.throwIfAborted()
        const index = journal.indexOf(entry)
        journal[index] = { request: entry.request, selected: selected.id, superseded: false }
        await this.#store.put(this.#key, encodePeerValue(journal))
        return notice
      } catch (error) {
        // Competing permitted successors are resolved by the host CAS, never by
        // silently changing this request's expected generation or recovery base.
        if (isControlConflict(error)) {
          const bundle = await this.#hostCall(() => host.application())
          this.#signal.throwIfAborted()
          await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
          this.#signal.throwIfAborted()
          const expected = entry.request.payload.expectedGeneration
          if (bundle.generations.at(-1)?.id === expected || !bundle.generations.some(generation => generation.id === expected)) {
            throw new Error('APPLICATION_TRANSITION_CONFLICT_UNCONFIRMED', { cause: error })
          }
          journal[journal.indexOf(entry)] = { ...entry, superseded: true }
          await this.#store.put(this.#key, encodePeerValue(journal))
          this.#signal.throwIfAborted()
          await this.#replica.adopt(bundle)
        }
        throw error
      }
    })
    this.#tail = operation.catch(() => undefined)
    return operation
  }

  async #journal(): Promise<ApplicationTransition[]> {
    this.#signal.throwIfAborted()
    const bytes = await this.#store.get(this.#key)
    this.#signal.throwIfAborted()
    if (bytes === null) return []
    const value = decodePeerValue<ApplicationTransition[]>(bytes)
    if (!Array.isArray(value) || value.length > 64 || value.some(entry => entry.request?.payload?.applicationId !== this.#replica.descriptor.applicationId ||
        entry.request.payload.requester !== this.#replica.device.publicKey || typeof entry.superseded !== 'boolean' ||
        entry.selected !== null && !/^[0-9a-f]{64}$/u.test(entry.selected))) throw new Error('APPLICATION_TRANSITION_JOURNAL_INVALID')
    return value
  }

  #hostCall<T>(call: () => Promise<T>): Promise<T> {
    // A remote mutation may still finish. Its original signed request stays
    // durable; cancellation only ends this owner's wait and subsequent work.
    return awaitOwnedTask(this.#signal, call)
  }
}

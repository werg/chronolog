import type { BytesStore } from '@chronolog/records'
import {
  decodePeerValue, encodePeerValue, peerDigest, signTransitionRequest, verifyAuthorityBundle, validateHistoryPoint,
  type AuthorityBundle, type PeerReplica, type RecoveryNotice, type HistoryPoint,
  type SignedGeneration, type SignedTransitionRequest,
} from '@chronolog/peer-generation'
import { awaitOwnedTask } from './lifetime.js'

/** The small hosted control port. Calls occur only at explicit lifecycle boundaries. */
export interface ApplicationControlHost {
  application(options?: { readonly signal?: AbortSignal }): Promise<AuthorityBundle>
  /** A lost generation CAS rejects with code `peer_generation_conflict`.
   * Other failures preserve the saved request for an exact retry. Messages are
   * diagnostic only; transport adapters must preserve or map the typed code. */
  selectGeneration(request: SignedTransitionRequest, options?: { readonly signal?: AbortSignal }): Promise<SignedGeneration>
}

/** A displayed recovery choice cannot silently cross a changed authority or prefix. */
export interface ApplicationRecoveryExpectation {
  /** Current selected generation used by the control CAS; the usable point may belong to an ancestor. */
  readonly generation: string
  readonly controlRevision: number
  readonly point: HistoryPoint
}

export { ApplicationControlConflictError } from './errors.js'
import { ApplicationControlConflictError } from './errors.js'

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
  readonly #adoptAuthority: (authority: AuthorityBundle) => Promise<void>
  readonly #signal: AbortSignal
  readonly #lifetime = new AbortController()
  readonly #key: string
  #tail: Promise<unknown> = Promise.resolve()

  constructor(options: { readonly replica: PeerReplica; readonly store: BytesStore; readonly signal: AbortSignal;
    readonly adoptAuthority: (authority: AuthorityBundle) => Promise<void> }) {
    this.#replica = options.replica; this.#store = options.store; this.#adoptAuthority = options.adoptAuthority; this.#signal = AbortSignal.any([options.signal, this.#lifetime.signal])
    this.#key = `peer-session/transitions/v1/${options.replica.descriptor.applicationId}`
  }

  async inspect(): Promise<readonly ApplicationTransition[]> {
    await this.#tail
    return structuredClone(await this.#journal())
  }

  /** Select this device's complete usable prefix after the caller's reconnect grace policy. */
  takeover(host: ApplicationControlHost, options: { readonly coordinator?: string; readonly transitionId?: string; readonly signal?: AbortSignal; readonly expected?: ApplicationRecoveryExpectation } = {}): Promise<RecoveryNotice | null> {
    return this.#select(host, options.coordinator ?? this.#replica.device.publicKey, 'takeover', options.transitionId, options.signal, options.expected)
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

  #select(host: ApplicationControlHost, coordinator: string, reason: 'takeover' | 'handover', transitionId?: string, externalSignal?: AbortSignal, expectation?: ApplicationRecoveryExpectation): Promise<RecoveryNotice | null> {
    const signal = externalSignal === undefined ? this.#signal : AbortSignal.any([this.#signal, externalSignal])
    const expected = expectation === undefined ? undefined : structuredClone(expectation)
    const operation = this.#tail.then(async () => {
      signal.throwIfAborted()
      if (expected !== undefined) {
        validateHistoryPoint(expected.point)
        if (!/^[0-9a-f]{64}$/u.test(expected.generation) || !Number.isSafeInteger(expected.controlRevision) || expected.controlRevision < 0) throw new Error('APPLICATION_RECOVERY_EXPECTATION_INVALID')
      }
      if (transitionId !== undefined && (transitionId.length < 1 || transitionId.length > 128)) throw new Error('APPLICATION_TRANSITION_ID_INVALID')
      if (!/^[0-9a-f]{64}$/u.test(coordinator)) throw new Error('APPLICATION_COORDINATOR_INVALID')
      const journal = await this.#journal(signal)
      let entry = transitionId === undefined ? [...journal].reverse().find(value => value.selected === null && !value.superseded)
        : journal.find(value => value.request.payload.transitionId === transitionId)
      if (entry !== undefined && (entry.request.payload.coordinator !== coordinator || entry.request.payload.reason !== reason)) {
        throw new Error('APPLICATION_TRANSITION_ID_REUSED')
      }
      if (entry !== undefined && expected !== undefined && (entry.request.payload.expectedGeneration !== expected.generation ||
          entry.request.payload.controlRevision !== expected.controlRevision || entry.request.payload.base?.point.generation !== expected.point.generation ||
          entry.request.payload.base.point.sequence !== expected.point.sequence || entry.request.payload.base.point.root !== expected.point.root)) {
        throw new Error('APPLICATION_RECOVERY_PROPOSAL_CHANGED')
      }
      if (entry?.superseded === true) throw new ApplicationControlConflictError()
      if (entry === undefined) {
        const bundle = await this.#hostCall(() => host.application({ signal }), signal)
        signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
        signal.throwIfAborted()
        await this.#adoptAuthority(bundle)
        signal.throwIfAborted()
        const generation = this.#replica.generation
        if (expected !== undefined && (expected.generation !== generation.id || expected.controlRevision !== generation.payload.controlRevision)) {
          throw new Error('APPLICATION_RECOVERY_PROPOSAL_CHANGED')
        }
        if (reason === 'takeover' && this.#replica.isCoordinator && this.#replica.ready) return null
        if (reason === 'handover' && !this.#replica.ready) throw new Error('PEER_RECOVERY_PREFIX_INCOMPLETE')
        if (reason === 'handover' && (!this.#replica.isCoordinator || coordinator === this.#replica.device.publicKey)) {
          throw new Error('APPLICATION_HANDOVER_REQUIRES_CURRENT_COORDINATOR')
        }
        const base = await this.#replica.recoveryPoint()
        signal.throwIfAborted()
        if (this.#replica.generation.id !== generation.id || expected !== undefined &&
            (expected.point.generation !== base.point.generation || expected.point.sequence !== base.point.sequence || expected.point.root !== base.point.root)) {
          throw new Error('APPLICATION_RECOVERY_PROPOSAL_CHANGED')
        }
        if ((reason === 'handover' || coordinator !== this.#replica.device.publicKey) &&
            (!this.#replica.ready || !this.#replica.shared(base.point).some(receipt => receipt.payload.peer === coordinator &&
              receipt.payload.point.generation === base.point.generation && receipt.payload.point.sequence === base.point.sequence && receipt.payload.point.root === base.point.root))) {
          throw new Error(reason === 'handover' ? 'APPLICATION_HANDOVER_REQUIRES_RETAINED_PREFIX' : 'APPLICATION_TAKEOVER_REQUIRES_RETAINED_PREFIX')
        }
        if (journal.length >= 64) throw new Error('APPLICATION_TRANSITION_JOURNAL_FULL')
        const descriptor = this.#replica.descriptor
        const request = await signTransitionRequest({ applicationId: descriptor.applicationId, profile: descriptor.profile,
          policy: descriptor.policy, expectedGeneration: generation.id, coordinator, requester: this.#replica.device.publicKey,
          controlRevision: generation.payload.controlRevision, base, transitionId: transitionId ?? crypto.randomUUID(), reason }, this.#replica.device)
        // Reuse the current authority's admission rules before retaining a new
        // intent. A forbidden transition must not become a pending exact retry.
        await (await verifyAuthorityBundle(this.#replica.authority)).authorizeTransition(request)
        signal.throwIfAborted()
        entry = { request, selected: null, superseded: false }
        journal.push(entry)
        // A dropped hosted reply cannot make a later retry choose a different base.
        await this.#store.put(this.#key, encodePeerValue(journal))
      }
      signal.throwIfAborted()
      const request = entry.request
      try {
        const selected = await this.#hostCall(() => host.selectGeneration(request, { signal }), signal)
        signal.throwIfAborted()
        const bundle = await this.#hostCall(() => host.application({ signal }), signal)
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
        // Its previous published view can precede several incomplete selections.
        await this.#adoptAuthority(bundle)
        const notice = await this.#replica.adopt(bundle) ?? this.#replica.inspectRecovery().findLast(value =>
          value.generation === selected.id) ?? null
        signal.throwIfAborted()
        const index = journal.indexOf(entry)
        journal[index] = { request: entry.request, selected: selected.id, superseded: false }
        await this.#store.put(this.#key, encodePeerValue(journal))
        return notice
      } catch (error) {
        // Competing permitted successors are resolved by the host CAS, never by
        // silently changing this request's expected generation or recovery base.
        if (isControlConflict(error)) {
          const bundle = await this.#hostCall(() => host.application({ signal }), signal)
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
          await this.#adoptAuthority(bundle)
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

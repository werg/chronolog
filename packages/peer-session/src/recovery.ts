import {
  controlIntentDigest, decodePeerValue, encodePeerValue, peerDigest, signTransitionRequest, verifyAuthorityBundle,
  type AuthorityBundle, type PeerReplica, type PeerStore, type RecoveryNotice,
  type SignedGeneration, type SignedTransitionRequest,
} from '@chronolog/peer-generation'

/** The small hosted control port. Calls occur only at explicit lifecycle boundaries. */
export interface ApplicationControlHost {
  application(): Promise<AuthorityBundle>
  selectGeneration(request: SignedTransitionRequest): Promise<SignedGeneration>
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
  readonly #key: string
  #tail: Promise<unknown> = Promise.resolve()

  constructor(options: { readonly replica: PeerReplica; readonly store: PeerStore; readonly signal: AbortSignal }) {
    this.#replica = options.replica; this.#store = options.store; this.#signal = options.signal
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
      if (entry === undefined) {
        const bundle = await host.application()
        this.#signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
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
          controlRevision: this.#replica.generation.payload.controlRevision,
          controlIntentDigest: await controlIntentDigest(this.#replica.authority.controls[this.#replica.generation.payload.controlRevision]!.payload),
          contextDigest: null, base, transitionId: transitionId ?? crypto.randomUUID(), reason }, this.#replica.device)
        entry = { request, selected: null, superseded: false }
        journal.push(entry)
        // A dropped hosted reply cannot make a later retry choose a different base.
        await this.#store.put(this.#key, encodePeerValue(journal))
      }
      this.#signal.throwIfAborted()
      try {
        const selected = await host.selectGeneration(entry.request)
        this.#signal.throwIfAborted()
        const bundle = await host.application()
        this.#signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
        const recorded = bundle.generations.find(generation => generation.id === selected.id)
        if (recorded === undefined || await peerDigest(recorded.payload.transition) !== await peerDigest(entry.request)) {
          throw new Error('APPLICATION_TRANSITION_REPLY_MISMATCH')
        }
        const notice = await this.#replica.adopt(bundle)
        const index = journal.indexOf(entry)
        journal[index] = { request: entry.request, selected: selected.id, superseded: false }
        await this.#store.put(this.#key, encodePeerValue(journal))
        return notice
      } catch (error) {
        // Competing permitted successors are resolved by the host CAS, never by
        // silently changing this request's expected generation or recovery base.
        if (error instanceof Error && error.message === 'PEER_GENERATION_CONFLICT') {
          const bundle = await host.application()
          this.#signal.throwIfAborted()
          await verifyAuthorityBundle(bundle, this.#replica.authority.descriptor)
          journal[journal.indexOf(entry)] = { ...entry, superseded: true }
          await this.#store.put(this.#key, encodePeerValue(journal))
          await this.#replica.adopt(bundle)
        }
        throw error
      }
    })
    this.#tail = operation.catch(() => undefined)
    return operation
  }

  async #journal(): Promise<ApplicationTransition[]> {
    const bytes = await this.#store.get(this.#key)
    if (bytes === null) return []
    const value = decodePeerValue<ApplicationTransition[]>(bytes)
    if (!Array.isArray(value) || value.length > 64 || value.some(entry => entry.request?.payload?.applicationId !== this.#replica.descriptor.applicationId ||
        entry.request.payload.requester !== this.#replica.device.publicKey || typeof entry.superseded !== 'boolean' ||
        entry.selected !== null && !/^[0-9a-f]{64}$/u.test(entry.selected))) throw new Error('APPLICATION_TRANSITION_JOURNAL_INVALID')
    return value
  }
}

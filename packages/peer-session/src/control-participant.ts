import type { BytesStore } from '@chronolog/records'
import {
  createParticipantTransport, decodePeerValue, encodePeerValue, peerDigest,
  verifyAuthorityBundle, verifyPublicationManifest, signPublicationManifest,
  validateApplicationDescription, applicationDescriptionDigest, verifyApplicationSchema, PUBLICATION_LIMITS,
  type ApplicationDescription, type AuthorityBundle, type PeerReplica, type ParticipantRequest, type ParticipantExchangeOptions, type ParticipantTransport,
  type SignedApplicationDescriptor, type SignedApplicationSchema, type SignedGeneration, type SignedTransitionRequest,
  type SignedPublication, type PublicationFile,
} from '@chronolog/peer-generation'
import type { ApplicationControlHost } from './recovery.js'
import { awaitOwnedTask } from './lifetime.js'

export interface ControlParticipantOptions {
  readonly exchange: (request: ParticipantRequest, options: ParticipantExchangeOptions) => Promise<unknown>
  readonly timeoutMs?: number
}
export interface ApplicationPublication { readonly publication: SignedPublication; readonly version: number }
export interface PublishedApplicationDefinition {
  readonly descriptor: SignedApplicationDescriptor
  readonly definition: ApplicationDescription
  readonly schema: SignedApplicationSchema | null
}

/**
 * The host is a control participant attached to this device's session. It has a
 * distinct delivery policy and never attaches as an application-data reader.
 * Attaching performs no I/O; explicit lifecycle actions are its only requests.
 */
export class ApplicationControlParticipant implements ApplicationControlHost {
  readonly role = 'control' as const
  readonly #replica: PeerReplica
  readonly #store: BytesStore
  readonly #transport: ParticipantTransport
  readonly #lifetime = new AbortController()
  readonly #signal: AbortSignal
  readonly #timeoutMs: number
  readonly #publicationKey: string
  readonly #publicationAttempts: string
  #tail: Promise<unknown> = Promise.resolve()

  constructor(replica: PeerReplica, store: BytesStore, signal: AbortSignal, options: ControlParticipantOptions) {
    const timeoutMs = options.timeoutMs ?? 30_000
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error('APPLICATION_CONTROL_TIMEOUT_INVALID')
    this.#replica = replica; this.#store = store; this.#timeoutMs = timeoutMs
    this.#signal = AbortSignal.any([signal, this.#lifetime.signal])
    this.#transport = createParticipantTransport({ applicationId: replica.descriptor.applicationId, exchange: options.exchange })
    this.#publicationKey = `peer-session/publication/${replica.descriptor.applicationId}`
    this.#publicationAttempts = `peer-session/publication-attempt/${replica.descriptor.applicationId}`
  }
  get signal(): AbortSignal { return this.#signal }
  get policy() { return this.#transport.policy }

  /** Learn and durably fence newer authority even while its selected data is still missing. */
  async application(options: { readonly signal?: AbortSignal } = {}): Promise<AuthorityBundle> {
    const signal = options.signal === undefined ? this.#signal : AbortSignal.any([this.#signal, options.signal])
    const bundle = await this.#request<AuthorityBundle>('control', 'read', {}, signal)
    signal.throwIfAborted()
    await this.#replica.receiveHistory(bundle, [])
    signal.throwIfAborted()
    return this.#replica.authority
  }

  async selectGeneration(input: SignedTransitionRequest, options: { readonly signal?: AbortSignal } = {}): Promise<SignedGeneration> {
    const signal = options.signal === undefined ? this.#signal : AbortSignal.any([this.#signal, options.signal])
    const request = structuredClone(input)
    if (request.payload.applicationId !== this.#replica.descriptor.applicationId) throw new Error('PEER_SCOPE_MISMATCH')
    const selected = await this.#request<SignedGeneration>('control', 'select', { request }, signal)
    const bundle = this.#replica.authority
    if (await peerDigest(selected.payload.transition) !== await peerDigest(request)) throw new Error('APPLICATION_TRANSITION_REPLY_MISMATCH')
    const index = selected.payload.number, known = bundle.generations[index]
    if (!Number.isSafeInteger(index) || index < 0 || index > bundle.generations.length || known !== undefined && known.id !== selected.id) {
      throw new Error('APPLICATION_TRANSITION_REPLY_MISMATCH')
    }
    await verifyAuthorityBundle({ descriptor: bundle.descriptor,
      controls: bundle.controls.slice(0, selected.payload.controlRevision + 1),
      generations: [...bundle.generations.slice(0, index), selected] }, bundle.descriptor)
    signal.throwIfAborted()
    return selected
  }

  async definition(): Promise<PublishedApplicationDefinition> {
    const result = await this.#request<PublishedApplicationDefinition>('publication', 'definition', {})
    const descriptor = this.#replica.authority.descriptor
    if (await peerDigest(result.descriptor) !== await peerDigest(descriptor)) throw new Error('PEER_DESCRIPTOR_CHANGED')
    const definition = validateApplicationDescription(result.definition)
    if (await applicationDescriptionDigest(definition) !== descriptor.payload.definitionDigest ||
      (result.schema === null ? null : await peerDigest(result.schema)) !== descriptor.payload.schemaDigest ||
      (definition.schema === null) !== (result.schema === null) || result.schema !== null && definition.schema !== result.schema.payload.program) {
      throw new Error('APPLICATION_DEFINITION_MISMATCH')
    }
    if (result.schema !== null) await verifyApplicationSchema(result.schema, descriptor.payload)
    this.#signal.throwIfAborted()
    return { descriptor, definition, schema: result.schema }
  }

  /** Verify the selected code chain and remember its head outside lossy application history. */
  publication(): Promise<ApplicationPublication | null> {
    return this.#serial(() => this.#readPublication())
  }

  /** Save the exact signed code update before returning; retrying its identity never signs new intent. */
  preparePublication(input: {
    readonly operationId: string; readonly entry: string; readonly files: readonly PublicationFile[]
  }): Promise<SignedPublication> {
    const captured = structuredClone(input)
    return this.#serial(async () => {
      const journalKey = `${this.#publicationAttempts}/${await peerDigest(captured.operationId)}`
      const saved = await this.#store.get(journalKey)
      this.#signal.throwIfAborted()
      if (saved !== null) {
        const publication = decodePeerValue<SignedPublication>(saved)
        await verifyPublicationManifest(publication, await verifyAuthorityBundle(this.#replica.authority))
        if (publication.payload.author !== this.#replica.device.publicKey || publication.payload.operationId !== captured.operationId ||
          await peerDigest({ entry: publication.payload.entry, files: publication.payload.files }) !== await peerDigest({ entry: captured.entry, files: captured.files })) {
          throw new Error('PEER_PUBLICATION_OPERATION_REUSED')
        }
        return publication
      }
      const current = await this.#readPublication(), authority = await verifyAuthorityBundle(this.#replica.authority)
      if (authority.grant(this.#replica.device.publicKey)?.administrator !== true) throw new Error('PEER_PUBLICATION_FORBIDDEN')
      const descriptor = authority.descriptor
      const publication = await signPublicationManifest({ applicationId: descriptor.applicationId, historyId: descriptor.historyId,
        profile: descriptor.profile, controlRevision: authority.control.payload.revision, author: this.#replica.device.publicKey,
        operationId: captured.operationId, revision: (current?.publication.payload.revision ?? -1) + 1,
        previous: current?.publication.id ?? null, definitionDigest: descriptor.definitionDigest,
        executionManifestDigest: descriptor.executionManifestDigest, entry: captured.entry, files: captured.files }, this.#replica.device)
      this.#signal.throwIfAborted()
      await this.#store.put(journalKey, encodePeerValue(publication))
      this.#signal.throwIfAborted()
      return publication
    })
  }

  publish(input: SignedPublication, assets: readonly { readonly hash: string; readonly bytes: string }[]): Promise<ApplicationPublication> {
    const publication = structuredClone(input), capturedAssets = structuredClone(assets)
    return this.#serial(async () => {
      await verifyPublicationManifest(publication, await verifyAuthorityBundle(this.#replica.authority))
      const receipt = await this.#request<ApplicationPublication>('publication', 'publish', { publication, assets: capturedAssets })
      if (await peerDigest(receipt.publication) !== await peerDigest(publication) || !Number.isSafeInteger(receipt.version) || receipt.version < 1) {
        throw new Error('APPLICATION_PUBLICATION_REPLY_MISMATCH')
      }
      // An exact old retry may return its original receipt after a newer release.
      // Refresh the selected head instead of making that old receipt current.
      await this.#readPublication()
      return receipt
    })
  }

  async #readPublication(): Promise<ApplicationPublication | null> {
    await this.application()
    const authority = await verifyAuthorityBundle(this.#replica.authority)
    const stored = await this.#store.get(this.#publicationKey)
    this.#signal.throwIfAborted()
    const previous = stored === null ? null : decodePeerValue<ApplicationPublication>(stored)
    if (previous !== null) await verifyPublicationManifest(previous.publication, authority)
    const current = await this.#request<ApplicationPublication | null>('publication', 'read', {})
    if (current === null) {
      if (previous !== null) throw new Error('APPLICATION_PUBLICATION_REGRESSION')
      return null
    }
    if (!Number.isSafeInteger(current.version) || current.version < 1) throw new Error('APPLICATION_PUBLICATION_REPLY_MISMATCH')
    let cursor = current.publication
    await verifyPublicationManifest(cursor, authority)
    if (previous !== null && (cursor.payload.revision < previous.publication.payload.revision ||
      cursor.payload.revision === previous.publication.payload.revision && cursor.id !== previous.publication.id)) {
      throw new Error('APPLICATION_PUBLICATION_REGRESSION')
    }
    let remaining = PUBLICATION_LIMITS.revisions
    while (cursor.id !== previous?.publication.id && cursor.payload.previous !== null) {
      if (--remaining < 0) throw new Error('APPLICATION_PUBLICATION_HISTORY_LIMIT')
      const prior = await this.#request<ApplicationPublication | null>('publication', 'read', { id: cursor.payload.previous })
      if (prior === null || prior.publication.id !== cursor.payload.previous || prior.publication.payload.revision !== cursor.payload.revision - 1) {
        throw new Error('APPLICATION_PUBLICATION_CHAIN_INVALID')
      }
      await verifyPublicationManifest(prior.publication, authority)
      cursor = prior.publication
    }
    if (previous !== null && cursor.id !== previous.publication.id) throw new Error('APPLICATION_PUBLICATION_REGRESSION')
    this.#signal.throwIfAborted()
    await this.#store.put(this.#publicationKey, encodePeerValue(current))
    this.#signal.throwIfAborted()
    return structuredClone(current)
  }

  close(): Promise<void> {
    this.#lifetime.abort(new Error('APPLICATION_CONTROL_CLOSED'))
    return this.#tail.then(() => undefined)
  }

  #serial<T>(call: () => Promise<T>): Promise<T> {
    const result = this.#tail.then(() => { this.#signal.throwIfAborted(); return call() })
    this.#tail = result.catch(() => undefined)
    return result
  }
  async #request<T>(facet: 'control' | 'publication', action: string, payload: unknown, lifetime = this.#signal): Promise<T> {
    lifetime.throwIfAborted()
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(new Error('APPLICATION_CONTROL_TIMEOUT')), this.#timeoutMs)
    const signal = AbortSignal.any([lifetime, controller.signal])
    try { return await awaitOwnedTask(signal, () => this.#transport.request<T>(facet, action, payload, { signal })) }
    finally { clearTimeout(timer) }
  }
}

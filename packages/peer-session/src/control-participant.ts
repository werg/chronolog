import type { BytesStore } from '@chronolog/records'
import {
  createParticipantTransport, decodePeerValue, encodePeerValue, peerDigest,
  verifyAuthorityBundle, verifyPublicationManifest, signPublicationManifest,
  validateApplicationDescription, applicationDescriptionDigest, verifyApplicationSchema, PUBLICATION_LIMITS,
  type ApplicationDescription, type AuthorityBundle, type ParticipantRequest, type ParticipantExchangeOptions, type ParticipantTransport,
  type SignedApplicationDescriptor, type SignedApplicationSchema, type SignedGeneration, type SignedTransitionRequest,
  type SignedPublication, type PublicationFile,
} from '@chronolog/peer-generation/control'
import type { ApplicationControlHost } from './recovery.js'
import { awaitOwnedTask } from './lifetime.js'
import { updateDeviceMetadata } from './metadata.js'
import type { ApplicationParticipant } from './participant-types.js'

type ControlOwner = Pick<ApplicationParticipant, 'device' | 'descriptor' | 'authority' | 'adoptAuthority'>

export interface ControlParticipantOptions {
  readonly exchange: (request: ParticipantRequest, options: ParticipantExchangeOptions) => Promise<unknown>
  readonly timeoutMs?: number
}
export interface ApplicationPublication { readonly publication: SignedPublication; readonly version: number }
export interface ApplicationPublicationOperation {
  readonly publication: SignedPublication
  /** A retained acknowledgement, not a claim that this publication is still selected. */
  readonly receipt: ApplicationPublication | null
}
export type ApplicationPublicationPhase = 'submission' | 'receipt' | 'retention' | 'selection'

/** A failed publication call can still have a confirmed, retry-stable host receipt. */
export class ApplicationPublicationError extends Error {
  readonly code: 'APPLICATION_PUBLICATION_OUTCOME_UNKNOWN' | 'APPLICATION_PUBLICATION_COMMITTED'
  readonly outcome: 'unknown' | 'committed'
  readonly operationId: string
  readonly publicationId: string
  readonly receipt: ApplicationPublication | null

  constructor(publication: SignedPublication, readonly phase: ApplicationPublicationPhase, cause: unknown,
    receipt: ApplicationPublication | null = null) {
    const code = receipt === null ? 'APPLICATION_PUBLICATION_OUTCOME_UNKNOWN' : 'APPLICATION_PUBLICATION_COMMITTED'
    super(`${code}${cause instanceof Error ? `: ${cause.message}` : ''}`, { cause })
    this.name = 'ApplicationPublicationError'; this.code = code
    this.outcome = receipt === null ? 'unknown' : 'committed'
    this.operationId = publication.payload.operationId; this.publicationId = publication.id
    this.receipt = receipt === null ? null : structuredClone(receipt)
  }
}
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
  readonly #participant: ControlOwner
  readonly #store: BytesStore
  readonly #transport: ParticipantTransport
  readonly #lifetime = new AbortController()
  readonly #signal: AbortSignal
  readonly #timeoutMs: number
  readonly #publicationKey: string
  readonly #publicationAttempts: string
  readonly #publicationReceipts: string
  #tail: Promise<unknown> = Promise.resolve()

  constructor(participant: ControlOwner, store: BytesStore, signal: AbortSignal, options: ControlParticipantOptions) {
    const timeoutMs = options.timeoutMs ?? 30_000
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error('APPLICATION_CONTROL_TIMEOUT_INVALID')
    this.#participant = participant; this.#store = store; this.#timeoutMs = timeoutMs
    this.#signal = AbortSignal.any([signal, this.#lifetime.signal])
    this.#transport = createParticipantTransport({ applicationId: participant.descriptor.applicationId, exchange: options.exchange })
    this.#publicationKey = `peer-session/publication/${participant.descriptor.applicationId}`
    this.#publicationAttempts = `peer-session/publication-attempt/${participant.descriptor.applicationId}`
    this.#publicationReceipts = `peer-session/publication-receipt/${participant.descriptor.applicationId}`
  }
  get signal(): AbortSignal { return this.#signal }
  get policy() { return this.#transport.policy }

  /** Learn and durably fence newer authority even while its selected data is still missing. */
  async application(options: { readonly signal?: AbortSignal } = {}): Promise<AuthorityBundle> {
    const signal = options.signal === undefined ? this.#signal : AbortSignal.any([this.#signal, options.signal])
    const bundle = await this.#request<AuthorityBundle>('control', 'read', {}, signal)
    signal.throwIfAborted()
    await this.#participant.adoptAuthority(bundle)
    signal.throwIfAborted()
    return this.#participant.authority
  }

  async selectGeneration(input: SignedTransitionRequest, options: { readonly signal?: AbortSignal } = {}): Promise<SignedGeneration> {
    const signal = options.signal === undefined ? this.#signal : AbortSignal.any([this.#signal, options.signal])
    const request = structuredClone(input)
    if (request.payload.applicationId !== this.#participant.descriptor.applicationId) throw new Error('PEER_SCOPE_MISMATCH')
    const selected = await this.#request<SignedGeneration>('control', 'select', { request }, signal)
    const bundle = this.#participant.authority
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
    const descriptor = this.#participant.authority.descriptor
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

  /** Inspect this device's saved intent and receipt without contacting the host or opening application data. */
  publicationOperation(operationId: string): Promise<ApplicationPublicationOperation | null> {
    return this.#serial(async () => {
      const key = await peerDigest(operationId), author = this.#participant.device.publicKey
      const attempt = await this.#store.get(`${this.#publicationAttempts}/${key}`)
      const retained = await this.#store.get(`${this.#publicationReceipts}/${author}/${key}`)
      if (attempt === null && retained === null) { this.#signal.throwIfAborted(); return null }
      const receipt = retained === null ? null : readPublicationReceipt(decodePeerValue<unknown>(retained))
      const publication = attempt === null ? receipt!.publication : decodePeerValue<SignedPublication>(attempt)
      await verifyPublicationManifest(publication, await verifyAuthorityBundle(this.#participant.authority))
      if (publication.payload.author !== author || publication.payload.operationId !== operationId) {
        throw new Error('PEER_PUBLICATION_OPERATION_REUSED')
      }
      if (receipt !== null) await verifyPublicationReceipt(receipt, publication)
      this.#signal.throwIfAborted()
      return structuredClone({ publication, receipt })
    })
  }

  /** Save the exact signed code update before returning; retrying its identity never signs new intent. */
  preparePublication(input: {
    readonly operationId: string; readonly entry: string; readonly files: readonly PublicationFile[]
  }): Promise<SignedPublication> {
    const captured = structuredClone(input)
    return this.#serial(async () => {
      const journalKey = `${this.#publicationAttempts}/${await peerDigest(captured.operationId)}`
      const saved = await updateDeviceMetadata(this.#store, journalKey, async currentAttempt => {
        this.#signal.throwIfAborted()
        if (currentAttempt !== null) {
          const publication = decodePeerValue<SignedPublication>(currentAttempt)
          await verifyPublicationManifest(publication, await verifyAuthorityBundle(this.#participant.authority))
          if (publication.payload.author !== this.#participant.device.publicKey || publication.payload.operationId !== captured.operationId ||
            await peerDigest({ entry: publication.payload.entry, files: publication.payload.files }) !== await peerDigest({ entry: captured.entry, files: captured.files })) {
            throw new Error('PEER_PUBLICATION_OPERATION_REUSED')
          }
          return currentAttempt
        }
        const current = await this.#readPublication(), authority = await verifyAuthorityBundle(this.#participant.authority)
        if (authority.grant(this.#participant.device.publicKey)?.publisher !== true) throw new Error('PEER_PUBLICATION_FORBIDDEN')
        const descriptor = authority.descriptor
        const publication = await signPublicationManifest({ applicationId: descriptor.applicationId, historyId: descriptor.historyId,
          profile: descriptor.profile, controlRevision: authority.control.payload.revision, author: this.#participant.device.publicKey,
          operationId: captured.operationId, revision: (current?.publication.payload.revision ?? -1) + 1,
          previous: current?.publication.id ?? null, definitionDigest: descriptor.definitionDigest,
          executionManifestDigest: descriptor.executionManifestDigest, entry: captured.entry, files: captured.files }, this.#participant.device)
        this.#signal.throwIfAborted()
        return encodePeerValue(publication)
      })
      this.#signal.throwIfAborted()
      return decodePeerValue<SignedPublication>(saved)
    })
  }

  publish(input: SignedPublication, assets: readonly { readonly hash: string; readonly bytes: string }[]): Promise<ApplicationPublication> {
    const publication = structuredClone(input), capturedAssets = structuredClone(assets)
    return this.#serial(async () => {
      await verifyPublicationManifest(publication, await verifyAuthorityBundle(this.#participant.authority))
      const key = `${this.#publicationReceipts}/${publication.payload.author}/${await peerDigest(publication.payload.operationId)}`
      const stored = await this.#store.get(key)
      // Previously confirmed acceptance must not become unknown on a later retry.
      let receipt = stored === null ? null : await verifyPublicationReceipt(decodePeerValue<unknown>(stored), publication)
      let phase: ApplicationPublicationPhase = 'submission'
      try {
        const reply = await this.#request<unknown>('publication', 'publish', { publication, assets: capturedAssets })
        phase = 'receipt'
        const acknowledged = await verifyPublicationReceipt(reply, publication)
        if (receipt !== null && receipt.version !== acknowledged.version) throw new Error('APPLICATION_PUBLICATION_REPLY_MISMATCH')
        receipt = acknowledged
        phase = 'retention'
        // Once the reply is validated, drain its journal write even if the session
        // closes. Session close retains storage ownership until this task settles.
        await updateDeviceMetadata(this.#store, key, async current => {
          if (current !== null && await peerDigest(decodePeerValue<unknown>(current)) !== await peerDigest(acknowledged)) {
            throw new Error('APPLICATION_PUBLICATION_RECEIPT_CONFLICT')
          }
          return encodePeerValue(acknowledged)
        })
        phase = 'selection'
        // An exact old retry may return its original receipt after a newer release.
        // Refresh the selected head instead of making that old receipt current.
        await this.#readPublication(acknowledged)
        return receipt
      } catch (cause) {
        throw new ApplicationPublicationError(publication, phase, cause, receipt)
      }
    })
  }

  async #readPublication(acknowledged?: ApplicationPublication): Promise<ApplicationPublication | null> {
    await this.application()
    const authority = await verifyAuthorityBundle(this.#participant.authority)
    const reply = await this.#request<unknown>('publication', 'read', {})
    const current = reply === null ? null : readPublicationReceipt(reply)
    if (current === null) {
      if (await this.#store.get(this.#publicationKey) !== null) throw new Error('APPLICATION_PUBLICATION_REGRESSION')
      if (acknowledged !== undefined) throw new Error('APPLICATION_PUBLICATION_NOT_SELECTED')
      this.#signal.throwIfAborted()
      return null
    }
    await updateDeviceMetadata(this.#store, this.#publicationKey, async stored => {
      this.#signal.throwIfAborted()
      const previous = stored === null ? null : readPublicationReceipt(decodePeerValue<unknown>(stored))
      if (previous !== null) await verifyPublicationManifest(previous.publication, authority)
      // Storage versions are host acknowledgements, but each manifest must keep
      // the same version across its receipt, selected head and retained history.
      const checkVersion = async (receipt: ApplicationPublication): Promise<void> => {
        const publication = receipt.publication
        // The candidate manifest was verified against this application's authority.
        // Bind its exact journal receipt before trusting the saved storage version,
        // including when an earlier failed selection never established a checkpoint.
        const retained = await this.#store.get(`${this.#publicationReceipts}/${publication.payload.author}/${await peerDigest(publication.payload.operationId)}`)
        const saved = retained === null ? null : await verifyPublicationReceipt(decodePeerValue<unknown>(retained), publication)
        for (const expected of [previous, acknowledged, saved]) {
          if (expected != null && receipt.publication.id === expected.publication.id && receipt.version !== expected.version) {
            throw new Error('APPLICATION_PUBLICATION_REPLY_MISMATCH')
          }
        }
      }
      let cursor = current.publication
      await verifyPublicationManifest(cursor, authority)
      await checkVersion(current)
      if (previous !== null && (cursor.payload.revision < previous.publication.payload.revision ||
        cursor.payload.revision === previous.publication.payload.revision && cursor.id !== previous.publication.id)) {
        throw new Error('APPLICATION_PUBLICATION_REGRESSION')
      }
      let previousSeen = cursor.id === previous?.publication.id
      let acknowledgedSeen = acknowledged === undefined || cursor.id === acknowledged.publication.id
      let remaining = PUBLICATION_LIMITS.revisions
      while ((previous === null || !previousSeen || !acknowledgedSeen) && cursor.payload.previous !== null) {
        if (--remaining < 0) throw new Error('APPLICATION_PUBLICATION_HISTORY_LIMIT')
        const response = await this.#request<unknown>('publication', 'read', { id: cursor.payload.previous })
        const prior = response === null ? null : readPublicationReceipt(response)
        if (prior === null || prior.publication.id !== cursor.payload.previous || prior.publication.payload.revision !== cursor.payload.revision - 1) {
          throw new Error('APPLICATION_PUBLICATION_CHAIN_INVALID')
        }
        await verifyPublicationManifest(prior.publication, authority)
        await checkVersion(prior)
        cursor = prior.publication
        previousSeen ||= cursor.id === previous?.publication.id
        acknowledgedSeen ||= cursor.id === acknowledged?.publication.id
      }
      if (previous !== null && !previousSeen) throw new Error('APPLICATION_PUBLICATION_REGRESSION')
      if (!acknowledgedSeen) throw new Error('APPLICATION_PUBLICATION_NOT_SELECTED')
      this.#signal.throwIfAborted()
      return encodePeerValue(current)
    })
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

async function verifyPublicationReceipt(input: unknown, publication: SignedPublication): Promise<ApplicationPublication> {
  const receipt = readPublicationReceipt(input)
  if (await peerDigest(receipt.publication) !== await peerDigest(publication)) throw new Error('APPLICATION_PUBLICATION_REPLY_MISMATCH')
  return { publication: structuredClone(publication), version: receipt.version }
}

function readPublicationReceipt(input: unknown): ApplicationPublication {
  if (input === null || typeof input !== 'object' || !('publication' in input) || !('version' in input) ||
    typeof input.version !== 'number' || !Number.isSafeInteger(input.version) || input.version < 1) {
    throw new Error('APPLICATION_PUBLICATION_REPLY_MISMATCH')
  }
  return { publication: input.publication as SignedPublication, version: input.version }
}

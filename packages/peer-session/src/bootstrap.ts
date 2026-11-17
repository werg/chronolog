import {
  applicationDescriptionDigest, bytesDigest, decodePeerValue, encodePeerValue, participantGrant, peerDigest, signTransitionRequest, verifyApplicationSchema, verifyAuthorityBundle,
  type AuthorityBundle, type PeerGrant, type SignedApplicationDescriptor, type SignedApplicationSchema, type SignedTransitionRequest,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, canonicalJson, executionManifestArtifacts, hexToBytes, type EventPayload } from '@chronolog/protocol'
import { applicationDefinitionDigest, describeApplication, type ApplicationDefinition, type ApplicationDescription } from './definition.js'
import { claimApplicationDevice, type ApplicationDevice } from './device.js'
import { ApplicationKeyring } from './keys.js'
import type { ApplicationControlHost } from './recovery.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'

export type ApplicationMember = { readonly publicKey: string; readonly administrator?: boolean; readonly dataRole?: 'member' | 'admin' | null; readonly accountId?: string }
  | { readonly grant: PeerGrant; readonly accountId?: string }
export interface ApplicationConfiguration {
  readonly historyId: string
  readonly executionManifestDigest: string
  readonly definition: ApplicationDescription
  readonly schemaAdministrator: string
  readonly schema: SignedApplicationSchema | null
  readonly epoch: number
  readonly keyDigest: string
  readonly members: readonly ApplicationMember[]
}
export interface ApplicationPublication {
  readonly descriptor: SignedApplicationDescriptor
  readonly definition: ApplicationDescription
  readonly schema: SignedApplicationSchema | null
}
/** The public hosted control interface. It never receives application keys or commands. */
export interface ApplicationBootstrapHost extends ApplicationControlHost {
  configureApplication(configuration: ApplicationConfiguration): Promise<AuthorityBundle>
  definition(): Promise<ApplicationPublication>
}
export interface ApplicationCreation {
  /** Generated once and saved before publication when omitted. */
  readonly historyId?: string
  /** Defaults to this device as an ordinary eligible participant. */
  readonly members?: readonly ApplicationMember[]
  /** Omit for the SQL-free events profile; SQL preparation helpers provide these fields. */
  readonly executionManifestDigest?: string
  readonly schemaAdministrator?: string
  readonly schema?: SignedApplicationSchema | null
}
export interface ApplicationSessionBootstrapOptions<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly device: ApplicationDevice
  readonly definition: D
  readonly applicationId: string
  /** Required on first publication or first join. Cached reopen makes no hosted request. */
  readonly host?: ApplicationBootstrapHost
  /** Explicit first publication. Retrying it preserves its original key and transition identity. */
  readonly create?: ApplicationCreation
  readonly signal?: AbortSignal
}
export interface PreparedApplicationSession {
  readonly authority: AuthorityBundle
  readonly schema: SignedApplicationSchema | null
}
interface CreationJournal {
  readonly version: 1
  readonly applicationId: string
  readonly deviceId: string
  readonly epochKey: string
  readonly configuration: ApplicationConfiguration
  readonly descriptor: SignedApplicationDescriptor | null
  readonly request: SignedTransitionRequest | null
}

/**
 * Own initial publication, key enrollment and exact initial selection. SQL openers
 * reuse this prepared binding; callers never construct signed control requests.
 */
export async function prepareApplicationSession<const D extends ApplicationDefinition>(options: ApplicationSessionBootstrapOptions<D>): Promise<PreparedApplicationSession> {
  if (!/^[0-9a-f]{64}$/u.test(options.applicationId)) throw new Error('APPLICATION_ID_INVALID')
  options.signal?.throwIfAborted()
  const release = claimApplicationDevice(options.device)
  const cacheKey = `peer-session/application/v1/${options.applicationId}`, journalKey = `peer-session/creation/v1/${options.applicationId}`
  const write = async (key: string, bytes: Uint8Array): Promise<void> => {
    options.signal?.throwIfAborted()
    try { await options.device.store.put(key, bytes) }
    catch (error) { await options.device.close(); throw error }
  }
  const writeJournal = (value: CreationJournal): Promise<void> => write(journalKey, new TextEncoder().encode(journalJson(value)))
  const host = (): ApplicationBootstrapHost => {
    if (options.host === undefined) throw new Error('APPLICATION_BOOTSTRAP_HOST_REQUIRED')
    return options.host
  }
  const remote = <T>(action: () => Promise<T>): Promise<T> => { options.signal?.throwIfAborted(); return interrupted(action(), options.signal) }
  const verify = async (value: PreparedApplicationSession, pinned?: SignedApplicationDescriptor): Promise<PreparedApplicationSession> => {
    const authority = await verifyAuthorityBundle(value.authority, pinned)
    const descriptor = authority.descriptor
    if (descriptor.applicationId !== options.applicationId || descriptor.definitionDigest !== await applicationDefinitionDigest(options.definition)) {
      throw new Error('APPLICATION_DEFINITION_MISMATCH')
    }
    if (value.schema === null) {
      if (descriptor.schemaDigest !== null || options.definition.schema !== undefined) throw new Error('APPLICATION_SCHEMA_REQUIRED')
    } else {
      await verifyApplicationSchema(value.schema, descriptor)
      if (describeApplication(options.definition).schema !== value.schema.payload.program) throw new Error('APPLICATION_SCHEMA_DEFINITION_MISMATCH')
    }
    options.signal?.throwIfAborted()
    return value
  }
  try {
    const cached = await options.device.store.get(cacheKey)
    const cache = cached === null ? null : await verify(decodePeerValue<PreparedApplicationSession>(cached))
    if (options.create === undefined) {
      if (cache !== null) return structuredClone(cache)
      const authority = await remote(() => host().application()), publication = await remote(() => host().definition())
      const value = await verify({ authority, schema: publication.schema }, publication.descriptor)
      if (await applicationDescriptionDigest(publication.definition) !== await applicationDefinitionDigest(options.definition)) throw new Error('APPLICATION_DEFINITION_MISMATCH')
      if (value.authority.generations.length === 0) throw new Error('APPLICATION_NOT_INITIALIZED')
      await write(cacheKey, encodePeerValue(value)); return structuredClone(value)
    }

    const prior = await options.device.store.get(journalKey)
    const retained = prior === null ? null : readJournal(prior)
    const journalFields = ['version', 'applicationId', 'deviceId', 'epochKey', 'configuration', 'descriptor', 'request']
    if (retained !== null && (Object.keys(retained).length !== journalFields.length || !journalFields.every(field => Object.hasOwn(retained, field)) ||
        retained.version !== 1 || retained.applicationId !== options.applicationId || retained.deviceId !== options.device.identity.publicKey ||
        !/^[0-9a-f]{64}$/u.test(retained.epochKey))) throw new Error('APPLICATION_CREATION_JOURNAL_INVALID')
    let journal = retained
    const epochKey = journal?.epochKey ?? bytesToHex(crypto.getRandomValues(new Uint8Array(32)))
    if (options.definition.schema !== undefined && options.create.executionManifestDigest === undefined) throw new Error('APPLICATION_SQL_EXECUTION_REQUIRED')
    const configuration: ApplicationConfiguration = {
      historyId: options.create.historyId ?? journal?.configuration.historyId ?? crypto.randomUUID(),
      executionManifestDigest: options.create.executionManifestDigest ?? bytesToHex((await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))).executionManifestDigest),
      definition: describeApplication(options.definition), schemaAdministrator: options.create.schemaAdministrator ?? options.device.identity.publicKey,
      schema: options.create.schema ?? null, epoch: 0, keyDigest: await bytesDigest(hexToBytes(epochKey)),
      members: options.create.members ?? [{ publicKey: options.device.identity.publicKey }],
    }
    const member = configuration.members.map(value => 'grant' in value ? value.grant : participantGrant(value.publicKey, {
      ...(value.administrator === undefined ? {} : { administrator: value.administrator }),
      ...(value.dataRole === undefined ? {} : { dataRole: value.dataRole }),
    })).find(value => value.publicKey === options.device.identity.publicKey)
    if (member?.reader !== true || !member.coordinator || !member.recovery) throw new Error('APPLICATION_INITIAL_DEVICE_NOT_ELIGIBLE')
    if (journal !== null && await configurationDigest(journal.configuration) !== await configurationDigest(configuration)) throw new Error('APPLICATION_CREATION_INPUT_CHANGED')
    if (journal === null) {
      journal = { version: 1, applicationId: options.applicationId, deviceId: options.device.identity.publicKey, epochKey, configuration, descriptor: null, request: null }
      await writeJournal(journal)
    }
    if (cache !== null) return structuredClone(cache)
    const savedConfiguration = journal.configuration
    let authority = await remote(() => host().configureApplication(savedConfiguration))
    await verify({ authority, schema: journal.configuration.schema }, journal.descriptor ?? undefined)
    const descriptor = authority.descriptor.payload
    if (descriptor.historyId !== configuration.historyId || descriptor.executionManifestDigest !== configuration.executionManifestDigest ||
        descriptor.schemaAdministrator !== configuration.schemaAdministrator || authority.controls[0]?.payload.epoch !== 0 ||
        authority.controls[0]?.payload.keyDigest !== configuration.keyDigest) throw new Error('APPLICATION_CONFIGURATION_MISMATCH')
    if (journal.descriptor === null) { journal = { ...journal, descriptor: authority.descriptor }; await writeJournal(journal) }
    // Save enrolled keys before any generation can make this device responsible
    // for ordering. The bootstrap journal remains an exact retry record.
    const seed = hexToBytes(journal.epochKey)
    try {
      const keys = await ApplicationKeyring.open({ device: options.device, authority, epochKeys: new Map([[0, seed]]) })
      keys.close()
    } finally { seed.fill(0) }
    if (journal.request === null && authority.generations.length === 0) {
      const request = await signTransitionRequest({ applicationId: options.applicationId, profile: descriptor.profile, policy: descriptor.policy,
        transitionId: `create-${crypto.randomUUID()}`, expectedGeneration: null, coordinator: options.device.identity.publicKey,
        requester: options.device.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, options.device.identity)
      journal = { ...journal, request }; await writeJournal(journal)
    }
    if (journal.request !== null) {
      const request = journal.request, selected = await remote(() => host().selectGeneration(request))
      authority = await remote(() => host().application())
      const committed = authority.generations.find(generation => generation.id === selected.id)
      if (committed === undefined) throw new Error('APPLICATION_INITIAL_SELECTION_MISSING')
      if (await peerDigest(committed.payload.transition) !== await peerDigest(request)) throw new Error('APPLICATION_INITIAL_SELECTION_MISMATCH')
    }
    const completed = await verify({ authority, schema: journal.configuration.schema }, journal.descriptor!)
    if (completed.authority.generations.length === 0) throw new Error('APPLICATION_NOT_INITIALIZED')
    await write(cacheKey, encodePeerValue(completed))
    return structuredClone(completed)
  } catch (error) { await options.device.close(); throw error }
  finally { release() }
}

// Public JSON schemas permit finite fractional bounds. Keep their durable
// journal representation separate from the integer-only signed control codec.
const JOURNAL_BYTES = 1_048_576
function journalJson(value: CreationJournal): string {
  return canonicalJson(value as unknown as EventPayload, { maxBytes: JOURNAL_BYTES, maxNodes: 131_072, maxDepth: 40 })
}
function readJournal(bytes: Uint8Array): CreationJournal {
  if (bytes.length > JOURNAL_BYTES) throw new Error('APPLICATION_CREATION_JOURNAL_INVALID')
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes), value = JSON.parse(text) as CreationJournal
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('APPLICATION_CREATION_JOURNAL_INVALID')
  if (journalJson(value) !== text) throw new Error('APPLICATION_CREATION_JOURNAL_INVALID')
  return value
}
async function configurationDigest(value: ApplicationConfiguration): Promise<string> {
  return peerDigest({ ...value, definition: await applicationDescriptionDigest(value.definition) })
}

/** Supported events session: create, join or resume offline through one owned device. */
export async function openApplicationSession<const D extends ApplicationDefinition>(options: ApplicationSessionBootstrapOptions<D> &
  Omit<OpenPeerApplicationOptions<D>, 'device' | 'definition' | 'authority' | 'epochKeys'>): Promise<ApplicationSession<D>> {
  if (options.definition.schema !== undefined && options.createMaterializer === undefined) throw new Error('APPLICATION_SQL_MATERIALIZER_REQUIRED')
  const prepared = await prepareApplicationSession(options)
  return openPeerApplication({ device: options.device, definition: options.definition, authority: prepared.authority,
    ...(options.createMaterializer === undefined ? {} : { createMaterializer: options.createMaterializer }),
    ...(options.maxRecords === undefined ? {} : { maxRecords: options.maxRecords }),
    ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) })
}

function interrupted<T>(value: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return value
  if (signal.aborted) { void value.catch(() => undefined); return Promise.reject(signal.reason) }
  return new Promise((resolve, reject) => {
    const abort = (): void => { reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    void value.then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
  })
}

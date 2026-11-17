import {
  DeterministicMaterializer, createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import { applicationDescriptionDigest, signApplicationSchema, verifyApplicationSchema, type PeerIdentity, type SignedApplicationSchema } from '@chronolog/peer-generation'
import { bytesToHex, encodeChangeProgram, executionManifestArtifacts, hexToBytes } from '@chronolog/protocol'

import { describeApplication, type ApplicationDefinition } from './definition.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'
import { prepareApplicationSession, type ApplicationCreation, type ApplicationSessionBootstrapOptions } from './bootstrap.js'

/** Exact compiled native engine and platform identity for the peer-generation SQL profile. */
export function createNativeSqlManifest() {
  return createDoltLiteExecutionManifest({ profile: 'chronolog-peer-sql-v1' })
}

/** Public definition and signed schema fields ready for hosted application configuration. */
export async function prepareNativeSqlApplication(options: {
  readonly applicationId: string
  readonly definition: ApplicationDefinition
  readonly schemaAdministrator: PeerIdentity
}) {
  const definition = describeApplication(options.definition)
  if (definition.schema === null) throw new Error('APPLICATION_SCHEMA_REQUIRED')
  const definitionDigest = await applicationDescriptionDigest(definition)
  const executionManifestDigest = bytesToHex((await executionManifestArtifacts(createNativeSqlManifest())).executionManifestDigest)
  const schema = await signApplicationSchema({ applicationId: options.applicationId, definitionDigest, executionManifestDigest,
    program: definition.schema }, options.schemaAdministrator)
  return { definition, schema, executionManifestDigest, schemaAdministrator: options.schemaAdministrator.publicKey }
}

/** Verifies a separately authorized schema before constructing the permanent genesis state. */
export async function openNativeSqlApplication<const D extends ApplicationDefinition>(options: Omit<OpenPeerApplicationOptions<D>, 'createMaterializer'> & {
  readonly databasePath: string
  readonly schema: SignedApplicationSchema
}): Promise<ApplicationSession<D>> {
  return openPeerApplication({ ...options, createMaterializer: async () => {
    const descriptor = options.authority.descriptor.payload
    const bootstrapProgram = await verifyApplicationSchema(options.schema, descriptor)
    if (options.definition.schema === undefined || bytesToHex(encodeChangeProgram(options.definition.schema)) !== options.schema.payload.program) {
      throw new Error('APPLICATION_SCHEMA_DEFINITION_MISMATCH')
    }
    const executionManifest = createNativeSqlManifest()
    if (bytesToHex((await executionManifestArtifacts(executionManifest)).executionManifestDigest) !== descriptor.executionManifestDigest) {
      throw new Error('PEER_EXECUTION_MANIFEST_MISMATCH')
    }
    const materializer = await DeterministicMaterializer.open({ path: options.databasePath, executionManifest,
      historyProfile: 'peer-generation-v1', rootAdministrator: hexToBytes(descriptor.schemaAdministrator),
      bootstrapGroupId: hexToBytes(descriptor.applicationId), bootstrapProgram })
    return createDoltLiteMaterializationRuntime(materializer)
  } })
}

/** Create, join or resume SQL using the same owned bootstrap and schema authority. */
export async function openNativeSqlSession<const D extends ApplicationDefinition>(options: Omit<ApplicationSessionBootstrapOptions<D>, 'create'> & {
  readonly create?: Omit<ApplicationCreation, 'executionManifestDigest' | 'schemaAdministrator' | 'schema'>
  readonly databasePath: string
  readonly maxRecords?: number
  readonly maxHistoryBytes?: number
}): Promise<ApplicationSession<D>> {
  const creation = options.create === undefined ? undefined : await prepareNativeSqlApplication({
    applicationId: options.applicationId, definition: options.definition, schemaAdministrator: options.device.identity,
  })
  const prepared = await prepareApplicationSession({ device: options.device, definition: options.definition, applicationId: options.applicationId,
    ...(options.host === undefined ? {} : { host: options.host }), ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(creation === undefined ? {} : { create: { ...options.create, executionManifestDigest: creation.executionManifestDigest,
      schemaAdministrator: creation.schemaAdministrator, schema: creation.schema } }) })
  if (prepared.schema === null) { await options.device.close(); throw new Error('APPLICATION_SCHEMA_REQUIRED') }
  return openNativeSqlApplication({ device: options.device, definition: options.definition, authority: prepared.authority, schema: prepared.schema,
    databasePath: options.databasePath,
    ...(options.maxRecords === undefined ? {} : { maxRecords: options.maxRecords }),
    ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) })
}

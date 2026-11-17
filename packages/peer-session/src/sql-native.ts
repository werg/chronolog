import {
  DeterministicMaterializer, createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import { peerDigest, signApplicationSchema, verifyApplicationSchema, type PeerIdentity, type SignedApplicationSchema } from '@chronolog/peer-generation'
import { bytesToHex, encodeChangeProgram, executionManifestArtifacts, hexToBytes } from '@chronolog/protocol'

import { applicationDefinitionDigest, type ApplicationDefinition } from './definition.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'

/** Exact compiled native engine and platform identity for the peer-generation SQL profile. */
export function createNativeSqlManifest() {
  return createDoltLiteExecutionManifest({ profile: 'chronolog-peer-sql-v1' })
}

/** Prepare the signed schema and binding fields for initial hosted publication. */
export async function prepareNativeSqlApplication(options: {
  readonly applicationId: string
  readonly definition: ApplicationDefinition
  readonly schemaAdministrator: PeerIdentity
}) {
  if (options.definition.schema === undefined) throw new Error('APPLICATION_SCHEMA_REQUIRED')
  const definitionDigest = await applicationDefinitionDigest(options.definition)
  const executionManifestDigest = bytesToHex((await executionManifestArtifacts(createNativeSqlManifest())).executionManifestDigest)
  const schema = await signApplicationSchema({ applicationId: options.applicationId, definitionDigest, executionManifestDigest,
    program: bytesToHex(encodeChangeProgram(options.definition.schema)) }, options.schemaAdministrator)
  return { schema, binding: { definitionDigest, executionManifestDigest, schemaDigest: await peerDigest(schema), schemaAdministrator: options.schemaAdministrator.publicKey } }
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
    const materializer = await DeterministicMaterializer.open({ path: options.databasePath, executionManifest: createNativeSqlManifest(),
      historyProfile: 'peer-generation-v1', rootAdministrator: hexToBytes(descriptor.schemaAdministrator),
      bootstrapGroupId: hexToBytes(descriptor.applicationId), bootstrapProgram })
    return createDoltLiteMaterializationRuntime(materializer)
  } })
}

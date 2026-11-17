import {
  AppliedMaterializer, createDoltLiteExecutionManifest, createDoltLiteAppliedMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import { verifyApplicationSchema, type SignedApplicationSchema } from '@chronolog/peer-generation'
import { bytesToHex, encodeChangeProgram, hexToBytes } from '@chronolog/protocol'

import type { ApplicationDefinition } from './definition.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'

/** Exact compiled native engine and platform identity for the peer-generation SQL profile. */
export function createNativeSqlManifest() {
  return createDoltLiteExecutionManifest({ profile: 'chronolog-peer-sql-v1', sqlPolicy: 'data-only' })
}

/** Verifies a separately authorized schema before constructing the permanent genesis state. */
export async function openNativeSqlApplication<const D extends ApplicationDefinition>(options: Omit<OpenPeerApplicationOptions<D>, 'materializer'> & {
  readonly databasePath: string
  readonly schema: SignedApplicationSchema
}): Promise<ApplicationSession<D>> {
  const descriptor = options.authority.descriptor.payload
  const bootstrapProgram = await verifyApplicationSchema(options.schema, descriptor)
  if (options.definition.schema === undefined || bytesToHex(encodeChangeProgram(options.definition.schema)) !== options.schema.payload.program) {
    throw new Error('APPLICATION_SCHEMA_DEFINITION_MISMATCH')
  }
  const materializer = await AppliedMaterializer.open({ path: options.databasePath, executionManifest: createNativeSqlManifest(),
    sqlPolicy: 'data-only', rootAdministrator: hexToBytes(descriptor.schemaAdministrator),
    bootstrapGroupId: hexToBytes(descriptor.applicationId), bootstrapProgram })
  try { return await openPeerApplication({ ...options, materializer: createDoltLiteAppliedMaterializationRuntime(materializer) }) }
  catch (error) { materializer.close(); throw error }
}

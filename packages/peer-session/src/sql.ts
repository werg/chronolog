import type { SqlEngine } from '@chronolog/materializer-doltlite/browser'
import { peerDigest, signApplicationSchema, verifyApplicationSchema, type PeerIdentity, type SignedApplicationSchema } from '@chronolog/peer-generation/control'
import { bytesToHex, encodeChangeProgram, executionManifestArtifacts, hexToBytes } from '@chronolog/protocol'

import { applicationDefinitionDigest, type ApplicationDefinition } from './definition.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'

export type { SqlEngine } from '@chronolog/materializer-doltlite/browser'

export type OpenSqlApplicationOptions<D extends ApplicationDefinition = ApplicationDefinition> = Omit<OpenPeerApplicationOptions<D>, 'createMaterializer'> & {
  /** Load the engine only when this participant first uses durable application data. */
  readonly createEngine: (options: { readonly signal: AbortSignal }) => SqlEngine | Promise<SqlEngine>
  readonly databasePath: string
  readonly schema: SignedApplicationSchema
}

/** Prepare the same authenticated schema for every runtime using this engine capability. */
export async function prepareSqlApplication(options: {
  readonly engine: SqlEngine
  readonly applicationId: string
  readonly definition: ApplicationDefinition
  readonly schemaAdministrator: PeerIdentity
}) {
  const { applicationId, definition, schemaAdministrator } = options
  if (definition.schema === undefined) throw new Error('APPLICATION_SCHEMA_REQUIRED')
  const manifest = structuredClone(options.engine.executionManifest)
  const program = bytesToHex(encodeChangeProgram(definition.schema))
  const definitionDigest = await applicationDefinitionDigest(definition)
  const executionManifestDigest = bytesToHex((await executionManifestArtifacts(manifest)).executionManifestDigest)
  const schema = await signApplicationSchema({ applicationId, definitionDigest, executionManifestDigest, program }, schemaAdministrator)
  return { schema, binding: { definitionDigest, executionManifestDigest, schemaDigest: await peerDigest(schema), schemaAdministrator: schemaAdministrator.publicKey } }
}

/** One schema, materializer and session lifecycle; adapters provide only an engine. */
export function openSqlApplication<const D extends ApplicationDefinition>(options: OpenSqlApplicationOptions<D>): Promise<ApplicationSession<D>> {
  const { createEngine, databasePath, schema: suppliedSchema, ...application } = options
  if (typeof createEngine !== 'function') throw new Error('APPLICATION_ENGINE_FACTORY_REQUIRED')
  const schema = structuredClone(suppliedSchema), authority = structuredClone(application.authority)
  const program = application.definition.schema === undefined ? null : bytesToHex(encodeChangeProgram(application.definition.schema))
  return openPeerApplication({ ...application, authority, createMaterializer: async ({ signal }) => {
    signal.throwIfAborted()
    const suppliedEngine = await createEngine({ signal })
    signal.throwIfAborted()
    const engine: SqlEngine = { executionManifest: structuredClone(suppliedEngine.executionManifest), openDatabase: suppliedEngine.openDatabase.bind(suppliedEngine) }
    const descriptor = authority.descriptor.payload
    const artifacts = await executionManifestArtifacts(engine.executionManifest)
    if (bytesToHex(artifacts.executionManifestDigest) !== descriptor.executionManifestDigest) throw new Error('APPLICATION_EXECUTION_MANIFEST_MISMATCH')
    const bootstrapProgram = await verifyApplicationSchema(schema, descriptor)
    if (program === null || program !== schema.payload.program) throw new Error('APPLICATION_SCHEMA_DEFINITION_MISMATCH')
    const { DeterministicMaterializer, createDoltLiteMaterializationRuntime } = await import('@chronolog/materializer-doltlite/browser')
    signal.throwIfAborted()
    const materializer = await DeterministicMaterializer.open({ engine, path: databasePath,
      rootAdministrator: hexToBytes(descriptor.schemaAdministrator), bootstrapGroupId: hexToBytes(descriptor.applicationId), bootstrapProgram })
    return createDoltLiteMaterializationRuntime(materializer)
  } })
}

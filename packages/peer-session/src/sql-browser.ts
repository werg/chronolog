import {
  DeterministicMaterializer, createDoltLiteMaterializationRuntime, PLATFORM_DIGEST,
} from '@chronolog/materializer-doltlite/browser'
import { loadBrowserEngine, createWasmEngineFactory, wasmEngineDigest, type WasmBuildManifest } from '@chronolog/materializer-doltlite/wasm'
import { bytesDigest, verifyApplicationSchema, type SignedApplicationSchema } from '@chronolog/peer-generation'
import { bytesToHex, createExecutionManifest, encodeChangeProgram, executionManifestArtifacts, hexToBytes, utf8 } from '@chronolog/protocol'

import type { ApplicationDefinition } from './definition.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'

/** Browser and native peers authenticate the same SQL execution identity. */
export function createBrowserSqlManifest(build: WasmBuildManifest) {
  return createExecutionManifest({ profile: 'chronolog-peer-sql-v1', engineDigest: wasmEngineDigest(build), platformDigest: PLATFORM_DIGEST })
}

/** The owning Worker opens the verified engine, OPFS database and application together. */
export async function openBrowserSqlApplication<const D extends ApplicationDefinition>(options: Omit<OpenPeerApplicationOptions<D>, 'createMaterializer'> & {
  /** URL of the engine directory shipped with the SQL-enabled session artifact. */
  readonly engineUrl: string | URL
  readonly schema: SignedApplicationSchema
}): Promise<ApplicationSession<D>> {
  if (typeof document !== 'undefined' || !globalThis.crossOriginIsolated) throw new Error('BROWSER_PEER_ISOLATED_WORKER_REQUIRED')
  return openPeerApplication({ ...options, createMaterializer: async () => {
    const descriptor = options.authority.descriptor.payload
    const bootstrapProgram = await verifyApplicationSchema(options.schema, descriptor)
    if (options.definition.schema === undefined || bytesToHex(encodeChangeProgram(options.definition.schema)) !== options.schema.payload.program) {
      throw new Error('APPLICATION_SCHEMA_DEFINITION_MISMATCH')
    }
    const engine = await loadBrowserEngine(options.engineUrl)
    const executionManifest = createBrowserSqlManifest(engine.manifest)
    if (bytesToHex((await executionManifestArtifacts(executionManifest)).executionManifestDigest) !== descriptor.executionManifestDigest) {
      throw new Error('PEER_EXECUTION_MANIFEST_MISMATCH')
    }
    if (engine.module.installOpfsSAHPoolVfs === undefined) throw new Error('BROWSER_SQLITE_OPFS_POOL_UNAVAILABLE')
    const owner = await bytesDigest(utf8(options.device.storageId))
    const directory = `/chronolog-peer-sql/${owner}/${descriptor.applicationId}`
    const pool = await engine.module.installOpfsSAHPoolVfs({ name: `chronolog-peer-${descriptor.applicationId}`, directory, initialCapacity: 16 })
    try {
      const materializer = await DeterministicMaterializer.open({ path: `${directory}/application.db`,
        executionManifest, historyProfile: 'peer-generation-v1',
        rootAdministrator: hexToBytes(descriptor.schemaAdministrator), bootstrapGroupId: hexToBytes(descriptor.applicationId),
        bootstrapProgram, openDatabase: createWasmEngineFactory(engine.module, engine.manifest, pool.vfsName) })
      const runtime = createDoltLiteMaterializationRuntime(materializer)
      return { ...runtime, async close() { try { await runtime.close() } finally { pool.pauseVfs() } } }
    } catch (error) { pool.pauseVfs(); throw error }
  } })
}

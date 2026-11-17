import {
  DeterministicMaterializer, createDoltLiteMaterializationRuntime, PLATFORM_DIGEST,
} from '@chronolog/materializer-doltlite/browser'
import { loadBrowserEngine, createWasmEngineFactory, wasmEngineDigest, type WasmBuildManifest } from '@chronolog/materializer-doltlite/wasm'
import { applicationDescriptionDigest, bytesDigest, signApplicationSchema, verifyApplicationSchema, type PeerIdentity, type SignedApplicationSchema } from '@chronolog/peer-generation'
import { bytesToHex, createExecutionManifest, encodeChangeProgram, executionManifestArtifacts, hexToBytes, utf8 } from '@chronolog/protocol'

import { describeApplication, type ApplicationDefinition } from './definition.js'
import { prepareApplicationSession, type ApplicationCreation, type ApplicationSessionBootstrapOptions } from './bootstrap.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'

/** Browser and native peers authenticate the same SQL execution identity. */
export function createBrowserSqlManifest(build: WasmBuildManifest) {
  return createExecutionManifest({ profile: 'chronolog-peer-sql-v1', engineDigest: wasmEngineDigest(build), platformDigest: PLATFORM_DIGEST })
}

/** Public configuration fields from the exact browser engine and separately authorized schema. */
export async function prepareBrowserSqlApplication(options: {
  readonly applicationId: string
  readonly definition: ApplicationDefinition
  readonly schemaAdministrator: PeerIdentity
  readonly engine: WasmBuildManifest
}) {
  const definition = describeApplication(options.definition)
  if (definition.schema === null) throw new Error('APPLICATION_SCHEMA_REQUIRED')
  const definitionDigest = await applicationDescriptionDigest(definition)
  const executionManifestDigest = bytesToHex((await executionManifestArtifacts(createBrowserSqlManifest(options.engine))).executionManifestDigest)
  const schema = await signApplicationSchema({ applicationId: options.applicationId, definitionDigest, executionManifestDigest,
    program: definition.schema }, options.schemaAdministrator)
  return { definition, schema, executionManifestDigest, schemaAdministrator: options.schemaAdministrator.publicKey }
}

type BrowserSqlOptions<D extends ApplicationDefinition> = Omit<OpenPeerApplicationOptions<D>, 'createMaterializer'> & {
  /**
   * URL of the verified browser-engine directory included by --sql-browser.
   * Deployments serve these packaged assets with JavaScript/WASM content types.
   */
  readonly engineUrl: string | URL
  readonly schema: SignedApplicationSchema
}

/** The owning Worker opens the verified engine, OPFS database and application together. */
export async function openBrowserSqlApplication<const D extends ApplicationDefinition>(options: BrowserSqlOptions<D>): Promise<ApplicationSession<D>> {
  return openBrowserSqlOwner(options, () => loadBrowserEngine(options.engineUrl))
}

async function openBrowserSqlOwner<const D extends ApplicationDefinition>(options: BrowserSqlOptions<D>,
  load: () => ReturnType<typeof loadBrowserEngine>): Promise<ApplicationSession<D>> {
  if (typeof document !== 'undefined' || !globalThis.crossOriginIsolated) throw new Error('BROWSER_PEER_ISOLATED_WORKER_REQUIRED')
  return openPeerApplication({ ...options, createMaterializer: async () => {
    const descriptor = options.authority.descriptor.payload
    const bootstrapProgram = await verifyApplicationSchema(options.schema, descriptor)
    if (options.definition.schema === undefined || bytesToHex(encodeChangeProgram(options.definition.schema)) !== options.schema.payload.program) {
      throw new Error('APPLICATION_SCHEMA_DEFINITION_MISMATCH')
    }
    const engine = await load()
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
      let closing: Promise<void> | undefined
      return { ...runtime, close() {
        closing ??= Promise.resolve().then(async () => { try { await runtime.close() } finally { await pool.pauseVfs() } })
        return closing
      } }
    } catch (error) { await pool.pauseVfs(); throw error }
  } })
}

/** Create, join or resume SQL in the owning Worker without application-owned bootstrap glue. */
export async function openBrowserSqlSession<const D extends ApplicationDefinition>(options: Omit<ApplicationSessionBootstrapOptions<D>, 'create'> & {
  readonly create?: Omit<ApplicationCreation, 'executionManifestDigest' | 'schemaAdministrator' | 'schema'>
  readonly engineUrl: string | URL
  readonly maxRecords?: number
  readonly maxHistoryBytes?: number
}): Promise<ApplicationSession<D>> {
  if (typeof document !== 'undefined' || !globalThis.crossOriginIsolated) throw new Error('BROWSER_PEER_ISOLATED_WORKER_REQUIRED')
  let engine: ReturnType<typeof loadBrowserEngine> | undefined
  const load = (): ReturnType<typeof loadBrowserEngine> => engine ??= loadBrowserEngine(options.engineUrl)
  const creation = options.create === undefined ? undefined : await prepareBrowserSqlApplication({
    applicationId: options.applicationId, definition: options.definition, schemaAdministrator: options.device.identity, engine: (await load()).manifest,
  })
  const prepared = await prepareApplicationSession({ device: options.device, definition: options.definition, applicationId: options.applicationId,
    ...(options.host === undefined ? {} : { host: options.host }), ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(creation === undefined ? {} : { create: { ...options.create, executionManifestDigest: creation.executionManifestDigest,
      schemaAdministrator: creation.schemaAdministrator, schema: creation.schema } }) })
  if (prepared.schema === null) { await options.device.close(); throw new Error('APPLICATION_SCHEMA_REQUIRED') }
  return openBrowserSqlOwner({ device: options.device, definition: options.definition, authority: prepared.authority, schema: prepared.schema,
    engineUrl: options.engineUrl,
    ...(options.maxRecords === undefined ? {} : { maxRecords: options.maxRecords }),
    ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) }, load)
}

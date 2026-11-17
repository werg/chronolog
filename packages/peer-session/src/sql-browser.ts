/** Browser-specific loading produces the engine used by the common /sql application entry. */
export {
  createBrowserSqlEngine, loadBrowserEngine, verifyWasmBuild,
  type ChronologWasmModule, type LoadedBrowserEngine, type OpfsSqlitePool, type SqlEngine, type WasmBuildManifest,
} from '@chronolog/materializer-doltlite/browser'

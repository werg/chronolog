import { verifyWasmBuild, type ChronologWasmModule, type WasmBuildManifest } from './wasm-engine.js'

export interface LoadedBrowserEngine {
  readonly module: ChronologWasmModule
  readonly manifest: WasmBuildManifest
}

/** Load the reproducible build, validate exact WASM bytes, and instantiate once in the owner Worker. */
export async function loadBrowserEngine(baseUrl: string | URL): Promise<LoadedBrowserEngine> {
  const base = new URL(baseUrl, globalThis.location.href)
  if (!base.pathname.endsWith('/')) base.pathname += '/'
  const [manifestResponse, wasmResponse] = await Promise.all([
    fetch(new URL('manifest.json', base)), fetch(new URL('sqlite3.wasm', base)),
  ])
  if (!manifestResponse.ok || !wasmResponse.ok) throw new Error('WASM_ENGINE_DOWNLOAD_FAILED')
  const manifest = await manifestResponse.json() as WasmBuildManifest
  const bytes = new Uint8Array(await wasmResponse.arrayBuffer())
  verifyWasmBuild(bytes, manifest)
  const compiled = await WebAssembly.compile(bytes)
  const url = new URL('sqlite3.mjs', base).href
  const { default: initialize } = await import(/* @vite-ignore */ url) as {
    default(this: void, options: unknown): Promise<ChronologWasmModule>
  }
  const module = await initialize({
    locateFile: (name: string) => new URL(name, base).href,
    instantiateWasm(imports: WebAssembly.Imports, done: (instance: WebAssembly.Instance, compiled: WebAssembly.Module) => void) {
      const instance = new WebAssembly.Instance(compiled, imports)
      done(instance, compiled)
      return instance.exports
    },
  })
  return { module, manifest }
}

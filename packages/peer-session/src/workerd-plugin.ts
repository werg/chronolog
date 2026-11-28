import { copyFileSync, mkdirSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'

export interface WorkerdWasmPluginOptions {
  /** Directory where `.wasm` assets will be copied alongside the Worker bundle. */
  readonly outDir: string
  /** Optional workspace root (defaults to `process.cwd()`). */
  readonly rootDir?: string
  /** Optional callback notified whenever a `.wasm` asset is copied. */
  readonly onAsset?: (fileName: string, sourcePath: string) => void
}

interface EsbuildPluginBuildLike {
  onResolve(
    options: { readonly filter: RegExp },
    callback: (args: { readonly path: string; readonly resolveDir: string }) => { readonly path: string; readonly external?: boolean; readonly namespace?: string },
  ): void
  onLoad(
    options: { readonly filter: RegExp; readonly namespace?: string },
    callback: () => { readonly contents: string; readonly loader: 'js' },
  ): void
}

/**
 * Reusable esbuild plugin for bundling Chronolog applications into Cloudflare Workers (`workerd`):
 * - Copies `@jitl/quickjs-ng-wasmfile-release-sync/wasm`, `@chronolog/peer-session/sqlite-cas.wasm`,
 *   and relative `*.wasm` imports beside the Worker bundle as static external `./<name>` imports
 *   (so Wrangler compiles them via `CompiledWasm`).
 * - Stubs `node:module` (`createRequire`) cleanly for workerd compatibility.
 */
export function createWorkerdWasmPlugin(options: WorkerdWasmPluginOptions): {
  readonly name: string
  setup(builder: EsbuildPluginBuildLike): void
} {
  const root = resolve(options.rootDir ?? process.cwd())
  const outDir = resolve(options.outDir)

  return {
    name: 'chronolog-workerd-wasm',
    setup(builder) {
      builder.onResolve(
        { filter: /(?:\.wasm$|^@jitl\/quickjs-ng-wasmfile-release-sync\/wasm$|^@chronolog\/peer-session\/sqlite-cas\.wasm$)/ },
        args => {
          let resolved: string
          if (args.path === '@jitl/quickjs-ng-wasmfile-release-sync/wasm') {
            resolved = join(root, 'node_modules/@jitl/quickjs-ng-wasmfile-release-sync/dist/emscripten-module.wasm')
          } else if (args.path === '@chronolog/peer-session/sqlite-cas.wasm') {
            resolved = join(root, 'node_modules/@chronolog/peer-session/wasm/sqlite-cas.wasm')
          } else {
            resolved = join(args.resolveDir, args.path)
          }
          const name = basename(resolved)
          mkdirSync(outDir, { recursive: true })
          copyFileSync(resolved, join(outDir, name))
          options.onAsset?.(name, resolved)
          return { path: `./${name}`, external: true }
        },
      )
      builder.onResolve({ filter: /^module$/ }, () => ({
        path: 'chronolog-workerd-empty-module',
        namespace: 'chronolog-workerd-stub',
      }))
      builder.onLoad({ filter: /.*/, namespace: 'chronolog-workerd-stub' }, () => ({
        contents: 'export function createRequire() { throw new Error("node:module is unavailable in Cloudflare Workers"); }',
        loader: 'js',
      }))
    },
  }
}

import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { basename, extname, isAbsolute, join, resolve } from 'node:path'

export interface WorkerdWasmPluginOptions {
  /** Directory where `.wasm` assets will be copied alongside the Worker bundle. */
  readonly outDir: string
  /** Optional workspace root, used as a fallback resolution base (defaults to `process.cwd()`). */
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
 * Locate a `.wasm` import on disk through Node package resolution (package `exports`, any
 * hoisted or pnpm-nested layout). Relative and absolute paths resolve against the importer.
 * Bare specifiers try the importing file's directory first (where nested pnpm dependencies
 * are visible), then the workspace root.
 */
function locateWasm(specifier: string, resolveDir: string, root: string): string {
  if (specifier.startsWith('.') || isAbsolute(specifier)) return resolve(resolveDir, specifier)
  let firstError: unknown
  for (const base of [resolveDir, root]) {
    try { return createRequire(join(base, 'noop.cjs')).resolve(specifier) }
    catch (error) { firstError ??= error }
  }
  throw new Error(`chronolog-workerd-wasm: cannot resolve ${specifier} from ${resolveDir} or ${root}`, { cause: firstError })
}

/**
 * Reusable esbuild plugin for bundling Chronolog applications into Cloudflare Workers (`workerd`):
 * - Copies `@jitl/quickjs-ng-wasmfile-release-sync/wasm`, `@chronolog/peer-session/sqlite-cas.wasm`,
 *   and `*.wasm` imports beside the Worker bundle as static external `./<stem>.<sha256-prefix>.wasm`
 *   imports (so Wrangler compiles them via `CompiledWasm`). Packages are located with Node
 *   resolution, never a hardcoded `node_modules` path, and output names carry a content hash so
 *   same-named files from different packages cannot collide.
 * - Stubs `node:module` / `module` (`createRequire`) cleanly for workerd compatibility.
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
          const resolved = locateWasm(args.path, args.resolveDir, root)
          const bytes = readFileSync(resolved)
          const digest = createHash('sha256').update(bytes).digest('hex').slice(0, 16)
          const stem = basename(resolved, extname(resolved))
          const name = `${stem}.${digest}.wasm`
          mkdirSync(outDir, { recursive: true })
          copyFileSync(resolved, join(outDir, name))
          options.onAsset?.(name, resolved)
          return { path: `./${name}`, external: true }
        },
      )
      builder.onResolve({ filter: /^(?:node:)?module$/ }, () => ({
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

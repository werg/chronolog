import { readFile } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'
import { build as esbuildBuild } from 'esbuild'
import { utf8 } from '@chronolog/canonical'
import {
  casRef,
  computeCasHash,
  ContentAddressedStore,
  MemoryBytesStore,
  normalizePosixPath,
  putDerivationNode,
  putPackageDag,
  putTreeDag,
  type CasPartition,
  type ChronologBuiltinName,
  type ChronologPackageNode,
} from '@chronolog/records'
import type { GenesisCasNode } from '@chronolog/peer-session'
import { detectRequiredBuiltins, lintDeterminism, type DeterminismDiagnostic } from './linter.js'
import { createLockfile, type ChronologLockEntry, type ChronologLockfile } from './lockfile.js'
import { parseCanonicalTarball } from './tarball.js'

export const ESBUILD_BUILDER_ID = 'esbuild-neutral-esm@0.28.2'
export const ESBUILD_BUILDER_REF = casRef(computeCasHash(utf8(`chronolog-builder:${ESBUILD_BUILDER_ID}`), []))

export interface PackEntryInput {
  /** Absolute or cwd-relative path to an entry .ts/.js file on disk. */
  readonly path?: string
  /** In-memory entry source (when packing virtual TS/JS reducers without temp files). */
  readonly source?: string
  /** Optional multi-file virtual files map (relative POSIX path -> TS/JS source). */
  readonly files?: Readonly<Record<string, string>>
  readonly name?: string
  readonly version?: string
  /** Bundle into 1 clean tree-shaken ESM file per package export (default: true). */
  readonly bundle?: boolean
  /** Explicit package-scoped dependencies (bare specifier -> cas:sha256-...). */
  readonly dependencies?: Readonly<Record<string, string>>
  /** Explicit capability allowlist (defaults to auto-detected minimal chronolog:* imports). */
  readonly builtins?: readonly ChronologBuiltinName[]
  readonly partition?: CasPartition
}

export interface PackReducersOptions {
  readonly entries: Readonly<Record<string, string | PackEntryInput>>
  readonly cwd?: string
  readonly cas?: ContentAddressedStore
  /** Determinism lint policy: 'error' (default), 'warn', or 'off'. */
  readonly lint?: 'error' | 'warn' | 'off'
  /** Record chronolog-drv/v1 provenance back-links & canonical source trees (default: true). */
  readonly includeDerivation?: boolean
  /** Additional bare specifiers to keep external (always keeps chronolog:* and chronolog/* external). */
  readonly external?: readonly string[]
}

export interface PackedEntryResult {
  readonly alias: string
  readonly pkgHash: string
  readonly pkgRef: string
  readonly drvHash?: string
  readonly drvRef?: string
  readonly manifest: ChronologPackageNode
  readonly diagnostics: readonly DeterminismDiagnostic[]
}

export interface PackedBundleResult {
  readonly imports: Readonly<Record<string, string>>
  readonly casNodes: readonly GenesisCasNode[]
  readonly entries: Readonly<Record<string, PackedEntryResult>>
  readonly lockfile: ChronologLockfile
  readonly diagnostics: readonly DeterminismDiagnostic[]
}

const STANDARD_EXTERNALS = [
  'chronolog:crypto',
  'chronolog:cas',
  'chronolog:sqlite',
  'chronolog:wasm',
  'chronolog/*',
  'node:*',
]

async function bundleSingleEntry(
  entry: PackEntryInput,
  cwd: string,
  extraExternal: readonly string[],
): Promise<{
  readonly compiledFiles: Record<string, string>
  readonly sourceFiles: Record<string, string>
  readonly exportsMap: Record<string, string>
}> {
  const external = [
    ...STANDARD_EXTERNALS,
    ...Object.keys(entry.dependencies ?? {}),
    ...extraExternal,
  ]
  const shouldBundle = entry.bundle !== false

  // Multi-file virtual package (non-bundled): transpile each TS/JS file individually while keeping relative imports!
  if (!shouldBundle && entry.files !== undefined) {
    const compiledFiles: Record<string, string> = {}
    const sourceFiles: Record<string, string> = {}
    let defaultExportFile: string | undefined
    for (const [rawPath, src] of Object.entries(entry.files).sort(([a], [b]) => a.localeCompare(b))) {
      const norm = normalizePosixPath(rawPath)
      sourceFiles[norm] = src
      const outPath = norm.replace(/\.tsx?$/u, '.js')
      if (defaultExportFile === undefined || outPath === 'index.js') defaultExportFile = outPath
      const res = await esbuildBuild({
        stdin: {
          contents: src,
          loader: norm.endsWith('.ts') ? 'ts' : norm.endsWith('.tsx') ? 'tsx' : 'js',
          sourcefile: norm,
          resolveDir: cwd,
        },
        bundle: false,
        write: false,
        format: 'esm',
        target: 'es2022',
        charset: 'utf8',
        legalComments: 'none',
      })
      compiledFiles[outPath] = res.outputFiles[0]!.text
    }
    return {
      compiledFiles,
      sourceFiles,
      exportsMap: defaultExportFile === undefined ? {} : { '.': defaultExportFile },
    }
  }

  // Virtual single or multi-file entry bundled deterministically with esbuild (resolving npm packages in cwd!)
  if (entry.source !== undefined || entry.files !== undefined) {
    const virtualFiles = new Map<string, string>()
    const sourceFiles: Record<string, string> = {}
    if (entry.files !== undefined) {
      for (const [rawPath, src] of Object.entries(entry.files).sort(([a], [b]) => a.localeCompare(b))) {
        const norm = normalizePosixPath(rawPath)
        virtualFiles.set(norm, src)
        sourceFiles[norm] = src
      }
    }
    const entryName = entry.path !== undefined ? normalizePosixPath(entry.path) : 'index.ts'
    if (entry.source !== undefined) {
      virtualFiles.set(entryName, entry.source)
      sourceFiles[entryName] = entry.source
    }
    const entryCode = virtualFiles.get(entryName) ?? virtualFiles.values().next().value
    if (entryCode === undefined) throw new Error('PACK_ENTRY_EMPTY')

    const res = await esbuildBuild({
      stdin: {
        contents: entryCode,
        loader: entryName.endsWith('.ts') ? 'ts' : entryName.endsWith('.tsx') ? 'tsx' : 'js',
        sourcefile: entryName,
        resolveDir: cwd,
      },
      plugins: [{
        name: 'chronolog-virtual-fs',
        setup(build) {
          build.onResolve({ filter: /^\.\.?\// }, args => {
            if (args.importer && !isAbsolute(args.importer)) {
              const baseDir = dirname(args.importer)
              const rawJoined = baseDir === '.' ? args.path : `${baseDir}/${args.path}`
              const cleaned = rawJoined.replace(/^\.\//u, '')
              for (const cand of [cleaned, `${cleaned}.ts`, `${cleaned}.js`, `${cleaned}.mjs`, `${cleaned}/index.ts`, `${cleaned}/index.js`]) {
                try {
                  const norm = normalizePosixPath(cand)
                  if (virtualFiles.has(norm)) return { path: norm, namespace: 'chronolog-vfs' }
                } catch { /* ignore */ }
              }
            }
            return null
          })
          build.onLoad({ filter: /.*/, namespace: 'chronolog-vfs' }, args => {
            const contents = virtualFiles.get(args.path)
            if (contents === undefined) return null
            return {
              contents,
              loader: args.path.endsWith('.ts') ? 'ts' : args.path.endsWith('.tsx') ? 'tsx' : 'js',
              resolveDir: cwd,
            }
          })
        },
      }],
      bundle: shouldBundle,
      write: false,
      platform: 'neutral',
      mainFields: ['module', 'main'],
      conditions: ['import', 'default'],
      format: 'esm',
      target: 'es2022',
      treeShaking: true,
      minifySyntax: true,
      sourcemap: false,
      legalComments: 'none',
      charset: 'utf8',
      define: { 'process.env.NODE_ENV': '"production"' },
      external,
    })
    return {
      compiledFiles: { 'index.js': res.outputFiles[0]!.text },
      sourceFiles,
      exportsMap: { '.': 'index.js' },
    }
  }

  // Real file on disk (can import local TS/JS modules AND npm packages from node_modules!)
  if (entry.path === undefined) throw new Error('PACK_ENTRY_PATH_OR_SOURCE_REQUIRED')
  const absPath = isAbsolute(entry.path) ? entry.path : resolve(cwd, entry.path)
  const rawSource = await readFile(absPath, 'utf8')
  const res = await esbuildBuild({
    entryPoints: [absPath],
    bundle: shouldBundle,
    write: false,
    platform: 'neutral',
    mainFields: ['module', 'main'],
    conditions: ['import', 'default'],
    format: 'esm',
    target: 'es2022',
    treeShaking: true,
    minifySyntax: true,
    sourcemap: false,
    legalComments: 'none',
    charset: 'utf8',
    define: { 'process.env.NODE_ENV': '"production"' },
    external,
    absWorkingDir: cwd,
  })
  return {
    compiledFiles: { 'index.js': res.outputFiles[0]!.text },
    sourceFiles: { 'entry.ts': rawSource },
    exportsMap: { '.': 'index.js' },
  }
}

/**
 * Deterministically compile, lint, and pack TypeScript/JS reducers (including real npm dependencies)
 * into capability-attenuated `chronolog-pkg/v1` + `chronolog-drv/v1` CAS Merkle-DAGs and a lockfile.
 */
export async function packReducers(options: PackReducersOptions): Promise<PackedBundleResult> {
  const cwd = options.cwd ?? process.cwd()
  const cas = options.cas ?? new ContentAddressedStore({ store: new MemoryBytesStore() })
  const lintMode = options.lint ?? 'error'
  const includeDerivation = options.includeDerivation ?? true
  const extraExternal = options.external ?? []

  const imports: Record<string, string> = {}
  const entriesOut: Record<string, PackedEntryResult> = {}
  const lockEntries: Record<string, ChronologLockEntry> = {}
  const allDiagnostics: DeterminismDiagnostic[] = []
  const collectedNodes = new Map<string, GenesisCasNode>()

  for (const [alias, rawEntry] of Object.entries(options.entries).sort(([a], [b]) => a.localeCompare(b))) {
    const entry: PackEntryInput = typeof rawEntry === 'string' ? { path: rawEntry } : rawEntry
    const partition: CasPartition = entry.partition ?? 'public'
    const { compiledFiles, sourceFiles, exportsMap } = await bundleSingleEntry(entry, cwd, extraExternal)

    const entryDiagnostics: DeterminismDiagnostic[] = []
    if (lintMode !== 'off') {
      for (const [file, code] of Object.entries(compiledFiles)) {
        entryDiagnostics.push(...lintDeterminism(code, `${alias}:${file}`))
      }
      allDiagnostics.push(...entryDiagnostics)
      if (lintMode === 'error' && entryDiagnostics.length > 0) {
        const first = entryDiagnostics[0]!
        throw new Error(`DETERMINISM_LINT_FAILED: ${first.file}:${first.line}:${first.column} [${first.code}] ${first.message} (${first.suggestion})`)
      }
    }

    const builtins = entry.builtins ?? detectRequiredBuiltins(Object.values(compiledFiles))

    let drvHash: string | undefined
    let drvRef: string | undefined
    if (includeDerivation) {
      const srcTree = await putTreeDag(cas, sourceFiles, partition)
      const drv = await putDerivationNode(cas, {
        format: 'chronolog-drv/v1',
        profile: 'wasi-cas-v1',
        builder: ESBUILD_BUILDER_REF,
        inputs: {
          src: srcTree.ref,
          ...(entry.dependencies ?? {}),
        },
        args: {
          alias,
          bundle: entry.bundle !== false,
          target: 'chronolog-pkg/v1',
        },
        limits: {
          maxMemoryBytes: 64 * 1024 * 1024,
          maxFuel: 200_000,
        },
      }, partition)
      drvHash = drv.hash
      drvRef = drv.ref
    }

    const pkg = await putPackageDag(cas, {
      name: entry.name ?? alias,
      version: entry.version ?? '0.0.0',
      runtime: 'esm-quickjs',
      files: compiledFiles,
      exports: exportsMap,
      ...(entry.dependencies === undefined ? {} : { dependencies: entry.dependencies }),
      builtins,
      ...(drvRef === undefined ? {} : { derivation: drvRef }),
    }, partition)

    imports[alias] = pkg.ref
    entriesOut[alias] = {
      alias,
      pkgHash: pkg.hash,
      pkgRef: pkg.ref,
      ...(drvHash === undefined ? {} : { drvHash }),
      ...(drvRef === undefined ? {} : { drvRef }),
      manifest: pkg.manifest,
      diagnostics: entryDiagnostics,
    }
    lockEntries[alias] = {
      pkgRef: pkg.ref,
      ...(drvRef === undefined ? {} : { drvRef }),
      runtime: pkg.manifest.runtime,
      builtins: pkg.manifest.builtins,
      dependencies: pkg.manifest.dependencies,
    }

    // Export the executable package subgraph (manifest + files + dependencies; never bloaty source trees!)
    const sub = await cas.collectSubgraph([pkg.hash], { allowedPartition: partition, maxNodes: 4096, maxBytes: 32 * 1024 * 1024 })
    for (const node of sub) {
      collectedNodes.set(`${node.partition}:${node.hash}`, node)
    }
  }

  return {
    imports,
    casNodes: [...collectedNodes.values()],
    entries: entriesOut,
    lockfile: createLockfile(lockEntries),
    diagnostics: allDiagnostics,
  }
}

/**
 * Ingest a canonical npm/JSR tarball into CAS (verifying optional integrity), deterministically
 * bundle its entry point into a clean tree-shaken ESM `chronolog-pkg/v1`, and record its `chronolog-drv/v1`.
 */
export async function packNpmTarball(options: {
  readonly tarball: Uint8Array
  readonly integrity?: string
  readonly entry?: string
  readonly name?: string
  readonly version?: string
  readonly cas?: ContentAddressedStore
  readonly lint?: 'error' | 'warn' | 'off'
}): Promise<PackedEntryResult & { readonly casNodes: readonly GenesisCasNode[]; readonly sourceTreeRef: string }> {
  const cas = options.cas ?? new ContentAddressedStore({ store: new MemoryBytesStore() })
  const tarEntries = parseCanonicalTarball(options.tarball, {
    ...(options.integrity === undefined ? {} : { integrity: options.integrity }),
  })
  const dec = new TextDecoder()
  const files: Record<string, string> = {}
  for (const e of tarEntries) files[e.path] = dec.decode(e.bytes)

  let pkgJson: { name?: string; version?: string; module?: string; main?: string; exports?: unknown } = {}
  if (files['package.json'] !== undefined) {
    pkgJson = JSON.parse(files['package.json']) as typeof pkgJson
  }
  const entryFile = normalizePosixPath(
    options.entry ??
    (typeof pkgJson.module === 'string' ? pkgJson.module : undefined) ??
    (typeof pkgJson.main === 'string' ? pkgJson.main : undefined) ??
    'index.js',
  )
  const name = options.name ?? pkgJson.name ?? 'npm-pkg'
  const version = options.version ?? pkgJson.version ?? '0.0.0'
  const sourceTree = await putTreeDag(cas, files, 'public')

  const packed = await packReducers({
    cas,
    lint: options.lint ?? 'error',
    includeDerivation: true,
    entries: {
      [name]: {
        name,
        version,
        path: entryFile,
        files,
        bundle: true,
      },
    },
  })
  const result = packed.entries[name]!
  return {
    ...result,
    casNodes: packed.casNodes,
    sourceTreeRef: sourceTree.ref,
  }
}

/**
 * A pure-JS lightweight deterministic builder that executes RIGHT INSIDE QuickJS-NG
 * as a zero-authority `profile: 'quickjs-inline'` chronolog-drv/v1 derivation!
 * Strips simple TypeScript type annotations / `as Type` casts / interfaces and writes
 * the resulting ESM source straight to CAS.
 */
export const INLINE_TS_BUILDER_SOURCE = `
import { get, put } from 'chronolog:cas';

function hexToUtf8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return out;
}

function stripSimpleTs(src) {
  return src
    .replace(/^\\s*(?:export\\s+)?(?:interface|type)\\s+[A-Za-z_$][\\w$]*[^{=]*(\\{[^}]*\\}|=[^;]+;)/gm, '')
    .replace(/(\\b(?:const|let|var)\\s+[A-Za-z_$][\\w$]*)\\s*:\\s*[A-Za-z_$][\\w$<>\\[\\]|&\\s?]*(?=\\s*=)/g, '$1')
    .replace(/(\\([A-Za-z_$][\\w$]*)\\s*:\\s*[A-Za-z_$][\\w$<>\\[\\]|&\\s?]*(?=[,)])/g, '$1')
    .replace(/(,\\s*[A-Za-z_$][\\w$]*)\\s*:\\s*[A-Za-z_$][\\w$<>\\[\\]|&\\s?]*(?=[,)])/g, '$1')
    .replace(/\\)\\s*:\\s*[A-Za-z_$][\\w$<>\\[\\]|&\\s?]*\\s*\\{/g, ') {');
}

export default {
  derive(payload) {
    const srcRef = payload && payload.inputs && payload.inputs.src;
    if (typeof srcRef !== 'string') throw new Error('INLINE_TS_MISSING_SRC');
    const raw = JSON.parse(get(srcRef));
    const tsSource = hexToUtf8(raw.bytesHex);
    const jsSource = stripSimpleTs(tsSource);
    const outHash = put(jsSource, []);
    return { output: 'cas:sha256-' + outHash };
  },
};
`.trimStart()

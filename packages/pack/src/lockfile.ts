import { parseCasRef, type ChronologBuiltinName, type ChronologPackageRuntime } from '@chronolog/records'

export interface ChronologLockEntry {
  readonly pkgRef: string
  readonly drvRef?: string
  readonly runtime: ChronologPackageRuntime
  readonly builtins: readonly ChronologBuiltinName[]
  readonly dependencies: Readonly<Record<string, string>>
  readonly integrity?: string
}

export interface ChronologLockfile {
  readonly format: 'chronolog-lock/v1'
  readonly packages: Readonly<Record<string, ChronologLockEntry>>
}

export function createLockfile(packages: Readonly<Record<string, ChronologLockEntry>>): ChronologLockfile {
  const sorted: Record<string, ChronologLockEntry> = {}
  for (const alias of Object.keys(packages).sort()) {
    const entry = packages[alias]!
    parseCasRef(entry.pkgRef)
    if (entry.drvRef !== undefined) parseCasRef(entry.drvRef)
    const deps: Record<string, string> = {}
    for (const k of Object.keys(entry.dependencies).sort()) {
      parseCasRef(entry.dependencies[k]!)
      deps[k] = entry.dependencies[k]!
    }
    sorted[alias] = {
      pkgRef: entry.pkgRef,
      ...(entry.drvRef === undefined ? {} : { drvRef: entry.drvRef }),
      runtime: entry.runtime,
      builtins: [...new Set(entry.builtins)].sort(),
      dependencies: deps,
      ...(entry.integrity === undefined ? {} : { integrity: entry.integrity }),
    }
  }
  return { format: 'chronolog-lock/v1', packages: sorted }
}

export function formatLockfile(lockfile: ChronologLockfile): string {
  return `${JSON.stringify(createLockfile(lockfile.packages), null, 2)}\n`
}

export function parseLockfile(raw: string): ChronologLockfile {
  const parsed = JSON.parse(raw) as unknown
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('LOCKFILE_INVALID')
  }
  const obj = parsed as Record<string, unknown>
  if (obj.format !== 'chronolog-lock/v1' || obj.packages === null || typeof obj.packages !== 'object' || Array.isArray(obj.packages)) {
    throw new Error('LOCKFILE_INVALID')
  }
  return createLockfile(obj.packages as Readonly<Record<string, ChronologLockEntry>>)
}

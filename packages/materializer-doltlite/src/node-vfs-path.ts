import { posix, win32 } from 'node:path'

/** DoltLite's portable chunk-store derives sibling names with strrchr(path, '/'). */
export function nodeVfsFullPath(name: string, windows = process.platform === 'win32'): string {
  return windows ? win32.resolve(name).replaceAll('\\', '/') : posix.resolve(name)
}

/** Case aliases must share locks without case-folding distinct case-sensitive names. */
export function nodeVfsFileIdentity(path: string, stat: { readonly dev: bigint; readonly ino: bigint }): string {
  return stat.ino === 0n ? path : `${stat.dev}:${stat.ino}`
}

/**
 * One process 'exit' listener shared by every disposable resource, instead of a
 * listener per resource. Cleanups must be synchronous; the listener is removed
 * when the last registration is released.
 */
const cleanups = new Set<() => void>()
function runCleanups(): void {
  for (const cleanup of [...cleanups]) {
    cleanups.delete(cleanup)
    try { cleanup() } catch { /* Best-effort cleanup during process exit. */ }
  }
}
export function registerExitCleanup(cleanup: () => void): () => void {
  const entry = (): void => { cleanup() }
  if (cleanups.size === 0) process.on('exit', runCleanups)
  cleanups.add(entry)
  return () => {
    if (cleanups.delete(entry) && cleanups.size === 0) process.removeListener('exit', runCleanups)
  }
}
/** Registered cleanup count, for leak diagnostics in tests. */
export function exitCleanupCount(): number { return cleanups.size }

/**
 * Process-wide performance counters for Chronolog hot paths.
 *
 * Counting is always on: each call is one Map lookup + add, cheap enough for
 * per-op paths. Timers (`perfTime`) cost two `performance.now()` calls and are
 * only used around coarse phases (materialize, reduce, verify batches).
 * Consumers read `perfCounters()` for benchmarks and diagnostics snapshots.
 */
const counts = new Map<string, number>()
const now: () => number = typeof globalThis.performance?.now === 'function'
  ? () => globalThis.performance.now()
  : () => Date.now()

/** Increment `name` by `n` (default 1). */
export function perfCount(name: string, n = 1): void {
  counts.set(name, (counts.get(name) ?? 0) + n)
}

/** Accumulate elapsed milliseconds of `fn` under `<name>.ms` and calls under `<name>`. */
export function perfTime<T>(name: string, fn: () => T): T {
  const start = now()
  try { return fn() } finally { perfCount(`${name}.ms`, now() - start); perfCount(name) }
}

/** Async variant of `perfTime`. */
export async function perfTimeAsync<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const start = now()
  try { return await fn() } finally { perfCount(`${name}.ms`, now() - start); perfCount(name) }
}

/** Snapshot of all counters, sorted by name; `.ms` values are rounded to 0.01. */
export function perfCounters(): Record<string, number> {
  const out: Record<string, number> = {}
  for (const key of [...counts.keys()].sort()) {
    const value = counts.get(key)!
    out[key] = key.endsWith('.ms') ? Math.round(value * 100) / 100 : value
  }
  return out
}

export function resetPerfCounters(): void { counts.clear() }

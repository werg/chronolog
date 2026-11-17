/**
 * Allocate fresh author time after the caller's observed causal dependencies.
 * This has no inclusion or finality policy. Callers enforce their signed clock
 * bounds before publishing; exact retries reuse their original timestamp.
 */
export function nextAuthorTimestampMs(
  wallClockMs: bigint,
  after: readonly bigint[],
  minimumMs = 0n,
): bigint {
  let next = wallClockMs > minimumMs ? wallClockMs : minimumMs
  for (const previous of after) if (next <= previous) next = previous + 1n
  return next
}

import type { ClockPolicy } from './types.js'

/** Default live collaboration cadence; each group signs its chosen policy in genesis. */
export const DEFAULT_LIVE_CLOCK_POLICY: ClockPolicy = Object.freeze({
  cutoffLagMs: 1_000n,
  maxFutureSkewMs: 30_000n,
  heartbeatIntervalMs: 1_000n,
})

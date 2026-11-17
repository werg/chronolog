import type { ExecutionLimits } from '@chronolog/protocol'
import { openDatabase, readNativeEngineInfo } from './driver.js'
import { createDoltLiteExecutionManifest } from './manifest.js'
import type { SqlEngine } from './types.js'

/** The native adapter constructs an engine capability; the common class owns replay. */
export function createNativeSqlEngine(options: { readonly limits?: Partial<ExecutionLimits> } = {}): SqlEngine {
  return Object.freeze({
    executionManifest: createDoltLiteExecutionManifest({ engineDigest: readNativeEngineInfo().digest,
      ...(options.limits === undefined ? {} : { limits: options.limits }) }),
    openDatabase,
  })
}

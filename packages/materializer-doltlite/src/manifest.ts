import { createExecutionManifest, type ExecutionLimits, type ExecutionManifest } from '@chronolog/protocol'

import { PLATFORM_DIGEST } from './platform/digest.js'

/** One SQL semantics identity, independent of host runtime and history ordering. */
export function createDoltLiteExecutionManifest(options: {
  readonly engineDigest: Uint8Array
  readonly limits?: Partial<ExecutionLimits>
}): ExecutionManifest {
  return createExecutionManifest({
    profile: 'chronolog-sql-v1',
    engineDigest: options.engineDigest,
    platformDigest: PLATFORM_DIGEST,
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  })
}

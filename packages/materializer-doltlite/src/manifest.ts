import { createExecutionManifest, type ExecutionLimits, type ExecutionManifest } from '@chronolog/protocol'

import { readNativeEngineInfo } from './driver.js'
import { PLATFORM_DIGEST } from './platform/digest.js'

/** The execution profile Chronolog nodes run. */
export const DEFAULT_EXECUTION_PROFILE = 'chronolog-core-portable'

/** The manifest for the linked DoltLite engine and this build's platform code. */
export function createDoltLiteExecutionManifest(options: {
  readonly profile?: string
  readonly limits?: Partial<ExecutionLimits>
} = {}): ExecutionManifest {
  return createExecutionManifest({
    profile: options.profile ?? DEFAULT_EXECUTION_PROFILE,
    engineDigest: readNativeEngineInfo().digest,
    platformDigest: PLATFORM_DIGEST,
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  })
}

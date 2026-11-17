import { createExecutionManifest, type ExecutionLimits, type ExecutionManifest } from '@chronolog/protocol'

import { readNativeEngineInfo } from './driver.js'
import { computePlatformDigest } from './platform/digest.js'
import type { SqlAuthorizationPolicy, SqlMutationPolicy } from './types.js'

/** The execution profile Chronolog nodes run. */
export const DEFAULT_EXECUTION_PROFILE = 'chronolog-core-portable'

/** The manifest for the linked DoltLite engine and this build's platform code. */
export function createDoltLiteExecutionManifest(options: {
  readonly profile?: string
  readonly limits?: Partial<ExecutionLimits>
  readonly sqlPolicy?: SqlMutationPolicy
  readonly authorizationPolicy?: SqlAuthorizationPolicy
} = {}): ExecutionManifest {
  return createExecutionManifest({
    profile: options.profile ?? DEFAULT_EXECUTION_PROFILE,
    engineDigest: readNativeEngineInfo().digest,
    platformDigest: computePlatformDigest(options.sqlPolicy, options.authorizationPolicy),
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  })
}

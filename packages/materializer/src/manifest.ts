import { sha256 } from '@chronolog/canonical'
import { createExecutionManifest, utf8 } from '@chronolog/protocol'

/** Pure execution metadata; no database or materialization implementation is imported. */
export async function eventExecutionManifest() {
  return createExecutionManifest({
    profile: 'chronolog-events-v1', engine: 'none',
    engineDigest: await sha256(utf8('chronolog/events-only/v1')),
    platformDigest: await sha256(utf8('chronolog/change-program/v3;literal-events;operation-conflicts/v1;verified-input-order/v1')),
  })
}


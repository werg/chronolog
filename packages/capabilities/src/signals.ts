import { SignalChannel, signalAuthorId } from '@chronolog/signals'
import type { SignalChannelOptions } from '@chronolog/signals'

import { isCapabilityActive } from './reducer.js'
import type { CapabilitySnapshot } from './types.js'

/** Current group policy adapts to the live channel without changing its wire protocol. */
export function createCapabilitySignals(options: Omit<SignalChannelOptions, 'scope' | 'authorize'> & {
  readonly groupId: Uint8Array
  readonly current: () => CapabilitySnapshot
}): SignalChannel {
  const group = signalAuthorId(options.groupId)
  return new SignalChannel({ ...options, scope: `chronolog:${group}`,
    authorize: ({ authorId, topic }) => {
      const snapshot = options.current()
      if (signalAuthorId(snapshot.groupId) !== group) return false
      return [...snapshot.capabilities.values()].some(capability => {
        const topics = capability.grant.program?.signals
        return capability.grant.role === 'writer' && isCapabilityActive(capability, snapshot.revision) &&
          signalAuthorId(capability.grant.signingPublicKey) === authorId && topics !== undefined &&
          (topics.includes('*') || topics.includes(topic))
      })
    },
  })
}

import { bytesToHex, equalBytes } from '@chronolog/protocol'
import { SignalChannel, type SignalChannelOptions } from '@chronolog/signals'
import { signalAllowed } from './program-rights.js'
import type { CapabilitySnapshot } from './types.js'

/** Ledger authorization is an adapter, not a requirement of ephemeral messaging. */
export function createCapabilitySignals(options: Omit<SignalChannelOptions, 'scope' | 'credential' | 'authorize'> & {
  readonly groupId: Uint8Array
  readonly current: () => CapabilitySnapshot
}): SignalChannel {
  const groupId = options.groupId.slice(), scope = bytesToHex(groupId)
  if (groupId.length !== 32) throw new Error('SIGNAL_GROUP_INVALID')
  const current = (): CapabilitySnapshot => {
    const snapshot = options.current()
    if (!equalBytes(snapshot.groupId, groupId)) throw new Error('SIGNAL_GROUP_MISMATCH')
    return snapshot
  }
  return new SignalChannel({ ...options, scope,
    credential(topic) {
      const snapshot = current()
      for (const capability of snapshot.capabilities.values()) {
        if (signalAllowed(snapshot, { capabilityId: capability.id, signer: options.identity.publicKeyBytes, topic })) return capability.id.slice()
      }
      throw new Error('SIGNAL_UNAUTHORIZED')
    },
    authorize({ authorId, credential, topic }) {
      return credential !== null && credential.length === 32 && signalAllowed(current(), { capabilityId: credential, signer: authorId, topic })
    },
  })
}

export * from './control.js'
export * from './types.js'
export { MemoryBytesStore } from '@chronolog/records'
import type { PeerReplica, PeerReplicaOptions } from './types.js'

/** Database machinery loads only when an owner explicitly asks for a replica. */
export async function createPeerReplica(options: PeerReplicaOptions): Promise<PeerReplica> {
  return (await import('./replica.js')).createPeerReplica(options)
}
export * from './schema.js'
export { validatePeerRevision } from './attempt.js'
export { samePeerValue } from './codec.js'

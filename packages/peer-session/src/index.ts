import type { ApplicationDefinition } from './definition.js'
import type { CreateApplicationSessionOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'

/** Passive import; actual storage and execution modules load only on explicit local open. */
export async function createApplicationSession<const D extends ApplicationDefinition = ApplicationDefinition>(
  options: CreateApplicationSessionOptions<D>,
): Promise<ApplicationSession<D>> {
  return (await import('./runtime.js')).createApplicationSession(options)
}

export type { CreateApplicationSessionOptions } from './runtime.js'
export type {
  ApplicationSession,
  SessionFacts,
  SessionCasNode,
  MemberRecord,
  PermissionsTopicState,
  KeysTopicState,
  CheckpointBootstrapSnapshot,
} from './session.js'
export type * from './session-types.js'
export type * from './operation.js'
export * from './genesis.js'
export * from './definition.js'
export * from './device.js'
export * from '@chronolog/authority'
export {
  bytesToHex,
  hexToBytes,
  encodeLogGenesis,
  decodeLogGenesis,
  genesisLogId,
  encodeSignedOperation,
  decodeSignedOperation,
  signOperationCore,
  verifySignedOperation,
  encodeEncryptedEnvelope,
  decodeEncryptedEnvelope,
  encryptedEnvelopeDigest,
  envelopeAad,
  operationIdDigest,
  compareOperationOrder,
  isControlTopic,
  normalizeJsonValue,
  DEFAULT_RUNTIME_MANIFEST,
  DEFAULT_GENESIS_LIMITS,
} from '@chronolog/protocol'
export type {
  EventPayload,
  LogGenesis,
  JsonValue,
  OperationCore,
  OperationVisibility,
  ReducersConfig,
  RuntimeManifest,
  SignedOperation,
  EncryptedOperationEnvelope,
  TopicBinding,
  TopicUpdate,
} from '@chronolog/protocol'
export { STANDARD_MODULE_SOURCES, STANDARD_MODULE_IMPORTS } from '@chronolog/materializer/std-modules'
export type { ApplicationPeerLink, ApplicationPeerConnectOptions, ApplicationPeerDiagnostics, ApplicationPeerLinkStats, ApplicationPeerLiveDiagnostics } from './network.js'
export type { FramedPeerConnection, PeerLiveLane } from '@chronolog/records'
export * from './live-view.js'
export * from './projection.js'
export * from './view-store.js'
export * from './event-forwarder.js'
export * from './checkpoint.js'
export * from './owner-lock.js'
export * from './tools.js'
export * from './ergonomics.js'
export type * from './content.js'
export { createApplicationBackend } from './tendriller.js'
export { createApplicationOwner } from './session-owner.js'
export type * from './owner-types.js'
export { createWrapKeyPair, importWrapPrivateKey } from './wrap-keys.js'
export * from './multi-session.js'

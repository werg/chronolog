import type { ApplicationDefinition } from './definition.js'
import type { CreateApplicationSessionOptions } from './runtime.js'
import type { ApplicationSession } from './session.js'
import type { queryFederatedSql as QueryFederatedSqlFn } from './sql-extensions.js'

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
  GuardianMember,
  GuardiansConfig,
  RecoveryRequestRecord,
  KeyRingState,
  PermissionsMultisigInfo,
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
  OperationAssumption,
  OperationAssumptionsConfig,
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
export type {
  FederatedSqlSource,
  SqlBranch,
  SqlBranchDiff,
  SqlBranchProposal,
  TableRowDiff,
} from './sql-extensions.js'
export type { MerkleDbDiff } from 'chronolog-db'
export { splitSecret, combineShares, type ShamirShare } from '@chronolog/crypto'

/** Lazy passive wrapper so importing @chronolog/peer-session never eagerly pulls sqlite-cas WASM. */
export async function queryFederatedSql(
  ...args: Parameters<typeof QueryFederatedSqlFn>
): ReturnType<typeof QueryFederatedSqlFn> {
  return (await import('./sql-extensions.js')).queryFederatedSql(...args)
}

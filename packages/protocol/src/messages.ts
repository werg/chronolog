import { hashDomain as hashCanonicalDomain } from '@chronolog/canonical'

import { compareBytes } from './bytes.js'
import { assertCanonicalCbor, type CborValue, encodeCanonicalCbor } from './cbor.js'
import { ProtocolError, protocolInvariant } from './errors.js'
import {
  assertKnownIntegerKeys, expectBytes, expectMap, expectUint64,
  expectVersion, expectString, integerMap, optional, required,
} from './schema.js'
import {
  assertValidChangeProgram,
  changeProgramFromCanonicalCbor,
  changeProgramToCanonicalCbor,
  type ChangeProgram,
} from './program.js'

export interface TransactionCore {
  readonly operationId: string
  readonly groupId: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly validationPolicy: Uint8Array
  readonly authorId: Uint8Array
  /** Exact writer grant; required by governed groups, unused by static membership. */
  readonly writerCapability?: Uint8Array
  readonly authorTimestampMs: bigint
  readonly nonce: Uint8Array
  readonly executionManifestDigest: Uint8Array
  readonly program: ChangeProgram
  readonly metadata?: ReadonlyMap<string, Uint8Array>
}

export type EnvelopeMessageType = 'candidate' | 'attestation' | 'heartbeat' | 'capability' | 'epoch-manifest' | 'proof-bundle' | 'snapshot'
export interface ChronologEnvelope {
  readonly groupRoute: Uint8Array
  readonly messageType: EnvelopeMessageType
  readonly encryptionEpoch: Uint8Array | null
  /** The (possibly encrypted) signed wire message. */
  readonly payload: Uint8Array
}
export interface ValidatorAttestation {
  readonly groupId: Uint8Array; readonly membershipRevision: Uint8Array; readonly validatorCapability: Uint8Array
  readonly txId: Uint8Array; readonly validatorId: Uint8Array; readonly authorTimestampMs: bigint
  readonly acceptedAboveMs: bigint; readonly candidateDigest: Uint8Array; readonly decision: 'admit'; readonly policyVersion: bigint
}
export interface ValidatorHeartbeat { readonly groupId: Uint8Array; readonly membershipRevision: Uint8Array; readonly validatorCapability: Uint8Array; readonly validatorId: Uint8Array; readonly acceptanceCutoffMs: bigint }
/** Application order depends only on the signed proposal, never its delivery transport. */
export interface TransactionOrderKey { readonly authorTimestampMs: bigint; readonly authorId: Uint8Array; readonly txId: Uint8Array }

function metadataToCbor(metadata: ReadonlyMap<string, Uint8Array> | undefined): CborValue | undefined {
  if (metadata === undefined) return undefined
  return new Map([...metadata.entries()].map(([key, value]) => [key, value] as const))
}

function metadataFromCbor(value: CborValue): ReadonlyMap<string, Uint8Array> {
  const map = expectMap(value, 'transaction.metadata'), result = new Map<string, Uint8Array>()
  for (const [key, item] of map) { protocolInvariant(typeof key === 'string', 'SCHEMA_INVALID', 'Transaction metadata keys must be text'); result.set(key, expectBytes(item, `transaction.metadata.${String(key)}`)) }
  return result
}

function transactionToCbor(value: TransactionCore): CborValue {
  protocolInvariant(typeof value.operationId === 'string' && value.operationId.length > 0 && value.operationId.length <= 512 &&
    [...value.operationId].every((character) => character.charCodeAt(0) >= 32), 'SCHEMA_INVALID', 'Operation identity must be bounded nonempty text')
  for (const [field, bytes] of [
    ['groupId', value.groupId], ['membershipRevision', value.membershipRevision],
    ['validationPolicy', value.validationPolicy], ['authorId', value.authorId],
  ] as const) protocolInvariant(bytes.length === 32, 'SCHEMA_INVALID', `${field} must contain 32 bytes`)
  protocolInvariant(value.authorTimestampMs >= 0n && value.authorTimestampMs <= (1n << 63n) - 1n, 'INTEGER_OUT_OF_RANGE', 'Author timestamp must be a nonnegative int64')
  protocolInvariant(value.nonce.length >= 16, 'SCHEMA_INVALID', 'Transaction nonce must contain at least 16 bytes')
  protocolInvariant(value.executionManifestDigest.length === 32, 'SCHEMA_INVALID', 'Execution-manifest digest must contain 32 bytes')
  if (value.writerCapability !== undefined) protocolInvariant(value.writerCapability.length === 32, 'SCHEMA_INVALID', 'Writer capability must contain 32 bytes')
  assertValidChangeProgram(value.program)
  return integerMap([
    [0, 2n], [1, value.groupId], [2, value.membershipRevision], [3, value.validationPolicy],
    [4, value.authorId], [5, value.authorTimestampMs], [6, value.nonce], [7, value.executionManifestDigest],
    [8, changeProgramToCanonicalCbor(value.program)], [9, metadataToCbor(value.metadata)], [10, value.writerCapability], [11, value.operationId],
  ])
}

export function encodeTransactionCore(value: TransactionCore): Uint8Array { return encodeCanonicalCbor(transactionToCbor(value)) }

export function decodeTransactionCore(bytes: Uint8Array): TransactionCore {
  const map = expectMap(assertCanonicalCbor(bytes), 'transaction')
  assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 'transaction')
  expectVersion(map, 2n, 'transaction')
  const authorTimestampMs = expectUint64(required(map, 5, 'transaction.author_timestamp_ms'), 'transaction.author_timestamp_ms')
  protocolInvariant(authorTimestampMs <= (1n << 63n) - 1n, 'INTEGER_OUT_OF_RANGE', 'Author timestamp is outside nonnegative int64')
  const nonce = expectBytes(required(map, 6, 'transaction.nonce'), 'transaction.nonce')
  protocolInvariant(nonce.length >= 16, 'SCHEMA_INVALID', 'Transaction nonce must contain at least 16 bytes')
  const program = changeProgramFromCanonicalCbor(required(map, 8, 'transaction.program'))
  assertValidChangeProgram(program)
  const metadata = optional(map, 9)
  const writerCapability = optional(map, 10)
  const core: TransactionCore = {
    operationId: expectString(required(map, 11, 'transaction.operation_id'), 'transaction.operation_id'),
    groupId: expectBytes(required(map, 1, 'transaction.group_id'), 'transaction.group_id', 32),
    membershipRevision: expectBytes(required(map, 2, 'transaction.membership_revision'), 'transaction.membership_revision', 32),
    validationPolicy: expectBytes(required(map, 3, 'transaction.validation_policy'), 'transaction.validation_policy', 32),
    authorId: expectBytes(required(map, 4, 'transaction.author_id'), 'transaction.author_id', 32),
    authorTimestampMs, nonce,
    executionManifestDigest: expectBytes(required(map, 7, 'transaction.execution_manifest_digest'), 'transaction.execution_manifest_digest', 32),
    program,
    ...(metadata === undefined ? {} : { metadata: metadataFromCbor(metadata) }),
    ...(writerCapability === undefined ? {} : { writerCapability: expectBytes(writerCapability, 'transaction.writer_capability', 32) }),
  }
  transactionToCbor(core)
  return core
}

export async function transactionDigest(value: TransactionCore | Uint8Array): Promise<Uint8Array> { return hashCanonicalDomain('transaction', value instanceof Uint8Array ? value : encodeTransactionCore(value)) }
// Wire codes are positions in this list; code 4 (formerly 'recovery') is retired.
const MESSAGE_TYPES: readonly (EnvelopeMessageType | null)[] = ['candidate', 'attestation', 'heartbeat', 'capability', null, 'epoch-manifest', 'proof-bundle', 'snapshot']
export function encodeEnvelope(value: ChronologEnvelope): Uint8Array {
  const messageIndex = MESSAGE_TYPES.indexOf(value.messageType); protocolInvariant(messageIndex >= 0, 'SCHEMA_INVALID', 'Unknown envelope message type')
  return encodeCanonicalCbor(integerMap([[0, 1n], [1, value.groupRoute], [2, BigInt(messageIndex)], [3, value.encryptionEpoch], [4, value.payload]]))
}
export function decodeEnvelope(bytes: Uint8Array): ChronologEnvelope {
  const map = expectMap(assertCanonicalCbor(bytes), 'envelope'); assertKnownIntegerKeys(map, [0, 1, 2, 3, 4], 'envelope'); expectVersion(map, 1n, 'envelope')
  const typeIndex = expectUint64(required(map, 2, 'envelope.message_type'), 'envelope.message_type'); protocolInvariant(typeIndex < BigInt(MESSAGE_TYPES.length), 'SCHEMA_INVALID', 'Unknown envelope message type')
  const messageType = MESSAGE_TYPES[Number(typeIndex)]; protocolInvariant(messageType !== undefined && messageType !== null, 'SCHEMA_INVALID', 'Unknown envelope message type')
  const epoch = required(map, 3, 'envelope.encryption_epoch'); protocolInvariant(epoch === null || epoch instanceof Uint8Array, 'SCHEMA_INVALID', 'Envelope encryption epoch must be null or bytes')
  return { groupRoute: expectBytes(required(map, 1, 'envelope.group_route'), 'envelope.group_route'), messageType, encryptionEpoch: epoch, payload: expectBytes(required(map, 4, 'envelope.payload'), 'envelope.payload') }
}

function attestationToCbor(value: ValidatorAttestation): CborValue {
  protocolInvariant(value.decision === 'admit', 'SCHEMA_INVALID', 'Only positive validator attestations are protocol events')
  protocolInvariant(value.authorTimestampMs > value.acceptedAboveMs, 'SCHEMA_INVALID', 'Attestation timestamp must exceed validator cutoff')
  return integerMap([[0, 1n], [1, value.groupId], [2, value.membershipRevision], [3, value.validatorCapability], [4, value.txId], [5, value.validatorId], [6, value.authorTimestampMs], [7, value.acceptedAboveMs], [8, value.candidateDigest], [9, 1n], [10, value.policyVersion]])
}
export function encodeValidatorAttestation(value: ValidatorAttestation): Uint8Array { return encodeCanonicalCbor(attestationToCbor(value)) }
export function decodeValidatorAttestation(bytes: Uint8Array): ValidatorAttestation {
  const map = expectMap(assertCanonicalCbor(bytes), 'attestation'); assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 'attestation'); expectVersion(map, 1n, 'attestation')
  protocolInvariant(expectUint64(required(map, 9, 'attestation.decision'), 'attestation.decision') === 1n, 'SCHEMA_INVALID', 'Only admit attestations are supported')
  const authorTimestampMs = expectUint64(required(map, 6, 'attestation.author_timestamp_ms'), 'attestation.author_timestamp_ms'), acceptedAboveMs = expectUint64(required(map, 7, 'attestation.accepted_above_ms'), 'attestation.accepted_above_ms')
  protocolInvariant(authorTimestampMs > acceptedAboveMs, 'SCHEMA_INVALID', 'Attestation timestamp must exceed validator cutoff')
  return { groupId: expectBytes(required(map, 1, 'attestation.group_id'), 'attestation.group_id'), membershipRevision: expectBytes(required(map, 2, 'attestation.membership_revision'), 'attestation.membership_revision'), validatorCapability: expectBytes(required(map, 3, 'attestation.validator_capability'), 'attestation.validator_capability'), txId: expectBytes(required(map, 4, 'attestation.tx_id'), 'attestation.tx_id'), validatorId: expectBytes(required(map, 5, 'attestation.validator_id'), 'attestation.validator_id'), authorTimestampMs, acceptedAboveMs, candidateDigest: expectBytes(required(map, 8, 'attestation.candidate_digest'), 'attestation.candidate_digest', 32), decision: 'admit', policyVersion: expectUint64(required(map, 10, 'attestation.policy_version'), 'attestation.policy_version') }
}

function heartbeatToCbor(value: ValidatorHeartbeat): CborValue { return integerMap([[0, 1n], [1, value.groupId], [2, value.membershipRevision], [3, value.validatorCapability], [4, value.validatorId], [5, value.acceptanceCutoffMs]]) }
export function encodeValidatorHeartbeat(value: ValidatorHeartbeat): Uint8Array { return encodeCanonicalCbor(heartbeatToCbor(value)) }
export function decodeValidatorHeartbeat(bytes: Uint8Array): ValidatorHeartbeat {
  const map = expectMap(assertCanonicalCbor(bytes), 'heartbeat'); assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 5], 'heartbeat'); expectVersion(map, 1n, 'heartbeat')
  return { groupId: expectBytes(required(map, 1, 'heartbeat.group_id'), 'heartbeat.group_id'), membershipRevision: expectBytes(required(map, 2, 'heartbeat.membership_revision'), 'heartbeat.membership_revision'), validatorCapability: expectBytes(required(map, 3, 'heartbeat.validator_capability'), 'heartbeat.validator_capability'), validatorId: expectBytes(required(map, 4, 'heartbeat.validator_id'), 'heartbeat.validator_id'), acceptanceCutoffMs: expectUint64(required(map, 5, 'heartbeat.acceptance_cutoff_ms'), 'heartbeat.acceptance_cutoff_ms') }
}

export function transactionOrderKey(core: Pick<TransactionCore, 'authorTimestampMs' | 'authorId'>, txId: Uint8Array): TransactionOrderKey {
  return { authorTimestampMs: core.authorTimestampMs, authorId: core.authorId, txId }
}
export function compareTransactionOrder(left: TransactionOrderKey, right: TransactionOrderKey): number {
  if (left.authorTimestampMs !== right.authorTimestampMs) return left.authorTimestampMs < right.authorTimestampMs ? -1 : 1
  const authorOrder = compareBytes(left.authorId, right.authorId)
  return authorOrder === 0 ? compareBytes(left.txId, right.txId) : authorOrder
}
export function assertUniqueOrderKeys(keys: readonly TransactionOrderKey[]): void { const sorted = [...keys].sort(compareTransactionOrder); for (let index = 1; index < sorted.length; index += 1) if (compareTransactionOrder(sorted[index - 1]!, sorted[index]!) === 0) throw new ProtocolError('DUPLICATE_TRANSACTION', 'Duplicate transaction order key') }

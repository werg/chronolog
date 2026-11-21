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
  readonly writerCapability?: Uint8Array
  readonly authorTimestampMs: bigint
  readonly nonce: Uint8Array
  readonly executionManifestDigest: Uint8Array
  readonly program: ChangeProgram
  readonly metadata?: ReadonlyMap<string, Uint8Array>
}

/** Deterministic tie-break key for an authored transaction. */
export interface TransactionOrderKey { readonly authorTimestampMs: bigint; readonly authorId: Uint8Array; readonly txId: Uint8Array }

function metadataToCbor(metadata: ReadonlyMap<string, Uint8Array> | undefined): CborValue | undefined {
  if (metadata === undefined) return undefined
  return new Map([...metadata.entries()].map(([key, value]) => [key, value] as const))
}

function metadataFromCbor(value: CborValue): ReadonlyMap<string, Uint8Array> {
  const map = expectMap(value, 'transaction.metadata'), result = new Map<string, Uint8Array>()
  for (const [key, item] of map) {
    protocolInvariant(typeof key === 'string', 'SCHEMA_INVALID', 'Transaction metadata keys must be text')
    result.set(key, expectBytes(item, `transaction.metadata.${String(key)}`))
  }
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

export async function transactionDigest(value: TransactionCore | Uint8Array): Promise<Uint8Array> {
  return hashCanonicalDomain('transaction', value instanceof Uint8Array ? value : encodeTransactionCore(value))
}

export function transactionOrderKey(core: Pick<TransactionCore, 'authorTimestampMs' | 'authorId'>, txId: Uint8Array): TransactionOrderKey {
  return { authorTimestampMs: core.authorTimestampMs, authorId: core.authorId, txId }
}

export function compareTransactionOrder(left: TransactionOrderKey, right: TransactionOrderKey): number {
  if (left.authorTimestampMs !== right.authorTimestampMs) return left.authorTimestampMs < right.authorTimestampMs ? -1 : 1
  const authorOrder = compareBytes(left.authorId, right.authorId)
  if (authorOrder !== 0) return authorOrder
  return compareBytes(left.txId, right.txId)
}

export function assertUniqueOrderKeys(keys: readonly TransactionOrderKey[]): void {
  const sorted = [...keys].sort(compareTransactionOrder)
  for (let index = 1; index < sorted.length; index += 1) {
    if (compareTransactionOrder(sorted[index - 1]!, sorted[index]!) === 0) {
      throw new ProtocolError('DUPLICATE_TRANSACTION', 'Duplicate transaction order key')
    }
  }
}

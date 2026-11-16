import { compareBytes, equalBytes, utf8 } from './bytes.js'
import { assertCanonicalCbor, encodeCanonicalCbor, type CborValue } from './cbor.js'
import { protocolInvariant } from './errors.js'
import {
  assertKnownIntegerKeys, expectArray, expectBytes, expectMap, expectString,
  expectUint64, expectVersion, integerMap, optional, required,
} from './schema.js'
import { sqlValueFromCanonicalCbor, sqlValueToCanonicalCbor, toSqlValue, type SqlValue } from './sql.js'

/** Sealed values contain client ciphertext; no plaintext or secret key enters a transaction. */
export const MAX_SEALED_READERS = 256
export const MAX_SEALED_NAME_BYTES = 128
export const MAX_SEALED_ROW_KEY_VALUES = 64
export const MAX_SEALED_PLAINTEXT_BYTES = 1024 * 1024
export const MAX_SEALED_ENVELOPE_BYTES = MAX_SEALED_PLAINTEXT_BYTES + MAX_SEALED_READERS * 192 + 1024
/** Versions are stored in SQLite INTEGER columns, so they use the positive int64 range. */
export const MAX_SEALED_VERSION = (1n << 63n) - 1n

export interface SealedContext {
  readonly groupId: Uint8Array
  readonly policyId: Uint8Array
  readonly policyVersion: bigint
  readonly slot: string
  readonly dataVersion: bigint
}

/** A policy snapshots each reader's registered HPKE key; key registration alone changes no policy. */
export interface SealedRecipient {
  readonly readerId: Uint8Array
  readonly publicKey: Uint8Array
}

export interface SealedKeyWrap extends SealedRecipient {
  readonly encapsulatedKey: Uint8Array
  readonly ciphertext: Uint8Array
}

export interface SealedEnvelope {
  readonly context: SealedContext
  readonly nonce: Uint8Array
  readonly ciphertext: Uint8Array
  /** Strictly increasing reader ids. Every current policy reader has exactly one wrap. */
  readonly wraps: readonly SealedKeyWrap[]
}

/** Reserved codes leave the original ownership operation encoding unchanged. */
export const SEALED_OP_CODES = Object.freeze({
  register_reader_key: 64n,
  reader_policy: 65n,
  sealed_put: 66n,
})

export type SealedPlatformOp =
  | { readonly op: 'register_reader_key'; readonly publicKey: Uint8Array }
  | {
    readonly op: 'reader_policy'
    readonly table: string
    readonly rowKey: readonly SqlValue[]
    /** Absent only when creating a new policy generation (expectedVersion = 0). */
    readonly expectedPolicyId?: Uint8Array
    readonly expectedVersion: bigint
    /** Signing-key ids, strictly sorted and unique. No owner or administrator is added implicitly. */
    readonly readers: readonly Uint8Array[]
  }
  | {
    readonly op: 'sealed_put'
    readonly policyId: Uint8Array
    readonly expectedPolicyVersion: bigint
    readonly expectedDataVersion: bigint
    readonly slot: string
    readonly envelope: SealedEnvelope
  }

export function isSealedPlatformOp(value: unknown): value is SealedPlatformOp {
  return typeof value === 'object' && value !== null && 'op' in value &&
    typeof value.op === 'string' && Object.hasOwn(SEALED_OP_CODES, value.op)
}

export const sealedOp = Object.freeze({
  registerReaderKey: (publicKey: Uint8Array): SealedPlatformOp =>
    checked({ op: 'register_reader_key', publicKey: id(publicKey, 'register_reader_key.public_key') }),
  readerPolicy: (input: {
    readonly table: string
    readonly rowKey: readonly unknown[]
    readonly expectedPolicyId?: Uint8Array
    readonly expectedVersion: bigint
    readonly readers: readonly Uint8Array[]
  }): SealedPlatformOp => checked({
    op: 'reader_policy',
    table: input.table,
    rowKey: input.rowKey.map(toSqlValue),
    expectedVersion: input.expectedVersion,
    ...(input.expectedPolicyId === undefined ? {} : { expectedPolicyId: id(input.expectedPolicyId, 'reader_policy.expected_policy_id') }),
    readers: input.readers.map((reader) => id(reader, 'reader_policy.reader')).sort(compareBytes),
  }),
  put: (input: {
    readonly policyId: Uint8Array
    readonly expectedPolicyVersion: bigint
    readonly expectedDataVersion: bigint
    readonly slot: string
    readonly envelope: SealedEnvelope
  }): SealedPlatformOp => checked({
    op: 'sealed_put',
    policyId: id(input.policyId, 'sealed_put.policy_id'),
    expectedPolicyVersion: input.expectedPolicyVersion,
    expectedDataVersion: input.expectedDataVersion,
    slot: input.slot,
    envelope: decodeSealedEnvelope(encodeSealedEnvelope(input.envelope)),
  }),
})

function checked(op: SealedPlatformOp): SealedPlatformOp {
  // Decode the validated canonical form as well, so nested bytes cannot be
  // mutated through a caller's row-key or envelope object after construction.
  return sealedPlatformOpFromCanonicalCbor(sealedPlatformOpToCanonicalCbor(op))
}

function id(value: Uint8Array, field: string): Uint8Array {
  protocolInvariant(value instanceof Uint8Array && value.length === 32, 'SCHEMA_INVALID', `${field} must contain 32 bytes`)
  return Uint8Array.from(value)
}

function name(value: string, field: string): string {
  protocolInvariant(typeof value === 'string' && value.length > 0 && !value.includes('\0'), 'SCHEMA_INVALID', `${field} must be nonempty text without U+0000`)
  protocolInvariant(utf8(value).length <= MAX_SEALED_NAME_BYTES, 'SCHEMA_INVALID', `${field} is too long`)
  return value
}

function version(value: bigint, field: string, minimum = 1n, maximum = MAX_SEALED_VERSION): bigint {
  const parsed = expectUint64(value, field)
  protocolInvariant(parsed >= minimum && parsed <= maximum, 'INTEGER_OUT_OF_RANGE', `${field} is outside the supported version range`)
  return parsed
}

const isList = (value: unknown): boolean => Array.isArray(value)

function orderedReaders(readers: readonly Uint8Array[], field: string): Uint8Array[] {
  protocolInvariant(isList(readers) && readers.length <= MAX_SEALED_READERS, 'SCHEMA_INVALID', `${field} has too many readers or is not an array`)
  return readers.map((reader, index) => {
    const key = id(reader, field)
    if (index > 0) protocolInvariant(compareBytes(readers[index - 1]!, reader) < 0, 'SCHEMA_INVALID', `${field} must be sorted and unique`)
    return key
  })
}

export function sealedContextToCanonicalCbor(value: SealedContext): CborValue {
  return integerMap([
    [0, 1n],
    [1, id(value.groupId, 'sealed_context.group_id')],
    [2, id(value.policyId, 'sealed_context.policy_id')],
    [3, version(value.policyVersion, 'sealed_context.policy_version')],
    [4, name(value.slot, 'sealed_context.slot')],
    [5, version(value.dataVersion, 'sealed_context.data_version')],
  ])
}

export function sealedContextFromCanonicalCbor(value: CborValue): SealedContext {
  const map = expectMap(value, 'sealed_context')
  assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 5], 'sealed_context')
  expectVersion(map, 1n, 'sealed_context')
  const context: SealedContext = {
    groupId: id(expectBytes(required(map, 1, 'group_id'), 'group_id', 32), 'group_id'),
    policyId: id(expectBytes(required(map, 2, 'policy_id'), 'policy_id', 32), 'policy_id'),
    policyVersion: expectUint64(required(map, 3, 'policy_version'), 'policy_version'),
    slot: expectString(required(map, 4, 'slot'), 'slot'),
    dataVersion: expectUint64(required(map, 5, 'data_version'), 'data_version'),
  }
  sealedContextToCanonicalCbor(context)
  return context
}

export function encodeSealedContext(context: SealedContext): Uint8Array {
  return encodeCanonicalCbor(sealedContextToCanonicalCbor(context))
}

export function sealedEnvelopeToCanonicalCbor(value: SealedEnvelope): CborValue {
  protocolInvariant(value.nonce instanceof Uint8Array && value.nonce.length === 12, 'SCHEMA_INVALID', 'sealed_envelope.nonce must contain 12 bytes')
  protocolInvariant(value.ciphertext instanceof Uint8Array && value.ciphertext.length >= 16 && value.ciphertext.length <= MAX_SEALED_PLAINTEXT_BYTES + 16,
    'SCHEMA_INVALID', 'sealed_envelope.ciphertext has an invalid length')
  protocolInvariant(isList(value.wraps), 'SCHEMA_INVALID', 'sealed_envelope.wraps must be an array')
  orderedReaders(value.wraps.map((wrap) => wrap.readerId), 'sealed_envelope.wraps')
  return integerMap([
    [0, 1n],
    [1, sealedContextToCanonicalCbor(value.context)],
    [2, Uint8Array.from(value.nonce)],
    [3, Uint8Array.from(value.ciphertext)],
    [4, value.wraps.map((wrap) => {
      protocolInvariant(wrap.ciphertext instanceof Uint8Array && wrap.ciphertext.length === 48, 'SCHEMA_INVALID', 'sealed_wrap.ciphertext must contain 48 bytes')
      return [id(wrap.readerId, 'sealed_wrap.reader_id'), id(wrap.publicKey, 'sealed_wrap.public_key'),
        id(wrap.encapsulatedKey, 'sealed_wrap.encapsulated_key'), Uint8Array.from(wrap.ciphertext)]
    })],
  ])
}

export function sealedEnvelopeFromCanonicalCbor(value: CborValue): SealedEnvelope {
  const map = expectMap(value, 'sealed_envelope')
  assertKnownIntegerKeys(map, [0, 1, 2, 3, 4], 'sealed_envelope')
  expectVersion(map, 1n, 'sealed_envelope')
  const envelope: SealedEnvelope = {
    context: sealedContextFromCanonicalCbor(required(map, 1, 'context')),
    nonce: Uint8Array.from(expectBytes(required(map, 2, 'nonce'), 'nonce', 12)),
    ciphertext: Uint8Array.from(expectBytes(required(map, 3, 'ciphertext'), 'ciphertext')),
    wraps: expectArray(required(map, 4, 'wraps'), 'wraps').map((entry) => {
      const fields = expectArray(entry, 'sealed_wrap')
      protocolInvariant(fields.length === 4, 'SCHEMA_INVALID', 'sealed_wrap must contain four fields')
      return {
        readerId: id(expectBytes(fields[0]!, 'reader_id', 32), 'reader_id'),
        publicKey: id(expectBytes(fields[1]!, 'public_key', 32), 'public_key'),
        encapsulatedKey: id(expectBytes(fields[2]!, 'encapsulated_key', 32), 'encapsulated_key'),
        ciphertext: Uint8Array.from(expectBytes(fields[3]!, 'wrapped_key', 48)),
      }
    }),
  }
  sealedEnvelopeToCanonicalCbor(envelope)
  return envelope
}

export function encodeSealedEnvelope(envelope: SealedEnvelope): Uint8Array {
  return encodeCanonicalCbor(sealedEnvelopeToCanonicalCbor(envelope))
}

export function decodeSealedEnvelope(bytes: Uint8Array): SealedEnvelope {
  protocolInvariant(bytes.length <= MAX_SEALED_ENVELOPE_BYTES, 'SCHEMA_INVALID', 'sealed_envelope exceeds the encoded size limit')
  return sealedEnvelopeFromCanonicalCbor(assertCanonicalCbor(bytes))
}

export function sealedPlatformOpToCanonicalCbor(op: SealedPlatformOp): CborValue {
  protocolInvariant(isSealedPlatformOp(op), 'SCHEMA_INVALID', 'Unknown sealed operation')
  const entries: (readonly [number, CborValue | undefined])[] = [[0, SEALED_OP_CODES[op.op]]]
  switch (op.op) {
    case 'register_reader_key':
      entries.push([1, id(op.publicKey, 'register_reader_key.public_key')])
      break
    case 'reader_policy': {
      const expected = version(op.expectedVersion, 'reader_policy.expected_version', 0n, MAX_SEALED_VERSION - 1n)
      protocolInvariant((expected === 0n) === (op.expectedPolicyId === undefined), 'SCHEMA_INVALID', 'reader_policy creation uses version 0 without an id; replacement requires an id and positive version')
      protocolInvariant(isList(op.rowKey) && op.rowKey.length >= 1 && op.rowKey.length <= MAX_SEALED_ROW_KEY_VALUES, 'SCHEMA_INVALID', 'reader_policy.row_key has an invalid length')
      entries.push(
        [1, name(op.table, 'reader_policy.table')],
        [2, op.rowKey.map(sqlValueToCanonicalCbor)],
        [3, op.expectedPolicyId === undefined ? undefined : id(op.expectedPolicyId, 'reader_policy.expected_policy_id')],
        [4, expected],
        [5, orderedReaders(op.readers, 'reader_policy.readers')],
      )
      break
    }
    case 'sealed_put': {
      const policyId = id(op.policyId, 'sealed_put.policy_id')
      const policyVersion = version(op.expectedPolicyVersion, 'sealed_put.expected_policy_version')
      const dataVersion = version(op.expectedDataVersion, 'sealed_put.expected_data_version', 0n, MAX_SEALED_VERSION - 1n)
      const slot = name(op.slot, 'sealed_put.slot')
      const envelope = sealedEnvelopeToCanonicalCbor(op.envelope)
      protocolInvariant(equalBytes(op.envelope.context.policyId, policyId) && op.envelope.context.policyVersion === policyVersion &&
        op.envelope.context.slot === slot && op.envelope.context.dataVersion === dataVersion + 1n,
      'SCHEMA_INVALID', 'sealed_put envelope does not match its policy, slot or next data version')
      entries.push([1, policyId], [2, policyVersion], [3, dataVersion], [4, slot], [5, envelope])
      break
    }
  }
  return integerMap(entries)
}

export function sealedPlatformOpFromCanonicalCbor(value: CborValue, field = 'sealed_op'): SealedPlatformOp {
  const map = expectMap(value, field)
  const code = expectUint64(required(map, 0, `${field}.op`), `${field}.op`)
  let op: SealedPlatformOp
  if (code === SEALED_OP_CODES.register_reader_key) {
    assertKnownIntegerKeys(map, [0, 1], field)
    op = { op: 'register_reader_key', publicKey: id(expectBytes(required(map, 1, 'public_key'), 'public_key', 32), 'public_key') }
  } else if (code === SEALED_OP_CODES.reader_policy) {
    assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 5], field)
    const expectedPolicyId = optional(map, 3)
    op = {
      op: 'reader_policy',
      table: expectString(required(map, 1, 'table'), 'table'),
      rowKey: expectArray(required(map, 2, 'row_key'), 'row_key').map((item, index) => sqlValueFromCanonicalCbor(item, `row_key[${index}]`)),
      ...(expectedPolicyId === undefined ? {} : { expectedPolicyId: id(expectBytes(expectedPolicyId, 'expected_policy_id', 32), 'expected_policy_id') }),
      expectedVersion: expectUint64(required(map, 4, 'expected_version'), 'expected_version'),
      readers: expectArray(required(map, 5, 'readers'), 'readers').map((reader) => id(expectBytes(reader, 'reader', 32), 'reader')),
    }
  } else if (code === SEALED_OP_CODES.sealed_put) {
    assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 5], field)
    op = {
      op: 'sealed_put',
      policyId: id(expectBytes(required(map, 1, 'policy_id'), 'policy_id', 32), 'policy_id'),
      expectedPolicyVersion: expectUint64(required(map, 2, 'expected_policy_version'), 'expected_policy_version'),
      expectedDataVersion: expectUint64(required(map, 3, 'expected_data_version'), 'expected_data_version'),
      slot: expectString(required(map, 4, 'slot'), 'slot'),
      envelope: sealedEnvelopeFromCanonicalCbor(required(map, 5, 'envelope')),
    }
  } else {
    protocolInvariant(false, 'SCHEMA_INVALID', `${field} has an unknown sealed operation`)
  }
  sealedPlatformOpToCanonicalCbor(op)
  return op
}

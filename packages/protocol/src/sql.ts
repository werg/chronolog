import { hashDomain } from '@chronolog/canonical'

import { utf8 } from './bytes.js'
import { assertCanonicalCbor, encodeCanonicalCbor, type CborValue } from './cbor.js'
import { protocolInvariant } from './errors.js'
import {
  assertKnownIntegerKeys,
  expectArray,
  expectBytes,
  expectInt64,
  expectMap,
  expectString,
  expectUint64,
  expectVersion,
  integerMap,
  required,
} from './schema.js'

/** SQLite's five storage classes; the only values a transaction can bind. */
export type SqlValue =
  | { readonly kind: 'null' }
  | { readonly kind: 'integer'; readonly value: bigint }
  | { readonly kind: 'real'; readonly value: number }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'blob'; readonly value: Uint8Array }

export interface SqlBinding {
  readonly parameter:
    | { readonly kind: 'index'; readonly index: number }
    | { readonly kind: 'name'; readonly name: string }
  readonly value: SqlValue
}

export interface SqlStatement {
  readonly sql: string
  readonly bindings: readonly SqlBinding[]
}

export const MAX_SQL_STATEMENT_BINDINGS = 1_000
export const MAX_ASSERT_CODE_BYTES = 128

const MIN_INT64 = -(1n << 63n)
const MAX_INT64 = (1n << 63n) - 1n

export const sqlValue = Object.freeze({
  null: (): SqlValue => ({ kind: 'null' }),
  integer: (value: bigint | number): SqlValue => {
    const integer = typeof value === 'bigint' ? value : BigInt(value)
    protocolInvariant(integer >= MIN_INT64 && integer <= MAX_INT64, 'INTEGER_OUT_OF_RANGE', 'SQL INTEGER must be signed 64-bit')
    return { kind: 'integer', value: integer }
  },
  real: (value: number): SqlValue => {
    protocolInvariant(Number.isFinite(value), 'SCHEMA_INVALID', 'SQL REAL must be finite')
    return { kind: 'real', value }
  },
  text: (value: string): SqlValue => {
    utf8(value)
    return { kind: 'text', value }
  },
  blob: (value: Uint8Array): SqlValue => ({ kind: 'blob', value: Uint8Array.from(value) }),
})

/**
 * The natural SQLite value of a JavaScript value: safe-integer numbers and
 * bigints are INTEGER, other finite numbers REAL, strings TEXT, bytes BLOB.
 * Use `sqlValue.real(1)` for an integral REAL.
 */
export function toSqlValue(value: unknown): SqlValue {
  if (value === null || value === undefined) return sqlValue.null()
  if (typeof value === 'bigint') return sqlValue.integer(value)
  if (typeof value === 'number') return Number.isSafeInteger(value) ? sqlValue.integer(value) : sqlValue.real(value)
  if (typeof value === 'boolean') return sqlValue.integer(value ? 1n : 0n)
  if (typeof value === 'string') return sqlValue.text(value)
  if (value instanceof Uint8Array) return sqlValue.blob(value)
  if (isSqlValue(value)) return value
  throw new TypeError('SQL values must be null, boolean, bigint, number, string, Uint8Array or a tagged SqlValue')
}

export function isSqlValue(value: unknown): value is SqlValue {
  if (typeof value !== 'object' || value === null || !('kind' in value)) return false
  const tagged = value as { readonly kind: unknown; readonly value?: unknown }
  switch (tagged.kind) {
    case 'null': return true
    case 'integer': return typeof tagged.value === 'bigint'
    case 'real': return typeof tagged.value === 'number'
    case 'text': return typeof tagged.value === 'string'
    case 'blob': return tagged.value instanceof Uint8Array
    default: return false
  }
}

/** Positional or named bindings in the shape SQL builders produce. */
export function sqlStatement(sql: string, parameters: readonly unknown[] | Readonly<Record<string, unknown>> = []): SqlStatement {
  const bindings: SqlBinding[] = Array.isArray(parameters)
    ? (parameters as readonly unknown[]).map((value, index) => ({ parameter: { kind: 'index', index: index + 1 }, value: toSqlValue(value) }))
    : Object.entries(parameters).map(([name, value]) => ({
        parameter: { kind: 'name', name: /^[:@$]/u.test(name) ? name : `:${name}` },
        value: toSqlValue(value),
      }))
  const statement = { sql, bindings }
  sqlStatementToCanonicalCbor(statement)
  return statement
}

function realBits(value: number): Uint8Array {
  const bits = new Uint8Array(8)
  new DataView(bits.buffer).setFloat64(0, value, false)
  return bits
}

export function sqlValueToCanonicalCbor(value: SqlValue): CborValue {
  switch (value.kind) {
    case 'null': return [0n]
    case 'integer':
      protocolInvariant(value.value >= MIN_INT64 && value.value <= MAX_INT64, 'INTEGER_OUT_OF_RANGE', 'SQL INTEGER must be signed 64-bit')
      return [1n, value.value]
    case 'real':
      protocolInvariant(Number.isFinite(value.value), 'SCHEMA_INVALID', 'SQL REAL must be finite')
      return [2n, realBits(value.value)]
    case 'text':
      utf8(value.value)
      return [3n, value.value]
    case 'blob': return [4n, Uint8Array.from(value.value)]
  }
}

export function sqlValueFromCanonicalCbor(value: CborValue, name = 'sql_value'): SqlValue {
  const tuple = expectArray(value, name)
  const kind = expectUint64(tuple[0] ?? null, `${name}.kind`)
  protocolInvariant(tuple.length === (kind === 0n ? 1 : 2), 'SCHEMA_INVALID', `${name} has invalid arity`)
  switch (kind) {
    case 0n: return { kind: 'null' }
    case 1n: return { kind: 'integer', value: expectInt64(tuple[1] ?? null, `${name}.integer`) }
    case 2n: {
      const bits = expectBytes(tuple[1] ?? null, `${name}.real`, 8)
      const real = new DataView(bits.buffer, bits.byteOffset, 8).getFloat64(0, false)
      protocolInvariant(Number.isFinite(real), 'SCHEMA_INVALID', `${name}.real must be finite`)
      return { kind: 'real', value: real }
    }
    case 3n: return { kind: 'text', value: expectString(tuple[1] ?? null, `${name}.text`) }
    case 4n: return { kind: 'blob', value: Uint8Array.from(expectBytes(tuple[1] ?? null, `${name}.blob`)) }
    default: protocolInvariant(false, 'SCHEMA_INVALID', `${name} has unknown kind`)
  }
}

function bindingToCbor(binding: SqlBinding): CborValue {
  if (binding.parameter.kind === 'index') {
    const index = binding.parameter.index
    protocolInvariant(Number.isSafeInteger(index) && index >= 1, 'INTEGER_OUT_OF_RANGE', 'SQL binding index must be a positive integer')
    return [[0n, BigInt(index)], sqlValueToCanonicalCbor(binding.value)]
  }
  protocolInvariant(/^[:@$].+/u.test(binding.parameter.name), 'SCHEMA_INVALID', 'Named SQL bindings must keep their SQLite prefix (:, @ or $)')
  return [[1n, binding.parameter.name], sqlValueToCanonicalCbor(binding.value)]
}

function bindingFromCbor(value: CborValue, name: string): SqlBinding {
  const tuple = expectArray(value, name)
  protocolInvariant(tuple.length === 2, 'SCHEMA_INVALID', `${name} has invalid arity`)
  const parameter = expectArray(tuple[0] ?? null, `${name}.parameter`)
  protocolInvariant(parameter.length === 2, 'SCHEMA_INVALID', `${name}.parameter has invalid arity`)
  const kind = expectUint64(parameter[0] ?? null, `${name}.parameter.kind`)
  let decoded: SqlBinding['parameter']
  if (kind === 0n) {
    const index = expectUint64(parameter[1] ?? null, `${name}.parameter.index`)
    protocolInvariant(index >= 1n && index <= BigInt(MAX_SQL_STATEMENT_BINDINGS), 'INTEGER_OUT_OF_RANGE', `${name}.parameter.index is out of range`)
    decoded = { kind: 'index', index: Number(index) }
  } else {
    protocolInvariant(kind === 1n, 'SCHEMA_INVALID', `${name}.parameter has unknown kind`)
    const parameterName = expectString(parameter[1] ?? null, `${name}.parameter.name`)
    protocolInvariant(/^[:@$].+/u.test(parameterName), 'SCHEMA_INVALID', `${name}.parameter.name must keep its SQLite prefix`)
    decoded = { kind: 'name', name: parameterName }
  }
  return { parameter: decoded, value: sqlValueFromCanonicalCbor(tuple[1] ?? null, `${name}.value`) }
}

function parameterKey(parameter: SqlBinding['parameter']): string {
  return parameter.kind === 'index' ? `#${parameter.index}` : parameter.name
}

export function sqlStatementToCanonicalCbor(value: SqlStatement): CborValue {
  protocolInvariant(typeof value.sql === 'string' && value.sql.trim().length > 0, 'SCHEMA_INVALID', 'SQL statement source cannot be empty')
  protocolInvariant(!value.sql.includes('\0'), 'SCHEMA_INVALID', 'SQL statement source cannot contain U+0000')
  utf8(value.sql)
  protocolInvariant(value.bindings.length <= MAX_SQL_STATEMENT_BINDINGS, 'SCHEMA_INVALID', 'SQL statement has too many bindings')
  const seen = new Set<string>()
  for (const binding of value.bindings) {
    const key = parameterKey(binding.parameter)
    protocolInvariant(!seen.has(key), 'SCHEMA_INVALID', 'SQL statement binds a parameter twice')
    seen.add(key)
  }
  return integerMap([[0, value.sql], [1, value.bindings.map(bindingToCbor)]])
}

export function sqlStatementFromCanonicalCbor(value: CborValue, name = 'sql_statement'): SqlStatement {
  const map = expectMap(value, name)
  assertKnownIntegerKeys(map, [0, 1], name)
  const statement: SqlStatement = {
    sql: expectString(required(map, 0, `${name}.sql`), `${name}.sql`),
    bindings: expectArray(required(map, 1, `${name}.bindings`), `${name}.bindings`)
      .map((binding, index) => bindingFromCbor(binding, `${name}.bindings[${index}]`)),
  }
  sqlStatementToCanonicalCbor(statement)
  return statement
}

// ── Execution manifest ──────────────────────────────────────────────────────

export interface ExecutionLimits {
  /** Maximum UTF-8 bytes of one statement's SQL source. */
  readonly maxSqlBytes: number
  /** Deterministic VM-step budget for one statement. */
  readonly maxVmSteps: number
  /** Maximum bytes of any one string or BLOB value. */
  readonly maxValueBytes: number
}

/**
 * What a transaction was authored for: the exact engine build, the platform
 * code that enforces row ownership, the SQL profile and the execution limits.
 * A replica only executes transactions for the manifest it runs; changing any
 * of them is a group-wide upgrade.
 */
export interface ExecutionManifest {
  readonly version: 2
  readonly profile: string
  /** Engine build identity, e.g. the native patch profile. */
  readonly engine: string
  /** SHA-256 over the native engine descriptor. */
  readonly engineDigest: Uint8Array
  readonly programVersion: 3
  /** SHA-256 over the platform operations and the trigger and view generators. */
  readonly platformDigest: Uint8Array
  /** `PRAGMA recursive_triggers` during consensus execution; always on. */
  readonly recursiveTriggers: true
  readonly limits: ExecutionLimits
}

export const DEFAULT_EXECUTION_LIMITS: Readonly<ExecutionLimits> = Object.freeze({
  maxSqlBytes: 1_000_000,
  maxVmSteps: 1_000_000,
  maxValueBytes: 16 * 1024 * 1024,
})

export function createExecutionManifest(options: {
  readonly profile: string
  readonly engineDigest: Uint8Array
  readonly platformDigest: Uint8Array
  readonly engine?: string
  readonly limits?: Partial<ExecutionLimits>
}): ExecutionManifest {
  const manifest: ExecutionManifest = {
    version: 2,
    profile: options.profile,
    engine: options.engine ?? 'doltlite',
    engineDigest: Uint8Array.from(options.engineDigest),
    programVersion: 3,
    platformDigest: Uint8Array.from(options.platformDigest),
    recursiveTriggers: true,
    limits: { ...DEFAULT_EXECUTION_LIMITS, ...options.limits },
  }
  executionManifestToCbor(manifest)
  return manifest
}

function positiveLimit(value: number, name: string): bigint {
  protocolInvariant(Number.isSafeInteger(value) && value >= 1, 'INTEGER_OUT_OF_RANGE', `${name} must be a positive safe integer`)
  return BigInt(value)
}

export function executionManifestToCbor(value: ExecutionManifest): CborValue {
  protocolInvariant(value.version === 2 && value.programVersion === 3, 'UNSUPPORTED_VERSION', 'Unsupported execution manifest version')
  protocolInvariant(value.profile.length > 0 && value.engine.length > 0, 'SCHEMA_INVALID', 'Execution manifest needs a profile and engine')
  protocolInvariant(value.engineDigest.length === 32, 'SCHEMA_INVALID', 'Execution manifest engine digest must be 32 bytes')
  protocolInvariant(value.platformDigest.length === 32, 'SCHEMA_INVALID', 'Execution manifest platform digest must be 32 bytes')
  protocolInvariant(value.recursiveTriggers === true, 'SCHEMA_INVALID', 'Consensus execution requires recursive_triggers')
  return integerMap([
    [0, 2n],
    [1, value.profile],
    [2, value.engine],
    [3, Uint8Array.from(value.engineDigest)],
    [4, 3n],
    [5, integerMap([
      [0, positiveLimit(value.limits.maxSqlBytes, 'maxSqlBytes')],
      [1, positiveLimit(value.limits.maxVmSteps, 'maxVmSteps')],
      [2, positiveLimit(value.limits.maxValueBytes, 'maxValueBytes')],
    ])],
    [6, Uint8Array.from(value.platformDigest)],
    [7, integerMap([[0, true]])],
  ])
}

export function executionManifestFromCbor(value: CborValue): ExecutionManifest {
  const map = expectMap(value, 'execution_manifest')
  assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 5, 6, 7], 'execution_manifest')
  expectVersion(map, 2n, 'execution_manifest')
  protocolInvariant(expectUint64(required(map, 4, 'execution_manifest.program_version'), 'execution_manifest.program_version') === 3n,
    'UNSUPPORTED_VERSION', 'Unsupported program version')
  const limits = expectMap(required(map, 5, 'execution_manifest.limits'), 'execution_manifest.limits')
  assertKnownIntegerKeys(limits, [0, 1, 2], 'execution_manifest.limits')
  const limit = (key: number, name: string): number => {
    const parsed = expectUint64(required(limits, key, name), name)
    protocolInvariant(parsed >= 1n && parsed <= BigInt(Number.MAX_SAFE_INTEGER), 'INTEGER_OUT_OF_RANGE', `${name} is out of range`)
    return Number(parsed)
  }
  const sqlProfile = expectMap(required(map, 7, 'execution_manifest.sql_profile'), 'execution_manifest.sql_profile')
  assertKnownIntegerKeys(sqlProfile, [0], 'execution_manifest.sql_profile')
  protocolInvariant(required(sqlProfile, 0, 'execution_manifest.sql_profile.recursive_triggers') === true,
    'SCHEMA_INVALID', 'Consensus execution requires recursive_triggers')
  const manifest: ExecutionManifest = {
    version: 2,
    profile: expectString(required(map, 1, 'execution_manifest.profile'), 'execution_manifest.profile'),
    engine: expectString(required(map, 2, 'execution_manifest.engine'), 'execution_manifest.engine'),
    engineDigest: Uint8Array.from(expectBytes(required(map, 3, 'execution_manifest.engine_digest'), 'execution_manifest.engine_digest', 32)),
    programVersion: 3,
    platformDigest: Uint8Array.from(expectBytes(required(map, 6, 'execution_manifest.platform_digest'), 'execution_manifest.platform_digest', 32)),
    recursiveTriggers: true,
    limits: {
      maxSqlBytes: limit(0, 'execution_manifest.limits.max_sql_bytes'),
      maxVmSteps: limit(1, 'execution_manifest.limits.max_vm_steps'),
      maxValueBytes: limit(2, 'execution_manifest.limits.max_value_bytes'),
    },
  }
  executionManifestToCbor(manifest)
  return manifest
}
export function encodeExecutionManifest(value: ExecutionManifest): Uint8Array {
  return encodeCanonicalCbor(executionManifestToCbor(value))
}

export function decodeExecutionManifest(bytes: Uint8Array): ExecutionManifest {
  return executionManifestFromCbor(assertCanonicalCbor(bytes))
}

export async function digestExecutionManifest(value: ExecutionManifest): Promise<Uint8Array> {
  return hashDomain('executionManifest', encodeExecutionManifest(value))
}

export interface ManifestArtifacts {
  readonly executionManifestDigest: Uint8Array
  readonly canonicalExecutionManifest: Uint8Array
}

export async function executionManifestArtifacts(value: ExecutionManifest): Promise<ManifestArtifacts> {
  return {
    executionManifestDigest: await digestExecutionManifest(value),
    canonicalExecutionManifest: encodeExecutionManifest(value),
  }
}

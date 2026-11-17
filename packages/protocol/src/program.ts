import { assertCanonicalCbor, encodeCanonicalCbor, type CborValue } from './cbor.js'
import { utf8 } from './bytes.js'
import { protocolInvariant } from './errors.js'
import { isPlatformOp, platformOpFromCanonicalCbor, platformOpToCanonicalCbor, type PlatformOp } from './platform.js'
import { assertKnownIntegerKeys, expectArray, expectMap, expectString, expectUint64, expectVersion, integerMap, required } from './schema.js'
import { sqlStatement, sqlStatementFromCanonicalCbor, sqlStatementToCanonicalCbor, type SqlStatement } from './sql.js'

export type EventPayload = null | boolean | number | string | readonly EventPayload[] | { readonly [key: string]: EventPayload }
export interface EmitStep { readonly op: 'emit'; readonly topic: string; readonly payload: EventPayload }
/** One signed program, one outcome, and one atomic SQL/event visibility boundary. */
export type ProgramStep = SqlStatement | PlatformOp | EmitStep
export interface ChangeProgram { readonly version: 3; readonly steps: readonly ProgramStep[] }

export const MAX_PROGRAM_STEPS = 256
export const MAX_PROGRAM_BYTES = 262_144
export const MAX_PROGRAM_EVENTS = 64
export const MAX_EVENT_BYTES = 16_384
export const MAX_TOPIC_BYTES = 128

export function assertEventTopic(topic: string): void {
  protocolInvariant(typeof topic === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(topic) && utf8(topic).length <= MAX_TOPIC_BYTES,
    'SCHEMA_INVALID', 'Event topic must be a bounded application label')
}

/** Bounded canonical JSON, shared by event bodies and public application metadata. */
export function canonicalJson(payload: EventPayload, limits: { readonly maxBytes: number; readonly maxNodes: number; readonly maxDepth: number }): string {
  for (const bound of [limits.maxBytes, limits.maxNodes, limits.maxDepth]) protocolInvariant(Number.isSafeInteger(bound) && bound > 0, 'SCHEMA_INVALID', 'Invalid JSON limits')
  let nodes = 0
  const visit = (value: EventPayload, depth: number): string => {
    protocolInvariant(depth <= limits.maxDepth && ++nodes <= limits.maxNodes, 'SCHEMA_INVALID', 'JSON payload is too complex')
    if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
    if (typeof value === 'number') {
      protocolInvariant(Number.isFinite(value), 'SCHEMA_INVALID', 'Event numbers must be finite')
      return JSON.stringify(value)
    }
    if (Array.isArray(value)) {
      protocolInvariant(Reflect.ownKeys(value).length === value.length + 1, 'SCHEMA_INVALID', 'Event arrays cannot carry extra properties')
      const entries: string[] = []
      for (let i = 0; i < value.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, i)
        protocolInvariant(descriptor !== undefined && 'value' in descriptor && descriptor.enumerable === true,
          'SCHEMA_INVALID', 'Event arrays require dense data elements')
        entries.push(visit(descriptor.value as EventPayload, depth + 1))
      }
      return `[${entries.join(',')}]`
    }
    protocolInvariant(typeof value === 'object' && value !== null &&
      (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null),
    'SCHEMA_INVALID', 'Event payload must contain JSON values')
    protocolInvariant(Reflect.ownKeys(value).length === Object.keys(value).length, 'SCHEMA_INVALID', 'Event objects require enumerable string keys')
    return `{${Object.keys(value).sort().map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)!
      protocolInvariant('value' in descriptor, 'SCHEMA_INVALID', 'Event payload cannot contain accessors')
      return `${JSON.stringify(key)}:${visit(descriptor.value as EventPayload, depth + 1)}`
    }).join(',')}}`
  }
  const encoded = visit(payload, 0)
  protocolInvariant(utf8(encoded).length <= limits.maxBytes, 'SCHEMA_INVALID', 'JSON payload is too large')
  return encoded
}

/** Canonical JSON embedded in canonical CBOR; rejects lossy/non-JSON inputs. */
export function canonicalEventPayload(payload: EventPayload): string {
  return canonicalJson(payload, { maxBytes: MAX_EVENT_BYTES, maxNodes: 4096, maxDepth: 32 })
}

export function emit(topic: string, payload: EventPayload): EmitStep {
  assertEventTopic(topic)
  return { op: 'emit', topic, payload: JSON.parse(canonicalEventPayload(payload)) as EventPayload }
}
export function isEmitStep(step: unknown): step is EmitStep {
  return typeof step === 'object' && step !== null && 'op' in step && step.op === 'emit'
}
export function isSqlStatementStep(step: ProgramStep): step is SqlStatement { return !isPlatformOp(step) && !isEmitStep(step) }

export function program(...steps: readonly (ProgramStep | string)[]): ChangeProgram {
  const result: ChangeProgram = { version: 3, steps: steps.map((step) => typeof step === 'string' ? sqlStatement(step) : step) }
  assertValidChangeProgram(result)
  return result
}

function stepToCbor(step: ProgramStep): CborValue {
  if (isEmitStep(step)) {
    protocolInvariant(Object.keys(step).every((key) => ['op', 'topic', 'payload'].includes(key)), 'SCHEMA_INVALID', 'Unknown emit field')
    assertEventTopic(step.topic)
    return [2n, step.topic, canonicalEventPayload(step.payload)]
  }
  return isPlatformOp(step) ? [1n, platformOpToCanonicalCbor(step)] : [0n, sqlStatementToCanonicalCbor(step)]
}
function stepFromCbor(value: CborValue, name: string): ProgramStep {
  const tuple = expectArray(value, name)
  const kind = expectUint64(tuple[0] ?? null, `${name}.kind`)
  if (kind === 2n) {
    protocolInvariant(tuple.length === 3, 'SCHEMA_INVALID', `${name} has invalid arity`)
    const encoded = expectString(tuple[2] ?? null, `${name}.payload`)
    protocolInvariant(utf8(encoded).length <= MAX_EVENT_BYTES, 'SCHEMA_INVALID', 'Event payload is too large')
    let payload: EventPayload
    try { payload = JSON.parse(encoded) as EventPayload } catch { throw new Error('EVENT_PAYLOAD_INVALID') }
    protocolInvariant(canonicalEventPayload(payload) === encoded, 'SCHEMA_INVALID', 'Event payload must be canonical')
    return emit(expectString(tuple[1] ?? null, `${name}.topic`), payload)
  }
  protocolInvariant(tuple.length === 2, 'SCHEMA_INVALID', `${name} has invalid arity`)
  if (kind === 0n) return sqlStatementFromCanonicalCbor(tuple[1] ?? null, `${name}.statement`)
  protocolInvariant(kind === 1n, 'SCHEMA_INVALID', `${name} has an unknown kind`)
  return platformOpFromCanonicalCbor(tuple[1] ?? null, `${name}.platform_op`)
}

export function assertValidChangeProgram(value: ChangeProgram): void {
  protocolInvariant(value.version === 3, 'UNSUPPORTED_VERSION', 'Unsupported change program version')
  protocolInvariant(Array.isArray(value.steps) && value.steps.length > 0 && value.steps.length <= MAX_PROGRAM_STEPS,
    'SCHEMA_INVALID', 'Change program requires a bounded nonempty step list')
  protocolInvariant(value.steps.filter(isEmitStep).length <= MAX_PROGRAM_EVENTS, 'SCHEMA_INVALID', 'Too many emitted events')
  protocolInvariant(encodeCanonicalCbor(value.steps.map(stepToCbor)).length <= MAX_PROGRAM_BYTES,
    'SCHEMA_INVALID', 'Change program is too large')
}
export function changeProgramToCanonicalCbor(value: ChangeProgram): CborValue {
  assertValidChangeProgram(value)
  return integerMap([[0, 3n], [1, value.steps.map(stepToCbor)]])
}
export function changeProgramFromCanonicalCbor(value: CborValue): ChangeProgram {
  const map = expectMap(value, 'change_program')
  assertKnownIntegerKeys(map, [0, 1], 'change_program')
  expectVersion(map, 3n, 'change_program')
  const result: ChangeProgram = { version: 3, steps: expectArray(required(map, 1, 'change_program.steps'), 'change_program.steps')
    .map((step, index) => stepFromCbor(step, `change_program.steps[${index}]`)) }
  assertValidChangeProgram(result)
  return result
}
export function encodeChangeProgram(value: ChangeProgram): Uint8Array { return encodeCanonicalCbor(changeProgramToCanonicalCbor(value)) }
export function decodeChangeProgram(bytes: Uint8Array): ChangeProgram { return changeProgramFromCanonicalCbor(assertCanonicalCbor(bytes)) }

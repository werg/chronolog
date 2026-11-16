import { assertEventTopic, assertValidChangeProgram, bytesToHex, equalBytes, isEmitStep, type ChangeProgram } from '@chronolog/protocol'
import { isCapabilityActive } from './reducer.js'
import type { CapabilityGrant, CapabilitySnapshot } from './types.js'

export type ProgramRights = NonNullable<CapabilityGrant['program']>
export function normalizeProgramRights(value?: ProgramRights): Required<ProgramRights> {
  if (value === undefined) return { sql: true, topics: [], signals: [], forwarded: false }
  if (typeof value.sql !== 'boolean' || (value.forwarded !== undefined && typeof value.forwarded !== 'boolean')) throw new Error('PROGRAM_RIGHTS_INVALID')
  const topics = (items: readonly string[]): readonly string[] => {
    const input: unknown = items
    if (!Array.isArray(input) || items.length > 128 || new Set(items).size !== items.length) throw new Error('PROGRAM_RIGHTS_INVALID')
    items.forEach((topic) => { if (topic !== '*') assertEventTopic(topic) })
    return [...items].sort()
  }
  return { sql: value.sql, topics: topics(value.topics), signals: topics(value.signals), forwarded: value.forwarded ?? false }
}
export function programRightsSubset(granted?: ProgramRights, requested?: ProgramRights): boolean {
  const next = normalizeProgramRights(granted), allowed = normalizeProgramRights(requested)
  return (!next.sql || allowed.sql) && (!next.forwarded || allowed.forwarded) &&
    next.topics.every((topic) => allowed.topics.includes('*') || allowed.topics.includes(topic)) &&
    next.signals.every((topic) => allowed.signals.includes('*') || allowed.signals.includes(topic))
}

/** Every step must fit one exact writer grant; rights are never pooled. */
export function programAllowed(grant: CapabilityGrant, program: ChangeProgram): boolean {
  if (grant.role !== 'writer') return false
  assertValidChangeProgram(program)
  const rights = grant.program
  return program.steps.every((step) => isEmitStep(step)
    ? rights !== undefined && (rights.topics.includes('*') || rights.topics.includes(step.topic))
    : rights?.sql !== false)
}

/** Signals use the active grant, independent of SQL and durable event rights. */
export function signalAllowed(snapshot: CapabilitySnapshot, input: {
  readonly capabilityId: Uint8Array; readonly signer: Uint8Array; readonly topic: string
}): boolean {
  const capability = snapshot.capabilities.get(bytesToHex(input.capabilityId))
  const rights = capability?.grant.program
  return capability !== undefined && capability.grant.role === 'writer' &&
    isCapabilityActive(capability, snapshot.revision) && equalBytes(capability.grant.signingPublicKey, input.signer) &&
    rights !== undefined && (rights.signals.includes('*') || rights.signals.includes(input.topic))
}

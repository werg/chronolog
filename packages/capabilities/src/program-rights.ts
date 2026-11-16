import { assertValidChangeProgram, bytesToHex, equalBytes, isEmitStep, type ChangeProgram } from '@chronolog/protocol'
import { isCapabilityActive } from './reducer.js'
import type { CapabilityGrant, CapabilitySnapshot } from './types.js'

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

import { bytesToHex, compareBytes, protocolInvariant } from '@chronolog/protocol'
import type { PolicyEvaluation, ValidationPolicy, ValidatorEvidence } from './types.js'

/**
 * A policy is satisfied by `minimumValidators` distinct validator
 * capabilities. The proof is the lexicographically smallest such set of
 * capability ids, so every replica selects the same one.
 */
export function evaluateValidationPolicy(
  policy: ValidationPolicy,
  evidence: readonly ValidatorEvidence[],
): PolicyEvaluation {
  protocolInvariant(policy.minimumValidators > 0n, 'SCHEMA_INVALID', 'Validation threshold must be positive')
  const unique = new Map<string, ValidatorEvidence>()
  const canonical = [...evidence].sort((left, right) =>
    compareBytes(left.capabilityId, right.capabilityId) || compareBytes(left.validatorId, right.validatorId))
  for (const item of canonical) {
    const key = bytesToHex(item.capabilityId)
    if (!unique.has(key)) unique.set(key, item)
  }
  const sorted = [...unique.values()]
  if (BigInt(sorted.length) < policy.minimumValidators) {
    return { satisfied: false, selected: [], missing: [`validators:${policy.minimumValidators - BigInt(sorted.length)}`] }
  }
  return { satisfied: true, selected: sorted.slice(0, Number(policy.minimumValidators)), missing: [] }
}

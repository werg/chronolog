import { bytesToHex, compareBytes, protocolInvariant } from '@chronolog/protocol'
import type { PolicyEvaluation, ValidationPolicy, ValidatorEvidence } from './types.js'

/**
 * A policy is satisfied by `minimumValidators` distinct validator signing
 * keys. Verified snapshots authorize one active capability per key. Select
 * the lexicographically smallest capability IDs and defensively deduplicate
 * both keys and grants, so raw evidence cannot multiply a validator's votes.
 */
export function evaluateValidationPolicy(
  policy: ValidationPolicy,
  evidence: readonly ValidatorEvidence[],
): PolicyEvaluation {
  protocolInvariant(policy.minimumValidators > 0n, 'SCHEMA_INVALID', 'Validation threshold must be positive')
  const unique = new Map<string, ValidatorEvidence>()
  const validators = new Set<string>()
  const canonical = [...evidence].sort((left, right) =>
    compareBytes(left.capabilityId, right.capabilityId) || compareBytes(left.validatorId, right.validatorId))
  for (const item of canonical) {
    const key = bytesToHex(item.capabilityId)
    const validatorId = bytesToHex(item.validatorId)
    if (unique.has(key) || validators.has(validatorId)) continue
    unique.set(key, item)
    validators.add(validatorId)
  }
  const sorted = [...unique.values()]
  if (BigInt(sorted.length) < policy.minimumValidators) {
    return { satisfied: false, selected: [], missing: [`validators:${policy.minimumValidators - BigInt(sorted.length)}`] }
  }
  return { satisfied: true, selected: sorted.slice(0, Number(policy.minimumValidators)), missing: [] }
}

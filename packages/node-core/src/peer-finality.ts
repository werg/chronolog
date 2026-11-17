import type { ControlStore, StoredAttestation, StoredCandidate, WatermarkPolicy } from '@chronolog/control-store/browser'
import { bytesToHex, equalBytes, type TransactionCore } from '@chronolog/protocol'

import type { LiveFinalityBlocker, LiveFinalityExclusion, LiveFinalityFrontier } from './finality.js'
import type { AdmissionScope, ClosedAdmissionRevision, MembershipResolver } from './types.js'

/** One verified admission/exclusion evaluation for peer replay and diagnostics. */
export async function evaluatePeerLiveFinality(options: {
  readonly groupId: Uint8Array
  readonly initialMembershipRevision: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly membership: MembershipResolver
  readonly control: ControlStore
  readonly candidateCores: ReadonlyMap<string, TransactionCore>
  readonly verifiedHeartbeatIds: ReadonlySet<string>
  readonly closedRevisions: readonly ClosedAdmissionRevision[]
  readonly isPrefixApplied: (author: string, sequence: bigint) => boolean
  readonly eligibleAttestations: (candidate: StoredCandidate, core: TransactionCore) => Promise<readonly StoredAttestation[]>
}): Promise<LiveFinalityFrontier> {
  const { control, membership, candidateCores, verifiedHeartbeatIds } = options
  const empty: LiveFinalityFrontier = {
    mode: 'live', provenThroughMs: null, closedThroughMs: null, blockers: [], exclusions: [],
  }
  // Completeness comes from authenticated membership activation, never from
  // whichever proposals happened to arrive. An unseen easier policy or open
  // intermediate revision can still admit an earlier transaction.
  const scopes = structuredClone(await membership.admissionScopes?.({ groupId: options.groupId.slice() }) ?? null)
  if (scopes === null || scopes.length === 0 ||
      !equalBytes(scopes[0]!.membershipRevision, options.initialMembershipRevision) ||
      !equalBytes(scopes.at(-1)!.membershipRevision, options.membershipRevision)) return empty
  const indexedScopes = new Map<string, AdmissionScope>()
  let previousBound = -1n
  for (const scope of scopes) {
    const key = bytesToHex(scope.membershipRevision)
    if (scope.membershipRevision.length !== 32 || indexedScopes.has(key) || typeof scope.authorTimeAfterMs !== 'bigint' ||
        scope.authorTimeAfterMs < previousBound || (indexedScopes.size === 0 && scope.authorTimeAfterMs !== -1n) ||
        scope.policies.length === 0 || new Set(scope.policies.map(policy => policy.policyId)).size !== scope.policies.length ||
        scope.policies.some(policy => !validWatermarkPolicy(policy))) return empty
    indexedScopes.set(key, scope)
    previousBound = scope.authorTimeAfterMs
  }

  // A signed old-revision closure names its successor. Cross-check the same
  // activation and floor used for authorization before retiring an old scope.
  // Its complete feed prefixes and candidate bodies must also be consumed.
  const closed = new Set<string>(), declaredClosures = new Set<string>()
  for (const revision of options.closedRevisions) {
    const key = bytesToHex(revision.membershipRevision)
    const index = scopes.findIndex(scope => equalBytes(scope.membershipRevision, revision.membershipRevision))
    const scope = scopes[index], successor = scopes[index + 1]
    if (declaredClosures.has(key) || scope === undefined || successor === undefined || revision.closedThroughMs < 0n ||
        revision.closedThroughMs < scope.authorTimeAfterMs || !equalBytes(revision.nextMembershipRevision, successor.membershipRevision) ||
        revision.closedThroughMs !== successor.authorTimeAfterMs) throw new Error('PEER_FINALITY_ACTIVATION_CONFLICT')
    declaredClosures.add(key)
    if (revision.proposalIds.every(id => candidateCores.has(bytesToHex(id)) && control.getCandidate(id) !== null) &&
        revision.feedPrefixes.every(prefix => options.isPrefixApplied(prefix.author, prefix.throughSequence))) closed.add(key)
  }

  // Every open revision and every policy it permits contributes a boundary.
  // Its authenticated activation floor can close old work before its first
  // heartbeat; a closed revision never lifts some other open revision's proof.
  let provenThroughMs: bigint | null = null
  for (const scope of scopes) {
    if (closed.has(bytesToHex(scope.membershipRevision))) continue
    let policyCutoff: bigint | null = null
    for (const policy of scope.policies) {
      const cutoff = control.watermark(policy, scope.membershipRevision, verifiedHeartbeatIds).cutoffMs
      if (cutoff === null) { policyCutoff = null; break }
      if (policyCutoff === null || cutoff < policyCutoff) policyCutoff = cutoff
    }
    const cutoff = policyCutoff !== null && policyCutoff > scope.authorTimeAfterMs ? policyCutoff : scope.authorTimeAfterMs
    if (provenThroughMs === null || cutoff < provenThroughMs) provenThroughMs = cutoff
  }
  if (provenThroughMs !== null && provenThroughMs < 0n) provenThroughMs = null

  const blockers: LiveFinalityBlocker[] = [], exclusions: LiveFinalityExclusion[] = []
  const candidates = control.listCandidates().filter(candidate =>
    candidate.state === 'pending_validation' || candidate.state === 'provisional' || candidate.state === 'admissible')
  for (const candidate of candidates) {
    const core = candidateCores.get(bytesToHex(candidate.txId))
    if (core === undefined) {
      blockers.push({ proposalId: candidate.txId, authorTimestampMs: candidate.orderKey.authorTimestampMs,
        reason: 'missing-candidate', attestationIds: control.attestationsFor(candidate.txId).map(proof => proof.attestationId) })
      continue
    }
    const scope = indexedScopes.get(bytesToHex(core.membershipRevision))
    const policy = await membership.watermarkPolicy?.(core)
    if (scope === undefined || policy == null || !scope.policies.some(declared => sameWatermarkPolicy(declared, policy))) return empty
    if (core.authorTimestampMs <= scope.authorTimeAfterMs) {
      // A custom resolver must not authorize a successor before its proved
      // activation. Silently finalizing it would hide a broken contract.
      throw new Error('PEER_FINALITY_ACTIVATION_CONFLICT')
    }
    if (candidate.state === 'admissible') continue
    const attestations = await options.eligibleAttestations(candidate, core)
    let exclusion: LiveFinalityExclusion['reason'] | null = null
    if (membership.selectAdmission === undefined || membership.canStillAdmit !== undefined) {
      const open = closed.has(bytesToHex(core.membershipRevision)) ? [] : policy.validatorIds.filter(validatorId => {
        const heartbeat = control.heartbeatFor(validatorId, core.membershipRevision)
        return heartbeat?.feedContiguous !== true || !verifiedHeartbeatIds.has(bytesToHex(heartbeat.heartbeatId)) ||
          heartbeat.acceptanceCutoffMs < core.authorTimestampMs
      })
      const context = {
        groupId: core.groupId, membershipRevision: core.membershipRevision, validationPolicy: core.validationPolicy,
        writerId: core.authorId, authorTimestampMs: core.authorTimestampMs, program: core.program,
        ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
      }
      const possibleWith = async (openValidatorIds: readonly Uint8Array[]): Promise<boolean> => {
        if (membership.canStillAdmit !== undefined) return membership.canStillAdmit(context, { attestations, openValidatorIds })
        const threshold = await membership.threshold(context)
        if (!Number.isSafeInteger(threshold) || threshold < 1) throw new Error('INVALID_VALIDATION_THRESHOLD')
        return new Set([...attestations.map(proof => bytesToHex(proof.validatorId)), ...openValidatorIds.map(bytesToHex)]).size >= threshold
      }
      if (!await possibleWith(open)) exclusion = await possibleWith(policy.validatorIds) ? 'FINALITY_TIMESTAMP_CLOSED' : 'ADMISSION_IMPOSSIBLE'
    }
    if (exclusion !== null) exclusions.push({ proposalId: candidate.txId, reason: exclusion })
    else blockers.push({ proposalId: candidate.txId, authorTimestampMs: core.authorTimestampMs,
      reason: 'pending-admission', attestationIds: attestations.map(proof => proof.attestationId) })
  }

  const unknownByProposal = new Map<string, LiveFinalityBlocker>()
  for (const proof of control.unresolvedAttestations()) {
    const scope = indexedScopes.get(bytesToHex(proof.membershipRevision))
    if (scope === undefined) return empty
    if (proof.authorTimestampMs <= scope.authorTimeAfterMs) continue
    const key = bytesToHex(proof.txId), prior = unknownByProposal.get(key)
    unknownByProposal.set(key, { proposalId: proof.txId,
      authorTimestampMs: prior === undefined || proof.authorTimestampMs < prior.authorTimestampMs ? proof.authorTimestampMs : prior.authorTimestampMs,
      reason: 'missing-candidate', attestationIds: [...prior?.attestationIds ?? [], proof.attestationId] })
  }
  blockers.push(...unknownByProposal.values())
  blockers.sort((left, right) => left.authorTimestampMs === right.authorTimestampMs
    ? bytesToHex(left.proposalId).localeCompare(bytesToHex(right.proposalId)) : left.authorTimestampMs < right.authorTimestampMs ? -1 : 1)
  let closedThroughMs = provenThroughMs
  for (const blocker of blockers) {
    if (closedThroughMs !== null && blocker.authorTimestampMs <= closedThroughMs) {
      closedThroughMs = blocker.authorTimestampMs === 0n ? null : blocker.authorTimestampMs - 1n
    }
  }
  return { mode: 'live', provenThroughMs, closedThroughMs, blockers, exclusions }
}

function validWatermarkPolicy(policy: WatermarkPolicy): boolean {
  return policy.kind === 'threshold' && typeof policy.policyId === 'string' && policy.policyId.length > 0 &&
    Number.isSafeInteger(policy.threshold) && policy.threshold > 0 && policy.threshold <= policy.validatorIds.length &&
    policy.validatorIds.every(id => id.length === 32) && new Set(policy.validatorIds.map(bytesToHex)).size === policy.validatorIds.length
}

function sameWatermarkPolicy(left: WatermarkPolicy, right: WatermarkPolicy): boolean {
  return left.kind === right.kind && left.policyId === right.policyId && left.threshold === right.threshold &&
    left.validatorIds.length === right.validatorIds.length &&
    left.validatorIds.every(id => right.validatorIds.some(other => equalBytes(id, other)))
}

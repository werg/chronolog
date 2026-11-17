import type { ControlStore, StoredAttestation, StoredCandidate, WatermarkPolicy } from '@chronolog/control-store/browser'
import { bytesToHex, equalBytes, type TransactionCore } from '@chronolog/protocol'

import type { LiveFinalityFrontier } from './finality.js'
import type { AdmissionScope, ClosedAdmissionRevision, MembershipResolver } from './types.js'

/** Normalize verified peer admission evidence into the live timestamp contract. */
export async function evaluatePeerLiveFinality(options: {
  readonly groupId: Uint8Array
  readonly membership: MembershipResolver
  readonly control: ControlStore
  readonly candidateCores: ReadonlyMap<string, TransactionCore>
  readonly verifiedHeartbeatIds: ReadonlySet<string>
  readonly closedRevisions: readonly ClosedAdmissionRevision[]
  readonly isPrefixApplied: (author: string, sequence: bigint) => boolean
  readonly isValidAdmissionProof: (candidate: StoredCandidate, core: TransactionCore, proof: StoredAttestation) => Promise<boolean>
}): Promise<LiveFinalityFrontier> {
  const empty: LiveFinalityFrontier = {
    mode: 'live', provenThroughMs: null, closedThroughMs: null, blockers: [], excludedProposalIds: [],
  }
  // The authority adapter supplies completeness. Locally encountered proposals
  // cannot reveal an unseen easier policy or an intermediate open revision.
  const scopes = structuredClone(await options.membership.admissionScopes?.({ groupId: options.groupId.slice() }) ?? null)
  if (scopes === null || scopes.length === 0) return empty
  const indexedScopes = new Map<string, AdmissionScope>()
  let previousBound = -1n
  for (const scope of scopes) {
    const key = bytesToHex(scope.membershipRevision)
    if (indexedScopes.has(key) || typeof scope.authorTimeAfterMs !== 'bigint' || scope.authorTimeAfterMs < previousBound ||
        (indexedScopes.size === 0 && scope.authorTimeAfterMs !== -1n) || scope.policies.length === 0 ||
        new Set(scope.policies.map(policy => policy.policyId)).size !== scope.policies.length ||
        scope.policies.some(policy => !validWatermarkPolicy(policy))) return empty
    indexedScopes.set(key, scope)
    previousBound = scope.authorTimeAfterMs
  }
  if (new Set(options.closedRevisions.map(revision => bytesToHex(revision.membershipRevision))).size !== options.closedRevisions.length ||
      options.closedRevisions.some(revision => !indexedScopes.has(bytesToHex(revision.membershipRevision)) || revision.closedThroughMs < 0n ||
        revision.closedThroughMs < indexedScopes.get(bytesToHex(revision.membershipRevision))!.authorTimeAfterMs)) return empty
  const closed = options.closedRevisions.filter(revision =>
    revision.proposalIds.every(id => options.candidateCores.has(bytesToHex(id)) &&
      options.control.getCandidate(id) !== null) &&
    revision.feedPrefixes.every(prefix => options.isPrefixApplied(prefix.author, prefix.throughSequence)))
  const closedMembershipRevisions = new Set(closed.map(revision => bytesToHex(revision.membershipRevision)))
  const candidates = options.control.listCandidates().filter(candidate =>
    candidate.state === 'pending_validation' || candidate.state === 'provisional' || candidate.state === 'admissible')

  // A stricter policy's blocking set cannot close an easier policy. Similarly,
  // a newer membership revision cannot silently retire an older open revision.
  let provenThroughMs: bigint | null = null
  for (const scope of scopes) {
    if (closedMembershipRevisions.has(bytesToHex(scope.membershipRevision))) continue
    let policyCutoff: bigint | null = null
    for (const policy of scope.policies) {
      const cutoff = options.control.watermark(policy, scope.membershipRevision, options.verifiedHeartbeatIds).cutoffMs
      if (cutoff === null) { policyCutoff = null; break }
      if (policyCutoff === null || cutoff < policyCutoff) policyCutoff = cutoff
    }
    const cutoff = policyCutoff !== null && policyCutoff > scope.authorTimeAfterMs ? policyCutoff : scope.authorTimeAfterMs
    if (provenThroughMs === null || cutoff < provenThroughMs) provenThroughMs = cutoff
  }
  // A fully closed history has no remaining admission scope. A closed revision
  // never lifts the cutoff of some other revision which can still admit.
  if (closedMembershipRevisions.size === scopes.length) for (const revision of closed) {
    if (provenThroughMs === null || revision.closedThroughMs > provenThroughMs) provenThroughMs = revision.closedThroughMs
  }
  if (provenThroughMs !== null && provenThroughMs < 0n) provenThroughMs = null

  const verifiedAttestationIds = new Set<string>()
  const candidatePolicies = new Map<string, { policy: WatermarkPolicy; membershipRevision: Uint8Array }>()
  for (const candidate of candidates) {
    const key = bytesToHex(candidate.txId), core = options.candidateCores.get(key)
    if (core === undefined) return empty
    const scope = indexedScopes.get(bytesToHex(core.membershipRevision))
    const policy = await options.membership.watermarkPolicy?.(core)
    if (scope === undefined || policy === undefined || policy === null ||
        !scope.policies.some(declared => sameWatermarkPolicy(declared, policy))) return empty
    if (candidate.state !== 'pending_validation' && candidate.state !== 'provisional') continue
    candidatePolicies.set(key, { policy, membershipRevision: core.membershipRevision })
    for (const proof of options.control.attestationsFor(candidate.txId)) {
      if (await options.isValidAdmissionProof(candidate, core, proof)) verifiedAttestationIds.add(bytesToHex(proof.attestationId))
    }
  }
  // Complete scopes prove the global bound. Each unresolved proposal still
  // uses its own verified policy; no representative policy supplies a fallback.
  return { mode: 'live', ...options.control.admissionFrontier(null, undefined, {
    provenThroughMs, candidatePolicies, verifiedAttestationIds,
    verifiedHeartbeatIds: options.verifiedHeartbeatIds, closedMembershipRevisions,
  }) }
}

function validWatermarkPolicy(policy: WatermarkPolicy): boolean {
  return policy.kind === 'threshold' && typeof policy.policyId === 'string' && policy.policyId.length > 0 &&
    Number.isSafeInteger(policy.threshold) && policy.threshold > 0 && policy.threshold <= policy.validatorIds.length &&
    new Set(policy.validatorIds.map(bytesToHex)).size === policy.validatorIds.length
}

function sameWatermarkPolicy(left: WatermarkPolicy, right: WatermarkPolicy): boolean {
  return left.kind === right.kind && left.policyId === right.policyId && left.threshold === right.threshold &&
    left.validatorIds.length === right.validatorIds.length &&
    left.validatorIds.every(id => right.validatorIds.some(other => equalBytes(id, other)))
}

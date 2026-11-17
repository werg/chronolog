import type { ControlStore, StoredAttestation, StoredCandidate, WatermarkPolicy } from '@chronolog/control-store/browser'
import { bytesToHex, type TransactionCore } from '@chronolog/protocol'

import type { LiveFinalityFrontier } from './finality.js'
import type { ClosedAdmissionRevision, MembershipResolver } from './types.js'

/** Normalize verified peer admission evidence into the live timestamp contract. */
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
  readonly isValidAdmissionProof: (candidate: StoredCandidate, core: TransactionCore, proof: StoredAttestation) => Promise<boolean>
}): Promise<LiveFinalityFrontier> {
  const empty: LiveFinalityFrontier = {
    mode: 'live', provenThroughMs: null, closedThroughMs: null, blockers: [], excludedProposalIds: [],
  }
  const closed = options.closedRevisions.filter(revision =>
    revision.proposalIds.every(id => options.candidateCores.has(bytesToHex(id))) &&
    revision.feedPrefixes.every(prefix => options.isPrefixApplied(prefix.author, prefix.throughSequence)))
  const closedMembershipRevisions = new Set(closed.map(revision => bytesToHex(revision.membershipRevision)))
  const revisions = new Map([
    [bytesToHex(options.initialMembershipRevision), options.initialMembershipRevision],
    [bytesToHex(options.membershipRevision), options.membershipRevision],
  ])
  const candidates = options.control.listCandidates().filter(candidate =>
    candidate.state === 'pending_validation' || candidate.state === 'provisional' || candidate.state === 'admissible')
  for (const candidate of candidates) {
    const core = options.candidateCores.get(bytesToHex(candidate.txId))
    if (core !== undefined) revisions.set(bytesToHex(core.membershipRevision), core.membershipRevision)
  }

  // A stricter policy's blocking set cannot close an easier policy. Similarly,
  // a newer membership revision cannot silently retire an older open revision.
  let representative: WatermarkPolicy | undefined
  let heartbeatFrontier: bigint | null | undefined
  for (const [key, membershipRevision] of revisions) {
    const policies = await options.membership.liveFinalityPolicies?.({ groupId: options.groupId, membershipRevision })
    if (policies === undefined || policies === null || policies.length === 0) return empty
    representative ??= policies[0]
    if (closedMembershipRevisions.has(key)) continue
    for (const policy of policies) {
      const cutoff = options.control.watermark(policy, membershipRevision, options.verifiedHeartbeatIds).cutoffMs
      heartbeatFrontier = heartbeatFrontier === null || cutoff === null ? null
        : heartbeatFrontier === undefined || cutoff < heartbeatFrontier ? cutoff : heartbeatFrontier
    }
  }
  if (representative === undefined) return empty
  let provenThroughMs = heartbeatFrontier ?? null
  for (const revision of closed) {
    if (provenThroughMs === null || revision.closedThroughMs > provenThroughMs) provenThroughMs = revision.closedThroughMs
  }

  const verifiedAttestationIds = new Set<string>()
  const candidatePolicies = new Map<string, { policy: WatermarkPolicy; membershipRevision: Uint8Array }>()
  for (const candidate of candidates) {
    if (candidate.state !== 'pending_validation' && candidate.state !== 'provisional') continue
    const key = bytesToHex(candidate.txId), core = options.candidateCores.get(key)
    if (core === undefined) continue
    const policy = await options.membership.watermarkPolicy?.(core)
    if (policy === undefined || policy === null) continue
    candidatePolicies.set(key, { policy, membershipRevision: core.membershipRevision })
    for (const proof of options.control.attestationsFor(candidate.txId)) {
      if (await options.isValidAdmissionProof(candidate, core, proof)) verifiedAttestationIds.add(bytesToHex(proof.attestationId))
    }
  }
  return { mode: 'live', ...options.control.admissionFrontier(representative, options.membershipRevision, {
    provenThroughMs, candidatePolicies, verifiedAttestationIds,
    verifiedHeartbeatIds: options.verifiedHeartbeatIds, closedMembershipRevisions,
  }) }
}

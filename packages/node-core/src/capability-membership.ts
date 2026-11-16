import {
  evaluateValidationPolicy,
  isCapabilityActive,
  programAllowed,
  type CapabilitySnapshot,
  type EffectiveCapability,
  type ValidatorEvidence,
} from '@chronolog/capabilities'
import type { StoredAttestation, WatermarkPolicy } from '@chronolog/control-store'
import { bytesToHex, equalBytes, type TransactionCore } from '@chronolog/protocol'

import type {
  CandidateAdmissionContext,
  MembershipResolver,
  TransportAuthorContext,
  ValidatorAuthorityContext,
} from './types.js'

export interface CapabilityMembershipResolverOptions {
  readonly snapshotForRevision: (
    revisionDigest: Uint8Array,
  ) => CapabilitySnapshot | null | Promise<CapabilitySnapshot | null>
  readonly maximumWatermarkValidators?: number
  /**
   * Effective snapshot at the transaction's signed author timestamp.
   * A null result means required causal/closure evidence has not arrived.
   * Governed production runtimes must provide this; the pinned-only default is
   * useful for isolated revision verification, not revocation activation.
   */
  readonly authorizationSnapshot?: (context: WriterAuthorizationContext) =>
    CapabilitySnapshot | null | Promise<CapabilitySnapshot | null>
  /** Recovery-controlled binding from a capability to its authenticated SSB feed. */
  readonly transportAuthorForCapability?: (
    capability: EffectiveCapability,
    snapshot: CapabilitySnapshot,
  ) => string | null | Promise<string | null>
}

export type WriterAuthorizationContext = Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'> & {
  readonly writerCapability?: Uint8Array
  readonly authorTimestampMs?: bigint
  /** The author time is closed and all included causal controls are resolved. */
  readonly finalityClosed?: boolean
  readonly txId?: Uint8Array
}

export class GovernanceEvidencePendingError extends Error {
  readonly code = 'GOVERNANCE_EVIDENCE_PENDING'
  constructor() { super('GOVERNANCE_EVIDENCE_PENDING'); this.name = 'GovernanceEvidencePendingError' }
}

/** Bridges the signed capability log to revision-pinned node authorization. */
export class CapabilityMembershipResolver implements MembershipResolver {
  readonly #snapshots: CapabilityMembershipResolverOptions['snapshotForRevision']
  readonly #maximumWatermarkValidators: number
  readonly #transportAuthorForCapability: CapabilityMembershipResolverOptions['transportAuthorForCapability']
  readonly #authorizationSnapshot: CapabilityMembershipResolverOptions['authorizationSnapshot']

  constructor(options: CapabilityMembershipResolverOptions) {
    this.#snapshots = options.snapshotForRevision
    this.#maximumWatermarkValidators = options.maximumWatermarkValidators ?? 20
    this.#transportAuthorForCapability = options.transportAuthorForCapability
    this.#authorizationSnapshot = options.authorizationSnapshot
  }

  async canWrite(context: WriterAuthorizationContext): Promise<boolean> {
    const snapshot = await this.#snapshot(context)
    if (!snapshot) {
      // Inclusion receipts do not establish causal governance completeness.
      // A signed predecessor may still arrive through a later provider batch.
      if (await this.#snapshots(context.membershipRevision) === null && !context.finalityClosed) throw new GovernanceEvidencePendingError()
      return false
    }
    if (context.writerCapability === undefined) return false
    const id = bytesToHex(context.writerCapability)
    const grant = snapshot.capabilities.get(id)
    if (grant === undefined || !this.#activeRole(grant, snapshot, 'writer') ||
        !equalBytes(grant.grant.signingPublicKey, context.writerId)) return false
    if (context.program !== undefined && !programAllowed(grant.grant, context.program)) return false
    const effective = this.#authorizationSnapshot === undefined ? snapshot : await this.#authorizationSnapshot(context)
    if (effective === null) {
      if (context.finalityClosed) return false
      throw new GovernanceEvidencePendingError()
    }
    const active = effective.capabilities.get(id)
    return equalBytes(effective.groupId, context.groupId) && snapshot.revision <= effective.revision &&
      active !== undefined && this.#activeRole(active, effective, 'writer') &&
      equalBytes(active.grant.signingPublicKey, context.writerId)
  }

  async canValidate(context: CandidateAdmissionContext): Promise<boolean> {
    const snapshot = await this.#snapshot(context)
    if (!snapshot) return false
    const capability = snapshot.capabilities.get(bytesToHex(context.validatorCapability))
    return capability !== undefined &&
      this.#activeRole(capability, snapshot, 'validator') &&
      equalBytes(capability.grant.signingPublicKey, context.validatorId)
  }

  async threshold(context: Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'>): Promise<number> {
    const snapshot = await this.#snapshot(context)
    const policy = snapshot?.policies.get(bytesToHex(context.validationPolicy))?.policy
    if (!policy || policy.minimumValidators > BigInt(Number.MAX_SAFE_INTEGER)) return Number.MAX_SAFE_INTEGER
    return Number(policy.minimumValidators)
  }

  async policyVersion(
    context: Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'>,
  ): Promise<bigint> {
    const snapshot = await this.#snapshot(context)
    return snapshot?.policies.get(bytesToHex(context.validationPolicy))?.policy.version ?? -1n
  }

  async canHeartbeat(context: ValidatorAuthorityContext): Promise<boolean> {
    const snapshot = await this.#snapshot({ ...context, validationPolicy: new Uint8Array(), writerId: new Uint8Array() })
    if (!snapshot) return false
    const capability = snapshot.capabilities.get(bytesToHex(context.validatorCapability))
    return capability !== undefined &&
      this.#activeRole(capability, snapshot, 'validator') &&
      equalBytes(capability.grant.signingPublicKey, context.validatorId)
  }

  async canUseTransportAuthor(context: TransportAuthorContext): Promise<boolean> {
    const snapshot = await this.#snapshot({
      groupId: context.groupId,
      membershipRevision: context.membershipRevision,
      validationPolicy: new Uint8Array(),
      writerId: context.signingId,
    })
    if (!snapshot) {
      if (await this.#snapshots(context.membershipRevision) === null) throw new GovernanceEvidencePendingError()
      return false
    }
    const capability = context.role === 'validator'
      ? snapshot.capabilities.get(bytesToHex(context.validatorCapability ?? new Uint8Array()))
      : snapshot.capabilities.get(bytesToHex(context.writerCapability ?? new Uint8Array()))
    if (
      capability === undefined ||
      !this.#activeRole(capability, snapshot, context.role) ||
      !equalBytes(capability.grant.signingPublicKey, context.signingId)
    ) return false
    const authorized = this.#transportAuthorForCapability === undefined
      ? capability.grant.transportAuthor ?? null
      : await this.#transportAuthorForCapability(capability, snapshot)
    if (authorized === context.transportAuthor) return true
    return context.role === 'writer' && capability.grant.program?.forwarded === true &&
      [...snapshot.capabilities.values()].some((relay) => isCapabilityActive(relay, snapshot.revision) &&
        (relay.grant.role === 'reader' || relay.grant.role === 'writer') && relay.grant.transportAuthor === context.transportAuthor)
  }

  async selectAdmission(
    context: Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'>,
    attestations: readonly StoredAttestation[],
  ): Promise<readonly StoredAttestation[]> {
    const snapshot = await this.#snapshot(context)
    const policy = snapshot?.policies.get(bytesToHex(context.validationPolicy))?.policy
    if (!snapshot || !policy) return []
    const indexed = new Map<string, { readonly evidence: ValidatorEvidence; readonly attestation: StoredAttestation }>()
    for (const attestation of attestations) {
      const capability = snapshot.capabilities.get(bytesToHex(attestation.validatorCapability))
      if (
        capability === undefined ||
        !this.#activeRole(capability, snapshot, 'validator') ||
        !equalBytes(capability.grant.signingPublicKey, attestation.validatorId) ||
        !equalBytes(attestation.membershipRevision, snapshot.revisionDigest) ||
        attestation.policyVersion !== policy.version ||
        attestation.authorTimestampMs <= attestation.acceptedAboveMs ||
        attestation.authorTimestampMs <= (capability.grant.minimumAuthorTimestampMs ?? -1n)
      ) continue
      const key = bytesToHex(capability.id)
      if (indexed.has(key)) continue
      indexed.set(key, {
        evidence: {
          capabilityId: capability.id,
          validatorId: attestation.validatorId,
        },
        attestation,
      })
    }
    const evaluation = evaluateValidationPolicy(policy, [...indexed.values()].map((item) => item.evidence))
    if (!evaluation.satisfied) return []
    return evaluation.selected.map((evidence) => indexed.get(bytesToHex(evidence.capabilityId))!.attestation)
  }

  async watermarkPolicy(core: TransactionCore): Promise<WatermarkPolicy | null> {
    const context = {
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      validationPolicy: core.validationPolicy,
      writerId: core.authorId,
      ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
    }
    const snapshot = await this.#snapshot(context)
    const effective = snapshot?.policies.get(bytesToHex(core.validationPolicy))
    if (!snapshot || !effective) return null
    const validators = [...snapshot.capabilities.values()]
      .filter((capability) => this.#activeRole(capability, snapshot, 'validator'))
    if (validators.length > this.#maximumWatermarkValidators) return null
    const policyId = bytesToHex(effective.id)
    const threshold = Number(effective.policy.minimumValidators)
    if (!Number.isSafeInteger(threshold)) return null
    return {
      kind: 'threshold',
      policyId,
      validatorIds: validators.map((capability) => capability.grant.signingPublicKey),
      threshold,
    }
  }

  async #snapshot(context: Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'>): Promise<CapabilitySnapshot | null> {
    const snapshot = await this.#snapshots(context.membershipRevision)
    return snapshot !== null &&
      equalBytes(snapshot.groupId, context.groupId) &&
      equalBytes(snapshot.revisionDigest, context.membershipRevision)
      ? snapshot
      : null
  }

  #activeRole(capability: EffectiveCapability, snapshot: CapabilitySnapshot, role: 'writer' | 'validator'): boolean {
    return capability.grant.role === role && isCapabilityActive(capability, snapshot.revision)
  }
}


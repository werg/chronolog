import { isCapabilityActive, type CapabilitySnapshot, type EffectiveCapability } from '@chronolog/capabilities'
import { assertCanonicalCbor, bytesToHex, equalBytes } from '@chronolog/protocol'

import type { WriterAuthorizationContext } from './capability-membership.js'

interface Activation {
  readonly snapshot: CapabilitySnapshot
  /** The new revision governs author timestamps strictly after this closed bound. */
  readonly after: bigint
}

/**
 * Shared author-time activation, independent of the selected proof provider.
 * Policy activation is separate from receiving a newer governance snapshot.
 * Replay always selects the snapshot at the immutable author timestamp; a later
 * revocation never changes authorization of an earlier final transaction.
 */
export class GovernanceActivationIndex {
  readonly #groupId: Uint8Array
  readonly #snapshots = new Map<string, CapabilitySnapshot>()
  readonly #activations: Activation[]
  readonly #validators: readonly EffectiveCapability[]

  constructor(genesis: CapabilitySnapshot) {
    if (genesis.revision !== 0n) throw new Error('GOVERNANCE_ACTIVATION_GENESIS_REQUIRED')
    this.#groupId = genesis.groupId.slice()
    this.#validators = activeValidators(genesis)
    this.#activations = [{ snapshot: structuredClone(genesis), after: -1n }]
    this.observe(genesis)
  }

  /** Register a snapshot already verified by the signed governance reducer. */
  observe(snapshot: CapabilitySnapshot): void {
    if (!equalBytes(snapshot.groupId, this.#groupId)) throw new Error('GOVERNANCE_ACTIVATION_GROUP_MISMATCH')
    this.#snapshots.set(bytesToHex(snapshot.revisionDigest), structuredClone(snapshot))
  }

  get activeSnapshot(): CapabilitySnapshot { return structuredClone(this.#activations[this.#activations.length - 1]!.snapshot) }
  get activationBoundary(): bigint { return this.#activations[this.#activations.length - 1]!.after }
  get finalityRevisions(): readonly { readonly membershipRevision: Uint8Array; readonly authorTimeAfterMs: bigint }[] {
    return this.#activations.map(({ snapshot, after }) => ({ membershipRevision: snapshot.revisionDigest.slice(), authorTimeAfterMs: after }))
  }

  /** Envelope authority follows the same timestamp-selected state as writer grants. */
  encryptionEpochStatusAt(authorTimestampMs: bigint, epochId: Uint8Array | null): 'active' | 'closed' | 'unissued' {
    const epoch = decodeEpochId(epochId)
    if (epoch === null || authorTimestampMs < 0n) return 'unissued'
    const activation = this.#activations.findLast(item => authorTimestampMs > item.after)
    if (activation === undefined || epoch > activation.snapshot.encryptionEpoch) return 'unissued'
    return epoch === activation.snapshot.encryptionEpoch ? 'active' : 'closed'
  }

  /** Does an epoch's authority overlap (afterMs, throughMs]? The caller proves that complete window closed. */
  encryptionEpochCanAuthorize(afterMs: bigint, throughMs: bigint, epochId: Uint8Array | null): boolean {
    const epoch = decodeEpochId(epochId)
    if (epoch === null || throughMs < 0n || afterMs >= throughMs) return false
    return this.#activations.some((activation, index) => {
      const next = this.#activations[index + 1]
      const lower = afterMs > activation.after ? afterMs : activation.after
      const upper = next !== undefined && next.after < throughMs ? next.after : throughMs
      return activation.snapshot.encryptionEpoch === epoch && lower < upper
    })
  }

  /** The provider proved inclusion and closed this author-time boundary. */
  activateFinalized(snapshot: CapabilitySnapshot, cutoffMs: bigint): void {
    if (cutoffMs < 0n) throw new Error('GOVERNANCE_ACTIVATION_BOUNDARY_INVALID')
    // A successor whose predecessor arrived in a later closure takes effect
    // with that predecessor, never retroactively inside an already closed view.
    this.#activate(snapshot, cutoffMs < this.activationBoundary ? this.activationBoundary : cutoffMs)
  }

  snapshotFor(context: WriterAuthorizationContext): CapabilitySnapshot | null {
    if (!equalBytes(context.groupId, this.#groupId) || !this.#snapshots.has(bytesToHex(context.membershipRevision))) return null
    if (this.#snapshots.get(bytesToHex(context.membershipRevision))!.revision > this.activeSnapshot.revision) return null
    const point = context.authorTimestampMs
    if (point === undefined || point < 0n) return null
    for (let index = this.#activations.length - 1; index >= 0; index -= 1) {
      const activation = this.#activations[index]!
      if (point > activation.after) return structuredClone(activation.snapshot)
    }
    return null
  }

  #activate(snapshot: CapabilitySnapshot, after: bigint): void {
    this.#assertSuccessor(snapshot)
    if (after < this.activationBoundary) throw new Error('GOVERNANCE_ACTIVATION_REGRESSION')
    // Several causal membership revisions may share one closed batch. Their
    // signed revision chain, not receipt order, resolves the effective state.
    this.observe(snapshot)
    this.#activations.push({ snapshot: structuredClone(snapshot), after })
  }

  #assertSuccessor(snapshot: CapabilitySnapshot): void {
    const active = this.activeSnapshot
    if (!equalBytes(snapshot.groupId, this.#groupId) || snapshot.revision !== active.revision + 1n) {
      throw new Error('GOVERNANCE_ACTIVATION_CHAIN_INVALID')
    }
    if (!equalBytes(snapshot.rootAdminPublicKey, active.rootAdminPublicKey) ||
        !equalBytes(snapshot.capabilityLogFeed, active.capabilityLogFeed)) throw new Error('GOVERNANCE_AUTHORITY_RECONFIGURATION_UNSUPPORTED')
    if (snapshot.policies.size !== active.policies.size || [...snapshot.policies.keys()].some((key) => !active.policies.has(key))) {
      throw new Error('GOVERNANCE_POLICY_RECONFIGURATION_UNSUPPORTED')
    }
    // Initial enrollment changes application membership, never consensus roles.
    const validators = activeValidators(snapshot)
    if (validators.length !== this.#validators.length || validators.some((item, index) =>
      !equalBytes(item.id, this.#validators[index]!.id))) throw new Error('GOVERNANCE_VALIDATOR_RECONFIGURATION_UNSUPPORTED')
  }
}

function activeValidators(snapshot: CapabilitySnapshot): EffectiveCapability[] {
  return [...snapshot.capabilities.values()]
    .filter((item) => item.grant.role === 'validator' && isCapabilityActive(item, snapshot.revision))
    .sort((left, right) => bytesToHex(left.id).localeCompare(bytesToHex(right.id)))
}

function decodeEpochId(epochId: Uint8Array | null): bigint | null {
  if (epochId === null) return null
  try {
    const value = assertCanonicalCbor(epochId)
    return typeof value === 'bigint' && value >= 0n ? value : null
  } catch { return null }
}

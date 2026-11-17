import type { TransactionOrderKey } from '@chronolog/protocol'

export type CandidateState =
  | 'waiting_for_payload'
  | 'pending_validation'
  | 'admissible'
  | 'invalid_protocol'
  | 'unauthorized'
  | 'inadmissible'
  | 'quarantined'

export interface StoredCandidate {
  readonly txId: Uint8Array
  readonly groupId: Uint8Array
  readonly candidateDigest: Uint8Array
  readonly validationPolicy: Uint8Array
  readonly orderKey: TransactionOrderKey
  readonly canonicalPayload?: Uint8Array
  readonly state: CandidateState
  readonly stateReason?: string
  readonly proofAttestationIds: readonly Uint8Array[]
}

export interface PutCandidateInput extends Omit<StoredCandidate, 'proofAttestationIds'> {
  readonly proofAttestationIds?: readonly Uint8Array[]
}

export interface StoredAttestation {
  readonly attestationId: Uint8Array
  readonly txId: Uint8Array
  readonly validatorId: Uint8Array
  readonly validatorCapability: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly candidateDigest: Uint8Array
  readonly validatorFeedSequence: bigint
  readonly authorTimestampMs: bigint
  readonly acceptedAboveMs: bigint
  /** Validator policy implementation version committed by the signed proof. */
  readonly policyVersion: bigint
  /** Authenticated outer feed which carried the signed proof. */
  readonly transportAuthor: string
}

export interface ValidatorHeartbeat {
  readonly heartbeatId: Uint8Array
  readonly validatorId: Uint8Array
  readonly validatorCapability: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly validatorFeedSequence: bigint
  readonly acceptanceCutoffMs: bigint
  /** True only if the validator feed is known contiguous through this message. */
  readonly feedContiguous: boolean
}

/** The watermark is the cutoff that `threshold` of these validators have all passed. */
export interface WatermarkPolicy {
  readonly kind: 'threshold'
  readonly policyId: string
  readonly validatorIds: readonly Uint8Array[]
  readonly threshold: number
}

export interface WatermarkEvidence {
  readonly policyId: string
  readonly cutoffMs: bigint | null
  readonly blockingValidatorIds: readonly Uint8Array[]
  readonly heartbeatIds: readonly Uint8Array[]
  readonly explanation:
    | 'established'
    | 'insufficient_contiguous_heartbeats'
    | 'invalid_policy'
}

export interface SettlementEvidence {
  readonly txId: Uint8Array
  readonly candidateState: CandidateState
  readonly orderKey: TransactionOrderKey
  readonly proofAttestationIds: readonly Uint8Array[]
  readonly watermark: WatermarkEvidence
  readonly belowWatermark: boolean
  readonly unresolvedAttestationIds: readonly Uint8Array[]
  readonly frontier: AdmissionFrontier
}

/** An authentic admission promise whose eventual effect is not yet resolved. */
export interface AdmissionBlocker {
  readonly proposalId: Uint8Array
  readonly authorTimestampMs: bigint
  readonly reason: 'missing-proposal' | 'pending-admission'
  readonly attestationIds: readonly Uint8Array[]
}

/** A closed timestamp range, reduced by every still possible earlier admission. */
export interface AdmissionFrontier {
  readonly provenThroughMs: bigint | null
  /** A blocker at T limits this safe chronological frontier to T - 1. */
  readonly closedThroughMs: bigint | null
  readonly blockers: readonly AdmissionBlocker[]
  /** Known proposals whose remaining eligible validators cannot satisfy their policy. */
  readonly excludedProposalIds: readonly Uint8Array[]
}

export interface AdmissionFrontierOptions {
  /** The adapter's frontier across every permitted policy, when not a single-policy store. */
  readonly provenThroughMs?: bigint | null
  /** Fully verified revision closures, after every preceding admission was evaluated. */
  readonly closedMembershipRevisions?: ReadonlySet<string>
  /** Fully verified proof IDs, encoded as lowercase hexadecimal, for known payloads. */
  readonly verifiedAttestationIds?: ReadonlySet<string>
  /** Heartbeat IDs whose complete feed prefixes the current admission index has consumed. */
  readonly verifiedHeartbeatIds?: ReadonlySet<string>
  /** Every known pending proposal's own policy and signed membership revision. */
  readonly candidatePolicies?: ReadonlyMap<string, {
    readonly policy: WatermarkPolicy
    readonly membershipRevision: Uint8Array
  }>
}

export interface MaterializedHead {
  readonly localRevision: bigint
  readonly headRef: string
  readonly orderLength: number
  readonly orderDigest: Uint8Array
}

export interface StoredCheckpoint {
  readonly prefixLength: number
  readonly checkpointRef: string
  readonly prefixDigest: Uint8Array
  readonly pinned: boolean
}


export type ControlStoreDelta =
  | {
      readonly sequence: bigint
      readonly kind: 'candidate_added'
      readonly txId: Uint8Array
      readonly state: CandidateState
    }
  | {
      readonly sequence: bigint
      readonly kind: 'candidate_state_changed'
      readonly txId: Uint8Array
      readonly previousState: CandidateState
      readonly state: CandidateState
      readonly reason?: string
    }
  | {
      readonly sequence: bigint
      readonly kind: 'attestation_added'
      readonly attestationId: Uint8Array
      readonly txId: Uint8Array
      readonly unresolvedCandidate: boolean
    }
  | {
      readonly sequence: bigint
      readonly kind: 'order_append' | 'order_insert'
      readonly txId: Uint8Array
      readonly index: number
      readonly previousLength: number
    }
  | {
      readonly sequence: bigint
      readonly kind: 'heartbeat_advanced'
      readonly heartbeatId: Uint8Array
      readonly validatorId: Uint8Array
      readonly cutoffMs: bigint
      readonly feedContiguous: boolean
    }
  | {
      readonly sequence: bigint
      readonly kind: 'materialized_head_published'
      readonly head: MaterializedHead
    }
  | {
      readonly sequence: bigint
      readonly kind: 'checkpoint_stored'
      readonly checkpoint: StoredCheckpoint
    }

export interface ControlStoreSnapshot {
  readonly orderPolicy?: 'peer' | 'coordinated'
  readonly format: 'chronolog-control-store/v1'
  readonly sequence: bigint
  readonly candidates: readonly StoredCandidate[]
  readonly attestations: readonly StoredAttestation[]
  readonly heartbeats: readonly ValidatorHeartbeat[]
  readonly orderedTxIds: readonly Uint8Array[]
  readonly deltas: readonly ControlStoreDelta[]
  /** Highest sequence no longer retained in `deltas`. */
  readonly deltaFloor?: bigint
  readonly materializedHead: MaterializedHead | null
  readonly checkpoints: readonly StoredCheckpoint[]
  /**
   * Cutoffs are validator signing state rather than a rebuildable index. They
   * are written synchronously before a validator publishes a signed record.
   * Optional for snapshots produced before cutoff journaling was introduced.
   */
  readonly validatorCutoffs?: readonly {
    readonly validatorId: Uint8Array
    readonly acceptedAboveMs: bigint
  }[]
}

/**
 * One state mutation of the rebuildable control index, as recorded in an
 * append-only journal. Replaying the operations in order through the store's
 * own mutation methods reproduces the state, sequence and deltas exactly.
 */
export type ControlStoreOperation =
  | { readonly kind: 'put_candidate'; readonly candidate: StoredCandidate }
  | { readonly kind: 'put_attestation'; readonly attestation: StoredAttestation }
  | {
      readonly kind: 'set_candidate_state'
      readonly txId: Uint8Array
      readonly state: CandidateState
      readonly proofAttestationIds: readonly Uint8Array[]
      readonly reason?: string
    }
  | { readonly kind: 'record_heartbeat'; readonly heartbeat: ValidatorHeartbeat }
  | { readonly kind: 'publish_materialized_head'; readonly head: MaterializedHead }
  | { readonly kind: 'put_checkpoint'; readonly checkpoint: StoredCheckpoint }

export interface ControlStoreJournalEntry {
  /** Store sequence after the operation was applied. */
  readonly sequence: bigint
  readonly operation: ControlStoreOperation
}

export interface ControlStorePersistence {
  load(): ControlStoreSnapshot | null
  save(snapshot: ControlStoreSnapshot): void
  /**
   * Operations recorded after the snapshot returned by load(), in order.
   * Entries at or below the snapshot sequence are already contained in it.
   */
  loadJournal?(): readonly ControlStoreJournalEntry[]
  /**
   * Records one mutation instead of rewriting the snapshot. When present the
   * store calls it in place of requestSave()/save() per mutation. Returns true
   * when the journal should be compacted into a fresh snapshot.
   */
  appendJournal?(entry: ControlStoreJournalEntry): boolean
  /** True when loadJournal() found a journal file that should be compacted. */
  journalPresent?(): boolean
  /** Loads non-rebuildable validator signing state from its independent journal. */
  loadValidatorCutoffs?(): readonly ValidatorCutoffState[] | null
  /** Initializes the independent cutoff journal after loading a valid legacy snapshot. */
  initializeValidatorCutoffs?(cutoffs: readonly ValidatorCutoffState[]): void
  /** Synchronously and durably advances one validator's signing cutoff. */
  saveValidatorCutoff?(cutoff: ValidatorCutoffState): void
  /** Optional coalescing hook for rebuildable persistence implementations. */
  requestSave?(snapshot: () => ControlStoreSnapshot): void
  flush?(): void
  /** Quarantines a structurally corrupt rebuildable snapshot, if supported. */
  recoverCorruptSnapshot?(error: unknown): boolean
}

export interface ValidatorCutoffState {
  readonly validatorId: Uint8Array
  readonly acceptedAboveMs: bigint
}

export interface AdmissionEvaluation {
  readonly state: Extract<CandidateState, 'pending_validation' | 'admissible'>
  readonly proofAttestationIds?: readonly Uint8Array[]
  readonly reason?: string
}

export type AdmissionEvaluator = (
  candidate: StoredCandidate,
  attestations: readonly StoredAttestation[],
) => AdmissionEvaluation

import { bytesToHex, hexToBytes, compareTransactionOrder } from '@chronolog/protocol'

import type {
  AdmissionBlocker,
  AdmissionFrontier,
  AdmissionFrontierOptions,
  CandidateState,
  ControlStoreDelta,
  ControlStoreJournalEntry,
  ControlStoreOperation,
  ControlStorePersistence,
  ControlStoreSnapshot,
  MaterializedHead,
  PutCandidateInput,
  SettlementEvidence,
  StoredAttestation,
  StoredCandidate,
  StoredCheckpoint,
  ValidatorHeartbeat,
  ValidatorCutoffState,
  WatermarkEvidence,
  WatermarkPolicy,
} from './types.js'

const TERMINAL_INVALID_STATES = new Set<CandidateState>([
  'unauthorized',
  'inadmissible',
])

type WithoutSequence<T> = T extends unknown ? Omit<T, 'sequence'> : never

export class ControlStoreConflictError extends Error {
  constructor(readonly code: string) {
    super(code)
    this.name = 'ControlStoreConflictError'
  }
}

export class ControlStore {
  readonly #persistence: ControlStorePersistence | null
  #sequence = 0n
  #deltaFloor = 0n
  readonly #maximumRetainedDeltas: number
  readonly #candidates = new Map<string, StoredCandidate>()
  readonly #attestations = new Map<string, StoredAttestation>()
  readonly #attestationsByTx = new Map<string, Set<string>>()
  readonly #heartbeats = new Map<string, ValidatorHeartbeat>()
  readonly #validatorCutoffs = new Map<string, bigint>()
  readonly #orderedTxIds: Uint8Array[] = []
  readonly #deltas: ControlStoreDelta[] = []
  readonly #checkpoints = new Map<number, StoredCheckpoint>()
  #materializedHead: MaterializedHead | null = null
  #replaying = false

  constructor(
    persistence: ControlStorePersistence | null = null,
    options: { readonly maximumRetainedDeltas?: number } = {},
  ) {
    this.#persistence = persistence
    this.#maximumRetainedDeltas = options.maximumRetainedDeltas ?? 2_048
    if (!Number.isSafeInteger(this.#maximumRetainedDeltas) || this.#maximumRetainedDeltas < 1) {
      throw new RangeError('CONTROL_STORE_INVALID_DELTA_RETENTION')
    }
    const journalCutoffs = persistence?.loadValidatorCutoffs?.() ?? []
    const snapshot = persistence?.load()
    if (snapshot !== null && snapshot !== undefined) this.#restore(snapshot)
    this.#replayJournal(persistence?.loadJournal?.() ?? [])
    for (const cutoff of journalCutoffs) this.#mergeValidatorCutoff(cutoff)
    // Compact on open: bounds replay work and discards any torn final line
    // before new entries are appended after it.
    if (persistence?.journalPresent?.() === true) persistence.save(this.snapshot())
  }

  get sequence(): bigint {
    return this.#sequence
  }

  /** Sequences at or below this floor require a fresh snapshot. */
  get deltaFloor(): bigint {
    return this.#deltaFloor
  }

  /** Flushes a coalesced rebuildable snapshot at graceful durability points. */
  flush(): void {
    this.#persistence?.flush?.()
  }

  validatorCutoff(validatorId: Uint8Array): bigint | null {
    return this.#validatorCutoffs.get(idKey(validatorId)) ?? null
  }

  /**
   * Durably advances validator signing state before the corresponding signed
   * feed record is published. This deliberately bypasses coalesced snapshot
   * persistence: losing this value could let a restarted validator sign below
   * a cutoff it had already announced.
   */
  persistValidatorCutoff(validatorId: Uint8Array, acceptedAboveMs: bigint): void {
    const key = idKey(validatorId)
    const previous = this.#validatorCutoffs.get(key)
    if (previous !== undefined && acceptedAboveMs < previous) {
      throw new ControlStoreConflictError('CONTROL_STORE_VALIDATOR_CUTOFF_REGRESSION')
    }
    if (previous === acceptedAboveMs) return
    if (this.#persistence?.saveValidatorCutoff !== undefined) {
      this.#persistence.saveValidatorCutoff({ validatorId, acceptedAboveMs })
      this.#validatorCutoffs.set(key, acceptedAboveMs)
      return
    }
    this.#validatorCutoffs.set(key, acceptedAboveMs)
    try {
      this.#persistence?.save(this.snapshot())
    } catch (error) {
      if (previous === undefined) this.#validatorCutoffs.delete(key)
      else this.#validatorCutoffs.set(key, previous)
      throw error
    }
  }

  putCandidate(input: PutCandidateInput): { added: boolean; deltas: readonly ControlStoreDelta[] } {
    const txKey = idKey(input.txId)
    const existing = this.#candidates.get(txKey)
    const candidate = cloneCandidate({
      ...input,
      proofAttestationIds: input.proofAttestationIds ?? [],
    })

    if (existing !== undefined) {
      if (!sameCandidateIdentity(existing, candidate)) {
        throw new ControlStoreConflictError('CONTROL_STORE_CANDIDATE_CONFLICT')
      }
      return { added: false, deltas: [] }
    }

    this.#candidates.set(txKey, candidate)
    const deltas: ControlStoreDelta[] = [
      this.#appendDelta({ kind: 'candidate_added', txId: candidate.txId, state: candidate.state }),
    ]
    if (isSelected(candidate.state)) deltas.push(this.#insertOrder(candidate))
    this.#persist({ kind: 'put_candidate', candidate })
    return { added: true, deltas: clone(deltas) }
  }

  getCandidate(txId: Uint8Array): StoredCandidate | null {
    const candidate = this.#candidates.get(idKey(txId))
    return candidate === undefined ? null : cloneCandidate(candidate)
  }

  listCandidates(): readonly StoredCandidate[] {
    return [...this.#candidates.values()].map(cloneCandidate)
  }

  putAttestation(attestation: StoredAttestation): {
    added: boolean
    delta: ControlStoreDelta | null
  } {
    const key = idKey(attestation.attestationId)
    const stored = cloneAttestation(attestation)
    const existing = this.#attestations.get(key)
    if (existing !== undefined) {
      if (!sameValue(existing, stored)) {
        throw new ControlStoreConflictError('CONTROL_STORE_ATTESTATION_CONFLICT')
      }
      return { added: false, delta: null }
    }

    this.#attestations.set(key, stored)
    const txKey = idKey(stored.txId)
    let refs = this.#attestationsByTx.get(txKey)
    if (refs === undefined) {
      refs = new Set()
      this.#attestationsByTx.set(txKey, refs)
    }
    refs.add(key)
    const delta = this.#appendDelta({
      kind: 'attestation_added',
      attestationId: stored.attestationId,
      txId: stored.txId,
      unresolvedCandidate: !this.#candidates.has(txKey),
    })
    this.#persist({ kind: 'put_attestation', attestation: stored })
    return { added: true, delta: clone(delta) }
  }

  /** Distinct authentic references whose proposal body has not been indexed. */
  get missingProposalCount(): number {
    let count = 0
    for (const key of this.#attestationsByTx.keys()) if (!this.#candidates.has(key)) count += 1
    return count
  }

  attestationsFor(txId: Uint8Array): readonly StoredAttestation[] {
    const refs = this.#attestationsByTx.get(idKey(txId))
    if (refs === undefined) return []
    return [...refs]
      .map((ref) => this.#attestations.get(ref))
      .filter((value): value is StoredAttestation => value !== undefined)
      .map(cloneAttestation)
  }

  setCandidateState(
    txId: Uint8Array,
    state: CandidateState,
    options: { readonly proofAttestationIds?: readonly Uint8Array[]; readonly reason?: string } = {},
  ): readonly ControlStoreDelta[] {
    const key = idKey(txId)
    const candidate = this.#requiredCandidate(txId)
    validateStateTransition(candidate.state, state)
    const proofAttestationIds = options.proofAttestationIds ?? candidate.proofAttestationIds
    for (const attestationId of proofAttestationIds) {
      const attestation = this.#attestations.get(idKey(attestationId))
      if (attestation === undefined || idKey(attestation.txId) !== key) {
        throw new ControlStoreConflictError('CONTROL_STORE_INVALID_ADMISSION_PROOF')
      }
    }

    if (
      candidate.state === state &&
      sameBytesList(candidate.proofAttestationIds, proofAttestationIds) &&
      candidate.stateReason === options.reason
    ) {
      return []
    }

    const identity = { ...candidate }
    delete identity.stateReason
    const next: StoredCandidate = cloneCandidate({
      ...identity,
      state,
      ...(options.reason === undefined ? {} : { stateReason: options.reason }),
      proofAttestationIds,
    })
    this.#candidates.set(key, next)
    const deltas: ControlStoreDelta[] = [
      this.#appendDelta({
        kind: 'candidate_state_changed',
        txId: next.txId,
        previousState: candidate.state,
        state,
        ...(options.reason === undefined ? {} : { reason: options.reason }),
      }),
    ]
    if (!isSelected(candidate.state) && isSelected(state)) {
      deltas.push(this.#insertOrder(next))
    } else if (isSelected(candidate.state) && !isSelected(state)) {
      deltas.push(this.#removeOrder(next))
    }
    this.#persist({
      kind: 'set_candidate_state',
      txId: next.txId,
      state,
      proofAttestationIds,
      ...(options.reason === undefined ? {} : { reason: options.reason }),
    })
    return clone(deltas)
  }

  orderedCandidates(): readonly StoredCandidate[] {
    return this.#orderedTxIds.map((txId) => cloneCandidate(this.#requiredCandidate(txId)))
  }

  orderedTransactionIds(): readonly Uint8Array[] {
    return this.#orderedTxIds.map(copyBytes)
  }

  earliestOrderDifference(previous: readonly Uint8Array[]): number | null {
    const common = Math.min(previous.length, this.#orderedTxIds.length)
    for (let index = 0; index < common; index += 1) {
      if (!bytesEqual(previous[index]!, this.#orderedTxIds[index]!)) return index
    }
    return previous.length === this.#orderedTxIds.length ? null : common
  }

  recordHeartbeat(heartbeat: ValidatorHeartbeat): ControlStoreDelta | null {
    const validatorKey = heartbeatKey(heartbeat.membershipRevision, heartbeat.validatorId)
    const next = cloneHeartbeat(heartbeat)
    const previous = this.#heartbeats.get(validatorKey)
    if (previous !== undefined) {
      if (heartbeat.validatorFeedSequence < previous.validatorFeedSequence) {
        // A persisted control snapshot may already contain a later heartbeat
        // when the authenticated transport history is replayed from sequence
        // one after restart. Older feed records are superseded, not conflicts.
        return null
      }
      if (heartbeat.acceptanceCutoffMs < previous.acceptanceCutoffMs) {
        throw new ControlStoreConflictError('CONTROL_STORE_HEARTBEAT_CUTOFF_REGRESSION')
      }
      if (heartbeat.validatorFeedSequence === previous.validatorFeedSequence) {
        // Feed continuity is locally verified evidence, not a signed field.
        // Filling a replication gap can upgrade this exact heartbeat later.
        if (!sameValue({ ...previous, feedContiguous: next.feedContiguous }, next)) {
          throw new ControlStoreConflictError('CONTROL_STORE_HEARTBEAT_CONFLICT')
        }
        if (previous.feedContiguous || !next.feedContiguous) return null
      }
    }

    this.#heartbeats.set(validatorKey, next)
    const delta = this.#appendDelta({
      kind: 'heartbeat_advanced',
      heartbeatId: next.heartbeatId,
      validatorId: next.validatorId,
      cutoffMs: next.acceptanceCutoffMs,
      feedContiguous: next.feedContiguous,
    })
    this.#persist({ kind: 'record_heartbeat', heartbeat: next })
    return clone(delta)
  }

  /** Current signed heartbeats and the locally established prefix evidence. */
  listHeartbeats(): readonly ValidatorHeartbeat[] {
    return [...this.#heartbeats.values()].map(cloneHeartbeat)
  }

  watermark(policy: WatermarkPolicy, membershipRevision?: Uint8Array,
    verifiedHeartbeatIds?: ReadonlySet<string>): WatermarkEvidence {
    return this.#thresholdWatermark(policy, membershipRevision, verifiedHeartbeatIds)
  }

  #thresholdWatermark(
    policy: Extract<WatermarkPolicy, { kind: 'threshold' }>,
    membershipRevision?: Uint8Array,
    verifiedHeartbeatIds?: ReadonlySet<string>,
  ): WatermarkEvidence {
    if (
      !Number.isSafeInteger(policy.threshold) ||
      policy.threshold < 1 ||
      policy.threshold > policy.validatorIds.length ||
      new Set(policy.validatorIds.map(idKey)).size !== policy.validatorIds.length
    ) {
      return {
        policyId: policy.policyId,
        cutoffMs: null,
        blockingValidatorIds: [],
        heartbeatIds: [],
        explanation: 'invalid_policy',
      }
    }

    const heartbeats = policy.validatorIds.map((validatorId) => {
      const heartbeat = this.#heartbeatFor(validatorId, membershipRevision)
      return heartbeat?.feedContiguous === true &&
        (verifiedHeartbeatIds === undefined || verifiedHeartbeatIds.has(idKey(heartbeat.heartbeatId))) ? heartbeat : null
    })
    const available = heartbeats
      .filter((heartbeat): heartbeat is ValidatorHeartbeat => heartbeat !== null)
      .sort((left, right) =>
        left.acceptanceCutoffMs === right.acceptanceCutoffMs
          ? 0
          : left.acceptanceCutoffMs < right.acceptanceCutoffMs
            ? -1
            : 1,
      )
    // For a k-of-n policy, every possible proof intersects any n-k+1
    // validators. The maximum safe cutoff is the kth-lowest validator cutoff;
    // missing/non-contiguous feeds behave as negative infinity.
    const missing = heartbeats.length - available.length
    const selectedIndex = policy.threshold - 1 - missing
    if (selectedIndex < 0 || selectedIndex >= available.length) {
      return {
        policyId: policy.policyId,
        cutoffMs: null,
        blockingValidatorIds: [],
        heartbeatIds: [],
        explanation: 'insufficient_contiguous_heartbeats',
      }
    }
    const cutoffMs = available[selectedIndex]!.acceptanceCutoffMs
    const blocking = available.filter((heartbeat) => heartbeat.acceptanceCutoffMs >= cutoffMs)
    return {
      policyId: policy.policyId,
      cutoffMs,
      blockingValidatorIds: blocking.map((heartbeat) => copyBytes(heartbeat.validatorId)),
      heartbeatIds: blocking.map((heartbeat) => copyBytes(heartbeat.heartbeatId)),
      explanation: 'established',
    }
  }

  settlementEvidence(
    txId: Uint8Array,
    policy: WatermarkPolicy,
    membershipRevision?: Uint8Array,
    options: AdmissionFrontierOptions = {},
  ): SettlementEvidence {
    const candidate = this.#requiredCandidate(txId)
    const watermark = this.watermark(policy, membershipRevision, options.verifiedHeartbeatIds)
    const frontier = this.admissionFrontier(policy, membershipRevision, options)
    const unresolved = frontier.blockers.filter(item => item.authorTimestampMs <= candidate.orderKey.authorTimestampMs)
    return {
      txId: copyBytes(txId),
      candidateState: candidate.state,
      orderKey: clone(candidate.orderKey),
      proofAttestationIds: candidate.proofAttestationIds.map(copyBytes),
      watermark,
      belowWatermark:
        frontier.closedThroughMs !== null && candidate.orderKey.authorTimestampMs <= frontier.closedThroughMs,
      unresolvedAttestationIds: unresolved.flatMap(item => item.attestationIds.map(copyBytes)),
      frontier,
    }
  }

  /**
   * A blocking set prevents wholly new admissions before its cutoff. Existing
   * partial votes can still complete through delayed records from another
   * validator, so every such proposal must also be admitted or excluded.
   * Callers verify proof eligibility and consume complete heartbeat feed
   * prefixes before using this result to publish application finality.
   */
  admissionFrontier(policy: WatermarkPolicy | null, membershipRevision?: Uint8Array,
    options: AdmissionFrontierOptions = {}): AdmissionFrontier {
    const provenThroughMs = options.provenThroughMs === undefined
      ? policy === null ? null : this.watermark(policy, membershipRevision, options.verifiedHeartbeatIds).cutoffMs : options.provenThroughMs
    const blockers: AdmissionBlocker[] = [], excludedProposalIds: Uint8Array[] = []
    const proposals = new Map<string, StoredAttestation[]>()
    for (const attestation of this.#attestations.values()) {
      if (attestation.authorTimestampMs <= attestation.acceptedAboveMs) continue
      const key = idKey(attestation.txId), known = this.#candidates.get(key)
      if (known?.state === 'admissible' || known !== undefined && TERMINAL_INVALID_STATES.has(known.state)) continue
      const context = options.candidatePolicies?.get(key)
      const revision = context?.membershipRevision ?? (options.candidatePolicies === undefined ? membershipRevision : undefined)
      if (known !== undefined && (revision !== undefined && idKey(attestation.membershipRevision) !== idKey(revision) ||
          attestation.authorTimestampMs !== known.orderKey.authorTimestampMs ||
          idKey(attestation.candidateDigest) !== idKey(known.candidateDigest) ||
          options.verifiedAttestationIds !== undefined && !options.verifiedAttestationIds.has(idKey(attestation.attestationId)))) continue
      const values = proposals.get(key) ?? []
      values.push(attestation); proposals.set(key, values)
    }
    // Payload arrival and proof arrival are independent. A known proposal with
    // no local vote may still have admissible votes in flight under its policy.
    for (const [key, candidate] of this.#candidates) {
      if ((candidate.state === 'pending_validation' || candidate.state === 'provisional') && !proposals.has(key)) proposals.set(key, [])
    }
    for (const [key, attestations] of proposals) {
      const candidate = this.#candidates.get(key)
      if (candidate === undefined) {
        // Until the payload arrives its own policy and signed timestamp cannot
        // be checked. Authentic metadata blocks; it never proves rejection.
        for (const attestation of attestations) blockers.push({ proposalId: copyBytes(attestation.txId),
          authorTimestampMs: attestation.authorTimestampMs, reason: 'missing-proposal',
          attestationIds: [copyBytes(attestation.attestationId)] })
        continue
      }
      const context = options.candidatePolicies?.get(key)
      if (options.candidatePolicies !== undefined && context === undefined) {
        blockers.push({ proposalId: copyBytes(candidate.txId), authorTimestampMs: candidate.orderKey.authorTimestampMs,
          reason: 'pending-admission', attestationIds: attestations.map(value => copyBytes(value.attestationId)) })
        continue
      }
      const candidatePolicy = context?.policy ?? policy
      if (candidatePolicy === null) {
        blockers.push({ proposalId: copyBytes(candidate.txId), authorTimestampMs: candidate.orderKey.authorTimestampMs,
          reason: 'pending-admission', attestationIds: attestations.map(value => copyBytes(value.attestationId)) })
        continue
      }
      const validators = new Set(candidatePolicy.validatorIds.map(idKey))
      const votes = attestations.filter(value => validators.has(idKey(value.validatorId)))
      const possible = new Set(votes.map(value => idKey(value.validatorId)))
      const timestamp = candidate.orderKey.authorTimestampMs
      const revision = context?.membershipRevision ?? membershipRevision
      const revisionClosed = revision !== undefined && options.closedMembershipRevisions?.has(idKey(revision)) === true
      for (const validator of revisionClosed ? [] : candidatePolicy.validatorIds) {
        const heartbeat = this.#heartbeatFor(validator, revision)
        if (heartbeat?.feedContiguous !== true ||
            options.verifiedHeartbeatIds !== undefined && !options.verifiedHeartbeatIds.has(idKey(heartbeat.heartbeatId)) ||
            heartbeat.acceptanceCutoffMs < timestamp) possible.add(idKey(validator))
      }
      // A complete revision closure also proves the current evaluated vote set
      // cannot change. It resolves stricter custom admission policies as well.
      if (revisionClosed || Number.isSafeInteger(candidatePolicy.threshold) && candidatePolicy.threshold > 0 &&
          candidatePolicy.threshold <= validators.size && possible.size < candidatePolicy.threshold) {
        excludedProposalIds.push(copyBytes(candidate.txId))
      } else {
        blockers.push({ proposalId: copyBytes(candidate.txId), authorTimestampMs: timestamp,
          reason: 'pending-admission', attestationIds: votes.map(value => copyBytes(value.attestationId)) })
      }
    }
    blockers.sort((left, right) => left.authorTimestampMs < right.authorTimestampMs ? -1
      : left.authorTimestampMs > right.authorTimestampMs ? 1 : idKey(left.proposalId).localeCompare(idKey(right.proposalId)))
    let closedThroughMs = provenThroughMs
    if (closedThroughMs !== null) for (const blocker of blockers) {
      if (blocker.authorTimestampMs <= closedThroughMs) closedThroughMs = blocker.authorTimestampMs - 1n
    }
    return { provenThroughMs, closedThroughMs, blockers, excludedProposalIds }
  }

  publishMaterializedHead(head: MaterializedHead): ControlStoreDelta | null {
    if (this.#materializedHead !== null) {
      if (head.localRevision < this.#materializedHead.localRevision) {
        throw new ControlStoreConflictError('CONTROL_STORE_HEAD_REVISION_REGRESSION')
      }
      if (head.localRevision === this.#materializedHead.localRevision) {
        if (!sameValue(head, this.#materializedHead)) {
          throw new ControlStoreConflictError('CONTROL_STORE_HEAD_REVISION_CONFLICT')
        }
        return null
      }
    }
    if (head.orderLength > this.#orderedTxIds.length) {
      throw new ControlStoreConflictError('CONTROL_STORE_HEAD_AHEAD_OF_ORDER')
    }
    this.#materializedHead = clone(head)
    const delta = this.#appendDelta({ kind: 'materialized_head_published', head })
    this.#persist({ kind: 'publish_materialized_head', head })
    return clone(delta)
  }

  materializedHead(): MaterializedHead | null {
    return this.#materializedHead === null ? null : clone(this.#materializedHead)
  }

  putCheckpoint(checkpoint: StoredCheckpoint): ControlStoreDelta | null {
    if (checkpoint.prefixLength < 0 || checkpoint.prefixLength > this.#orderedTxIds.length) {
      throw new ControlStoreConflictError('CONTROL_STORE_INVALID_CHECKPOINT_PREFIX')
    }
    const previous = this.#checkpoints.get(checkpoint.prefixLength)
    if (previous !== undefined && sameValue(previous, checkpoint)) return null
    if (previous?.pinned === true && checkpoint.pinned === false) {
      throw new ControlStoreConflictError('CONTROL_STORE_PINNED_CHECKPOINT_REPLACEMENT')
    }
    this.#checkpoints.set(checkpoint.prefixLength, clone(checkpoint))
    const delta = this.#appendDelta({ kind: 'checkpoint_stored', checkpoint })
    this.#persist({ kind: 'put_checkpoint', checkpoint })
    return clone(delta)
  }

  nearestCheckpointBefore(orderIndex: number): StoredCheckpoint | null {
    let nearest: StoredCheckpoint | null = null
    for (const checkpoint of this.#checkpoints.values()) {
      if (
        checkpoint.prefixLength <= orderIndex &&
        (nearest === null || checkpoint.prefixLength > nearest.prefixLength)
      ) {
        nearest = checkpoint
      }
    }
    return nearest === null ? null : clone(nearest)
  }

  changesSince(sequence: bigint): readonly ControlStoreDelta[] {
    if (sequence < this.#deltaFloor) {
      throw new ControlStoreConflictError('CONTROL_STORE_DELTA_HISTORY_RESET')
    }
    return this.#deltas.filter((delta) => delta.sequence > sequence).map(clone)
  }

  snapshot(): ControlStoreSnapshot {
    return {
      format: 'chronolog-control-store/v1',
      sequence: this.#sequence,
      candidates: this.listCandidates(),
      attestations: [...this.#attestations.values()].map(cloneAttestation),
      heartbeats: [...this.#heartbeats.values()].map(cloneHeartbeat),
      orderedTxIds: this.orderedTransactionIds(),
      deltas: this.#deltas.map(clone),
      deltaFloor: this.#deltaFloor,
      materializedHead: this.materializedHead(),
      checkpoints: [...this.#checkpoints.values()].map(clone),
      validatorCutoffs: this.#listValidatorCutoffs(),
    }
  }

  #requiredCandidate(txId: Uint8Array): StoredCandidate {
    const candidate = this.#candidates.get(idKey(txId))
    if (candidate === undefined) throw new ControlStoreConflictError('CONTROL_STORE_UNKNOWN_CANDIDATE')
    return candidate
  }

  #insertOrder(candidate: StoredCandidate): ControlStoreDelta {
    // Inclusion/finality providers never select execution order. All replicas
    // use the same signed chronological key, regardless of evidence arrival.
    let low = 0
    let high = this.#orderedTxIds.length
    while (low < high) {
      const middle = (low + high) >>> 1
      const middleCandidate = this.#requiredCandidate(this.#orderedTxIds[middle]!)
      if (compareTransactionOrder(middleCandidate.orderKey, candidate.orderKey) < 0) low = middle + 1
      else high = middle
    }
    if (
      low < this.#orderedTxIds.length &&
      bytesEqual(this.#orderedTxIds[low]!, candidate.txId)
    ) {
      throw new ControlStoreConflictError('CONTROL_STORE_DUPLICATE_ORDER_ENTRY')
    }
    const previousLength = this.#orderedTxIds.length
    this.#orderedTxIds.splice(low, 0, copyBytes(candidate.txId))
    return this.#appendDelta({
      kind: low === previousLength ? 'order_append' : 'order_insert',
      txId: candidate.txId,
      index: low,
      previousLength,
    })
  }

  #removeOrder(candidate: StoredCandidate): ControlStoreDelta {
    const index = this.#orderedTxIds.findIndex(id => bytesEqual(id, candidate.txId))
    if (index < 0) throw new ControlStoreConflictError('CONTROL_STORE_SELECTED_PROPOSAL_MISSING')
    const previousLength = this.#orderedTxIds.length
    this.#orderedTxIds.splice(index, 1)
    return this.#appendDelta({ kind: 'order_remove', txId: candidate.txId, index, previousLength })
  }

  #appendDelta(delta: WithoutSequence<ControlStoreDelta>): ControlStoreDelta {
    this.#sequence += 1n
    const sequenced = clone({ ...delta, sequence: this.#sequence })
    this.#deltas.push(sequenced)
    this.#trimDeltas()
    return sequenced
  }

  #persist(operation: ControlStoreOperation): void {
    if (this.#replaying) return
    const persistence = this.#persistence
    if (persistence?.appendJournal !== undefined) {
      const compact = persistence.appendJournal({ sequence: this.#sequence, operation: clone(operation) })
      if (compact) {
        if (persistence.requestSave !== undefined) persistence.requestSave(() => this.snapshot())
        else persistence.save(this.snapshot())
      }
      return
    }
    if (this.#persistence?.requestSave !== undefined) {
      this.#persistence.requestSave(() => this.snapshot())
    } else {
      this.#persistence?.save(this.snapshot())
    }
  }

  /**
   * Re-applies journaled operations through the normal mutation paths. Every
   * entry must advance the sequence to exactly the recorded value, so a
   * missing, reordered, duplicated or altered entry fails closed. A leading
   * run of entries already covered by the snapshot (a crash between writing a
   * compacted snapshot and removing the journal) is skipped.
   */
  #replayJournal(entries: readonly ControlStoreJournalEntry[]): void {
    if (entries.length === 0) return
    this.#replaying = true
    try {
      let applying = false
      for (const entry of entries) {
        if (entry.sequence <= this.#sequence) {
          if (applying) throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_JOURNAL_SEQUENCE')
          continue
        }
        applying = true
        this.#applyOperation(entry.operation)
        if (this.#sequence !== entry.sequence) {
          throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_JOURNAL_SEQUENCE')
        }
      }
    } finally {
      this.#replaying = false
    }
  }

  #applyOperation(operation: ControlStoreOperation): void {
    switch (operation.kind) {
      case 'put_candidate':
        this.putCandidate(operation.candidate)
        return
      case 'put_attestation':
        this.putAttestation(operation.attestation)
        return
      case 'set_candidate_state':
        this.setCandidateState(operation.txId, operation.state, {
          proofAttestationIds: operation.proofAttestationIds,
          ...(operation.reason === undefined ? {} : { reason: operation.reason }),
        })
        return
      case 'record_heartbeat':
        this.recordHeartbeat(operation.heartbeat)
        return
      case 'publish_materialized_head':
        this.publishMaterializedHead(operation.head)
        return
      case 'put_checkpoint':
        this.putCheckpoint(operation.checkpoint)
        return
      default:
        throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_JOURNAL_OPERATION')
    }
  }

  #restore(snapshot: ControlStoreSnapshot): void {
    this.#sequence = snapshot.sequence
    this.#deltaFloor = snapshot.deltaFloor
    for (const candidate of snapshot.candidates) {
      this.#candidates.set(idKey(candidate.txId), cloneCandidate(candidate))
    }
    for (const attestation of snapshot.attestations) {
      const cloned = cloneAttestation(attestation)
      const key = idKey(cloned.attestationId)
      this.#attestations.set(key, cloned)
      const txKey = idKey(cloned.txId)
      const refs = this.#attestationsByTx.get(txKey) ?? new Set<string>()
      refs.add(key)
      this.#attestationsByTx.set(txKey, refs)
    }
    for (const heartbeat of snapshot.heartbeats) {
      this.#heartbeats.set(heartbeatKey(heartbeat.membershipRevision, heartbeat.validatorId), cloneHeartbeat(heartbeat))
    }
    for (const cutoff of snapshot.validatorCutoffs) {
      this.#validatorCutoffs.set(idKey(cutoff.validatorId), cutoff.acceptedAboveMs)
    }
    this.#orderedTxIds.push(...snapshot.orderedTxIds.map(copyBytes))
    this.#deltas.push(...snapshot.deltas.map(clone))
    this.#trimDeltas()
    this.#materializedHead = snapshot.materializedHead === null ? null : clone(snapshot.materializedHead)
    for (const checkpoint of snapshot.checkpoints) {
      this.#checkpoints.set(checkpoint.prefixLength, clone(checkpoint))
    }
    this.#verifyRestoredOrder()
  }

  #verifyRestoredOrder(): void {
    if (this.#deltas.length > 0 && this.#deltas.at(-1)?.sequence !== this.#sequence) {
      throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_DELTA_SEQUENCE')
    }
    if (this.#deltas.length > 0 && this.#deltas[0]!.sequence !== this.#deltaFloor + 1n) {
      throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_DELTA_FLOOR')
    }
    if (this.#deltas.length === 0 && this.#deltaFloor !== this.#sequence) {
      throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_DELTA_FLOOR')
    }
    for (let index = 1; index < this.#deltas.length; index += 1) {
      if (this.#deltas[index]!.sequence <= this.#deltas[index - 1]!.sequence) {
        throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_DELTA_SEQUENCE')
      }
    }
    let previous: StoredCandidate | null = null
    const seen = new Set<string>()
    for (const txId of this.#orderedTxIds) {
      const candidate = this.#requiredCandidate(txId)
      if (!isSelected(candidate.state)) {
        throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_ORDER_STATE')
      }
      const key = idKey(txId)
      if (seen.has(key)) throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_DUPLICATE_ORDER')
      seen.add(key)
      if (previous !== null && compareTransactionOrder(previous.orderKey, candidate.orderKey) >= 0) {
        throw new ControlStoreConflictError('CONTROL_STORE_CORRUPT_ORDER')
      }
      previous = candidate
    }
  }

  #heartbeatFor(
    validatorId: Uint8Array,
    membershipRevision?: Uint8Array,
  ): ValidatorHeartbeat | undefined {
    if (membershipRevision !== undefined) {
      return this.#heartbeats.get(heartbeatKey(membershipRevision, validatorId))
    }
    let latest: ValidatorHeartbeat | undefined
    for (const heartbeat of this.#heartbeats.values()) {
      if (
        bytesEqual(heartbeat.validatorId, validatorId) &&
        (latest === undefined || heartbeat.validatorFeedSequence > latest.validatorFeedSequence)
      ) latest = heartbeat
    }
    return latest
  }

  #trimDeltas(): void {
    const excess = this.#deltas.length - this.#maximumRetainedDeltas
    if (excess <= 0) return
    const removed = this.#deltas.splice(0, excess)
    this.#deltaFloor = removed.at(-1)!.sequence
  }

  #mergeValidatorCutoff(cutoff: ValidatorCutoffState): void {
    const key = idKey(cutoff.validatorId)
    const previous = this.#validatorCutoffs.get(key)
    if (previous === undefined || cutoff.acceptedAboveMs > previous) {
      this.#validatorCutoffs.set(key, cutoff.acceptedAboveMs)
    }
  }

  #listValidatorCutoffs(): ValidatorCutoffState[] {
    return [...this.#validatorCutoffs.entries()].map(([key, acceptedAboveMs]) => ({
      validatorId: hexToBytes(key),
      acceptedAboveMs,
    }))
  }
}

function isSelected(state: CandidateState): boolean {
  return state === 'provisional' || state === 'admissible'
}

function validateStateTransition(previous: CandidateState, next: CandidateState): void {
  if (previous === next) return
  if (previous === 'admissible') {
    throw new ControlStoreConflictError('CONTROL_STORE_ADMISSION_NOT_MONOTONIC')
  }
  if (TERMINAL_INVALID_STATES.has(previous)) {
    throw new ControlStoreConflictError('CONTROL_STORE_TERMINAL_STATE')
  }
}

function idKey(value: Uint8Array): string {
  return bytesToHex(value)
}

function heartbeatKey(membershipRevision: Uint8Array, validatorId: Uint8Array): string {
  return `${idKey(membershipRevision)}:${idKey(validatorId)}`
}

function copyBytes(value: Uint8Array): Uint8Array {
  return Uint8Array.from(value)
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  return left.every((value, index) => value === right[index])
}

function sameBytesList(left: readonly Uint8Array[], right: readonly Uint8Array[]): boolean {
  return left.length === right.length && left.every((value, index) => bytesEqual(value, right[index]!))
}

function cloneCandidate(candidate: StoredCandidate): StoredCandidate {
  return clone(candidate)
}

function cloneAttestation(attestation: StoredAttestation): StoredAttestation {
  return clone(attestation)
}

function cloneHeartbeat(heartbeat: ValidatorHeartbeat): ValidatorHeartbeat {
  return clone(heartbeat)
}

function clone<T>(value: T): T {
  return structuredClone(value)
}

function sameCandidateIdentity(left: StoredCandidate, right: StoredCandidate): boolean {
  return sameValue(
    {
      txId: left.txId,
      groupId: left.groupId,
      candidateDigest: left.candidateDigest,
      validationPolicy: left.validationPolicy,
      orderKey: left.orderKey,
      canonicalPayload: left.canonicalPayload,
    },
    {
      txId: right.txId,
      groupId: right.groupId,
      candidateDigest: right.candidateDigest,
      validationPolicy: right.validationPolicy,
      orderKey: right.orderKey,
      canonicalPayload: right.canonicalPayload,
    },
  )
}

function sameValue(left: unknown, right: unknown): boolean {
  if (typeof left === 'bigint' || typeof right === 'bigint') return left === right
  if (left instanceof Uint8Array && right instanceof Uint8Array) return bytesEqual(left, right)
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((value, index) => sameValue(value, right[index]))
  }
  if (typeof left === 'object' && left !== null && typeof right === 'object' && right !== null) {
    const leftRecord = left as Record<string, unknown>
    const rightRecord = right as Record<string, unknown>
    const leftKeys = Object.keys(leftRecord).sort()
    const rightKeys = Object.keys(rightRecord).sort()
    return (
      leftKeys.length === rightKeys.length &&
      leftKeys.every((key, index) => key === rightKeys[index] && sameValue(leftRecord[key], rightRecord[key]))
    )
  }
  return Object.is(left, right)
}

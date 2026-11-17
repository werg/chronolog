import {
  DOMAINS, compareTransactionOrder, encodeChangeProgram, encodeTransactionCore, nextAuthorTimestampMs, transactionDigest, transactionOrderKey,
  type TransactionCore,
} from '@chronolog/protocol'
import type { ReplayProposal, PeerExecutionControls } from '@chronolog/materializer'
import { createSignedAttempt, validatePeerRevision, verifyAttempt } from './attempt.js'
import {
  boundedText, bytesDigest, bytesToHex, check, isArray, decodePeerValue, encodePeerValue,
  hexToBytes, peerDigest, PeerGenerationError, samePeerValue, Serial, signPeerValue, verifyPeerValue,
} from './codec.js'
import { generationStartRoot, type PeerAuthority, validateHistoryPoint, verifyAuthorityBundle, verifyOrderReceipt } from './control.js'
import type {
  AppliedResult, AuthorityBundle, CapturedPeerView, HistoryPoint, OperationState, OrderedCommand,
  PeerReplica, PeerReplicaOptions, PeerRevision, PeerStore, PrefixProof, PrepareCommand,
  RecoveryNotice, SignedAttempt, SignedGeneration, SignedRetainedCoverage,
} from './types.js'

interface Head { readonly sequence: number; readonly root: string; readonly bytes: number }
interface Retained { readonly command: OrderedCommand; readonly core: TransactionCore }
const activeOwners = new WeakMap<PeerStore, Set<string>>()
const operationKey = (author: string, operationId: string): string => `${author}\u0000${operationId}`

/** One durable history/journal owner shared by browser and native sessions. */
class Replica implements PeerReplica {
  readonly #options: PeerReplicaOptions
  readonly #serial = new Serial()
  #authority: PeerAuthority
  #closed = false
  #disposed = false
  #ready = false
  #publishedRevision: PeerRevision | null = null
  #journalHead = 0
  #retainedBytes = 0
  #authoredTimestampMs: bigint | null = null
  #observedTimestampMs: bigint | null = null
  readonly #heads = new Map<string, Head>()
  readonly #records = new Map<string, Map<number, Retained>>()
  readonly #attempts = new Map<string, SignedAttempt>()
  readonly #operations = new Map<string, string>()
  readonly #receipts = new Map<string, OrderedCommand>()
  #selected: Retained[] = []
  #executionOrder: Retained[] = []
  #selectedIds = new Set<string>()
  readonly #lastOutcomes = new Map<string, AppliedResult>()
  readonly #fenced = new Set<string>()
  readonly #coverage = new Map<string, SignedRetainedCoverage>()
  readonly #listeners = new Set<() => void>()
  readonly #recoveryListeners = new Set<(notice: RecoveryNotice) => void>()
  readonly #recoveries: RecoveryNotice[] = []
  readonly #prefix: string

  constructor(options: PeerReplicaOptions, authority: PeerAuthority) {
    this.#options = options; this.#authority = authority
    this.#prefix = `peer-generation/replica/${authority.descriptor.applicationId}`
  }
  get descriptor() { return this.#authority.descriptor }
  get device() { return this.#options.device }
  get authority() { return this.#authority.bundle }
  get generation(): SignedGeneration {
    const generation = this.#authority.current; check(generation !== null, 'PEER_NO_SELECTED_GENERATION'); return generation
  }
  get isCoordinator(): boolean { return this.generation.payload.coordinator === this.device.publicKey }
  get ready(): boolean { return this.#ready && !this.#closed }
  get revision(): PeerRevision {
    check(this.#publishedRevision !== null, 'PEER_RECOVERING')
    return structuredClone(this.#publishedRevision)
  }
  async initialize(): Promise<void> {
    const stored = await this.#options.store.get(`${this.#prefix}/authority`)
    if (stored !== null) {
      const previous = await verifyAuthorityBundle(decodePeerValue<AuthorityBundle>(stored), this.#authority.bundle.descriptor)
      if (previous.bundle.generations.length > this.#authority.bundle.generations.length) {
        assertExtension(this.#authority, previous); this.#authority = previous
      } else assertExtension(previous, this.#authority)
    }
    check(this.#authority.current !== null, 'PEER_NO_SELECTED_GENERATION')
    check(this.#options.materializer.kind === 'applied', 'PEER_MATERIALIZER_PROFILE_MISMATCH')
    check(bytesToHex(this.#options.materializer.queries.executionManifestDigest) === this.descriptor.executionManifestDigest,
      'PEER_EXECUTION_MANIFEST_MISMATCH')
    const journal = await this.#options.store.get(`${this.#prefix}/journal-head`)
    this.#journalHead = journal === null ? 0 : decodePeerValue<number>(journal)
    check(Number.isSafeInteger(this.#journalHead) && this.#journalHead >= 0 && this.#journalHead <= this.#maxRecords, 'PEER_JOURNAL_INVALID')
    for (let index = 1; index <= this.#journalHead; index++) {
      const bytes = await this.#options.store.get(`${this.#prefix}/journal/${index}`)
      check(bytes !== null, 'PEER_JOURNAL_INCOMPLETE')
      const attempt = decodePeerValue<SignedAttempt>(bytes)
      const core = await verifyAttempt(attempt, this.#authority, this.#options.epochKeys)
      this.#remember(attempt, core)
    }
    for (const generation of this.#authority.bundle.generations) await this.#loadGeneration(generation, this.#authority)
    const recoveryBytes = await this.#options.store.get(`${this.#prefix}/recoveries`)
    if (recoveryBytes !== null) {
      const notices = decodePeerValue<RecoveryNotice[]>(recoveryBytes)
      check(isArray(notices) && notices.length <= 32, 'PEER_RECOVERY_JOURNAL_INVALID')
      this.#recoveries.push(...notices)
    }
    try { await this.#materialize(this.#authority) }
    catch (error) { if (!(error instanceof PeerGenerationError) || error.code !== 'PEER_RECOVERY_PREFIX_INCOMPLETE') throw error }
    await this.#write(`${this.#prefix}/authority`, encodePeerValue(this.#authority.bundle))
  }
  get #maxRecords(): number { return this.#options.maxRecords ?? 100_000 }
  #assertOpen(): void { check(!this.#closed, 'PEER_REPLICA_CLOSED') }
  #assertReady(): void {
    this.#assertOpen(); check(this.#ready, 'PEER_RECOVERING')
    check(this.#authority.grant(this.device.publicKey)?.reader === true, 'PEER_READER_FORBIDDEN')
  }
  async #write(key: string, bytes: Uint8Array): Promise<void> {
    try { await this.#options.store.put(key, bytes) }
    catch (error) {
      // An atomic write may have committed before its reply was lost. Reopen;
      // never continue from stale signing or sequence state.
      this.#closed = true; throw error
    }
  }
  #remember(attempt: SignedAttempt, core: TransactionCore): void {
    const key = operationKey(attempt.payload.header.author, attempt.payload.header.operationId)
    const previous = this.#operations.get(key)
    check(previous === undefined || previous === attempt.id, 'PEER_OPERATION_ID_REUSED')
    this.#operations.set(key, attempt.id); this.#attempts.set(attempt.id, structuredClone(attempt))
    if (attempt.payload.header.author === this.device.publicKey &&
        (this.#authoredTimestampMs === null || this.#authoredTimestampMs < core.authorTimestampMs)) {
      this.#authoredTimestampMs = core.authorTimestampMs
    }
  }
  #observeApplied(timestampMs: bigint): void {
    if (this.#observedTimestampMs === null || this.#observedTimestampMs < timestampMs) this.#observedTimestampMs = timestampMs
  }
  async #loadGeneration(generation: SignedGeneration, authority: PeerAuthority): Promise<void> {
    if (this.#heads.has(generation.id)) return
    const start = await generationStartRoot(generation)
    const bytes = await this.#options.store.get(`${this.#prefix}/head/${generation.id}`)
    const head = bytes === null ? { sequence: 0, root: start, bytes: 0 } : decodePeerValue<Head>(bytes)
    check(Number.isSafeInteger(head.sequence) && head.sequence >= 0 && head.sequence <= this.#maxRecords &&
      Number.isSafeInteger(head.bytes) && head.bytes >= 0, 'PEER_HEAD_INVALID')
    this.#heads.set(generation.id, { sequence: 0, root: start, bytes: 0 })
    this.#records.set(generation.id, new Map())
    for (let index = 1; index <= head.sequence; index++) {
      const retained = await this.#options.store.get(`${this.#prefix}/record/${generation.id}/${index}`)
      check(retained !== null, 'PEER_HISTORY_INCOMPLETE')
      await this.#retain(decodePeerValue<OrderedCommand>(retained), authority, false)
      const command = this.#records.get(generation.id)!.get(index)!.command
      const resultBytes = await this.#options.store.get(`${this.#prefix}/result/${command.attempt.id}`)
      if (resultBytes !== null) {
        const result = decodePeerValue<AppliedResult>(resultBytes)
        check(result.status === 'applied' && result.attemptId === command.attempt.id && result.generation === generation.id &&
          result.sequence === index && result.operationId === command.receipt.payload.operationId &&
          result.author === command.receipt.payload.author && (result.outcome === 'accepted' || result.outcome === 'rejected'), 'PEER_RESULT_JOURNAL_INVALID')
        validatePeerRevision(result.revision)
        check(result.revision.applicationId === this.descriptor.applicationId && result.revision.historyId === this.descriptor.historyId,
          'PEER_RESULT_JOURNAL_INVALID')
        this.#lastOutcomes.set(command.attempt.id, result)
        // This durable result records a locally applied observation, even when
        // later recovery abandons that proposal. Merely retained remote bodies
        // do not advance the author's causal clock.
        this.#observeApplied(this.#records.get(generation.id)!.get(index)!.core.authorTimestampMs)
      }
    }
    check(samePeerValue(this.#heads.get(generation.id), head), 'PEER_HEAD_ROOT_MISMATCH')
    if (await this.#options.store.get(`${this.#prefix}/fence/${generation.id}`) !== null) this.#fenced.add(generation.id)
  }
  async #retain(command: OrderedCommand, authority: PeerAuthority, persist: boolean): Promise<void> {
    const { receipt, attempt } = command, generation = authority.generation(receipt.payload.generation)
    await verifyOrderReceipt(receipt, generation, this.descriptor)
    const core = await verifyAttempt(attempt, authority, this.#options.epochKeys)
    check(receipt.payload.attemptId === attempt.id && receipt.payload.author === attempt.payload.header.author &&
      receipt.payload.operationId === attempt.payload.header.operationId && receipt.payload.generation === attempt.payload.header.generation &&
      receipt.payload.bodyHash === await bytesDigest(encodePeerValue(attempt)) && receipt.payload.bodyBytes === encodePeerValue(attempt).length,
    'PEER_ORDER_BODY_MISMATCH')
    const entries = this.#records.get(generation.id), head = this.#heads.get(generation.id)
    check(entries !== undefined && head !== undefined, 'PEER_GENERATION_NOT_LOADED')
    const previous = entries.get(receipt.payload.sequence)
    if (previous !== undefined) {
      if (previous.command.receipt.root !== receipt.root) {
        this.#fenced.add(generation.id)
        if (persist) await this.#write(`${this.#prefix}/fence/${generation.id}`, encodePeerValue(receipt))
        throw new PeerGenerationError('PEER_COORDINATOR_EQUIVOCATION')
      }
      check(samePeerValue(previous.command, command), 'PEER_ORDER_IDENTITY_CONFLICT'); return
    }
    check(receipt.payload.sequence === head.sequence + 1 && receipt.payload.previousRoot === head.root, 'PEER_HISTORY_GAP')
    check(head.sequence < this.#maxRecords && this.#retainedBytes + receipt.payload.bodyBytes <= (this.#options.maxHistoryBytes ?? 128 * 1024 * 1024), 'PEER_STORAGE_QUOTA')
    const key = operationKey(receipt.payload.author, receipt.payload.operationId), existing = this.#operations.get(key)
    check(existing === undefined || existing === attempt.id, 'PEER_OPERATION_ID_REUSED')
    const knownOrder = this.#receipts.get(attempt.id)
    check(knownOrder === undefined || samePeerValue(knownOrder.receipt, receipt), 'PEER_ATTEMPT_ORDERED_TWICE')
    const next = { sequence: receipt.payload.sequence, root: receipt.root, bytes: head.bytes + receipt.payload.bodyBytes }
    if (persist) {
      // Persist exact original body and signed receipt before publishing the head.
      await this.#write(`${this.#prefix}/record/${generation.id}/${next.sequence}`, encodePeerValue(command))
      await this.#write(`${this.#prefix}/head/${generation.id}`, encodePeerValue(next))
    }
    this.#heads.set(generation.id, next); entries.set(next.sequence, { command: structuredClone(command), core })
    this.#remember(attempt, core); this.#receipts.set(attempt.id, structuredClone(command)); this.#retainedBytes += receipt.payload.bodyBytes
  }
  #selectedHistory(authority: PeerAuthority): Retained[] {
    const result: Retained[] = []
    for (const segment of authority.selectedSegments()) {
      const head = this.#heads.get(segment.generation.id), records = this.#records.get(segment.generation.id)
      check(head !== undefined && records !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      const through = segment.cutoff?.sequence ?? head.sequence
      check(through <= head.sequence, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      if (segment.cutoff !== null) {
        const root = through === 0 ? records.get(1)?.command.receipt.payload.previousRoot ?? head.root : records.get(through)?.command.receipt.root
        check(root === segment.cutoff.root, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      }
      for (let sequence = 1; sequence <= through; sequence++) {
        const retained = records.get(sequence); check(retained !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE'); result.push(retained)
      }
    }
    return result
  }
  async #materialize(authority: PeerAuthority): Promise<void> {
    const selected = this.#selectedHistory(authority)
    // Receipt ancestry selects membership; the signed proposal always determines
    // execution order, including when a new receipt introduces an earlier intent.
    const executionOrder = [...selected].sort((left, right) => compareTransactionOrder(
      transactionOrderKey(left.core, hexToBytes(left.command.attempt.id)),
      transactionOrderKey(right.core, hexToBytes(right.command.attempt.id)),
    ))
    const proposals: ReplayProposal[] = executionOrder.map(({ command, core }) => ({
      txId: hexToBytes(command.attempt.id), candidateDigest: hexToBytes(command.attempt.payload.header.coreDigest),
      canonicalCandidate: encodeTransactionCore(core), core,
    }))
    const controls: PeerExecutionControls = { applicationId: hexToBytes(authority.descriptor.applicationId),
      currentRevision: authority.current!.payload.controlRevision,
      revisions: await Promise.all(authority.bundle.controls.map(async control => ({ revision: control.payload.revision,
        digest: hexToBytes(await peerDigest(control)), members: control.payload.grants.flatMap(grant => grant.dataRole === null ? [] :
          [{ publicKey: hexToBytes(grant.publicKey), role: grant.dataRole }]) }))) }
    const output = await this.#options.materializer.coordinator.materialize(proposals, controls)
    if (output !== null) await this.#options.materializer.publications.publish(output.publication)
    const generation = authority.current!, head = this.#heads.get(generation.id)!
    const revision: PeerRevision = { applicationId: authority.descriptor.applicationId, historyId: authority.descriptor.historyId,
      generation: generation.id, point: { generation: generation.id, sequence: head.sequence, root: head.root },
      controlRevision: generation.payload.controlRevision, materializationRevision: String(this.#options.materializer.queries.revision) }
    for (const item of selected) {
      const { receipt, attempt } = item.command
      const outcome = this.#options.materializer.queries.outcome(hexToBytes(attempt.id))
      check(outcome !== null, 'PEER_OUTCOME_MISSING')
      const result: AppliedResult = { status: 'applied', attemptId: attempt.id, operationId: receipt.payload.operationId,
        author: receipt.payload.author, generation: receipt.payload.generation, sequence: receipt.payload.sequence,
        outcome: outcome.outcome, rejectionCode: outcome.rejectionCode, revision }
      const previous = this.#lastOutcomes.get(attempt.id)
      if (previous === undefined || !samePeerValue(previous, result)) {
        await this.#write(`${this.#prefix}/result/${attempt.id}`, encodePeerValue(result))
      }
      this.#lastOutcomes.set(attempt.id, result)
    }
    // No await between these assignments: even synchronous status observers see
    // either the old complete publication or the new complete publication.
    this.#authority = authority
    this.#selected = selected; this.#executionOrder = executionOrder
    this.#selectedIds = new Set(selected.map(value => value.command.attempt.id))
    this.#publishedRevision = revision
    this.#ready = true
    const latest = executionOrder.at(-1)
    if (latest !== undefined) this.#observeApplied(latest.core.authorTimestampMs)
  }
  #publish(): void { for (const listener of [...this.#listeners]) { try { listener() } catch { /* Consumer failure cannot undo persistence. */ } } }
  #pointAvailable(point: HistoryPoint, authority = this.#authority): boolean {
    if (!authority.contains(point)) return false
    const head = this.#heads.get(point.generation), records = this.#records.get(point.generation)
    if (head === undefined || records === undefined || point.sequence > head.sequence) return false
    const root = point.sequence === 0 ? records.get(1)?.command.receipt.payload.previousRoot ?? head.root : records.get(point.sequence)?.command.receipt.root
    return root === point.root
  }
  #checkView(revision: PeerRevision): void {
    validatePeerRevision(revision)
    check(revision.applicationId === this.descriptor.applicationId && revision.historyId === this.descriptor.historyId &&
      this.#pointAvailable(revision.point), 'PEER_VIEW_RECOVERY_REQUIRED')
    check(revision.controlRevision === this.#authority.generation(revision.generation).payload.controlRevision,
      'PEER_REVISION_INVALID')
  }
  prepare(input: PrepareCommand): Promise<SignedAttempt> {
    const captured = structuredClone(input)
    return this.#serial.run(async () => {
      this.#assertReady(); boundedText(captured.operationId)
      check(Object.keys(captured).every(key => ['operationId', 'program', 'command', 'commandVersion', 'observedRevision', 'reapplyOf', 'authorTimestampMs'].includes(key)),
        'PEER_COMMAND_OPTIONS_INVALID')
      const previousId = this.#operations.get(operationKey(this.device.publicKey, captured.operationId))
      if (previousId !== undefined) {
        const previous = this.#attempts.get(previousId)!, core = await verifyAttempt(previous, this.#authority, this.#options.epochKeys)
        check(bytesToHex(encodeChangeProgram(core.program)) === bytesToHex(encodeChangeProgram(captured.program)) &&
          previous.payload.header.command === (captured.command ?? 'raw') && previous.payload.header.commandVersion === (captured.commandVersion ?? '1') &&
          previous.payload.header.reapplyOf === (captured.reapplyOf ?? null) &&
          (captured.authorTimestampMs === undefined || captured.authorTimestampMs === core.authorTimestampMs) &&
          (captured.observedRevision === undefined || samePeerValue(previous.payload.header.observedRevision, captured.observedRevision)), 'PEER_OPERATION_ID_REUSED')
        return structuredClone(previous)
      }
      const generation = this.generation, control = this.#authority.controlAt(generation.payload.controlRevision)
      check(this.#authority.grant(this.device.publicKey, control.payload.revision)?.writer === true, 'PEER_AUTHOR_FORBIDDEN')
      if (captured.observedRevision !== undefined) this.#checkView(captured.observedRevision)
      if (captured.reapplyOf !== undefined) {
        const old = this.#attempts.get(captured.reapplyOf)
        check(old !== undefined && !this.#selectedIds.has(old.id) && old.payload.header.generation !== generation.id, 'PEER_REAPPLY_SOURCE_INVALID')
      }
      const key = this.#options.epochKeys.get(control.payload.epoch); check(key !== undefined, 'PEER_EPOCH_KEY_UNAVAILABLE')
      const core: TransactionCore = { operationId: captured.operationId, groupId: hexToBytes(this.descriptor.applicationId),
        membershipRevision: hexToBytes(await peerDigest(control)), validationPolicy: hexToBytes(await peerDigest([this.descriptor.profile, this.descriptor.policy])),
        authorId: hexToBytes(this.device.publicKey), authorTimestampMs: captured.authorTimestampMs ?? nextAuthorTimestampMs(BigInt(this.#now()),
          [this.#authoredTimestampMs, this.#observedTimestampMs].filter(value => value !== null)),
        nonce: crypto.getRandomValues(new Uint8Array(16)), executionManifestDigest: hexToBytes(this.descriptor.executionManifestDigest), program: captured.program }
      const attempt = await createSignedAttempt({ applicationId: this.descriptor.applicationId, profile: 'peer-generation-v1',
        generation: generation.id, controlRevision: control.payload.revision, epoch: control.payload.epoch, author: this.device.publicKey,
        operationId: captured.operationId, definitionDigest: this.descriptor.definitionDigest, command: captured.command ?? 'raw',
        commandVersion: captured.commandVersion ?? '1', observedRevision: captured.observedRevision ?? null, reapplyOf: captured.reapplyOf ?? null,
        coreDigest: bytesToHex(await transactionDigest(core)) }, core, key, this.device)
      await verifyAttempt(attempt, this.#authority, this.#options.epochKeys)
      check(this.#journalHead < this.#maxRecords, 'PEER_STORAGE_QUOTA')
      await this.#write(`${this.#prefix}/journal/${this.#journalHead + 1}`, encodePeerValue(attempt))
      await this.#write(`${this.#prefix}/journal-head`, encodePeerValue(this.#journalHead + 1))
      this.#journalHead++; this.#remember(attempt, core); this.#publish(); return structuredClone(attempt)
    })
  }
  order(input: SignedAttempt): Promise<OrderedCommand> {
    const attempt = structuredClone(input)
    return this.#serial.run(async () => {
      this.#assertReady(); check(this.isCoordinator, 'PEER_NOT_COORDINATOR'); check(!this.#fenced.has(this.generation.id), 'PEER_COORDINATOR_FENCED')
      await verifyAttempt(attempt, this.#authority, this.#options.epochKeys)
      const existing = this.#receipts.get(attempt.id)
      if (existing !== undefined) {
        check(this.#selectedIds.has(attempt.id), 'PEER_ATTEMPT_ABANDONED')
        return structuredClone(existing)
      }
      check(attempt.payload.header.generation === this.generation.id, 'PEER_ATTEMPT_NEEDS_REAPPLY')
      if (attempt.payload.header.observedRevision !== null) this.#checkView(attempt.payload.header.observedRevision)
      const head = this.#heads.get(this.generation.id)!
      const payload = { applicationId: this.descriptor.applicationId, profile: 'peer-generation-v1' as const,
        generation: this.generation.id, sequence: head.sequence + 1, previousRoot: head.root, attemptId: attempt.id,
        author: attempt.payload.header.author, operationId: attempt.payload.header.operationId,
        bodyHash: await bytesDigest(encodePeerValue(attempt)), bodyBytes: encodePeerValue(attempt).length }
      const receipt = { ...await signPeerValue(DOMAINS.peerOrder, payload, this.device), root: await peerDigest(['chronolog/peer-generation/order/v1', payload]) }
      const command = { receipt, attempt }
      await this.#retain(command, this.#authority, true)
      try { await this.#materialize(this.#authority) } catch (error) { this.#closed = true; throw error }
      this.#publish(); return structuredClone(command)
    })
  }
  ingest(input: readonly OrderedCommand[]): Promise<void> {
    const commands = structuredClone(input)
    return this.#serial.run(async () => {
      this.#assertOpen(); check(commands.length <= 4096, 'PEER_REPLICATION_BATCH_LIMIT')
      for (const command of commands) await this.#retain(command, this.#authority, true)
      try { await this.#materialize(this.#authority) } catch (error) { this.#closed = true; throw error }
      this.#publish()
    })
  }
  adopt(authority: AuthorityBundle): Promise<RecoveryNotice | null> { return this.synchronize(authority, []) }
  synchronize(input: AuthorityBundle, inputCommands: readonly OrderedCommand[]): Promise<RecoveryNotice | null> {
    const bundle = structuredClone(input), commands = structuredClone(inputCommands)
    return this.#serial.run(async () => {
      this.#assertOpen(); check(commands.length <= this.#maxRecords, 'PEER_REPLICATION_BATCH_LIMIT')
      const next = await verifyAuthorityBundle(bundle, this.#authority.bundle.descriptor)
      assertExtension(this.#authority, next)
      for (const generation of next.bundle.generations) await this.#loadGeneration(generation, next)
      for (const command of commands) await this.#retain(command, next, true)
      const previous = this.generation, previousIds = new Set(this.#selectedIds)
      this.#selectedHistory(next)
      // Pin selection before publishing the new materialization. A crash can
      // replay the retained evidence; readers remain serialized until both agree.
      await this.#write(`${this.#prefix}/authority`, encodePeerValue(next.bundle))
      try { await this.#materialize(next) } catch (error) { this.#closed = true; throw error }
      this.#authority = next
      let notice: RecoveryNotice | null = null
      if (previous.id !== this.generation.id) {
        const abandoned: OperationState[] = []
        for (const [id, attempt] of this.#attempts) if (!this.#selectedIds.has(id) && attempt.payload.header.generation !== this.generation.id) abandoned.push(this.#state(attempt))
        notice = { previousGeneration: previous.id, generation: this.generation.id, adopted: this.generation.payload.adopted,
          revision: this.revision, abandoned: abandoned.slice(0, 1024),
          unknownLoss: ![...previousIds].some(id => !this.#selectedIds.has(id)) }
        this.#recoveries.push(structuredClone(notice)); if (this.#recoveries.length > 32) this.#recoveries.shift()
        await this.#write(`${this.#prefix}/recoveries`, encodePeerValue(this.#recoveries))
        for (const listener of [...this.#recoveryListeners]) { try { listener(structuredClone(notice)) } catch { /* Observers are isolated. */ } }
      }
      this.#publish(); return notice
    })
  }
  #state(attempt: SignedAttempt): OperationState {
    const header = attempt.payload.header, previous = this.#lastOutcomes.get(attempt.id)
    if (this.#selectedIds.has(attempt.id)) { check(previous !== undefined, 'PEER_OUTCOME_MISSING'); return structuredClone(previous) }
    if (header.generation === this.generation.id) return { status: 'saved', attemptId: attempt.id, operationId: header.operationId, generation: header.generation }
    return { status: this.#receipts.has(attempt.id) ? 'abandoned' : 'needsReapply', attemptId: attempt.id,
      operationId: header.operationId, generation: header.generation, selectedGeneration: this.generation.id, previous: structuredClone(previous ?? null) }
  }
  operation(operationId: string, author = this.device.publicKey): Promise<OperationState | null> {
    return this.#serial.run(async () => { this.#assertOpen(); const id = this.#operations.get(operationKey(author, operationId)); return id === undefined ? null : this.#state(this.#attempts.get(id)!) })
  }
  attempt(operationId: string, author = this.device.publicKey): Promise<SignedAttempt | null> {
    return this.#serial.run(async () => { this.#assertOpen(); const id = this.#operations.get(operationKey(author, operationId)); return structuredClone(id === undefined ? null : this.#attempts.get(id)!) })
  }
  pendingAttempts(): Promise<readonly SignedAttempt[]> {
    return this.#serial.run(async () => { this.#assertOpen(); return [...this.#attempts.values()].filter(value => value.payload.header.generation === this.generation.id && !this.#receipts.has(value.id)).map(value => structuredClone(value)) })
  }
  capture(): Promise<CapturedPeerView> {
    return this.#serial.run(async () => {
      this.#assertReady()
      const read = this.#options.materializer.queries.captureRead()
      const outcomes = this.#executionOrder.map(value => this.#options.materializer.queries.outcome(hexToBytes(value.command.attempt.id))!)
      return { authority: this.authority, revision: this.revision, read, outcomes: structuredClone(outcomes), release: () => read.release() }
    })
  }
  async #proof(point: HistoryPoint): Promise<PrefixProof> {
    validateHistoryPoint(point); check(this.#pointAvailable(point), 'PEER_RECOVERY_PREFIX_INCOMPLETE')
    const records = this.#records.get(point.generation)!, segment = this.#authority.selectedSegments().find(value => value.generation.id === point.generation)!
    const receipt = point.sequence === 0 ? null : records.get(point.sequence)!.command.receipt
    const bridge = segment.cutoff === null ? [] : Array.from({ length: segment.cutoff.sequence - point.sequence }, (_, index) => records.get(point.sequence + index + 1)!.command.receipt)
    check(bridge.length <= 4096, 'PEER_PREFIX_PROOF_TOO_LARGE')
    return structuredClone({ point, receipt, bridge })
  }
  recoveryPoint(): Promise<PrefixProof> { return this.#serial.run(async () => { this.#assertReady(); return this.#proof(this.revision.point) }) }
  prefixProof(point: HistoryPoint): Promise<PrefixProof> { return this.#serial.run(async () => { this.#assertReady(); return this.#proof(point) }) }
  exportCommands(options: { readonly after?: HistoryPoint; readonly offset?: number; readonly limit?: number; readonly at?: PeerRevision } = {}): Promise<readonly OrderedCommand[]> {
    return this.#serial.run(async () => {
      this.#assertReady(); let start = 0, end = this.#selected.length
      if (options.at !== undefined) {
        this.#checkView(options.at)
        check(options.at.generation === this.generation.id && options.at.point.generation === this.generation.id, 'PEER_VIEW_RECOVERY_REQUIRED')
        end -= this.revision.point.sequence - options.at.point.sequence
      }
      if (options.offset !== undefined) {
        check(options.after === undefined && Number.isSafeInteger(options.offset) && options.offset >= 0 && options.offset <= end, 'PEER_RANGE_OFFSET_INVALID')
        start = options.offset
      }
      if (options.after !== undefined) {
        check(this.#pointAvailable(options.after), 'PEER_CURSOR_RECOVERY_REQUIRED')
        if (options.after.sequence > 0) {
          start = this.#selected.findIndex(value => value.command.receipt.payload.generation === options.after!.generation && value.command.receipt.payload.sequence === options.after!.sequence) + 1
          check(start > 0, 'PEER_CURSOR_RECOVERY_REQUIRED')
        } else {
          start = this.#selected.findIndex(value => value.command.receipt.payload.generation === options.after!.generation)
          if (start < 0) start = this.#selected.length
        }
      }
      const limit = options.limit ?? this.#maxRecords
      check(Number.isSafeInteger(limit) && limit > 0 && limit <= this.#maxRecords, 'PEER_RANGE_LIMIT_INVALID')
      return this.#selected.slice(start, Math.min(end, start + limit)).map(value => structuredClone(value.command))
    })
  }
  retainedCoverage(input?: HistoryPoint): Promise<SignedRetainedCoverage> {
    const requested = input === undefined ? undefined : structuredClone(input)
    return this.#serial.run(async () => {
      this.#assertReady()
      const point = requested ?? this.revision.point
      check(this.#pointAvailable(point), 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      return signPeerValue(DOMAINS.peerCoverage, { applicationId: this.descriptor.applicationId, generation: this.generation.id,
        point, peer: this.device.publicKey, storageId: this.#options.storageId, retainedAt: this.#now() }, this.device)
    })
  }
  observeCoverage(input: SignedRetainedCoverage): Promise<void> {
    const coverage = structuredClone(input)
    return this.#serial.run(async () => {
      this.#assertReady(); const value = coverage.payload
      await verifyPeerValue(DOMAINS.peerCoverage, coverage, value.peer)
      boundedText(value.storageId, 256)
      check(value.applicationId === this.descriptor.applicationId && value.generation === this.generation.id &&
        this.#authority.grant(value.peer)?.reader === true && this.#pointAvailable(value.point) && Number.isSafeInteger(value.retainedAt) && value.retainedAt >= 0,
      'PEER_COVERAGE_INVALID')
      this.#coverage.set(`${value.peer}/${value.storageId}`, coverage); this.#publish()
    })
  }
  shared(point = this.revision.point): readonly SignedRetainedCoverage[] {
    this.#assertReady()
    return [...this.#coverage.values()].filter(value => value.payload.storageId !== this.#options.storageId &&
      value.payload.peer !== this.device.publicKey && value.payload.generation === this.generation.id &&
      this.#pointAvailable(value.payload.point) && this.#authority.atOrAfter(value.payload.point, point)).map(value => structuredClone(value))
  }
  #now(): number { const now = (this.#options.now ?? Date.now)(); check(Number.isSafeInteger(now) && now >= 0, 'PEER_CLOCK_INVALID'); return now }
  subscribe(listener: () => void): () => void { this.#listeners.add(listener); return () => this.#listeners.delete(listener) }
  onRecovery(listener: (notice: RecoveryNotice) => void): () => void { this.#recoveryListeners.add(listener); return () => this.#recoveryListeners.delete(listener) }
  inspectRecovery(): readonly RecoveryNotice[] { return structuredClone(this.#recoveries) }
  async close(): Promise<void> {
    await this.#serial.run(async () => {
      if (this.#disposed) return
      this.#disposed = true
      this.#closed = true; this.#listeners.clear(); this.#recoveryListeners.clear()
      try { await this.#options.materializer.close() }
      finally { activeOwners.get(this.#options.store)?.delete(this.descriptor.applicationId) }
    })
  }
}

function assertExtension(previous: PeerAuthority, next: PeerAuthority): void {
  const old = previous.bundle, current = next.bundle
  check(current.generations.length >= old.generations.length && current.controls.length >= old.controls.length, 'PEER_AUTHORITY_REGRESSION')
  for (let index = 0; index < old.generations.length; index++) check(samePeerValue(old.generations[index], current.generations[index]), 'PEER_CONTROL_EQUIVOCATION')
  for (let index = 0; index < old.controls.length; index++) check(samePeerValue(old.controls[index], current.controls[index]), 'PEER_CONTROL_EQUIVOCATION')
}
export async function createPeerReplica(options: PeerReplicaOptions): Promise<PeerReplica> {
  const authority = await verifyAuthorityBundle(options.authority)
  boundedText(options.storageId, 256)
  let owners = activeOwners.get(options.store)
  if (owners === undefined) { owners = new Set(); activeOwners.set(options.store, owners) }
  check(!owners.has(authority.descriptor.applicationId), 'PEER_STORAGE_BUSY')
  owners.add(authority.descriptor.applicationId)
  const replica = new Replica(options, authority)
  try { await replica.initialize(); return replica }
  catch (error) { await replica.close(); throw error }
}

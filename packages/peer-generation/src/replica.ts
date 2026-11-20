import type { BytesStore } from '@chronolog/records'
import {
  DOMAINS, encodeChangeProgram, encodeTransactionCore, transactionDigest,
  type TransactionCore,
} from '@chronolog/protocol'
import type { ReplayProposal, PeerExecutionControls } from '@chronolog/materializer'
import { createSignedAttempt, validatePeerRevision, verifyAttempt } from './attempt.js'
import {
  boundedText, bytesDigest, bytesToHex, check, isArray, decodePeerValue, encodePeerValue, hex, object,
  hexToBytes, peerDigest, PeerGenerationError, samePeerValue, Serial, signPeerValue, verifyPeerValue,
} from './codec.js'
import { assertAuthorityExtension, generationStartRoot, type PeerAuthority, validateHistoryPoint, verifyAuthorityBundle, verifyOrderReceipt } from './control.js'
import { PEER_MAX_RECORDS, PEER_MAX_HISTORY_BYTES } from './control-types.js'
import type {
  AppliedResult, AuthorityBundle, CapturedPeerView, HistoryPoint, HistoryReceiveResult, OperationState, OrderedCommand,
  PeerGrant, PeerReplica, PeerReplicaOptions, PeerRevision, PeerOrderingPause, PrefixProof, PrepareCommand,
  RecoveryNotice, SignedAttempt, SignedGeneration, SignedRetainedCoverage,
} from './types.js'

interface Head { readonly sequence: number; readonly root: string; readonly bytes: number }
interface Retained { readonly command: OrderedCommand; readonly proposal: ReplayProposal }
interface SelectedRange {
  readonly generation: string
  readonly offset: number
  readonly length: number
  readonly records: ReadonlyMap<number, Retained>
}
interface PendingRecovery {
  readonly previousGeneration: string
  readonly generation: string
  readonly knownAttemptId: string | null
}
interface StoredSelection { readonly authority: AuthorityBundle; readonly recovery: PendingRecovery | null }
interface StoredOrderingPause extends PeerOrderingPause { readonly applicationId: string; readonly author: string }
const activeOwners = new WeakMap<BytesStore, Set<string>>()
const operationKey = (author: string, operationId: string): string => `${author}\u0000${operationId}`

/** One durable history/journal owner shared by browser and native sessions. */
class Replica implements PeerReplica {
  readonly queryCapabilities: PeerReplica['queryCapabilities']
  readonly #options: PeerReplicaOptions
  readonly #serial = new Serial()
  #authority: PeerAuthority
  #closed = false
  #disposed = false
  #ready = false
  #publishedRevision: PeerRevision | null = null
  #pendingRecovery: PendingRecovery | null = null
  #orderingPause: StoredOrderingPause | null = null
  #journalHead = 0
  #retainedBytes = 0
  readonly #heads = new Map<string, Head>()
  readonly #records = new Map<string, Map<number, Retained>>()
  readonly #attempts = new Map<string, SignedAttempt>()
  readonly #operations = new Map<string, string>()
  readonly #receipts = new Map<string, OrderedCommand>()
  #selected: Retained[] = []
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
    this.queryCapabilities = Object.freeze({ sql: options.materializer.queries.capabilities.sql })
    this.#prefix = `peer-generation/replica/${authority.descriptor.applicationId}`
  }
  get descriptor() { return this.#authority.descriptor }
  get device() { return this.#options.device }
  get storageId(): string { return this.#options.storageId }
  get requiredEpochs(): readonly number[] {
    return [...new Set(this.#authority.selectedSegments().filter(segment => segment.cutoff?.sequence !== 0)
      .map(segment => this.#authority.controlAt(segment.generation.payload.controlRevision).payload.epoch))].sort((a, b) => a - b)
  }
  get authority() { return this.#authority.bundle }
  get generation(): SignedGeneration {
    const generation = this.#authority.current; check(generation !== null, 'PEER_NO_SELECTED_GENERATION'); return generation
  }
  get isCoordinator(): boolean { return this.generation.payload.coordinator === this.device.publicKey }
  grant(publicKey: string): PeerGrant | null { this.#assertOpen(); return this.#authority.grant(publicKey) }
  get closed(): boolean { return this.#closed }
  get ready(): boolean { return !this.#closed && this.#ready }
  get retainedPoint(): HistoryPoint | null {
    this.#assertOpen()
    let point: HistoryPoint | null = null
    for (const segment of this.#authority.selectedSegments()) {
      const head = this.#heads.get(segment.generation.id), records = this.#records.get(segment.generation.id)
      check(head !== undefined && records !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      const requested = segment.cutoff?.sequence ?? head.sequence
      const through = Math.min(requested, head.sequence)
      if (through > 0) {
        const command = records.get(through)?.command
        check(command !== undefined, 'PEER_HISTORY_INCOMPLETE')
        point = { generation: segment.generation.id, sequence: through, root: command.receipt.root }
      }
      if (through < requested) break
    }
    return point
  }
  get revision(): PeerRevision {
    this.#assertOpen()
    check(this.#ready && this.#publishedRevision !== null, 'PEER_RECOVERING')
    return structuredClone(this.#publishedRevision)
  }
  async initialize(): Promise<void> {
    const stored = await this.#options.store.get(`${this.#prefix}/selection`)
    let previous: PeerAuthority | undefined
    if (stored !== null) {
      const selection = decodePeerValue<StoredSelection>(stored)
      object(selection, ['authority', 'recovery'])
      previous = await verifyAuthorityBundle(selection.authority, this.#authority.bundle.descriptor)
      if (previous.bundle.generations.length > this.#authority.bundle.generations.length) {
        assertAuthorityExtension(this.#authority, previous); this.#authority = previous
      } else assertAuthorityExtension(previous, this.#authority)
      if (selection.recovery !== null) {
        object(selection.recovery, ['previousGeneration', 'generation', 'knownAttemptId'])
        hex(selection.recovery.previousGeneration); hex(selection.recovery.generation)
        if (selection.recovery.knownAttemptId !== null) hex(selection.recovery.knownAttemptId)
        check(selection.recovery.generation === previous.current?.id, 'PEER_RECOVERY_JOURNAL_INVALID')
        previous.generation(selection.recovery.previousGeneration)
        this.#pendingRecovery = { ...selection.recovery, generation: this.generation.id }
      }
    }
    check(this.#authority.current !== null, 'PEER_NO_SELECTED_GENERATION')
    check(bytesToHex(this.#options.materializer.queries.executionManifestDigest) === this.descriptor.executionManifestDigest,
      'PEER_EXECUTION_MANIFEST_MISMATCH')
    const journal = await this.#options.store.get(`${this.#prefix}/journal-head`)
    this.#journalHead = journal === null ? 0 : decodePeerValue<number>(journal)
    check(Number.isSafeInteger(this.#journalHead) && this.#journalHead >= 0 && this.#journalHead <= this.#maxRecords, 'PEER_JOURNAL_INVALID')
    for (let index = 1; index <= this.#journalHead; index++) {
      const bytes = await this.#options.store.get(`${this.#prefix}/journal/${index}`)
      check(bytes !== null, 'PEER_JOURNAL_INCOMPLETE')
      const attempt = decodePeerValue<SignedAttempt>(bytes)
      await verifyAttempt(attempt, this.#authority, this.#options.epochKeys)
      this.#remember(attempt)
    }
    for (const generation of this.#authority.bundle.generations) await this.#loadGeneration(generation, this.#authority)
    const pauseBytes = await this.#options.store.get(`${this.#prefix}/ordering-pause`)
    if (pauseBytes !== null) {
      const pause = decodePeerValue<StoredOrderingPause | null>(pauseBytes)
      if (pause !== null) {
        object(pause, ['operationId', 'applicationId', 'author', 'generation', 'base'])
        boundedText(pause.operationId); hex(pause.generation)
        check(pause.applicationId === this.descriptor.applicationId && pause.author === this.device.publicKey &&
          this.#authority.generation(pause.generation).payload.coordinator === pause.author &&
          pause.base.point.generation === pause.generation, 'PEER_ORDERING_PAUSE_INVALID')
        await this.#authority.verifyPrefix(pause.base)
        this.#orderingPause = pause
      }
    }
    const previousGeneration = previous?.current
    if (previous !== undefined && previousGeneration !== null && previousGeneration !== undefined && previousGeneration.id !== this.generation.id && this.#pendingRecovery === null) {
      const known = this.#selectedHistory(previous, false).at(-1)?.command.attempt.id ?? null
      this.#pendingRecovery = { previousGeneration: previousGeneration.id, generation: this.generation.id, knownAttemptId: known }
    }
    if (this.#pendingRecovery?.knownAttemptId !== undefined && this.#pendingRecovery.knownAttemptId !== null) {
      check(this.#attempts.has(this.#pendingRecovery.knownAttemptId), 'PEER_RECOVERY_JOURNAL_INVALID')
    }
    const recoveryBytes = await this.#options.store.get(`${this.#prefix}/recoveries`)
    if (recoveryBytes !== null) {
      const notices = decodePeerValue<RecoveryNotice[]>(recoveryBytes)
      check(isArray(notices) && notices.length <= 32, 'PEER_RECOVERY_JOURNAL_INVALID')
      this.#recoveries.push(...notices)
    }
    // Selection and its recovery baseline are one atomic pointer. Reopening
    // cannot forget an accepted generation or confuse it with a published view.
    await this.#writeSelection(this.#authority, this.#pendingRecovery)
    try { await this.#materialize(this.#authority); await this.#finishRecovery(false) }
    catch (error) { if (!(error instanceof PeerGenerationError) || error.code !== 'PEER_RECOVERY_PREFIX_INCOMPLETE') throw error }
  }
  get #maxRecords(): number { return this.#options.maxRecords ?? PEER_MAX_RECORDS }
  #assertOpen(): void { check(!this.#closed, 'PEER_REPLICA_CLOSED') }
  #fail(error: unknown): never {
    if (!this.#closed) { this.#closed = true; this.#ready = false; this.#publish() }
    throw error
  }
  #assertReady(): void {
    this.#assertOpen(); check(this.#ready, 'PEER_RECOVERING')
    check(this.#authority.grant(this.device.publicKey)?.reader === true, 'PEER_READER_FORBIDDEN')
  }
  async #checkCurrentKey(): Promise<void> {
    const control = this.#authority.control, key = this.#options.epochKeys.get(control.payload.epoch)
    check(key !== undefined, 'PEER_EPOCH_KEY_UNAVAILABLE')
    check(key.length === 32 && await bytesDigest(key) === control.payload.keyDigest, 'PEER_EPOCH_KEY_MISMATCH')
  }
  async #write(key: string, bytes: Uint8Array): Promise<void> {
    try { await this.#options.store.put(key, bytes) }
    catch (error) {
      // An atomic write may have committed before its reply was lost. Reopen;
      // never continue from stale signing or sequence state.
      this.#fail(error)
    }
  }
  #writeSelection(authority: PeerAuthority, recovery: PendingRecovery | null): Promise<void> {
    return this.#write(`${this.#prefix}/selection`, encodePeerValue({ authority: authority.bundle, recovery } satisfies StoredSelection))
  }
  #remember(attempt: SignedAttempt): void {
    const key = operationKey(attempt.payload.header.author, attempt.payload.header.operationId)
    const previous = this.#operations.get(key)
    check(previous === undefined || previous === attempt.id, 'PEER_OPERATION_ID_REUSED')
    this.#operations.set(key, attempt.id); this.#attempts.set(attempt.id, structuredClone(attempt))
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
        this.#lastOutcomes.set(command.attempt.id, result)
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
    const recordBytes = encodePeerValue(command)
    check(this.#receipts.size < this.#maxRecords && this.#retainedBytes + recordBytes.length + 2 <= (this.#options.maxHistoryBytes ?? PEER_MAX_HISTORY_BYTES), 'PEER_STORAGE_QUOTA')
    const key = operationKey(receipt.payload.author, receipt.payload.operationId), existing = this.#operations.get(key)
    check(existing === undefined || existing === attempt.id, 'PEER_OPERATION_ID_REUSED')
    const knownOrder = this.#receipts.get(attempt.id)
    check(knownOrder === undefined || samePeerValue(knownOrder.receipt, receipt), 'PEER_ATTEMPT_ORDERED_TWICE')
    const next = { sequence: receipt.payload.sequence, root: receipt.root, bytes: head.bytes + receipt.payload.bodyBytes }
    if (persist) {
      // Persist exact original body and signed receipt before publishing the head.
      await this.#write(`${this.#prefix}/record/${generation.id}/${next.sequence}`, recordBytes)
      await this.#write(`${this.#prefix}/head/${generation.id}`, encodePeerValue(next))
    }
    this.#heads.set(generation.id, next)
    entries.set(next.sequence, { command: structuredClone(command), proposal: {
      txId: hexToBytes(attempt.id), candidateDigest: hexToBytes(attempt.payload.header.coreDigest),
      canonicalCandidate: encodeTransactionCore(core), core,
    } })
    this.#remember(attempt); this.#receipts.set(attempt.id, structuredClone(command)); this.#retainedBytes += recordBytes.length + 2
  }
  /** Describe retained selected segments without visiting their individual records. */
  #selectedRanges(authority: PeerAuthority, complete = true): SelectedRange[] {
    const ranges: SelectedRange[] = []
    let offset = 0
    for (const segment of authority.selectedSegments()) {
      const head = this.#heads.get(segment.generation.id), records = this.#records.get(segment.generation.id)
      check(head !== undefined && records !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      const requested = segment.cutoff?.sequence ?? head.sequence
      if (complete) check(requested <= head.sequence, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      const through = Math.min(requested, head.sequence)
      if (segment.cutoff !== null && requested <= head.sequence) {
        const root = through === 0 ? records.get(1)?.command.receipt.payload.previousRoot ?? head.root : records.get(through)?.command.receipt.root
        check(root === segment.cutoff.root, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      }
      ranges.push({ generation: segment.generation.id, offset, length: through, records })
      offset += through
      // Later generations cannot fill an earlier missing prefix. Export the
      // available evidence without publishing an incomplete application view.
      if (through < requested) break
    }
    return ranges
  }
  #selectedHistory(authority: PeerAuthority, complete = true): Retained[] {
    const result: Retained[] = []
    for (const range of this.#selectedRanges(authority, complete)) {
      for (let sequence = 1; sequence <= range.length; sequence++) {
        const retained = range.records.get(sequence); check(retained !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE'); result.push(retained)
      }
    }
    return result
  }
  async #materialize(authority: PeerAuthority): Promise<void> {
    const generation = authority.current!, head = this.#heads.get(generation.id)!, published = this.#publishedRevision
    const continuing = this.#ready && published !== null && published.generation === generation.id &&
      published.controlRevision === generation.payload.controlRevision
    let selected: Retained[]
    if (continuing) {
      // A selected generation only appends. Selection/control changes and
      // restart take the full verified-history path below.
      check(head.sequence >= published.point.sequence, 'PEER_HISTORY_REGRESSION')
      if (head.sequence === published.point.sequence) {
        check(head.root === published.point.root, 'PEER_HEAD_ROOT_MISMATCH'); return
      }
      selected = this.#selected.slice()
      const records = this.#records.get(generation.id)!
      for (let sequence = published.point.sequence + 1; sequence <= head.sequence; sequence++) {
        const retained = records.get(sequence); check(retained !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE'); selected.push(retained)
      }
    } else selected = this.#selectedHistory(authority)
    const previousLength = this.#selected.length
    await this.#replay(selected, authority, continuing)
    // Control may already have advanced while ready=false. Publish all view
    // metadata together before allowing readers to observe the complete prefix.
    this.#authority = authority
    this.#selected = selected
    if (continuing) for (let index = previousLength; index < selected.length; index++) this.#selectedIds.add(selected[index]!.command.attempt.id)
    else this.#selectedIds = new Set(selected.map(value => value.command.attempt.id))
    this.#publishedRevision = { applicationId: authority.descriptor.applicationId, historyId: authority.descriptor.historyId,
      generation: generation.id, point: { generation: generation.id, sequence: head.sequence, root: head.root },
      controlRevision: generation.payload.controlRevision, materializationRevision: String(this.#options.materializer.queries.revision) }
    this.#ready = true
  }
  /** Replay also validates a recovery candidate without publishing it as the selected application view. */
  async #replay(selected: readonly Retained[], authority: PeerAuthority, continuing = false): Promise<void> {
    const admitted = selected.map(value => value.proposal)
    const controls: PeerExecutionControls = { applicationId: hexToBytes(authority.descriptor.applicationId),
      attemptGenerations: selected.map(value => ({ attemptId: hexToBytes(value.command.attempt.id), generation: hexToBytes(value.command.attempt.payload.header.generation) })),
      currentRevision: authority.current!.payload.controlRevision,
      revisions: await Promise.all(authority.bundle.controls.map(async control => ({ revision: control.payload.revision,
        digest: hexToBytes(await peerDigest(control)), members: control.payload.grants.flatMap(grant => grant.dataRole === null ? [] :
          [{ publicKey: hexToBytes(grant.publicKey), role: grant.dataRole }]) }))) }
    const output = await this.#options.materializer.coordinator.materialize(admitted, controls)
    if (output !== null) await this.#options.materializer.publications.publish(output.publication)
    const previousLength = this.#selected.length, changedFrom = output?.revision.earliestChangedOrderIndex ?? previousLength
    check(Number.isSafeInteger(changedFrom) && changedFrom >= 0 && (output === null || changedFrom <= selected.length), 'PEER_MATERIALIZATION_BOUNDARY_INVALID')
    const inspectFrom = continuing ? Math.min(previousLength, changedFrom) : 0
    for (const item of selected.slice(inspectFrom)) {
      const { receipt, attempt } = item.command
      const outcome = this.#options.materializer.queries.outcome(hexToBytes(attempt.id))
      check(outcome !== null, 'PEER_OUTCOME_MISSING')
      const result: AppliedResult = { status: 'applied', attemptId: attempt.id, operationId: receipt.payload.operationId,
        author: receipt.payload.author, generation: receipt.payload.generation, sequence: receipt.payload.sequence,
        outcome: outcome.outcome, rejectionCode: outcome.rejectionCode }
      const previous = this.#lastOutcomes.get(attempt.id)
      check(previous === undefined || samePeerValue(previous, result), 'PEER_REPLAY_OUTCOME_CONFLICT')
      if (previous === undefined) await this.#write(`${this.#prefix}/result/${attempt.id}`, encodePeerValue(result))
      this.#lastOutcomes.set(attempt.id, result)
    }
  }
  async #finishRecovery(notify: boolean): Promise<RecoveryNotice | null> {
    const pending = this.#pendingRecovery
    if (pending === null) return null
    let notice = this.#recoveries.find(value => value.previousGeneration === pending.previousGeneration && value.generation === pending.generation)
    if (notice === undefined) {
      const abandoned: OperationState[] = []
      for (const [id, attempt] of this.#attempts) {
        if (!this.#selectedIds.has(id) && attempt.payload.header.generation !== this.generation.id) abandoned.push(this.#state(attempt))
      }
      notice = { previousGeneration: pending.previousGeneration, generation: pending.generation, adopted: this.generation.payload.adopted,
        revision: this.revision, abandoned: abandoned.slice(0, 1024),
        unknownLoss: true }
      const recoveries = [...this.#recoveries, structuredClone(notice)].slice(-32)
      await this.#write(`${this.#prefix}/recoveries`, encodePeerValue(recoveries))
      this.#recoveries.splice(0, this.#recoveries.length, ...recoveries)
    }
    await this.#writeSelection(this.#authority, null)
    this.#pendingRecovery = null
    if (notify) {
      for (const listener of [...this.#recoveryListeners]) { try { listener(structuredClone(notice)) } catch { /* Observers are isolated. */ } }
    }
    return structuredClone(notice)
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
  }
  prepare(input: PrepareCommand): Promise<SignedAttempt> {
    const captured = structuredClone(input)
    return this.#serial.run(async () => {
      this.#assertReady(); boundedText(captured.operationId)
      const previousId = this.#operations.get(operationKey(this.device.publicKey, captured.operationId))
      if (previousId !== undefined) {
        const previous = this.#attempts.get(previousId)!, core = await verifyAttempt(previous, this.#authority, this.#options.epochKeys)
        check(bytesToHex(encodeChangeProgram(core.program)) === bytesToHex(encodeChangeProgram(captured.program)) &&
          previous.payload.header.command === (captured.command ?? 'raw') && previous.payload.header.commandVersion === (captured.commandVersion ?? '1') &&
          previous.payload.header.reapplyOf === (captured.reapplyOf ?? null) &&
          (captured.basedOn === undefined || samePeerValue(previous.payload.header.basedOn, captured.basedOn)), 'PEER_OPERATION_ID_REUSED')
        return structuredClone(previous)
      }
      const generation = this.generation, control = this.#authority.controlAt(generation.payload.controlRevision)
      check(this.#authority.grant(this.device.publicKey, control.payload.revision)?.writer === true, 'PEER_AUTHOR_FORBIDDEN')
      if (captured.basedOn !== undefined) this.#checkView(captured.basedOn)
      if (captured.reapplyOf !== undefined) {
        const old = this.#attempts.get(captured.reapplyOf)
        check(old !== undefined && !this.#selectedIds.has(old.id) && old.payload.header.generation !== generation.id, 'PEER_REAPPLY_SOURCE_INVALID')
      }
      const key = this.#options.epochKeys.get(control.payload.epoch); check(key !== undefined, 'PEER_EPOCH_KEY_UNAVAILABLE')
      const core: TransactionCore = { operationId: captured.operationId, groupId: hexToBytes(this.descriptor.applicationId),
        membershipRevision: hexToBytes(await peerDigest(control)), validationPolicy: hexToBytes(await peerDigest([this.descriptor.profile, this.descriptor.policy])),
        authorId: hexToBytes(this.device.publicKey), authorTimestampMs: captured.authorTimestampMs ?? BigInt(this.#now()),
        nonce: crypto.getRandomValues(new Uint8Array(16)), executionManifestDigest: hexToBytes(this.descriptor.executionManifestDigest), program: captured.program }
      const attempt = await createSignedAttempt({ applicationId: this.descriptor.applicationId, profile: 'peer-generation-v1',
        generation: generation.id, controlRevision: control.payload.revision, epoch: control.payload.epoch, author: this.device.publicKey,
        operationId: captured.operationId, definitionDigest: this.descriptor.definitionDigest, command: captured.command ?? 'raw',
        commandVersion: captured.commandVersion ?? '1', basedOn: captured.basedOn ?? null, reapplyOf: captured.reapplyOf ?? null,
        coreDigest: bytesToHex(await transactionDigest(core)) }, core, key, this.device)
      await verifyAttempt(attempt, this.#authority, this.#options.epochKeys)
      check(this.#journalHead < this.#maxRecords, 'PEER_STORAGE_QUOTA')
      await this.#write(`${this.#prefix}/journal/${this.#journalHead + 1}`, encodePeerValue(attempt))
      await this.#write(`${this.#prefix}/journal-head`, encodePeerValue(this.#journalHead + 1))
      this.#journalHead++; this.#remember(attempt); this.#publish(); return structuredClone(attempt)
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
      check(this.#orderingPause === null, 'PEER_ORDERING_PAUSED')
      check(attempt.payload.header.generation === this.generation.id, 'PEER_ATTEMPT_NEEDS_REAPPLY')
      if (attempt.payload.header.basedOn !== null) this.#checkView(attempt.payload.header.basedOn)
      const head = this.#heads.get(this.generation.id)!
      const payload = { applicationId: this.descriptor.applicationId, profile: 'peer-generation-v1' as const,
        generation: this.generation.id, sequence: head.sequence + 1, previousRoot: head.root, attemptId: attempt.id,
        author: attempt.payload.header.author, operationId: attempt.payload.header.operationId,
        bodyHash: await bytesDigest(encodePeerValue(attempt)), bodyBytes: encodePeerValue(attempt).length }
      const receipt = { ...await signPeerValue(DOMAINS.peerOrder, payload, this.device), root: await peerDigest(['chronolog/peer-generation/order/v1', payload]) }
      const command = { receipt, attempt }
      await this.#retain(command, this.#authority, true)
      try { await this.#materialize(this.#authority) } catch (error) { this.#fail(error) }
      this.#publish(); return structuredClone(command)
    })
  }
  ingest(input: readonly OrderedCommand[]): Promise<void> {
    const commands = structuredClone(input)
    return this.#serial.run(async () => {
      this.#assertOpen(); check(commands.length <= 4096, 'PEER_REPLICATION_BATCH_LIMIT')
      for (const command of commands) await this.#retain(command, this.#authority, true)
      try { await this.#materialize(this.#authority) }
      catch (error) {
        if (!(error instanceof PeerGenerationError) || error.code !== 'PEER_RECOVERY_PREFIX_INCOMPLETE') this.#fail(error)
        throw error
      }
      await this.#finishRecovery(true)
      this.#publish()
    })
  }
  adopt(authority: AuthorityBundle): Promise<RecoveryNotice | null> { return this.synchronize(authority, []) }
  async synchronize(input: AuthorityBundle, inputCommands: readonly OrderedCommand[] | AsyncIterable<readonly OrderedCommand[]>, options: { readonly at?: PeerRevision } = {}): Promise<RecoveryNotice | null> {
    const result = await this.#receive(input, inputCommands, options)
    check(result.ready, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
    return result.recovery
  }
  receiveHistory(input: AuthorityBundle, inputCommands: readonly OrderedCommand[]): Promise<HistoryReceiveResult> {
    return this.#receive(input, inputCommands)
  }
  async #receive(input: AuthorityBundle, inputCommands: readonly OrderedCommand[] | AsyncIterable<readonly OrderedCommand[]>, options: { readonly at?: PeerRevision } = {}): Promise<HistoryReceiveResult> {
    const bundle = structuredClone(input), at = structuredClone(options.at)
    const commands = isArray(inputCommands) ? structuredClone(inputCommands as readonly OrderedCommand[]) : inputCommands
    const next = await verifyAuthorityBundle(bundle, this.#authority.bundle.descriptor)
    if (at !== undefined) {
      validatePeerRevision(at)
      check(at.applicationId === this.descriptor.applicationId && at.historyId === this.descriptor.historyId &&
        at.generation === next.current?.id && at.point.generation === at.generation && at.controlRevision === next.current.payload.controlRevision,
      'PEER_REPLICATION_TARGET_INVALID')
    }
    await this.#serial.run(async () => {
      this.#assertOpen(); assertAuthorityExtension(this.#authority, next)
      const previous = this.generation
      if (previous.id !== next.current!.id) {
        const pending = this.#pendingRecovery === null
          ? { previousGeneration: previous.id, generation: next.current!.id, knownAttemptId: this.#selected.at(-1)?.command.attempt.id ?? null }
          : { ...this.#pendingRecovery, generation: next.current!.id }
        await this.#writeSelection(next, pending)
        // Restrictive controls fence readers and coordinators before peer I/O.
        this.#authority = next; this.#pendingRecovery = pending; this.#ready = false; this.#coverage.clear()
        this.#publish()
      } else if (!samePeerValue(this.#authority.bundle, next.bundle)) {
        await this.#writeSelection(next, this.#pendingRecovery)
        this.#authority = next
      }
      for (const generation of next.bundle.generations) await this.#loadGeneration(generation, next)
    })
    let count = 0
    // A remote reader may concurrently need our retained pages. Never hold the
    // replica's serial section while waiting for the next network page.
    for await (const inputPage of replicationPages(commands)) {
      check(isArray(inputPage) && inputPage.length > 0 && inputPage.length <= PEER_MAX_RECORDS, 'PEER_REPLICATION_BATCH_LIMIT')
      count += inputPage.length; check(count <= this.#maxRecords, 'PEER_REPLICATION_BATCH_LIMIT')
      const page = structuredClone(inputPage)
      await this.#serial.run(async () => {
        this.#assertOpen(); assertAuthorityExtension(this.#authority, next)
        for (const command of page) await this.#retain(command, next, true)
      })
    }
    return this.#serial.run(async () => {
      this.#assertOpen(); assertAuthorityExtension(this.#authority, next)
      if (at !== undefined) check(this.#pointAvailable(at.point, next), 'PEER_REPLICATION_TARGET_INCOMPLETE')
      try { await this.#materialize(next) }
      catch (error) {
        if (error instanceof PeerGenerationError && error.code === 'PEER_RECOVERY_PREFIX_INCOMPLETE') {
          this.#publish(); return { ready: false, recovery: null }
        }
        this.#fail(error)
      }
      const recovery = await this.#finishRecovery(true)
      this.#publish(); return { ready: true, recovery }
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
    return this.#serial.run(async () => { this.#assertReady(); const id = this.#operations.get(operationKey(author, operationId)); return id === undefined ? null : this.#state(this.#attempts.get(id)!) })
  }
  attempt(operationId: string, author = this.device.publicKey): Promise<SignedAttempt | null> {
    return this.#serial.run(async () => { this.#assertOpen(); const id = this.#operations.get(operationKey(author, operationId)); return structuredClone(id === undefined ? null : this.#attempts.get(id)!) })
  }
  pendingAttempts(): Promise<readonly SignedAttempt[]> {
    return this.#serial.run(async () => { this.#assertOpen(); return [...this.#attempts.values()].filter(value => value.payload.header.generation === this.generation.id && !this.#receipts.has(value.id)).map(value => structuredClone(value)) })
  }
  capture(): Promise<CapturedPeerView> {
    return this.#serial.run(async () => {
      this.#assertReady(); check(this.#options.materializer.queries.captureRead !== undefined, 'PEER_CAPTURE_UNSUPPORTED')
      const read = this.#options.materializer.queries.captureRead({ view: 'local' })
      return { authority: this.authority, revision: this.revision, read, release: () => read.release() }
    })
  }
  async #proof(point: HistoryPoint): Promise<PrefixProof> {
    validateHistoryPoint(point); check(this.#pointAvailable(point), 'PEER_RECOVERY_PREFIX_INCOMPLETE')
    const records = this.#records.get(point.generation)!, segment = this.#authority.selectedSegments().find(value => value.generation.id === point.generation)!
    const receipt = point.sequence === 0 ? null : records.get(point.sequence)!.command.receipt
    const length = segment.cutoff === null ? 0 : segment.cutoff.sequence - point.sequence
    check(length <= 4096, 'PEER_PREFIX_PROOF_TOO_LARGE')
    const bridge = Array.from({ length }, (_, index) => {
      const retained = records.get(point.sequence + index + 1)
      check(retained !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE'); return retained.command.receipt
    })
    return structuredClone({ point, receipt, bridge })
  }
  recoveryPoint(): Promise<PrefixProof> {
    return this.#serial.run(async () => {
      this.#assertOpen()
      check(this.#authority.grant(this.device.publicKey)?.reader === true, 'PEER_READER_FORBIDDEN')
      await this.#checkCurrentKey()
      if (this.#ready) return this.#proof(this.revision.point)
      const selected: Retained[] = [], segments = this.#authority.selectedSegments()
      let point: HistoryPoint | null = null
      for (const [index, range] of this.#selectedRanges(this.#authority, false).entries()) {
        const segment = segments[index]!
        // An incomplete inherited segment lacks both application bodies and
        // the receipt bridge to its selected cutoff. Keep the last complete
        // ancestor instead; later stored branches cannot repair this gap.
        if (segment.cutoff !== null && range.length < segment.cutoff.sequence) break
        for (let sequence = 1; sequence <= range.length; sequence++) {
          const retained = range.records.get(sequence); check(retained !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE'); selected.push(retained)
        }
        const head = this.#heads.get(range.generation)!
        point = segment.cutoff ?? { generation: range.generation, sequence: head.sequence, root: head.root }
      }
      // A new empty peer is not evidence for an implicit reset to genesis.
      check(point !== null && selected.length > 0, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      const proof = await this.#proof(point)
      await this.#authority.verifyPrefix(proof)
      const floor = this.#authority.control.payload.recoveryFloor
      check(floor === null || this.#authority.atOrAfter(point, floor), 'PEER_RECOVERY_FLOOR_UNAVAILABLE')
      await this.#replay(selected, this.#authority)
      // Selection, readiness, captured views and recovery observers remain
      // unchanged until an authorized successor actually adopts this prefix.
      return proof
    })
  }
  pauseOrdering(operationId: string): Promise<PeerOrderingPause> {
    return this.#serial.run(async () => {
      this.#assertOpen(); boundedText(operationId)
      if (this.#orderingPause !== null) {
        check(this.#orderingPause.operationId === operationId, 'PEER_ORDERING_PAUSE_IN_USE')
        return this.#publicOrderingPause(this.#orderingPause)
      }
      this.#assertReady(); check(this.isCoordinator, 'PEER_NOT_COORDINATOR')
      check(!this.#fenced.has(this.generation.id), 'PEER_COORDINATOR_FENCED')
      const pause: StoredOrderingPause = { operationId, applicationId: this.descriptor.applicationId,
        author: this.device.publicKey, generation: this.generation.id, base: await this.#proof(this.revision.point) }
      // This write precedes the returned proof. A failed write fences this owner;
      // a process restart reloads a successfully retained pause before ordering.
      await this.#write(`${this.#prefix}/ordering-pause`, encodePeerValue(pause))
      this.#orderingPause = pause
      return this.#publicOrderingPause(pause)
    })
  }
  orderingPause(): Promise<PeerOrderingPause | null> {
    return this.#serial.run(async () => { this.#assertOpen(); return this.#orderingPause === null ? null : this.#publicOrderingPause(this.#orderingPause) })
  }
  resumeOrdering(operationId: string): Promise<void> {
    return this.#serial.run(async () => {
      this.#assertReady(); boundedText(operationId)
      const pause = this.#orderingPause
      check(pause !== null && pause.operationId === operationId, 'PEER_ORDERING_PAUSE_MISMATCH')
      // Resuming must not hide a separately selected history which lost the
      // reviewed prefix. Such a recovery requires its own explicit policy.
      check(this.#pointAvailable(pause.base.point) && this.#authority.atOrAfter(this.revision.point, pause.base.point),
        'PEER_ORDERING_PAUSE_RECOVERY_REQUIRED')
      await this.#write(`${this.#prefix}/ordering-pause`, encodePeerValue(null))
      this.#orderingPause = null
    })
  }
  #publicOrderingPause(pause: StoredOrderingPause): PeerOrderingPause {
    return structuredClone({ operationId: pause.operationId, generation: pause.generation, base: pause.base })
  }
  prefixProof(point: HistoryPoint): Promise<PrefixProof> { return this.#serial.run(async () => { this.#assertReady(); return this.#proof(point) }) }
  exportCommands(options: { readonly after?: HistoryPoint; readonly offset?: number; readonly limit?: number; readonly maxBytes?: number; readonly at?: PeerRevision } = {}): Promise<readonly OrderedCommand[]> {
    return this.#serial.run(async () => {
      this.#assertOpen()
      check(this.#authority.grant(this.device.publicKey)?.reader === true, 'PEER_READER_FORBIDDEN')
      const ranges = this.#selectedRanges(this.#authority, false), last = ranges.at(-1)
      let start = 0, end = last === undefined ? 0 : last.offset + last.length
      if (options.at !== undefined) {
        this.#assertReady()
        this.#checkView(options.at)
        check(options.at.generation === this.generation.id && options.at.point.generation === this.generation.id, 'PEER_VIEW_RECOVERY_REQUIRED')
        end -= this.#heads.get(this.generation.id)!.sequence - options.at.point.sequence
      }
      if (options.offset !== undefined) {
        check(options.after === undefined && Number.isSafeInteger(options.offset) && options.offset >= 0 && options.offset <= end, 'PEER_RANGE_OFFSET_INVALID')
        start = options.offset
      }
      if (options.after !== undefined) {
        check(this.#pointAvailable(options.after), 'PEER_CURSOR_RECOVERY_REQUIRED')
        const range = ranges.find(value => value.generation === options.after!.generation)
        check(options.after.sequence === 0 || range !== undefined && options.after.sequence <= range.length, 'PEER_CURSOR_RECOVERY_REQUIRED')
        start = range === undefined ? end : range.offset + options.after.sequence
      }
      const limit = options.limit ?? this.#maxRecords
      check(Number.isSafeInteger(limit) && limit > 0 && limit <= this.#maxRecords, 'PEER_RANGE_LIMIT_INVALID')
      const maxBytes = options.maxBytes ?? Number.MAX_SAFE_INTEGER
      check(Number.isSafeInteger(maxBytes) && maxBytes > 0, 'PEER_RANGE_BYTES_INVALID')
      const result: OrderedCommand[] = []
      const through = Math.min(end, start + limit)
      let bytes = 0
      for (const range of ranges) {
        const first = Math.max(1, start - range.offset + 1), last = Math.min(range.length, through - range.offset)
        for (let sequence = first; sequence <= last; sequence++) {
          const value = range.records.get(sequence); check(value !== undefined, 'PEER_RECOVERY_PREFIX_INCOMPLETE')
          const size = encodePeerValue(value.command).byteLength
          if (bytes + size > maxBytes) { check(result.length > 0, 'PEER_RANGE_RECORD_TOO_LARGE'); return result }
          bytes += size; result.push(structuredClone(value.command))
        }
      }
      return result
    })
  }
  retainedCoverage(point?: HistoryPoint): Promise<SignedRetainedCoverage> {
    const requested = point === undefined ? undefined : structuredClone(point)
    return this.#serial.run(async () => {
      this.#assertOpen()
      check(this.#authority.grant(this.device.publicKey)?.reader === true, 'PEER_READER_FORBIDDEN')
      const retained = requested ?? this.revision.point
      validateHistoryPoint(retained)
      check(this.#pointAvailable(retained), 'PEER_RECOVERY_PREFIX_INCOMPLETE')
      // Current-generation coverage can nominate a remote successor. Retaining
      // old bodies alone does not prove it can verify new work after rotation.
      await this.#checkCurrentKey()
      return signPeerValue(DOMAINS.peerCoverage, { applicationId: this.descriptor.applicationId, generation: this.generation.id,
        point: retained, peer: this.device.publicKey, storageId: this.#options.storageId, retainedAt: this.#now() }, this.device)
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
      // One current signing identity is one peer; a stale receipt cannot
      // replace its newer already verified durable coverage.
      const previous = this.#coverage.get(value.peer)
      if (previous !== undefined && !this.#authority.atOrAfter(value.point, previous.payload.point)) return
      this.#coverage.set(value.peer, coverage); this.#publish()
    })
  }
  shared(point = this.revision.point): readonly SignedRetainedCoverage[] {
    this.#assertReady()
    return [...this.#coverage.values()].filter(value => value.payload.storageId !== this.#options.storageId &&
      value.payload.peer !== this.device.publicKey && value.payload.generation === this.generation.id &&
      this.#authority.grant(value.payload.peer)?.reader === true &&
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

async function* replicationPages(commands: readonly OrderedCommand[] | AsyncIterable<readonly OrderedCommand[]>): AsyncGenerator<readonly OrderedCommand[]> {
  if (isArray(commands)) {
    const values = commands as readonly OrderedCommand[]
    for (let offset = 0; offset < values.length; offset += PEER_MAX_RECORDS) yield values.slice(offset, offset + PEER_MAX_RECORDS)
  } else yield* commands as AsyncIterable<readonly OrderedCommand[]>
}

export async function createPeerReplica(options: PeerReplicaOptions): Promise<PeerReplica> {
  check(typeof options.materializer.queries.capabilities?.sql === 'boolean', 'PEER_QUERY_CAPABILITIES_INVALID')
  check(options.maxRecords === undefined || Number.isSafeInteger(options.maxRecords) && options.maxRecords >= 1 && options.maxRecords <= PEER_MAX_RECORDS, 'PEER_RECORD_LIMIT_INVALID')
  check(options.maxHistoryBytes === undefined || Number.isSafeInteger(options.maxHistoryBytes) && options.maxHistoryBytes >= 1024 && options.maxHistoryBytes <= PEER_MAX_HISTORY_BYTES, 'PEER_HISTORY_LIMIT_INVALID')
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

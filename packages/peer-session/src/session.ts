import type { AuthorityBundle as InlineAuthorityBundle } from '@chronolog/authority'
import type { ApplicationPeerConnectOptions as InlineApplicationPeerConnectOptions } from './network.js'
import type { ApplicationPeerDiagnostics as InlineApplicationPeerDiagnostics } from './network.js'
import type { ApplicationPeerLink as InlineApplicationPeerLink } from './network.js'
import { createEventMaterializationRuntime, type ChronologMaterializationRuntime, type ReplayProposal, type MaterializedLocalSqlValue } from '@chronolog/materializer'
import { bytesToHex, hexToBytes, check, equalRecord, decodeRecord, encodeRecord, recordDigest, signRecord, verifyRecord, finalityPolicyDigest, verifyFinalityProofs, mergeFinalityProofs, finalityAdmissionScopes, signFinalityStatement, type FinalityStatement, type Signed, type AuthorityProvider, type FinalityProof, type VerifiedFinality } from '@chronolog/authority'
import { compareTransactionOrder, encodeChangeProgram, decodeTransactionCore, isEmitStep, transactionOrderKey, type TransactionCore } from '@chronolog/protocol'
import { createApplicationProvisioning, type ApplicationProvisioning } from './provisioning.js'
import { awaitOwnedTask } from './lifetime.js'
import { ApplicationContent } from './content.js'
import { SignalChannel } from '@chronolog/signals'
import type { BytesStore } from '@chronolog/records'
import type { ApplicationDefinition } from './definition.js'
import type { CreateApplicationSessionOptions } from './runtime.js'
import { ApplicationOperation, type ApplicationSubmission, type OperationInspection, type RetentionEvidence, type MaterializedOperation } from './operation.js'
import { signOperation, wrapOperation, unwrapOperation, verifyEnvelope, type SignedOperationEnvelope } from './operation-codec.js'
import type { ApplicationChange, ApplicationEvent, ApplicationEventBatch, ApplicationEventOptions, ApplicationReadView, CommandOptions, MaterializedRevision, QueryParameter, SessionStatus, WaitOptions } from './session-types.js'
interface StoredRequest { readonly operationId: string; readonly requestDigest: string; readonly proposalId: string; readonly suppliedTimestamp: bigint | null; readonly authorTimestampMs: bigint }
interface PreparedIntent { readonly request: StoredRequest; readonly envelope: SignedOperationEnvelope }
interface Journal { readonly format: 'authored-operation-set-v1'; readonly applicationId: string; readonly envelopes: readonly SignedOperationEnvelope[]; readonly requests: readonly StoredRequest[]; readonly retentions: readonly RetentionEvidence[]; readonly finality: readonly FinalityProof[] }
export interface SessionFacts { readonly authority?: InlineAuthorityBundle; readonly envelopes: readonly SignedOperationEnvelope[]; readonly retentions: readonly RetentionEvidence[]; readonly finality: readonly FinalityProof[] }
type SessionOptions<D extends ApplicationDefinition> = CreateApplicationSessionOptions<D> & { readonly authority: AuthorityProvider; readonly store: BytesStore; readonly release: () => Promise<void> }
interface ResolvedOperation { readonly envelope: SignedOperationEnvelope; readonly core: TransactionCore; readonly proposal: ReplayProposal }
/** The signed operation set owns facts; execution is a replaceable deterministic projection. */
export class ApplicationSession<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly authority: AuthorityProvider
  readonly definition: D
  readonly device: CreateApplicationSessionOptions<D>['device']
  readonly content: ApplicationContent
  readonly provisioning: ApplicationProvisioning
  readonly signals: SignalChannel
  readonly #options: SessionOptions<D>
  readonly #key: string
  #journal: Journal
  readonly #prepared = new Map<string, PreparedIntent>()
  #tail: Promise<unknown> = Promise.resolve()
  #replayTail: Promise<void> = Promise.resolve()
  #runtime: ChronologMaterializationRuntime | null = null
  #openingRuntime: Promise<ChronologMaterializationRuntime> | null = null
  readonly #lifetime = new AbortController()
  #closed = false
  #closing: Promise<void> | undefined
  #database: SessionStatus['database'] = 'idle'
  #error: Error | null = null
  #connectedPeers = 0
  #connectionRevision = 0
  #pending = new Map<string, OperationInspection['pending']>()
  #invalid = new Set<string>()
  #invalidEnvelopes = new Set<string>()
  readonly #envelopeDigests = new WeakMap<SignedOperationEnvelope, string>()
  #envelopesByDigest = new Map<string, SignedOperationEnvelope>()
  #resolved = new Map<string, ResolvedOperation>()
  #outcomes = new Map<string, MaterializedOperation>()
  #finality: VerifiedFinality = { closedThroughMs: null, included: new Map(), excludedProposalIds: new Set(), proofs: [] }
  #revision: MaterializedRevision
  readonly #listeners = new Set<() => void>()
  readonly #statusListeners = new Set<(status: SessionStatus) => void>()
  readonly #factListeners = new Set<() => void>()
  readonly #changeListeners = new Set<(change: ApplicationChange) => void>()
  readonly #stopAuthority: () => void
  private constructor(options: SessionOptions<D>, journal: Journal, policyDigest: string) {
    this.#options = options; this.authority = options.authority; this.definition = options.definition; this.device = options.device
    this.#key = `operation-set/${options.authority.descriptor.applicationId}`; this.#journal = journal
    this.#revision = { digest: '', view: 'local', executionManifestDigest: this.authority.descriptor.executionManifestDigest, policyDigest }
    this.provisioning = createApplicationProvisioning({ authority: options.authority, identity: options.device.identity })
    this.content = new ApplicationContent({ store: options.store, authority: options.authority, identity: options.device.identity, storageId: options.device.storageId })
    this.signals = new SignalChannel({ scope: options.authority.descriptor.applicationId, identity: { publicKeyBytes: hexToBytes(options.device.identity.publicKey), privateKey: options.device.identity.privateKey }, localEcho: true, relay: true, authorize: input => options.authority.grant(bytesToHex(input.authorId))?.reader === true })
    this.#stopAuthority = this.authority.subscribe(() => { this.#scheduleReplay(); this.#factsChanged() })
  }
  static async open<D extends ApplicationDefinition>(options: SessionOptions<D>): Promise<ApplicationSession<D>> {
    const applicationId = options.authority.descriptor.applicationId, bytes = await options.store.get(`operation-set/${applicationId}`)
    const journal: Journal = bytes === null ? { format: 'authored-operation-set-v1', applicationId, envelopes: [], requests: [], retentions: [], finality: [] } : decodeRecord<Journal>(bytes)
    check(journal.format === 'authored-operation-set-v1' && journal.applicationId === applicationId && journal.requests.every(request => typeof request.authorTimestampMs === 'bigint' && request.authorTimestampMs >= 0n && request.authorTimestampMs <= (1n << 63n) - 1n), 'OPERATION_STORE_FORMAT_INVALID')
    const session = new ApplicationSession(options, journal, await finalityPolicyDigest(options.authority.descriptor.finalityPolicy))
    for (const envelope of journal.envelopes) await verifyEnvelope(envelope, session.authority)
    await session.#indexEnvelopes()
    for (const retention of journal.retentions) await session.#verifyRetention(retention)
    session.#finality = await verifyFinalityProofs(session.authority.descriptor, journal.finality, session.authority)
    if (bytes === null) await options.store.put(session.#key, encodeRecord(journal))
    session.#scheduleReplay(); return session
  }
  get signal(): AbortSignal { return this.#lifetime.signal }
  connectPeer(options: InlineApplicationPeerConnectOptions): Promise<InlineApplicationPeerLink> { return import('./network.js').then(module => module.connectApplicationPeer(this, options)) }
  diagnostics(): Promise<readonly InlineApplicationPeerDiagnostics[]> { return import('./network.js').then(module => module.applicationPeerDiagnostics(this)) }
  get applicationId(): string { return this.authority.descriptor.applicationId }
  get identity(): { readonly publicKey: string } { return { publicKey: this.device.identity.publicKey } }
  get revision(): MaterializedRevision { return { ...this.#revision } }
  get status(): SessionStatus { return { pendingDependencies: [...(this.#finality.pendingDependencies ?? []), ...[...this.#pending].filter(([, kind]) => kind !== 'materializer').map(([id, kind]) => `${kind}/${id}`)], canAuthor: !this.#closed && this.authority.grant(this.device.identity.publicKey)?.writer === true && this.authority.epochKey(this.authority.currentMembership.epoch) !== null, phase: this.#closed ? 'closed' : [...this.#pending.values()].includes('key') ? 'awaiting-keys' : 'ready', database: this.#database, connectedPeers: this.#connectedPeers, connectionRevision: this.#connectionRevision, pendingOperations: this.#pending.size, materializationError: this.#error?.message ?? null } }
  #serial<T>(work: () => Promise<T>): Promise<T> {
    const task = this.#tail.then(() => { check(!this.#closed, 'SESSION_CLOSED'); return work() }); this.#tail = task.catch(() => undefined); return task
  }
  async #indexEnvelopes(): Promise<void> {
    const indexed = new Map<string, SignedOperationEnvelope>()
    for (const envelope of this.#journal.envelopes) {
      let digest = this.#envelopeDigests.get(envelope)
      if (digest === undefined) { digest = await recordDigest(envelope); this.#envelopeDigests.set(envelope, digest) }
      indexed.set(digest, envelope)
    }
    this.#envelopesByDigest = indexed
  }
  #canonicalAuthor(id: string): string | undefined {
    if (this.#journal.requests.some(request => request.proposalId === id)) return this.device.identity.publicKey
    const resolved = this.#resolved.get(id)
    return resolved === undefined ? undefined : bytesToHex(resolved.core.authorId)
  }
  #subjectEnvelope(id: string): SignedOperationEnvelope | undefined {
    const knownAuthor = this.#canonicalAuthor(id), candidates = [...this.#envelopesByDigest].filter(([digest, envelope]) => envelope.payload.proposalId === id && !this.#invalidEnvelopes.has(digest) && (knownAuthor === undefined || envelope.payload.author === knownAuthor))
    const authors = new Set(candidates.map(([, envelope]) => envelope.payload.author))
    return authors.size === 1 ? candidates[0]?.[1] : undefined
  }
  #retained(id: string): readonly RetentionEvidence[] {
    const author = this.#canonicalAuthor(id) ?? this.#subjectEnvelope(id)?.payload.author
    if (author === undefined) return []
    return this.#journal.retentions.filter(evidence => {
      const receipt = evidence.payload, envelope = this.#envelopesByDigest.get(receipt.envelopeDigest)
      return receipt.proposalId === id && receipt.author === author && this.authority.grant(evidence.signer) !== null && evidence.signer !== this.device.identity.publicKey && receipt.storageId !== this.device.storageId && envelope?.payload.proposalId === id && envelope.payload.author === author && !this.#invalidEnvelopes.has(receipt.envelopeDigest)
    })
  }
  async #persist(journal: Journal): Promise<void> {
    check(journal.envelopes.length <= (this.#options.maxOperations ?? 100_000), 'OPERATION_COUNT_LIMIT')
    const bytes = encodeRecord(journal); check(bytes.length <= (this.#options.maxHistoryBytes ?? 32 * 1024 * 1024), 'OPERATION_HISTORY_LIMIT')
    try { await this.#options.store.put(this.#key, bytes); this.#journal = journal; await this.#indexEnvelopes() }
    catch (error) {
      // A lost durability reply is not proof that the write failed. Reconcile before retry.
      const retained = await this.#options.store.get(this.#key)
      if (retained !== null) { this.#journal = decodeRecord<Journal>(retained); await this.#indexEnvelopes(); this.#scheduleReplay(); this.#factsChanged(); this.#notify() }
      throw error
    }
  }
  async #commitPrepared(intent: PreparedIntent): Promise<ApplicationOperation> {
    const { request, envelope } = intent
    await this.#persist({ ...this.#journal, envelopes: [...this.#journal.envelopes, envelope], requests: [...this.#journal.requests, request] })
    this.#prepared.delete(request.operationId); this.#pending.set(request.proposalId, 'materializer'); this.#notify(); this.#factsChanged(); this.#scheduleReplay()
    return new ApplicationOperation(request.proposalId, request.operationId, this)
  }
  /** Completion is local durable signed storage, not network dispatch or engine warm-up. */
  submit(input: ApplicationSubmission): Promise<ApplicationOperation> {
    const program = structuredClone(input.program), operationId = input.operationId ?? crypto.randomUUID(), suppliedTimestamp = input.authorTimestampMs ?? null
    return this.#serial(async () => {
      const requestDigest = await recordDigest({ program: bytesToHex(encodeChangeProgram(program)) })
      const prior = this.#journal.requests.find(request => request.operationId === operationId)
      if (prior !== undefined) {
        check(prior.requestDigest === requestDigest && (suppliedTimestamp === null || suppliedTimestamp === prior.authorTimestampMs), 'OPERATION_ID_REUSED')
        this.#prepared.delete(operationId); this.#scheduleReplay(); this.#factsChanged(); return new ApplicationOperation(prior.proposalId, operationId, this)
      }
      const prepared = this.#prepared.get(operationId)
      if (prepared !== undefined) {
        check(prepared.request.requestDigest === requestDigest && (suppliedTimestamp === null || suppliedTimestamp === prepared.envelope.payload.authorTimestampMs), 'OPERATION_ID_REUSED')
        return this.#commitPrepared(prepared)
      }
      check(this.#prepared.size < 32, 'AUTHORING_PREPARATION_LIMIT')
      const grant = this.authority.grant(this.device.identity.publicKey)
      check(grant?.writer, 'OPERATION_WRITER_FORBIDDEN')
      // Only this device's durable DEFAULT allocations advance its author clock.
      // Explicit authored timestamps (including authenticated remote int64 maxima) never poison defaults.
      const highestDefault = this.#journal.requests.filter(request => request.suppliedTimestamp === null).reduce((highest, request) => request.authorTimestampMs > highest ? request.authorTimestampMs : highest, -1n)
      const now = BigInt(Date.now())
      const authorTimestampMs = suppliedTimestamp ?? (now > highestDefault ? now : highestDefault + 1n)
      const memberships = this.authority.bundle().memberships
      const historical = [...memberships].reverse().find(item => authorTimestampMs > item.payload.authorTimeAfterMs)
      check(historical !== undefined && historical.payload.members.some(member => member.publicKey === this.device.identity.publicKey && member.writer), 'OPERATION_MEMBERSHIP_TIME_INVALID')
      const membership = historical.payload, membershipId = await recordDigest(historical)
      const epochKey = this.authority.epochKey(membership.epoch); check(epochKey !== null, 'OPERATION_EPOCH_KEY_MISSING')
      const core: TransactionCore = { operationId, groupId: hexToBytes(this.applicationId), membershipRevision: hexToBytes(membershipId), validationPolicy: hexToBytes(this.#revision.policyDigest), authorId: hexToBytes(this.device.identity.publicKey), authorTimestampMs, nonce: crypto.getRandomValues(new Uint8Array(16)), executionManifestDigest: hexToBytes(this.authority.descriptor.executionManifestDigest), program }
      const body = await signOperation(core, this.device.identity), envelope = await wrapOperation(body, this.device.identity, membership.epoch, epochKey)
      const intent = { envelope, request: { operationId, requestDigest, suppliedTimestamp, authorTimestampMs, proposalId: body.payload.proposalId } }
      this.#prepared.set(operationId, intent)
      return this.#commitPrepared(intent)
    }).catch((error: unknown) => {
      if (error instanceof Error) Object.assign(error, { operationId, applicationId: this.applicationId, durability: this.#journal.requests.some(request => request.operationId === operationId) ? 'stored' : 'unconfirmed' })
      throw error
    })
  }
  command(name: string, input: unknown, options: CommandOptions = {}): Promise<ApplicationOperation> {
    const command = this.definition.commands[name]; check(command !== undefined, 'APPLICATION_COMMAND_UNKNOWN')
    return this.submit({ ...options, program: command.prepare(input as never) })
  }
  #operation(id: string): ApplicationOperation | null {
    const request = this.#journal.requests.find(item => item.operationId === id || item.proposalId === id)
    const resolved = this.#resolved.get(id)
    const envelope = this.#subjectEnvelope(id)
    return request === undefined ? resolved === undefined ? envelope === undefined ? null : new ApplicationOperation(id, '', this) : new ApplicationOperation(id, resolved.core.operationId, this) : new ApplicationOperation(request.proposalId, request.operationId, this)
  }
  get operations() {
    const session = this
    return { get: (id: string) => session.#operation(id), async retry(id: string): Promise<ApplicationOperation> {
      const operation = session.#operation(id); check(operation !== null && operation.inspect().author === session.device.identity.publicKey, 'OPERATION_RETRY_FORBIDDEN')
      session.#scheduleReplay(); session.#factsChanged(); return operation
    }, async *subscribe(options: { readonly operationId: string; readonly signal?: AbortSignal }): AsyncIterable<OperationInspection> {
      const signal = options.signal === undefined ? session.signal : AbortSignal.any([session.signal, options.signal]); let dirty = true, wake: (() => void) | undefined
      const listener = (): void => { dirty = true; wake?.() }; session.#listeners.add(listener); signal.addEventListener('abort', listener)
      try { while (!signal.aborted) { if (!dirty) await new Promise<void>(resolve => { wake = resolve }); if (signal.aborted) break; dirty = false; const operation = session.#operation(options.operationId); if (operation !== null) yield operation.inspect(); else if (session.#pending.has(options.operationId)) yield session.inspectOperation(options.operationId) } }
      finally { session.#listeners.delete(listener); signal.removeEventListener('abort', listener) }
    } }
  }
  inspectOperation(id: string): OperationInspection {
    const envelope = this.#subjectEnvelope(id), resolved = this.#resolved.get(id)
    const materialized = this.#outcomes.get(id) ?? null, cutoff = this.#finality.closedThroughMs
    const finalized = this.authority.descriptor.finalityPolicy.kind !== 'none' && cutoff !== null && this.#finality.included.has(id) && !this.#finality.excludedProposalIds.has(id) && resolved !== undefined && resolved.core.authorTimestampMs <= cutoff && materialized !== null && this.#pending.size === 0 && this.#error === null
    return { applicationId: this.applicationId, author: resolved === undefined ? envelope?.payload.author ?? '' : bytesToHex(resolved.core.authorId), authorTimestampMs: (resolved?.core.authorTimestampMs ?? envelope?.payload.authorTimestampMs)?.toString() ?? null, proposalId: id, operationId: resolved?.core.operationId ?? this.#journal.requests.find(item => item.proposalId === id)?.operationId ?? '', stored: envelope !== undefined, pending: this.#pending.get(id) ?? null, materialized, retained: structuredClone(this.#retained(id)), finalized, excluded: this.#invalid.has(id) || this.#finality.excludedProposalIds.has(id) }
  }
  waitOperation(id: string, fact: 'materialized' | 'retained' | 'finalized', options: WaitOptions = {}): Promise<OperationInspection> {
    if (fact === 'finalized' && this.authority.descriptor.finalityPolicy.kind === 'none') return Promise.reject(Object.assign(new Error('FINALITY_UNSUPPORTED'), { code: 'FINALITY_UNSUPPORTED' }))
    const timeoutMs = options.timeoutMs ?? 30_000
    check(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 120_000, 'OPERATION_WAIT_LIMIT')
    return new Promise((resolve, reject) => {
      const finish = (error?: unknown, value?: OperationInspection): void => { clearTimeout(timer); this.#listeners.delete(checkFact); options.signal?.removeEventListener('abort', abort); if (error !== undefined) reject(error); else resolve(value!) }
      const abort = (): void => finish(options.signal?.reason ?? new Error('ABORTED'))
      const checkFact = (): void => { const value = this.inspectOperation(id); if (this.#closed) finish(new Error('SESSION_CLOSED')); else if (value.excluded) finish(Object.assign(new Error('OPERATION_EXCLUDED'), { inspection: value })); else if (fact === 'materialized' ? value.materialized !== null : fact === 'retained' ? value.retained.length > 0 : value.finalized) finish(undefined, value) }
      const timer = setTimeout(() => finish(new Error('OPERATION_WAIT_TIMEOUT')), timeoutMs); this.#listeners.add(checkFact); options.signal?.addEventListener('abort', abort, { once: true }); if (options.signal?.aborted) abort(); else checkFact()
    })
  }
  exportFacts(): SessionFacts { return structuredClone({ authority: this.authority.bundle(), envelopes: this.#journal.envelopes, retentions: this.#journal.retentions, finality: this.#journal.finality }) }
  async #verifyRetention(evidence: RetentionEvidence): Promise<void> {
    check(evidence.payload.applicationId === this.applicationId && evidence.payload.peer === evidence.signer && typeof evidence.payload.storageId === 'string' && evidence.payload.storageId.length > 0 && evidence.payload.storageId.length <= 128 && /^[0-9a-f]{64}$/u.test(evidence.payload.proposalId) && /^[0-9a-f]{64}$/u.test(evidence.payload.author) && /^[0-9a-f]{64}$/u.test(evidence.payload.envelopeDigest) && this.authority.bundle().memberships.some(membership => membership.payload.members.some(member => member.publicKey === evidence.signer)), 'RETENTION_SCOPE_INVALID')
    await verifyRecord('retention', evidence, evidence.payload.peer)
  }
  async mergeFacts(input: SessionFacts): Promise<void> {
    const facts = structuredClone(input)
    if (facts.authority !== undefined) await this.mergeAuthority(facts.authority)
    return this.#serial(async () => {
      const envelopes = [...this.#journal.envelopes], retentions = [...this.#journal.retentions]
      const known = new Set(this.#envelopesByDigest.keys())
      for (const envelope of facts.envelopes) { await verifyEnvelope(envelope, this.authority); const id = await recordDigest(envelope); if (!known.has(id)) { check(envelopes.filter(item => item.payload.proposalId === envelope.payload.proposalId && item.payload.author === envelope.payload.author).length < 8, 'OPERATION_ENVELOPE_LIMIT'); known.add(id); envelopes.push(envelope) } }
      const receipts = new Set(await Promise.all(retentions.map(item => recordDigest(item))))
      for (const receipt of facts.retentions) { await this.#verifyRetention(receipt); const id = await recordDigest(receipt); if (!receipts.has(id)) { receipts.add(id); retentions.push(receipt) } }
      const proofs = facts.finality.length === 0 ? this.#journal.finality : await mergeFinalityProofs(this.#journal.finality, facts.finality)
      const envelopesChanged = envelopes.length !== this.#journal.envelopes.length, finalityChanged = !equalRecord(proofs, this.#journal.finality)
      if (!envelopesChanged && !finalityChanged && retentions.length === this.#journal.retentions.length) return
      const verified = finalityChanged ? await verifyFinalityProofs(this.authority.descriptor, proofs, this.authority) : this.#finality
      const journal = { ...this.#journal, envelopes, retentions, finality: proofs }
      await this.#persist(journal); if (finalityChanged) this.#finality = verified
      this.#notify(); this.#factsChanged()
      // Retention is availability evidence, not an execution input. Its durable
      // observers still run, but it cannot require decrypting/replaying history.
      if (envelopesChanged || finalityChanged) this.#scheduleReplay()
    })
  }
  async retain(proposalId: string, subject?: { readonly author: string; readonly envelopeDigest: string }): Promise<RetentionEvidence> {
    const envelope = subject === undefined ? this.#subjectEnvelope(proposalId) : this.#envelopesByDigest.get(subject.envelopeDigest)
    check(envelope !== undefined && envelope.payload.proposalId === proposalId && (subject === undefined || envelope.payload.author === subject.author), 'RETENTION_SUBJECT_MISSING')
    const author = envelope.payload.author, envelopeDigest = this.#envelopeDigests.get(envelope)!
    check(!this.#invalidEnvelopes.has(envelopeDigest), 'RETENTION_SUBJECT_INVALID')
    const existing = this.#journal.retentions.find(item => item.payload.proposalId === proposalId && item.payload.author === author && item.payload.envelopeDigest === envelopeDigest && item.signer === this.device.identity.publicKey && item.payload.storageId === this.device.storageId)
    if (existing !== undefined) return structuredClone(existing)
    const evidence = await signRecord('retention', { applicationId: this.applicationId, proposalId, author, envelopeDigest, peer: this.device.identity.publicKey, storageId: this.device.storageId }, this.device.identity)
    await this.mergeFacts({ envelopes: [], retentions: [evidence], finality: [] }); return evidence
  }
  async mergeAuthority(bundle: InlineAuthorityBundle): Promise<void> {
    const current = this.authority.currentMembership.revision, sealed = this.#finality.closedThroughMs
    if (sealed !== null) for (const membership of bundle.memberships.slice(current + 1)) check(membership.payload.authorTimeAfterMs >= sealed, 'FINALITY_MEMBERSHIP_BEHIND_SEAL')
    await this.authority.merge(bundle)
  }
  get finality() {
    const session = this
    const prepare = (options: { readonly throughMs: bigint }): Promise<readonly Signed<FinalityStatement>[]> => session.#serial(async () => {
      const policy = session.authority.descriptor.finalityPolicy
      check(policy.kind !== 'none', 'FINALITY_UNSUPPORTED')
      check(session.authority.grant(session.device.identity.publicKey)?.finalizer === true, 'FINALITY_FINALIZER_REQUIRED')
      check(policy.kind === 'signed-frontier' ? policy.signer === session.device.identity.publicKey : policy.validators.includes(session.device.identity.publicKey), 'FINALITY_SIGNER_FORBIDDEN')
      check(typeof options.throughMs === 'bigint' && options.throughMs >= 0n && options.throughMs <= (1n << 63n) - 1n, 'FINALITY_TIME_INVALID')
      const entriesById = new Map<string, { id: string; timestamp: bigint; membershipId: string; author: string; available: boolean }>()
      for (const envelope of session.#journal.envelopes) {
        try {
          const resolved = await unwrapOperation(envelope, session.authority)
          if (typeof resolved !== 'string' && resolved.admission === 'excluded') continue
          const entry = { id: envelope.payload.proposalId, timestamp: envelope.payload.authorTimestampMs, membershipId: envelope.payload.membershipId, author: envelope.payload.author, available: typeof resolved !== 'string' }, prior = entriesById.get(entry.id)
          if (prior === undefined || !prior.available && (entry.available || entry.timestamp < prior.timestamp)) entriesById.set(entry.id, entry)
        } catch { /* Invalid envelopes cannot supply execution or a closure dependency. */ }
      }
      const entries = [...entriesById.values()], certified = await verifyFinalityProofs(session.authority.descriptor, session.#journal.finality, session.authority)
      const votes: Signed<FinalityStatement>[] = []
      for (const scope of await finalityAdmissionScopes(session.authority)) {
        const history = (certified.certifiedProofs ?? []).filter(proof => proof.statement.scope === scope.id), head = history.at(-1)?.statement
        const firstIncluded = new Set(history.flatMap(proof => proof.statement.inclusions.map(inclusion => inclusion.proposalId)))
        const matching = entries.filter(entry => entry.timestamp > scope.authorTimeAfterMs && (!session.authority.hasMembership(scope.id) || entry.membershipId === scope.id))
        const blockers = matching.filter(entry => !entry.available && entry.timestamp <= options.throughMs).map(entry => ({ proposalId: entry.id, authorTimestampMs: entry.timestamp, membershipId: entry.membershipId, author: entry.author }))
        let closedThroughMs = options.throughMs > scope.authorTimeAfterMs ? options.throughMs : scope.authorTimeAfterMs
        for (const blocker of blockers) if (closedThroughMs >= blocker.authorTimestampMs) closedThroughMs = blocker.authorTimestampMs - 1n
        check(closedThroughMs >= (head?.closedThroughMs ?? scope.authorTimeAfterMs), 'FINALITY_DEPENDENCY_BEHIND_SEAL')
        const statement: FinalityStatement = { applicationId: session.applicationId, policyDigest: session.#revision.policyDigest, authorityHead: session.authority.currentMembershipId, scope: scope.id, sequence: (head?.sequence ?? -1) + 1, previous: head === undefined ? null : await recordDigest(head), inclusions: matching.filter(entry => entry.available && !firstIncluded.has(entry.id)).map(entry => ({ proposalId: entry.id, authorTimestampMs: entry.timestamp, membershipId: entry.membershipId, author: entry.author })).sort((a, b) => a.proposalId.localeCompare(b.proposalId)), closedThroughMs, blockers }
        votes.push(await signFinalityStatement(statement, session.device.identity))
      }
      return votes
    })
    return { voteAuthorTime: prepare, async closeAuthorTime(options: { readonly throughMs: bigint }): Promise<{ readonly closedThroughMs: bigint | null; readonly proofs: readonly FinalityProof[] }> {
      const policy = session.authority.descriptor.finalityPolicy; check(policy.kind !== 'none', 'FINALITY_UNSUPPORTED'); check(session.authority.grant(session.device.identity.publicKey)?.finalizer === true, 'FINALITY_FINALIZER_REQUIRED'); check(policy.kind === 'signed-frontier' || policy.threshold === 1, 'FINALITY_QUORUM_REQUIRED')
      const votes = await prepare(options), proofs = votes.map(vote => ({ statement: vote.payload, signatures: [vote] }))
      await session.mergeFacts({ envelopes: [], retentions: [], finality: proofs }); await session.retryMaterialization()
      return { closedThroughMs: session.#finality.closedThroughMs, proofs }
    }, async submitProofs(proofs: readonly FinalityProof[]): Promise<void> { await session.mergeFacts({ envelopes: [], retentions: [], finality: proofs }) } }
  }
  onFacts(listener: () => void): () => void { this.#factListeners.add(listener); return () => { this.#factListeners.delete(listener) } }
  #factsChanged(): void { for (const listener of this.#factListeners) { try { listener() } catch { /* A transport observer cannot reject committed facts. */ } } }
  #notify(): void { for (const listener of this.#listeners) { try { listener() } catch { /* Isolated observers. */ } }; for (const listener of this.#statusListeners) { try { listener(this.status) } catch { /* Isolated observers. */ } } }
  onStatus(listener: (value: SessionStatus) => void): () => void { this.#statusListeners.add(listener); try { listener(this.status) } catch { /* Observation cannot reject a committed session. */ }; return () => { this.#statusListeners.delete(listener) } }
  onChange(listener: (value: ApplicationChange) => void): () => void { this.#changeListeners.add(listener); return () => { this.#changeListeners.delete(listener) } }
  setConnectedPeers(count: number): void { check(Number.isSafeInteger(count) && count >= 0 && count <= 8, 'SESSION_PEER_LIMIT'); if (count !== this.#connectedPeers) this.#connectionRevision++; this.#connectedPeers = count; this.#notify() }
  #scheduleReplay(): void {
    if (this.#closed) return
    this.#replayTail = this.#replayTail.then(() => this.#replay()).catch(error => { this.#error = error instanceof Error ? error : new Error('MATERIALIZATION_FAILED', { cause: error }); this.#database = 'failed'; this.#notify() })
  }
  async #engine(): Promise<ChronologMaterializationRuntime> {
    if (this.#runtime !== null) return this.#runtime
    this.#database = 'opening'; this.#notify()
    if (this.#openingRuntime === null) {
      const opening = this.#options.createMaterializer === undefined ? createEventMaterializationRuntime({ store: this.#options.store, namespace: this.applicationId }) : this.#options.createMaterializer({ signal: this.#lifetime.signal, rootPrincipal: hexToBytes(this.authority.descriptor.rootPrincipal), store: this.#options.store })
      this.#openingRuntime = Promise.resolve(opening)
    }
    try { const runtime = await this.#openingRuntime; check(bytesToHex(runtime.queries.executionManifestDigest) === this.authority.descriptor.executionManifestDigest, 'EXECUTION_MANIFEST_UNAVAILABLE'); this.#runtime = runtime; return runtime }
    catch (error) { this.#openingRuntime = null; throw error }
  }
  async #replay(): Promise<void> {
    if (this.#closed) return
    const journal = this.#journal, resolved = new Map<string, ResolvedOperation>(), pending = new Map<string, OperationInspection['pending']>(), invalid = new Set<string>(), invalidEnvelopes = new Set<string>()
    for (const envelope of journal.envelopes) {
      const id = envelope.payload.proposalId, digest = this.#envelopeDigests.get(envelope)!, knownAuthor = this.#canonicalAuthor(id)
      if (knownAuthor !== undefined && knownAuthor !== envelope.payload.author) { invalidEnvelopes.add(digest); continue }
      let result: Awaited<ReturnType<typeof unwrapOperation>>
      try { result = await unwrapOperation(envelope, this.authority) } catch { invalidEnvelopes.add(digest); continue }
      if (typeof result === 'string') { if (!resolved.has(id)) pending.set(id, result); continue }
      const txId = hexToBytes(id)
      pending.delete(id)
      if (result.admission === 'excluded') invalid.add(id); else invalid.delete(id)
      resolved.set(id, { envelope, core: result.core, proposal: { txId, candidateDigest: txId, canonicalCandidate: result.body.payload.canonicalCore, core: result.core } })
    }
    // Header claims cannot poison another author's proposal. Identity verification does not await SQL.
    this.#invalidEnvelopes = invalidEnvelopes; this.#resolved = resolved
    const finality = await verifyFinalityProofs(this.authority.descriptor, journal.finality, this.authority, [...resolved].map(([proposalId, entry]) => ({ proposalId, authorTimestampMs: entry.core.authorTimestampMs, membershipId: bytesToHex(entry.core.membershipRevision), author: bytesToHex(entry.core.authorId) })))
    for (const [id, inclusion] of finality.included) {
      const entry = resolved.get(id)
      if (entry === undefined) pending.set(id, 'body')
      else check(entry.core.authorTimestampMs === inclusion.authorTimestampMs, 'FINALITY_BODY_TIME_MISMATCH')
    }
    const cutoffForAdmission = finality.closedThroughMs
    for (const [id, entry] of resolved) if (cutoffForAdmission !== null && entry.core.authorTimestampMs <= cutoffForAdmission && !finality.included.has(id)) invalid.add(id)
    const eligible = [...resolved.values()].filter(entry => !invalid.has(entry.envelope.payload.proposalId) && !finality.excludedProposalIds.has(entry.envelope.payload.proposalId)).sort((a, b) => compareTransactionOrder(transactionOrderKey(a.core, a.proposal.txId), transactionOrderKey(b.core, b.proposal.txId)))
    this.#pending = new Map(pending); for (const entry of eligible) this.#pending.set(entry.envelope.payload.proposalId, 'materializer'); this.#invalid = invalid
    const runtime = await this.#engine()
    const result = await runtime.replay.materialize(eligible.map(entry => entry.proposal))
    if (result !== null) await runtime.publications.publish(result.publication)
    const digest = await recordDigest(['materialized-operation-set', this.applicationId, this.#revision.executionManifestDigest, this.#revision.policyDigest, 'local', eligible.map(entry => entry.envelope.payload.proposalId)])
    const revision: MaterializedRevision = { ...this.#revision, digest }
    const outcomes = new Map<string, MaterializedOperation>()
    for (const entry of eligible) { const id = entry.envelope.payload.proposalId, outcome = runtime.queries.outcome(entry.proposal.txId); check(outcome !== null, 'MATERIALIZATION_OUTCOME_MISSING'); outcomes.set(id, { proposalId: id, revision, outcome: outcome.outcome, rejectionCode: outcome.rejectionCode, failingStatementIndex: outcome.failingStatementIndex }) }
    let finalLength = 0
    const cutoff = finality.closedThroughMs
    if (cutoff !== null && pending.size === 0) {
      for (const entry of eligible) { if (entry.core.authorTimestampMs > cutoff || !finality.included.has(entry.envelope.payload.proposalId)) break; finalLength++ }
      await runtime.replay.publishFinal?.(finalLength)
    }
    const revisedProposalIds = [...new Set([...this.#outcomes.keys(), ...outcomes.keys()])].filter(id => { const prior = this.#outcomes.get(id), current = outcomes.get(id); return prior?.outcome !== current?.outcome || prior?.rejectionCode !== current?.rejectionCode })
    const changed = this.#revision.digest !== digest
    this.#resolved = resolved; this.#pending = pending; this.#outcomes = outcomes; this.#revision = revision; this.#finality = finality; this.#error = null; this.#database = 'ready'; this.#notify()
    if (changed || finalLength > 0) for (const listener of this.#changeListeners) { try { listener({ kind: changed ? 'materialized' : 'finalized', revision, revisedProposalIds }) } catch { /* Isolated observers. */ } }
  }
  async retryMaterialization(): Promise<void> { this.#scheduleReplay(); await this.#replayTail; if (this.#error !== null) throw this.#error }
  async readView(options: { readonly view?: 'local' | 'final' } = {}): Promise<ApplicationReadView> {
    await this.#replayTail; check(!this.#closed, 'SESSION_CLOSED'); check(this.authority.grant(this.device.identity.publicKey)?.reader, 'APPLICATION_READER_REQUIRED'); if (this.#error !== null) throw this.#error
    check(this.#runtime !== null, 'MATERIALIZATION_UNAVAILABLE')
    const view = options.view ?? 'local'
    if (view === 'final') { check(this.authority.descriptor.finalityPolicy.kind !== 'none', 'FINALITY_UNSUPPORTED'); check(this.#finality.closedThroughMs !== null && this.#pending.size === 0, 'FINAL_READ_UNAVAILABLE') }
    const readHandle = this.#runtime.queries.captureRead?.({ view }), snapshot = readHandle ?? this.#runtime.queries.captureApplication({ view })
    const ids: string[] = [], events: ApplicationEvent[] = []
    for (let i = 0; i < snapshot.orderLength; i++) {
      const transaction = snapshot.transactionAt(i); check(transaction !== null, 'READ_SNAPSHOT_INCOMPLETE')
      const id = bytesToHex(transaction.txId); ids.push(id)
      if (transaction.outcome !== 'accepted') continue
      const core = decodeTransactionCore(transaction.canonicalCandidate)
      let ordinal = 0
      for (const step of core.program.steps) if (isEmitStep(step)) events.push({ id: `${id}:${ordinal++}`, proposalId: id, operationId: core.operationId, author: bytesToHex(core.authorId), authorTimestampMs: core.authorTimestampMs.toString(), topic: step.topic, payload: structuredClone(step.payload) })
    }
    const revision: MaterializedRevision = { ...this.#revision, view, digest: await recordDigest(['materialized-operation-set', this.applicationId, this.#revision.executionManifestDigest, this.#revision.policyDigest, view, ids]) }
    let released = false
    return { applicationId: this.applicationId, revision, query(sql, parameters = []) {
      check(!released, 'READ_VIEW_RELEASED'); check(readHandle !== undefined, 'SQL_UNAVAILABLE')
      const result = readHandle.query(sql, parameters.map(toSqlValue))
      return { columns: result.columns, rows: result.rows.map(row => row.map(fromSqlValue)) }
    }, readEvents: (input = {}) => { check(!released, 'READ_VIEW_RELEASED'); return readEvents(events, revision, input) }, release() { if (released) return; released = true; readHandle?.release() } }
  }
  async query(name: string, input: unknown, options: { readonly signal?: AbortSignal } = {}): Promise<{ readonly applicationId: string; readonly revision: MaterializedRevision; readonly value: unknown }> {
    const query = this.definition.queries[name]; check(query !== undefined, 'APPLICATION_QUERY_UNKNOWN')
    const signal = options.signal === undefined ? this.signal : AbortSignal.any([this.signal, options.signal]), opening = this.readView()
    let view: ApplicationReadView
    try { view = await awaitOwnedTask(signal, () => opening) }
    catch (error) { void opening.then(late => late.release()).catch(() => undefined); throw error }
    try { return { applicationId: this.applicationId, revision: view.revision, value: await awaitOwnedTask(signal, () => query.read(view as never, input as never)) } }
    finally { view.release() }
  }
  async readEvents(options: ApplicationEventOptions = {}): Promise<ApplicationEventBatch> { const view = await this.readView(); try { return view.readEvents(options) } finally { view.release() } }
  async *changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationChange> {
    const queue: ApplicationChange[] = []; let wake: (() => void) | undefined
    const stop = this.onChange(value => { queue.splice(0, queue.length, value); wake?.() }), close = (): void => { wake?.() }
    const signal = options.signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, options.signal]); signal.addEventListener('abort', close)
    try { while (!signal.aborted) { if (queue.length === 0) await new Promise<void>(resolve => { wake = resolve }); while (queue.length > 0 && !signal.aborted) yield queue.shift()! } }
    finally { stop(); signal.removeEventListener('abort', close) }
  }
  close(): Promise<void> {
    return this.#closing ??= (async () => { this.#closed = true; this.#stopAuthority(); this.#lifetime.abort(new Error('SESSION_CLOSED')); this.#notify(); await this.#tail; await this.#replayTail; this.#database = 'closed'; await this.#runtime?.close(); this.signals.close(); await this.content.close(); await this.#options.release(); this.#notify(); this.#listeners.clear(); this.#factListeners.clear(); this.#statusListeners.clear(); this.#changeListeners.clear() })()
  }
}
function toSqlValue(value: QueryParameter): MaterializedLocalSqlValue {
  if (value === null) return { kind: 'null' }; if (typeof value === 'bigint') return { kind: 'integer', value: value.toString() }; if (typeof value === 'number') return Number.isSafeInteger(value) ? { kind: 'integer', value: String(value) } : { kind: 'real', value }; if (typeof value === 'string') return { kind: 'text', value }; return { kind: 'blob', value: value.slice() }
}
function fromSqlValue(value: MaterializedLocalSqlValue): QueryParameter { switch (value.kind) { case 'null': return null; case 'integer': { const bigint = BigInt(value.value); return bigint >= BigInt(Number.MIN_SAFE_INTEGER) && bigint <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(bigint) : bigint }; case 'real': case 'text': return value.value; case 'blob': return value.value.slice() } }
function readEvents(events: readonly ApplicationEvent[], revision: MaterializedRevision, options: ApplicationEventOptions): ApplicationEventBatch {
  const topics = options.topics === undefined ? null : [...new Set(options.topics)].sort(), limit = options.limit ?? 100
  check(Number.isSafeInteger(limit) && limit > 0 && limit <= 1000 && (topics === null || topics.length <= 128 && topics.every(topic => typeof topic === 'string' && topic.length <= 128)), 'EVENT_READ_LIMIT')
  const scope = JSON.stringify(topics); let offset = 0
  if (options.cursor !== undefined) { check(options.cursor.length <= 128 * 1024, 'EVENT_CURSOR_LIMIT'); const cursor = JSON.parse(options.cursor) as { revision: string; scope: string; offset: number }; check(cursor.revision === revision.digest, 'EVENT_CURSOR_STALE'); check(cursor.scope === scope && Number.isSafeInteger(cursor.offset) && cursor.offset >= 0 && cursor.offset <= events.length, 'EVENT_CURSOR_INVALID'); offset = cursor.offset }
  const selected: ApplicationEvent[] = []; let index = offset
  while (index < events.length && selected.length < limit) { const event = events[index++]!; if (topics === null || topics.includes(event.topic)) selected.push(structuredClone(event)) }
  return { revision, events: selected, cursor: JSON.stringify({ revision: revision.digest, scope, offset: index }), hasMore: index < events.length }
}
export type { MaterializedRevision, SessionStatus, ApplicationReadView, QueryRows, QueryParameter, ApplicationEvent, ApplicationEventOptions, ApplicationEventBatch, CommandOptions, ApplicationChange } from './session-types.js'
export { ApplicationOperation } from './operation.js'
export type { ApplicationSubmission, OperationInspection, MaterializedOperation, RetentionEvidence } from './operation.js'

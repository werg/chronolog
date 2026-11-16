import {
  encodePlatformOp,
  isPlatformOp,
  isSqlValue,
  platformOp,
  toSqlValue,
  type CollectiveGovernance,
  type CollectiveRole,
  type MemberChange,
  type PlatformOp,
  type SqlStatement,
  type SqlValue,
} from '@chronolog/protocol'
import {
  ChronologRpcError,
  isChronologRpcError,
  type LiveSqlEvent,
  type LocalSqlValue,
  type NodeStatus,
  type ReplicationStatus,
  type RevisionMetadata,
  type RpcCallOptions,
  type RpcProgramStep,
  type RpcSqlStatement,
  type RpcTransport,
  type SettlementEvidence,
  type SubmitTransactionResponse,
  type TransactionOutcome,
  type UnaryRequest,
  type UnaryResponse,
  type UnaryRpcMethod,
  type ValidatorWatermark,
} from '@chronolog/rpc'

import {
  decodeLocalSqlResult,
  encodeCompiledLocalSqlQuery,
  encodeLocalSqlParameters,
  type CompiledLocalSqlQuery,
  type DecodedLocalSqlResult,
  type LocalSqlInput,
} from './local-sql.js'
import {
  TransactionRejectedError,
  createdObjectId,
  ownershipSteps,
  type OfferAllInput,
  type OfferRowInput,
  type ShareInput,
} from './ownership.js'
import { StreamResource } from './stream-resource.js'
import { SealedDataActions } from './sealed.js'

export interface ChronologClientOptions {
  readonly transport: RpcTransport
  readonly groupId: string
  readonly token?: string
  readonly requestId?: () => string
  readonly unaryRetryAttempts?: number
  readonly streamRetryDelayMs?: (attempt: number) => number
}

export interface QueryOptions {
  readonly signal?: AbortSignal
  readonly maxRows?: number
  readonly atRevision?: string
}

export interface LocalSqlQueryResponse {
  readonly revision: RevisionMetadata
  readonly result: DecodedLocalSqlResult
}

export interface LiveQueryValue {
  readonly type: LiveSqlEvent['type']
  readonly revision: RevisionMetadata
  readonly queryDigest: string
  readonly result?: DecodedLocalSqlResult
  readonly resetReason?: Extract<LiveSqlEvent, { type: 'reset' }>['reason']
}

export interface TransactionOptions {
  readonly signal?: AbortSignal
  /** Repeating a key with the same steps returns the original submission. */
  readonly idempotencyKey?: string
}

/** A JavaScript value bound to a SQL parameter; see `toSqlValue` for the mapping. */
export type ClientSqlValue = null | undefined | boolean | bigint | number | string | Uint8Array | SqlValue
export type ClientSqlBindings = readonly ClientSqlValue[] | Readonly<Record<string, ClientSqlValue>>

/** One statement of a transaction, in the shape common SQL builders produce. */
export interface CompiledSqlStatement {
  readonly sql: string
  /** Positional values, or named values keyed with or without their `:`/`@`/`$` prefix. */
  readonly params?: readonly unknown[] | Readonly<Record<string, unknown>>
}

export type TransactionStatementInput = string | CompiledSqlStatement | SqlStatement

/** One step of a transaction: a SQL statement, or a platform operation built with `platformOp`. */
export type TransactionStepInput = TransactionStatementInput | PlatformOp

export class TransactionHandle {
  readonly outcome: StreamResource<TransactionOutcome>
  readonly evidence: StreamResource<SettlementEvidence>

  constructor(
    readonly client: ChronologClient,
    readonly submission: SubmitTransactionResponse,
  ) {
    this.outcome = client.transactionOutcome(submission.transactionId)
    this.evidence = client.settlementEvidence(submission.transactionId)
  }

  get transactionId(): string { return this.submission.transactionId }

  /** Resolves once the transaction is accepted or rejected at its current position. */
  async settled(options: { readonly signal?: AbortSignal } = {}): Promise<TransactionOutcome> {
    for await (const outcome of this.outcome) {
      if (options.signal?.aborted === true) throw options.signal.reason
      if (outcome.outcome.type !== 'pending') return outcome
    }
    throw new ChronologRpcError('transport_unavailable', 'Outcome stream ended before the transaction settled')
  }

  /**
   * Resolves once the transaction is accepted; throws `TransactionRejectedError`
   * (with a parsed `reason`) if it is rejected. Like `settled()`, this is the
   * outcome at the transaction's current position.
   */
  async accepted(options: { readonly signal?: AbortSignal } = {}): Promise<TransactionOutcome> {
    const outcome = await this.settled(options)
    if (outcome.outcome.type === 'rejected') throw new TransactionRejectedError(this.transactionId, outcome.outcome.rejection)
    return outcome
  }

  /** The id of the grant, team or transfer offer created by step `stepIndex` of this transaction. */
  createdId(stepIndex: number): Promise<Uint8Array> {
    return createdObjectId(this.transactionId, stepIndex)
  }

  dispose(): void { this.outcome.dispose(); this.evidence.dispose() }
  [Symbol.dispose](): void { this.dispose() }
}

export class ChronologClient {
  readonly groupId: string
  readonly #transport: RpcTransport
  readonly #token?: string
  readonly #idFactory: () => string
  readonly #unaryRetryAttempts: number
  readonly #streamRetryDelayMs?: (attempt: number) => number
  readonly #resources = new Set<{ dispose(): void }>()
  #identity: Promise<Uint8Array> | undefined
  #closed = false
  /** Sharing, teams and transfers of owned rows; each call submits one transaction. */
  readonly ownership: OwnershipActions = new OwnershipActions(this)
  /** Explicit reader policies and client-encrypted BLOB columns. */
  readonly sealed: SealedDataActions = new SealedDataActions(this)

  constructor(options: ChronologClientOptions) {
    this.groupId = options.groupId
    this.#transport = options.transport
    if (options.token !== undefined) this.#token = options.token
    this.#idFactory = options.requestId ?? (() => crypto.randomUUID())
    this.#unaryRetryAttempts = options.unaryRetryAttempts ?? 2
    if (options.streamRetryDelayMs !== undefined) this.#streamRetryDelayMs = options.streamRetryDelayMs
  }

  async query(sql: string, bindings: readonly LocalSqlInput[] = [], options: QueryOptions = {}): Promise<LocalSqlQueryResponse> {
    const response = await this._unary('query.localSql', {
      groupId: this.groupId,
      requestId: this._requestId(),
      sql,
      parameters: encodeLocalSqlParameters(bindings),
      ...(options.maxRows === undefined ? {} : { maxRows: options.maxRows }),
      ...(options.atRevision === undefined ? {} : { atRevision: options.atRevision }),
    }, options.signal === undefined ? {} : { signal: options.signal })
    this._assertCompatibility(response.revision)
    return { revision: response.revision, result: decodeLocalSqlResult(response.result) }
  }

  async queryCompiled(query: CompiledLocalSqlQuery, options: QueryOptions = {}): Promise<LocalSqlQueryResponse> {
    const compiled = encodeCompiledLocalSqlQuery(query)
    return this.query(compiled.sql, compiled.parameters, options)
  }

  liveQuery(sql: string, bindings: readonly LocalSqlInput[] = [], options: Omit<QueryOptions, 'atRevision'> = {}): StreamResource<LiveQueryValue> {
    const requestId = this._requestId()
    const parameters = encodeLocalSqlParameters(bindings)
    let queryDigest: string | undefined
    return this.#track(new StreamResource({
      open: (cursor, signal) => mapAsync(
        this.#transport.stream('query.liveSql', {
          groupId: this.groupId,
          requestId,
          sql,
          parameters,
          ...(options.maxRows === undefined ? {} : { maxRows: options.maxRows }),
          ...(cursor === undefined || queryDigest === undefined ? {} : { resume: { groupId: this.groupId, queryDigest, eventSetRevision: cursor } }),
        }, this.#callOptions(signal)),
        (event): LiveQueryValue => {
          this._assertCompatibility(event.revision)
          queryDigest = event.queryDigest
          return {
            type: event.type,
            revision: event.revision,
            queryDigest: event.queryDigest,
            ...(event.result === undefined ? {} : { result: decodeLocalSqlResult(event.result) }),
            ...(event.type === 'reset' ? { resetReason: event.reason } : {}),
          }
        },
      ),
      cursor: (value) => value.revision.eventSetRevision,
      ...(this.#streamRetryDelayMs === undefined ? {} : { retryDelayMs: this.#streamRetryDelayMs }),
    }))
  }

  /**
   * Submit SQLite statements and platform operations as one replicated
   * transaction, executed in order as this node's key. Any failing step
   * rejects the whole transaction; use `SELECT chronolog_assert(condition,
   * 'code')` to state assumptions. Rows written belong to this node's key
   * unless a grant or collective says otherwise.
   */
  async transaction(steps: readonly TransactionStepInput[], options: TransactionOptions = {}): Promise<TransactionHandle> {
    const submission = await this._unary('transaction.submit', {
      groupId: this.groupId,
      requestId: this._requestId(),
      steps: steps.map(encodeTransactionStep),
      ...(options.idempotencyKey === undefined ? {} : { idempotencyKey: options.idempotencyKey }),
    }, options.signal === undefined ? {} : { signal: options.signal })
    return new TransactionHandle(this, submission)
  }

  async getTransactionOutcome(transactionId: string): Promise<TransactionOutcome> {
    return this._unary('transaction.getOutcome', { groupId: this.groupId, transactionId, requestId: this._requestId() })
  }

  transactionOutcome(transactionId: string): StreamResource<TransactionOutcome> {
    const requestId = this._requestId()
    return this.#revisionStream(
      (cursor, signal) => this.#transport.stream('transaction.streamOutcome', {
        groupId: this.groupId,
        transactionId,
        requestId,
        ...(cursor === undefined ? {} : { resumeAfterEventSetRevision: cursor }),
      }, this.#callOptions(signal)),
      (outcome) => outcome.eventSetRevision,
    )
  }

  async getSettlementEvidence(transactionId: string): Promise<SettlementEvidence> {
    return this._unary('evidence.getSettlement', { groupId: this.groupId, transactionId, requestId: this._requestId() })
  }

  settlementEvidence(transactionId: string): StreamResource<SettlementEvidence> {
    const requestId = this._requestId()
    return this.#revisionStream(
      (cursor, signal) => this.#transport.stream('evidence.streamSettlement', {
        groupId: this.groupId,
        transactionId,
        requestId,
        ...(cursor === undefined ? {} : { resumeAfterEventSetRevision: cursor }),
      }, this.#callOptions(signal)),
      (evidence) => evidence.evidenceRevision,
    )
  }

  async validatorWatermark(): Promise<ValidatorWatermark> {
    return this._unary('evidence.getValidatorWatermark', { groupId: this.groupId, requestId: this._requestId() })
  }

  async getReplicationStatus(): Promise<ReplicationStatus> {
    return this._unary('node.getReplicationStatus', { groupId: this.groupId, requestId: this._requestId() })
  }

  replicationStatus(): StreamResource<ReplicationStatus> {
    const requestId = this._requestId()
    return this.#revisionStream(
      (cursor, signal) => this.#transport.stream('node.streamReplicationStatus', {
        groupId: this.groupId,
        requestId,
        ...(cursor === undefined ? {} : { resumeAfterEventSetRevision: cursor }),
      }, this.#callOptions(signal)),
      (status) => status.revision,
    )
  }

  async getStatus(): Promise<NodeStatus> {
    const status = await this._unary('node.getStatus', { groupId: this.groupId, requestId: this._requestId() })
    if (status.revision !== undefined) this._assertCompatibility(status.revision)
    return status
  }

  status(): StreamResource<NodeStatus> {
    const requestId = this._requestId()
    return this.#revisionStream(
      (cursor, signal) => mapAsync(this.#transport.stream('node.streamStatus', {
        groupId: this.groupId,
        requestId,
        ...(cursor === undefined ? {} : { resumeAfterEventSetRevision: cursor }),
      }, this.#callOptions(signal)), (status) => { if (status.revision !== undefined) this._assertCompatibility(status.revision); return status }),
      (status) => status.revision?.eventSetRevision,
    )
  }

  /**
   * This node's signing key: the key that signs its transactions and owns the
   * rows they insert. Compare it with `ownerKeySql()` in local reads.
   */
  identity(): Promise<Uint8Array> {
    this.#identity ??= this.getStatus().then(
      (status) => Uint8Array.from(Buffer.from(status.nodeId, 'base64url')),
      (error: unknown) => { this.#identity = undefined; throw error },
    )
    return this.#identity
  }

  queryResourceKey(sql: string, bindings: readonly LocalSqlInput[] = []): string {
    return `${sql}\0${stableClientValue(bindings)}`
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    for (const resource of this.#resources) resource.dispose()
    this.#resources.clear()
    await this.#transport.close?.()
  }

  _requestId(): string { return this.#idFactory() }
  /** Retained for callers that validate revisions; every manifest is accepted. */
  _assertCompatibility(_revision: RevisionMetadata): void { /* no generated bindings to check */ }

  async _unary<M extends UnaryRpcMethod>(method: M, request: UnaryRequest<M>, options: RpcCallOptions = {}): Promise<UnaryResponse<M>> {
    if (this.#closed) throw new ChronologRpcError('transport_unavailable', 'Client is closed')
    let attempt = 0
    while (true) {
      try { return await this.#transport.unary(method, request, { ...this.#callOptions(options.signal), ...options }) } catch (error) {
        attempt += 1
        if (attempt > this.#unaryRetryAttempts || !isChronologRpcError(error) || !error.retryable || options.signal?.aborted === true) throw error
        await delay(Math.min(50 * 2 ** attempt, 500), options.signal)
      }
    }
  }

  #revisionStream<T>(open: (cursor: string | undefined, signal: AbortSignal) => AsyncIterable<T>, cursor: (value: T) => string | undefined): StreamResource<T> {
    return this.#track(new StreamResource({ open, cursor, ...(this.#streamRetryDelayMs === undefined ? {} : { retryDelayMs: this.#streamRetryDelayMs }) }))
  }

  #track<T>(resource: StreamResource<T>): StreamResource<T> {
    this.#resources.add(resource)
    resource.onDispose(() => this.#resources.delete(resource))
    return resource
  }

  #callOptions(signal?: AbortSignal): RpcCallOptions {
    return { ...(signal === undefined ? {} : { signal }), ...(this.#token === undefined ? {} : { token: this.#token }) }
  }
}

/** A submitted ownership change, with the id of the object it created (when it creates one). */
export interface OwnershipChange<Id extends Uint8Array | undefined = undefined> {
  readonly handle: TransactionHandle
  readonly id: Id
}

/**
 * Sharing, teams and transfers. Each method submits one transaction whose
 * only step is the platform operation; await `change.handle.accepted()` for
 * the result. To combine them with SQL in one transaction, use
 * `ownershipSteps` or `platformOp` and `TransactionHandle.createdId()`.
 */
export class OwnershipActions {
  constructor(readonly client: ChronologClient) {}

  /** Let `input.with` change your rows of a table (one row, or all of them). */
  async share(input: ShareInput, options?: TransactionOptions): Promise<OwnershipChange<Uint8Array>> {
    return this.#create(ownershipSteps.share(input), options)
  }

  /** End a grant. The grantor (or an admin of a grantor team) revokes; the grantee may renounce. */
  async revoke(grantId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.revokeGrant(grantId), options)
  }

  /** Create a team administered by you. Invitees join by accepting. */
  async createTeam(
    input: { readonly governance?: CollectiveGovernance; readonly invite?: readonly Uint8Array[] } = {},
    options?: TransactionOptions,
  ): Promise<OwnershipChange<Uint8Array>> {
    return this.#create(ownershipSteps.createTeam(input), options)
  }

  async acceptInvitation(teamId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.acceptMembership(teamId), options)
  }

  async leaveTeam(teamId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.leave(teamId), options)
  }

  /** Invite keys to a team (team admins only); an existing member's role changes instead. */
  async invite(teamId: Uint8Array, members: readonly Uint8Array[], role: CollectiveRole = 'member', options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(ownershipSteps.invite(teamId, members, role), options)
  }

  async removeMembers(teamId: Uint8Array, members: readonly Uint8Array[], options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(ownershipSteps.remove(teamId, members), options)
  }

  /** Any mix of invitations, role changes and removals, applied together. */
  async setMembers(teamId: Uint8Array, changes: readonly MemberChange[], options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.setMembers(teamId, changes), options)
  }

  /** Offer one row to a new owner; it moves when the recipient accepts. */
  async offerRow(input: OfferRowInput, options?: TransactionOptions): Promise<OwnershipChange<Uint8Array>> {
    return this.#create(ownershipSteps.offerRow(input), options)
  }

  /**
   * Offer every row you (or a team you administer) own, across all tables:
   * the key-change path. The offered row set and contents must remain unchanged.
   */
  async offerAll(input: OfferAllInput, options?: TransactionOptions): Promise<OwnershipChange<Uint8Array>> {
    return this.#create(ownershipSteps.offerAll(input), options)
  }

  /** Cancel your offer, or decline an offer addressed to you (team admins may act for teams). */
  async cancelOffer(offerId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.cancelTransfer(offerId), options)
  }

  async acceptOffer(offerId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.acceptTransfer(offerId), options)
  }

  async #submit(step: PlatformOp, options?: TransactionOptions): Promise<OwnershipChange> {
    return { handle: await this.client.transaction([step], options), id: undefined }
  }

  async #create(step: PlatformOp, options?: TransactionOptions): Promise<OwnershipChange<Uint8Array>> {
    const handle = await this.client.transaction([step], options)
    return { handle, id: await handle.createdId(0) }
  }
}

function encodeTransactionStep(input: TransactionStepInput): RpcProgramStep {
  return typeof input !== 'string' && isPlatformOp(input) ? { platform: encodePlatformOp(input) } : encodeTransactionStatement(input)
}

function encodeTransactionStatement(input: TransactionStatementInput): RpcSqlStatement {
  if (typeof input === 'string') return { sql: input, bindings: [] }
  if ('bindings' in input) {
    return {
      sql: input.sql,
      bindings: input.bindings.map((binding) => ({ parameter: binding.parameter, value: toRpcValue(binding.value) })),
    }
  }
  const params = input.params ?? []
  if (isClientSqlValueArray(params)) {
    return {
      sql: input.sql,
      bindings: params.map((value, index) => ({ parameter: { kind: 'index' as const, index: index + 1 }, value: toRpcValue(toSqlValue(value)) })),
    }
  }
  const used = new Set<string>()
  const bindings = scanNamedParameters(input.sql).map((token) => {
    const bare = token.slice(1)
    const key = Object.hasOwn(params, token) ? token : Object.hasOwn(params, bare) ? bare : undefined
    if (key === undefined) throw new TypeError(`Missing SQL binding ${token}`)
    used.add(key)
    return { parameter: { kind: 'name' as const, name: token }, value: toRpcValue(toSqlValue(params[key])) }
  })
  const unused = Object.keys(params).filter((key) => !used.has(key))
  if (unused.length > 0) throw new TypeError(`Unused SQL bindings: ${unused.join(', ')}`)
  return { sql: input.sql, bindings }
}

function toRpcValue(value: SqlValue): LocalSqlValue {
  if (!isSqlValue(value)) throw new TypeError('Invalid SQL value')
  switch (value.kind) {
    case 'null': return { kind: 'null' }
    case 'integer': return { kind: 'integer', value: value.value.toString(10) }
    case 'real': return { kind: 'real', value: value.value }
    case 'text': return { kind: 'text', value: value.value }
    case 'blob': return { kind: 'blob', value: Uint8Array.from(value.value) }
  }
}

/** Finds SQLite named parameters while ignoring quoted text, identifiers, and comments. */
function scanNamedParameters(sql: string): readonly string[] {
  const found: string[] = []
  const seen = new Set<string>()
  for (let index = 0; index < sql.length;) {
    const char = sql[index]!
    const next = sql[index + 1]
    if (char === "'" || char === '"' || char === '`' || char === '[') {
      const close = char === '[' ? ']' : char
      index += 1
      while (index < sql.length) {
        if (sql[index] === close) {
          if (close !== ']' && sql[index + 1] === close) { index += 2; continue }
          index += 1
          break
        }
        index += 1
      }
      continue
    }
    if (char === '-' && next === '-') { index = sql.indexOf('\n', index + 2); if (index < 0) break; continue }
    if (char === '/' && next === '*') { const end = sql.indexOf('*/', index + 2); index = end < 0 ? sql.length : end + 2; continue }
    if ((char === ':' || char === '@' || char === '$') && /[A-Za-z_]/u.test(next ?? '')) {
      let end = index + 2
      while (/[A-Za-z0-9_]/u.test(sql[end] ?? '')) end += 1
      const token = sql.slice(index, end)
      if (!seen.has(token)) { seen.add(token); found.push(token) }
      index = end
      continue
    }
    index += 1
  }
  return found
}

function toBase64Url(value: Uint8Array): string { return Buffer.from(value).toString('base64url') }

async function* mapAsync<A, B>(source: AsyncIterable<A>, map: (value: A) => B): AsyncIterable<B> {
  for await (const value of source) yield map(value)
}

function stableClientValue(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'bigint') return `${value}n`
  if (value instanceof Uint8Array) return toBase64Url(value)
  if (Array.isArray(value)) return `[${value.map(stableClientValue).join(',')}]`
  if (typeof value === 'object') {
    const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableClientValue(item)}`).join(',')}}`
  }
  return typeof value
}

function isClientSqlValueArray(value: readonly unknown[] | Readonly<Record<string, unknown>>): value is readonly unknown[] {
  return Array.isArray(value)
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted === true) return Promise.reject(signal.reason)
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timeout); reject(signal?.reason) }
    const timeout = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve() }, milliseconds)
    signal?.addEventListener('abort', abort, { once: true })
  })
}

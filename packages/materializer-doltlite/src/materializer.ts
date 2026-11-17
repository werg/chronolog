import {
  bytesToBase64Url,
  equalBytes as bytesEqual,
  compareTransactionOrder,
  decodeTransactionCore,
  encodeTransactionCore,
  encodeChangeProgram,
  encodeCanonicalCbor,
  hashDomain,
  DOMAINS,
  executionManifestArtifacts,
  transactionDigest,
  type ExecutionManifest,
  type ManifestArtifacts,
  type TransactionOrderKey,
} from '@chronolog/protocol'
import type { MaterializedApplicationSnapshot, MaterializedReadHandle, PeerExecutionControls } from '@chronolog/materializer'

import {
  HEAD_BRANCH,
  checkpointOrderDigest,
  cleanupOrphanBranches,
  createCheckpointRef,
  createReplayBranch,
  createRevisionRef,
  discoverCheckpoints,
  discoverPublishedRef,
  discoverFinalRef,
  publishFinalRef,
  orderDigest,
  publishRef,
  removeBranchIfPresent,
  verifyPublishedLog,
  type PublishedRef,
} from './checkpoints.js'
import { withAuthorizer } from './sql-profile.js'
import { applyPeerExecutionControl, hasCurrentPeerControl, hasPeerExecutionControl, peerControlFor, validatePeerExecutionControls } from './peer-controls.js'
import { executeTransactionProgram, SqlRejection } from './sql-executor.js'
import { executeLocalSql } from './sql-values.js'
import {
  initializeSystemLog,
  insertExecutionManifest,
  insertSystemLogRow,
  readExecutionManifest,
  readSystemLog,
} from './system-log.js'
import { materializedLogDigest } from './snapshot-evidence.js'
import { PLATFORM_DIGEST } from './platform/digest.js'
import { initializePlatform, readRootAdministrator } from './platform/schema.js'
import type {
  ReplayProposal,
  DatabaseLike,
  LocalSqlOptions,
  LocalSqlQueryResult,
  LocalSqlValue,
  MaterializedRevision,
  MaterializerBackendInfo,
  MaterializerCheckpointInfo,
  MaterializerSqlBackend,
  MaterializerOptions,
  MaterializerPublicationFaultPoint,
  OutcomeChange,
  RevisionSubscriber,
  StoredExecutionManifest,
  TransactionLogRow,
  TransactionOutcome,
} from './types.js'

export class MaterializerInputError extends Error {
  constructor(readonly code: string) {
    super(code)
    this.name = 'MaterializerInputError'
  }
}

export class DeterministicMaterializer implements MaterializerSqlBackend {
  readonly #readLeases = new Set<() => void>()
  readonly #writer: DatabaseLike
  #reader: DatabaseLike
  #finalReader: DatabaseLike
  #finalPublished: PublishedRef
  #finalLog: TransactionLogRow[]
  readonly #sourceOptions: MaterializerOptions
  readonly #options: Required<Pick<MaterializerOptions, 'checkpointEvery' | 'retainCheckpoints'>>
  readonly #backend: MaterializerBackendInfo
  readonly #executionManifest: ExecutionManifest
  readonly #artifacts: ManifestArtifacts
  readonly #rootAdministrator: Uint8Array
  readonly #subscribers = new Set<RevisionSubscriber>()
  #published: PublishedRef
  #checkpoints: MaterializerCheckpointInfo[]
  #order: Uint8Array[]
  #log: TransactionLogRow[]
  #closed = false
  #materializing = false
  #checkpointError: string | null = null

  private constructor(
    writer: DatabaseLike,
    reader: DatabaseLike,
    options: MaterializerOptions,
    backend: MaterializerBackendInfo,
    executionManifest: ExecutionManifest,
    artifacts: ManifestArtifacts,
    published: PublishedRef,
    checkpoints: MaterializerCheckpointInfo[],
    log: TransactionLogRow[],
    finalReader: DatabaseLike,
    finalPublished: PublishedRef,
    finalLog: TransactionLogRow[],
  ) {
    this.#writer = writer
    this.#reader = reader
    this.#finalReader = finalReader
    this.#finalPublished = finalPublished
    this.#finalLog = finalLog
    this.#sourceOptions = options
    this.#backend = backend
    this.#executionManifest = structuredClone(executionManifest)
    this.#artifacts = artifacts
    this.#rootAdministrator = copyBytes(options.rootAdministrator)
    this.#published = published
    this.#checkpoints = checkpoints
    this.#log = log
    this.#order = log.map((row) => copyBytes(row.txId))
    this.#options = {
      checkpointEvery: validatePositiveInteger(options.checkpointEvery ?? 100, 'checkpointEvery'),
      retainCheckpoints: validatePositiveInteger(options.retainCheckpoints ?? 16, 'retainCheckpoints'),
    }
  }

  static async open(options: MaterializerOptions): Promise<DeterministicMaterializer> {
    if (!(options.rootAdministrator instanceof Uint8Array) || options.rootAdministrator.length !== 32) {
      throw new MaterializerInputError('MATERIALIZER_ROOT_ADMINISTRATOR_INVALID')
    }
    if (!bytesEqual(options.executionManifest.platformDigest, PLATFORM_DIGEST)) {
      throw new MaterializerInputError('MATERIALIZER_PLATFORM_DIGEST_MISMATCH')
    }
    const artifacts = await executionManifestArtifacts(options.executionManifest)
    const bootstrapProgram = bootstrapBytes(options)
    const expected: ExpectedState = { artifacts, rootAdministrator: options.rootAdministrator, bootstrapProgram }
    const bootstrapIdentity = await hashDomain(DOMAINS.peerSchema, bootstrapProgram)
    const opened = openDatabase(options)
    let reader: DatabaseLike | null = null
    let finalReader: DatabaseLike | null = null
    try {
      if (!bytesEqual(opened.backend.engineDigest, options.executionManifest.engineDigest)) {
        throw new MaterializerInputError('MATERIALIZER_ENGINE_DIGEST_MISMATCH')
      }
      let published = discoverPublishedRef(opened.database)
      if (published === null) {
        published = initializeRepository(opened.database, expected, options.forkSeeding === true, options, bootstrapIdentity)
      } else {
        resetActiveWorkingSet(opened.database)
        opened.database.doltCheckout(HEAD_BRANCH)
        verifyDatabaseState(opened.database, expected)
      }
      const log = readSystemLog(opened.database)
      verifyPublishedLog(published, log)
      const checkpoints = validateCheckpointRefs(opened.database, published, log, artifacts)
      cleanupOrphanBranches(opened.database, published, checkpoints)
      // Read leases are process-owned. No lease can survive reopening the sole
      // storage owner, so crash leftovers can be reclaimed before new readers.
      for (const branch of opened.database.doltBranches()) {
        if (branch.name.startsWith('chronolog_read_')) opened.database.doltDeleteBranch(branch.name)
      }

      const readerOpened = openDatabase(options)
      reader = readerOpened.database
      if (!bytesEqual(readerOpened.backend.engineDigest, options.executionManifest.engineDigest)) {
        throw new MaterializerInputError('MATERIALIZER_ENGINE_DIGEST_MISMATCH')
      }
      reader.doltCheckout(published.branchRef)
      verifyDatabaseState(reader, expected)
      const readerLog = readSystemLog(reader)
      verifyPublishedLog(published, readerLog)
      if (reader.doltHashOf(published.branchRef) !== published.contentHash) {
        throw new Error('MATERIALIZER_READER_CONTENT_MISMATCH')
      }
      const finalPublished = discoverFinalRef(opened.database) ?? publishFinalRef(
        opened.database, 0n, [], checkpoints.find((checkpoint) => checkpoint.prefixLength === 0)!.doltCommitHash,
      )
      finalReader = openDatabase(options).database
      finalReader.doltCheckout(finalPublished.branchRef)
      verifyDatabaseState(finalReader, expected)
      const finalLog = readSystemLog(finalReader)
      verifyPublishedLog(finalPublished, finalLog)
      verifyFinalPrefix(finalLog, readerLog)
      return new DeterministicMaterializer(
        opened.database,
        reader,
        options,
        opened.backend,
        options.executionManifest,
        artifacts,
        published,
        checkpoints,
        readerLog,
        finalReader,
        finalPublished,
        finalLog,
      )
    } catch (error) {
      reader?.close()
      finalReader?.close()
      opened.database.close()
      throw error
    }
  }

  get revision(): bigint { return this.#published.revision }
  get orderLength(): number { return this.#order.length }
  get finalRevision(): bigint { return this.#finalPublished.revision }
  get finalOrderLength(): number { return this.#finalLog.length }
  get executionManifestDigest(): Uint8Array { return copyBytes(this.#artifacts.executionManifestDigest) }
  get executionManifest(): ExecutionManifest { return structuredClone(this.#executionManifest) }
  get backend(): MaterializerBackendInfo { return structuredClone(this.#backend) }
  get checkpointError(): string | null { return this.#checkpointError }
  get databaseContentHash(): string { return this.#published.contentHash }

  proposalIdAt(index: number): Uint8Array | null { return this.#order[index]?.slice() ?? null }

  transactionLogDigest(): Promise<Uint8Array> { return materializedLogDigest(this.#log) }

  checkpoints(): readonly MaterializerCheckpointInfo[] {
    return this.#checkpoints.map((checkpoint) => structuredClone(checkpoint))
  }

  transactionLog(): readonly TransactionLogRow[] { return this.#log.map(cloneLogRow) }

  outcome(txId: Uint8Array): TransactionOutcome | null {
    const row = this.#log.find((entry) => bytesEqual(entry.txId, txId))
    if (row === undefined) return null
    return {
      txId: copyBytes(row.txId),
      orderKey: structuredClone(row.orderKey),
      orderIndex: row.orderIndex,
      outcome: row.outcome,
      rejectionCode: row.rejectionCode,
      failingStatementIndex: row.failingStatementIndex,
    }
  }

  localSql(
    sql: string,
    parameters: readonly LocalSqlValue[] = [],
    options: LocalSqlOptions = {},
  ): LocalSqlQueryResult {
    this.#assertOpen()
    const final = options.view === 'final'
    const revision = final ? this.finalRevision : this.revision
    if (options.atRevision !== undefined && options.atRevision !== revision) {
      throw new MaterializerInputError('MATERIALIZER_REVISION_UNAVAILABLE')
    }
    const result = executeLocalSql(final ? this.#finalReader : this.#reader, sql, parameters)
    return { revision, orderLength: final ? this.finalOrderLength : this.orderLength, view: final ? 'final' : 'local', finalOrderLength: this.finalOrderLength, ...result }
  }

  localQuery(
    sql: string,
    parameters: readonly LocalSqlValue[] = [],
    options: LocalSqlOptions = {},
  ): LocalSqlQueryResult {
    return this.localSql(sql, parameters, options)
  }

  captureApplication(options: { readonly view?: 'local' | 'final' } = {}): MaterializedApplicationSnapshot {
    this.#assertOpen()
    const view = options.view ?? 'local'
    const log = view === 'final' ? this.#finalLog : this.#log
    return {
      view, revision: view === 'final' ? this.finalRevision : this.revision, orderLength: log.length,
      finalRevision: this.finalRevision, finalOrderLength: this.finalOrderLength,
      transactionAt(index) {
        if (!Number.isSafeInteger(index) || index < 0 || index >= log.length) return null
        const entry = log[index]!
        return { txId: copyBytes(entry.txId), canonicalCandidate: copyBytes(entry.canonicalCandidate), outcome: entry.outcome }
      },
    }
  }

  captureRead(options: { readonly view?: 'local' | 'final' } = {}): MaterializedReadHandle {
    this.#assertOpen()
    if (this.#readLeases.size >= 16) throw new Error('MATERIALIZER_SNAPSHOT_LIMIT')
    const application = this.captureApplication(options)
    const { view, revision, orderLength, finalOrderLength } = application
    const published = view === 'final' ? this.#finalPublished : this.#published
    const branch = `chronolog_read_${crypto.randomUUID().replaceAll('-', '')}`
    this.#writer.doltBranch(branch, published.doltCommitHash)
    let reader: DatabaseLike | undefined
    try { reader = openDatabase(this.#sourceOptions).database; reader.doltCheckout(branch) }
    catch (error) { try { reader?.close() } finally { removeBranchIfPresent(this.#writer, branch) }; throw error }
    let released = false
    const release = (): void => {
      if (released) return
      released = true
      try { reader.close() }
      finally { try { removeBranchIfPresent(this.#writer, branch) } finally { this.#readLeases.delete(release) } }
    }
    this.#readLeases.add(release)
    return { ...application,
      query(sql, parameters = []) {
        if (released) throw new Error('MATERIALIZER_SNAPSHOT_RELEASED')
        return { revision, orderLength, finalOrderLength, view, ...executeLocalSql(reader, sql, parameters) }
      }, release }
  }

  subscribe(subscriber: RevisionSubscriber): () => void {
    this.#assertOpen()
    this.#subscribers.add(subscriber)
    return () => this.#subscribers.delete(subscriber)
  }

  async materialize(orderedTransactions: readonly ReplayProposal[], peerControls?: PeerExecutionControls): Promise<MaterializedRevision | null> {
    this.#assertOpen()
    if (this.#materializing) throw new Error('MATERIALIZER_REENTRANT_CALL')
    this.#materializing = true
    let replayBranch: string | null = null
    let revisionBranch: string | null = null
    let newCheckpoint: MaterializerCheckpointInfo | null = null
    let candidateReader: DatabaseLike | null = null
    let publishedMoved = false
    let replayBaseRef: string | null = null
    try {
      const transactions = orderedTransactions.map(cloneTransaction)
      if (peerControls === undefined && hasPeerExecutionControl(this.#writer)) throw new Error('MATERIALIZER_CONTROLS_REQUIRED')
      const controls = peerControls === undefined ? undefined : validatePeerExecutionControls(peerControls, transactions)
      // Rows of the published log were fully verified when they were read;
      // byte-identical rows are not re-verified, so an append costs O(1)
      // verification work instead of O(history).
      await validateTransactionSet(transactions, this.#log)
      for (const transaction of transactions) {
        if (!bytesEqual(transaction.core.executionManifestDigest, this.#artifacts.executionManifestDigest)) {
          throw new MaterializerInputError('MATERIALIZER_EXECUTION_MANIFEST_UNAVAILABLE')
        }
      }
      verifyFinalTransactions(this.#finalLog, transactions)
      validateExistingIdentities(this.#log, transactions)
      const changedAt = earliestDifference(this.#order, transactions.map((transaction) => transaction.txId))
      if (changedAt === null && (controls === undefined || hasCurrentPeerControl(this.#writer, controls))) return null
      const difference = changedAt ?? transactions.length

      const previousRevision = this.revision
      // #log is replaced, never mutated, so the reference stays a stable copy.
      const previousLog = this.#log
      const isAppend = difference === this.#order.length
      const checkpoint = isAppend ? null : this.#checkpointAtOrBefore(difference)
      if (!isAppend && checkpoint === null) throw new Error('MATERIALIZER_GENESIS_CHECKPOINT_MISSING')
      const baseRef = isAppend ? this.#published.doltCommitHash : checkpoint!.doltCommitHash
      replayBaseRef = baseRef
      const replayFrom = isAppend ? this.#order.length : checkpoint!.prefixLength
      const nextRevision = previousRevision + 1n

      replayBranch = createReplayBranch(this.#writer, nextRevision, baseRef)
      this.#writer.doltCheckout(replayBranch)
      verifyDatabaseState(this.#writer, this.#expected)
      verifyReplayBase(readSystemLog(this.#writer), transactions, replayFrom)

      for (let index = replayFrom; index < transactions.length; index += 1) {
        verifyNextLogIndex(this.#writer, index)
        if (controls !== undefined) applyPeerExecutionControl(this.#writer, controls.applicationId, peerControlFor(controls, transactions[index]!))
        this.#applyTransaction(transactions[index]!, index)
      }

      if (controls !== undefined) applyPeerExecutionControl(this.#writer, controls.applicationId, controls.revisions[controls.currentRevision]!)
      const candidateLog = readSystemLog(this.#writer)
      verifyDesiredLog(candidateLog, transactions)
      verifyDatabaseState(this.#writer, this.#expected)
      // Recovery can land exactly on a retained checkpoint. Publish its existing
      // immutable content under the new view revision without an empty commit.
      // A newer control projection may still change that candidate with no replay.
      const commitHash = this.#writer.prepare('SELECT * FROM dolt_status').all().length === 0
        ? baseRef : this.#writer.doltCommit(`chronolog revision ${nextRevision}`)
      const contentHash = this.#writer.doltHashOf(commitHash)
      if (contentHash !== this.#writer.doltHashOf()) throw new Error('MATERIALIZER_COMMIT_CONTENT_MISMATCH')
      this.#publicationFault('after_candidate_commit')

      const retainedBeforeInsertion = this.#checkpoints.filter(
        (entry) => isAppend || entry.prefixLength <= difference,
      )
      if (shouldCheckpoint(retainedBeforeInsertion, transactions.length, this.#options.checkpointEvery)) {
        newCheckpoint = createCheckpointRef(this.#writer, transactions.length, nextRevision, commitHash, candidateLog)
      }
      const nextPublished = createRevisionRef(this.#writer, nextRevision, transactions.length, commitHash, candidateLog)
      revisionBranch = nextPublished.branchRef
      if (nextPublished.contentHash !== contentHash) throw new Error('MATERIALIZER_REVISION_CONTENT_MISMATCH')
      this.#publicationFault('after_revision_ref_created')

      const candidateOpened = openDatabase(this.#sourceOptions)
      candidateReader = candidateOpened.database
      candidateReader.doltCheckout(revisionBranch)
      verifyDatabaseState(candidateReader, this.#expected)
      const readerLog = readSystemLog(candidateReader)
      verifyPublishedLog(nextPublished, readerLog)
      if (candidateReader.doltHashOf(revisionBranch) !== contentHash) {
        throw new Error('MATERIALIZER_CANDIDATE_READER_CONTENT_MISMATCH')
      }

      this.#publicationFault('before_head_publish')
      publishRef(this.#writer, nextPublished)
      publishedMoved = true
      this.#publicationFault('after_head_publish')

      const oldReader = this.#reader
      this.#reader = candidateReader
      candidateReader = null
      this.#published = nextPublished
      this.#log = readerLog
      this.#order = transactions.map((transaction) => copyBytes(transaction.txId))
      oldReader.close()
      this.#publicationFault('after_reader_swap')

      try {
        this.#writer.doltCheckout(HEAD_BRANCH)
        const retained = newCheckpoint === null ? retainedBeforeInsertion : [...retainedBeforeInsertion, newCheckpoint]
        this.#checkpoints = this.#pruneCheckpoints(retained)
        cleanupOrphanBranches(this.#writer, nextPublished, this.#checkpoints)
        this.#checkpointError = null
      } catch (error) {
        this.#checkpointError = nonThrowingDiagnostic(error, 'CHECKPOINT_CLEANUP_FAILED')
      }

      const event: MaterializedRevision = {
        revision: nextRevision,
        previousRevision,
        orderLength: transactions.length,
        replayFromIndex: replayFrom,
        replayedTransactions: transactions.length - replayFrom,
        checkpointPrefix: checkpoint?.prefixLength ?? replayFrom,
        contentHash,
        manifestDigest: this.executionManifestDigest,
        earliestChangedOrderIndex: difference,
        outcomeChanges: calculateOutcomeChanges(previousLog, this.#log),
      }
      for (const subscriber of [...this.#subscribers]) {
        try { subscriber(structuredClone(event)) } catch { /* subscriber failures are local */ }
      }
      return event
    } catch (error) {
      candidateReader?.close()
      rollbackIfActive(this.#writer)
      if (!publishedMoved) {
        try {
          if (replayBaseRef !== null && replayBranch !== null && this.#writer.doltActiveBranch() === replayBranch) {
            this.#writer.doltResetHard(replayBaseRef)
          }
          this.#writer.doltCheckout(HEAD_BRANCH)
          if (replayBranch !== null) removeBranchIfPresent(this.#writer, replayBranch)
          if (revisionBranch !== null) removeBranchIfPresent(this.#writer, revisionBranch)
          if (newCheckpoint !== null) removeBranchIfPresent(this.#writer, newCheckpoint.branchRef)
        } catch { /* startup orphan cleanup is authoritative */ }
      }
      throw error
    } finally {
      this.#materializing = false
    }
  }

  async publishFinal(prefixLength: number, peerControls?: PeerExecutionControls): Promise<void> {
    this.#assertOpen()
    if (!Number.isSafeInteger(prefixLength) || prefixLength < this.finalOrderLength || prefixLength > this.orderLength) {
      throw new MaterializerInputError('MATERIALIZER_FINAL_PREFIX_INVALID')
    }
    if (this.#materializing) throw new Error('MATERIALIZER_REENTRANT_CALL')
    this.#materializing = true
    let replayBranch: string | null = null
    let replayBaseRef: string | null = null
    let replayCommitted = false
    let reader: DatabaseLike | null = null
    try {
      const prefix = this.#log.slice(0, prefixLength)
      if (peerControls === undefined && hasPeerExecutionControl(this.#writer)) throw new Error('MATERIALIZER_CONTROLS_REQUIRED')
      const transactions = prefix.map(row => ({ txId: row.txId, candidateDigest: row.candidateDigest,
        canonicalCandidate: row.canonicalCandidate, core: decodeTransactionCore(row.canonicalCandidate) }))
      const controls = peerControls === undefined ? undefined : validatePeerExecutionControls(peerControls, transactions)
      if (controls !== undefined && !hasCurrentPeerControl(this.#writer, controls)) throw new Error('MATERIALIZER_CONTROL_PROJECTION_UNPUBLISHED')
      // The same settled data prefix can still need a newly restrictive control projection.
      if (prefixLength === this.finalOrderLength && (controls === undefined || hasCurrentPeerControl(this.#finalReader, controls))) return
      let commitHash: string
      if (prefixLength === this.#log.length) {
        commitHash = this.#published.doltCommitHash
      } else {
        const checkpoint = this.#checkpointAtOrBefore(prefixLength)
        if (checkpoint === null) throw new Error('MATERIALIZER_GENESIS_CHECKPOINT_MISSING')
        // A published final prefix is an immutable verified replay base. During
        // catch-up the local view can be far ahead of finality; rebuilding each
        // successive final prefix from an older checkpoint repeats settled SQL.
        const base = this.#finalPublished.prefixLength >= checkpoint.prefixLength ? this.#finalPublished : checkpoint
        replayBaseRef = base.doltCommitHash
        replayBranch = createReplayBranch(this.#writer, this.revision, replayBaseRef)
        this.#writer.doltCheckout(replayBranch)
        verifyDatabaseState(this.#writer, this.#expected)
        const baseLog = readSystemLog(this.#writer)
        verifyReplayBase(baseLog, transactions, base.prefixLength)
        verifyFinalPrefix(this.#finalLog, baseLog)
        for (let index = base.prefixLength; index < prefixLength; index += 1) {
          const transaction = transactions[index]!
          if (controls !== undefined) applyPeerExecutionControl(this.#writer, controls.applicationId, peerControlFor(controls, transaction))
          this.#applyTransaction(transaction, index)
        }
        if (controls !== undefined) applyPeerExecutionControl(this.#writer, controls.applicationId, controls.revisions[controls.currentRevision]!)
        verifyFinalPrefix(prefix, readSystemLog(this.#writer))
        commitHash = this.#writer.prepare('SELECT * FROM dolt_status').all().length === 0
          ? replayBaseRef : this.#writer.doltCommit(`chronolog final prefix ${prefixLength}`)
        replayCommitted = true
      }
      // Read and validate the exact SQL commit before publishing its final ref.
      const temporary = replayBranch ?? this.#published.branchRef
      reader = openDatabase(this.#sourceOptions).database
      reader.doltCheckout(temporary)
      verifyDatabaseState(reader, this.#expected)
      const log = readSystemLog(reader)
      if (log.length !== prefixLength) throw new Error('MATERIALIZER_FINAL_LOG_LENGTH_MISMATCH')
      verifyFinalPrefix(prefix, log)
      if (controls !== undefined && !hasCurrentPeerControl(reader, controls)) throw new Error('MATERIALIZER_FINAL_CONTROL_MISMATCH')
      const published = publishFinalRef(this.#writer, this.finalRevision + 1n, log, commitHash)
      reader.doltCheckout(published.branchRef)
      const oldReader = this.#finalReader
      this.#finalReader = reader
      reader = null
      this.#finalPublished = published
      this.#finalLog = log
      oldReader.close()
    } finally {
      try {
        reader?.close()
        rollbackIfActive(this.#writer)
        // Successful SQL transactions can precede a failed candidate commit.
        // Discard that private working set before returning to the local head.
        if (!replayCommitted && replayBaseRef !== null && this.#writer.doltActiveBranch() === replayBranch) {
          this.#writer.doltResetHard(replayBaseRef)
        }
        this.#writer.doltCheckout(HEAD_BRANCH)
        if (replayBranch !== null) removeBranchIfPresent(this.#writer, replayBranch)
      } finally { this.#materializing = false }
    }
  }

  close(): void {
    if (this.#closed) return
    for (const release of [...this.#readLeases]) release()
    this.#closed = true
    this.#subscribers.clear()
    this.#reader.close()
    this.#finalReader.close()
    this.#writer.close()
  }

  #applyTransaction(transaction: ReplayProposal, orderIndex: number): void {
    this.#writer.exec('BEGIN IMMEDIATE')
    this.#writer.exec('SAVEPOINT chronolog_program')
    let rejection: { readonly code: string; readonly statementIndex: number | null } | null = null
    try {
      const duplicate = this.#writer.prepare('SELECT tx_id FROM chronolog_transactions WHERE author_id = ? AND operation_id = ? LIMIT 1')
        .get(transaction.core.authorId, transaction.core.operationId)
      if (duplicate !== undefined) throw new SqlRejection('operation_conflict', null)
      executeTransactionProgram(this.#writer, transaction.core.program, {
          authorTimestampMs: transaction.core.authorTimestampMs,
          txId: transaction.txId,
          actor: transaction.core.authorId,
          groupId: transaction.core.groupId,
        }, this.#executionManifest.limits, { protectedChanges: !hasPeerExecutionControl(this.#writer) })
    } catch (error) {
      if (!(error instanceof SqlRejection)) {
        rollbackIfActive(this.#writer)
        throw error
      }
      rejection = { code: error.code, statementIndex: error.statementIndex }
    }
    try {
      // Roll back to the savepoint rather than the outer transaction: a full
      // ROLLBACK after checking out a replay branch can restore DoltLite's
      // previous branch working set, resurrecting later log rows.
      if (rejection !== null) this.#writer.exec('ROLLBACK TO SAVEPOINT chronolog_program')
      this.#writer.exec('RELEASE SAVEPOINT chronolog_program')
      insertSystemLogRow(this.#writer, logRow(transaction, orderIndex, rejection))
      this.#writer.exec('COMMIT')
    } catch (error) {
      rollbackIfActive(this.#writer)
      throw new Error(`MATERIALIZER_LOG_WRITE_FAILED:${errorMessage(error)}`, { cause: error })
    }
  }

  get #expected(): ExpectedState {
    return { artifacts: this.#artifacts, rootAdministrator: this.#rootAdministrator,
      bootstrapProgram: bootstrapBytes(this.#sourceOptions) }
  }

  #publicationFault(point: MaterializerPublicationFaultPoint): void {
    this.#sourceOptions.publicationFaultInjector?.(point)
  }

  #checkpointAtOrBefore(prefixLength: number): MaterializerCheckpointInfo | null {
    let selected: MaterializerCheckpointInfo | null = null
    for (const checkpoint of this.#checkpoints) {
      if (checkpoint.prefixLength <= prefixLength &&
          (selected === null || checkpoint.prefixLength > selected.prefixLength)) selected = checkpoint
    }
    return selected
  }

  #pruneCheckpoints(checkpoints: readonly MaterializerCheckpointInfo[]): MaterializerCheckpointInfo[] {
    const sorted = [...checkpoints].sort((left, right) => left.prefixLength - right.prefixLength)
    const genesis = sorted.find((checkpoint) => checkpoint.prefixLength === 0)
    const keep = sorted.slice(-Math.max(1, this.#options.retainCheckpoints - (genesis === undefined ? 0 : 1)))
    if (genesis !== undefined && !keep.some((checkpoint) => checkpoint.branchRef === genesis.branchRef)) keep.unshift(genesis)
    const retained = new Set(keep.map((checkpoint) => checkpoint.branchRef))
    for (const checkpoint of sorted) if (!retained.has(checkpoint.branchRef)) removeBranchIfPresent(this.#writer, checkpoint.branchRef)
    return keep
  }

  #assertOpen(): void { if (this.#closed) throw new Error('MATERIALIZER_CLOSED') }
}

interface ExpectedState {
  readonly artifacts: ManifestArtifacts
  readonly rootAdministrator: Uint8Array
  readonly bootstrapProgram: Uint8Array
}

/** `forkSeeding`: the genesis is a fork's, so its root may seed rows until the plan ends seeding. */
function initializeRepository(
  database: DatabaseLike,
  expected: ExpectedState,
  forkSeeding: boolean,
  options: MaterializerOptions,
  bootstrapIdentity: Uint8Array,
): PublishedRef {
  if (!isFreshRepository(database)) throw new Error('MATERIALIZER_RESERVED_HEAD_MISSING')
  database.exec('BEGIN IMMEDIATE')
  try {
    withAuthorizer(database, 'internal_bootstrap', () => {
      initializeSystemLog(database)
      insertExecutionManifest(database, { ...storedManifest(expected.artifacts), bootstrapProgram: expected.bootstrapProgram })
      initializePlatform(database, expected.rootAdministrator, forkSeeding)
    })
    if (options.bootstrapProgram !== undefined) {
      if (options.bootstrapGroupId?.length !== 32) throw new Error('MATERIALIZER_BOOTSTRAP_GROUP_REQUIRED')
      executeTransactionProgram(database, options.bootstrapProgram, { authorTimestampMs: 0n, txId: bootstrapIdentity,
        actor: expected.rootAdministrator, groupId: options.bootstrapGroupId }, options.executionManifest.limits)
    }
    verifyDatabaseState(database, expected)
    database.exec('COMMIT')
  } catch (error) {
    rollbackIfActive(database)
    throw error
  }
  const log = readSystemLog(database)
  const commitHash = database.doltCommit('chronolog genesis')
  createCheckpointRef(database, 0, 0n, commitHash, log)
  const published = createRevisionRef(database, 0n, 0, commitHash, log)
  publishRef(database, published)
  database.doltCheckout(HEAD_BRANCH)
  return published
}

function isFreshRepository(database: DatabaseLike): boolean {
  return database.prepare(`
    SELECT name FROM sqlite_schema
     WHERE type IN ('table', 'view', 'trigger', 'index')
       AND name NOT LIKE 'sqlite_%'
       AND name NOT LIKE 'dolt_%'
     LIMIT 1
  `).get() === undefined
}

function verifyDatabaseState(
  database: DatabaseLike,
  expected: ExpectedState,
): void {
  const stored = readExecutionManifest(database)
  verifyStoredManifest(stored, expected.artifacts)
  if (!bytesEqual(stored.bootstrapProgram, expected.bootstrapProgram)) {
    throw new Error('DATABASE_BOOTSTRAP_MISMATCH')
  }
  if (!bytesEqual(readRootAdministrator(database), expected.rootAdministrator)) {
    throw new Error('DATABASE_ROOT_ADMINISTRATOR_MISMATCH')
  }
}

function validateCheckpointRefs(
  database: DatabaseLike,
  published: PublishedRef,
  publishedLog: readonly TransactionLogRow[],
  artifacts: ManifestArtifacts,
): MaterializerCheckpointInfo[] {
  const valid: MaterializerCheckpointInfo[] = []
  for (const checkpoint of discoverCheckpoints(database)) {
    const expectedDigest = orderDigest(publishedLog.slice(0, checkpoint.prefixLength))
    if (checkpoint.prefixLength > publishedLog.length || checkpointOrderDigest(checkpoint.branchRef) !== expectedDigest) {
      removeBranchIfPresent(database, checkpoint.branchRef)
      continue
    }
    let matches: boolean
    try {
      database.doltCheckout(checkpoint.branchRef)
      verifyStoredManifest(readExecutionManifest(database), artifacts)
      const checkpointLog = readSystemLog(database)
      matches = checkpointLog.length === checkpoint.prefixLength && orderDigest(checkpointLog) === expectedDigest
    } catch { matches = false }
    database.doltCheckout(HEAD_BRANCH)
    if (!matches) {
      removeBranchIfPresent(database, checkpoint.branchRef)
      continue
    }
    valid.push(checkpoint)
  }
  database.doltCheckout(HEAD_BRANCH)
  if (!valid.some((checkpoint) => checkpoint.prefixLength === 0)) throw new Error('MATERIALIZER_GENESIS_CHECKPOINT_MISSING')
  verifyPublishedLog(published, publishedLog)
  return valid.sort((left, right) => left.prefixLength - right.prefixLength)
}

async function validateTransactionSet(
  transactions: readonly ReplayProposal[],
  verified: readonly TransactionLogRow[],
): Promise<void> {
  const seen = new Set<string>()
  const proposals = new Set<string>()
  for (const [index, transaction] of transactions.entries()) {
    if (transaction.txId.length === 0) throw new MaterializerInputError('MATERIALIZER_TRANSACTION_ID_INVALID')
    if (!bytesEqual(encodeTransactionCore(transaction.core), transaction.canonicalCandidate)) {
      throw new MaterializerInputError('MATERIALIZER_CANONICAL_CANDIDATE_MISMATCH')
    }
    // A logged row's digest was checked when it was applied. It is a pure function of the canonical bytes, which the check above
    // binds to this core, so a byte-identical candidate needs no recheck.
    const known = verified[index]
    const alreadyVerified = known !== undefined &&
      bytesEqual(known.txId, transaction.txId) &&
      bytesEqual(known.canonicalCandidate, transaction.canonicalCandidate) &&
      bytesEqual(known.candidateDigest, transaction.candidateDigest)
    if (!alreadyVerified) {
      if (!bytesEqual(await transactionDigest(transaction.canonicalCandidate), transaction.candidateDigest)) {
        throw new MaterializerInputError('MATERIALIZER_CANDIDATE_DIGEST_MISMATCH')
      }
    }
    const txKey = idKey(transaction.txId)
    if (seen.has(txKey)) throw new MaterializerInputError('MATERIALIZER_DUPLICATE_TRANSACTION')
    seen.add(txKey)
    const proposal = idKey(transaction.candidateDigest)
    if (proposals.has(proposal)) throw new MaterializerInputError('MATERIALIZER_DUPLICATE_PROPOSAL')
    proposals.add(proposal)
  }
}

function openDatabase(options: MaterializerOptions): ReturnType<NonNullable<MaterializerOptions['openDatabase']>> {
  if (options.openDatabase === undefined) throw new Error('MATERIALIZER_ENGINE_FACTORY_REQUIRED')
  return options.openDatabase(options)
}

function verifyFinalTransactions(final: readonly TransactionLogRow[], transactions: readonly ReplayProposal[]): void {
  if (transactions.length < final.length) throw new Error('MATERIALIZER_FINAL_PREFIX_CHANGED')
  for (let index = 0; index < final.length; index += 1) {
    if (!sameIdentity(final[index]!, transactions[index]!)) throw new Error('MATERIALIZER_FINAL_PREFIX_CHANGED')
  }
}

function verifyFinalPrefix(final: readonly TransactionLogRow[], current: readonly TransactionLogRow[]): void {
  if (current.length < final.length) throw new Error('MATERIALIZER_FINAL_PREFIX_CHANGED')
  for (let index = 0; index < final.length; index += 1) {
    const a = final[index]!, b = current[index]!
    if (!bytesEqual(a.txId, b.txId) || !bytesEqual(a.candidateDigest, b.candidateDigest) ||
        a.outcome !== b.outcome || a.rejectionCode !== b.rejectionCode || a.failingStatementIndex !== b.failingStatementIndex) {
      throw new Error('MATERIALIZER_FINAL_PREFIX_CHANGED')
    }
  }
}

function validateExistingIdentities(
  existing: readonly TransactionLogRow[],
  transactions: readonly ReplayProposal[],
): void {
  const transactionsById = new Map(transactions.map((transaction) => [idKey(transaction.txId), transaction]))
  for (const row of existing) {
    const transaction = transactionsById.get(idKey(row.txId))
    if (transaction !== undefined && !sameIdentity(row, transaction)) {
      throw new MaterializerInputError('MATERIALIZER_TRANSACTION_IDENTITY_CONFLICT')
    }
  }
}

function verifyReplayBase(
  baseLog: readonly TransactionLogRow[],
  transactions: readonly ReplayProposal[],
  prefixLength: number,
): void {
  if (baseLog.length !== prefixLength) throw new Error('MATERIALIZER_CHECKPOINT_PREFIX_LENGTH_MISMATCH')
  for (let index = 0; index < prefixLength; index += 1) {
    if (!sameIdentity(baseLog[index]!, transactions[index]!)) throw new Error('MATERIALIZER_CHECKPOINT_PREFIX_MISMATCH')
  }
}

function verifyNextLogIndex(database: DatabaseLike, expectedIndex: number): void {
  const row = database.prepare(`
    SELECT count(*) AS row_count, max(order_index) AS maximum_index
      FROM chronolog_transactions
  `).get()
  if (row === undefined || Array.isArray(row)) throw new Error('MATERIALIZER_REPLAY_LOG_STATE_UNAVAILABLE')
  const count = Number(row.row_count)
  const maximum = row.maximum_index === null ? -1 : Number(row.maximum_index)
  if (count !== expectedIndex || maximum !== expectedIndex - 1) {
    throw new Error(`MATERIALIZER_REPLAY_LOG_DRIFT:${expectedIndex}:${count}:${maximum}`)
  }
}

function verifyDesiredLog(log: readonly TransactionLogRow[], transactions: readonly ReplayProposal[]): void {
  if (log.length !== transactions.length) throw new Error('MATERIALIZER_LOG_LENGTH_MISMATCH')
  for (let index = 0; index < log.length; index += 1) {
    if (log[index]!.orderIndex !== index || !sameIdentity(log[index]!, transactions[index]!)) {
      throw new Error('MATERIALIZER_LOG_ORDER_MISMATCH')
    }
  }
}

function sameIdentity(row: TransactionLogRow, transaction: ReplayProposal): boolean {
  return bytesEqual(row.txId, transaction.txId) &&
    bytesEqual(row.candidateDigest, transaction.candidateDigest) &&
    bytesEqual(row.canonicalCandidate, transaction.canonicalCandidate) &&
    bytesEqual(row.authorId, transaction.core.authorId) &&
    row.authorTimestampMs === transaction.core.authorTimestampMs &&
    compareTransactionOrder(row.orderKey, orderKeyOf(transaction)) === 0
}

function shouldCheckpoint(
  checkpoints: readonly MaterializerCheckpointInfo[],
  prefixLength: number,
  interval: number,
): boolean {
  const nearest = checkpoints.reduce((max, checkpoint) => Math.max(max, checkpoint.prefixLength), 0)
  return prefixLength - nearest >= interval
}

function calculateOutcomeChanges(previous: readonly TransactionLogRow[], current: readonly TransactionLogRow[]): OutcomeChange[] {
  const previousById = new Map(previous.map((row) => [idKey(row.txId), row]))
  const changes: OutcomeChange[] = []
  for (const row of current) {
    const prior = previousById.get(idKey(row.txId))
    if (prior?.outcome !== row.outcome || prior.rejectionCode !== row.rejectionCode) {
      changes.push({
        txId: copyBytes(row.txId),
        previous: prior?.outcome ?? null,
        current: row.outcome,
        previousRejectionCode: prior?.rejectionCode ?? null,
        currentRejectionCode: row.rejectionCode,
      })
    }
    previousById.delete(idKey(row.txId))
  }
  for (const row of previousById.values()) changes.push({
    txId: copyBytes(row.txId), previous: row.outcome, current: null,
    previousRejectionCode: row.rejectionCode, currentRejectionCode: null,
  })
  return changes
}

function earliestDifference(previous: readonly Uint8Array[], next: readonly Uint8Array[]): number | null {
  const length = Math.min(previous.length, next.length)
  for (let index = 0; index < length; index += 1) if (!bytesEqual(previous[index]!, next[index]!)) return index
  return previous.length === next.length ? null : length
}

function logRow(
  transaction: ReplayProposal,
  orderIndex: number,
  rejection: { readonly code: string; readonly statementIndex: number | null } | null,
): Omit<TransactionLogRow, 'orderKey'> {
  return {
    txId: transaction.txId,
    orderIndex,
    operationId: transaction.core.operationId,
    authorId: transaction.core.authorId,
    authorTimestampMs: transaction.core.authorTimestampMs,
    candidateDigest: transaction.candidateDigest,
    canonicalCandidate: transaction.canonicalCandidate,
    outcome: rejection === null ? 'accepted' : 'rejected',
    rejectionCode: rejection?.code ?? null,
    failingStatementIndex: rejection?.statementIndex ?? null,
  }
}

function storedManifest(artifacts: ManifestArtifacts): Omit<StoredExecutionManifest, 'bootstrapProgram'> {
  return {
    manifestDigest: artifacts.executionManifestDigest,
    canonicalManifest: artifacts.canonicalExecutionManifest,
  }
}

function verifyStoredManifest(stored: StoredExecutionManifest, artifacts: ManifestArtifacts): void {
  if (!bytesEqual(stored.manifestDigest, artifacts.executionManifestDigest) ||
      !bytesEqual(stored.canonicalManifest, artifacts.canonicalExecutionManifest)) {
    throw new Error('DATABASE_MANIFEST_MISMATCH')
  }
}

function rollbackIfActive(database: DatabaseLike): void { if (database.inTransaction) database.exec('ROLLBACK') }
function orderKeyOf(transaction: ReplayProposal): TransactionOrderKey {
  return { authorTimestampMs: transaction.core.authorTimestampMs, authorId: copyBytes(transaction.core.authorId), txId: copyBytes(transaction.txId) }
}
function cloneTransaction(transaction: ReplayProposal): ReplayProposal { return structuredClone(transaction) }
function cloneLogRow(row: TransactionLogRow): TransactionLogRow { return structuredClone(row) }
function idKey(bytes: Uint8Array): string { return bytesToBase64Url(bytes) }
function copyBytes(value: Uint8Array): Uint8Array { return Uint8Array.from(value) }
function validatePositiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new MaterializerInputError(`MATERIALIZER_INVALID_${name.toUpperCase()}`)
  return value
}
function nonThrowingDiagnostic(error: unknown, fallback: string): string { return error instanceof Error && error.message.length > 0 ? error.message : fallback }
function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error) }
function resetActiveWorkingSet(database: DatabaseLike): void {
  const active = database.doltActiveBranch()
  const branch = database.doltBranches().find((entry) => entry.name === active)
  if (branch === undefined) throw new Error('MATERIALIZER_ACTIVE_BRANCH_MISSING')
  database.doltResetHard(branch.hash)
}

function bootstrapBytes(options: MaterializerOptions): Uint8Array {
  if (options.bootstrapProgram === undefined) return new Uint8Array()
  if (options.bootstrapGroupId?.length !== 32) throw new Error('MATERIALIZER_BOOTSTRAP_GROUP_REQUIRED')
  return encodeCanonicalCbor([options.bootstrapGroupId, encodeChangeProgram(options.bootstrapProgram)])
}

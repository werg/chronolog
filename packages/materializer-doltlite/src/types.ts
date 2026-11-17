import type { ChangeProgram, ExecutionManifest, TransactionOrderKey } from '@chronolog/protocol'
export type { ReplayProposal } from '@chronolog/materializer'

export type TransactionOutcomeKind = 'accepted' | 'rejected'

export interface TransactionOutcome {
  readonly txId: Uint8Array
  readonly orderKey: TransactionOrderKey
  readonly orderIndex: number
  readonly outcome: TransactionOutcomeKind
  /** `assert:<code>`, `policy:<table>:<command>`, `platform:<reason>`, `constraint`, … ; null when accepted. */
  readonly rejectionCode: string | null
  /** Index of the program step that failed; null when accepted or for whole-transaction checks. */
  readonly failingStatementIndex: number | null
}

export interface TransactionLogRow extends TransactionOutcome {
  readonly operationId: string
  readonly authorId: Uint8Array
  readonly authorTimestampMs: bigint
  readonly candidateDigest: Uint8Array
  readonly canonicalCandidate: Uint8Array
}

export interface OutcomeChange {
  readonly txId: Uint8Array
  readonly previous: TransactionOutcomeKind | null
  readonly current: TransactionOutcomeKind | null
  readonly previousRejectionCode: string | null
  readonly currentRejectionCode: string | null
}

export interface MaterializedRevision {
  readonly revision: bigint
  readonly previousRevision: bigint
  readonly orderLength: number
  readonly replayFromIndex: number
  readonly replayedTransactions: number
  readonly checkpointPrefix: number
  readonly contentHash: string
  readonly manifestDigest: Uint8Array
  readonly earliestChangedOrderIndex: number
  readonly outcomeChanges: readonly OutcomeChange[]
}

export interface MaterializerCheckpointInfo {
  readonly prefixLength: number
  readonly branchRef: string
  readonly doltCommitHash: string
  readonly contentHash: string
  readonly createdAtRevision: bigint
}

export interface MaterializerBackendInfo {
  readonly engine: 'doltlite'
  readonly version: string
  readonly sqliteVersion: string
  readonly vecVersion: string | null
  readonly nativeManifest: EngineBuildManifest
  readonly engineDigest: Uint8Array
  readonly securityConfigured: boolean
}

export interface EngineBuildManifest {
  readonly doltliteVersion: string
  readonly doltliteSourceSha256: string
  readonly sqliteVecVersion: string
  readonly sqliteVecSourceSha256: string
  readonly chronologPatchProfile: string
  readonly fts5: boolean
  readonly json1: boolean
  readonly rtree: boolean
  readonly dynamicExtensions: boolean
}

export interface SqlRuntimeLimits {
  /** Maximum SQL source size in UTF-8 bytes. */
  readonly maxSqlBytes: number
  /** SQLite virtual-machine operations allowed per statement. */
  readonly maxVmSteps: number
  /** Number of VM operations between progress callbacks. */
  readonly progressGranularity: number
  /** Maximum bytes of one string or BLOB value (SQLITE_LIMIT_LENGTH). */
  readonly maxValueBytes: number
  /** Maximum rows returned by one local query. */
  readonly maxResultRows: number
}

export interface NativeSecurityConfiguration {
  /** Each returned boolean is a native success flag; configureSecurity throws on mismatch. */
  readonly defensive: boolean
  readonly trustedSchema: boolean
  readonly loadExtension: boolean
  readonly dqsDml: boolean
  readonly dqsDdl: boolean
  readonly qpsg: boolean
  readonly ftsTokenizer: boolean
  readonly writableSchema: boolean
  readonly extendedResultCodes: boolean
  readonly attachCreate?: boolean
  readonly attachWrite?: boolean
  readonly reverseScanOrder?: boolean
  readonly fpDigits?: boolean
}

export type SecurityConfiguration = NativeSecurityConfiguration

export interface DoltBranchInfoLike {
  readonly name: string
  readonly hash: string
}

export type LocalSqlValue =
  | { readonly kind: 'null' }
  | { readonly kind: 'integer'; readonly value: string }
  | { readonly kind: 'real'; readonly value: number }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'blob'; readonly value: Uint8Array }

export interface LocalSqlQueryResult {
  readonly revision: bigint
  readonly orderLength: number
  readonly view?: 'local' | 'final'
  readonly finalOrderLength?: number
  readonly columns: readonly { readonly name: string; readonly declaredType?: string }[]
  readonly rows: readonly (readonly LocalSqlValue[])[]
}

export interface LocalSqlOptions {
  readonly atRevision?: bigint
  readonly view?: 'local' | 'final'
}

export interface MaterializerSqlBackend {
  readonly revision: bigint
  readonly orderLength: number
  readonly executionManifestDigest: Uint8Array
  localQuery(sql: string, parameters?: readonly LocalSqlValue[], options?: LocalSqlOptions): LocalSqlQueryResult
}

export interface StatementLike {
  /** Release the prepared engine handle when the owning scope exits. */
  finalize?(): void
  run(...parameters: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint }
  get(...parameters: unknown[]): Record<string, unknown> | unknown[] | undefined
  all(...parameters: unknown[]): Array<Record<string, unknown> | unknown[]>
  columns(): Array<{ name: string | null }>
  setReturnArrays?(enabled: boolean): void
  setReadBigInts?(enabled: boolean): void
  readonly sourceSQL: string
  /** UTF-8 byte offset immediately after the prepared statement. */
  readonly tailOffset: number
  /** Number of SQL parameters (largest parameter position). */
  readonly parameterCount: number
  /** SQLite's position of a named or numbered parameter, or 0. */
  parameterIndex(name: string): number
}

export interface DatabaseLike {
  /** Engine tokenizer inspection, identical in native and WASM profiles. */
  triggerUsesIgnore(sql: string): boolean
  readonly inTransaction: boolean
  exec(sql: string): void
  prepare(sql: string): StatementLike
  close(): void
  configureSecurity(): NativeSecurityConfiguration
  setAuthorizer(
    callback:
      | ((
          actionCode: number,
          arg1: string | null,
          arg2: string | null,
          databaseName: string | null,
          triggerOrView: string | null,
        ) => number)
      | null,
  ): void
  setProgressHandler(steps: number, callback: (() => boolean) | null): void
  /** Returns the previous value, matching sqlite3_limit(). */
  setLimit(category: number, value: number): number
  interrupt(): void
  /** Pin 'now', the PRNG seed, UTC localtime, chronolog_actor() and chronolog_actor_id(); resets last_insert_rowid. */
  setDeterministicContext(unixMs: bigint, seed: number, actor?: Uint8Array | null, actorId?: bigint | null, transactionId?: Uint8Array | null): void
  clearDeterministicContext(): void
  doltCommit(message: string): string
  doltBranch(name: string, from?: string): void
  doltCheckout(branch: string): void
  doltResetHard(ref: string): void
  doltForceBranch(name: string, ref: string): void
  doltDeleteBranch(name: string): void
  doltHashOf(ref?: string): string
  doltVersion(): string
  doltBranches(): DoltBranchInfoLike[]
  doltActiveBranch(): string
}

/** Explicit execution capability; adapters supply an engine without owning an application. */
export interface SqlEngine {
  readonly executionManifest: ExecutionManifest
  openDatabase(options: { readonly path: string }): {
    readonly database: DatabaseLike
    readonly backend: MaterializerBackendInfo
    readonly security: SecurityConfiguration
  }
}

export interface MaterializerOptions {
  /** Verified schema-author program, executed once before the genesis checkpoint. */
  readonly bootstrapProgram?: ChangeProgram
  readonly bootstrapGroupId?: Uint8Array
  /** Native and browser supply the same explicit capability to the sole reducer. */
  readonly engine: SqlEngine
  readonly path: string
  /**
   * The genesis schemaAdminPublicKey: the first SQL admin of the
   * `group` collective, and the only key that may seed rows into a fork.
   */
  readonly rootAdministrator: Uint8Array
  /**
   * The group is a fork (its genesis names a source group): the new database
   * starts with fork seeding open, so the root may `SeedRows` until another
   * author's first accepted transaction. Every other group never allows
   * seeding. Used only when the database is created.
   */
  readonly forkSeeding?: boolean
  readonly checkpointEvery?: number
  readonly retainCheckpoints?: number
  /**
   * Test and operator-diagnostic seam for reproducible process termination at
   * durable publication boundaries. Production callers normally omit it.
   */
  readonly publicationFaultInjector?: (point: MaterializerPublicationFaultPoint) => void
}

export type MaterializerPublicationFaultPoint =
  | 'after_candidate_commit'
  | 'after_revision_ref_created'
  | 'before_head_publish'
  | 'after_head_publish'
  | 'after_reader_swap'

export interface StoredExecutionManifest {
  readonly bootstrapProgram: Uint8Array
  readonly manifestDigest: Uint8Array
  readonly canonicalManifest: Uint8Array
}

export type RevisionSubscriber = (revision: MaterializedRevision) => void

import type {
  JsonValue,
  OperationAssumption,
  OperationAssumptionsConfig,
  TopicUpdate,
} from '@chronolog/protocol'
import type { ApplicationOperation } from './operation.js'
import type { ApplicationSession } from './session.js'

export interface GuardedSqlPrecondition {
  readonly kind?: 'based_on_row' | 'row_matches'
  readonly table?: string
  readonly where?: Readonly<Record<string, JsonValue>>
  readonly lastOpId?: string | null
  readonly expect?: JsonValue
  readonly sql?: string
  readonly params?: readonly JsonValue[]
  readonly code?: string
}

export interface GuardedTxOptions {
  readonly defaultSqlTopic?: string
  readonly onFailed?: 'reject' | 'record_conflict'
}

export interface GuardedTx {
  /**
   * Read a single SQL row and automatically capture an optimistic concurrency precondition:
   * - If the table has a `_last_op_id` column (via `stampRowOp`), records `{ kind: 'based_on_row', table, where, lastOpId }`.
   * - Otherwise records `{ kind: 'row_matches', table, where, expect }` for the read columns (or `{ kind: 'based_on_row', lastOpId: null }` when absent).
   */
  readRow(
    table: string,
    where: Readonly<Record<string, JsonValue>>,
    options?: { readonly topic?: string; readonly columns?: readonly string[]; readonly code?: string },
  ): Promise<Record<string, JsonValue> | null>

  /**
   * Execute a read-only SQL query and capture an exact precondition on its result (`rows`, `count`, or `exists`).
   */
  readSql(
    sql: string,
    params?: readonly JsonValue[],
    options?: { readonly topic?: string; readonly mode?: 'rows' | 'count' | 'exists'; readonly code?: string },
  ): Promise<{ readonly columns: readonly string[]; readonly rows: readonly (readonly JsonValue[])[] }>

  /**
   * Execute `session.query(topic, query)` and capture a kernel-level `query_match` assumption.
   */
  readQuery(topic: string, query?: JsonValue): Promise<JsonValue>

  /**
   * Capture a kernel-level `topic_revision` assumption asserting `topic` has not been modified since now.
   */
  requireTopicUnchanged(topic: string): this

  /**
   * Capture a kernel-level `author_last_op` assumption asserting this author's causal history chain
   * matches their latest accepted/local op (100% offline-friendly; chains across sequential local writes).
   */
  requireOwnHistory(author?: string): this

  /**
   * Capture a kernel-level `op_accepted` / `op_rejected` / `op_present` assumption.
   */
  requireOp(opId: string, kind?: 'op_accepted' | 'op_rejected' | 'op_present'): this

  /** Add an explicit SQL precondition (evaluated before DML on `topic`). */
  addSqlPrecondition(precondition: GuardedSqlPrecondition, topic?: string): this

  /** Add an explicit SQL postcondition (evaluated after DML, before `db.commit()`). */
  addSqlPostcondition(postcondition: GuardedSqlPrecondition, topic?: string): this

  /** Inspect captured kernel-level assumptions. */
  assumptions(options?: { readonly onFailed?: 'reject' | 'record_conflict' }): OperationAssumptionsConfig | undefined

  /** Inspect captured SQL preconditions for `topic`. */
  sqlPreconditions(topic?: string): readonly GuardedSqlPrecondition[]

  /** Inspect captured SQL postconditions for `topic`. */
  sqlPostconditions(topic?: string): readonly GuardedSqlPrecondition[]

  /**
   * Submit a guarded operation combining all captured kernel assumptions and SQL pre/post conditions.
   * Any `updates` targeting a SQL topic automatically receive the captured `preconditions` and `postconditions`.
   */
  submit(input: {
    readonly updates: readonly TopicUpdate[]
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
    readonly visibility?: 'public' | 'encrypted'
    readonly onFailed?: 'reject' | 'record_conflict'
    readonly awaitMaterialized?: boolean
  }): Promise<ApplicationOperation>
}

function quoteIdent(name: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) throw new Error(`INVALID_SQL_IDENT:${name}`)
  return `"${name}"`
}

function buildWhere(where: Readonly<Record<string, JsonValue>>): { readonly clause: string; readonly params: JsonValue[] } {
  const keys = Object.keys(where).sort()
  if (keys.length === 0) throw new Error('GUARDED_TX_WHERE_EMPTY')
  const parts: string[] = []
  const params: JsonValue[] = []
  for (const key of keys) {
    const val = where[key]
    if (val === null) {
      parts.push(`${quoteIdent(key)} IS NULL`)
    } else {
      parts.push(`${quoteIdent(key)} = ?`)
      params.push(val!)
    }
  }
  return { clause: parts.join(' AND '), params }
}

/**
 * Create an explicit, scoped Optimistic Concurrency Control (OCC) transaction builder over an
 * `ApplicationSession`. Unlike implicit global query tracking, only reads performed through this
 * `GuardedTx` instance are added to the operation's signed read-set (`OperationAssumptions` +
 * `chronolog/sql` preconditions/postconditions), avoiding phantom conflicts with UI views.
 */
export function createGuardedTx(session: ApplicationSession, options: GuardedTxOptions = {}): GuardedTx {
  const defaultSqlTopic = options.defaultSqlTopic ?? 'sql'
  const defaultOnFailed = options.onFailed ?? 'reject'
  const kernelChecks: OperationAssumption[] = []
  const sqlPreByTopic = new Map<string, GuardedSqlPrecondition[]>()
  const sqlPostByTopic = new Map<string, GuardedSqlPrecondition[]>()

  const pushSqlPre = (topic: string, pre: GuardedSqlPrecondition): void => {
    let list = sqlPreByTopic.get(topic)
    if (list === undefined) { list = []; sqlPreByTopic.set(topic, list) }
    list.push(pre)
  }
  const pushSqlPost = (topic: string, post: GuardedSqlPrecondition): void => {
    let list = sqlPostByTopic.get(topic)
    if (list === undefined) { list = []; sqlPostByTopic.set(topic, list) }
    list.push(post)
  }

  const tx: GuardedTx = {
    async readRow(table, where, opts = {}) {
      const topic = opts.topic ?? defaultSqlTopic
      const { clause, params } = buildWhere(where)
      const colsSql = opts.columns !== undefined && opts.columns.length > 0
        ? opts.columns.map(quoteIdent).join(', ')
        : '*'
      const raw = await session.query(topic, { sql: `SELECT ${colsSql} FROM ${quoteIdent(table)} WHERE ${clause}`, params })
      const val = raw.value as { readonly columns?: readonly string[]; readonly rows?: readonly (readonly JsonValue[])[] } | null
      const columns: readonly string[] = Array.isArray(val?.columns) ? (val.columns as readonly string[]) : []
      const rows: readonly (readonly JsonValue[])[] = Array.isArray(val?.rows) ? (val.rows as readonly (readonly JsonValue[])[]) : []
      if (rows.length === 0) {
        pushSqlPre(topic, {
          sql: `SELECT COUNT(*) FROM ${quoteIdent(table)} WHERE ${clause}`,
          params,
          expect: { firstValue: 0 },
          ...(opts.code === undefined ? { code: 'sql:row_already_exists' } : { code: opts.code }),
        })
        return null
      }
      const firstRow: readonly JsonValue[] = rows[0]!
      const record: Record<string, JsonValue> = {}
      for (let i = 0; i < columns.length; i++) {
        const colName = columns[i]
        if (colName !== undefined) record[colName] = firstRow[i] ?? null
      }
      if (Object.hasOwn(record, '_last_op_id') && typeof record._last_op_id === 'string') {
        pushSqlPre(topic, {
          kind: 'based_on_row',
          table,
          where: { ...where },
          lastOpId: record._last_op_id,
          ...(opts.code === undefined ? {} : { code: opts.code }),
        })
      } else {
        pushSqlPre(topic, {
          kind: 'row_matches',
          table,
          where: { ...where },
          expect: record,
          ...(opts.code === undefined ? {} : { code: opts.code }),
        })
      }
      return record
    },

    async readSql(sql, params = [], opts = {}) {
      const topic = opts.topic ?? defaultSqlTopic
      const mode = opts.mode ?? 'rows'
      const raw = await session.query(topic, { sql, params: [...params] })
      const val = raw.value as { readonly columns?: readonly string[]; readonly rows?: readonly (readonly JsonValue[])[] } | null
      const columns = Array.isArray(val?.columns) ? val.columns : []
      const rows = Array.isArray(val?.rows) ? val.rows : []
      if (mode === 'exists') {
        pushSqlPre(topic, { sql, params: [...params], expect: { exists: rows.length > 0 }, ...(opts.code === undefined ? {} : { code: opts.code }) })
      } else if (mode === 'count') {
        pushSqlPre(topic, { sql, params: [...params], expect: { rowCount: rows.length }, ...(opts.code === undefined ? {} : { code: opts.code }) })
      } else {
        pushSqlPre(topic, { sql, params: [...params], expect: { equals: rows as unknown as JsonValue }, ...(opts.code === undefined ? {} : { code: opts.code }) })
      }
      return { columns, rows }
    },

    async readQuery(topic, query = null) {
      const res = await session.query(topic, query)
      const val = (res.value ?? null) as JsonValue
      kernelChecks.push({ kind: 'query_match', topic, query, expect: val })
      return val
    },

    requireTopicUnchanged(topic) {
      const lastOpId = session.topicLastOpId(topic)
      kernelChecks.push({ kind: 'topic_revision', topic, lastOpId })
      return tx
    },

    requireOwnHistory(author) {
      const target = author ?? session.identity.publicKey
      const lastOpId = session.authorLastOpId(target)
      kernelChecks.push({
        kind: 'author_last_op',
        ...(author === undefined ? {} : { author: target }),
        lastOpId,
      })
      return tx
    },

    requireOp(opId, kind = 'op_accepted') {
      kernelChecks.push({ kind, opId })
      return tx
    },

    addSqlPrecondition(pre, topic = defaultSqlTopic) {
      pushSqlPre(topic, pre)
      return tx
    },

    addSqlPostcondition(post, topic = defaultSqlTopic) {
      pushSqlPost(topic, post)
      return tx
    },

    assumptions(opts = {}) {
      if (kernelChecks.length === 0) return undefined
      const onFailed = opts.onFailed ?? defaultOnFailed
      return {
        checks: [...kernelChecks],
        ...(onFailed === 'reject' ? {} : { onFailed }),
      }
    },

    sqlPreconditions(topic = defaultSqlTopic) {
      return [...(sqlPreByTopic.get(topic) ?? [])]
    },

    sqlPostconditions(topic = defaultSqlTopic) {
      return [...(sqlPostByTopic.get(topic) ?? [])]
    },

    async submit(input) {
      const onFailed = input.onFailed ?? defaultOnFailed
      const mergedUpdates: TopicUpdate[] = input.updates.map(update => {
        const pre = sqlPreByTopic.get(update.topic)
        const post = sqlPostByTopic.get(update.topic)
        if ((pre === undefined || pre.length === 0) && (post === undefined || post.length === 0)) {
          return update
        }
        if (update.input === null || typeof update.input !== 'object' || Array.isArray(update.input)) {
          return update
        }
        const obj = update.input as Readonly<Record<string, JsonValue>>
        const existingPre: readonly JsonValue[] = Array.isArray(obj.preconditions) ? (obj.preconditions as readonly JsonValue[]) : []
        const existingPost: readonly JsonValue[] = Array.isArray(obj.postconditions) ? (obj.postconditions as readonly JsonValue[]) : []
        const nextPre: JsonValue[] = [...(pre ?? []) as unknown as JsonValue[], ...existingPre]
        const nextPost: JsonValue[] = [...existingPost, ...(post ?? []) as unknown as JsonValue[]]
        return {
          topic: update.topic,
          input: {
            ...obj,
            ...(nextPre.length > 0 ? { preconditions: nextPre } : {}),
            ...(nextPost.length > 0 ? { postconditions: nextPost } : {}),
            ...(onFailed === 'record_conflict' && obj.onPreconditionFailed === undefined ? { onPreconditionFailed: 'record_conflict' } : {}),
          },
        }
      })
      const assumptions = tx.assumptions({ onFailed })
      return session.submit({
        updates: mergedUpdates,
        awaitMaterialized: input.awaitMaterialized ?? true,
        ...(input.operationId === undefined ? {} : { operationId: input.operationId }),
        ...(input.authorTimestampMs === undefined ? {} : { authorTimestampMs: input.authorTimestampMs }),
        ...(input.visibility === undefined ? {} : { visibility: input.visibility }),
        ...(assumptions === undefined ? {} : { assumptions }),
      })
    },
  }
  return tx
}

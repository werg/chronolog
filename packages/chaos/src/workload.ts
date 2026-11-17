import type { PlatformOp } from '@chronolog/protocol'

import type { ChaosCluster } from './cluster.js'
import { errorText, type RunArtifacts } from './artifacts.js'
import type { SeededRandom } from './rng.js'
import { balanceAssertion, balanceQuery, balanceUpdate, schemaVersionAssertion } from './schema.js'
import {
  WORKLOAD_OPERATION_KINDS,
  type ChaosScenario,
  type WorkloadExpectation,
  type WorkloadOperationKind,
  type WorkloadSpec,
} from './types.js'

export const DEFAULT_OPERATION_WEIGHTS: Readonly<Record<WorkloadOperationKind, number>> = Object.freeze({
  migration_chain: 5,
  migration_rollback: 4,
  legacy_client_write: 8,
  current_client_write: 8,
  balance_update: 25,
  transfer: 15,
  ordered_touch: 8,
  empty_returning: 4,
  document_insert: 7,
  ddl_sequence: 3,
  precondition_rejection: 7,
  constraint_rejection: 6,
  owner_probe: 6,
})

/** Operations that run DDL; only the root (schema) administrator may submit them. */
const SCHEMA_OPERATIONS: ReadonlySet<WorkloadOperationKind> = new Set(['migration_chain', 'migration_rollback', 'ddl_sequence'])

export interface WorkloadResult {
  readonly attempted: number
  readonly published: number
  readonly failed: number
  readonly transactionIds: readonly string[]
  readonly expectations: readonly WorkloadExpectation[]
  readonly byKind: Readonly<Partial<Record<WorkloadOperationKind, number>>>
}

export async function runWorkload(options: {
  readonly cluster: ChaosCluster
  readonly scenario: ChaosScenario
  readonly artifacts: RunArtifacts
  readonly random: SeededRandom
  readonly startedAt: number
  readonly signal: AbortSignal
}): Promise<WorkloadResult> {
  let attempted = 0
  let published = 0
  let failed = 0
  const transactionIds: string[] = []
  const expectations: WorkloadExpectation[] = []
  const byKind: Partial<Record<WorkloadOperationKind, number>> = {}
  const queries = Array.from({ length: options.scenario.workload.accounts }, (_value, account) => balanceQuery(account))
  const workers = Array.from({ length: options.scenario.workload.workers }, (_value, worker) => (async () => {
    const random = options.random.fork(`worker-${worker}`)
    let operation = 0
    while (!options.signal.aborted && (
      performance.now() - options.startedAt < options.scenario.durationMs ||
      hasPendingCoverage(options.scenario.workload, worker, operation)
    )) {
      const picked = random.pick(options.cluster.nodeNames())
      const account = random.integer(0, options.scenario.workload.accounts - 1)
      const delta = random.integer(options.scenario.workload.minimumDelta, options.scenario.workload.maximumDelta)
      const operationIndex = operation++
      const operationId = `worker-${worker}-operation-${operationIndex}`
      const kind = chooseScheduledWorkloadOperation(random, options.scenario.workload, worker, operationIndex)
      const node = SCHEMA_OPERATIONS.has(kind) ? options.cluster.adminNodeName() : picked
      byKind[kind] = (byKind[kind] ?? 0) + 1
      attempted += 1
      await options.artifacts.record({
        type: 'operation', phase: 'start', name: operationId, node,
        details: { kind, account, delta },
      })
      try {
        const expectation = expectationFor(kind, operationId)
        const client = options.cluster.client(node)
        const statements = await workloadStatements(kind, {
          operationId, worker, operation: operationIndex, account, delta, random, expectation,
          workload: options.scenario.workload,
          readBalance: async (target) => {
            const query = queries[target]!
            const value = (await client.query(query.sql, [...query.parameters])).result.rows[0]?.[0]
            if (typeof value !== 'bigint') throw new Error('CHAOS_BALANCE_RESULT_INVALID')
            return value
          },
        })
        const handle = await client.transaction(statements, {
          operationId: `${options.random.seed}:${operationId}`,
          signal: AbortSignal.timeout(15_000),
        })
        published += 1
        transactionIds.push(handle.transactionId)
        expectations.push({ transactionId: handle.transactionId, operationId, operation: kind, ...expectation })
        await options.artifacts.record({
          type: 'operation', phase: 'success', name: operationId, node,
          transactionId: handle.transactionId,
          details: {
            kind, account, delta, allowedOutcomes: expectation.allowedOutcomes,
            ...(expectation.migrationPrefix === undefined ? {} : { migrationPrefix: expectation.migrationPrefix }),
          },
        })
        handle.dispose()
      } catch (error) {
        failed += 1
        await options.artifacts.record({
          type: 'operation', phase: 'failure', name: operationId, node,
          details: { kind, account, delta }, error: errorText(error),
        })
      }
      const interval = options.scenario.workload.intervalMs
      if (interval > 0) await delay(random.integer(Math.floor(interval / 2), Math.max(1, Math.ceil(interval * 1.5))), options.signal)
    }
  })())
  await Promise.all(workers)
  return { attempted, published, failed, transactionIds, expectations, byKind }
}

type WorkloadStatement = { readonly sql: string; readonly params?: readonly unknown[] } | PlatformOp

/**
 * Statements for one workload operation. Assumptions about the state the
 * client read are ordinary `chronolog_assert` statements re-checked at the
 * transaction's replay position.
 */
async function workloadStatements(kind: WorkloadOperationKind, context: {
  readonly operationId: string
  readonly worker: number
  readonly operation: number
  readonly account: number
  readonly delta: number
  readonly random: SeededRandom
  readonly expectation: Omit<WorkloadExpectation, 'transactionId' | 'operationId' | 'operation'>
  readonly workload: WorkloadSpec
  readonly readBalance: (account: number) => Promise<bigint>
}): Promise<readonly WorkloadStatement[]> {
  const { operationId, worker, account, delta, random } = context
  switch (kind) {
    case 'migration_chain':
      return [schemaVersionAssertion('profiles', 2), ...migrationChainStatements(context.expectation.migrationPrefix!)]
    case 'migration_rollback':
      return [schemaVersionAssertion('profiles', 2), ...migrationRollbackStatements(context.expectation.migrationPrefix!)]
    case 'legacy_client_write':
      return [schemaVersionAssertion('profiles', 1), {
        sql: 'INSERT INTO chaos_profiles (profile_id, display_name) VALUES (?, ?) RETURNING profile_id, display_name, schema_version',
        params: [operationId, `legacy-${worker}`],
      }]
    case 'current_client_write':
      return [schemaVersionAssertion('profiles', 2), {
        sql: 'INSERT INTO chaos_profiles (profile_id, display_name, email, schema_version, metadata) VALUES (?, ?, ?, 2, ?) RETURNING profile_id, display_name, email, schema_version, metadata',
        params: [operationId, `current-${worker}`, `${operationId}@example.test`, random.bytes(random.integer(0, 24))],
      }]
    case 'balance_update': {
      const balance = await context.readBalance(account)
      return [
        balanceAssertion(account, balance),
        balanceUpdate(account, balance + BigInt(delta)),
        ledgerInsert(operationId, 0, account, delta, random),
      ]
    }
    case 'transfer': {
      const other = distinctAccount(random, account, context.workload.accounts)
      const amount = random.integer(1, context.workload.maximumTransfer ?? Math.max(1, Math.abs(context.workload.maximumDelta)))
      const [sourceBalance, targetBalance] = await Promise.all([context.readBalance(account), context.readBalance(other)])
      return [
        balanceAssertion(account, sourceBalance),
        balanceAssertion(other, targetBalance),
        balanceUpdate(account, sourceBalance - BigInt(amount)),
        balanceUpdate(other, targetBalance + BigInt(amount)),
        ledgerInsert(operationId, 0, account, -amount, random),
        ledgerInsert(operationId, 1, other, amount, random),
      ]
    }
    case 'ordered_touch': {
      const limit = random.integer(1, Math.min(3, context.workload.accounts))
      const offset = random.integer(0, Math.max(0, context.workload.accounts - limit))
      return [{
        sql: 'UPDATE accounts SET touched = touched + 1 WHERE id IN (SELECT id FROM accounts ORDER BY balance DESC LIMIT ? OFFSET ?) RETURNING id, touched',
        params: [BigInt(limit), BigInt(offset)],
      }]
    }
    case 'empty_returning':
      return [{ sql: 'UPDATE accounts SET touched = touched WHERE id = -1 RETURNING id, touched' }]
    case 'document_insert':
      return [{
        sql: 'INSERT INTO chaos_documents (document_id, account_id, title, payload, optional_text) VALUES (?, ?, ?, ?, ?) RETURNING document_id, account_id, title, payload, optional_text',
        params: [operationId, BigInt(account), `title-${delta}`, random.bytes(random.integer(0, 32)), random.integer(0, 1) === 0 ? null : `optional-${worker}`],
      }]
    case 'ddl_sequence': {
      const table = `chaos_ddl_${worker}_${context.operation}`
      return [
        { sql: `CREATE TABLE ${table} (id INTEGER PRIMARY KEY, marker TEXT) STRICT` },
        { sql: `ALTER TABLE ${table} ADD COLUMN payload BLOB` },
        { sql: `SELECT name, type FROM pragma_table_info('${table}') ORDER BY cid` },
      ]
    }
    case 'precondition_rejection':
      return [
        { sql: "SELECT chronolog_assert(0, 'intentional_false')" },
        { sql: 'UPDATE accounts SET touched = touched + 1000000 WHERE id = ?', params: [BigInt(account)] },
      ]
    case 'constraint_rejection':
      return [
        { sql: 'UPDATE accounts SET touched = touched + 1000000 WHERE id = ? RETURNING touched', params: [BigInt(account)] },
        { sql: "INSERT INTO chaos_ledger (operation_id, leg, account_id, delta, note, payload) VALUES ('__reserved_constraint_key__', 0, 0, 0, NULL, X'')" },
      ]
    case 'owner_probe':
      // Touches every profile, including other writers' rows. It is accepted
      // only while all of them belong to the signer; otherwise the owner
      // check aborts the whole transaction instead of skipping rows.
      return [{ sql: 'UPDATE chaos_profiles SET display_name = display_name RETURNING profile_id' }]
  }
}

export function chooseWorkloadOperation(random: SeededRandom, workload: WorkloadSpec): WorkloadOperationKind {
  const weights = operationWeights(workload)
  const eligible = WORKLOAD_OPERATION_KINDS.map((kind) => ({
    kind: kind === 'transfer' && workload.accounts < 2 ? 'balance_update' as const : kind,
    weight: weights[kind],
  })).filter((entry) => entry.weight > 0)
  const total = eligible.reduce((sum, entry) => sum + entry.weight, 0)
  if (total <= 0) throw new Error('CHAOS_WORKLOAD_WEIGHTS_EMPTY')
  let selected = random.integer(1, total)
  for (const entry of eligible) {
    selected -= entry.weight
    if (selected <= 0) return entry.kind
  }
  return eligible.at(-1)!.kind
}

/** Ensures short smoke runs attempt every enabled operation before becoming purely random. */
export function chooseScheduledWorkloadOperation(
  random: SeededRandom,
  workload: WorkloadSpec,
  worker: number,
  operation: number,
): WorkloadOperationKind {
  const enabled = enabledWorkloadOperations(workload)
  const coverageIndex = operation * workload.workers + worker
  return enabled[coverageIndex] ?? chooseWorkloadOperation(random, workload)
}

export function enabledWorkloadOperations(workload: WorkloadSpec): readonly WorkloadOperationKind[] {
  return WORKLOAD_OPERATION_KINDS.filter((kind) => operationWeights(workload)[kind] > 0)
    .map((kind) => kind === 'transfer' && workload.accounts < 2 ? 'balance_update' as const : kind)
    .filter((kind, index, values) => values.indexOf(kind) === index)
}

function hasPendingCoverage(workload: WorkloadSpec, worker: number, operation: number): boolean {
  return operation * workload.workers + worker < enabledWorkloadOperations(workload).length
}

function operationWeights(workload: WorkloadSpec): Readonly<Record<WorkloadOperationKind, number>> {
  const configured = workload.operationWeights
  return configured === undefined
    ? DEFAULT_OPERATION_WEIGHTS
    : Object.fromEntries(WORKLOAD_OPERATION_KINDS.map((kind) => [kind, configured[kind] ?? 0])) as Record<WorkloadOperationKind, number>
}

function ledgerInsert(
  operationId: string,
  leg: number,
  account: number,
  delta: number,
  random: SeededRandom,
) {
  return {
    sql: 'INSERT INTO chaos_ledger (operation_id, leg, account_id, delta, note, payload) VALUES (?, ?, ?, ?, ?, ?) RETURNING operation_id, leg, account_id, delta, note, payload',
    params: [operationId, BigInt(leg), BigInt(account), BigInt(delta), delta % 2 === 0 ? null : `delta-${delta}`, random.bytes(random.integer(0, 16))],
  }
}

function distinctAccount(random: SeededRandom, account: number, accounts: number): number {
  if (accounts < 2) return account
  const selected = random.integer(0, accounts - 2)
  return selected >= account ? selected + 1 : selected
}

function expectationFor(kind: WorkloadOperationKind, operationId: string): Omit<WorkloadExpectation, 'transactionId' | 'operationId' | 'operation'> {
  switch (kind) {
    case 'balance_update': case 'transfer':
      return { allowedOutcomes: ['accepted', 'rejected'], rejectionCode: 'assert:balance_changed' }
    case 'precondition_rejection':
      return { allowedOutcomes: ['rejected'], rejectionCode: 'assert:intentional_false', failingStatementIndex: 0 }
    case 'constraint_rejection':
      return { allowedOutcomes: ['rejected'], rejectionCode: 'constraint', failingStatementIndex: 1 }
    case 'migration_chain':
      return { allowedOutcomes: ['accepted'], migrationPrefix: migrationPrefix('migrate', operationId) }
    case 'migration_rollback':
      // Step 0 is the schema assertion; the duplicate history insert is step 7.
      return { allowedOutcomes: ['rejected'], rejectionCode: 'constraint', failingStatementIndex: 6, migrationPrefix: migrationPrefix('rollback', operationId) }
    case 'owner_probe':
      return { allowedOutcomes: ['accepted', 'rejected'], rejectionCode: 'policy:chaos_profiles:update', failingStatementIndex: 0 }
    default:
      return { allowedOutcomes: ['accepted'] }
  }
}

/** Complete v1→v2 lifecycle: backfill, replacement index/view/trigger, and version history. */
export function migrationChainStatements(prefix: string): WorkloadStatement[] {
  const table = `${prefix}_items`
  const audit = `${prefix}_audit`
  return [
    { sql: `CREATE TABLE ${table} (id INTEGER PRIMARY KEY, legacy_name TEXT NOT NULL) STRICT` },
    { sql: `INSERT INTO ${table} (id, legacy_name) VALUES (1, 'Alpha'), (2, 'Beta') RETURNING id, legacy_name` },
    { sql: 'INSERT INTO chaos_schema_migrations (component, version, checksum) VALUES (?, 1, ?)', params: [prefix, `${prefix}-v1`] },
    { sql: `CREATE INDEX ${prefix}_legacy_idx ON ${table}(legacy_name)` },
    { sql: `CREATE VIEW ${prefix}_legacy_view AS SELECT id, legacy_name FROM ${table}` },
    { sql: `CREATE TABLE ${audit} (item_id INTEGER PRIMARY KEY NOT NULL, normalized_name TEXT NOT NULL) STRICT` },
    { sql: `CREATE TRIGGER ${prefix}_legacy_trigger AFTER INSERT ON ${table} BEGIN INSERT INTO ${audit} (item_id, normalized_name) VALUES (NEW.id, NEW.legacy_name); END` },
    { sql: `ALTER TABLE ${table} ADD COLUMN normalized_name TEXT` },
    { sql: `UPDATE ${table} SET normalized_name = lower(legacy_name) RETURNING id, normalized_name` },
    { sql: `DROP TRIGGER ${prefix}_legacy_trigger` },
    { sql: `DROP VIEW ${prefix}_legacy_view` },
    { sql: `DROP INDEX ${prefix}_legacy_idx` },
    { sql: `CREATE UNIQUE INDEX ${prefix}_current_idx ON ${table}(normalized_name)` },
    { sql: `CREATE VIEW ${prefix}_current_view AS SELECT id, normalized_name FROM ${table} WHERE normalized_name IS NOT NULL` },
    { sql: `CREATE TRIGGER ${prefix}_current_trigger AFTER INSERT ON ${table} BEGIN INSERT INTO ${audit} (item_id, normalized_name) VALUES (NEW.id, COALESCE(NEW.normalized_name, lower(NEW.legacy_name))); END` },
    { sql: `ALTER TABLE ${table} ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 2` },
    { sql: 'INSERT INTO chaos_schema_migrations (component, version, checksum) VALUES (?, 2, ?)', params: [prefix, `${prefix}-v2`] },
    { sql: `INSERT INTO ${table} (id, legacy_name, normalized_name) VALUES (3, 'Gamma', 'gamma') RETURNING id, normalized_name, schema_version` },
    { sql: `SELECT id, normalized_name, schema_version FROM ${table} ORDER BY id` },
    { sql: `SELECT item_id, normalized_name FROM ${audit} ORDER BY item_id` },
  ]
}

/** A deliberately failing migration whose catalog and history writes must roll back atomically. */
export function migrationRollbackStatements(prefix: string): WorkloadStatement[] {
  const table = `${prefix}_items`
  return [
    { sql: `CREATE TABLE ${table} (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT` },
    { sql: `CREATE INDEX ${prefix}_idx ON ${table}(value)` },
    { sql: `CREATE VIEW ${prefix}_view AS SELECT id, value FROM ${table}` },
    { sql: `CREATE TRIGGER ${prefix}_trigger AFTER INSERT ON ${table} BEGIN SELECT 1; END` },
    { sql: 'INSERT INTO chaos_schema_migrations (component, version, checksum) VALUES (?, 1, ?)', params: [prefix, `${prefix}-must-rollback`] },
    { sql: "INSERT INTO chaos_schema_migrations (component, version, checksum) VALUES ('profiles', 1, 'duplicate-must-fail')" },
  ]
}

function migrationPrefix(kind: 'migrate' | 'rollback', operationId: string): string {
  return `chaos_${kind}_${operationId.replaceAll('-', '_')}`
}

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve()
  return new Promise((resolveDelay) => {
    const timer = setTimeout(done, milliseconds)
    const abort = () => { clearTimeout(timer); done() }
    function done(): void { signal.removeEventListener('abort', abort); resolveDelay() }
    signal.addEventListener('abort', abort, { once: true })
  })
}

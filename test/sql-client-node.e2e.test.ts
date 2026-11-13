import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { ChronologClient, sqlValue } from '@chronolog/client'
import {
  DeterministicMaterializer,
  createDoltLiteMaterializationRuntime,
  readNativeEngineInfo,
} from '@chronolog/materializer-doltlite'
import { ChronologNode, type MembershipResolver } from '@chronolog/node-core'
import { createExecutionManifest, equalBytes, generateEd25519KeyPair, sqlStatement } from '@chronolog/protocol'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import { chaosBootstrapStatements, schemaVersionAssertion } from '../packages/chaos/src/schema.js'
import { migrationChainStatements, migrationRollbackStatements } from '../packages/chaos/src/workload.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('SQL client → RPC → node → reducer', () => {
  it('submits plain SQL with named and positional bindings and records the signed source', async () => {
    const { client, node } = await runtime()
    const bootstrap = await client.transaction([
      'CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL) STRICT',
      { sql: 'INSERT INTO accounts VALUES (:id, :balance)', params: { id: 1n, balance: 100n } },
    ])
    expect((await terminal(client, bootstrap.transactionId)).outcome.type).toBe('accepted')
    expect((await client.query('SELECT balance FROM accounts WHERE id = ?', [1n])).result.rows).toEqual([[100n]])

    const balance = (await client.query('SELECT balance FROM accounts WHERE id = ?', [1n])).result.rows[0]?.[0]
    const update = await client.transaction([
      { sql: "SELECT chronolog_assert((SELECT balance FROM accounts WHERE id = ?) = ?, 'balance_changed')", params: [1n, balance] },
      { sql: 'UPDATE accounts SET balance = :next WHERE id = :id RETURNING id, balance', params: { next: 90n, id: 1n } },
    ])
    expect((await terminal(client, update.transactionId)).outcome).toEqual({ type: 'accepted' })
    expect((await client.query('SELECT balance FROM accounts WHERE id = ?', [1n])).result.rows).toEqual([[90n]])

    const core = node.candidateCore(new TextEncoder().encode(update.transactionId))
    expect(core?.program.statements[1]?.sql).toBe('UPDATE accounts SET balance = :next WHERE id = :id RETURNING id, balance')
  })

  it('reports the failing statement and code, and rolls back partial work', async () => {
    const { client } = await runtime()
    await terminal(client, (await client.transaction([
      'CREATE TABLE guarded_values (id INTEGER PRIMARY KEY, value INTEGER NOT NULL) STRICT',
      'INSERT INTO guarded_values VALUES (1, 10)',
    ])).transactionId)

    const failedStatement = await client.transaction([
      'UPDATE guarded_values SET value = 20 WHERE id = 1 RETURNING value',
      'INSERT INTO guarded_values VALUES (1, 30)',
    ])
    expect((await terminal(client, failedStatement.transactionId)).outcome).toEqual({
      type: 'rejected',
      rejection: { code: 'constraint', statementIndex: 1 },
    })
    expect((await client.query('SELECT value FROM guarded_values WHERE id = 1')).result.rows).toEqual([[10n]])

    const failedAssertion = await client.transaction([
      "SELECT chronolog_assert((SELECT value FROM guarded_values WHERE id = 1) = 99, 'value_must_be_99')",
      'UPDATE guarded_values SET value = 99 WHERE id = 1',
    ])
    expect((await terminal(client, failedAssertion.transactionId)).outcome).toEqual({
      type: 'rejected',
      rejection: { code: 'assert:value_must_be_99', statementIndex: 0 },
    })
    expect((await client.query('SELECT value FROM guarded_values WHERE id = 1')).result.rows).toEqual([[10n]])

    const denied = await client.transaction(["ATTACH DATABASE ':memory:' AS other"])
    expect((await terminal(client, denied.transactionId)).outcome).toMatchObject({ type: 'rejected', rejection: { statementIndex: 0 } })
  })

  it('round-trips every SQLite storage class, including integral REALs and empty BLOBs', async () => {
    const { client } = await runtime()
    const transaction = await client.transaction([
      'CREATE TABLE dynamic_values (id INTEGER PRIMARY KEY, value)',
      {
        sql: 'INSERT INTO dynamic_values (value) VALUES (?), (?), (?), (?), (?), (?), (?)',
        params: [null, 42, 1.5, sqlValue.real(2), 'Grüße', Uint8Array.of(0, 255), new Uint8Array(0)],
      },
    ])
    expect((await terminal(client, transaction.transactionId)).outcome.type).toBe('accepted')
    const complete = await client.query('SELECT typeof(value), value FROM dynamic_values ORDER BY id')
    expect(complete.result.rows).toEqual([
      ['null', null], ['integer', 42n], ['real', 1.5], ['real', 2], ['text', 'Grüße'],
      ['blob', Uint8Array.of(0, 255)], ['blob', new Uint8Array(0)],
    ])
    const displayLimited = await client.query('SELECT value FROM dynamic_values ORDER BY id', [], { maxRows: 2 })
    expect(displayLimited.result.rows).toEqual([[null], [42n]])
    expect(displayLimited.result.truncated).toBe(true)
  })

  it('pins the clock and random generator to the transaction', async () => {
    const { client, node } = await runtime()
    const transaction = await client.transaction([
      'CREATE TABLE stamped (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, noise INTEGER NOT NULL)',
      "INSERT INTO stamped (at, noise) VALUES (unixepoch('now', 'subsec') * 1000, random())",
    ])
    expect((await terminal(client, transaction.transactionId)).outcome.type).toBe('accepted')
    const core = node.candidateCore(new TextEncoder().encode(transaction.transactionId))!
    const [[at]] = (await client.query('SELECT at FROM stamped')).result.rows as [[number | bigint]]
    expect(BigInt(Math.round(Number(at)))).toBe(core.authorTimestampMs)
  })

  it('runs schema assumptions, migrations, mixed clients and atomic migration rollback end to end', async () => {
    const { client } = await runtime()
    expect((await terminal(client, (await client.transaction(chaosBootstrapStatements(2))).transactionId)).outcome.type).toBe('accepted')

    const prefix = 'chaos_migrate_e2e'
    const migration = await client.transaction([schemaVersionAssertion('profiles', 2), ...migrationChainStatements(prefix)])
    expect((await terminal(client, migration.transactionId)).outcome).toEqual({ type: "accepted" })
    expect((await client.query(
      'SELECT version FROM chaos_schema_migrations WHERE component = ? ORDER BY version',
      [prefix],
    )).result.rows).toEqual([[1n], [2n]])
    expect((await client.query(
      "SELECT name FROM sqlite_schema WHERE name LIKE 'chaos_migrate_e2e_%' ORDER BY name",
    )).result.rows.map((row) => row[0])).toEqual([
      `${prefix}_audit`, `${prefix}_current_idx`, `${prefix}_current_trigger`, `${prefix}_current_view`, `${prefix}_items`,
    ])

    const legacy = await client.transaction([
      schemaVersionAssertion('profiles', 1),
      "INSERT INTO chaos_profiles (profile_id, display_name) VALUES ('legacy-e2e', 'Legacy')",
    ])
    const current = await client.transaction([
      schemaVersionAssertion('profiles', 2),
      "INSERT INTO chaos_profiles (profile_id, display_name, email, schema_version) VALUES ('current-e2e', 'Current', 'current@example.test', 2)",
    ])
    expect((await terminal(client, legacy.transactionId)).outcome.type).toBe('accepted')
    expect((await terminal(client, current.transactionId)).outcome.type).toBe('accepted')
    expect((await client.query('SELECT profile_id, schema_version, email_seen FROM chaos_profile_audit ORDER BY profile_id')).result.rows).toEqual([
      ['current-e2e', 2n, 1n],
      ['legacy-e2e', 2n, 0n],
    ])

    const rollbackPrefix = 'chaos_rollback_e2e'
    const rollback = await client.transaction([schemaVersionAssertion('profiles', 2), ...migrationRollbackStatements(rollbackPrefix)])
    expect((await terminal(client, rollback.transactionId)).outcome).toEqual({
      type: 'rejected',
      rejection: { code: 'constraint', statementIndex: 6 },
    })
    expect((await client.query('SELECT name FROM sqlite_schema WHERE name LIKE ?', [`${rollbackPrefix}%`])).result.rows).toEqual([])
    expect((await client.query('SELECT version FROM chaos_schema_migrations WHERE component = ?', [rollbackPrefix])).result.rows).toEqual([])
  })

  it('publishes replay changes through live SQL and outcome resources', async () => {
    let now = 10_000
    const { client, node } = await runtime({ clockNow: () => now })
    const bootstrap = await client.transaction([
      'CREATE TABLE replay_accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL) STRICT',
      'INSERT INTO replay_accounts VALUES (1, 100)',
    ])
    await terminal(client, bootstrap.transactionId)

    const live = client.liveQuery('SELECT balance FROM replay_accounts WHERE id = 1')
    const unsubscribeLive = live.subscribe(() => undefined)
    await waitFor(() => live.getSnapshot().value?.result?.rows[0]?.[0] === 100n)

    now += 1
    const later = await client.transaction([
      "SELECT chronolog_assert((SELECT balance FROM replay_accounts WHERE id = 1) = 100, 'balance_changed')",
      'UPDATE replay_accounts SET balance = 90 WHERE id = 1',
    ])
    expect((await terminal(client, later.transactionId)).outcome.type).toBe('accepted')
    await waitFor(() => live.getSnapshot().value?.result?.rows[0]?.[0] === 90n)

    const outcomeResource = later.outcome
    const unsubscribeOutcome = outcomeResource.subscribe(() => undefined)
    await waitFor(() => outcomeResource.getSnapshot().value?.outcome.type === 'accepted')

    const bootstrapTimestamp = node.candidateCore(new TextEncoder().encode(bootstrap.transactionId))!.authorTimestampMs
    const predecessor = await node.publish({
      authorTimestampMs: bootstrapTimestamp,
      program: { version: 1, statements: [sqlStatement('UPDATE replay_accounts SET balance = 80 WHERE id = 1')] },
    })
    expect((await terminal(client, predecessor.txIdText)).outcome.type).toBe('accepted')
    await waitFor(() => outcomeResource.getSnapshot().value?.outcome.type === 'rejected')
    expect(outcomeResource.getSnapshot().value).toMatchObject({
      changedByReplay: true,
      outcome: { type: 'rejected', rejection: { code: 'assert:balance_changed', statementIndex: 0 } },
    })
    await waitFor(() => live.getSnapshot().value?.result?.rows[0]?.[0] === 80n)
    expect((await client.query('SELECT balance FROM replay_accounts WHERE id = 1')).result.rows).toEqual([[80n]])

    unsubscribeOutcome()
    unsubscribeLive()
  })
})

async function terminal(client: ChronologClient, transactionId: string) {
  const deadline = Date.now() + 5_000
  while (true) {
    const outcome = await client.getTransactionOutcome(transactionId)
    if (outcome.outcome.type !== 'pending') return outcome
    if (Date.now() >= deadline) throw new Error('transaction did not settle')
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

async function waitFor(predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('condition did not become true')
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

async function runtime(options: { readonly clockNow?: () => number } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-sql-client-'))
  const identity = await generateEd25519KeyPair()
  const groupId = bytes32(1)
  const membershipRevision = bytes32(2)
  const validationPolicy = bytes32(3)
  const capability = bytes32(4)
  const native = readNativeEngineInfo()
  const materializer = await DeterministicMaterializer.open({
    path: join(directory, 'application.db'),
    executionManifest: createExecutionManifest({ profile: 'chronolog-core-portable', engine: native.descriptor, engineDigest: native.digest }),
  })
  const membership: MembershipResolver = {
    canWrite: ({ writerId }) => equalBytes(writerId, identity.publicKeyBytes),
    canValidate: ({ validatorId, validatorCapability }) => equalBytes(validatorId, identity.publicKeyBytes) && equalBytes(validatorCapability, capability),
    threshold: () => 1,
  }
  const node = new ChronologNode({
    groupId, membershipRevision, validationPolicy, identity,
    transport: new MemoryTransportNetwork().createNode('sql-client'),
    materialization: createDoltLiteMaterializationRuntime(materializer),
    membership,
    ...(options.clockNow === undefined ? {} : { clock: { now: options.clockNow } }),
    validator: { capabilityId: capability, cutoffLagMs: Number.MAX_SAFE_INTEGER },
  })
  await node.start()
  const client = new ChronologClient({
    groupId: Buffer.from(groupId).toString('base64url'),
    transport: new InProcessRpcTransport(new NodeRpcService({ node })),
  })
  cleanup.push(async () => { await client.close(); await node.close(); await rm(directory, { recursive: true, force: true }) })
  return { client, node }
}
function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }

// Real-runtime integration fixture, bundled by celld-bridge.integration.test.ts.
// No request supplies SQL or privileges; this is a fixed trusted test program.
import { encodeTransactionCore, platformOp, program, transactionDigest, type ProgramStep, type TransactionCore } from '@chronolog/protocol'
import { createCelldSqlEngine, type CelldSqlStorage } from './celld-engine.js'
import { DeterministicMaterializer } from './materializer.js'
import type { ReplayProposal } from './types.js'

const key = (fill: number) => new Uint8Array(32).fill(fill)
const root = key(160), alice = key(11), bob = key(12)
const check = (condition: boolean, code: string): void => { if (!condition) throw new Error(code) }

export class Repo {
  #materializer: Promise<DeterministicMaterializer> | undefined
  constructor(private readonly ctx: { readonly storage: CelldSqlStorage }) {}

  #open(): Promise<DeterministicMaterializer> {
    this.#materializer ??= DeterministicMaterializer.open({ engine: createCelldSqlEngine(this.ctx.storage), path: 'application', rootPrincipal: root, checkpointEvery: 1 })
    return this.#materializer
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const materializer = await this.#open()
      const path = new URL(request.url).pathname
      if (path === '/exercise') await this.#exercise(materializer)
      else if (path !== '/state') return new Response('not found', { status: 404 })
      return Response.json({
        profile: this.ctx.storage.dolt.programEngineProfile(),
        revision: String(materializer.revision), orderLength: materializer.orderLength, finalOrderLength: materializer.finalOrderLength,
        rows: materializer.localSql('SELECT id, balance FROM accounts ORDER BY id').rows,
        finalRows: materializer.localSql('SELECT id, balance FROM accounts ORDER BY id', [], { view: 'final' }).rows,
        outcomes: materializer.transactionLog().map(row => ({ operationId: row.operationId, outcome: row.outcome, rejectionCode: row.rejectionCode })),
        schema: materializer.localSql("SELECT name FROM chronolog_ddl_objects ORDER BY name").rows,
        grants: materializer.localSql('SELECT count(*) FROM chronolog_ddl_grants WHERE revoked_tx IS NULL').rows,
      })
    } catch (error) {
      return Response.json({ error: error instanceof Error ? error.message : String(error), stack: error instanceof Error ? error.stack : '' }, { status: 500 })
    }
  }

  async #exercise(materializer: DeterministicMaterializer): Promise<void> {
    check(materializer.orderLength === 0, 'EXERCISE_REQUIRES_EMPTY_STORE')
    const digest = materializer.executionManifestDigest
    const make = async (timestamp: bigint, operationId: string, actor: Uint8Array, ...steps: readonly (ProgramStep | string)[]): Promise<ReplayProposal> => {
      const core: TransactionCore = { groupId: key(1), membershipRevision: key(2), validationPolicy: key(3), nonce: key(Number(timestamp)), authorId: actor,
        authorTimestampMs: timestamp, operationId, executionManifestDigest: digest, program: program(...steps) }
      const canonicalCandidate = encodeTransactionCore(core)
      const candidateDigest = await transactionDigest(canonicalCandidate)
      return { core, canonicalCandidate, candidateDigest, txId: candidateDigest.slice() }
    }
    const schema = await make(10n, 'schema', root,
      'CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL)', 'INSERT INTO accounts (id, balance) VALUES (1, 10)',
      'CREATE TABLE other (id INTEGER PRIMARY KEY)',
      platformOp.grantDdl({ scope: { kind: 'namespace', name: 'main' }, grantee: alice, operations: ['create'] }))
    const mine = await make(30n, 'offline-create', alice, 'CREATE TABLE mine (id INTEGER PRIMARY KEY)', 'ALTER TABLE mine ADD COLUMN own TEXT')
    const deniedRoot = await make(40n, 'denied-root-cross-object', root, 'ALTER TABLE mine ADD COLUMN stolen TEXT')
    const deniedAlice = await make(50n, 'denied-alice-cross-object', alice, 'DROP TABLE other')
    const spend = await make(60n, 'spend', root, 'CREATE TABLE audit (id INTEGER PRIMARY KEY)',
      "SELECT chronolog_assert((SELECT balance FROM accounts WHERE id=1)>=50, 'balance')", 'UPDATE accounts SET balance=balance-50 WHERE id=1')
    const rollback = await make(70n, 'mixed-rollback', root,
      platformOp.grantDdl({ scope: { kind: 'object', name: 'other' }, grantee: bob, operations: ['alter'] }),
      'CREATE TABLE rolled_back (id INTEGER PRIMARY KEY)', 'INSERT INTO accounts (id, balance) VALUES (2, 5)', "SELECT chronolog_assert(0, 'rollback')")
    const history = [schema, mine, deniedRoot, deniedAlice, spend, rollback]
    await materializer.materialize(history)
    check(materializer.outcome(mine.txId)?.outcome === 'accepted', 'OFFLINE_DDL_FAILED')
    check(materializer.outcome(deniedRoot.txId)?.rejectionCode === 'denied', 'ROOT_CROSS_OBJECT_ALLOWED')
    check(materializer.outcome(deniedAlice.txId)?.rejectionCode === 'denied', 'ALICE_CROSS_OBJECT_ALLOWED')
    check(materializer.outcome(spend.txId)?.rejectionCode === 'assert:balance', 'MISSING_PREDECESSOR_NOT_REJECTED')
    check(materializer.outcome(rollback.txId)?.rejectionCode === 'assert:rollback', 'MIXED_ROLLBACK_FAILED')
    const held = materializer.captureRead()
    try {
      const late = await make(20n, 'late-deposit', root, 'UPDATE accounts SET balance=balance+100 WHERE id=1')
      await materializer.materialize([schema, late, ...history.slice(1)])
      check(materializer.outcome(spend.txId)?.outcome === 'accepted', 'LATE_PREDECESSOR_DID_NOT_REVISE_OUTCOME')
      check(JSON.stringify(held.query('SELECT balance FROM accounts').rows) === JSON.stringify([[{ kind: 'integer', value: '10' }]]), 'CAPTURE_CHANGED')
      check(materializer.localSql("SELECT name FROM sqlite_schema WHERE name='rolled_back'").rows.length === 0, 'SCHEMA_ROLLBACK_LEAK')
      await materializer.publishFinal(2)
      const read = materializer.captureRead()
      try {
        const provenance = read.query('SELECT tx_id, author_id, operation_id, outcome FROM chronolog_transactions ORDER BY order_index').rows
        check(provenance.length === 7, 'PROVENANCE_LOG_LENGTH')
        check(provenance[0]?.[0]?.kind === 'blob' && provenance[0][0].value.length === 32, 'PROPOSAL_NOT_RAW_DIGEST')
      } finally { read.release() }
    } finally { held.release() }
  }
}

export default {
  fetch(request: Request, env: { REPO: { idFromName(name: string): unknown; get(id: unknown): { fetch(request: Request): Promise<Response> } } }): Promise<Response> {
    return env.REPO.get(env.REPO.idFromName('chronolog-bridge')).fetch(request)
  },
}

import { afterEach, describe, expect, it } from 'vitest'
import { bytesToHex, sha256Sync, utf8 } from '@chronolog/canonical'
import { decodeOperationCore, decodeSignedOperation, operationIdDigest, type JsonValue } from '@chronolog/protocol'
import { MemoryBytesStore } from '@chronolog/records'
import {
  canonicalAdmissionCheckpointMessage,
  signAdmissionCheckpoint,
  signAdmissionMessage,
  type AdmissionCheckpointPayload,
} from '@chronolog/authority'
import { createLogGenesis } from './genesis.js'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import { createGuardedTx } from './guarded-tx.js'
import { replayBlindHostControl } from './blind-host.js'

const closes: Array<() => Promise<void>> = []
afterEach(async () => {
  for (const close of closes.splice(0).reverse()) {
    try { await close() } catch { /* ignore cleanup */ }
  }
})

describe('SQLite-CAS Read-Only Chronolog Introspection, Guarded OCC, Unified $admission, defineReducer & simulate()', () => {
  it('exposes transaction metadata, cross-topic state, and query-only history read-only in SQLite-CAS while enforcing partition isolation', async () => {
    const devAdmin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devAlice = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    const created = await createLogGenesis({
      creator: {
        publicKey: devAdmin.identity.publicKey,
        wrapKey: devAdmin.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
      },
      members: [
        { publicKey: devAlice.identity.publicKey, wrapKey: devAlice.wrapKey.publicKey, reader: true, writer: true },
      ],
      privateLog: true,
      topics: {
        db: { module: 'chronolog/sql' },
        settings: { module: 'chronolog/crdt', export: 'lwwMap' },
      },
    })

    const epochKeys = new Map([[0, created.epoch0Key!]])
    const sess = await createApplicationSession({
      device: devAdmin,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    closes.push(() => sess.close())

    // Populate a sibling JSON topic so SQL can introspect cross-topic reducer state
    const setOp = await sess.submit({
      awaitMaterialized: true,
      operationId: 'set-theme-1',
      updates: [{ topic: 'settings', input: { action: 'set', key: 'theme', value: 'solarized' } }],
    })
    expect((await setOp.materialized()).outcome).toBe('accepted')

    // Create a SQL table that writes transaction metadata directly via SQL functions + chronolog_tx
    const mig = await sess.submit({
      awaitMaterialized: true,
      operationId: 'mig-introspect-1',
      updates: [{
        topic: 'db',
        input: {
          action: 'migrate',
          statements: [
            'CREATE TABLE notes (id TEXT PRIMARY KEY, body TEXT NOT NULL, created_by TEXT NOT NULL, created_op TEXT NOT NULL, created_operation_id TEXT NOT NULL, vis TEXT NOT NULL, prev_author_op TEXT, theme_snapshot TEXT, _last_op_id TEXT)',
          ],
          stampTables: ['notes'],
        },
      }],
    })
    expect((await mig.materialized()).outcome).toBe('accepted')

    // Insert using chronolog_tx, operation_id(), tx_visibility(), chronolog_author_last_op(), chronolog_topic(), and chronolog_topic_query()
    const ins = await sess.submit({
      awaitMaterialized: true,
      operationId: 'insert-note-42',
      updates: [{
        topic: 'db',
        input: {
          action: 'exec',
          sql: `INSERT INTO notes (id, body, created_by, created_op, created_operation_id, vis, prev_author_op, theme_snapshot)
                SELECT 'n1', 'hello', author, op_id, operation_id(), tx_visibility(), chronolog_author_last_op(), json_extract(chronolog_topic('settings'), '$.entries.theme.value')
                FROM chronolog_tx`,
          preconditions: [
            { sql: "SELECT chronolog_can('writer')", expect: { firstValue: 1 } },
            { sql: "SELECT chronolog_topic_query('$admission', ?)", params: [JSON.stringify({ kind: 'can', capability: 'writer', actor: devAdmin.identity.publicKey })], expect: { firstValue: 'true' } },
            { sql: 'SELECT chronolog_op(?)', params: [setOp.id], expect: { firstValue: 'accepted' } },
            { sql: "SELECT chronolog_topic_last_op('settings')", expect: { firstValue: setOp.id } },
          ],
        },
      }],
    })
    const insRes = await ins.materialized()
    expect(insRes.outcome, `${insRes.rejectionCode}: ${insRes.rejectionDetail}`).toBe('accepted')

    // Query back the stored row and verify every introspected field
    const noteRes = await sess.query('db', { sql: 'SELECT id, created_by, created_op, created_operation_id, vis, prev_author_op, theme_snapshot, _last_op_id FROM notes WHERE id = ?', params: ['n1'], format: 'objects' })
    const row = (noteRes.value as { rows: Record<string, JsonValue>[] }).rows[0]!
    expect(row.created_by).toBe(devAdmin.identity.publicKey)
    expect(row.created_op).toBe(ins.id)
    expect(row.created_operation_id).toBe('insert-note-42')
    expect(row.vis).toBe('encrypted')
    expect(row.prev_author_op).toBe(mig.id)
    expect(row.theme_snapshot).toBe('solarized')
    expect(row._last_op_id).toBe(ins.id)

    // Virtual tables must be strictly read-only (DML rejected)
    for (const badSql of [
      "DELETE FROM chronolog_tx",
      "DELETE FROM chronolog_topics",
      "INSERT INTO chronolog_topics (topic, state_json, last_op_id) VALUES ('x', '{}', NULL)",
      "CREATE TABLE chronolog_spoof (id INT)",
    ]) {
      const bad = await sess.submit({
        awaitMaterialized: true,
        updates: [{ topic: 'db', input: { action: 'exec', sql: badSql } }],
      })
      expect((await bad.materialized()).outcome).toBe('rejected')
    }

    // chronolog_history MUST be rejected inside reduce() to preserve snapshot-bootstrap parity
    const histInReduce = await sess.submit({
      awaitMaterialized: true,
      updates: [{
        topic: 'db',
        input: {
          action: 'exec',
          sql: "INSERT INTO notes (id, body, created_by, created_op, created_operation_id, vis) SELECT 'bad', CAST(COUNT(*) AS TEXT), actor(), op_id(), operation_id(), tx_visibility() FROM chronolog_history",
        },
      }],
    })
    const histInReduceOut = await histInReduce.materialized()
    expect(histInReduceOut.outcome).toBe('rejected')

    // Inside query(), chronolog_topics and chronolog_history work read-only with full cross-topic state & history!
    const topicsRes = await sess.query('db', { sql: 'SELECT topic, last_op_id FROM chronolog_topics ORDER BY topic', format: 'objects' })
    const topicRows = (topicsRes.value as { rows: { topic: string; last_op_id: string | null }[] }).rows
    expect(topicRows.map(r => r.topic)).toContain('$admission')
    expect(topicRows.map(r => r.topic)).toContain('settings')
    expect(topicRows.find(r => r.topic === 'settings')?.last_op_id).toBe(setOp.id)

    const histRes = await sess.query('db', { sql: 'SELECT seq, op_id, author, operation_id, visibility, outcome, rejection_code FROM chronolog_history ORDER BY seq', format: 'objects' })
    const histRows = (histRes.value as { rows: { seq: number; op_id: string; author: string; operation_id: string; visibility: string; outcome: string; rejection_code: string | null }[] }).rows
    expect(histRows.length).toBeGreaterThanOrEqual(4)
    expect(histRows.some(r => r.op_id === ins.id && r.operation_id === 'insert-note-42' && r.outcome === 'accepted' && r.visibility === 'encrypted')).toBe(true)
    expect(histRows.some(r => r.op_id === histInReduce.id && r.outcome === 'rejected')).toBe(true)
  })

  it('tracks scoped OCC read-sets via createGuardedTx (readRow, readSql, readQuery, requireOwnHistory, postconditions) and detects conflicts', async () => {
    const devA = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devB = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    const created = await createLogGenesis({
      creator: {
        publicKey: devA.identity.publicKey,
        wrapKey: devA.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
      },
      members: [
        { publicKey: devB.identity.publicKey, wrapKey: devB.wrapKey.publicKey, reader: true, writer: true },
      ],
      privateLog: true,
      topics: {
        sql: { module: 'chronolog/sql' },
        meta: { module: 'chronolog/crdt', export: 'lwwMap' },
      },
    })

    const epochKeys = new Map([[0, created.epoch0Key!]])
    const sessA = await createApplicationSession({
      device: devA,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    const sessB = await createApplicationSession({
      device: devB,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    closes.push(() => sessA.close(), () => sessB.close())

    // Migrate accounts table with row stamping + unstamped tags table
    await (await sessA.submit({
      awaitMaterialized: true,
      updates: [{
        topic: 'sql',
        input: {
          action: 'migrate',
          statements: [
            'CREATE TABLE accounts (id TEXT PRIMARY KEY, balance INTEGER NOT NULL, _last_op_id TEXT)',
            'CREATE TABLE tags (id TEXT PRIMARY KEY, label TEXT NOT NULL)',
            "INSERT INTO accounts (id, balance) VALUES ('alice', 100), ('bob', 50)",
            "INSERT INTO tags (id, label) VALUES ('t1', 'initial')",
          ],
          stampTables: ['accounts'],
        },
      }],
    })).materialized()
    await sessB.mergeFacts(await sessA.exportFacts({ includePrivateCas: true }))

    // 1. Scoped guarded tx: readRow on stamped table + postcondition invariant (total balance == 150) + requireOwnHistory
    const tx1 = createGuardedTx(sessA)
    const aliceRow = await tx1.readRow('accounts', { id: 'alice' })
    expect(aliceRow?.balance).toBe(100)
    expect(tx1.sqlPreconditions('sql')[0]?.kind).toBe('based_on_row')
    tx1
      .requireOwnHistory()
      .addSqlPostcondition({ sql: 'SELECT SUM(balance) FROM accounts', expect: { firstValue: 150 }, code: 'sql:conservation_violated' })
    const op1 = await tx1.submit({
      updates: [{
        topic: 'sql',
        input: {
          action: 'exec',
          statements: [
            { sql: 'UPDATE accounts SET balance = balance - 30 WHERE id = ?', params: ['alice'] },
            { sql: 'UPDATE accounts SET balance = balance + 30 WHERE id = ?', params: ['bob'] },
          ],
        },
      }],
    })
    expect((await op1.materialized()).outcome).toBe('accepted')

    // 2. Chained sequential requireOwnHistory() on same session immediately succeeds (causal floor keeps timestamp monotonic)
    const tx2 = createGuardedTx(sessA)
    tx2.requireOwnHistory()
    const tagRow = await tx2.readRow('tags', { id: 't1' })
    expect(tagRow?.label).toBe('initial')
    expect(tx2.sqlPreconditions('sql')[0]?.kind).toBe('row_matches')
    const op2 = await tx2.submit({
      updates: [{ topic: 'sql', input: { action: 'exec', sql: "UPDATE tags SET label = 'v2' WHERE id = 't1'" } }],
    })
    expect((await op2.materialized()).outcome).toBe('accepted')

    // 3. Postcondition violation atomically rolls back DML
    const txBadPost = createGuardedTx(sessA)
    txBadPost.addSqlPostcondition({ sql: 'SELECT SUM(balance) FROM accounts', expect: { firstValue: 150 }, code: 'sql:conservation_violated' })
    const opBadPost = await txBadPost.submit({
      updates: [{ topic: 'sql', input: { action: 'exec', sql: "UPDATE accounts SET balance = balance - 10 WHERE id = 'alice'" } }],
    })
    const badPostRes = await opBadPost.materialized()
    expect(badPostRes.outcome).toBe('rejected')
    expect(badPostRes.rejectionCode).toBe('sql:conservation_violated')

    // 4. Stale concurrent writer (sessB hasn't synced op1 yet): readRow captures stale _last_op_id; on merge, conflict is recorded!
    const txStale = createGuardedTx(sessB, { onFailed: 'record_conflict' })
    const staleAlice = await txStale.readRow('accounts', { id: 'alice' })
    expect(staleAlice?.balance).toBe(100)
    const opStale = await txStale.submit({
      authorTimestampMs: BigInt(Date.now() + 5_000),
      updates: [{ topic: 'sql', input: { action: 'exec', sql: "UPDATE accounts SET balance = 999 WHERE id = 'alice'" } }],
    })
    expect((await opStale.materialized()).outcome).toBe('accepted') // accepted optimistically locally

    // Merge both ways: both replicas converge identically with opStale diverted into _chronolog_conflicts!
    await sessA.mergeFacts(await sessB.exportFacts({ includePrivateCas: true }))
    await sessB.mergeFacts(await sessA.exportFacts({ includePrivateCas: true }))
    expect(sessA.revision('local').stateRoot).toBe(sessB.revision('local').stateRoot)

    const balRes = await sessA.query('sql', { sql: "SELECT balance FROM accounts WHERE id = 'alice'" })
    expect((balRes.value as { rows: number[][] }).rows[0]![0]).toBe(70)
    const conflictsRes = await sessA.query('sql', { kind: 'conflicts' })
    const conflicts = (conflictsRes.value as { conflicts: { opId: string; code: string }[] }).conflicts
    expect(conflicts.some(c => c.opId === opStale.id && c.code === 'sql:row_modified')).toBe(true)

    // 5. Same-author forked history detection via author_last_op (two sessions sharing devA's identity)
    const devAClone = await openApplicationDevice({ store: new MemoryBytesStore(), create: true, managedSigner: devA.identity })
    const sessA2 = await createApplicationSession({
      device: devAClone,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    closes.push(() => sessA2.close())
    // sessA2 only knows up to genesis (authorLastOpId === null), while sessA already authored mig/op1/op2
    expect(sessA2.authorLastOpId()).toBeNull()
    expect(sessA.authorLastOpId()).toBe(op2.id)
    const forkedTx = createGuardedTx(sessA2)
    forkedTx.requireOwnHistory()
    expect(forkedTx.assumptions()).toEqual({ checks: [{ kind: 'author_last_op', lastOpId: null }] })
    const forkedOp = await forkedTx.submit({
      authorTimestampMs: BigInt(Date.now() + 10_000),
      updates: [{ topic: 'meta', input: { action: 'set', key: 'fork', value: 'bad' } }],
    })
    await sessA.mergeFacts(await sessA2.exportFacts({ includePrivateCas: true }))
    await sessA2.mergeFacts(await sessA.exportFacts({ includePrivateCas: true }))
    expect(sessA.opOutcome(forkedOp.id), `A=${sessA.authorLastOpId()} A2=${sessA2.authorLastOpId()} forked=${JSON.stringify(sessA.inspectOperation(forkedOp.id))}`).toBe('rejected')
    expect(sessA2.opOutcome(forkedOp.id)).toBe('rejected')
    expect(sessA.revision('local').stateRoot).toBe(sessA2.revision('local').stateRoot)
  })

  it('evaluates unified $admission history policies (weighted quorum, optimistic challenge, merkle anchor, member-quorum, surgical pinFrontier) identically on full peers and blind hosts', async () => {
    const devAdmin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devVal1 = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devVal2 = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devChallenger = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    const created = await createLogGenesis({
      creator: {
        publicKey: devAdmin.identity.publicKey,
        wrapKey: devAdmin.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
      },
      privateLog: true,
      topics: {
        notes: { module: 'chronolog/crdt', export: 'lwwMap' },
      },
    })

    const epochKeys = new Map([[0, created.epoch0Key!]])
    const sess = await createApplicationSession({
      device: devAdmin,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    closes.push(() => sess.close())

    const t1 = BigInt(Date.now())
    const opEarly = await sess.submit({
      awaitMaterialized: true,
      authorTimestampMs: t1 + 10n,
      updates: [{ topic: 'notes', input: { action: 'set', key: 'k1', value: 'included' } }],
    })
    expect((await opEarly.materialized()).outcome).toBe('accepted')

    // 1. Schedule weighted threshold-quorum (admin=2, val1=1, val2=1, threshold=3)
    const sched1 = await sess.admission.schedulePolicy({
      effectiveAfterMs: t1 + 50n,
      authorTimestampMs: t1 + 20n,
      policy: {
        kind: 'threshold-quorum',
        validators: {
          [devAdmin.identity.publicKey]: 2,
          [devVal1.identity.publicKey]: 1,
          [devVal2.identity.publicKey]: 1,
        },
        threshold: 3,
      },
    })
    expect((await sched1.materialized()).outcome).toBe('accepted')

    // Single signature (weight 2 < 3) must NOT finalize
    await sess.admission.createCheckpoint({
      throughMs: t1 + 100n,
      data: async (payload: AdmissionCheckpointPayload) => ({
        signatures: [await signAdmissionCheckpoint(payload, devAdmin.identity)],
      }),
    })
    expect(sess.admission.status().closedThroughMs).toBeNull()

    // Admin (2) + Val1 (1) = weight 3 >= 3 MUST finalize!
    const { evidence: quorumEv } = await sess.admission.createCheckpoint({
      throughMs: t1 + 100n,
      data: async (payload: AdmissionCheckpointPayload) => ({
        signatures: [
          await signAdmissionCheckpoint(payload, devAdmin.identity),
          await signAdmissionCheckpoint(payload, devVal1.identity),
        ],
      }),
    })
    expect(sess.admission.status().closedThroughMs).toBe(t1 + 100n)
    expect(sess.admissionStatus(opEarly.id)).toBe('finalized')

    // Verify blind host (Cloudflare Worker simulation) evaluates the exact same $admission.admit() identically!
    const facts = await sess.exportFacts()
    const blindPublicOps = facts.publicOps.map(raw => {
      const signed = decodeSignedOperation(raw)
      return { opId: operationIdDigest(signed.coreBytes), core: decodeOperationCore(signed.coreBytes) }
    })
    const blind = await replayBlindHostControl({
      genesis: created.genesis,
      publicCasNodes: facts.casNodes.filter(n => n.partition === 'public'),
      publicOps: blindPublicOps,
      evidence: [quorumEv],
    })
    expect(blind.admission.closedThroughMs).toBe(t1 + 100n)
    expect(blind.admission.includedOpIds.has(opEarly.id)).toBe(true)

    // 2. Handoff to optimistic-challenge at t1 + 200 (challengeWindowMs = 500)
    const sched2 = await sess.admission.schedulePolicy({
      effectiveAfterMs: t1 + 200n,
      authorTimestampMs: t1 + 120n,
      policy: {
        kind: 'optimistic-challenge',
        proposers: [devAdmin.identity.publicKey],
        challengers: [devChallenger.identity.publicKey],
        challengeWindowMs: 500,
      },
    })
    expect((await sched2.materialized()).outcome).toBe('accepted')

    // Seal handoff at t1 + 200 under quorum policy first
    await sess.admission.createCheckpoint({
      throughMs: t1 + 200n,
      data: async (payload: AdmissionCheckpointPayload) => ({
        signatures: [
          await signAdmissionCheckpoint(payload, devAdmin.identity),
          await signAdmissionCheckpoint(payload, devVal2.identity),
        ],
      }),
    })
    expect(sess.admission.status().closedThroughMs).toBe(t1 + 200n)

    // Optimistic checkpoint BEFORE window elapses -> rejected
    await sess.admission.createCheckpoint({
      throughMs: t1 + 300n,
      data: async (payload: AdmissionCheckpointPayload) => ({
        observedAtMs: Number(t1 + 500n), // < 300 + 500 = 800
        proposal: await signAdmissionCheckpoint(payload, devAdmin.identity),
      }),
    })
    expect(sess.admission.status().closedThroughMs).toBe(t1 + 200n)

    // Optimistic checkpoint AFTER window elapses BUT WITH valid fraud challenge -> rejected!
    await sess.admission.createCheckpoint({
      throughMs: t1 + 300n,
      data: async (payload: AdmissionCheckpointPayload) => {
        const chSig = await signAdmissionMessage('chronolog/admission-challenge/v1', {
          logId: payload.logId,
          scopeId: payload.scopeId ?? null,
          closedThroughMs: Number(payload.closedThroughMs),
          reason: 'invalid_state',
        }, devChallenger.identity)
        return {
          observedAtMs: Number(t1 + 900n),
          proposal: await signAdmissionCheckpoint(payload, devAdmin.identity),
          challenges: [{
            signer: chSig.signer,
            reason: 'invalid_state',
            signature: chSig.signature,
          }],
        }
      },
    })
    expect(sess.admission.status().closedThroughMs).toBe(t1 + 200n)

    // Optimistic checkpoint AFTER window with NO valid challenge -> admitted!
    await sess.admission.createCheckpoint({
      throughMs: t1 + 300n,
      data: async (payload: AdmissionCheckpointPayload) => ({
        observedAtMs: Number(t1 + 900n),
        proposal: await signAdmissionCheckpoint(payload, devAdmin.identity),
      }),
    })
    expect(sess.admission.status().closedThroughMs).toBe(t1 + 300n)

    // 3. Handoff to merkle-anchor at t1 + 400 (external anchor proof)
    const sched3 = await sess.admission.schedulePolicy({
      effectiveAfterMs: t1 + 400n,
      authorTimestampMs: t1 + 310n,
      policy: {
        kind: 'merkle-anchor',
        anchorSigners: [devVal1.identity.publicKey],
      },
    })
    expect((await sched3.materialized()).outcome).toBe('accepted')

    // Seal handoff at t1 + 400 under optimistic policy
    await sess.admission.createCheckpoint({
      throughMs: t1 + 400n,
      data: async (payload: AdmissionCheckpointPayload) => ({
        observedAtMs: Number(t1 + 1000n),
        proposal: await signAdmissionCheckpoint(payload, devAdmin.identity),
      }),
    })
    expect(sess.admission.status().closedThroughMs).toBe(t1 + 400n)

    // Submit Merkle-anchored checkpoint at t1 + 500
    await sess.admission.createCheckpoint({
      throughMs: t1 + 500n,
      data: async (payload: AdmissionCheckpointPayload) => {
        const leaf = bytesToHex(sha256Sync(utf8(canonicalAdmissionCheckpointMessage(payload))))
        const sibling = 'a'.repeat(64)
        const root = bytesToHex(sha256Sync(utf8(leaf + sibling)))
        const anchorSignature = await signAdmissionMessage('chronolog/merkle-anchor/v1', root, devVal1.identity)
        return {
          root,
          proof: [{ position: 'right', sibling }],
          anchorSignature,
        }
      },
    })
    expect(sess.admission.status().closedThroughMs).toBe(t1 + 500n)

    // 4. Surgical checkpoint descent via pinFrontier: backdated op <= closedThroughMs is excluded!
    const backdated = await sess.submit({
      awaitMaterialized: true,
      authorTimestampMs: t1 + 5n,
      updates: [{ topic: 'notes', input: { action: 'set', key: 'backdated', value: 'excluded' } }],
    })
    expect(sess.admissionStatus(backdated.id)).toBe('excluded')
    expect(sess.opOutcome(backdated.id)).toBeNull()
  })

  it('enforces kernel-level fail-closed $admission.authorize, monotonic topic tightening, defineReducer, and zero-side-effect session.simulate()', async () => {
    const devAdmin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devWriter = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devStranger = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    // A deliberately naive reducer that does NOT check permissions itself, plus a defineReducer module
    const naiveReducer = `
      export default {
        reduce(state, tx) {
          const items = Array.isArray(state) ? state : [];
          return { ok: true, state: items.concat([tx.payload.text]) };
        },
        query(state) { return state || []; },
      };
    `
    const strictDefineReducer = `
      import { defineReducer } from 'chronolog/reducer';
      export default defineReducer({
        initialState: { count: 0, log: [] },
        commands: {
          increment: {
            description: 'Increment counter by positive step',
            input: {
              type: 'object',
              required: ['step'],
              properties: { step: { type: 'integer', minimum: 1, maximum: 10 } },
            },
            requiredScope: 'billing:write',
            pre: (state, payload, tx, ctx) => {
              if (state.count + payload.step > 15) ctx.reject('cap_exceeded', 'max 15');
            },
            run: (state, payload, tx) => ({
              state: { count: state.count + payload.step, log: state.log.concat([tx.author]) },
              events: [{ topic: 'counter.inc', payload: { step: payload.step } }],
            }),
          },
        },
        queries: {
          total: {
            description: 'Read total count',
            input: { type: 'null' },
            run: (state) => state.count,
          },
        },
      });
    `

    const created = await createLogGenesis({
      creator: {
        publicKey: devAdmin.identity.publicKey,
        wrapKey: devAdmin.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
      },
      members: [
        { publicKey: devWriter.identity.publicKey, wrapKey: devWriter.wrapKey.publicKey, reader: true, writer: true, scopes: ['notes:read'] },
      ],
      privateLog: false,
      imports: {
        'app/naive': naiveReducer,
        'app/counter': strictDefineReducer,
      },
      topics: {
        naive: { module: 'app/naive', initialState: [] },
        counter: { module: 'app/counter' },
      },
    })

    const sessAdmin = await createApplicationSession({ device: devAdmin, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sessWriter = await createApplicationSession({ device: devWriter, genesis: created.genesisBytes, casNodes: created.casNodes })
    const sessStranger = await createApplicationSession({ device: devStranger, genesis: created.genesisBytes, casNodes: created.casNodes })
    closes.push(() => sessAdmin.close(), () => sessWriter.close(), () => sessStranger.close())

    // 1. Even though app/naive has ZERO auth checks, kernel-enforced $admission.authorize rejects non-writer!
    const strangerAttempt = await sessStranger.submit({
      awaitMaterialized: true,
      updates: [{ topic: 'naive', input: { text: 'unauthorized' } }],
    })
    const strangerRes = await strangerAttempt.materialized()
    expect(strangerRes.outcome).toBe('rejected')
    expect(strangerRes.rejectionCode).toBe('writer_required')
    expect(sessStranger.topic('naive')).toEqual([])

    // 2. Monotonic per-topic tightening: devWriter is a global writer, but counter.increment requires scope 'billing:write'!
    const writerNoScope = await sessWriter.submit({
      awaitMaterialized: true,
      updates: [{ topic: 'counter', input: { action: 'increment', step: 5 } }],
    })
    const writerRes = await writerNoScope.materialized()
    expect(writerRes.outcome).toBe('rejected')
    expect(writerRes.rejectionCode).toBe('scope_required')

    // 3. defineReducer auto-generates describe() metadata!
    const desc = await sessAdmin.describe()
    expect(desc.commands.some(c => c.name === 'increment')).toBe(true)
    expect(desc.queries.some(q => q.name === 'total')).toBe(true)

    // 4. session.simulate() performs ephemeral dry-run without mutating state or persisting ops
    const beforeRev = sessAdmin.revision().digest
    const simOk = await sessAdmin.simulate({
      updates: [{ topic: 'counter', input: { action: 'increment', step: 10 } }],
    })
    expect(simOk.ok).toBe(true)
    expect(simOk.changedTopics).toEqual(['counter'])
    expect(simOk.events).toHaveLength(1)
    expect(sessAdmin.revision().digest).toBe(beforeRev)
    expect((await sessAdmin.query('counter.total', null)).value).toBe(0)

    const simBadSchema = await sessAdmin.simulate({
      updates: [{ topic: 'counter', input: { action: 'increment', step: 99 } }],
    })
    expect(simBadSchema.ok).toBe(false)
    expect(simBadSchema.rejectionCode).toBe('schema:maximum')

    // Commit real +10, then simulate +6 -> hits pre() ctx.reject('cap_exceeded')
    await (await sessAdmin.submit({
      awaitMaterialized: true,
      updates: [{ topic: 'counter', input: { action: 'increment', step: 10 } }],
    })).materialized()
    const simCap = await sessAdmin.simulate({
      updates: [{ topic: 'counter', input: { action: 'increment', step: 6 } }],
    })
    expect(simCap.ok).toBe(false)
    expect(simCap.rejectionCode).toBe('cap_exceeded')
    expect(simCap.rejectionDetail).toBe('max 15')
    expect((await sessAdmin.query('counter.total', null)).value).toBe(10)
  })

  it('enforces kernel-level monotonic $seals (resolved reducer pins, frozen/append-only paths) and $admission.verify() cross-topic post-conditions', async () => {
    const devAdmin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devMember = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    const ledgerV1 = `
      export default {
        reduce(state, tx) {
          const bal = typeof state?.balance === 'number' ? state.balance : 0;
          return { ok: true, state: { balance: bal + Number(tx.payload.delta || 0) } };
        },
        query(state) { return state; },
      };
    `
    const ledgerV2 = `
      export default {
        reduce(state, tx) {
          return { ok: true, state: { balance: 999999 } };
        },
      };
    `
    const escrowMod = `
      export default {
        reduce(state, tx) {
          const locked = typeof state?.locked === 'number' ? state.locked : 0;
          return { ok: true, state: { locked: locked + Number(tx.payload.delta || 0) } };
        },
      };
    `
    const notesV1 = `
      export default {
        reduce(state, tx) {
          const cur = state && typeof state === 'object' ? state : { items: [] };
          return { ok: true, state: { ...cur, items: (cur.items || []).concat([tx.payload.text]) } };
        },
      };
    `
    const notesV2 = `
      export default {
        reduce(state, tx) {
          const cur = state && typeof state === 'object' ? state : { items: [] };
          return { ok: true, state: { ...cur, items: (cur.items || []).concat(['v2:' + tx.payload.text]) } };
        },
      };
    `
    const customAdmissionWithVerify = `
      import { createAdmission, attestedAdmission } from 'chronolog/admission';
      export default createAdmission({
        base: attestedAdmission,
        verify(before, after) {
          const bal = after.ledger?.balance ?? 0;
          const locked = after.escrow?.locked ?? 0;
          if (bal !== locked) {
            return { ok: false, code: 'conservation_mismatch', detail: bal + '!=' + locked };
          }
          return { ok: true };
        },
      });
    `

    const created = await createLogGenesis({
      creator: {
        publicKey: devAdmin.identity.publicKey,
        wrapKey: devAdmin.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
      },
      privateLog: false,
      imports: {
        'app/ledger': ledgerV1,
        'app/escrow': escrowMod,
        'app/notes': notesV1,
        'app/admission': customAdmissionWithVerify,
      },
      topics: {
        $admission: {
          module: 'app/admission',
          initialState: {
            members: [{
              publicKey: devAdmin.identity.publicKey,
              wrapKey: devAdmin.wrapKey.publicKey,
              reader: true,
              writer: true,
              administrator: true,
              publisher: true,
              finalizer: true,
            }],
            admission: null,
            schedule: [{ effectiveAfterMs: -1, policy: { kind: 'open' } }],
          },
        },
        ledger: { module: 'app/ledger', initialState: { balance: 0 } },
        escrow: { module: 'app/escrow', initialState: { locked: 0 } },
        notes: { module: 'app/notes', initialState: { items: [] } },
      },
      seals: {
        // Freeze $admission.schedule forever (auto-locks $admission reducer too!), while keeping $admission.members mutable!
        paths: [
          { topic: '$admission', path: 'schedule', mode: 'frozen' },
          { topic: 'notes', path: 'items', mode: 'append-only', allowMutableReducer: true },
        ],
        reducers: ['ledger'],
      },
    })

    const sess = await createApplicationSession({ device: devAdmin, genesis: created.genesisBytes, casNodes: created.casNodes })
    closes.push(() => sess.close())

    // 1. Inspect plain-data $seals directly: ledger & $admission reducers are locked, notes reducer is still mutable!
    const seals = sess.seals()
    expect(seals.reducers.ledger).toBe(true)
    expect(seals.reducers.$admission).toBe(true)
    expect(seals.reducers.notes).toBeUndefined()
    expect(seals.paths.$admission?.schedule).toBe('frozen')
    expect(seals.paths.notes?.items).toBe('append-only')

    // 2. Trying to upgrade sealed ledger reducer (via import map retargeting) is REJECTED by kernel!
    const rugLedger = await sess.updateReducers({ imports: { 'app/ledger': ledgerV2 } })
    const rugRes = await rugLedger.materialized()
    expect(rugRes.outcome).toBe('rejected')
    expect(rugRes.rejectionCode).toBe('seal:reducer_locked')
    expect(rugRes.rejectionDetail).toBe('ledger')

    // 3. Trying to change frozen $admission.schedule is REJECTED by kernel!
    const changeFinality = await sess.admission.schedulePolicy({
      effectiveAfterMs: BigInt(Date.now() + 60_000),
      policy: { kind: 'signed-frontier', signer: devAdmin.identity.publicKey },
    })
    const changeFinalityRes = await changeFinality.materialized()
    expect(changeFinalityRes.outcome).toBe('rejected')
    expect(changeFinalityRes.rejectionCode).toBe('seal:path_frozen')
    expect(changeFinalityRes.rejectionDetail).toBe('$admission.schedule')

    // 4. Meanwhile, $admission.members is STILL mutable (can admit devMember)!
    const admit = await sess.admitMember({ publicKey: devMember.identity.publicKey, reader: true, writer: true })
    expect((await admit.materialized()).outcome).toBe('accepted')
    expect(sess.isWriter(devMember.identity.publicKey)).toBe(true)

    // 5. And unsealed notes reducer CAN still be upgraded, while its append-only items array is protected!
    await (await sess.submit({ awaitMaterialized: true, updates: [{ topic: 'notes', input: { text: 'first' } }] })).materialized()
    const upNotes = await sess.updateReducers({ imports: { 'app/notes': notesV2 } })
    expect((await upNotes.materialized()).outcome).toBe('accepted')
    await (await sess.submit({ awaitMaterialized: true, updates: [{ topic: 'notes', input: { text: 'second' } }] })).materialized()
    expect(sess.topic('notes')).toEqual({ items: ['first', 'v2:second'] })

    // 6. Monotonicity: attempting to weaken a frozen seal to append-only is REJECTED!
    const weaken = await sess.seal({ paths: [{ topic: '$admission', path: 'schedule', mode: 'append-only' }] })
    expect((await weaken.materialized()).outcome).toBe('rejected')
    expect((await weaken.materialized()).rejectionCode).toBe('seal_cannot_weaken')

    // 7. Semantic post-condition $admission.verify(before, after, tx, ctx):
    //    Updating only ledger breaks ledger.balance === escrow.locked -> rejected atomically!
    const unbalanced = await sess.submit({
      awaitMaterialized: true,
      updates: [{ topic: 'ledger', input: { delta: 50 } }],
    })
    const unbalRes = await unbalanced.materialized()
    expect(unbalRes.outcome).toBe('rejected')
    expect(unbalRes.rejectionCode).toBe('conservation_mismatch')
    expect(sess.topic('ledger')).toEqual({ balance: 0 })

    //    Updating both ledger & escrow in one atomic tx passes $admission.verify!
    const balanced = await sess.submit({
      awaitMaterialized: true,
      updates: [
        { topic: 'ledger', input: { delta: 50 } },
        { topic: 'escrow', input: { delta: 50 } },
      ],
    })
    expect((await balanced.materialized()).outcome).toBe('accepted')
    expect(sess.topic('ledger')).toEqual({ balance: 50 })
    expect(sess.topic('escrow')).toEqual({ locked: 50 })
  })

  it('runs the expanded standard library modules (guards, quotas, queue, votes, schema, audit)', async () => {
    const devA = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    const devB = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

    const customGuardedReducer = `
      import { guardReducer, requireAuthorChain } from 'chronolog/guards';
      import { validate, migrateState } from 'chronolog/schema';

      const ITEM_SCHEMA = {
        type: 'object',
        required: ['amount'],
        properties: { amount: { type: 'integer', minimum: 1 } },
      };

      const base = {
        reduce(state, tx) {
          const cur = migrateState(state, { 1: s => ({ ...s, total: Number(s.total || 0) }) }, 1);
          const v = validate(ITEM_SCHEMA, tx.payload);
          if (!v.ok) return v;
          return { ok: true, state: { ...cur, total: cur.total + tx.payload.amount } };
        },
        query(state) { return state; },
      };

      export default guardReducer(base, {
        pre: [
          (state, tx, ctx) => tx.payload && tx.payload.expectedLastOp !== undefined
            ? requireAuthorChain(ctx, tx, tx.payload.expectedLastOp)
            : { ok: true },
        ],
        post: [
          (nextState) => nextState.total <= 100
            ? { ok: true }
            : { ok: false, code: 'cap_exceeded' },
        ],
      });
    `

    const created = await createLogGenesis({
      creator: {
        publicKey: devA.identity.publicKey,
        wrapKey: devA.wrapKey.publicKey,
        reader: true,
        writer: true,
        administrator: true,
      },
      members: [
        { publicKey: devB.identity.publicKey, wrapKey: devB.wrapKey.publicKey, reader: true, writer: true },
      ],
      privateLog: true,
      imports: { 'app/guarded': customGuardedReducer },
      topics: {
        guarded: { module: 'app/guarded' },
        quotas: { module: 'chronolog/quotas', config: { capacity: 2, refillPerSec: 1 } },
        jobs: { module: 'chronolog/queue', config: { defaultLeaseMs: 1000, maxAttempts: 2 } },
        votes: { module: 'chronolog/votes' },
        audit: { module: 'chronolog/audit' },
      },
    })

    const epochKeys = new Map([[0, created.epoch0Key!]])
    const sessA = await createApplicationSession({
      device: devA,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    const sessB = await createApplicationSession({
      device: devB,
      genesis: created.genesisBytes,
      casNodes: created.casNodes,
      epochKeys,
    })
    closes.push(() => sessA.close(), () => sessB.close())

    // 1. chronolog/guards + chronolog/schema
    const gBadSchema = await sessA.submit({ awaitMaterialized: true, updates: [{ topic: 'guarded', input: { amount: -5 } }] })
    expect((await gBadSchema.materialized()).rejectionCode).toBe('schema:minimum')

    const gOk = await sessA.submit({ awaitMaterialized: true, updates: [{ topic: 'guarded', input: { amount: 60 } }] })
    expect((await gOk.materialized()).outcome).toBe('accepted')

    const gBadPost = await sessA.submit({ awaitMaterialized: true, updates: [{ topic: 'guarded', input: { amount: 50 } }] })
    expect((await gBadPost.materialized()).rejectionCode).toBe('cap_exceeded')

    const gChain = await sessA.submit({ awaitMaterialized: true, updates: [{ topic: 'guarded', input: { amount: 10, expectedLastOp: gOk.id } }] })
    expect((await gChain.materialized()).outcome).toBe('accepted')
    expect((await sessA.query('guarded')).value).toEqual({ schemaVersion: 1, total: 70 })

    // 2. chronolog/quotas (capacity=2, refill=1/sec)
    const t0 = 1_700_000_000_000n
    expect((await (await sessA.submit({ awaitMaterialized: true, authorTimestampMs: t0, updates: [{ topic: 'quotas', input: { cost: 1 } }] })).materialized()).outcome).toBe('accepted')
    expect((await (await sessA.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 100n, updates: [{ topic: 'quotas', input: { cost: 1 } }] })).materialized()).outcome).toBe('accepted')
    expect((await (await sessA.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 200n, updates: [{ topic: 'quotas', input: { cost: 1 } }] })).materialized()).rejectionCode).toBe('quota:rate_limited')
    expect((await (await sessA.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 1500n, updates: [{ topic: 'quotas', input: { cost: 1 } }] })).materialized()).outcome).toBe('accepted')

    // 3. chronolog/queue (enqueue -> claim -> lease expiry reclaim -> complete)
    await (await sessA.submit({ awaitMaterialized: true, authorTimestampMs: t0, updates: [{ topic: 'jobs', input: { action: 'enqueue', id: 'j1', kind: 'index', payload: { doc: 1 } } }] })).materialized()
    await (await sessA.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 10n, updates: [{ topic: 'jobs', input: { action: 'claim', id: 'j1', leaseMs: 1000 } }] })).materialized()
    await sessB.mergeFacts(await sessA.exportFacts({ includePrivateCas: true }))
    // B cannot steal active lease before expiry
    const earlySteal = await sessB.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 500n, updates: [{ topic: 'jobs', input: { action: 'claim', id: 'j1' } }] })
    expect((await earlySteal.materialized()).rejectionCode).toBe('queue:already_claimed')
    // B CAN reclaim after lease expires (t0 + 1500 >= t0 + 1010) and complete
    const reclaim = await sessB.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 1500n, updates: [{ topic: 'jobs', input: { action: 'claim', id: 'j1' } }] })
    expect((await reclaim.materialized()).outcome).toBe('accepted')
    const complete = await sessB.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 1600n, updates: [{ topic: 'jobs', input: { action: 'complete', id: 'j1', result: { indexed: true } } }] })
    expect((await complete.materialized()).outcome).toBe('accepted')
    const jobState = (await sessB.query('jobs', { id: 'j1' })).value as { status: string; attempts: number; claimedBy: string }
    expect(jobState.status).toBe('completed')
    expect(jobState.attempts).toBe(2)
    expect(jobState.claimedBy).toBe(devB.identity.publicKey)

    // 4. chronolog/votes (weighted tally + quorum)
    await (await sessA.submit({
      awaitMaterialized: true,
      authorTimestampMs: t0,
      updates: [{
        topic: 'votes',
        input: {
          action: 'create',
          id: 'p1',
          title: 'Adopt predicates',
          options: ['yes', 'no'],
          quorum: 3,
          weights: { [devA.identity.publicKey]: 2, [devB.identity.publicKey]: 1 },
        },
      }],
    })).materialized()
    await (await sessA.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 10n, updates: [{ topic: 'votes', input: { action: 'cast', id: 'p1', choice: 'yes' } }] })).materialized()
    await sessB.mergeFacts(await sessA.exportFacts({ includePrivateCas: true }))
    await (await sessB.submit({ awaitMaterialized: true, authorTimestampMs: t0 + 20n, updates: [{ topic: 'votes', input: { action: 'cast', id: 'p1', choice: 'no' } }] })).materialized()
    const tally = (await sessB.query('votes', { id: 'p1' })).value as { quorumMet: boolean; winner: string; counts: Record<string, number> }
    expect(tally.quorumMet).toBe(true)
    expect(tally.winner).toBe('yes')
    expect(tally.counts).toEqual({ yes: 2, no: 1 })

    // 5. chronolog/audit (hash-chained tamper-evident log)
    await (await sessA.submit({ awaitMaterialized: true, updates: [{ topic: 'audit', input: { category: 'auth', subject: 'alice', detail: { ok: true } } }] })).materialized()
    await (await sessA.submit({ awaitMaterialized: true, updates: [{ topic: 'audit', input: { category: 'billing', subject: 'inv-1', detail: { cents: 500 } } }] })).materialized()
    const verified = (await sessA.query('audit', { verify: true })).value as { valid: boolean; count: number }
    expect(verified.valid).toBe(true)
    expect(verified.count).toBe(2)
  })
})

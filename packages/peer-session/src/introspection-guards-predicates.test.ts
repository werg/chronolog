import { afterEach, describe, expect, it } from 'vitest'
import { bytesToHex, sha256Sync, utf8 } from '@chronolog/canonical'
import { canonicalJson, decodeOperationCore, decodeSignedOperation, operationIdDigest, type JsonValue } from '@chronolog/protocol'
import { MemoryBytesStore } from '@chronolog/records'
import type { FinalityCheckpointPayload } from '@chronolog/authority'
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

function checkpointPayloadToJsonSafe(payload: FinalityCheckpointPayload): JsonValue {
  return {
    logId: payload.logId,
    policyScopeId: payload.policyScopeId,
    closedThroughMs: Number(payload.closedThroughMs),
    includedSetDigest: payload.includedSetDigest,
    historyDigest: payload.historyDigest,
    stateRoot: payload.stateRoot,
    inclusions: payload.inclusions.map(i => ({
      opId: i.opId,
      authorTimestampMs: Number(i.authorTimestampMs),
      author: i.author,
    })),
  }
}

async function signUtf8(privateKey: CryptoKey, message: string): Promise<string> {
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, new Uint8Array(utf8(message))))
  return bytesToHex(sig)
}

async function signPredicatePayload(payload: FinalityCheckpointPayload, privateKey: CryptoKey, publicKey: string): Promise<{ readonly signer: string; readonly signature: string }> {
  const msg = canonicalJson(['chronolog/finality-predicate/v1', checkpointPayloadToJsonSafe(payload)])
  return {
    signer: publicKey,
    signature: await signUtf8(privateKey, msg),
  }
}

describe('SQLite-CAS Read-Only Chronolog Introspection, Guarded OCC, Programmable Finality Predicates & Expanded Stdlib', () => {
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
            { sql: "SELECT chronolog_topic_query('$permissions', ?)", params: [JSON.stringify({ check: 'writer', actor: devAdmin.identity.publicKey })], expect: { firstValue: 'true' } },
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
    expect(topicRows.map(r => r.topic)).toContain('$permissions')
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

  it('evaluates programmable state-defined $finality predicates (weighted quorum, optimistic challenge, merkle anchor) identically on full peers and blind hosts', async () => {
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

    // 1. Schedule weighted thresholdQuorumPredicate (admin=2, val1=1, val2=1, threshold=3)
    const sched1 = await sess.submit({
      visibility: 'public',
      awaitMaterialized: true,
      authorTimestampMs: t1 + 20n,
      updates: [{
        topic: '$finality',
        input: {
          action: 'schedulePolicy',
          effectiveAfterMs: Number(t1 + 50n),
          policy: {
            kind: 'predicate',
            module: 'chronolog/finality-predicates',
            export: 'thresholdQuorumPredicate',
            config: {
              validators: {
                [devAdmin.identity.publicKey]: 2,
                [devVal1.identity.publicKey]: 1,
                [devVal2.identity.publicKey]: 1,
              },
              threshold: 3,
            },
          },
        },
      }],
    })
    expect((await sched1.materialized()).outcome).toBe('accepted')

    // Single signature (weight 2 < 3) must NOT finalize
    await sess.finality.createCheckpoint({
      throughMs: t1 + 100n,
      attestation: async payload => ({
        kind: 'evidence',
        data: { signatures: [await signPredicatePayload(payload, devAdmin.identity.privateKey, devAdmin.identity.publicKey)] },
      }),
    })
    expect(sess.finality.status().closedThroughMs).toBeNull()

    // Admin (2) + Val1 (1) = weight 3 >= 3 MUST finalize!
    const { checkpoint: quorumCp } = await sess.finality.createCheckpoint({
      throughMs: t1 + 100n,
      attestation: async payload => ({
        kind: 'evidence',
        data: {
          signatures: [
            await signPredicatePayload(payload, devAdmin.identity.privateKey, devAdmin.identity.publicKey),
            await signPredicatePayload(payload, devVal1.identity.privateKey, devVal1.identity.publicKey),
          ],
        },
      }),
    })
    expect(sess.finality.status().closedThroughMs).toBe(t1 + 100n)
    expect(sess.finalityStatus(opEarly.id)).toBe('finalized')

    // Verify blind host (Cloudflare Worker simulation) evaluates the exact same predicate identically!
    const facts = await sess.exportFacts()
    const blindPublicOps = facts.publicOps.map(raw => {
      const signed = decodeSignedOperation(raw)
      return { opId: operationIdDigest(signed.coreBytes), core: decodeOperationCore(signed.coreBytes) }
    })
    const blind = await replayBlindHostControl({
      genesis: created.genesis,
      publicCasNodes: facts.casNodes.filter(n => n.partition === 'public'),
      publicOps: blindPublicOps,
      checkpoints: [quorumCp],
    })
    expect(blind.finality.closedThroughMs).toBe(t1 + 100n)
    expect(blind.finality.includedOpIds.has(opEarly.id)).toBe(true)

    // 2. Handoff to optimisticChallengePredicate at t1 + 200 (challengeWindowMs = 500)
    const sched2 = await sess.submit({
      visibility: 'public',
      awaitMaterialized: true,
      authorTimestampMs: t1 + 120n,
      updates: [{
        topic: '$finality',
        input: {
          action: 'schedulePolicy',
          effectiveAfterMs: Number(t1 + 200n),
          policy: {
            kind: 'predicate',
            module: 'chronolog/finality-predicates',
            export: 'optimisticChallengePredicate',
            config: {
              proposers: [devAdmin.identity.publicKey],
              challengers: [devChallenger.identity.publicKey],
              challengeWindowMs: 500,
            },
          },
        },
      }],
    })
    expect((await sched2.materialized()).outcome).toBe('accepted')

    // Seal handoff at t1 + 200 under quorum policy first
    await sess.finality.createCheckpoint({
      throughMs: t1 + 200n,
      attestation: async payload => ({
        kind: 'evidence',
        data: {
          signatures: [
            await signPredicatePayload(payload, devAdmin.identity.privateKey, devAdmin.identity.publicKey),
            await signPredicatePayload(payload, devVal2.identity.privateKey, devVal2.identity.publicKey),
          ],
        },
      }),
    })
    expect(sess.finality.status().closedThroughMs).toBe(t1 + 200n)

    // Optimistic checkpoint BEFORE window elapses -> rejected
    await sess.finality.createCheckpoint({
      throughMs: t1 + 300n,
      attestation: async payload => ({
        kind: 'evidence',
        data: {
          observedAtMs: Number(t1 + 500n), // < 300 + 500 = 800
          proposal: await signPredicatePayload(payload, devAdmin.identity.privateKey, devAdmin.identity.publicKey),
        },
      }),
    })
    expect(sess.finality.status().closedThroughMs).toBe(t1 + 200n)

    // Optimistic checkpoint AFTER window elapses BUT WITH valid fraud challenge -> rejected!
    await sess.finality.createCheckpoint({
      throughMs: t1 + 300n,
      attestation: async payload => {
        const chMsg = canonicalJson(['chronolog/finality-challenge/v1', payload.logId, payload.policyScopeId, Number(payload.closedThroughMs), 'invalid_state'])
        return {
          kind: 'evidence',
          data: {
            observedAtMs: Number(t1 + 900n),
            proposal: await signPredicatePayload(payload, devAdmin.identity.privateKey, devAdmin.identity.publicKey),
            challenges: [{
              signer: devChallenger.identity.publicKey,
              reason: 'invalid_state',
              signature: await signUtf8(devChallenger.identity.privateKey, chMsg),
            }],
          },
        }
      },
    })
    expect(sess.finality.status().closedThroughMs).toBe(t1 + 200n)

    // Optimistic checkpoint AFTER window with NO valid challenge -> admitted!
    await sess.finality.createCheckpoint({
      throughMs: t1 + 300n,
      attestation: async payload => ({
        kind: 'evidence',
        data: {
          observedAtMs: Number(t1 + 900n),
          proposal: await signPredicatePayload(payload, devAdmin.identity.privateKey, devAdmin.identity.publicKey),
        },
      }),
    })
    expect(sess.finality.status().closedThroughMs).toBe(t1 + 300n)

    // 3. Handoff to merkleAnchorPredicate at t1 + 400 (external anchor proof)
    const sched3 = await sess.submit({
      visibility: 'public',
      awaitMaterialized: true,
      authorTimestampMs: t1 + 310n,
      updates: [{
        topic: '$finality',
        input: {
          action: 'schedulePolicy',
          effectiveAfterMs: Number(t1 + 400n),
          policy: {
            kind: 'predicate',
            module: 'chronolog/finality-predicates',
            export: 'merkleAnchorPredicate',
            config: { anchorSigners: [devVal1.identity.publicKey] },
          },
        },
      }],
    })
    expect((await sched3.materialized()).outcome).toBe('accepted')

    // Seal handoff at t1 + 400 under optimistic policy
    await sess.finality.createCheckpoint({
      throughMs: t1 + 400n,
      attestation: async payload => ({
        kind: 'evidence',
        data: {
          observedAtMs: Number(t1 + 1000n),
          proposal: await signPredicatePayload(payload, devAdmin.identity.privateKey, devAdmin.identity.publicKey),
        },
      }),
    })
    expect(sess.finality.status().closedThroughMs).toBe(t1 + 400n)

    // Submit Merkle-anchored checkpoint at t1 + 500
    await sess.finality.createCheckpoint({
      throughMs: t1 + 500n,
      attestation: async payload => {
        const leaf = bytesToHex(sha256Sync(utf8(canonicalJson(['chronolog/finality-predicate/v1', checkpointPayloadToJsonSafe(payload)]))))
        const sibling = 'a'.repeat(64)
        const root = bytesToHex(sha256Sync(utf8(leaf + sibling)))
        const anchorMsg = canonicalJson(['chronolog/merkle-anchor/v1', root])
        return {
          kind: 'evidence',
          data: {
            root,
            proof: [{ position: 'right', sibling }],
            anchorSignature: {
              signer: devVal1.identity.publicKey,
              signature: await signUtf8(devVal1.identity.privateKey, anchorMsg),
            },
          },
        }
      },
    })
    expect(sess.finality.status().closedThroughMs).toBe(t1 + 500n)
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

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { bytesToHex, utf8 } from '@chronolog/canonical'
import {
  generateEd25519KeyPair,
  operationIdDigest,
  type GenesisBlock,
  type OperationCore,
  type TopicUpdate,
} from '@chronolog/protocol'
import { ContentAddressedStore, MemoryBytesStore } from '@chronolog/records'
import {
  CAS_BUILTIN_ID,
  CRYPTO_BUILTIN_ID,
  QUICKJS_RUNTIME_ID,
  TopicKernel,
  seedStandardModules,
  type KernelOperationInput,
} from '@chronolog/materializer'
import { createSqliteCasDriver } from './driver.js'

function makeOp(
  chainId: Uint8Array,
  author: Uint8Array,
  operationId: string,
  authorTimestampMs: bigint,
  updates: readonly TopicUpdate[],
  nonceByte = 1,
): KernelOperationInput {
  const core: OperationCore = {
    version: 1,
    chainId,
    author,
    operationId,
    authorTimestampMs,
    nonce: new Uint8Array(16).fill(nonceByte),
    visibility: 'public',
    updates,
  }
  return { opId: operationIdDigest(core), core }
}

describe('Chronolog v2 sqlite-cas.wasm + RLS (Phase 2 Gate 2)', () => {
  it('runs deterministic SQL + sqlite-vec + fts5 + O(1) rollback suffix replay with exact dbRoot parity', async () => {
    const driver = await createSqliteCasDriver()
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const stdImports = await seedStandardModules(cas)

    const dbModHash = await cas.put(utf8(`
      import { openDb } from 'chronolog:sqlite';
      export default {
        reduce(state, tx) {
          const db = openDb(state?.dbRoot ?? null);
          if (tx.payload.action === 'init') {
            db.exec(\`
              CREATE TABLE items (id TEXT PRIMARY KEY, body TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL, local_at TEXT NOT NULL, op TEXT NOT NULL);
              CREATE VIRTUAL TABLE items_fts USING fts5(id, body);
              CREATE VIRTUAL TABLE items_vec USING vec0(embedding float[2]);
            \`);
            return { ok: true, state: { dbRoot: db.commit() } };
          }
          if (tx.payload.action === 'add') {
            db.exec(
              "INSERT INTO items (id, body, author, created_at, local_at, op) VALUES (?, ?, actor(), datetime('now'), datetime('now', 'localtime'), op_id())",
              [tx.payload.id, tx.payload.body],
            );
            db.exec('INSERT INTO items_fts (id, body) VALUES (?, ?)', [tx.payload.id, tx.payload.body]);
            if (tx.payload.vec) {
              db.exec('INSERT INTO items_vec (rowid, embedding) VALUES (?, ?)', [tx.payload.rowid, JSON.stringify(tx.payload.vec)]);
            }
            return { ok: true, state: { dbRoot: db.commit() } };
          }
          if (tx.payload.action === 'tryRandom') {
            db.exec('SELECT random()');
            return { ok: true, state: { dbRoot: db.commit() } };
          }
          if (tx.payload.action === 'checkChanges') {
            const res = db.query('SELECT changes(), last_insert_rowid()');
            return { ok: true, state: { dbRoot: state.dbRoot, check: res.rows[0] } };
          }
          return { ok: false, code: 'unknown' };
        },
        query(state, input) {
          const db = openDb(state?.dbRoot ?? null);
          if (input.kind === 'all') return db.query('SELECT id, body, author, created_at, local_at FROM items ORDER BY id');
          if (input.kind === 'fts') return db.query('SELECT id FROM items_fts WHERE items_fts MATCH ?', [input.q]);
          if (input.kind === 'vec') return db.query('SELECT rowid, distance FROM items_vec WHERE embedding MATCH ? ORDER BY distance LIMIT 2', [JSON.stringify(input.q)]);
          return null;
        },
      };
    `), [], 'public')

    const author = await generateEd25519KeyPair()
    const genesis: GenesisBlock = {
      version: 1,
      privateChain: false,
      initialTopics: {
        $reducers: {
          runtime: {
            js: QUICKJS_RUNTIME_ID,
            builtins: { 'chronolog:sqlite': driver.builtinId, 'chronolog:crypto': CRYPTO_BUILTIN_ID, 'chronolog:cas': CAS_BUILTIN_ID },
          },
          imports: { ...stdImports, '@app/db': `cas:sha256-${dbModHash}` },
          topics: { db: { module: '@app/db' } },
        },
        db: null,
      },
      limits: { maxMemoryBytes: 32 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16 },
      salt: new Uint8Array(16).fill(11),
    }

    const kWarm = new TopicKernel({ genesis, cas, sqliteDriver: driver, snapshotInterval: 2 })
    const initOp = makeOp(kWarm.chainId, author.publicKeyBytes, 'init', 1_700_000_000_000n, [{ topic: 'db', input: { action: 'init' } }])
    const addOps: KernelOperationInput[] = []
    for (let i = 1; i <= 10; i++) {
      addOps.push(makeOp(
        kWarm.chainId,
        author.publicKeyBytes,
        `add-${i}`,
        1_700_000_000_000n + BigInt(i * 1000),
        [{ topic: 'db', input: { action: 'add', id: `item-${String(i).padStart(2, '0')}`, body: `hello world ${i}`, rowid: i, vec: [i * 0.1, 1.0 - i * 0.1] } }],
        i,
      ))
    }

    await kWarm.materialize([initOp, ...addOps])
    const allRes = await kWarm.query('db', { kind: 'all' }) as { rows: unknown[][] }
    expect(allRes.rows.length).toBe(10)
    // Verify deterministic UTC datetime('now') === datetime('now', 'localtime') derived from op_time()!
    expect(allRes.rows[0]![3]).toBe('2023-11-14 22:13:21')
    expect(allRes.rows[0]![4]).toBe('2023-11-14 22:13:21')
    expect(allRes.rows[0]![2]).toBe(bytesToHex(author.publicKeyBytes))

    // FTS5 and sqlite-vec queries work!
    expect(await kWarm.query('db', { kind: 'fts', q: 'world' })).toMatchObject({ columns: ['id'] })
    const vecRes = await kWarm.query('db', { kind: 'vec', q: [0.1, 0.9] }) as { rows: unknown[][] }
    expect(vecRes.rows[0]![0]).toBe(1)

    // random() must deterministically reject!
    const randOp = makeOp(kWarm.chainId, author.publicKeyBytes, 'rand', 1_700_000_050_000n, [{ topic: 'db', input: { action: 'tryRandom' } }])
    const checkOp = makeOp(kWarm.chainId, author.publicKeyBytes, 'chk', 1_700_000_060_000n, [{ topic: 'db', input: { action: 'checkChanges' } }])
    const r2 = await kWarm.materialize([initOp, ...addOps, randOp, checkOp])
    expect(r2.outcomes.find(o => o.operationId === 'rand')!.outcome).toBe('rejected')
    // changes() and last_insert_rowid() reset to [0, 0] on fresh openDb()
    expect((kWarm.topic('db') as { check: number[] }).check).toEqual([0, 0])

    // Late-arriving op at depth 10 triggers O(1) rollback + suffix replay!
    const lateOp = makeOp(
      kWarm.chainId,
      author.publicKeyBytes,
      'late-0',
      1_700_000_000_500n,
      [{ topic: 'db', input: { action: 'add', id: 'item-00-late', body: 'arrived late', rowid: 99, vec: [0.5, 0.5] } }],
      99,
    )
    await kWarm.materialize([initOp, ...addOps, lateOp])
    const warmRoot = (kWarm.topic('db') as { dbRoot: string }).dbRoot

    // Cold replay from scratch on a fresh CAS + static WebAssembly.Module must produce the EXACT same dbRoot!
    const wasmBytes = readFileSync(resolve(import.meta.dirname, '../wasm/sqlite-cas.wasm'))
    const staticDriver = await createSqliteCasDriver({ wasmModule: new WebAssembly.Module(wasmBytes) })
    const coldCas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    await seedStandardModules(coldCas)
    await coldCas.put((await cas.get(dbModHash, 'public'))!.bytes, [], 'public')
    const kCold = new TopicKernel({ genesis, cas: coldCas, sqliteDriver: staticDriver })
    await kCold.materialize([lateOp, ...addOps.slice().reverse(), initOp])
    expect((kCold.topic('db') as { dbRoot: string }).dbRoot).toBe(warmRoot)
    expect(kCold.revision('local').stateRoot).toBe(kWarm.revision('local').stateRoot)

    // Verify CAS GC preserves every reachable SQLite page chunk
    const gcBefore = await coldCas.collectGarbage(kCold.gcRoots())
    expect(gcBefore.kept).toBeGreaterThan(2)
    expect((await kCold.query('db', { kind: 'all' }) as { rows: unknown[][] }).rows.length).toBe(11)
  })

  it('enforces Postgres-style chronolog/rls write guards, blocks INSERT OR REPLACE bypass & SQL injection, and supports non-admin table creation', async () => {
    const driver = await createSqliteCasDriver()
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const stdImports = await seedStandardModules(cas)

    const rlsAppHash = await cas.put(utf8(`
      import { openDb } from 'chronolog:sqlite';
      import { applyRls, ensureTableOwners, getOwnedTables, recordTableOwners } from 'chronolog/rls';

      export default {
        reduce(state, tx, ctx) {
          const perms = ctx.topic('$permissions');
          const member = perms.members.find(m => m.publicKey === tx.author);
          if (!member || !member.writer) return { ok: false, code: 'unauthorized' };
          const isAdmin = Boolean(member.administrator);
          const db = openDb(state?.dbRoot ?? null);

          if (tx.payload.action === 'adminMigrate') {
            if (!isAdmin) return { ok: false, code: 'admin_required' };
            db.exec(tx.payload.sql, tx.payload.params || [], { mode: 'admin' });
            if (tx.payload.rls) applyRls(db, tx.payload.rls);
            return { ok: true, state: { dbRoot: db.commit() } };
          }

          if (tx.payload.action === 'userSql') {
            const owned = isAdmin ? [] : getOwnedTables(db, tx.author);
            const res = db.exec(tx.payload.sql, tx.payload.params || [], {
              mode: isAdmin ? 'admin' : 'user',
              ddl: { createTable: true, alterTable: owned, dropTable: owned, indexOn: owned },
            });
            if (!isAdmin && (res.createdTables.length > 0 || res.droppedTables.length > 0)) {
              recordTableOwners(db, res.createdTables, res.droppedTables, tx.author);
              // Default owner-only RLS on newly created user tables
              const defaults = {};
              for (const t of res.createdTables) {
                const expr = "actor() = '" + tx.author + "'";
                defaults[t] = { insert: expr, update: expr, delete: expr };
              }
              if (res.createdTables.length > 0) applyRls(db, defaults);
            }
            return { ok: true, state: { dbRoot: db.commit() } };
          }

          if (tx.payload.action === 'setPolicy') {
            ensureTableOwners(db);
            const owned = getOwnedTables(db, tx.author);
            if (!isAdmin && !owned.includes(tx.payload.table)) return { ok: false, code: 'table_owner_required' };
            applyRls(db, { [tx.payload.table]: tx.payload.policy });
            return { ok: true, state: { dbRoot: db.commit() } };
          }

          return { ok: false, code: 'unknown_action' };
        },
        query(state, input) {
          const db = openDb(state?.dbRoot ?? null);
          return db.query(input.sql, input.params || []);
        },
      };
    `), [], 'public')

    const admin = await generateEd25519KeyPair()
    const alice = await generateEd25519KeyPair()
    const bob = await generateEd25519KeyPair()
    const adminHex = bytesToHex(admin.publicKeyBytes)
    const aliceHex = bytesToHex(alice.publicKeyBytes)
    const bobHex = bytesToHex(bob.publicKeyBytes)

    const genesis: GenesisBlock = {
      version: 1,
      privateChain: false,
      initialTopics: {
        $reducers: {
          runtime: {
            js: QUICKJS_RUNTIME_ID,
            builtins: { 'chronolog:sqlite': driver.builtinId, 'chronolog:crypto': CRYPTO_BUILTIN_ID, 'chronolog:cas': CAS_BUILTIN_ID },
          },
          imports: { ...stdImports, '@app/rls': `cas:sha256-${rlsAppHash}` },
          topics: {
            $permissions: { module: 'chronolog/permissions', export: 'attestedMembers' },
            sql: { module: '@app/rls' },
          },
        },
        $permissions: {
          members: [
            { publicKey: adminHex, reader: true, writer: true, administrator: true, publisher: true, finalizer: true },
            { publicKey: aliceHex, reader: true, writer: true, administrator: false, publisher: false, finalizer: false },
            { publicKey: bobHex, reader: true, writer: true, administrator: false, publisher: false, finalizer: false },
          ],
        },
        sql: null,
      },
      limits: { maxMemoryBytes: 32 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16 },
      salt: new Uint8Array(16).fill(12),
    }

    const kernel = new TopicKernel({ genesis, cas, sqliteDriver: driver })
    const ops: KernelOperationInput[] = [
      // 1. Admin creates tasks table + Postgres-style write RLS
      makeOp(kernel.chainId, admin.publicKeyBytes, 'mig-1', 10n, [{
        topic: 'sql',
        input: {
          action: 'adminMigrate',
          sql: 'CREATE TABLE tasks (id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL)',
          rls: {
            tasks: {
              insert: 'NEW.owner = actor()',
              update: 'OLD.owner = actor() AND NEW.owner = actor()',
              delete: 'OLD.owner = actor()',
            },
          },
        },
      }]),
      // 2. Alice inserts her own task (allowed)
      makeOp(kernel.chainId, alice.publicKeyBytes, 'a-1', 20n, [{
        topic: 'sql',
        input: { action: 'userSql', sql: "INSERT INTO tasks VALUES ('t1', actor(), 'Alice task')" },
      }]),
      // 3. Bob tries to overwrite Alice's task via UPDATE (denied by RLS)
      makeOp(kernel.chainId, bob.publicKeyBytes, 'b-upd', 30n, [{
        topic: 'sql',
        input: { action: 'userSql', sql: "UPDATE tasks SET title = 'hacked' WHERE id = 't1'" },
      }]),
      // 4. Bob tries INSERT OR REPLACE to bypass DELETE RLS (blocked because recursive_triggers = ON!)
      makeOp(kernel.chainId, bob.publicKeyBytes, 'b-rep', 40n, [{
        topic: 'sql',
        input: { action: 'userSql', sql: "INSERT OR REPLACE INTO tasks VALUES ('t1', actor(), 'replaced!')" },
      }]),
      // 5. Bob tries DROP TRIGGER to remove RLS (blocked by mode: 'user'!)
      makeOp(kernel.chainId, bob.publicKeyBytes, 'b-drop', 50n, [{
        topic: 'sql',
        input: { action: 'userSql', sql: 'DROP TRIGGER _rls_tasks_update' },
      }]),
      // 6. Non-admin Alice creates her OWN table + index + inserts a row in ONE op!
      makeOp(kernel.chainId, alice.publicKeyBytes, 'a-tbl', 60n, [{
        topic: 'sql',
        input: {
          action: 'userSql',
          sql: `
            CREATE TABLE alice_notes (id TEXT PRIMARY KEY, body TEXT, shared_with TEXT);
            CREATE INDEX idx_alice_notes ON alice_notes(shared_with);
            INSERT INTO alice_notes VALUES ('n1', 'draft', '${bobHex}');
          `,
        },
      }]),
      // 7. Bob tries to edit alice_notes before Alice shares it (denied by default owner-only RLS!)
      makeOp(kernel.chainId, bob.publicKeyBytes, 'b-note-early', 70n, [{
        topic: 'sql',
        input: { action: 'userSql', sql: "UPDATE alice_notes SET body = 'nope' WHERE id = 'n1'" },
      }]),
      // 8. Alice tries SQL injection inside setPolicy (blocked by mode:'readonly' validation!)
      makeOp(kernel.chainId, alice.publicKeyBytes, 'a-sqli', 80n, [{
        topic: 'sql',
        input: {
          action: 'setPolicy',
          table: 'alice_notes',
          policy: { update: '1=1) THEN RAISE(ABORT, \'x\') END; DROP TABLE tasks; --' },
        },
      }]),
      // 9. Alice installs a clean custom SQL RLS policy allowing Bob via OLD.shared_with = actor()!
      makeOp(kernel.chainId, alice.publicKeyBytes, 'a-pol', 90n, [{
        topic: 'sql',
        input: {
          action: 'setPolicy',
          table: 'alice_notes',
          policy: {
            insert: `actor() = '${aliceHex}'`,
            update: `actor() = '${aliceHex}' OR OLD.shared_with = actor()`,
            delete: `actor() = '${aliceHex}'`,
          },
        },
      }]),
      // 10. Now Bob CAN update alice_notes (allowed by Alice's custom SQL RLS!)
      makeOp(kernel.chainId, bob.publicKeyBytes, 'b-note-ok', 100n, [{
        topic: 'sql',
        input: { action: 'userSql', sql: "UPDATE alice_notes SET body = 'collab edit!' WHERE id = 'n1'" },
      }]),
      // 11. Bob STILL cannot DROP Alice's table!
      makeOp(kernel.chainId, bob.publicKeyBytes, 'b-drop-alice', 110n, [{
        topic: 'sql',
        input: { action: 'userSql', sql: 'DROP TABLE alice_notes' },
      }]),
    ]

    const res = await kernel.materialize(ops)
    const outcomeOf = (id: string) => res.outcomes.find(o => o.operationId === id)!
    expect(outcomeOf('mig-1').outcome).toBe('accepted')
    expect(outcomeOf('a-1').outcome).toBe('accepted')
    expect(outcomeOf('b-upd').outcome).toBe('rejected')
    expect(outcomeOf('b-rep').outcome).toBe('rejected')
    expect(outcomeOf('b-drop').outcome).toBe('rejected')
    expect(outcomeOf('a-tbl').outcome).toBe('accepted')
    expect(outcomeOf('b-note-early').outcome).toBe('rejected')
    expect(outcomeOf('a-sqli').outcome).toBe('rejected')
    expect(outcomeOf('a-pol').outcome).toBe('accepted')
    expect(outcomeOf('b-note-ok').outcome).toBe('accepted')
    expect(outcomeOf('b-drop-alice').outcome).toBe('rejected')

    const tasks = await kernel.query('sql', { sql: 'SELECT id, title FROM tasks' }) as { rows: unknown[][] }
    expect(tasks.rows).toEqual([['t1', 'Alice task']])
    const notes = await kernel.query('sql', { sql: 'SELECT id, body FROM alice_notes' }) as { rows: unknown[][] }
    expect(notes.rows).toEqual([['n1', 'collab edit!']])
  })
})
